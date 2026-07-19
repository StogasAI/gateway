package attest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	defaultSEVGuestCertBuffer = 64 * 1024
	maxSEVGuestCertBuffer     = 256 * 1024
)

type SEVGuestDevice struct {
	Path            string
	VMPL            uint32
	CertBufferBytes int
}

func (a SEVGuestDevice) Quote(ctx context.Context, reportData [64]byte) (quote []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := a.Path
	if path == "" {
		path = DefaultSEVGuestPath
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open SEV guest device: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			quote = nil
			err = errors.Join(err, fmt.Errorf("close SEV guest device: %w", closeErr))
		}
	}()

	report, certs, err := a.getExtReport(file.Fd(), reportData)
	if err != nil {
		report, err = a.getReport(file.Fd(), reportData)
		if err != nil {
			return nil, err
		}
	}
	return EncodeEnvelope(Envelope{
		Schema:   EnvelopeSchemaV1,
		Provider: ProviderSEVGuest,
		Report:   optionalBase64URL(report),
		AuxBlob:  optionalBase64URL(certs),
	})
}

func (a SEVGuestDevice) getReport(fd uintptr, reportData [64]byte) ([]byte, error) {
	req := &snpReportReq{VMPL: a.VMPL}
	copy(req.UserData[:], reportData[:])
	resp := &snpReportResp{}
	guestReq := &snpGuestRequestIoctl{
		MsgVersion: 1,
		ReqData:    uint64(uintptr(unsafe.Pointer(req))),
		RespData:   uint64(uintptr(unsafe.Pointer(resp))),
	}
	if err := sevGuestIoctl(fd, snpGetReportIOCTL(), guestReq); err != nil {
		return nil, formatSEVGuestError("SNP_GET_REPORT", err, guestReq.ExitInfo2)
	}
	return NormalizeReportBlob(append([]byte(nil), resp.Data[:]...)), nil
}

func (a SEVGuestDevice) getExtReport(fd uintptr, reportData [64]byte) ([]byte, []byte, error) {
	certBufferBytes := a.CertBufferBytes
	if certBufferBytes <= 0 {
		certBufferBytes = defaultSEVGuestCertBuffer
	}
	if certBufferBytes > maxSEVGuestCertBuffer {
		return nil, nil, fmt.Errorf("SEV guest cert buffer exceeds %d bytes", maxSEVGuestCertBuffer)
	}
	return a.getExtReportWithCertBuffer(fd, reportData, certBufferBytes)
}

func (a SEVGuestDevice) getExtReportWithCertBuffer(fd uintptr, reportData [64]byte, certBufferBytes int) ([]byte, []byte, error) {
	certs := make([]byte, certBufferBytes)
	req := &snpExtReportReq{}
	req.Data.VMPL = a.VMPL
	copy(req.Data.UserData[:], reportData[:])
	if len(certs) > 0 {
		req.CertsAddress = uint64(uintptr(unsafe.Pointer(&certs[0])))
		req.CertsLen = uint32(len(certs))
	}
	resp := &snpReportResp{}
	guestReq := &snpGuestRequestIoctl{
		MsgVersion: 1,
		ReqData:    uint64(uintptr(unsafe.Pointer(req))),
		RespData:   uint64(uintptr(unsafe.Pointer(resp))),
	}
	if err := sevGuestIoctl(fd, snpGetExtReportIOCTL(), guestReq); err != nil {
		if req.CertsLen > uint32(len(certs)) && req.CertsLen <= maxSEVGuestCertBuffer {
			return a.getExtReportWithCertBuffer(fd, reportData, int(req.CertsLen))
		}
		return nil, nil, formatSEVGuestError("SNP_GET_EXT_REPORT", err, guestReq.ExitInfo2)
	}
	certsLen := int(req.CertsLen)
	if certsLen > len(certs) {
		return nil, nil, fmt.Errorf("SNP_GET_EXT_REPORT returned cert length %d beyond buffer %d", certsLen, len(certs))
	}
	return NormalizeReportBlob(append([]byte(nil), resp.Data[:]...)), append([]byte(nil), certs[:certsLen]...), nil
}

type snpReportReq struct {
	UserData [64]byte
	VMPL     uint32
	Reserved [28]byte
}

type snpReportResp struct {
	Data [4000]byte
}

type snpExtReportReq struct {
	Data         snpReportReq
	CertsAddress uint64
	CertsLen     uint32
	_            [4]byte
}

type snpGuestRequestIoctl struct {
	MsgVersion uint8
	_          [7]byte
	ReqData    uint64
	RespData   uint64
	ExitInfo2  uint64
}

func sevGuestIoctl(fd uintptr, request uintptr, arg *snpGuestRequestIoctl) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, request, uintptr(unsafe.Pointer(arg)))
	if errno != 0 {
		return errno
	}
	return nil
}

func snpGetReportIOCTL() uintptr {
	return iowr('S', 0x0, unsafe.Sizeof(snpGuestRequestIoctl{}))
}

func snpGetExtReportIOCTL() uintptr {
	return iowr('S', 0x2, unsafe.Sizeof(snpGuestRequestIoctl{}))
}

func iowr(kind uintptr, nr uintptr, size uintptr) uintptr {
	const (
		iocNRBits    = 8
		iocTypeBits  = 8
		iocSizeBits  = 14
		iocNRShift   = 0
		iocTypeShift = iocNRShift + iocNRBits
		iocSizeShift = iocTypeShift + iocTypeBits
		iocDirShift  = iocSizeShift + iocSizeBits
		iocRead      = 2
		iocWrite     = 1
	)
	return ((iocRead | iocWrite) << iocDirShift) | (size << iocSizeShift) | (kind << iocTypeShift) | (nr << iocNRShift)
}

func formatSEVGuestError(op string, err error, exitInfo2 uint64) error {
	fwErr := uint32(exitInfo2)
	vmmErr := uint32(exitInfo2 >> 32)
	return fmt.Errorf("%s failed: %w (fw_error=%d vmm_error=%d)", op, err, fwErr, vmmErr)
}
