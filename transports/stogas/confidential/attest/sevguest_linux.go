package attest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type SEVGuestDevice struct {
	Path string
	VMPL uint32
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

	// Vendor certificates and CRLs come from the verified evidence bundle.
	// A session quote needs only SNP_GET_REPORT, never an extended cert-table call.
	report, err := a.getReport(file.Fd(), reportData)
	if err != nil {
		return nil, err
	}
	return EncodeEnvelope(Envelope{
		Schema:   EnvelopeSchemaV1,
		Provider: ProviderSEVGuest,
		Report:   base64.RawURLEncoding.EncodeToString(report),
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

type snpReportReq struct {
	UserData [64]byte
	VMPL     uint32
	Reserved [28]byte
}

type snpReportResp struct {
	Data [4000]byte
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
