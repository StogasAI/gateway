//go:build !linux

package attest

import (
	"context"
	"errors"
)

type SEVGuestDevice struct {
	Path            string
	VMPL            uint32
	CertBufferBytes int
}

func (a SEVGuestDevice) Quote(ctx context.Context, reportData [64]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("SEV guest device attester requires linux")
}
