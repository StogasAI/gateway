package entropy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const ProbeBytes = 64

func Probe(reader io.Reader) error {
	if reader == nil {
		reader = rand.Reader
	}
	buf := make([]byte, ProbeBytes)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return fmt.Errorf("read cryptographic randomness: %w", err)
	}
	nonzero := false
	for _, value := range buf {
		if value != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		return errors.New("cryptographic randomness probe returned all-zero bytes")
	}
	return nil
}

func Wait(ctx context.Context, reader io.Reader) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan error, 1)
	go func() {
		done <- Probe(reader)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("cryptographic randomness not ready: %w", ctx.Err())
	}
}
