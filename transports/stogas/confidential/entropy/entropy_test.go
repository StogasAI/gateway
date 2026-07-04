package entropy

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestProbeAcceptsNonZeroCryptographicBytes(t *testing.T) {
	if err := Probe(strings.NewReader(strings.Repeat("\x01", ProbeBytes))); err != nil {
		t.Fatalf("expected entropy probe to pass: %v", err)
	}
}

func TestProbeRejectsAllZeroBytes(t *testing.T) {
	if err := Probe(bytes.NewReader(make([]byte, ProbeBytes))); err == nil || !strings.Contains(err.Error(), "all-zero") {
		t.Fatalf("expected all-zero entropy probe error, got %v", err)
	}
}

func TestProbeRejectsShortRead(t *testing.T) {
	if err := Probe(strings.NewReader("short")); err == nil || !strings.Contains(err.Error(), "read cryptographic randomness") {
		t.Fatalf("expected short entropy probe error, got %v", err)
	}
}

func TestWaitReturnsWhenContextIsCanceled(t *testing.T) {
	unblock := make(chan struct{})
	reader := blockingReader{unblock: unblock}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Wait(ctx, reader)
	close(unblock)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("expected context cancellation error, got %v", err)
	}
}

type blockingReader struct {
	unblock <-chan struct{}
}

func (r blockingReader) Read(p []byte) (int, error) {
	<-r.unblock
	return 0, io.ErrUnexpectedEOF
}
