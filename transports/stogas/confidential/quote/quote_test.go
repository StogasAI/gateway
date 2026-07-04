package quote

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

func testPayload() reportdata.Payload {
	return reportdata.Payload{
		ReleaseMeasurement: strings.Repeat("a", 64),
		Region:             "global",
		CatalogHash:        strings.Repeat("b", 64),
		TLSSPKISHA256:      strings.Repeat("c", 64),
		ActiveCertSHA256:   strings.Repeat("d", 64),
		AcceptedCertSHA256: []string{strings.Repeat("d", 64)},
		HPKEPublicKey:      "aHBrZQ",
		Ed25519PublicKey:   "ZWQyNTUxOQ",
		Drand: reportdata.Drand{
			Round:      1,
			Randomness: strings.Repeat("e", 64),
			Signature:  strings.Repeat("f", 96),
		},
	}
}

func TestCurrentRefreshesOnDemandWhenEmpty(t *testing.T) {
	var calls atomic.Int32
	manager, err := New(AttesterFunc(func(ctx context.Context, reportData [64]byte) ([]byte, error) {
		calls.Add(1)
		return []byte("quote"), nil
	}), func(ctx context.Context) (reportdata.Payload, error) {
		return testPayload(), nil
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Quote) != "quote" {
		t.Fatalf("unexpected quote: %q", snapshot.Quote)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one quote generation, got %d", calls.Load())
	}
	again, err := manager.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Quote) != "quote" {
		t.Fatalf("unexpected cached quote: %q", again.Quote)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected cached quote read, got %d generations", calls.Load())
	}
}

func TestRefreshFailureKeepsLastValidQuote(t *testing.T) {
	fail := atomic.Bool{}
	manager, err := New(AttesterFunc(func(ctx context.Context, reportData [64]byte) ([]byte, error) {
		if fail.Load() {
			return nil, errors.New("psp unavailable")
		}
		return []byte("valid-quote"), nil
	}), func(ctx context.Context) (reportdata.Payload, error) {
		return testPayload(), nil
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := manager.Refresh(context.Background()); err == nil {
		t.Fatal("expected refresh failure")
	}
	snapshot, err := manager.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Quote) != "valid-quote" {
		t.Fatalf("last valid quote was not preserved: %q", snapshot.Quote)
	}
	if manager.LastError() == nil {
		t.Fatal("expected last error to be recorded")
	}
}

func TestBackgroundRefreshesAtConfiguredInterval(t *testing.T) {
	var calls atomic.Int32
	manager, err := New(AttesterFunc(func(ctx context.Context, reportData [64]byte) ([]byte, error) {
		count := calls.Add(1)
		return []byte{byte(count)}, nil
	}), func(ctx context.Context) (reportdata.Payload, error) {
		return testPayload(), nil
	}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if calls.Load() >= 2 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected background refreshes, got %d calls", calls.Load())
}
