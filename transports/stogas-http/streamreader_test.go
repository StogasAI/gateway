package stogashttp

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestSSEStreamReaderCloseUnblocksRead(t *testing.T) {
	reader := newSSEStreamReader(nil)
	readDone := make(chan error, 1)
	go func() {
		_, err := reader.Read(make([]byte, 1))
		readDone <- err
	}()

	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read error = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader close did not unblock read")
	}
}

func TestSSEStreamReaderAccountsOnlyUndeliveredBytes(t *testing.T) {
	admission := &requestMemoryAdmission{}
	delivery := admission.newLease(downstreamDeliveryMemory)
	reader := newSSEStreamReader(delivery)
	event := []byte("data: hello\n\n")

	sent, capacityExceeded := reader.send(t.Context(), event)
	if !sent || capacityExceeded {
		t.Fatalf("send = (%t, %t), want (true, false)", sent, capacityExceeded)
	}
	if got, want := admission.reserved.Load(), int64(len(event)); got != want {
		t.Fatalf("queued reservation = %d, want %d", got, want)
	}

	buffer := make([]byte, 4)
	if _, err := reader.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if got, want := admission.reserved.Load(), int64(len(event)); got != want {
		t.Fatalf("partial-read reservation = %d, want %d", got, want)
	}
	for admission.reserved.Load() != 0 {
		if _, err := reader.Read(buffer); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSSEStreamReaderCloseReleasesQueuedBytes(t *testing.T) {
	admission := &requestMemoryAdmission{}
	delivery := admission.newLease(downstreamDeliveryMemory)
	reader := newSSEStreamReader(delivery)

	if sent, capacityExceeded := reader.send(t.Context(), []byte("queued")); !sent || capacityExceeded {
		t.Fatalf("send = (%t, %t), want (true, false)", sent, capacityExceeded)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if got := admission.reserved.Load(); got != 0 {
		t.Fatalf("close left %d queued bytes reserved", got)
	}
}

func TestSSEStreamReaderReportsDeliveryMemoryCapacity(t *testing.T) {
	admission := &requestMemoryAdmission{}
	admission.reserved.Store(requestMemoryBudgetBytes - 1)
	delivery := admission.newLease(downstreamDeliveryMemory)
	reader := newSSEStreamReader(delivery)

	sent, capacityExceeded := reader.send(t.Context(), []byte("too large"))
	if sent || !capacityExceeded {
		t.Fatalf("send = (%t, %t), want (false, true)", sent, capacityExceeded)
	}
	if got, want := admission.reserved.Load(), requestMemoryBudgetBytes-1; got != want {
		t.Fatalf("failed send changed reservation to %d, want %d", got, want)
	}
}
