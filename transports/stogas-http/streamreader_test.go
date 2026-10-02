package stogashttp

import (
	"bytes"
	"context"
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
	if string(buffer) != "data" || !bytes.Equal(event[:4], make([]byte, 4)) || string(event[4:]) != ": hello\n\n" {
		t.Fatal("partial read did not clear only the consumed bytes")
	}
	if got, want := admission.reserved.Load(), int64(len(event)); got != want {
		t.Fatalf("partial-read reservation = %d, want %d", got, want)
	}
	for admission.reserved.Load() != 0 {
		if _, err := reader.Read(buffer); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(event, make([]byte, len(event))) {
		t.Fatal("completed read retained plaintext")
	}
}

func TestSSEStreamReaderCloseReleasesQueuedBytes(t *testing.T) {
	admission := &requestMemoryAdmission{}
	delivery := admission.newLease(downstreamDeliveryMemory)
	reader := newSSEStreamReader(delivery)

	current, queued := []byte("partially read"), []byte("queued")
	if sent, _ := reader.send(t.Context(), current); !sent {
		t.Fatal("send failed")
	}
	if _, err := reader.Read(make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	if sent, capacityExceeded := reader.send(t.Context(), queued); !sent || capacityExceeded {
		t.Fatalf("send = (%t, %t), want (true, false)", sent, capacityExceeded)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if got := admission.reserved.Load(); got != 0 {
		t.Fatalf("close left %d queued bytes reserved", got)
	}
	if !bytes.Equal(current, make([]byte, len(current))) || !bytes.Equal(queued, make([]byte, len(queued))) {
		t.Fatal("close retained consumed or queued plaintext")
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

func TestSSEStreamRetainsLeaseDuringBlockedWriteAndClose(t *testing.T) {
	admission := newRequestMemoryAdmission()
	reader := newSSEStreamReader(admission.newLease(downstreamDeliveryMemory))
	data := []byte("data: retained\n\n")
	if sent, _ := reader.send(t.Context(), data); !sent {
		t.Fatal("send failed")
	}
	writer := &blockedFrameWriter{started: make(chan struct{}), release: make(chan struct{})}
	copied := make(chan error, 1)
	go func() { _, err := io.Copy(writer, reader); copied <- err }()
	<-writer.started
	closed := make(chan struct{})
	go func() { _ = reader.Close(); close(closed) }()
	<-reader.closed()
	if got := admission.reserved.Load(); got != int64(len(data)) {
		t.Fatalf("blocked write lost its lease: %d", got)
	}
	if string(data) != "data: retained\n\n" {
		t.Fatal("close cleared a frame still in use by Write")
	}
	select {
	case <-closed:
		t.Fatal("close released a frame still used by Write")
	default:
	}
	finished := make(chan struct{})
	go func() { reader.done(); close(finished) }()
	close(writer.release)
	if err := <-copied; err != nil {
		t.Fatal(err)
	}
	<-closed
	<-finished
	if got := admission.reserved.Load(); got != 0 {
		t.Fatalf("finished stream retained %d bytes", got)
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("completed write retained plaintext")
	}
}

func TestSSERejectedFramesAndLateDeliveryAreCleared(t *testing.T) {
	for _, mode := range []string{"cancelled", "closed", "full", "unreserved-cancelled", "unreserved-full", "unreserved-closed"} {
		t.Run(mode, func(t *testing.T) {
			reader := newSSEStreamReader(nil)
			data := []byte("private frame")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var sent bool
			switch mode {
			case "cancelled":
				cancel()
				sent, _ = reader.send(ctx, data)
			case "closed":
				_ = reader.Close()
				sent, _ = reader.send(ctx, data)
			case "full":
				reader.trySend([]byte("queued"))
				sent, _ = reader.trySend(data)
			case "unreserved-cancelled":
				reader.trySend([]byte("queued"))
				cancel()
				sent = reader.sendUnreserved(ctx, data)
			case "unreserved-full":
				reader.trySend([]byte("queued"))
				sent = reader.trySendUnreserved(data)
			case "unreserved-closed":
				_ = reader.Close()
				// Either select arm may win; producer completion must also clear
				// a frame queued after the consumer finished.
				sent = reader.trySendUnreserved(data)
			}
			if sent && mode != "unreserved-closed" {
				t.Fatal("rejected frame was delivered")
			}
			reader.done()
			_ = reader.Close()
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Fatal("rejected frame retained plaintext")
			}
		})
	}
}

func TestSSECapacityFallbackPreservesErrorFrame(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		admission := &requestMemoryAdmission{budget: 1}
		reader := newSSEStreamReader(admission.newLease(downstreamDeliveryMemory))
		ctx, cancel := context.WithCancel(t.Context())
		if cancelled {
			cancel()
		}
		body := []byte(`{"error":"private detail"}`)
		if !reader.sendErrorEvent(ctx, "", body) {
			t.Fatal("bounded error fallback was rejected")
		}
		reader.done()
		got, err := io.ReadAll(reader)
		cancel()
		if err != nil || !bytes.Equal(got, frameSSEEvent("", body)) || admission.reserved.Load() != 0 {
			t.Fatal("capacity fallback changed the error or retained its reservation")
		}
	}
}

func TestSSEWriteFailureClearsRemainingFrame(t *testing.T) {
	for _, failure := range []error{nil, io.ErrClosedPipe} {
		reader := newSSEStreamReader(nil)
		frame := []byte("private response")
		reader.send(t.Context(), frame)
		reader.done()
		writer := shortFrameWriter{failure: failure}
		n, err := reader.WriteTo(&writer)
		want := failure
		if want == nil {
			want = io.ErrShortWrite
		}
		if n != 3 || !errors.Is(err, want) || writer.received != "pri" || !bytes.Equal(frame, make([]byte, len(frame))) {
			t.Fatal("failed write changed delivered bytes or retained its frame")
		}
	}
}

type shortFrameWriter struct {
	failure  error
	received string
}

func (w *shortFrameWriter) Write(data []byte) (int, error) {
	w.received = string(data[:3])
	return 3, w.failure
}

type blockedFrameWriter struct{ started, release chan struct{} }

func (w *blockedFrameWriter) Write(data []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(data), nil
}
