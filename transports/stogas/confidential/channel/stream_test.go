package channel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func requestWire(t *testing.T, root, id [32]byte, initialPublic [referencePublicBytes]byte, number uint64, body []byte) []byte {
	t.Helper()
	encoder, err := newRecords(requestMessageFor(root, number, initialPublic), id, number, requestDirection)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.fail(ErrClosed)
	encoded := append([]byte(requestHeader), id[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, number)
	encoded = append(encoded, sealRecord(t, encoder, Metadata, []byte(`{"method":"POST","path":"/v1/chat/completions"}`))...)
	for len(body) != 0 {
		n := min(len(body), MaxRecordPlaintext)
		encoded = append(encoded, sealRecord(t, encoder, Data, body[:n])...)
		body = body[n:]
	}
	return append(encoded, sealRecord(t, encoder, Finished, nil)...)
}

type fragmentReader struct {
	data []byte
	size int
}

func (r *fragmentReader) Read(output []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(output, r.data[:min(len(r.data), r.size)])
	r.data = r.data[n:]
	return n, nil
}

func TestStreamOwnershipFragmentationAndCompletion(t *testing.T) {
	store, retained := storeFixture(t, &setupReporter{})
	id, root, initialPublic := openStoredSession(t, store)
	defer clear(root[:])
	body := bytes.Repeat([]byte("payload"), MaxRecordPlaintext/4)
	for index, fragment := range []int{1, 3, 4096, MaxRecordBytes * 2} {
		wire := requestWire(t, root, id, initialPublic, uint64(index), body)
		incoming, metadata, err := Accept(store, &fragmentReader{data: wire, size: fragment})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(metadata, []byte("/v1/chat/completions")) {
			t.Fatal("lost authenticated metadata")
		}
		if store.Diagnostics().Active != 1 {
			t.Fatal("request does not own its session")
		}
		decoded, err := io.ReadAll(incoming)
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatalf("body fragmentation %d: %v", fragment, err)
		}
		var response bytes.Buffer
		outgoing := NewOutgoing(incoming.State, &response)
		if err := outgoing.Keepalive(); err != nil {
			t.Fatal(err)
		}
		if err := outgoing.Metadata([]byte(`{"status":200}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := outgoing.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := outgoing.Finish(); err != nil {
			t.Fatal(err)
		}
		decoder, err := responseRecordsFor(root, id, initialPublic, uint64(index))
		if err != nil {
			t.Fatal(err)
		}
		var actual []byte
		for response.Len() > 0 {
			size, err := RecordSize(response.Bytes()[:4])
			if err != nil {
				t.Fatal(err)
			}
			kind, content, err := decoder.open(response.Next(size))
			if err != nil {
				t.Fatal(err)
			}
			if kind == Data {
				actual = append(actual, content...)
			}
		}
		if !bytes.Equal(actual, body) || decoder.complete() != nil {
			t.Fatal("response is incomplete")
		}
		decoder.fail(ErrClosed)
		if err := outgoing.Finish(); !errors.Is(err, ErrClosed) {
			t.Fatal("reused completed writer")
		}
		incoming.Close()
		incoming.Close()
		if store.Diagnostics().Active != 0 || retained.Load() != 1 {
			t.Fatal("stream cleanup damaged session ownership")
		}
	}
}

func TestStreamRejectsTruncationTrailingDataAndRepeatedStarts(t *testing.T) {
	store, _ := storeFixture(t, &setupReporter{})
	id, root, initialPublic := openStoredSession(t, store)
	defer clear(root[:])
	// Test transport framing boundaries; the core exhaustively tests all byte truncations.
	original := requestWire(t, root, id, initialPublic, 0, []byte("body"))
	ends := []int{0, 1, RequestPrefixBytes - 1, RequestPrefixBytes}
	for start := RequestPrefixBytes; start < len(original); {
		length, _ := RecordSize(original[start : start+4])
		ends = append(ends, start+1, start+3, start+4, start+length-17, start+length-1)
		if start == RequestPrefixBytes {
			ends = append(ends, start+5, start+6, start+6+MaxRatchetHeaderBytes-1)
		}
		start += length
		if start < len(original) {
			ends = append(ends, start)
		}
	}
	for number, end := range ends {
		wire := requestWire(t, root, id, initialPublic, uint64(number), []byte("body"))
		incoming, _, err := Accept(store, bytes.NewReader(wire[:end]))
		if err == nil {
			_, err = io.ReadAll(incoming)
			incoming.Close()
		}
		if err == nil {
			t.Fatalf("accepted truncation at %d", end)
		}
	}
	for index, mutation := range []func([]byte) []byte{
		func(wire []byte) []byte { return append(wire, 0) },
		func(wire []byte) []byte { wire[len(wire)-1] ^= 1; return wire },
	} {
		wire := mutation(requestWire(t, root, id, initialPublic, uint64(len(ends)+index), []byte("body")))
		incoming, _, err := Accept(store, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(incoming); err == nil {
			t.Fatal("accepted malformed completion")
		}
		incoming.Close()
	}
	wire := requestWire(t, root, id, initialPublic, uint64(len(ends)+2), nil)
	incoming, _, err := Accept(store, bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Close()
	if duplicate, _, err := Accept(store, bytes.NewReader(wire)); !errors.Is(err, ErrReplay) || duplicate != nil {
		t.Fatalf("duplicate start created another response owner: %v", err)
	}
	store.Remove(id)
	if _, err := io.ReadAll(incoming); err != nil {
		t.Fatal("removal interrupted an admitted request", err)
	}
	if store.Diagnostics().Retained != 1 {
		t.Fatal("removal released active state")
	}
	incoming.Close()
	if store.Diagnostics().Retained != 0 {
		t.Fatal("finished request retained retired state")
	}
}

type shortWriter struct{ calls int }

func (w *shortWriter) Write(data []byte) (int, error) { w.calls++; return len(data) - 1, nil }

func TestOutgoingDoesNotResumeAfterPartialWrite(t *testing.T) {
	store, _ := storeFixture(t, &setupReporter{})
	id, root, initialPublic := openStoredSession(t, store)
	defer clear(root[:])
	incoming, _, err := Accept(store, bytes.NewReader(requestWire(t, root, id, initialPublic, 0, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Close()
	writer := &shortWriter{}
	outgoing := NewOutgoing(incoming.State, writer)
	if err := outgoing.Metadata([]byte(`{"status":200}`)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if _, err := outgoing.Write([]byte("body")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if err := outgoing.Finish(); !errors.Is(err, io.ErrShortWrite) || writer.calls != 1 {
		t.Fatal("resumed failed writer")
	}
}
