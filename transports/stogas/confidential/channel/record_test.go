package channel

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestRecordSizeBeforeAllocation(t *testing.T) {
	for _, size := range []uint32{0, 4, RecordOverhead - 1, MaxRecordBytes + 1, ^uint32(0)} {
		prefix := binary.BigEndian.AppendUint32(nil, size)
		if _, err := RecordSize(prefix); !errors.Is(err, ErrRecord) {
			t.Fatalf("accepted size %d", size)
		}
	}
	for _, prefix := range [][]byte{nil, {0, 0, 0}, {0, 0, 0, 21, 0}} {
		if _, err := RecordSize(prefix); !errors.Is(err, ErrRecord) {
			t.Fatal("accepted non-four-byte length")
		}
	}
}

// Every session has fresh setup keys, so inputs either mask a freshly sealed
// valid start or replace it entirely. Only the unmodified start authenticates.
func FuzzRecordDecoding(f *testing.F) {
	f.Add(false, []byte{})
	f.Add(false, []byte{0, 0, 0, 0, 0, 1})
	f.Add(true, []byte{0, 0, 0, 21})
	f.Fuzz(func(t *testing.T, raw bool, input []byte) {
		if len(input) > MaxRecordBytes+1 {
			return
		}
		session, client := testServerSession(t)
		defer session.Close()
		encoded := input
		if !raw {
			encoder := newRecords(requestMessage(client, 0), client.ID, 0, requestDirection)
			encoded = sealRecord(t, encoder, Metadata, []byte("metadata"))
			for i := range min(len(input), len(encoded)) {
				encoded[i] ^= input[i]
			}
		}
		request, metadata, err := session.AcceptStart(0, encoded)
		if err == nil {
			defer request.Close()
			if string(metadata) != "metadata" {
				t.Fatal("altered start authenticated")
			}
		}
	})
}
