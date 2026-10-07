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

func FuzzRecordDecoding(f *testing.F) {
	root, id := [32]byte{1}, [32]byte{2}
	encoder, _ := newRecords(requestMessage(root, 0), id, 0, requestDirection)
	valid, _ := encoder.seal(Metadata, []byte("metadata"))
	f.Add(valid)
	f.Add([]byte{0, 0, 0, 21})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxRecordBytes+1 {
			return
		}
		session := testServerSession(root, id)
		defer session.Close()
		request, metadata, err := session.AcceptStart(0, input)
		if err == nil {
			defer request.Close()
			if len(metadata) == 0 || len(metadata) > MaxRecordPlaintext {
				t.Fatal("invalid authenticated metadata")
			}
		}
	})
}
