// Package channel carries binary encrypted sessions. The public Rust verifier
// owns cryptography, ratcheting, record rules and authenticated request admission.
package channel

import (
	"encoding/binary"
	verifier "github.com/StogasAI/verifier/go"
)

const (
	MaxRecordBytes        = 64 * 1024
	RecordOverhead        = 4 + 1 + 16
	MaxRecordPlaintext    = MaxRecordBytes - RecordOverhead
	MaxRecords            = 1 << 24
	MaxRequestBodyBytes   = 128 * 1024 * 1024
	MaxResponseBodyBytes  = 64 * 1024 * 1024
	MaxRatchetHeaderBytes = 16 + 2352 + 16
	MaxRequestWireBytes   = RequestPrefixBytes + MaxRequestBodyBytes + MaxRecordPlaintext + MaxRecords*RecordOverhead + 2 + MaxRatchetHeaderBytes
	MaxResponseWireBytes  = MaxResponseBodyBytes + MaxRecordPlaintext + MaxRecords*RecordOverhead + 2 + MaxRatchetHeaderBytes
)

var (
	ErrRecord         = verifier.ErrChannelRecord
	ErrAuthentication = verifier.ErrChannelAuthentication
	ErrRecordLimit    = verifier.ErrChannelLimit
	ErrClosed         = verifier.ErrClosed
	ErrTruncated      = verifier.ErrChannelTruncated
)

type Kind byte

const (
	Metadata  Kind = 1
	Data      Kind = 2
	Finished  Kind = 3
	Keepalive Kind = 4
)

// RecordSize bounds the transport's read allocation before calling the core.
func RecordSize(prefix []byte) (int, error) {
	if len(prefix) != 4 {
		return 0, ErrRecord
	}
	size := binary.BigEndian.Uint32(prefix)
	if size < RecordOverhead || size > MaxRecordBytes {
		return 0, ErrRecord
	}
	return int(size), nil
}
