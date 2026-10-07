package channel

import "encoding/binary"

const (
	requestHeader      = "STGS\x01\x03"
	RequestPrefixBytes = len(requestHeader) + 32 + 8
)

// ParseRequestPrefix reads only the fixed dispatch prefix. Its values select
// the session and directional key; AcceptStart must authenticate before any
// operation, including session close. HTTP routing headers grant no authority.
func ParseRequestPrefix(prefix []byte) ([32]byte, uint64, error) {
	if len(prefix) != RequestPrefixBytes || string(prefix[:len(requestHeader)]) != requestHeader {
		return [32]byte{}, 0, ErrRecord
	}
	return [32]byte(prefix[len(requestHeader) : len(requestHeader)+32]), binary.BigEndian.Uint64(prefix[len(requestHeader)+32:]), nil
}
