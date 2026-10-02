package stogashttp

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Brotli's format permits a 24-bit history window and three groups of at most
// 256 Huffman tables. The pinned decoder uses at most 1,528 four-byte entries
// per table. Include overlapping growth and small context/lookup buffers.
// This temporary charge ends before inference; it is not a concurrency quota.
const brotliDecoderReservation = 2*((1<<24)+(3*256*1528*4)) + (64 << 10)

func decompressRequestBody(encoded []byte, encoding string, maximum int, lease *requestMemoryLease) ([]byte, error) {
	if encoding == "zstd" {
		return decodeZstdBody(encoded, maximum, lease)
	}
	raw := bytes.NewReader(encoded)
	var decoded io.Reader
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(raw)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		decoded = reader
	case "deflate":
		reader, err := zlib.NewReader(raw)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		decoded = reader
	case "br":
		scratch := lease.admission.newLease(requestBodyMemory)
		if !scratch.grow(brotliDecoderReservation) {
			return nil, errRequestMemoryCapacity
		}
		defer scratch.release()
		decoded = brotli.NewReader(raw)
	default:
		return nil, errors.New("unsupported content encoding")
	}
	// Decoder state and its reference to encoded bytes end before the caller
	// releases the compressed-body reservation and enters provider processing.
	return readAdmittedBody(decoded, maximum, lease, cap(encoded))
}

func decodeZstdBody(encoded []byte, maximum int, lease *requestMemoryLease) ([]byte, error) {
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(uint64(maximum)), zstd.WithDecodeAllCapLimit(true))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	var output []byte
	for capacity := min(32<<10, maximum); ; capacity = min(maximum, capacity*2) {
		if !lease.resize(cap(encoded) + cap(output) + capacity) {
			clear(output)
			return nil, errRequestMemoryCapacity
		}
		clear(output)
		output = make([]byte, 0, capacity)
		if !lease.resize(cap(encoded) + cap(output)) {
			panic("shrinking a live body lease failed")
		}
		decoded, err := decoder.DecodeAll(encoded, output)
		if err == nil {
			return decoded, nil
		}
		clear(output[:cap(output)])
		if !errors.Is(err, zstd.ErrDecoderSizeExceeded) {
			return nil, err
		}
		if capacity == maximum {
			return nil, errRequestBodyTooLarge
		}
	}
}
