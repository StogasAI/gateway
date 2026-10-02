package stogashttp

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestRequestCodecsBoundDecodedOutputAndReleaseScratch(t *testing.T) {
	payload := bytes.Repeat([]byte("private text "), 10000)
	for _, encoding := range []string{"gzip", "deflate", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			var encoded bytes.Buffer
			var writer io.WriteCloser
			switch encoding {
			case "gzip":
				writer = gzip.NewWriter(&encoded)
			case "deflate":
				writer = zlib.NewWriter(&encoded)
			case "br":
				writer = brotli.NewWriter(&encoded)
			case "zstd":
				var err error
				writer, err = zstd.NewWriter(&encoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := writer.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			for _, maximum := range []int{len(payload) - 1, len(payload), len(payload) + 1} {
				admission := newRequestMemoryAdmission()
				lease, ok := admission.acquire(encoded.Cap())
				if !ok {
					t.Fatal("initial reservation")
				}
				decoded, err := decompressRequestBody(encoded.Bytes(), encoding, maximum, lease)
				if maximum < len(payload) {
					if !errors.Is(err, errRequestBodyTooLarge) {
						t.Fatalf("oversize %s=%v", encoding, err)
					}
				} else if err != nil || !bytes.Equal(decoded, payload) {
					t.Fatalf("decoded %s=%d bytes, %v", encoding, len(decoded), err)
				}
				if got := admission.reserved.Load(); got != lease.weight {
					t.Fatalf("decoder retained scratch: total=%d body=%d", got, lease.weight)
				}
				lease.release()
				if admission.reserved.Load() != 0 {
					t.Fatal("decoder leaked memory admission")
				}
			}
		})
	}
}
