// Command generate pins and compresses the public tiktoken vocabularies.
// It is a development tool; Gateway requests never download tokenizer data.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	client := &http.Client{Timeout: time.Minute}
	if len(os.Args) > 1 && os.Args[1] == "published" {
		generatePublished(client)
		return
	}
	generateClaude(client)
	for _, asset := range []struct{ name, hash string }{
		{"cl100k_base", "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7"},
		{"o200k_base", "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d"},
	} {
		response, err := client.Get("https://openaipublic.blob.core.windows.net/encodings/" + asset.name + ".tiktoken")
		if err != nil {
			panic(err)
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		response.Body.Close()
		if err != nil {
			panic(err)
		}
		if response.StatusCode != 200 || fmt.Sprintf("%x", sha256.Sum256(raw)) != asset.hash {
			panic("vocabulary integrity check failed: " + asset.name)
		}
		var out bytes.Buffer
		compressed, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
		if err != nil {
			panic(err)
		}
		if _, err = compressed.Write(raw); err != nil {
			panic(err)
		}
		if err = compressed.Close(); err != nil {
			panic(err)
		}
		if err = os.WriteFile(asset.name+".tiktoken.gz", out.Bytes(), 0644); err != nil {
			panic(err)
		}
	}
}
