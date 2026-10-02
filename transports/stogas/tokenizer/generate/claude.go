package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// MIT-licensed measured vocabulary, pinned independently of mutable upstream.
func generateClaude(client *http.Client) {
	const url = "https://raw.githubusercontent.com/sanderland/ctok/ad78ea15a1febf983b379475b20f5a2b0d2ebe76/ctok/data/pieces_v4_7.json"
	response, err := client.Get(url)
	if err != nil {
		panic(err)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	response.Body.Close()
	if err != nil {
		panic(err)
	}
	if response.StatusCode != 200 || fmt.Sprintf("%x", sha256.Sum256(raw)) != "a785fc240010c855f3d9a498fbd422ee389752dd151f1d5eef57ca8c85c19993" {
		panic("Claude vocabulary integrity check failed")
	}
	var source struct {
		Tokens map[string]map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &source); err != nil {
		panic(err)
	}
	markers := strings.NewReplacer("⟨bow⟩", "\ufdd0", "⟨eow⟩", "\ufdd1", "⟨shift⟩", "\ufdd3", "⟨caps⟩", "\ufdd4")
	escape := regexp.MustCompile(`⟨0x([0-9a-fA-F]{2})⟩`)
	pieces := map[string]bool{}
	var data struct {
		Pieces []string `json:"pieces"`
		Bytes  []string `json:"bytes"`
	}
	for group, entries := range source.Tokens {
		for piece := range entries {
			if group == "bytes_fallback" {
				data.Bytes = append(data.Bytes, piece)
				continue
			}
			piece = escape.ReplaceAllStringFunc(markers.Replace(piece), func(s string) string {
				b, err := hex.DecodeString(s[len("⟨0x") : len(s)-len("⟩")])
				if err != nil {
					panic(err)
				}
				return string(b)
			})
			if !utf8.ValidString(piece) || utf8.RuneCountInString(piece) > 32 {
				panic("unsupported Claude vocabulary piece")
			}
			pieces[piece] = true
			if group == "contractions" {
				pieces[piece+"\ufdd1"] = true
			}
		}
	}
	for piece := range pieces {
		data.Pieces = append(data.Pieces, piece)
	}
	sort.Strings(data.Pieces)
	sort.Strings(data.Bytes)
	encoded, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	var out bytes.Buffer
	z, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		panic(err)
	}
	if _, err := z.Write(encoded); err != nil {
		panic(err)
	}
	if err := z.Close(); err != nil {
		panic(err)
	}
	if err := os.WriteFile("claude47.json.gz", out.Bytes(), 0644); err != nil {
		panic(err)
	}
}
