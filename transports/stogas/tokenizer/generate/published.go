package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

// Public, immutable tokenizer data only. No model code or weights are loaded.
// Output uses ordinary UTF-8 bytes so all families share the bounded Go merge
// engine. HF merge order, rather than token ID order, defines pair priorities.
func generatePublished(client *http.Client) {
	manifest, err := os.ReadFile("generate/published.json")
	if err != nil {
		panic(err)
	}
	var assets []struct{ Name, Repo, Revision, File, SHA256 string }
	if err := json.Unmarshal(manifest, &assets); err != nil {
		panic(err)
	}
	for _, asset := range assets {
		var raw []byte
		if cache := os.Getenv("TOKENIZER_SOURCE_CACHE"); cache != "" {
			raw, err = os.ReadFile(cache + "/" + strings.ReplaceAll(asset.Repo, "/", "--") + "/" + asset.File)
		} else {
			var response *http.Response
			response, err = client.Get("https://huggingface.co/" + asset.Repo + "/resolve/" + asset.Revision + "/" + asset.File)
			if err == nil {
				raw, err = io.ReadAll(io.LimitReader(response.Body, 32<<20))
				response.Body.Close()
				if response.StatusCode != 200 {
					panic("tokenizer download failed: " + asset.Name)
				}
			}
		}
		if err != nil {
			panic(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != asset.SHA256 {
			panic("tokenizer hash mismatch: " + asset.Name)
		}
		if asset.File == "tokenizer.json" {
			raw = convertPublished(raw, asset.Name == "gemma")
		}
		var out bytes.Buffer
		z, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
		if err != nil {
			panic(err)
		}
		if _, err = z.Write(raw); err != nil {
			panic(err)
		}
		if err = z.Close(); err != nil {
			panic(err)
		}
		if err = os.WriteFile(asset.Name+".tiktoken.gz", out.Bytes(), 0644); err != nil {
			panic(err)
		}
		fmt.Println(asset.Name, len(raw), out.Len())
	}
	licenses, err := os.ReadFile("generate/licenses.json")
	if err != nil {
		panic(err)
	}
	var sources []struct{ Name, URL, SHA256 string }
	if err = json.Unmarshal(licenses, &sources); err != nil {
		panic(err)
	}
	var notices bytes.Buffer
	notices.WriteString("Published tokenizer data\n\nPinned sources and hashes: generate/published.json.\nThe data is transformed into UTF-8 byte merge priorities for a bounded count-only estimator. Special control tokens are not executed.\nMiniMax M2 and Kimi K2.6 ordinary tokenizers also match the tested M3 and K3 vocabularies; their original licenses below are retained.\n\n")
	for _, source := range sources {
		response, err := client.Get(source.URL)
		if err != nil {
			panic(err)
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || fmt.Sprintf("%x", sha256.Sum256(raw)) != source.SHA256 {
			panic("license integrity check failed: " + source.Name)
		}
		fmt.Fprintf(&notices, "%s\n%s\n\n%s\n\n", source.Name, source.URL, strings.ReplaceAll(string(raw), "\r\n", "\n"))
	}
	noticeText := strings.TrimRight(notices.String(), "\n") + "\n"
	if err = os.WriteFile("NOTICE", []byte(noticeText), 0644); err != nil {
		panic(err)
	}
	// Binary release archives already include the repository's root NOTICE.
	// Preserve its hand-written notices and replace only our generated section.
	const marker = "\n--- Published tokenizer data (generated) ---\n"
	root, err := os.ReadFile("../../../NOTICE")
	if err != nil {
		panic(err)
	}
	prefix, _, _ := strings.Cut(string(root), marker)
	if err = os.WriteFile("../../../NOTICE", []byte(prefix+marker+noticeText), 0644); err != nil {
		panic(err)
	}
}

func convertPublished(raw []byte, sentencePiece bool) []byte {
	var source struct {
		Model struct {
			Type         string
			Vocab        map[string]uint32
			Merges       []json.RawMessage
			IgnoreMerges bool `json:"ignore_merges"`
		}
	}
	if err := json.Unmarshal(raw, &source); err != nil {
		panic(err)
	}
	if source.Model.Type != "BPE" {
		panic("unsupported published model")
	}
	byteMap := map[rune]byte{}
	next := rune(256)
	for i := range 256 {
		r := rune(i)
		if !(i >= 33 && i <= 126 || i >= 161 && i <= 172 || i >= 174) {
			r = next
			next++
		}
		byteMap[r] = byte(i)
	}
	decode := func(s string) string {
		if sentencePiece {
			return strings.ReplaceAll(s, "▁", " ")
		}
		var out []byte
		for _, r := range s {
			b, ok := byteMap[r]
			if !ok {
				return ""
			} // special tokens are deliberately not recognized
			out = append(out, b)
		}
		return string(out)
	}
	ranks := map[string]uint32{}
	type mergeKey struct{ left, right uint32 }
	type mergeValue struct{ rank, id uint32 }
	merges := map[mergeKey]mergeValue{}
	for i := range 256 {
		ranks[string([]byte{byte(i)})] = 0
	}
	// SentencePiece starts with vocabulary runes, before learned merges.
	if sentencePiece {
		for word := range source.Model.Vocab {
			if utf8.RuneCountInString(word) == 1 {
				word = decode(word)
				ranks[word] = 0
			}
		}
	}
	for i, rawPair := range source.Model.Merges {
		var pair []string
		if len(rawPair) > 0 && rawPair[0] == '"' {
			var value string
			if err := json.Unmarshal(rawPair, &value); err != nil {
				panic(err)
			}
			pair = strings.Split(value, " ")
		} else if err := json.Unmarshal(rawPair, &pair); err != nil {
			panic(err)
		}
		if len(pair) != 2 {
			panic("invalid BPE pair")
		}
		merges[mergeKey{source.Model.Vocab[pair[0]], source.Model.Vocab[pair[1]]}] = mergeValue{uint32(i), source.Model.Vocab[pair[0]+pair[1]]}
		word := decode(pair[0] + pair[1])
		if word == "" {
			panic("invalid ordinary BPE word")
		}
		if _, exists := ranks[word]; !exists {
			ranks[word] = uint32(i + 1)
		}
	}
	// HF models with ignore_merges=false cannot take tiktoken's whole-word
	// shortcut merely because a string exists in the vocabulary. Prove this
	// property offline against the published pair-ID rules, once per word.
	if !source.Model.IgnoreMerges {
		for word := range source.Model.Vocab {
			decoded := decode(word)
			rank, exists := ranks[decoded]
			if !exists || utf8.RuneCountInString(word) < 2 {
				continue
			}
			ids := make([]uint32, 0, len(word))
			for _, r := range word {
				id, ok := source.Model.Vocab[string(r)]
				if !ok {
					ids = nil
					break
				}
				ids = append(ids, id)
			}
			for len(ids) > 1 {
				best := -1
				var chosen mergeValue
				for i := 0; i+1 < len(ids); i++ {
					value, ok := merges[mergeKey{ids[i], ids[i+1]}]
					if ok && (best < 0 || value.rank < chosen.rank) {
						best = i
						chosen = value
					}
				}
				if best < 0 {
					break
				}
				ids[best] = chosen.id
				copy(ids[best+1:], ids[best+2:])
				ids = ids[:len(ids)-1]
			}
			if len(ids) != 1 {
				ranks[decoded] = rank | (1 << 31)
			}
		}
	}
	keys := make([]string, 0, len(ranks))
	for key := range ranks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out bytes.Buffer
	for _, key := range keys {
		fmt.Fprintf(&out, "%s %d\n", base64.StdEncoding.EncodeToString([]byte(key)), ranks[key])
	}
	return out.Bytes()
}
