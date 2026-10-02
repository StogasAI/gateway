package tokenizer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

//go:generate go run ./generate

// Vocabularies from OpenAI tiktoken (MIT); see LICENSE. The generator verifies
// the upstream SHA-256 before writing deterministic, embedded build assets.
//
//go:embed cl100k_base.tiktoken.gz
var cl100kData []byte

//go:embed o200k_base.tiktoken.gz
var o200kData []byte

const Cl100kBase = "cl100k_base"
const O200kBase = "o200k_base"

var cl100k = sync.OnceValue(func() *Counter { return load(Cl100kBase, cl100kData) })
var o200k = sync.OnceValue(func() *Counter { return load(O200kBase, o200kData) })

func Get(encoding string) (*Counter, error) {
	switch encoding {
	case Cl100kBase:
		return cl100k(), nil
	case O200kBase:
		return o200k(), nil
	default:
		if get, ok := publishedCounters[encoding]; ok {
			return get(), nil
		}
		return nil, fmt.Errorf("unsupported tokenizer encoding: %s", encoding)
	}
}

func load(name string, compressed []byte) *Counter {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		panic(err)
	}
	defer reader.Close()
	c := &Counter{name: name, ranks: make(map[string]uint32)}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		word, number, ok := strings.Cut(scanner.Text(), " ")
		if !ok {
			panic("invalid embedded tokenizer vocabulary")
		}
		decoded, err := base64.StdEncoding.DecodeString(word)
		if err != nil {
			panic(err)
		}
		rank, err := strconv.ParseUint(number, 10, 32)
		if err != nil {
			panic(err)
		}
		c.ranks[string(decoded)] = uint32(rank)
		if len(decoded) == 2 {
			c.pairRanks[uint16(decoded[0])<<8|uint16(decoded[1])] = (uint32(rank) &^ noWholeTokenShortcut) + 1
		}
		c.maxTokenBytes = max(c.maxTokenBytes, len(decoded))
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	return c
}
