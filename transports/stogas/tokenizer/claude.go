package tokenizer

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Claude47 is an unofficial count reconstruction, not Anthropic's tokenizer.
// The measured vocabulary is shared by the tested Opus 5, Sonnet 5 and
// Fable 5 models. Framing and a calibration margin belong to the request layer.
const Claude47 = "claude47"

//go:embed claude47.json.gz
var claudeData []byte

type claudeNode struct {
	start, end int32
	failure    int32
	lengths    uint32
}
type claudeEdge struct {
	ch   rune
	next int32
}
type ClaudeCounter struct {
	nodes   []claudeNode
	edges   []claudeEdge
	root    [128]int32
	unitBMP [65536]uint8
	bytes   map[string]bool
	units   map[rune]bool
	words   map[string]int
}

var claudeOnce = sync.OnceValue(loadClaude)

func Claude() *ClaudeCounter { return claudeOnce() }

func loadClaude() *ClaudeCounter {
	z, err := gzip.NewReader(bytes.NewReader(claudeData))
	if err != nil {
		panic(err)
	}
	defer z.Close()
	var data struct {
		Pieces []string
		Bytes  []string
	}
	if err := json.NewDecoder(z).Decode(&data); err != nil {
		panic(err)
	}
	type buildingNode struct {
		children map[rune]int32
		lengths  uint32
	}
	building := []buildingNode{{children: make(map[rune]int32)}}
	c := &ClaudeCounter{bytes: make(map[string]bool), units: make(map[rune]bool)}
	for _, piece := range data.Pieces {
		runes := []rune(piece)
		if len(runes) == 0 || len(runes) > 32 {
			panic("invalid embedded Claude vocabulary")
		}
		if len(runes) == 1 && (runes[0] < 0xfdd0 || runes[0] > 0xfdd4) {
			c.units[runes[0]] = true
			c.bytes[piece] = true
		}
		at := int32(0)
		for _, ch := range runes {
			next, ok := building[at].children[ch]
			if !ok {
				next = int32(len(building))
				building[at].children[ch] = next
				building = append(building, buildingNode{children: make(map[rune]int32)})
			}
			at = next
		}
		building[at].lengths |= 1 << (len(runes) - 1)
	}
	for _, word := range data.Bytes {
		b, err := hex.DecodeString(word)
		if err != nil {
			panic(err)
		}
		c.bytes[string(b)] = true
	}
	for _, node := range building {
		start := len(c.edges)
		for ch, next := range node.children {
			c.edges = append(c.edges, claudeEdge{ch, next})
		}
		sort.Slice(c.edges[start:], func(i, j int) bool { return c.edges[start+i].ch < c.edges[start+j].ch })
		c.nodes = append(c.nodes, claudeNode{start: int32(start), end: int32(len(c.edges)), lengths: node.lengths})
	}
	for ch, next := range building[0].children {
		if ch < 128 {
			c.root[ch] = next
		}
	}
	for ch := range c.unitBMP {
		c.unitBMP[ch] = uint8(c.rawUnitCost(rune(ch)))
	}
	// Aho-Corasick enumerates vocabulary suffixes in one pass. The output
	// bitset contains at most 32 lengths, so even repeated-character input
	// cannot create an unbounded match list or allocation.
	queue := make([]int32, 0, len(c.nodes))
	for _, edge := range c.edges[c.nodes[0].start:c.nodes[0].end] {
		queue = append(queue, edge.next)
	}
	for head := 0; head < len(queue); head++ {
		at := queue[head]
		for _, edge := range c.edges[c.nodes[at].start:c.nodes[at].end] {
			fail := c.nodes[at].failure
			next := c.next(fail, edge.ch)
			for next == 0 && fail != 0 {
				fail = c.nodes[fail].failure
				next = c.next(fail, edge.ch)
			}
			c.nodes[edge.next].failure = next
			c.nodes[edge.next].lengths |= c.nodes[next].lengths
			queue = append(queue, edge.next)
		}
	}
	// The measured vocabulary never crosses a closed word boundary. Cache
	// counts for vocabulary words, not customer text. This avoids automaton
	// work for common prose while retaining identical DP for unknown words.
	words := make(map[string]int)
	for _, piece := range data.Pieces {
		plain := strings.TrimPrefix(piece, string(claudeShift))
		if strings.ContainsRune(strings.TrimPrefix(plain, string(claudeBow)), claudeBow) {
			panic("Claude vocabulary crosses word boundary")
		}
		if at := strings.IndexRune(plain, claudeEow); at >= 0 && at != len(plain)-utf8.RuneLen(claudeEow) {
			panic("Claude vocabulary crosses word boundary")
		}
		if !strings.HasPrefix(plain, string(claudeBow)) || !strings.HasSuffix(plain, string(claudeEow)) {
			continue
		}
		word := strings.TrimSuffix(strings.TrimPrefix(plain, string(claudeBow)), string(claudeEow))
		if word == "" || strings.ContainsAny(word, "\ufdd0\ufdd1\ufdd2\ufdd3\ufdd4") {
			continue
		}
		first, n := utf8.DecodeRuneInString(word)
		for _, spelling := range []string{word, string(unicode.ToUpper(first)) + word[n:]} {
			run, rest := nextClaudeRun(spelling)
			if run.kind != claudeWord || rest != "" {
				continue
			}
			count, err := c.Count(spelling)
			if err != nil {
				panic(err)
			}
			words[spelling] = count
		}
	}
	c.words = words
	return c
}

func (c *ClaudeCounter) next(at int32, ch rune) int32 {
	if at == 0 && ch < 128 {
		return c.root[ch]
	}
	n := c.nodes[at]
	if n.end-n.start == 1 {
		edge := c.edges[n.start]
		if edge.ch == ch {
			return edge.next
		}
		return 0
	}
	lo, hi := n.start, n.end
	for lo < hi {
		mid := lo + (hi-lo)/2
		if c.edges[mid].ch < ch {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < n.end && c.edges[lo].ch == ch {
		return c.edges[lo].next
	}
	return 0
}

// A fixed rolling DP replaces ctok's input-sized arrays, token reconstruction
// and unbounded character memo. Each code point has at most 32 match lengths.
type claudeScan struct {
	c            *ClaudeCounter
	best         [33]int
	position     int
	node         int32
	last         rune
	pendingSpace bool
}

func (s *claudeScan) closedWord(count int) {
	if s.pendingSpace {
		s.pendingSpace = false
	}
	// No vocabulary piece crosses this boundary. Only the new origin is
	// reachable; subsequent positions overwrite the ring before reading it.
	s.best[0] = s.best[s.position%33] + count
	s.position = 0
	s.node = 0
	s.last = claudeEow
}

func (s *claudeScan) emit(ch rune) {
	// One seam space between marked words is absorbed. Delay only that one
	// byte, so literal and repeated whitespace remain distinct.
	if s.pendingSpace {
		if ch == claudeShift {
			s.put(ch)
			return
		}
		if ch != claudeBow {
			s.put(' ')
		}
		s.pendingSpace = false
	}
	if ch == ' ' && s.last == claudeEow {
		s.pendingSpace = true
		return
	}
	s.put(ch)
}

func (s *claudeScan) put(ch rune) {
	n := s.position + 1
	best := s.best[(n-1)%33] + s.c.unitCost(ch)
	at := s.c.next(s.node, ch)
	for at == 0 && s.node != 0 {
		s.node = s.c.nodes[s.node].failure
		at = s.c.next(s.node, ch)
	}
	s.node = at
	for lengths := s.c.nodes[at].lengths; lengths != 0; lengths &= lengths - 1 {
		length := bits.TrailingZeros32(lengths) + 1
		best = min(best, s.best[(n-length)%33]+1)
	}
	s.best[n%33] = best
	s.position = n
	s.last = ch
}

func (c *ClaudeCounter) unitCost(ch rune) int {
	if ch < 65536 {
		return int(c.unitBMP[ch])
	}
	return c.rawUnitCost(ch)
}

func (c *ClaudeCounter) rawUnitCost(ch rune) int {
	if ch == claudeBow || ch == claudeEow || ch == claudeShift || ch == 0xfdd4 {
		return 1
	}
	if ch >= 0xe000 && ch <= 0xe004 {
		ch = [...]rune{0xfdd0, 0xfdd1, 0xfdd2, 0xfdd3, 0xfdd4}[ch-0xe000]
	}
	if c.units[ch] {
		return 1
	}
	var raw [4]byte
	n := utf8.EncodeRune(raw[:], ch)
	var dp [5]int
	for end := 1; end <= n; end++ {
		dp[end] = dp[end-1] + 1
		for start := 0; start+1 < end; start++ {
			if c.bytes[string(raw[start:end])] {
				dp[end] = min(dp[end], dp[start]+1)
			}
		}
	}
	return dp[n]
}

func (c *ClaudeCounter) Count(text string) (int, error) {
	return c.CountAtMost(text, 0)
}

func (c *ClaudeCounter) CountAtMost(text string, limit int) (int, error) {
	if !utf8.ValidString(text) {
		return 0, fmt.Errorf("tokenizer input is not valid UTF-8")
	}
	normalized := normalizeClaude(text)
	tail := len(normalized) - len(strings.TrimRight(normalized, "\n"))
	normalized = normalized[:len(normalized)-tail]
	scan := claudeScan{c: c}
	previous, beforePrevious := claudeRun{}, claudeRun{}
	current, rest := nextClaudeRun(normalized)
	for current.text != "" {
		next, remaining := nextClaudeRun(rest)
		emitClaudeRun(&scan, beforePrevious, previous, current, next)
		// Future pieces can bridge only 32 code points. The minimum across
		// this DP window is a lower bound; the current endpoint alone isn't.
		if limit > 0 && scan.best[scan.position%33] >= limit && (scan.position >= 32 || scan.position == 0) {
			lower := scan.best[0]
			if scan.position != 0 {
				for _, v := range scan.best[1:] {
					lower = min(lower, v)
				}
			}
			if lower >= limit {
				return limit, nil
			}
		}
		beforePrevious, previous, current, rest = previous, current, next, remaining
	}
	if scan.pendingSpace {
		scan.put(' ')
	}
	count := scan.best[scan.position%33]
	if tail > 0 {
		end := claudeScan{c: c}
		for range tail + 2 {
			end.put('\n')
		}
		count += max(0, end.best[end.position%33]-1)
	}
	if limit > 0 {
		count = min(count, limit)
	}
	return count, nil
}
