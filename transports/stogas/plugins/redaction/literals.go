package redaction

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxLiterals          = 1000
	MaxLiteralBytes      = 256
	MaxLiteralTotalBytes = 65536
)

// Literal is text, not an expression. Case folding affects ASCII letters only.
// A nil WholeWord requires word boundaries. Fuzzy permits one ASCII edit,
// including an adjacent transposition, and always requires word boundaries.
type Literal struct {
	Text       string `json:"text"`
	IgnoreCase bool   `json:"ignoreCase"`
	WholeWord  *bool  `json:"wholeWord,omitempty"`
	Fuzzy      bool   `json:"fuzzy"`
}

func ValidateLiterals(rules []Literal) error {
	if len(rules) > MaxLiterals {
		return policyError("literal count exceeds %d", MaxLiterals)
	}
	total := 0
	for _, rule := range rules {
		if len(rule.Text) == 0 || len(rule.Text) > MaxLiteralBytes || !utf8.ValidString(rule.Text) {
			return policyError("literal text must be valid UTF-8 and 1–256 bytes")
		}
		total += len(rule.Text)
		if total > MaxLiteralTotalBytes {
			return policyError("literal text exceeds %d bytes", MaxLiteralTotalBytes)
		}
		if rule.Fuzzy {
			if len(rule.Text) < 8 || len(rule.Text) > 64 || !wholeWord(rule) ||
				!asciiWord(rule.Text[0]) || !asciiWord(rule.Text[len(rule.Text)-1]) {
				return policyError("fuzzy literals require 8–64 ASCII bytes and word boundaries")
			}
			for _, b := range []byte(rule.Text) {
				if b < 32 || b > 126 {
					return policyError("fuzzy literals require printable ASCII")
				}
			}
		}
	}
	return nil
}

type literalAnchor struct{ rule, offset, length int }
type literalEdge struct {
	b     byte
	state int
}
type literalNode struct {
	edges        []literalEdge
	anchors      []literalAnchor
	fail, output int
}

// A compact Aho–Corasick trie uses failure/output links rather than copying
// suffix match lists or allocating a states×alphabet DFA. Both compile memory
// and retained memory are linear in the bounded seed text. All overlaps remain
// visible. Candidate verification, including rejected candidates, is metered.
type literalMatcher struct {
	nodes      []literalNode
	root       [256]int
	rules      []Literal
	bytes      int64
	minWordRun int
}

func asciiFold(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
func asciiWord(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || asciiFold(b) >= 'a' && asciiFold(b) <= 'z'
}
func wordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) || r == '_'
}
func wholeWord(rule Literal) bool { return rule.WholeWord == nil || *rule.WholeWord }
func folded(text string) string {
	b := []byte(text)
	for i := range b {
		b[i] = asciiFold(b[i])
	}
	return string(b)
}

func compileLiterals(rules []Literal) (*literalMatcher, error) {
	if err := ValidateLiterals(rules); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, nil
	}
	m := &literalMatcher{nodes: []literalNode{{}}, minWordRun: MaxLiteralBytes}
	// Copy caller-owned values, including optional pointers. No request data is retained.
	for _, rule := range rules {
		rule.Text = strings.Clone(rule.Text)
		if rule.WholeWord != nil {
			value := *rule.WholeWord
			rule.WholeWord = &value
		}
		m.rules = append(m.rules, rule)
	}
	type transition struct {
		state int
		b     byte
	}
	transitions := make(map[transition]int)
	add := func(seed string, a literalAnchor) {
		state := 0
		wordRun, longestRun := 0, 0
		for i := range len(seed) {
			if asciiWord(seed[i]) {
				wordRun++
				longestRun = max(longestRun, wordRun)
			} else {
				wordRun = 0
			}
			key := transition{state, asciiFold(seed[i])}
			next, ok := transitions[key]
			if !ok {
				next = len(m.nodes)
				transitions[key] = next
				m.nodes = append(m.nodes, literalNode{})
				m.nodes[state].edges = append(m.nodes[state].edges, literalEdge{key.b, next})
			}
			state = next
		}
		m.minWordRun = min(m.minWordRun, longestRun)
		m.nodes[state].anchors = append(m.nodes[state].anchors, a)
	}
	frequency := make(map[string]int)
	for _, rule := range rules {
		if rule.Fuzzy {
			text := folded(rule.Text)
			for cut := 4; cut <= len(text)-4; cut++ {
				frequency[text[:cut]]++
				frequency[text[cut:]]++
			}
		}
	}
	for id, rule := range rules {
		if !rule.Fuzzy {
			add(rule.Text, literalAnchor{id, 0, len(rule.Text)})
			continue
		}
		text := folded(rule.Text)
		cut := len(text) / 2
		best := max(frequency[text[:cut]], frequency[text[cut:]])
		for candidate := 4; candidate <= len(text)-4; candidate++ {
			score := max(frequency[text[:candidate]], frequency[text[candidate:]])
			if score < best || score == best && abs(2*candidate-len(text)) < abs(2*cut-len(text)) {
				cut, best = candidate, score
			}
		}
		add(text[:cut], literalAnchor{id, 0, cut})
		add(text[cut:], literalAnchor{id, cut, len(text) - cut})
		// A swap across the partition changes both halves; this third seed
		// covers that case. Swaps within a half leave the other half exact.
		if text[cut-1] != text[cut] {
			seed := []byte(text[:cut])
			seed[cut-1] = text[cut]
			add(string(seed), literalAnchor{id, 0, cut})
		}
	}
	for i := range m.nodes {
		sort.Slice(m.nodes[i].edges, func(a, b int) bool { return m.nodes[i].edges[a].b < m.nodes[i].edges[b].b })
	}
	queue := make([]int, 0, len(m.nodes))
	for _, e := range m.nodes[0].edges {
		m.root[e.b] = e.state
		queue = append(queue, e.state)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for _, edge := range m.nodes[state].edges {
			fail := m.next(m.nodes[state].fail, edge.b)
			m.nodes[edge.state].fail = fail
			if len(m.nodes[fail].anchors) > 0 {
				m.nodes[edge.state].output = fail
			} else {
				m.nodes[edge.state].output = m.nodes[fail].output
			}
			queue = append(queue, edge.state)
		}
	}
	// Conservative retained allocation accounting, including slice capacities.
	m.bytes = 4096 + int64(cap(m.nodes))*80 + int64(cap(m.rules))*64
	for _, node := range m.nodes {
		m.bytes += int64(cap(node.edges))*16 + int64(cap(node.anchors))*24
	}
	for _, rule := range m.rules {
		m.bytes += int64(len(rule.Text)) + 8
	}
	return m, nil
}

// Every literal match needs one compiled seed. If the text has no ASCII word
// run long enough for any seed, a dictionary scan cannot find a candidate.
// One text pass supplies this necessary condition for every shared matcher.
func longestASCIIWordRun(text []byte, stopAt int) int {
	longest, current := 0, 0
	for _, b := range text {
		if asciiWord(b) {
			current++
			if current >= stopAt {
				return current
			}
			longest = max(longest, current)
		} else {
			current = 0
		}
	}
	return longest
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
func (m *literalMatcher) next(state int, b byte) int {
	for state != 0 {
		edges := m.nodes[state].edges
		if len(edges) <= 4 {
			for _, e := range edges {
				if e.b == b {
					return e.state
				}
			}
		} else {
			index := sort.Search(len(edges), func(i int) bool { return edges[i].b >= b })
			if index < len(edges) && edges[index].b == b {
				return edges[index].state
			}
		}
		state = m.nodes[state].fail
	}
	return m.root[b]
}

func literalBoundary(text []byte, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRune(text[:start])
		if wordRune(r) {
			return false
		}
	}
	if end < len(text) {
		r, _ := utf8.DecodeRune(text[end:])
		if wordRune(r) {
			return false
		}
	}
	return true
}

func (r *Redactor) scanLiterals(text []byte, matches []match, selection literalSelection) ([]match, error) {
	m := selection.matcher
	if m == nil {
		return matches, nil
	}
	if !r.chargeScanWork(uint64(len(text))) {
		return nil, ErrWorkLimit
	}
	state := 0
	for index, b := range text {
		state = m.next(state, asciiFold(b))
		for output := state; output != 0; output = m.nodes[output].output {
			for _, a := range m.nodes[output].anchors {
				if selection.enabled != nil && !selection.enabled[a.rule] {
					continue
				}
				rule := m.rules[a.rule]
				start := index + 1 - a.length - a.offset
				lo, hi := 0, 0
				if rule.Fuzzy {
					lo, hi = -1, 1
				}
				for delta := lo; delta <= hi; delta++ {
					if !r.chargeScanWork(8) {
						return nil, ErrWorkLimit
					}
					s := start + delta
					if s < 0 || s >= len(text) || !utf8.RuneStart(text[s]) {
						continue
					}
					for length := len(rule.Text) + lo; length <= len(rule.Text)+hi; length++ {
						e := s + length
						if e > len(text) || e < len(text) && !utf8.RuneStart(text[e]) || wholeWord(rule) && !literalBoundary(text, s, e) {
							continue
						}
						if rule.Fuzzy && (!asciiWord(text[s]) || !asciiWord(text[e-1])) {
							continue
						}
						if !r.chargeScanWork(uint64(2*len(rule.Text) + 1)) {
							return nil, ErrWorkLimit
						}
						candidate := text[s:e]
						ok := false
						if rule.Fuzzy {
							ok = oneASCIIEdit(rule.Text, candidate, rule.IgnoreCase)
						} else {
							ok = equalLiteral(rule.Text, candidate, rule.IgnoreCase)
						}
						if ok {
							var err error
							matches, err = appendMatch(matches, s, e, entityCustom, 1)
							if err != nil {
								return nil, err
							}
						}
					}
				}
			}
		}
	}
	return matches, nil
}

func equalLiteral(a string, b []byte, fold bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range b {
		if !equalASCII(a[i], b[i], fold) {
			return false
		}
	}
	return true
}
func equalASCII(a, b byte, fold bool) bool {
	if fold {
		return asciiFold(a) == asciiFold(b)
	}
	return a == b
}
func oneASCIIEdit(a string, b []byte, fold bool) bool {
	for _, c := range b {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	if abs(len(a)-len(b)) > 1 {
		return false
	}
	i := 0
	for i < len(a) && i < len(b) && equalASCII(a[i], b[i], fold) {
		i++
	}
	if i == min(len(a), len(b)) {
		return true
	}
	x, y := i, i
	if len(a) == len(b) {
		if i+1 < len(a) && equalASCII(a[i], b[i+1], fold) && equalASCII(a[i+1], b[i], fold) {
			return equalLiteral(a[i+2:], b[i+2:], fold)
		}
		x++
		y++
	} else if len(a) > len(b) {
		x++
	} else {
		y++
	}
	return equalLiteral(a[x:], b[y:], fold)
}

// NormalizeLiterals removes only rules whose match set is already covered.
// Independent fuzzy/case flags never combine into a more permissive rule.
func NormalizeLiterals(rules []Literal) []Literal {
	groups := map[string][]Literal{}
	for _, rule := range rules {
		word := wholeWord(rule)
		rule.WholeWord = &word
		if rule.IgnoreCase {
			rule.Text = folded(rule.Text)
		}
		key := folded(rule.Text)
		group := groups[key]
		covered := false
		for _, parent := range group {
			if literalCovers(parent, rule) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		next := group[:0]
		for _, child := range group {
			if !literalCovers(rule, child) {
				next = append(next, child)
			}
		}
		groups[key] = append(next, rule)
	}
	type orderedLiteral struct {
		rule     Literal
		identity string
	}
	ordered := make([]orderedLiteral, 0, len(rules))
	for _, group := range groups {
		for _, rule := range group {
			ordered = append(ordered, orderedLiteral{rule, literalIdentity(rule)})
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].identity < ordered[j].identity })
	out := make([]Literal, len(ordered))
	for i, entry := range ordered {
		out[i] = entry.rule
	}
	return out
}

func literalCovers(a, b Literal) bool {
	return (a.IgnoreCase || !b.IgnoreCase && a.Text == b.Text) && (a.Fuzzy || !b.Fuzzy) && (!wholeWord(a) || wholeWord(b))
}

func literalIdentity(rule Literal) string {
	// The source compiler uses this same field order, including explicit defaults.
	if rule.IgnoreCase {
		rule.Text = folded(rule.Text)
	}
	raw, _ := json.Marshal(struct {
		Text       string `json:"text"`
		IgnoreCase bool   `json:"ignoreCase"`
		WholeWord  bool   `json:"wholeWord"`
		Fuzzy      bool   `json:"fuzzy"`
	}{rule.Text, rule.IgnoreCase, wholeWord(rule), rule.Fuzzy})
	return string(raw)
}
