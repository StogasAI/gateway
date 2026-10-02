package tokenizer

import (
	"embed"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

//go:generate go run ./generate published
//go:embed deepseek.tiktoken.gz qwen3.tiktoken.gz qwen35.tiktoken.gz gemma.tiktoken.gz minimax.tiktoken.gz mistral.tiktoken.gz kimi.tiktoken.gz glm.tiktoken.gz
var publishedData embed.FS

var publishedCounters = func() map[string]func() *Counter {
	result := map[string]func() *Counter{}
	for _, name := range []string{"deepseek", "qwen3", "qwen35", "gemma", "minimax", "mistral", "kimi", "glm"} {
		result[name] = sync.OnceValue(func() *Counter {
			data, err := publishedData.ReadFile(name + ".tiktoken.gz")
			if err != nil {
				panic(err)
			}
			return load(name, data)
		})
	}
	return result
}()

func (c *Counter) normalize(text string) string {
	if c.name == "gemma" {
		return strings.ReplaceAll(text, "▁", " ")
	}
	if c.name == "qwen3" || c.name == "qwen35" || c.name == "minimax" {
		return norm.NFC.String(text)
	}
	return text
}

// Specialized scanners avoid regex allocations and backtracking. Gemma uses
// word-sized pieces instead of merging a whole passage; its resulting counts,
// like the 16-KiB work boundary, are estimates checked against published data.
func (c *Counter) piece(text string) int {
	modern := c.name == O200kBase || c.name == "minimax" || c.name == "mistral" || c.name == "kimi"
	singleNumber := c.name == "qwen3" || c.name == "qwen35" || c.name == "mistral"
	first, width := utf8.DecodeRuneInString(text)
	if singleNumber && runeClass(first)&classNumber != 0 {
		return width
	}
	if c.name == "deepseek" {
		return deepseekPiece(text)
	}
	if c.name == "qwen35" {
		return qwenPiece(text)
	}
	if c.name == "gemma" {
		if runeClass(first)&classNumber != 0 {
			return unicodePiece(text, false)
		}
		return qwenPiece(text)
	}
	if c.name == "kimi" {
		if unicode.Is(unicode.Han, first) {
			i := width
			for i < len(text) {
				r, n := utf8.DecodeRuneInString(text[i:])
				if !unicode.Is(unicode.Han, r) {
					break
				}
				i += n
			}
			return i
		}
	}
	n := asciiPiece(text, modern)
	if n == 0 {
		n = unicodePiece(text, modern)
	}
	if c.name == "kimi" {
		// Inspect only this candidate, never the rest of the request per word.
		for i, r := range text[:n] {
			if r >= 0x2e80 && unicode.Is(unicode.Han, r) {
				return i
			}
		}
	}
	if c.name == "mistral" && n > 0 {
		// Tekken has no contraction suffix in its word alternatives.
		for i := 1; i < n; i++ {
			if text[i] == '\'' && unicodeContraction(text[i:n]) == n-i {
				return i
			}
		}
	}
	return n
}

func qwenPiece(s string) int {
	if n := unicodeContraction(s); n > 0 {
		return n
	}
	r, w := utf8.DecodeRuneInString(s)
	letterMask := uint8(classLetter | classCommon | classUpper | classLower)
	if runeClass(r)&classNumber != 0 {
		return w
	}
	start := 0
	if runeClass(r)&(classLetter|classNumber) == 0 && r != '\r' && r != '\n' {
		start = w
	}
	i := start
	for i < len(s) {
		r, n := utf8.DecodeRuneInString(s[i:])
		if runeClass(r)&letterMask == 0 {
			break
		}
		i += n
	}
	if i > start {
		return i
	}
	if start > 0 && runeClass(r)&letterMask != 0 {
		return start
	}
	return unicodePiece(s, false)
}

func deepseekCJK(r rune) bool { return r >= 0x4e00 && r <= 0x9fa5 || r >= 0x3040 && r <= 0x30ff }

func deepseekPiece(s string) int {
	r, w := utf8.DecodeRuneInString(s)
	if runeClass(r)&classNumber != 0 || deepseekCJK(r) {
		i, n := w, 1
		for i < len(s) {
			next, width := utf8.DecodeRuneInString(s[i:])
			if deepseekCJK(r) {
				if !deepseekCJK(next) {
					break
				}
			} else if n == 3 || runeClass(next)&classNumber == 0 {
				break
			}
			i += width
			n++
		}
		return i
	}
	if len(s) > 1 && s[0] < 128 && !letter(s[0]) && !digit(s[0]) && !space(s[0]) && letter(s[1]) {
		i := 2
		for i < len(s) && letter(s[i]) {
			i++
		}
		return i
	}
	start := 0
	if r != '\r' && r != '\n' && runeClass(r)&classLetter == 0 && !unicode.IsPunct(r) && !unicode.IsSymbol(r) {
		start = w
	}
	n := start
	for n < len(s) {
		next, size := utf8.DecodeRuneInString(s[n:])
		if runeClass(next)&(classLetter|classCommon|classUpper|classLower) == 0 {
			break
		}
		n += size
	}
	if n == start {
		start = 0
		if r == ' ' {
			start = 1
		}
		n = start
		for n < len(s) {
			next, size := utf8.DecodeRuneInString(s[n:])
			if !unicode.IsPunct(next) && !unicode.IsSymbol(next) {
				break
			}
			n += size
		}
		if n > start {
			for n < len(s) && (s[n] == '\r' || s[n] == '\n') {
				n++
			}
		} else if runeClass(r)&classSpace != 0 {
			n, lastNewline := 0, 0
			for n < len(s) {
				next, size := utf8.DecodeRuneInString(s[n:])
				if runeClass(next)&classSpace == 0 {
					break
				}
				n += size
				if next == '\r' || next == '\n' {
					lastNewline = n
				}
			}
			if lastNewline > 0 {
				return lastNewline
			}
			return n
		} else {
			n = w
		}
	}
	// The first two isolated passes bound the current piece. Searching only
	// that piece avoids a quadratic scan on requests without numbers or CJK.
	for i, r := range s[:n] {
		if i > 0 && (runeClass(r)&classNumber != 0 || deepseekCJK(r)) {
			return i
		}
	}
	return n
}
