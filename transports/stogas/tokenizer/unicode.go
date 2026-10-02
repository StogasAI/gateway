package tokenizer

import (
	"unicode"
	"unicode/utf8"
)

const (
	classLetter = 1 << iota
	classNumber
	classUpper
	classLower
	classCommon
	classSpace
)

// One byte per code point avoids range searches for both common scripts and
// supplementary characters. Both vocabularies share this immutable 1.1-MiB table.
var runeClasses = func() [unicode.MaxRune + 1]uint8 {
	var table [unicode.MaxRune + 1]uint8
	fill := func(ranges *unicode.RangeTable, class uint8) {
		for _, r := range ranges.R16 {
			for code := uint32(r.Lo); code <= uint32(r.Hi); code += uint32(r.Stride) {
				table[code] = class
			}
		}
		for _, r := range ranges.R32 {
			for code := r.Lo; code <= r.Hi; code += r.Stride {
				table[code] = class
			}
		}
	}
	fill(unicode.L, classLetter|classCommon)
	fill(unicode.Ll, classLetter|classLower)
	fill(unicode.Lu, classLetter|classUpper)
	fill(unicode.Lt, classLetter|classUpper)
	fill(unicode.M, classCommon)
	fill(unicode.N, classNumber)
	fill(unicode.White_Space, classSpace)
	return table
}()

// runeClass implements the Unicode categories in the published tiktoken
// patterns. A fixed scanner avoids a general regexp match/allocation per word.
func runeClass(r rune) uint8 {
	if uint32(r) < uint32(len(runeClasses)) {
		return runeClasses[r]
	}
	return 0
}

func unicodePiece(s string, modern bool) int {
	if !modern {
		if n := unicodeContraction(s); n > 0 {
			return n
		}
	}
	r, width := utf8.DecodeRuneInString(s)
	first := runeClass(r)
	if first&(classLetter|classNumber) == 0 && r != '\r' && r != '\n' {
		if end := unicodeWord(s, width, modern); end > width {
			return end
		}
	}
	// The optional prefix may itself be a combining mark in the modern word
	// alternatives. Backtrack that prefix when consuming it left no word.
	if end := unicodeWord(s, 0, modern); end > 0 {
		return end
	}
	if first&classNumber != 0 {
		i := width
		for n := 1; n < 3 && i < len(s); n++ {
			next, size := utf8.DecodeRuneInString(s[i:])
			if runeClass(next)&classNumber == 0 {
				break
			}
			i += size
		}
		return i
	}
	start := 0
	if r == ' ' {
		start = 1
	}
	i := start
	for i < len(s) {
		next, size := utf8.DecodeRuneInString(s[i:])
		if runeClass(next)&(classLetter|classNumber|classSpace) != 0 {
			break
		}
		i += size
	}
	if i > start {
		for i < len(s) && (s[i] == '\r' || s[i] == '\n' || modern && s[i] == '/') {
			i++
		}
		return i
	}
	i, lastNewline := 0, 0
	for i < len(s) {
		next, size := utf8.DecodeRuneInString(s[i:])
		if runeClass(next)&classSpace == 0 {
			break
		}
		i += size
		if next == '\r' || next == '\n' {
			lastNewline = i
		}
	}
	if lastNewline > 0 {
		return lastNewline
	}
	return i
}

func unicodeWord(s string, start int, modern bool) int {
	i := start
	if !modern {
		for i < len(s) {
			r, width := utf8.DecodeRuneInString(s[i:])
			if runeClass(r)&classLetter == 0 {
				break
			}
			i += width
		}
		return i
	}
	lastCommon := start
	for i < len(s) {
		r, width := utf8.DecodeRuneInString(s[i:])
		class := runeClass(r)
		if class&(classUpper|classCommon) == 0 {
			break
		}
		i += width
		if class&classCommon != 0 {
			lastCommon = i
		}
	}
	upperEnd := i
	for i < len(s) {
		r, width := utf8.DecodeRuneInString(s[i:])
		if runeClass(r)&(classLower|classCommon) == 0 {
			break
		}
		i += width
	}
	if i == upperEnd && lastCommon > start {
		// A* B+ has priority over A+ B*. Its greedy A* backtracks to the
		// final shared-category rune when there is no following lower-case run.
		i = lastCommon
	}
	if i > start {
		i += unicodeContraction(s[i:])
	}
	return i
}

func unicodeContraction(s string) int {
	if n := contraction(s); n > 0 {
		return n
	}
	// Long s is the only non-ASCII SimpleFold equivalent in the fixed
	// contraction alternatives ('s, 't, 're, 've, 'm, 'll, 'd).
	if len(s) >= 3 && s[0] == '\'' && s[1] == 0xc5 && s[2] == 0xbf {
		return 3
	}
	return 0
}
