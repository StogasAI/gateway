package tokenizer

// Normalization follows ctok's measured v4.7+ reconstruction (MIT; see LICENSE).
// It is deliberately separate from vocabulary tiling and provider framing.
import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	claudeBow   rune  = 0xfdd0
	claudeEow   rune  = 0xfdd1
	claudeShift rune  = 0xfdd3
	claudeWord  uint8 = iota + 1
	claudeHard
	claudeDigit
	claudePunct
	claudeSpace
	claudeStray
)

func normalizeClaude(text string) string {
	text = norm.NFC.String(text)
	text = strings.ReplaceAll(text, "\u0e4d\u0e32", "\u0e33")
	return strings.Map(func(r rune) rune {
		switch {
		case r == 0:
			return ' '
		case r >= 1 && r <= 8 || r >= 0x0b && r <= 0x1f || r >= 0x7f && r <= 0x9f || r >= 0xe000 && r <= 0xf8ff:
			return -1
		case r == 0xa0 || r == 0x1680 || r >= 0x2000 && r <= 0x200a || r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f:
			return ' '
		case r >= 0xfdd0 && r <= 0xfdd4:
			return 0xe000 + (r - 0xfdd0)
		default:
			return r
		}
	}, text)
}

func claudeSelector(r rune) bool       { return r >= 0xfe00 && r <= 0xfe0f }
func claudeAlphabeticMark(r rune) bool { return unicode.Is(unicode.Other_Alphabetic, r) }
func claudeSeparator(r rune) bool {
	return r >= 128 && r < 0x10000 && unicode.IsMark(r) && !claudeSelector(r) && !claudeAlphabeticMark(r)
}
func claudeStrayMark(r rune) bool {
	if r < 128 || r == 0x0711 || r >= 0x0730 && r <= 0x073f || r >= 0x10000 || !unicode.IsMark(r) || claudeSeparator(r) {
		return false
	}
	var b [4]byte
	n := utf8.EncodeRune(b[:], r)
	return norm.NFC.Properties(b[:n]).CCC() != 0
}
func claudeHardLetter(r rune) bool {
	return r >= 0x10000 || r >= 0x4e00 && r <= 0x9fff || r >= 0x3400 && r <= 0x4dbf || r >= 0xf900 && r <= 0xfaff || r >= 0xac00 && r <= 0xd7a3 || r == 0x3005 || r == 0x3006 || r >= 0x3031 && r <= 0x3035 || r == 0x303b || r == 0x303c
}

var claudeBMPClasses = func() (classes [65536]uint8) {
	for r := range classes {
		classes[r] = rawClaudeClass(rune(r))
	}
	return
}()

func claudeClass(r rune) uint8 {
	if r < 65536 {
		return claudeBMPClasses[r]
	}
	return rawClaudeClass(r)
}

func rawClaudeClass(r rune) uint8 {
	if r < 128 {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
			return claudeWord
		case r >= '0' && r <= '9':
			return claudeDigit
		case r == ' ' || r == '\t' || r == '\n':
			return claudeSpace
		default:
			return claudePunct
		}
	}
	if unicode.Is(unicode.Z, r) {
		return claudeSpace
	}
	if r == 0x1c89 || r == 0x1c8a || r == 0xa7cb || r >= 0x16ee && r <= 0x16f0 || r >= 0x2160 && r <= 0x2188 || r >= 0x24b6 && r <= 0x24e9 || r >= 0xa6e6 && r <= 0xa6ef {
		return claudeWord
	}
	if r >= 0x0660 && r <= 0x0669 || r >= 0x06f0 && r <= 0x06f9 {
		return claudeDigit
	}
	if strings.ContainsRune("—»«•°„–−£§€…√→（№†└│།·─═█", r) {
		return claudePunct
	}
	if claudeSelector(r) {
		return claudeHard
	}
	if unicode.IsMark(r) {
		if r < 0x10000 && claudeAlphabeticMark(r) {
			return claudeWord
		}
		return claudeHard
	}
	if unicode.IsLetter(r) && !claudeHardLetter(r) {
		return claudeWord
	}
	return claudeHard
}

func claudePunctMark(r rune) bool {
	if r < 128 {
		return r >= 33 && r <= 126 && claudeClass(r) == claudePunct
	}
	if r >= 0xe000 && r <= 0xe004 {
		r = 0xfdd0 + (r - 0xe000)
	}
	if r >= 0x10000 {
		return false
	}
	if claudeSeparator(r) {
		return true
	}
	if r >= 0x3001 && r <= 0x303f && (unicode.IsPunct(r) || strings.ContainsRune("〄〒〓〠〶〷〾〿", r)) {
		return false
	}
	return unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.Is(unicode.Cf, r) || !unicode.IsGraphic(r) && !unicode.IsControl(r) && !unicode.Is(unicode.Co, r) && !unicode.IsSpace(r)
}
func claudeDigitBorder(r rune) bool {
	return r >= 128 && r < 0x10000 && (unicode.Is(unicode.No, r) || unicode.IsDigit(r))
}
func claudeHardKind(r rune) uint8 {
	if claudePunctMark(r) {
		return 1
	}
	if claudeDigitBorder(r) {
		return 2
	}
	return 3
}

type claudeRun struct {
	text        string
	kind        uint8
	first, last rune
	digits      bool
}

func nextClaudeRun(text string) (claudeRun, string) {
	if text == "" {
		return claudeRun{}, ""
	}
	first, width := utf8.DecodeRuneInString(text)
	kind := claudeClass(first)
	if kind == claudeWord && claudeStrayMark(first) {
		kind = claudeStray
	}
	hardKind := uint8(0)
	if kind == claudeHard {
		hardKind = claudeHardKind(first)
	}
	last, end := first, width
	digitClass := uint8(0)
	if first >= '0' && first <= '9' || first >= 128 && unicode.IsDigit(first) {
		digitClass = 1
	} else if first >= 128 && unicode.Is(unicode.No, first) {
		digitClass = 2
	}
	digits := digitClass != 0
	for end < len(text) {
		r, n := utf8.DecodeRuneInString(text[end:])
		cls := claudeClass(r)
		if cls != kind && !(kind == claudeStray && cls == claudeWord && claudeStrayMark(r)) {
			break
		}
		if kind == claudeHard && !claudeSelector(r) && claudeHardKind(r) != hardKind {
			break
		}
		if digits && (digitClass == 1 && !unicode.IsDigit(r) || digitClass == 2 && !unicode.Is(unicode.No, r)) {
			digits = false
		}
		last = r
		end += n
	}
	return claudeRun{text[:end], kind, first, last, digits}, text[end:]
}

func claudeLower(r rune) rune {
	switch r {
	case 0x03f4:
		return r
	case 0x1c89:
		return 0x1c8a
	case 0xa7cb:
		return 0x0264
	default:
		return unicode.ToLower(r)
	}
}
func claudeUpper(r rune) bool {
	return r != 0x03f4 && claudeLower(r) != r && (unicode.IsUpper(r) || r == 0x1c89 || r == 0xa7cb)
}
func claudeTitle(text string) bool {
	first, _ := utf8.DecodeRuneInString(text)
	if !claudeUpper(first) || first == 'İ' || strings.ContainsRune(text, 'ẞ') {
		return false
	}
	for _, r := range text[utf8.RuneLen(first):] {
		if r != 'İ' && claudeUpper(r) {
			return false
		}
	}
	return true
}
func claudeRightBorder(r claudeRun) bool {
	return r.kind == claudePunct || claudeSelector(r.last) || claudePunctMark(r.last) || r.digits && claudeDigitBorder(r.last)
}
func claudeContraction(s string) bool {
	switch s {
	case "s", "t", "d", "m", "ll", "re", "ve":
		return true
	}
	return false
}

func emitClaudeRun(scan *claudeScan, before, previous, current, next claudeRun) {
	leftSpace := previous.kind == claudeSpace && previous.last == ' '
	rightSpace := next.kind == claudeSpace && next.first == ' ' && !strings.HasPrefix(next.text, "  ")
	bow, eow, title := false, false, false
	switch current.kind {
	case claudeWord:
		fused := previous.kind == claudeStray
		bow = !fused && !(previous.kind == claudePunct && previous.text == "'" && claudeContraction(current.text) && !claudeRightBorder(before))
		eow = true
	case claudeStray:
		bow = true
		eow = next.kind != claudeWord
	default:
		leftMark := current.kind == claudePunct || claudeSelector(current.first) || claudePunctMark(current.first)
		rightMark := current.kind == claudePunct || claudeSelector(current.last) || claudePunctMark(current.last)
		if leftMark || rightMark {
			opensWord := current.text == "'" && (next.kind == claudeWord || next.kind == claudeStray)
			bow = leftSpace && leftMark && !opensWord
			eow = rightSpace && rightMark
		} else if current.digits {
			bow = leftSpace && claudeDigitBorder(current.first)
			eow = rightSpace && claudeDigitBorder(current.last)
		}
	}
	if current.kind == claudeWord && bow && eow {
		if count, ok := scan.c.words[current.text]; ok {
			scan.closedWord(count)
			return
		}
	}
	if current.kind == claudeWord && previous.kind != claudeStray {
		title = claudeTitle(current.text)
	}
	if title {
		scan.emit(claudeShift)
	}
	if bow {
		scan.emit(claudeBow)
	}
	for _, r := range current.text {
		if title && r != 'İ' {
			r = claudeLower(r)
		}
		scan.emit(r)
	}
	if eow {
		scan.emit(claudeEow)
	}
}
