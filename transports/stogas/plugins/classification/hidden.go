package classification

import (
	"math/bits"
	"unicode/utf8"
)

// Hidden counts the characters in text that a reader cannot see and a model still reads, the
// carriers of ASCII smuggling, emoji smuggling, zero-width encodings and Trojan Source:
//
//   - every Unicode tag character outside the three tag sequences of the subdivision flags
//     (England, Scotland and Wales), which Unicode recommends and nothing else uses;
//   - every bidirectional override (U+202D and U+202E), which shows the characters after it
//     against their own direction, so that a reader sees them in another order than a model
//     reads them;
//   - every character of a run of two or more other default-ignorable characters, such as
//     zero-width characters, variation selectors and the other bidirectional controls.
//
// Text in any language uses the other default-ignorable characters one at a time: a zero-width
// joiner inside a word or an emoji sequence, a variation selector after its base character, a
// direction mark, or an isolate around a placeholder, as localization libraries write it. The
// one pair that text uses is an emoji presentation selector before a zero-width joiner, as in the
// rainbow flag, so a joiner after a selector that stands alone starts a new run.
//
// Write takes text in order, in pieces that end on a character boundary, and keeps a few bytes
// of state, so it reads a stream of any length in constant memory. The zero value has read
// nothing.
type Hidden struct {
	count int
	run   int
	prev  rune
	// counted reports that the run's first character counts on its own, as an override does.
	counted bool
	// flag is one more than the tag letters that follow a waving black flag, or 0 when the last
	// character does not continue a flag sequence.
	flag    int
	letters [flagLetters]rune
	// runStart is where the run starts, and flagStart and flagEnd hold a flag's tag letters, as
	// offsets in the text of HiddenSpans.
	runStart, flagStart, flagEnd int
	// spans are the characters that HiddenSpans found, when keep is set.
	spans []Span
	keep  bool
}

// Span is the bytes from Start to End of a text.
type Span struct{ Start, End int }

const (
	blackFlag   = 0x1F3F4
	cancelTag   = 0xE007F
	tagBase     = 0xE0000
	flagLetters = 5
	selector16  = 0xFE0F
	zwj         = 0x200D
	// leftOverride and rightOverride are LEFT-TO-RIGHT OVERRIDE and RIGHT-TO-LEFT OVERRIDE.
	leftOverride  = 0x202D
	rightOverride = 0x202E
)

// rgiFlags are the letters of the subdivision flags that Unicode recommends for interchange
// (emoji-sequences.txt, RGI_Emoji_Tag_Sequence).
var rgiFlags = [...]string{"gbeng", "gbsct", "gbwls"}

// CountHidden counts the hidden characters of one complete text.
func CountHidden[T string | []byte](text T) int {
	var h Hidden
	write(&h, text)
	return h.Count()
}

// HiddenSpans returns where the characters that CountHidden counts are in one complete text, in
// order and with the characters that follow each other in one span.
func HiddenSpans[T string | []byte](text T) []Span {
	h := Hidden{keep: true}
	write(&h, text)
	h.Break()
	return h.spans
}

// hiddenLeads are the bytes that mayHide takes first, which pass most text without a call.
var hiddenLeads = [256]bool{0xC2: true, 0xCD: true, 0xD8: true, 0xE1: true, 0xE2: true, 0xE3: true, 0xEF: true, 0xF0: true, 0xF3: true}

// mayHide reports whether a character that starts with these two bytes can be a default-ignorable
// character or the waving black flag, the only characters that Write decodes.
func mayHide(lead, next byte) bool {
	switch lead {
	case 0xC2:
		return next == 0xAD
	case 0xCD:
		return next == 0x8F
	case 0xD8:
		return next == 0x9C
	case 0xE1:
		return next == 0x85 || next == 0x9E || next == 0xA0
	case 0xE2:
		return next == 0x80 || next == 0x81
	case 0xE3:
		return next == 0x85
	case 0xEF:
		return next == 0xB8 || next == 0xBB || next == 0xBE || next == 0xBF
	case 0xF0:
		return next == 0x9B || next == 0x9D || next == 0x9F
	case 0xF3:
		return next == 0xA0
	}
	return false
}

// Write reads the next piece of text.
func (h *Hidden) Write(text string) {
	write(h, text)
}

// write decodes only the characters that mayHide takes, and skips the others whole and ASCII
// eight bytes at a time, so it reads text in any script at close to the speed of memory.
func write[T string | []byte](h *Hidden, text T) {
	for i := 0; i < len(text); {
		b := text[i]
		switch {
		case b < utf8.RuneSelf:
			for i++; i+8 <= len(text); i += 8 {
				word := uint64(text[i]) | uint64(text[i+1])<<8 | uint64(text[i+2])<<16 | uint64(text[i+3])<<24 |
					uint64(text[i+4])<<32 | uint64(text[i+5])<<40 | uint64(text[i+6])<<48 | uint64(text[i+7])<<56
				if word&0x8080808080808080 != 0 {
					break
				}
			}
			h.visible()
		case hiddenLeads[b] && i+1 < len(text) && mayHide(b, text[i+1]):
			// A conversion of at most four bytes that the call keeps copies nothing.
			r, size := utf8.DecodeRuneInString(string(text[i:min(i+utf8.UTFMax, len(text))]))
			h.read(r, i, i+size)
			i += size
		default:
			// The continuation bytes of a character start none, so they go with it. An invalid
			// byte goes alone, as a range over the text reads it.
			width := bits.LeadingZeros8(^b)
			if width < 2 || width > utf8.UTFMax {
				width = 1
			}
			end := min(i+width, len(text))
			for i++; i < end && text[i]&0xC0 == 0x80; i++ {
			}
			h.visible()
		}
	}
}

// Break ends a text, so that a run of hidden characters or a flag sequence does not continue
// into the next one.
func (h *Hidden) Break() {
	h.visible()
}

// Count is the number of hidden characters read so far, including the tag letters of a flag
// sequence that has not ended.
func (h *Hidden) Count() int {
	return h.count + max(h.flag-1, 0)
}

// visible reads a character that is neither hidden nor a flag.
func (h *Hidden) visible() {
	h.endFlag()
	h.run, h.prev = 0, 0
}

// endFlag counts the tag letters of a flag sequence that ends without the cancel tag.
func (h *Hidden) endFlag() {
	if h.flag > 1 {
		h.count += h.flag - 1
		h.mark(h.flagStart, h.flagEnd)
	}
	h.flag = 0
}

// mark keeps the characters from start to end that were just counted, for HiddenSpans.
func (h *Hidden) mark(start, end int) {
	if !h.keep {
		return
	}
	if last := len(h.spans) - 1; last >= 0 && h.spans[last].End == start {
		h.spans[last].End = end
		return
	}
	h.spans = append(h.spans, Span{Start: start, End: end})
}

// read reads the character r, from start to end in the text.
func (h *Hidden) read(r rune, start, end int) {
	if r >= tagBase && r <= cancelTag {
		h.readTag(r, start, end)
		h.run, h.prev = 0, r
		return
	}
	h.endFlag()
	if r == blackFlag {
		h.flag = 1
	}
	switch {
	case !defaultIgnorable(r):
		h.run = 0
	case r == zwj && h.prev == selector16 && h.run == 1:
		// The selector stood alone, so the joiner starts a run of its own.
		h.runStart = start
	default:
		h.run++
		switch {
		case h.run == 1 && (r == leftOverride || r == rightOverride):
			h.count++
			h.counted = true
			h.mark(start, end)
		case h.run == 1:
			h.counted = false
		case h.run == 2 && !h.counted:
			h.count += 2
			h.mark(h.runStart, end)
		default:
			h.count++
			h.mark(start, end)
		}
		if h.run == 1 {
			h.runStart = start
		}
	}
	h.prev = r
}

func (h *Hidden) readTag(r rune, start, end int) {
	if h.flag == 0 {
		h.count++
		h.mark(start, end)
		return
	}
	letters := h.flag - 1
	switch letter := r - tagBase; {
	case r == cancelTag && letters == flagLetters && h.rgiPrefix(letters):
		h.flag = 0
	case letters < flagLetters && letter >= 'a' && letter <= 'z':
		if letters == 0 {
			h.flagStart = start
		}
		h.letters[letters] = letter
		h.flag++
		h.flagEnd = end
		if !h.rgiPrefix(letters + 1) {
			h.endFlag()
		}
	default:
		// The letters before it, then the tag itself.
		h.endFlag()
		h.count++
		h.mark(start, end)
	}
}

// rgiPrefix reports whether the first n letters read after the flag begin a recommended flag.
func (h *Hidden) rgiPrefix(n int) bool {
	for _, flag := range rgiFlags {
		matches := true
		for i := range n {
			if rune(flag[i]) != h.letters[i] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

// defaultIgnorable reports the Default_Ignorable_Code_Point property of Unicode 17.0
// (DerivedCoreProperties.txt). Tag characters are handled before this is called.
func defaultIgnorable(r rune) bool {
	switch {
	case r < 0xAD:
		return false
	case r < 0x2000:
		return r == 0xAD || r == 0x34F || r == 0x61C || r == 0x115F || r == 0x1160 ||
			r == 0x17B4 || r == 0x17B5 || r >= 0x180B && r <= 0x180F
	case r < 0x3000:
		return r >= 0x200B && r <= 0x200F || r >= 0x202A && r <= 0x202E || r >= 0x2060 && r <= 0x206F
	case r < 0xFE00:
		return r == 0x3164
	case r < 0x10000:
		return r <= 0xFE0F || r == 0xFEFF || r == 0xFFA0 || r >= 0xFFF0 && r <= 0xFFF8
	default:
		return r >= 0x1BCA0 && r <= 0x1BCA3 || r >= 0x1D173 && r <= 0x1D17A || r >= 0xE0000 && r <= 0xE0FFF
	}
}
