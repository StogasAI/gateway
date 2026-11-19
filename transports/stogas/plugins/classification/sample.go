package classification

import (
	"strings"
	"unicode/utf8"
)

// SampleBytes is the most text that language detection reads: the start of a text.
const SampleBytes = 512

// Sample keeps the first SampleBytes of prose written to it, leaving out fenced code blocks,
// whose keywords would read as English. Write takes text in order, in any pieces, so a reply's
// sample is taken as the reply streams.
type Sample struct {
	text []byte
	// line holds the start of a line until it shows whether the line opens or closes a fence:
	// up to three spaces, then a run of backticks or tildes.
	line      []byte
	state     lineState
	run       int
	runByte   byte
	fenced    bool
	fenceByte byte
	fenceRun  int
}

type lineState uint8

const (
	lineIndent lineState = iota
	lineFence
	lineProse
	lineSkip
)

// Full reports whether the sample holds SampleBytes, after which Write ignores text.
func (s *Sample) Full() bool {
	return len(s.text) >= SampleBytes
}

// Text is the sample, ending on a character boundary.
func (s *Sample) Text() string {
	text := s.text
	for i := len(text) - 1; i >= 0 && i >= len(text)-utf8.UTFMax; i-- {
		if utf8.RuneStart(text[i]) {
			if !utf8.FullRune(text[i:]) {
				text = text[:i]
			}
			break
		}
	}
	return string(text)
}

// Write reads the next piece of text. It finds the end of a skipped line as fast as memory
// reads, so code before the prose costs little.
func (s *Sample) Write(text string) {
	for len(text) > 0 && !s.Full() {
		if s.state == lineSkip {
			i := strings.IndexByte(text, '\n')
			if i < 0 {
				return
			}
			text = text[i:]
		}
		s.read(text[0])
		text = text[1:]
	}
}

// Break ends a line, as between two parts of one message.
func (s *Sample) Break() {
	if !s.Full() {
		s.read('\n')
	}
}

// Language returns the language of the sample (DetectLanguage), or "" when it holds nothing but
// white space.
func (s *Sample) Language() string {
	text := s.Text()
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return DetectLanguage(text)
}

func (s *Sample) read(b byte) {
	if b == '\n' {
		switch {
		case s.state == lineFence && !s.decideFence(), s.state == lineIndent:
			s.startLine(b)
		case s.state == lineProse:
			s.keep([]byte{b})
		}
		s.line, s.state, s.run = s.line[:0], lineIndent, 0
		return
	}
	switch s.state {
	case lineIndent:
		switch {
		case b == ' ' && len(s.line) < 3:
			s.line = append(s.line, b)
		case b == '`' || b == '~':
			s.line = append(s.line, b)
			s.state, s.run, s.runByte = lineFence, 1, b
		default:
			s.startLine(b)
		}
	case lineFence:
		if b == s.runByte {
			s.line = append(s.line, b)
			s.run++
			return
		}
		if !s.decideFence() {
			s.startLine(b)
		}
	case lineProse:
		s.keep([]byte{b})
	}
}

// decideFence ends a run of backticks or tildes at the start of a line. A run of three or more
// opens a fence, or closes the open fence when it repeats its character at least as often; the
// rest of such a line is skipped.
func (s *Sample) decideFence() bool {
	if s.run < 3 {
		return false
	}
	switch {
	case !s.fenced:
		s.fenced, s.fenceByte, s.fenceRun = true, s.runByte, s.run
	case s.runByte == s.fenceByte && s.run >= s.fenceRun:
		s.fenced = false
	}
	s.state = lineSkip
	return true
}

func (s *Sample) startLine(b byte) {
	if s.fenced {
		s.state = lineSkip
		return
	}
	s.state = lineProse
	s.keep(s.line)
	s.keep([]byte{b})
}

func (s *Sample) keep(bytes []byte) {
	room := SampleBytes - len(s.text)
	if room <= 0 {
		return
	}
	s.text = append(s.text, bytes[:min(len(bytes), room)]...)
}
