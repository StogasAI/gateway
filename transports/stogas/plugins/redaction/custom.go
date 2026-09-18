package redaction

import (
	"io"
	"math/bits"
	"regexp"
	"regexp/syntax"
	"unicode/utf8"
)

type customMatcher struct {
	start, after *regexp.Regexp
	firstASCII   [utf8.RuneSelf]bool
	first        []syntax.Inst
	weight       uint64
	firstWeight  uint64
}

func newCustomMatcher(expression string, program *syntax.Prog) *customMatcher {
	// RE2 permits a quoted literal to end at EOF without \E. Close it before
	// embedding the expression, or the wrapper's ')' becomes literal text.
	quoted := false
	for position := 0; position+1 < len(expression); position++ {
		if expression[position] != '\\' {
			continue
		}
		next := expression[position+1]
		if quoted {
			if next == 'E' {
				quoted = false
				position++
			}
		} else {
			quoted = next == 'Q'
			position++
		}
	}
	if quoted {
		expression += `\E`
	}
	matcher := &customMatcher{
		start: regexp.MustCompile(`\A(?:` + expression + `)`),
		// One real preceding rune preserves ^, \A and word-boundary semantics
		// at nonzero positions. No synthetic prefix or end-of-input is used.
		after:       regexp.MustCompile(`\A(?s:.)(?:` + expression + `)`),
		weight:      uint64(len(program.Inst) + 4),
		firstWeight: 1,
	}
	matcher.start.Longest()
	matcher.after.Longest()
	for _, instruction := range program.Inst {
		// MatchRune binary-searches large Unicode classes. Include their cost.
		matcher.weight += uint64(bits.Len(uint(len(instruction.Rune))))
	}
	pending := []uint32{uint32(program.Start)}
	seen := make([]bool, len(program.Inst))
	for len(pending) > 0 {
		pc := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[pc] {
			continue
		}
		seen[pc] = true
		instruction := program.Inst[pc]
		switch instruction.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			pending = append(pending, instruction.Out, instruction.Arg)
		case syntax.InstCapture, syntax.InstEmptyWidth, syntax.InstNop:
			pending = append(pending, instruction.Out)
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			matcher.first = append(matcher.first, instruction)
			matcher.firstWeight += 1 + uint64(bits.Len(uint(len(instruction.Rune))))
		}
	}
	for character := rune(0); character < utf8.RuneSelf; character++ {
		matcher.firstASCII[character] = matcher.canStart(character)
	}
	return matcher
}

func (m *customMatcher) canStart(character rune) bool {
	for _, instruction := range m.first {
		switch instruction.Op {
		case syntax.InstRuneAny:
			return true
		case syntax.InstRuneAnyNotNL:
			if character != '\n' {
				return true
			}
		default:
			if instruction.MatchRune(character) {
				return true
			}
		}
	}
	return false
}

type customReader struct {
	text      []byte
	redactor  *Redactor
	weight    uint64
	exhausted bool
}

func (r *customReader) ReadRune() (rune, int, error) {
	if len(r.text) == 0 {
		return 0, 0, io.EOF
	}
	if !r.redactor.chargeScanWork(r.weight) {
		r.exhausted = true
		return 0, 0, ErrWorkLimit
	}
	character, width := utf8.DecodeRune(r.text)
	r.text = r.text[width:]
	return character, width, nil
}

func (r *Redactor) scanCustomPatterns(text []byte, matches []match, expression *customMatcher) ([]match, error) {
	reader := &customReader{redactor: r, weight: expression.weight}
	for position := 0; position < len(text); {
		character, width := utf8.DecodeRune(text[position:])
		cost := uint64(1)
		if character >= utf8.RuneSelf {
			cost = expression.firstWeight
		}
		if !r.chargeScanWork(cost) {
			return nil, ErrWorkLimit
		}
		possible := false
		if character < utf8.RuneSelf {
			possible = expression.firstASCII[character]
		} else {
			possible = expression.canStart(character)
		}
		if !possible {
			position += width
			continue
		}
		base := position
		matcher := expression.start
		if position > 0 {
			_, previousWidth := utf8.DecodeLastRune(text[:position])
			base -= previousWidth
			matcher = expression.after
		}
		reader.text = text[base:]
		index := matcher.FindReaderIndex(reader)
		// regexp treats any reader error as EOF. Discard even a successful
		// match after exhaustion: otherwise '$' could match an artificial end.
		if reader.exhausted {
			return nil, ErrWorkLimit
		}
		if index == nil {
			position += width
			continue
		}
		end := base + index[1]
		var err error
		matches, err = appendMatch(matches, position, end, entityCustom, 64)
		if err != nil {
			return nil, err
		}
		position = end
	}
	return matches, nil
}

func customPatternTouchesPlaceholder(expression *regexp.Regexp) bool {
	corpus := make([]byte, 0, 4_096)
	for entity := EntityEmail; entity <= EntityDatabaseCredential; entity++ {
		value := placeholder(entity)
		if expression.MatchString(value) {
			return true
		}
		corpus = append(corpus, value...)
	}
	for _, value := range []string{placeholder(entityCustom), placeholder(entityCustom), "<REDACTED>"} {
		if expression.MatchString(value) {
			return true
		}
		corpus = append(corpus, value...)
	}
	return expression.Match(corpus)
}
