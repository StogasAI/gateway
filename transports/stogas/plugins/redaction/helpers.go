package redaction

func isASCIILetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isASCIIDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func isASCIIAlphanumeric(value byte) bool {
	return isASCIILetter(value) || isASCIIDigit(value)
}

func allASCIIAlphanumeric(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		if !isASCIIAlphanumeric(character) {
			return false
		}
	}
	return true
}

func isIdentifierByte(value byte) bool {
	return isASCIIAlphanumeric(value) || value == '_'
}

func lowerASCII(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

func equalFoldASCII(value []byte, expected string) bool {
	if len(value) != len(expected) {
		return false
	}
	for index := range value {
		if lowerASCII(value[index]) != lowerASCII(expected[index]) {
			return false
		}
	}
	return true
}

func hasPrefixFoldASCII(value []byte, prefix string) bool {
	return len(value) >= len(prefix) && equalFoldASCII(value[:len(prefix)], prefix)
}

func hasNearbyContext(text []byte, start, end int, terms ...string) bool {
	windowStart := start - 72
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + 40
	if windowEnd > len(text) {
		windowEnd = len(text)
	}
	for _, term := range terms {
		if containsContextTerm(text, windowStart, windowEnd, term) {
			return true
		}
	}
	return false
}

func containsContextTerm(text []byte, windowStart, windowEnd int, term string) bool {
	if term == "" {
		return false
	}
	for start := windowStart; start < windowEnd; start++ {
		end, ok := contextTermEnd(text[:windowEnd], start, term)
		if !ok || end > windowEnd {
			continue
		}
		if isASCIIAlphanumeric(term[0]) && start > 0 && isASCIIAlphanumeric(text[start-1]) {
			continue
		}
		if isASCIIAlphanumeric(term[len(term)-1]) && end < len(text) && isASCIIAlphanumeric(text[end]) {
			continue
		}
		if contextInsidePlaceholder(text, start) {
			continue
		}
		return true
	}
	return false
}

// Typed replacements describe a previous match, not a label supplied by the
// source. This affects context only; it never exempts surrounding redaction.
func contextInsidePlaceholder(text []byte, position int) bool {
	for start := position; start >= max(0, position-64); start-- {
		if text[start] == '>' {
			return false
		}
		if text[start] != '<' {
			continue
		}
		for entity := EntityEmail; entity <= entityCustom; entity++ {
			value := placeholder(entity)
			end := start + len(value)
			if end <= len(text) && string(text[start:end]) == value {
				return true
			}
		}
		return false
	}
	return false
}

func contextTermEnd(text []byte, start int, term string) (int, bool) {
	textPosition := start
	termPosition := 0
	for termPosition < len(term) {
		if contextSeparator(term[termPosition]) {
			for termPosition < len(term) && contextSeparator(term[termPosition]) {
				termPosition++
			}
			if textPosition >= len(text) || !contextSeparator(text[textPosition]) {
				return start, false
			}
			for textPosition < len(text) && contextSeparator(text[textPosition]) {
				textPosition++
			}
			continue
		}
		if textPosition >= len(text) || lowerASCII(text[textPosition]) != lowerASCII(term[termPosition]) {
			return start, false
		}
		textPosition++
		termPosition++
	}
	return textPosition, true
}

func contextSeparator(value byte) bool {
	return value == ' ' || value == '\t' || value == '_' || value == '-'
}

func wordBoundaryBefore(text []byte, start int) bool {
	return start == 0 || !isIdentifierByte(text[start-1])
}

func wordBoundaryAfter(text []byte, end int) bool {
	return end >= len(text) || !isIdentifierByte(text[end])
}

func allEqual(value []byte) bool {
	if len(value) < 2 {
		return true
	}
	for index := 1; index < len(value); index++ {
		if value[index] != value[0] {
			return false
		}
	}
	return true
}
