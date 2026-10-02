package tokenizer

// The ASCII branches avoid a regexp allocation per ordinary word. Any Unicode
// boundary that might extend a match falls back to the full Unicode splitter.
func asciiPiece(s string, modern bool) int {
	if s[0] >= 128 {
		return 0
	}
	if !modern {
		if n := contraction(s); n > 0 {
			return n
		}
	}
	start := 0
	if !letter(s[0]) && !digit(s[0]) && s[0] != '\r' && s[0] != '\n' {
		start = 1
	}
	if start < len(s) {
		if s[start] >= 128 {
			return 0
		}
		if letter(s[start]) {
			i := start
			if modern {
				for i < len(s) && s[i] >= 'A' && s[i] <= 'Z' {
					i++
				}
				for i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
					i++
				}
			} else {
				for i < len(s) && letter(s[i]) {
					i++
				}
			}
			if i < len(s) && s[i] >= 128 {
				return 0
			}
			if modern {
				// Unicode case folding can match an apostrophe + long s.
				if i+1 < len(s) && s[i] == '\'' && s[i+1] >= 128 {
					return 0
				}
				i += contraction(s[i:])
			}
			return i
		}
	}
	if digit(s[0]) {
		i := 1
		for i < len(s) && i < 3 && digit(s[i]) {
			i++
		}
		if i < 3 && i < len(s) && s[i] >= 128 {
			return 0
		}
		return i
	}
	start = 0
	if s[0] == ' ' {
		start = 1
	}
	i := start
	for i < len(s) && s[i] < 128 && !space(s[i]) && !letter(s[i]) && !digit(s[i]) {
		i++
	}
	if i < len(s) && s[i] >= 128 {
		return 0
	}
	if i > start {
		for i < len(s) && (s[i] == '\r' || s[i] == '\n' || modern && s[i] == '/') {
			i++
		}
		return i
	}
	i = 0
	lastNewline := 0
	for i < len(s) && space(s[i]) {
		if s[i] == '\r' || s[i] == '\n' {
			lastNewline = i + 1
		}
		i++
	}
	if i < len(s) && s[i] >= 128 {
		return 0
	}
	if lastNewline > 0 {
		return lastNewline
	}
	// The caller implements the whitespace lookahead for both paths.
	return i
}

func letter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }
func digit(b byte) bool  { return b >= '0' && b <= '9' }
func space(b byte) bool  { return b == ' ' || b >= '\t' && b <= '\r' }
func contraction(s string) int {
	if len(s) < 2 || s[0] != '\'' {
		return 0
	}
	switch s[1] | 32 {
	case 's', 't', 'm', 'd':
		return 2
	case 'r':
		if len(s) > 2 && s[2]|32 == 'e' {
			return 3
		}
	case 'v':
		if len(s) > 2 && s[2]|32 == 'e' {
			return 3
		}
	case 'l':
		if len(s) > 2 && s[2]|32 == 'l' {
			return 3
		}
	}
	return 0
}
