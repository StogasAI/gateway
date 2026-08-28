package redaction

import "regexp"

const maxTypedPlaceholderBytes = 64

func scanCustomPatterns(text []byte, matches []match, expression *regexp.Regexp) ([]match, error) {
	remaining := maxMatchesPerText - len(matches)
	if remaining <= 0 {
		return nil, ErrMatchLimit
	}
	indexes := expression.FindAllIndex(text, remaining+1)
	if len(indexes) > remaining {
		return nil, ErrMatchLimit
	}
	for _, index := range indexes {
		if len(index) != 2 || index[0] >= index[1] || overlapsTypedPlaceholder(text, index[0], index[1]) {
			continue
		}
		var err error
		matches, err = appendMatch(matches, index[0], index[1], entityCustom, 64)
		if err != nil {
			return nil, err
		}
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

func overlapsTypedPlaceholder(text []byte, start, end int) bool {
	searchStart := start - maxTypedPlaceholderBytes + 1
	if searchStart < 0 {
		searchStart = 0
	}
	for position := searchStart; position < end && position < len(text); position++ {
		if text[position] != '<' {
			continue
		}
		placeholderEnd := typedPlaceholderEndAt(text, position)
		if placeholderEnd > start {
			return true
		}
	}
	return false
}

func typedPlaceholderEndAt(text []byte, start int) int {
	for entity := EntityEmail; entity <= EntityDatabaseCredential; entity++ {
		value := placeholder(entity)
		if bytesHaveStringPrefix(text[start:], value) {
			return start + len(value)
		}
	}
	for _, value := range []string{placeholder(entityCustom), "<REDACTED>"} {
		if bytesHaveStringPrefix(text[start:], value) {
			return start + len(value)
		}
	}
	return 0
}

func bytesHaveStringPrefix(value []byte, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for index := range prefix {
		if value[index] != prefix[index] {
			return false
		}
	}
	return true
}
