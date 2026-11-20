package redaction

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// maxPlaceholderBytes bounds a numbered placeholder: the longest name and a number.
const maxPlaceholderBytes = 64

// Restorer holds the values that the restoring redactions of one request replaced, each under
// its numbered placeholder, such as <EMAIL_ADDRESS_1>. A value keeps its number through the
// request, so the provider can tell two values apart, and the same conversation numbers its
// values the same way on every turn, because the walk reads its text in the same order. The
// values never leave the gateway: they go back only into the response of the same request.
type Restorer struct {
	numbers map[restoredValue]uint32
	values  map[string]string
	counts  [entityCustom + 1]uint32
}

type restoredValue struct {
	entity Entity
	value  string
}

// numbered returns the placeholder of a value, giving the value the next number of its kind
// when the request has not held it before.
func (r *Redactor) numbered(entity Entity, value []byte) (string, error) {
	if r.restorer == nil {
		r.restorer = &Restorer{numbers: map[restoredValue]uint32{}, values: map[string]string{}}
	}
	restorer := r.restorer
	number, known := restorer.numbers[restoredValue{entity, string(value)}]
	if !known {
		// The value is kept beside the request text that held it.
		if err := r.reserveGrowth(len(value)); err != nil {
			return "", err
		}
		restorer.counts[entity]++
		number = restorer.counts[entity]
		restorer.numbers[restoredValue{entity, string(value)}] = number
	}
	base := placeholder(entity)
	name := base[:len(base)-1] + "_" + strconv.FormatUint(uint64(number), 10) + ">"
	if !known {
		restorer.values[name] = string(value)
	}
	return name, nil
}

// restore puts the values back where text holds their placeholders. In a JSON document, a
// value is written as the inside of a JSON string, so the document stays valid.
func (v *Restorer) restore(text []byte, inJSON bool) ([]byte, uint32) {
	if v == nil {
		return text, 0
	}
	var out []byte
	var restored uint32
	// out holds text[:copied] with its values back.
	copied := 0
	for search := 0; ; {
		open := bytes.IndexByte(text[search:], '<')
		if open < 0 {
			break
		}
		open += search
		end := open + 1
		for end < len(text) && end-open < maxPlaceholderBytes && placeholderByte(text[end]) {
			end++
		}
		search = open + 1
		if end >= len(text) || text[end] != '>' {
			continue
		}
		value, known := v.values[string(text[open:end+1])]
		if !known {
			continue
		}
		out = append(out, text[copied:open]...)
		if inJSON {
			out = appendJSONStringBody(out, value)
		} else {
			out = append(out, value...)
		}
		restored++
		copied, search = end+1, end+1
	}
	if restored == 0 {
		return text, 0
	}
	return append(out, text[copied:]...), restored
}

// UnfinishedPlaceholder returns the end of text that more text could complete into a numbered
// placeholder, or "" when the text ends in none. A stream holds that end back until the rest
// arrives.
func UnfinishedPlaceholder(text string) string {
	open := strings.LastIndexByte(text, '<')
	if open < 0 || len(text)-open >= maxPlaceholderBytes {
		return ""
	}
	for index := open + 1; index < len(text); index++ {
		if !placeholderByte(text[index]) {
			return ""
		}
	}
	return text[open:]
}

func placeholderByte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}

// appendJSONStringBody appends value as the inside of a JSON string.
func appendJSONStringBody(out []byte, value string) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return out
	}
	encoded := buffer.Bytes()
	return append(out, encoded[1:len(encoded)-2]...)
}
