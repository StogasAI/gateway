package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// Independent encoding/json v1 oracle for the strict request boundary. Keep
// explicit Unicode/duplicate/depth checks: v1 accepts several ambiguous forms.
func referenceValidateRequestJSON(body []byte) error {
	if !utf8.Valid(body) {
		return errors.New("JSON body is not valid UTF-8")
	}
	if !referenceValidJSONUnicodeEscapes(body) {
		return errors.New("JSON string contains an invalid Unicode surrogate")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	values := 0
	if err := referenceScanRequestJSONValue(decoder, 0, &values); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func referenceValidJSONUnicodeEscapes(body []byte) bool {
	inString := false
	for index := 0; index < len(body); index++ {
		switch body[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			index++
			if index >= len(body) {
				return false
			}
			if body[index] != 'u' {
				continue
			}
			value, ok := referenceParseJSONHex4(body, index+1)
			if !ok {
				return false
			}
			index += 4
			switch {
			case value >= 0xd800 && value <= 0xdbff:
				if index+6 >= len(body) || body[index+1] != '\\' || body[index+2] != 'u' {
					return false
				}
				low, lowOK := referenceParseJSONHex4(body, index+3)
				if !lowOK || low < 0xdc00 || low > 0xdfff {
					return false
				}
				index += 6
			case value >= 0xdc00 && value <= 0xdfff:
				return false
			}
		}
	}
	return true
}

func referenceParseJSONHex4(body []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(body) {
		return 0, false
	}
	var value uint16
	for _, digit := range body[start : start+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func referenceScanRequestJSONValue(decoder *json.Decoder, depth int, values *int) error {
	*values++
	if *values > MaxRequestJSONValues {
		return errors.New("JSON value limit exceeded")
	}
	if depth > maxRequestJSONDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := referenceScanRequestJSONValue(decoder, depth+1, values); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := referenceScanRequestJSONValue(decoder, depth+1, values); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
