package rawjson

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
)

// Array borrows values from source. Callers must not mutate the returned byte
// slices or source while either is in use.
// Keeping the original bytes avoids copying whole prompts at each JSON layer.
func Array(source []byte) ([]json.RawMessage, error) {
	decoder := jsontext.NewDecoder(bytes.NewBuffer(source))
	if token, err := decoder.ReadToken(); err != nil || token.Kind() != '[' {
		return nil, errors.New("expected JSON array")
	}
	values := make([]json.RawMessage, 0)
	for decoder.PeekKind() != ']' {
		value, err := borrowedValue(decoder, source)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, finishContainer(decoder)
}

// Object borrows member values under the same ownership rules as Array.
func Object(source []byte) (map[string]json.RawMessage, error) {
	decoder := jsontext.NewDecoder(bytes.NewBuffer(source))
	if token, err := decoder.ReadToken(); err != nil || token.Kind() != '{' {
		return nil, errors.New("expected JSON object")
	}
	values := make(map[string]json.RawMessage)
	for decoder.PeekKind() != '}' {
		name, err := decoder.ReadToken()
		if err != nil {
			return nil, err
		}
		key := name.String()
		value, err := borrowedValue(decoder, source)
		if err != nil {
			return nil, err
		}
		values[key] = value
	}
	return values, finishContainer(decoder)
}

func borrowedValue(decoder *jsontext.Decoder, source []byte) (json.RawMessage, error) {
	value, err := decoder.ReadValue()
	if err != nil {
		return nil, err
	}
	end := int(decoder.InputOffset())
	return source[end-len(value) : end : end], nil
}

func finishContainer(decoder *jsontext.Decoder) error {
	if _, err := decoder.ReadToken(); err != nil {
		return err
	}
	if _, err := decoder.ReadToken(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("trailing JSON value")
	}
	return nil
}
