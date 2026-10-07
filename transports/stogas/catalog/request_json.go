package catalog

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"net/http"
)

const (
	maxRequestJSONDepth = 128
	// The largest explicit per-request message ceiling in the provider survey.
	maxRequestMessages = 100_000
	// MaxRequestJSONValues separates structural work from text size. It admits 100,000 ordinary
	// messages with typed content blocks while bounding dense schemas and arrays.
	MaxRequestJSONValues = 1_000_000
)

var (
	errRequestMessageLimit   = APIError{StatusCode: http.StatusRequestEntityTooLarge, Type: ErrorTypeInvalidRequest, Message: "Request exceeds the messages/input item limit"}
	errRequestJSONValueLimit = APIError{StatusCode: http.StatusRequestEntityTooLarge, Type: ErrorTypeInvalidRequest, Message: "Request exceeds the JSON structure limit"}
)

// admit, when supplied, reserves the decoded JSON structure before duplicate-name
// bookkeeping, request fields or typed message arrays are materialized. It
// receives the number of JSON values, including containers; member names and
// string contents are not values.
// Values borrow body storage; callers may replace fields but must not mutate it.
func DecodeRequestBody(body []byte, admit func(int) error) (map[string]json.RawMessage, error) {
	if admit != nil {
		values, _, err := scanRequestJSON(body, countRequestJSON)
		if err != nil {
			return nil, requestJSONError(err)
		}
		if err := admit(values); err != nil {
			return nil, err
		}
	}
	_, fields, err := scanRequestJSON(body, decodeRequestJSON)
	if err != nil {
		return nil, requestJSONError(err)
	}
	rawData := make(map[string]json.RawMessage, len(fields))
	for _, field := range fields {
		rawData[field.name] = field.value
	}
	return rawData, nil
}

func requestJSONError(err error) error {
	if errors.Is(err, errRequestMessageLimit) || errors.Is(err, errRequestJSONValueLimit) {
		return err
	}
	return ErrInvalidJSON
}

// ValidateJSONObjectText applies the request JSON ambiguity and resource limits
// to an object encoded inside a string, such as function-call arguments.
func ValidateJSONObjectText(value string) bool {
	body := bytes.TrimSpace([]byte(value))
	if len(body) == 0 || body[0] != '{' {
		return false
	}
	_, err := validateRequestJSON(body)
	return err == nil
}

func validateRequestJSON(body []byte) (int, error) {
	values, _, err := scanRequestJSON(body, validateJSON)
	return values, err
}

type requestJSONField struct {
	name  string
	value json.RawMessage
}

type requestJSONScanMode uint8

const (
	validateJSON requestJSONScanMode = iota
	countRequestJSON
	decodeRequestJSON
)

func scanRequestJSON(body []byte, mode requestJSONScanMode) (int, []requestJSONField, error) {
	// The counting pass uses the same syntax/UTF-8/surrogate validation, but
	// defers duplicate-name maps and field retention until their byte charge
	// is admitted. The second pass always rejects duplicate names.
	decoder := jsontext.NewDecoder(bytes.NewBuffer(body), jsontext.AllowDuplicateNames(mode == countRequestJSON))
	request := mode != validateJSON
	captureFields := mode == decodeRequestJSON
	if request && decoder.PeekKind() != '{' {
		return 0, nil, errors.New("expected JSON object")
	}
	values := 0
	var fields []requestJSONField
	var name string
	start := -1
	for {
		// An empty container at the boundary is valid; its child values are not.
		if decoder.StackDepth() > maxRequestJSONDepth {
			if kind := decoder.PeekKind(); kind != '}' && kind != ']' {
				return 0, nil, errors.New("JSON nesting exceeds limit")
			}
		}
		depth := decoder.StackDepth()
		container, index := decoder.StackIndex(depth)
		if request && depth == 2 && container == '[' && (name == "messages" || name == "input") && index >= maxRequestMessages && decoder.PeekKind() != ']' {
			return 0, nil, errRequestMessageLimit
		}
		if captureFields && depth == 1 && container == '{' && index%2 == 1 {
			start = int(decoder.InputOffset())
		}
		token, err := decoder.ReadToken()
		if err != nil {
			return 0, nil, err
		}
		if request && depth == 1 && container == '{' && index%2 == 0 && token.Kind() == '"' {
			name = token.String()
		}
		if start >= 0 && decoder.StackDepth() == 1 {
			end := int(decoder.InputOffset())
			// ReadToken has already validated the separator and the entire value.
			value := bytes.TrimLeft(body[start:end:end], ": \r\n\t")
			fields = append(fields, requestJSONField{name, value})
			start = -1
		}
		if kind := token.Kind(); kind != '}' && kind != ']' && !(kind == '"' && container == '{' && index%2 == 0) {
			values++
			if values > MaxRequestJSONValues {
				return 0, nil, errRequestJSONValueLimit
			}
		}
		if decoder.StackDepth() == 0 {
			break
		}
	}
	if _, err := decoder.ReadToken(); !errors.Is(err, io.EOF) {
		if err == nil {
			return 0, nil, errors.New("trailing JSON value")
		}
		return 0, nil, err
	}
	return values, fields, nil
}
