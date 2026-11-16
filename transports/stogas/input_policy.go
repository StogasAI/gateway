package stogas

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

func requiredInputString(object map[string]json.RawMessage, key string, path string, allowEmpty bool) (string, error) {
	raw, ok := object[key]
	if !ok {
		return "", invalidRequest(path + "." + key + " is required")
	}
	value, ok := rawStringValue(raw)
	if !ok {
		return "", invalidRequest(path + "." + key + " must be a string")
	}
	if !allowEmpty && strings.TrimSpace(value) == "" {
		return "", invalidRequest(path + "." + key + " must be non-empty")
	}
	return value, nil
}

func rejectUnsupportedInputKeys(object map[string]json.RawMessage, path string, keys ...string) error {
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	for key, value := range object {
		if !rawJSONValueSet(value) {
			delete(object, key)
			continue
		}
		if !allowed[key] {
			return invalidRequest(path + "." + key + " is not supported")
		}
	}
	return nil
}

func requiredInputStrings(item map[string]json.RawMessage, path string, keys ...string) error {
	for _, key := range keys {
		if _, err := requiredInputString(item, key, path, false); err != nil {
			return err
		}
	}
	return nil
}

func optionalInputStrings(item map[string]json.RawMessage, path string, keys ...string) error {
	for _, key := range keys {
		if raw := item[key]; rawJSONValueSet(raw) {
			if _, ok := rawStringValue(raw); !ok {
				return invalidRequest(path + "." + key + " must be a string")
			}
		}
	}
	return nil
}

// inputShape lists the keys that an input object may hold and what each holds: an inputKind,
// another object's shape, or an array of objects of a shape.
type inputShape map[string]any

type inputObjects inputShape

type inputKind uint8

const (
	inputText inputKind = iota + 1
	inputTexts
)

// checkInputShape refuses a key that the shape does not list and a value of another kind. A null
// value counts as absent.
func checkInputShape(object map[string]json.RawMessage, path string, shape inputShape) error {
	for key, raw := range object {
		if !rawJSONValueSet(raw) {
			continue
		}
		field := path + "." + key
		switch kind := shape[key].(type) {
		case inputKind:
			if _, ok := rawStringValue(raw); kind == inputText && !ok {
				return invalidRequest(field + " must be a string")
			}
			var values []string
			if kind == inputTexts && sonic.Unmarshal(raw, &values) != nil {
				return invalidRequest(field + " must be an array of strings")
			}
		case inputShape:
			nested, ok := rawObject(raw)
			if !ok {
				return invalidRequest(field + " must be an object")
			}
			if err := checkInputShape(nested, field, kind); err != nil {
				return err
			}
		case inputObjects:
			items, err := rawjson.Array(raw)
			if err != nil {
				return invalidRequest(field + " must be an array")
			}
			for index, itemRaw := range items {
				itemPath := fmt.Sprintf("%s[%d]", field, index)
				nested, ok := rawObject(itemRaw)
				if !ok {
					return invalidRequest(itemPath + " must be an object")
				}
				if err := checkInputShape(nested, itemPath, inputShape(kind)); err != nil {
					return err
				}
			}
		default:
			return invalidRequest(field + " is not supported")
		}
	}
	return nil
}
