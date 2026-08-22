package stogas

import (
	"encoding/json"
	"strings"
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
