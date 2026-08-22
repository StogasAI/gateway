package rawjson

import (
	"encoding/json"
	"strings"

	"github.com/bytedance/sonic"
)

func NormalizedStringField(object map[string]json.RawMessage, key string) string {
	raw, ok := object[key]
	if !ok {
		return ""
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(value))
}
