package stogas

import (
	"encoding/json"
	"strings"

	"github.com/bytedance/sonic"
)

func rawChatCacheControlExists(raw json.RawMessage, includeMessage bool) bool {
	if len(raw) == 0 {
		return false
	}
	var messages []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &messages); err != nil {
		return false
	}
	for _, message := range messages {
		if _, ok := message["cache_control"]; includeMessage && ok {
			return true
		}
		for _, block := range rawChatMessageContentBlocks(message) {
			if _, ok := block["cache_control"]; ok {
				return true
			}
		}
	}
	return false
}

func rawChatMessageContentBlocks(message map[string]json.RawMessage) []map[string]json.RawMessage {
	contentRaw := message["content"]
	trimmed := strings.TrimSpace(string(contentRaw))
	if len(contentRaw) == 0 || trimmed == "" || trimmed == "null" || trimmed[0] != '[' {
		return nil
	}
	var blocks []map[string]json.RawMessage
	if err := sonic.Unmarshal(contentRaw, &blocks); err != nil {
		return nil
	}
	return blocks
}

func rawResponsesCacheControlExists(raw json.RawMessage) bool {
	return rawResponsesCacheControlMatches(raw, func(json.RawMessage) bool { return true })
}

func rawResponsesCacheControlMatches(raw json.RawMessage, matches func(json.RawMessage) bool) bool {
	if len(raw) == 0 {
		return false
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed[0] == '"' {
		return false
	}
	switch trimmed[0] {
	case '{':
		object, ok := rawObject(raw)
		if !ok {
			return false
		}
		if cacheControl, ok := object["cache_control"]; ok && matches(cacheControl) {
			return true
		}
		return rawResponsesCacheControlMatches(object["content"], matches)
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return false
		}
		for _, child := range array {
			if rawResponsesCacheControlMatches(child, matches) {
				return true
			}
		}
	}
	return false
}
