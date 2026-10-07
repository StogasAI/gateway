package stogas

import (
	"bytes"
	"encoding/json"

	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

func rawChatCacheControlExists(raw json.RawMessage, includeMessage bool) bool {
	if len(raw) == 0 {
		return false
	}
	messages, err := rawjson.Array(raw)
	if err != nil {
		return false
	}
	for _, messageRaw := range messages {
		message, err := rawjson.Object(messageRaw)
		if err != nil {
			continue
		}
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
	trimmed := bytes.TrimSpace(contentRaw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil
	}
	items, err := rawjson.Array(contentRaw)
	if err != nil {
		return nil
	}
	blocks := make([]map[string]json.RawMessage, 0, len(items))
	for _, item := range items {
		if block, err := rawjson.Object(item); err == nil {
			blocks = append(blocks, block)
		}
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
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || trimmed[0] == '"' {
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
		array, err := rawjson.Array(raw)
		if err != nil {
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
