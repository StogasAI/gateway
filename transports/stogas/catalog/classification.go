package catalog

import (
	"bytes"
	"encoding/json"

	"github.com/maximhq/bifrost/transports/stogas/plugins/classification"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// newestUserLanguage returns the language of the request's newest user message that holds
// prose, which a person wrote, or "" without one. System prompts, tool results and the text that
// the gateway extracts from files are not a person's own words.
func newestUserLanguage(route Route, raw map[string]json.RawMessage) string {
	field, partType := "messages", "text"
	if route == RouteResponses {
		field, partType = "input", "input_text"
	}
	value := bytes.TrimSpace(raw[field])
	if len(value) > 0 && value[0] == '"' {
		return contentLanguage(value, partType)
	}
	messages, err := rawjson.Array(value)
	if err != nil {
		return ""
	}
	for i := len(messages) - 1; i >= 0; i-- {
		message, err := rawjson.Object(messages[i])
		if err != nil {
			continue
		}
		var role, itemType string
		if json.Unmarshal(message["role"], &role) != nil || role != "user" {
			continue
		}
		if kind := message["type"]; kind != nil && (json.Unmarshal(kind, &itemType) != nil || itemType != "message") {
			continue
		}
		if language := contentLanguage(message["content"], partType); language != "" {
			return language
		}
	}
	return ""
}

// contentLanguage returns the language of a message's text content, or "" when it holds no
// prose.
func contentLanguage(content json.RawMessage, partType string) string {
	var sample classification.Sample
	content = bytes.TrimSpace(content)
	if len(content) > 0 && content[0] == '"' {
		var text string
		if json.Unmarshal(content, &text) == nil {
			sample.Write(text)
		}
	} else if parts, err := rawjson.Array(content); err == nil {
		for _, raw := range parts {
			var part struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}
			if sample.Full() {
				break
			}
			if json.Unmarshal(raw, &part) == nil && part.Type == partType {
				sample.Write(part.Text)
				sample.Break()
			}
		}
	}
	return sample.Language()
}
