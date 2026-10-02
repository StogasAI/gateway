package catalog

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// Read only feature selectors. Large prompt strings and tool schemas are skipped
// by the JSON decoder, rather than decoded into provider request types here.
func requestCapabilities(raw map[string]json.RawMessage, route Route, shared Capabilities) (Capabilities, error) {
	var required Capabilities
	for _, name := range []string{"prompt_cache_key", "prompt_cache_retention", "prompt_cache_options"} {
		value := bytes.TrimSpace(raw[name])
		if len(value) == 0 || bytes.Equal(value, []byte("null")) {
			continue
		}
		if name == "prompt_cache_options" {
			required.ExplicitPromptCaching = true
		} else {
			required.ImplicitPromptCaching = true
		}
	}
	for _, field := range []struct {
		name      string
		supported bool
		target    *bool
	}{{"stream", shared.Streaming, &required.Streaming}, {"parallel_tool_calls", shared.ParallelFunctionCalling, &required.ParallelFunctionCalling}} {
		if value, ok := raw[field.name]; ok && !field.supported {
			if err := json.Unmarshal(value, field.target); err != nil {
				return required, ErrInvalidJSON
			}
		}
	}
	var tools []struct{ Type string }
	if value, ok := raw["tools"]; ok && !shared.FunctionCalling {
		if err := json.Unmarshal(value, &tools); err != nil {
			return required, ErrInvalidJSON
		}
		for _, tool := range tools {
			if tool.Type == "function" || tool.Type == "custom" {
				required.FunctionCalling = true
			}
		}
	}
	if value, ok := raw["functions"]; ok && route == RouteChat && !shared.FunctionCalling {
		var functions []struct{}
		if err := json.Unmarshal(value, &functions); err != nil {
			return required, ErrInvalidJSON
		}
		required.FunctionCalling = required.FunctionCalling || len(functions) != 0
	}
	for _, name := range []string{"tool_choice", "function_call"} {
		if shared.ToolChoice {
			break
		}
		value := bytes.TrimSpace(raw[name])
		if len(value) == 0 || bytes.Equal(value, []byte("null")) {
			continue
		}
		choice := rawStringValue(value)
		if value[0] != '"' || (choice != "auto" && choice != "none") {
			required.ToolChoice = true
		}
	}
	var format struct{ Type string }
	if value, ok := raw["response_format"]; ok && route == RouteChat && !shared.StructuredOutputs {
		if err := json.Unmarshal(value, &format); err != nil {
			return required, ErrInvalidJSON
		}
	}
	if value, ok := raw["text"]; ok && route == RouteResponses && !shared.StructuredOutputs {
		var text struct{ Format struct{ Type string } }
		if err := json.Unmarshal(value, &text); err != nil {
			return required, ErrInvalidJSON
		}
		format = text.Format
	}
	required.StructuredOutputs = format.Type == "json_schema"
	if shared.SystemMessages {
		return required, nil
	}
	messageField := "messages"
	if route == RouteResponses {
		messageField = "input"
		instructions := bytes.TrimSpace(raw["instructions"])
		required.SystemMessages = len(instructions) != 0 && !bytes.Equal(instructions, []byte("null")) && !bytes.Equal(instructions, []byte(`""`))
	}
	if value := bytes.TrimSpace(raw[messageField]); len(value) > 0 && value[0] == '[' {
		var messages []struct{ Role string }
		if err := json.Unmarshal(value, &messages); err != nil {
			return required, ErrInvalidJSON
		}
		for _, message := range messages {
			if message.Role == "system" || message.Role == "developer" {
				required.SystemMessages = true
				break
			}
		}
	}
	return required, nil
}

// Features supported by every candidate cannot narrow the selection. Avoid
// traversing prompt containers merely to rediscover that they are acceptable.
func sharedRequestCapabilities(selections []routingSelection) Capabilities {
	shared := Capabilities{Streaming: true, FunctionCalling: true, ParallelFunctionCalling: true, ToolChoice: true, StructuredOutputs: true, SystemMessages: true}
	for _, selection := range selections {
		c := selection.deployment.Capabilities
		shared.Streaming = shared.Streaming && c.Streaming
		shared.FunctionCalling = shared.FunctionCalling && c.FunctionCalling
		shared.ParallelFunctionCalling = shared.ParallelFunctionCalling && c.ParallelFunctionCalling
		shared.ToolChoice = shared.ToolChoice && c.ToolChoice
		shared.StructuredOutputs = shared.StructuredOutputs && c.StructuredOutputs
		shared.SystemMessages = shared.SystemMessages && c.SystemMessages
	}
	return shared
}

func validateRequestCapabilities(required, supported Capabilities) error {
	for _, feature := range []struct {
		name                string
		required, supported bool
	}{
		{"streaming", required.Streaming, supported.Streaming},
		{"function calling", required.FunctionCalling, supported.FunctionCalling},
		{"parallel function calling", required.ParallelFunctionCalling, supported.ParallelFunctionCalling},
		{"tool choice", required.ToolChoice, supported.ToolChoice},
		{"structured outputs", required.StructuredOutputs, supported.StructuredOutputs},
		{"system messages", required.SystemMessages, supported.SystemMessages},
		{"prompt caching", required.ImplicitPromptCaching, supported.ImplicitPromptCaching},
		{"explicit prompt caching", required.ExplicitPromptCaching, supported.ExplicitPromptCaching},
	} {
		if feature.required && !feature.supported {
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: feature.name + " is not supported for the selected deployment"}
		}
	}
	return nil
}
