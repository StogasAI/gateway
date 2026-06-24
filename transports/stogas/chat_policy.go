package stogas

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	maxMetadataKeys        = 16
	maxMetadataKeyBytes    = 64
	maxMetadataValueBytes  = 512
	maxPromptCacheKeyBytes = 256
)

func validateChatCompletionPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteChat {
		return nil
	}
	raw := state.Resolution.RawBody()
	if len(raw) == 0 {
		return invalidRequest("Invalid chat completion request")
	}
	if _, ok := raw["model"]; !ok {
		return invalidRequest("model is required")
	}
	if _, ok := raw["messages"]; !ok {
		return invalidRequest("messages is required")
	}
	for _, name := range []string{"audio", "function_call", "functions", "safety_identifier", "store", "user", "container", "fallbacks", "inference_geo", "stream_options"} {
		if _, ok := raw[name]; ok {
			return invalidRequest(name + " is not supported by Stogas API")
		}
	}
	if state.Resolution.Provider != schemas.Anthropic {
		for _, name := range []string{"mcp_servers", "cache_control", "task_budget", "context_management"} {
			if _, ok := raw[name]; ok {
				return invalidRequest(name + " is only supported for Anthropic deployments")
			}
		}
	}
	if err := validateNumericRange(raw, "frequency_penalty", -2, 2); err != nil {
		return err
	}
	if err := validateNumericRange(raw, "presence_penalty", -2, 2); err != nil {
		return err
	}
	if err := validateNumericRange(raw, "temperature", 0, 2); err != nil {
		return err
	}
	if err := validateNumericRange(raw, "top_p", 0, 1); err != nil {
		return err
	}
	if err := validatePositiveInteger(raw, "max_completion_tokens"); err != nil {
		return err
	}
	if err := validatePositiveInteger(raw, "max_tokens"); err != nil {
		return err
	}
	if err := validateIntegerAtLeast(raw, "top_logprobs", 0); err != nil {
		return err
	}
	if _, ok := raw["top_logprobs"]; ok && !rawBool(raw["logprobs"]) {
		return invalidRequest("top_logprobs requires logprobs=true")
	}
	if err := validateInteger(raw, "seed"); err != nil {
		return err
	}
	if err := validateLogitBias(raw["logit_bias"]); err != nil {
		return err
	}
	if err := validateMetadata(raw["metadata"]); err != nil {
		return err
	}
	if err := validateModalities(raw["modalities"]); err != nil {
		return err
	}
	if err := validateN(raw["n"]); err != nil {
		return err
	}
	if err := validatePromptCacheKey(raw["prompt_cache_key"], "prompt_cache_key"); err != nil {
		return err
	}
	if err := validatePromptCacheKey(raw["prompt_cache_isolation_key"], "prompt_cache_isolation_key"); err != nil {
		return err
	}
	if err := validateReasoningAliases(raw); err != nil {
		return err
	}
	if err := validateChatMessagesTextOnly(raw["messages"]); err != nil {
		return err
	}
	if err := validateChatTools(raw["tools"]); err != nil {
		return err
	}
	if err := validateChatToolChoice(raw["tool_choice"]); err != nil {
		return err
	}
	return nil
}

func invalidRequest(message string) error {
	return catalog.APIError{StatusCode: http.StatusBadRequest, Type: catalog.ErrorTypeInvalidRequest, Message: message}
}

func validateNumericRange(raw map[string]json.RawMessage, name string, min float64, max float64) error {
	valueRaw, ok := raw[name]
	if !ok {
		return nil
	}
	var value float64
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be a number")
	}
	if value < min || value > max {
		return invalidRequest(name + " is outside the supported range")
	}
	return nil
}

func validatePositiveInteger(raw map[string]json.RawMessage, name string) error {
	return validateIntegerAtLeast(raw, name, 1)
}

func validateIntegerAtLeast(raw map[string]json.RawMessage, name string, min int) error {
	valueRaw, ok := raw[name]
	if !ok {
		return nil
	}
	var value int
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be an integer")
	}
	if value < min {
		return invalidRequest(name + " is outside the supported range")
	}
	return nil
}

func validateInteger(raw map[string]json.RawMessage, name string) error {
	valueRaw, ok := raw[name]
	if !ok {
		return nil
	}
	var value int
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be an integer")
	}
	return nil
}

func rawBool(raw json.RawMessage) bool {
	var value bool
	return sonic.Unmarshal(raw, &value) == nil && value
}

func validateLogitBias(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var values map[string]float64
	if err := sonic.Unmarshal(raw, &values); err != nil {
		return invalidRequest("logit_bias must be an object")
	}
	for tokenID, bias := range values {
		if strings.TrimSpace(tokenID) == "" {
			return invalidRequest("logit_bias token ids must be non-empty strings")
		}
		if bias < -100 || bias > 100 {
			return invalidRequest("logit_bias values must be between -100 and 100")
		}
	}
	return nil
}

func validateMetadata(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var metadata map[string]any
	if err := sonic.Unmarshal(raw, &metadata); err != nil {
		return invalidRequest("metadata must be an object")
	}
	if len(metadata) > maxMetadataKeys {
		return invalidRequest("metadata supports at most 16 keys")
	}
	for key, value := range metadata {
		if key == "" || len(key) > maxMetadataKeyBytes || !utf8.ValidString(key) {
			return invalidRequest("metadata keys must be valid strings up to 64 bytes")
		}
		text, ok := value.(string)
		if !ok {
			return invalidRequest("metadata values must be strings")
		}
		if len(text) > maxMetadataValueBytes || !utf8.ValidString(text) {
			return invalidRequest("metadata values must be valid strings up to 512 bytes")
		}
	}
	return nil
}

func validateModalities(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var modalities []string
	if err := sonic.Unmarshal(raw, &modalities); err != nil {
		return invalidRequest("modalities must be an array")
	}
	if len(modalities) != 1 || modalities[0] != "text" {
		return invalidRequest("modalities must be exactly [\"text\"]")
	}
	return nil
}

func validateN(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var value int
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return invalidRequest("n must be an integer")
	}
	if value != 1 {
		return invalidRequest("n must be 1")
	}
	return nil
}

func validatePromptCacheKey(raw json.RawMessage, name string) error {
	if len(raw) == 0 {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return invalidRequest(name + " must be a string")
	}
	if value == "" || len(value) > maxPromptCacheKeyBytes || strings.ContainsAny(value, "\x00\r\n") || !utf8.ValidString(value) {
		return invalidRequest(name + " must be a non-empty string up to 256 bytes without control line breaks")
	}
	return nil
}

func validateReasoningAliases(raw map[string]json.RawMessage) error {
	reasoning, hasReasoning := rawObject(raw["reasoning"])
	for _, item := range []struct {
		alias string
		field string
	}{
		{"reasoning_effort", "effort"},
		{"reasoning_max_tokens", "max_tokens"},
		{"reasoning_display", "display"},
	} {
		if _, ok := raw[item.alias]; ok && hasReasoning {
			if _, exists := reasoning[item.field]; exists {
				return invalidRequest(item.alias + " conflicts with reasoning." + item.field)
			}
		}
	}
	return nil
}

func rawObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err != nil {
		return nil, false
	}
	return object, true
}

func validateChatMessagesTextOnly(raw json.RawMessage) error {
	var messages []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &messages); err != nil {
		return invalidRequest("messages must be an array")
	}
	for _, message := range messages {
		contentRaw, ok := message["content"]
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(string(contentRaw))
		if trimmed == "" || trimmed == "null" || trimmed[0] == '"' {
			continue
		}
		var blocks []map[string]json.RawMessage
		if err := sonic.Unmarshal(contentRaw, &blocks); err != nil {
			return invalidRequest("message content must be text")
		}
		for _, block := range blocks {
			if rawString(block["type"]) != "text" {
				return invalidRequest("Only text message content is supported")
			}
		}
	}
	return nil
}

func validateChatTools(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &tools); err != nil {
		return invalidRequest("tools must be an array")
	}
	for _, tool := range tools {
		switch rawString(tool["type"]) {
		case "function", "custom":
		default:
			return invalidRequest("Only function and custom tools are supported")
		}
	}
	return nil
}

func validateChatToolChoice(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err != nil {
		return invalidRequest("tool_choice must select a function or custom tool")
	}
	switch rawString(object["type"]) {
	case "function", "custom":
		return nil
	default:
		return invalidRequest("tool_choice must select a function or custom tool")
	}
}

func rawString(raw json.RawMessage) string {
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}
