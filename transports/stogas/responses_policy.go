package stogas

import (
	"encoding/json"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	openaiadapter "github.com/maximhq/bifrost/transports/stogas/providers/openai"
)

func validateResponsesPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteResponses {
		return nil
	}
	raw := state.Resolution.RawBody()
	if len(raw) == 0 {
		return invalidRequest("Invalid responses request")
	}
	if _, ok := raw["model"]; !ok {
		return invalidRequest("model is required")
	}
	if _, ok := raw["input"]; !ok {
		return invalidRequest("input is required")
	}
	for _, name := range []string{
		"background",
		"cache_control",
		"container",
		"context_management",
		"conversation",
		"fallbacks",
		"include",
		"mcp_servers",
		"previous_response_id",
		"prompt_cache_retention",
		"safety_identifier",
		"stream_options",
		"store",
		"task_budget",
		"user",
	} {
		if _, ok := raw[name]; ok {
			return invalidRequest(name + " is not supported by Stogas API")
		}
	}
	if err := validateJSONBool(raw, "stream"); err != nil {
		return err
	}
	if err := validateJSONBool(raw, "parallel_tool_calls"); err != nil {
		return err
	}
	if err := validateString(raw, "instructions"); err != nil {
		return err
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
	if err := validatePositiveInteger(raw, "max_output_tokens"); err != nil {
		return err
	}
	if err := validatePositiveInteger(raw, "max_tool_calls"); err != nil {
		return err
	}
	if err := validateIntegerAtLeast(raw, "top_logprobs", 0); err != nil {
		return err
	}
	if err := validateMetadata(raw["metadata"]); err != nil {
		return err
	}
	if err := validatePromptCacheKey(raw["prompt_cache_key"], "prompt_cache_key"); err != nil {
		return err
	}
	if err := validateResponsesReasoning(raw); err != nil {
		return err
	}
	if err := validateResponsesText(raw["text"]); err != nil {
		return err
	}
	if err := validateResponsesTruncation(raw["truncation"]); err != nil {
		return err
	}
	tools, err := parseResponsesTools(state, raw["tools"])
	if err != nil {
		return err
	}
	if len(tools) == 0 {
		if _, ok := raw["max_tool_calls"]; ok {
			return invalidRequest("max_tool_calls requires supported tools")
		}
		if _, ok := raw["parallel_tool_calls"]; ok {
			return invalidRequest("parallel_tool_calls requires supported tools")
		}
	}
	if err := validateResponsesToolChoice(raw["tool_choice"], tools); err != nil {
		return err
	}
	return validateResponsesInputTextOnly(raw["input"])
}

func validateJSONBool(raw map[string]json.RawMessage, name string) error {
	valueRaw, ok := raw[name]
	if !ok {
		return nil
	}
	var value bool
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be a boolean")
	}
	return nil
}

func validateString(raw map[string]json.RawMessage, name string) error {
	valueRaw, ok := raw[name]
	if !ok {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be a string")
	}
	return nil
}

func validateResponsesReasoning(raw map[string]json.RawMessage) error {
	reasoning, hasReasoning := rawObject(raw["reasoning"])
	if _, ok := raw["reasoning.effort"]; ok && hasReasoning {
		if _, exists := reasoning["effort"]; exists {
			return invalidRequest("reasoning.effort conflicts with reasoning.effort")
		}
	}
	if _, ok := raw["reasoning"]; ok && !hasReasoning {
		return invalidRequest("reasoning must be an object")
	}
	return nil
}

func validateResponsesText(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	text, ok := rawObject(raw)
	if !ok {
		return invalidRequest("text must be an object")
	}
	for name := range text {
		switch name {
		case "format", "verbosity":
		default:
			return invalidRequest("text." + name + " is not supported by Stogas API")
		}
	}
	if rawVerbosity, ok := text["verbosity"]; ok {
		switch rawString(rawVerbosity) {
		case "low", "medium", "high":
		default:
			return invalidRequest("text.verbosity must be low, medium, or high")
		}
	}
	if rawFormat, ok := text["format"]; ok {
		if err := validateResponsesTextFormat(rawFormat); err != nil {
			return err
		}
	}
	return nil
}

func validateResponsesTextFormat(raw json.RawMessage) error {
	format, ok := rawObject(raw)
	if !ok {
		return invalidRequest("text.format must be an object")
	}
	formatType := rawString(format["type"])
	switch formatType {
	case "text", "json_object":
		return nil
	case "json_schema":
		if strings.TrimSpace(rawString(format["name"])) == "" {
			return invalidRequest("text.format.name is required for json_schema")
		}
		if _, ok := format["schema"]; !ok {
			return invalidRequest("text.format.schema is required for json_schema")
		}
		if rawStrict, ok := format["strict"]; ok {
			var strict bool
			if err := sonic.Unmarshal(rawStrict, &strict); err != nil {
				return invalidRequest("text.format.strict must be a boolean")
			}
		}
		return nil
	default:
		return invalidRequest("text.format.type must be text, json_object, or json_schema")
	}
}

func validateResponsesTruncation(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	switch rawString(raw) {
	case "auto", "disabled":
		return nil
	default:
		return invalidRequest("truncation must be auto or disabled")
	}
}

func parseResponsesTools(state *State, raw json.RawMessage) ([]map[string]json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &tools); err != nil {
		return nil, invalidRequest("tools must be an array")
	}
	names := map[string]bool{}
	for _, tool := range tools {
		kind := responsesToolKind(rawString(tool["type"]))
		switch kind {
		case "function":
			name := strings.TrimSpace(rawString(tool["name"]))
			if name == "" {
				return nil, invalidRequest("function tools require a name")
			}
			names[name] = true
		case "web_search", "web_search_preview":
			if state != nil && !responsesHostedToolIsPriced(state, kind) {
				return nil, invalidRequest("Hosted tools are not supported for this deployment")
			}
		default:
			return nil, invalidRequest("Only function and priced hosted web search tools are supported")
		}
	}
	return tools, nil
}

func responsesHostedToolIsPriced(state *State, kind string) bool {
	if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.OpenAI {
		return false
	}
	pricing := state.Resolution.Deployment.Pricing
	switch kind {
	case "web_search":
		_, ok := pricing[openaiadapter.MeterOpenAIResponsesWebSearchCalls]
		return ok
	case "web_search_preview":
		_, ok := pricing[openaiadapter.MeterOpenAIResponsesWebSearchPreviewCalls]
		return ok
	default:
		return false
	}
}

func validateResponsesToolChoice(raw json.RawMessage, tools []map[string]json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if len(tools) == 0 {
		return invalidRequest("tool_choice requires supported tools")
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed != "" && trimmed[0] == '"' {
		switch rawString(raw) {
		case "auto", "none", "required":
			return nil
		default:
			return invalidRequest("tool_choice must be auto, none, required, or a supported tool selector")
		}
	}
	choice, ok := rawObject(raw)
	if !ok {
		return invalidRequest("tool_choice must be auto, none, required, or a supported tool selector")
	}
	kind := responsesToolKind(rawString(choice["type"]))
	switch kind {
	case "function":
		name := strings.TrimSpace(rawString(choice["name"]))
		if name == "" {
			name = strings.TrimSpace(rawString(choice["function"]))
		}
		if name != "" && !responsesToolNameExists(tools, name) {
			return invalidRequest("tool_choice selects an unknown function tool")
		}
		return nil
	case "web_search", "web_search_preview":
		return nil
	case "allowed_tools":
		rawAllowed, ok := choice["tools"]
		if !ok {
			return invalidRequest("tool_choice.allowed_tools requires tools")
		}
		_, err := parseResponsesTools(nil, rawAllowed)
		return err
	default:
		return invalidRequest("tool_choice must select a supported tool")
	}
}

func responsesToolNameExists(tools []map[string]json.RawMessage, name string) bool {
	for _, tool := range tools {
		if responsesToolKind(rawString(tool["type"])) == "function" && rawString(tool["name"]) == name {
			return true
		}
	}
	return false
}

func responsesToolKind(toolType string) string {
	normalized := strings.ToLower(strings.TrimSpace(toolType))
	switch {
	case normalized == "function":
		return "function"
	case normalized == "allowed_tools":
		return "allowed_tools"
	case normalized == "web_search" || strings.HasPrefix(normalized, "web_search_") && !strings.HasPrefix(normalized, "web_search_preview"):
		return "web_search"
	case normalized == "web_search_preview" || strings.HasPrefix(normalized, "web_search_preview_"):
		return "web_search_preview"
	default:
		return ""
	}
}

func validateResponsesInputTextOnly(raw json.RawMessage) error {
	if len(raw) == 0 {
		return invalidRequest("input is required")
	}
	return walkRawJSON(raw, func(object map[string]json.RawMessage) error {
		switch rawString(object["type"]) {
		case "", "message", "input_text", "output_text", "refusal":
			return nil
		case "input_file":
			return invalidRequest("Only text input is supported")
		default:
			return invalidRequest("Only text input is supported")
		}
	})
}

func walkRawJSON(raw json.RawMessage, visit func(map[string]json.RawMessage) error) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	switch trimmed[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := sonic.Unmarshal(raw, &object); err != nil {
			return invalidRequest("input must be valid JSON")
		}
		if err := visit(object); err != nil {
			return err
		}
		for _, child := range object {
			if err := walkRawJSON(child, visit); err != nil {
				return err
			}
		}
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return invalidRequest("input must be valid JSON")
		}
		for _, child := range array {
			if err := walkRawJSON(child, visit); err != nil {
				return err
			}
		}
	}
	return nil
}
