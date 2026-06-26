package stogas

import (
	"encoding/json"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	openaiadapter "github.com/maximhq/bifrost/transports/stogas/providers/openai"
)

const maxResponsesToolCalls = 128

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
	if err := validateIntegerRange(raw, "max_tool_calls", 1, maxResponsesToolCalls); err != nil {
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
	if err := validateResponsesCacheControls(state, raw); err != nil {
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
	} else if responsesHasHostedTool(tools) {
		if _, ok := raw["max_tool_calls"]; !ok {
			return invalidRequest("max_tool_calls is required for priced hosted tools")
		}
	}
	if err := validateResponsesToolChoice(state, raw["tool_choice"], tools); err != nil {
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

func validateIntegerRange(raw map[string]json.RawMessage, name string, min int, max int) error {
	valueRaw, ok := raw[name]
	if !ok {
		return nil
	}
	var value int
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be an integer")
	}
	if value < min || value > max {
		return invalidRequest(name + " is outside the supported range")
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

func validateResponsesCacheControls(state *State, raw map[string]json.RawMessage) error {
	if cacheControl, ok := raw["cache_control"]; ok {
		if err := validateProviderCacheControl(state, cacheControl, "cache_control"); err != nil {
			return err
		}
	}
	if err := validateResponsesInputCacheControls(state, raw["input"]); err != nil {
		return err
	}
	return validateResponsesToolCacheControls(state, raw["tools"])
}

func validateResponsesInputCacheControls(state *State, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	return walkResponsesInputCacheControls(state, raw, "input")
}

func walkResponsesInputCacheControls(state *State, raw json.RawMessage, path string) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed[0] == '"' {
		return nil
	}
	switch trimmed[0] {
	case '{':
		object, ok := rawObject(raw)
		if !ok {
			return nil
		}
		if cacheControl, ok := object["cache_control"]; ok {
			switch rawString(object["type"]) {
			case "input_text", "output_text":
				if err := validateProviderCacheControl(state, cacheControl, path+".cache_control"); err != nil {
					return err
				}
			default:
				return invalidRequest(path + ".cache_control is not supported by Stogas API")
			}
		}
		if content, ok := object["content"]; ok {
			if err := walkResponsesInputCacheControls(state, content, path+".content"); err != nil {
				return err
			}
		}
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return nil
		}
		for _, child := range array {
			if err := walkResponsesInputCacheControls(state, child, path+"[]"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateResponsesToolCacheControls(state *State, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &tools); err != nil {
		return nil
	}
	for _, tool := range tools {
		if cacheControl, ok := tool["cache_control"]; ok {
			if err := validateProviderCacheControl(state, cacheControl, "tools[].cache_control"); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseResponsesTools(state *State, raw json.RawMessage) ([]schemas.ResponsesTool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var rawTools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &rawTools); err != nil {
		return nil, invalidRequest("tools must be an array")
	}
	for _, rawTool := range rawTools {
		if err := validateRawResponsesToolType(state, rawTool); err != nil {
			return nil, err
		}
	}
	var tools []schemas.ResponsesTool
	if err := sonic.Unmarshal(raw, &tools); err != nil {
		return nil, invalidRequest("tools must be an array")
	}
	for _, tool := range tools {
		switch tool.Type {
		case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
			name := ""
			if tool.Name != nil {
				name = strings.TrimSpace(*tool.Name)
			}
			if name == "" {
				return nil, invalidRequest(string(tool.Type) + " tools require a name")
			}
		case schemas.ResponsesToolTypeLocalShell:
			if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.OpenAI {
				return nil, invalidRequest("local_shell is only supported for OpenAI Responses deployments")
			}
		case schemas.ResponsesToolTypeApplyPatch:
			if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.OpenAI {
				return nil, invalidRequest("apply_patch is only supported for OpenAI Responses deployments")
			}
		case schemas.ResponsesToolTypeShell:
			if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.OpenAI {
				return nil, invalidRequest("shell is only supported for OpenAI Responses deployments")
			}
			if err := validateResponsesLocalShellTool(raw, tool); err != nil {
				return nil, err
			}
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview:
			if err := validateResponsesHostedToolVersion(state, raw, tool.Type); err != nil {
				return nil, err
			}
			if state != nil && !responsesHostedToolIsPriced(state, tool.Type) {
				return nil, invalidRequest("Hosted tools are not supported for this deployment")
			}
		default:
			return nil, invalidRequest("Only function, custom, local_shell, apply_patch, local shell, and priced hosted web search tools are supported")
		}
	}
	return tools, nil
}

func validateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	rawType := rawString(tool["type"])
	if rawType == "" {
		return invalidRequest("tools must declare a type")
	}
	if state == nil || state.Resolution == nil {
		return invalidRequest("Only function, custom, local_shell, apply_patch, local shell, and priced hosted web search tools are supported")
	}
	switch state.Resolution.Provider {
	case schemas.OpenAI:
		if rawType == "function" || rawType == "custom" || rawType == "local_shell" || rawType == "apply_patch" || rawType == "shell" || openAIWebSearchToolType(rawType) {
			return nil
		}
	case schemas.Anthropic:
		switch rawType {
		case "local_shell", "apply_patch", "shell":
			return invalidRequest(rawType + " is only supported for OpenAI Responses deployments")
		}
		if strings.HasPrefix(rawType, "web_search") && rawType != "web_search_20250305" {
			return invalidRequest("Only Anthropic basic web_search_20250305 is supported until dynamic web search code execution is priced")
		}
		if rawType == "function" || rawType == "custom" || rawType == "web_search_20250305" {
			return nil
		}
	default:
		if rawType == "function" || rawType == "custom" {
			return nil
		}
	}
	return invalidRequest("Only function, custom, local_shell, apply_patch, local shell, and priced hosted web search tools are supported")
}

func openAIWebSearchToolType(rawType string) bool {
	if rawType == "web_search" || rawType == "web_search_preview" {
		return true
	}
	for _, prefix := range []string{"web_search_preview_", "web_search_"} {
		if strings.HasPrefix(rawType, prefix) {
			return validDatedToolSuffix(strings.TrimPrefix(rawType, prefix))
		}
	}
	return false
}

func validDatedToolSuffix(suffix string) bool {
	return validCompactDateSuffix(suffix) || validUnderscoreDateSuffix(suffix)
}

func validCompactDateSuffix(suffix string) bool {
	if len(suffix) != len("20060102") {
		return false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validUnderscoreDateSuffix(suffix string) bool {
	if len(suffix) != len("2006_01_02") {
		return false
	}
	for i, r := range suffix {
		switch i {
		case 4, 7:
			if r != '_' {
				return false
			}
		default:
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func validateResponsesLocalShellTool(rawTools json.RawMessage, selected schemas.ResponsesTool) error {
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(rawTools, &tools); err != nil {
		return invalidRequest("tools must be an array")
	}
	for _, tool := range tools {
		if rawString(tool["type"]) != string(selected.Type) {
			continue
		}
		rawEnvironment, ok := tool["environment"]
		if !ok {
			return invalidRequest("shell tools require environment.type=local")
		}
		environment, ok := rawObject(rawEnvironment)
		if !ok || rawString(environment["type"]) != "local" {
			return invalidRequest("Only local shell tools are supported")
		}
		if !onlyRawKeys(tool, "type", "environment") || !onlyRawKeys(environment, "type") {
			return invalidRequest("Only local shell tools are supported")
		}
	}
	return nil
}

func responsesHasHostedTool(tools []schemas.ResponsesTool) bool {
	for _, tool := range tools {
		switch tool.Type {
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview:
			return true
		}
	}
	return false
}

func validateResponsesHostedToolVersion(state *State, raw json.RawMessage, toolType schemas.ResponsesToolType) error {
	if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.Anthropic || toolType != schemas.ResponsesToolTypeWebSearch {
		return nil
	}
	var rawTools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &rawTools); err != nil {
		return nil
	}
	for _, tool := range rawTools {
		rawType := rawString(tool["type"])
		if strings.HasPrefix(rawType, "web_search") && rawType != "web_search_20250305" {
			return invalidRequest("Only Anthropic basic web_search_20250305 is supported until dynamic web search code execution is priced")
		}
	}
	return nil
}

func responsesHostedToolIsPriced(state *State, kind schemas.ResponsesToolType) bool {
	if state == nil || state.Resolution == nil {
		return false
	}
	pricing := state.Resolution.Deployment.Pricing
	switch state.Resolution.Provider {
	case schemas.OpenAI:
		switch kind {
		case schemas.ResponsesToolTypeWebSearch:
			_, ok := pricing[openaiadapter.MeterOpenAIResponsesWebSearchCalls]
			return ok
		case schemas.ResponsesToolTypeWebSearchPreview:
			_, ok := pricing[openaiadapter.MeterOpenAIResponsesWebSearchPreviewCalls]
			return ok
		default:
			return false
		}
	case schemas.Anthropic:
		if kind != schemas.ResponsesToolTypeWebSearch {
			return false
		}
		_, ok := pricing[meterAnthropicWebSearchCalls]
		return ok
	}
	return false
}

func validateResponsesToolChoice(state *State, raw json.RawMessage, tools []schemas.ResponsesTool) error {
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
	if rawString(choice["type"]) == "allowed_tools" {
		rawAllowed, ok := choice["tools"]
		if !ok {
			return invalidRequest("tool_choice.allowed_tools requires tools")
		}
		allowedTools, err := parseResponsesTools(state, rawAllowed)
		if err != nil {
			return err
		}
		for _, allowed := range allowedTools {
			if allowed.Type == schemas.ResponsesToolTypeFunction || allowed.Type == schemas.ResponsesToolTypeCustom {
				name := strings.TrimSpace(rawString(choice["name"]))
				if allowed.Name != nil {
					name = strings.TrimSpace(*allowed.Name)
				}
				if name != "" && !responsesNamedToolExists(tools, allowed.Type, name) {
					return invalidRequest("tool_choice selects an unknown " + string(allowed.Type) + " tool")
				}
				continue
			}
			if !responsesToolTypeExists(tools, allowed.Type) {
				return invalidRequest("tool_choice selects an unknown " + string(allowed.Type) + " tool")
			}
		}
		return nil
	}
	var selected schemas.ResponsesTool
	if err := sonic.Unmarshal(raw, &selected); err != nil {
		return invalidRequest("tool_choice must select a supported tool")
	}
	switch selected.Type {
	case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
		name := strings.TrimSpace(rawString(choice["name"]))
		if name == "" {
			name = strings.TrimSpace(rawString(choice["function"]))
		}
		if name != "" && !responsesNamedToolExists(tools, selected.Type, name) {
			return invalidRequest("tool_choice selects an unknown " + string(selected.Type) + " tool")
		}
		return nil
	case schemas.ResponsesToolTypeLocalShell:
		if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.OpenAI {
			return invalidRequest("local_shell is only supported for OpenAI Responses deployments")
		}
		if !responsesToolTypeExists(tools, schemas.ResponsesToolTypeLocalShell) {
			return invalidRequest("tool_choice selects an unknown local_shell tool")
		}
		return nil
	case schemas.ResponsesToolTypeApplyPatch:
		if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.OpenAI {
			return invalidRequest("apply_patch is only supported for OpenAI Responses deployments")
		}
		if !responsesToolTypeExists(tools, schemas.ResponsesToolTypeApplyPatch) {
			return invalidRequest("tool_choice selects an unknown apply_patch tool")
		}
		return nil
	case schemas.ResponsesToolTypeShell:
		if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.OpenAI {
			return invalidRequest("shell is only supported for OpenAI Responses deployments")
		}
		if !responsesToolTypeExists(tools, schemas.ResponsesToolTypeShell) {
			return invalidRequest("tool_choice selects an unknown shell tool")
		}
		return nil
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview:
		if !responsesToolTypeExists(tools, selected.Type) {
			return invalidRequest("tool_choice selects an unknown " + string(selected.Type) + " tool")
		}
		if state != nil && !responsesHostedToolIsPriced(state, selected.Type) {
			return invalidRequest("Hosted tools are not supported for this deployment")
		}
		return nil
	default:
		return invalidRequest("tool_choice must select a supported tool")
	}
}

func responsesToolTypeExists(tools []schemas.ResponsesTool, toolType schemas.ResponsesToolType) bool {
	for _, tool := range tools {
		if tool.Type == toolType {
			return true
		}
	}
	return false
}

func responsesNamedToolExists(tools []schemas.ResponsesTool, toolType schemas.ResponsesToolType, name string) bool {
	for _, tool := range tools {
		if tool.Type == toolType && tool.Name != nil && *tool.Name == name {
			return true
		}
	}
	return false
}

func onlyRawKeys(object map[string]json.RawMessage, keys ...string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
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
			if _, hasFileID := object["file_id"]; hasFileID {
				return invalidRequest("file_id inputs are not supported")
			}
			if _, hasFileURL := object["file_url"]; hasFileURL {
				return invalidRequest("file_url inputs are not supported")
			}
			return invalidRequest("file inputs are not supported")
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
		for key, child := range object {
			if key == "cache_control" {
				continue
			}
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
