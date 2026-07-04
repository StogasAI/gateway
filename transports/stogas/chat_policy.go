package stogas

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	maxMetadataKeys        = 16
	maxMetadataKeyBytes    = 64
	maxMetadataValueBytes  = 512
	maxMCPAuthTokenBytes   = 4096
	maxPromptCacheKeyBytes = 256
)

func validateCommonChatCompletionPolicy(state *State) error {
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
	for _, name := range []string{"audio", "function_call", "functions", "safety_identifier", "store", "user", "container", "fallbacks", "prompt_cache_isolation_key"} {
		if _, ok := raw[name]; ok {
			return unsupportedParameterError(name)
		}
	}
	if err := validateJSONBool(raw, "stream"); err != nil {
		return err
	}
	if err := validateJSONBool(raw, "parallel_tool_calls"); err != nil {
		return err
	}
	if err := validateStreamOptions(raw, true, false); err != nil {
		return err
	}
	if err := validateNumber(raw, "temperature"); err != nil {
		return err
	}
	if err := validateNumber(raw, "top_p"); err != nil {
		return err
	}
	if err := validateChatStop(raw["stop"]); err != nil {
		return err
	}
	if err := validateInteger(raw, "max_completion_tokens"); err != nil {
		return err
	}
	if err := validateInteger(raw, "max_tokens"); err != nil {
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
	if err := validateReasoningParameters(raw, chatReasoningFields); err != nil {
		return err
	}
	if err := validateChatMessagesTextOnly(raw["messages"]); err != nil {
		return err
	}
	return nil
}

type chatToolRef struct {
	kind string
	name string
}

type chatToolCapabilities struct {
	allowCustom     bool
	allowMCPToolset bool
}

func invalidRequest(message string) error {
	return catalog.APIError{StatusCode: http.StatusBadRequest, Type: catalog.ErrorTypeInvalidRequest, Message: message}
}

func unsupportedParameterError(name string) error {
	if name == "fallbacks" {
		return invalidRequest("Fallbacks are not supported")
	}
	return invalidRequest(name + " is not supported by Stogas API")
}

func validateNumber(raw map[string]json.RawMessage, name string) error {
	valueRaw, ok := raw[name]
	if !ok {
		return nil
	}
	var value float64
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be a number")
	}
	return nil
}

func rawJSONValueSet(raw json.RawMessage) bool {
	return len(raw) > 0 && strings.TrimSpace(string(raw)) != "null"
}

func validateChatStop(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var values []string
	if err := sonic.Unmarshal(raw, &values); err != nil {
		return invalidRequest("stop must be a string or array of strings")
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

func validateStreamOptions(raw map[string]json.RawMessage, allowIncludeUsage bool, allowIncludeObfuscation bool) error {
	valueRaw, ok := raw["stream_options"]
	if !ok {
		return nil
	}
	if !rawBool(raw["stream"]) {
		return invalidRequest("stream_options requires stream=true")
	}
	options, ok := rawObject(valueRaw)
	if !ok {
		return invalidRequest("stream_options must be an object")
	}
	for name, rawValue := range options {
		switch name {
		case "include_obfuscation":
			if !allowIncludeObfuscation {
				return invalidRequest("stream_options.include_obfuscation is not supported for Chat Completions")
			}
			if err := validateRawJSONBool(rawValue, "stream_options."+name); err != nil {
				return err
			}
		case "include_usage":
			if !allowIncludeUsage {
				return invalidRequest("stream_options.include_usage is not supported for Responses")
			}
			if err := validateRawJSONBool(rawValue, "stream_options."+name); err != nil {
				return err
			}
		default:
			return invalidRequest("stream_options." + name + " is not supported by Stogas API")
		}
	}
	return nil
}

func validateRawJSONBool(raw json.RawMessage, name string) error {
	var value bool
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return invalidRequest(name + " must be a boolean")
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

var (
	chatReasoningFields = map[string]bool{
		"display":    true,
		"effort":     true,
		"enabled":    true,
		"max_tokens": true,
	}
	responsesReasoningFields = map[string]bool{
		"effort":           true,
		"generate_summary": true,
		"max_tokens":       true,
		"summary":          true,
	}
)

func validateReasoningParameters(raw map[string]json.RawMessage, allowedFields map[string]bool) error {
	reasoning, hasReasoning := rawObject(raw["reasoning"])
	if _, ok := raw["reasoning"]; ok && !hasReasoning {
		return invalidRequest("reasoning must be an object")
	}
	for name := range reasoning {
		if !allowedFields[name] {
			return invalidRequest("reasoning." + name + " is not supported by Stogas API")
		}
	}
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
	if err := validateReasoningEffortValue(raw["reasoning_effort"], "reasoning_effort"); err != nil {
		return err
	}
	if err := validateReasoningDisplayValue(raw["reasoning_display"], "reasoning_display"); err != nil {
		return err
	}
	if err := validateReasoningMaxTokensValue(raw["reasoning_max_tokens"], "reasoning_max_tokens"); err != nil {
		return err
	}
	if hasReasoning {
		if err := validateReasoningEffortValue(reasoning["effort"], "reasoning.effort"); err != nil {
			return err
		}
		if err := validateReasoningDisplayValue(reasoning["display"], "reasoning.display"); err != nil {
			return err
		}
		if err := validateReasoningMaxTokensValue(reasoning["max_tokens"], "reasoning.max_tokens"); err != nil {
			return err
		}
		if err := validateReasoningEnabledValue(reasoning["enabled"], "reasoning.enabled"); err != nil {
			return err
		}
		if err := validateReasoningSummaryValue(reasoning["summary"], "reasoning.summary"); err != nil {
			return err
		}
		if err := validateReasoningSummaryValue(reasoning["generate_summary"], "reasoning.generate_summary"); err != nil {
			return err
		}
	}
	return nil
}

func validateReasoningEffortValue(raw json.RawMessage, name string) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return invalidRequest(name + " must be a string")
	}
	return nil
}

func validateReasoningMaxTokensValue(raw json.RawMessage, name string) error {
	value, exists, err := rawInteger(raw, name)
	if err != nil || !exists {
		return err
	}
	if value < 1 {
		return invalidRequest(name + " is outside the supported range")
	}
	return nil
}

func validateReasoningEnabledValue(raw json.RawMessage, name string) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value bool
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return invalidRequest(name + " must be a boolean")
	}
	return nil
}

func validateReasoningSummaryValue(raw json.RawMessage, name string) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return invalidRequest(name + " must be a string")
	}
	return nil
}

func validateReasoningDisplayValue(raw json.RawMessage, name string) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return invalidRequest(name + " must be a string")
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
		if err := validateTextOnlyMediaFields(message, "Only text message content is supported"); err != nil {
			return err
		}
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
			if err := validateTextOnlyMediaFields(block, "Only text message content is supported"); err != nil {
				return err
			}
			if rawString(block["type"]) != "text" {
				return invalidRequest("Only text message content is supported")
			}
		}
	}
	return nil
}

func validateTextOnlyMediaFields(object map[string]json.RawMessage, mediaMessage string) error {
	if _, ok := object["file_id"]; ok {
		return invalidRequest("file_id inputs are not supported")
	}
	if _, ok := object["file_url"]; ok {
		return invalidRequest("file_url inputs are not supported")
	}
	if _, ok := object["file_data"]; ok {
		return invalidRequest("file inputs are not supported")
	}
	for _, name := range []string{"file", "input_file"} {
		if _, ok := object[name]; ok {
			return invalidRequest("file inputs are not supported")
		}
	}
	for _, name := range []string{"audio", "image", "image_url", "input_audio", "input_image"} {
		if _, ok := object[name]; ok {
			return invalidRequest(mediaMessage)
		}
	}
	return nil
}

func validateChatTools(raw json.RawMessage, capabilities chatToolCapabilities) ([]chatToolRef, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &tools); err != nil {
		return nil, invalidRequest("tools must be an array")
	}
	refs := make([]chatToolRef, 0, len(tools))
	for _, tool := range tools {
		kind := rawString(tool["type"])
		if kind == "custom" && !capabilities.allowCustom {
			return nil, invalidRequest("custom tools are only supported for OpenAI Chat deployments")
		}
		switch kind {
		case "function", "custom":
			name := chatToolName(tool, kind)
			if name == "" {
				return nil, invalidRequest(kind + " tools require a name")
			}
			refs = append(refs, chatToolRef{kind: kind, name: name})
		case "mcp_toolset":
			if !capabilities.allowMCPToolset {
				return nil, invalidRequest("mcp_toolset tools are only supported for Anthropic deployments")
			}
			if err := validateMCPToolsetTool(tool); err != nil {
				return nil, err
			}
			name := strings.TrimSpace(rawString(tool["mcp_server_name"]))
			if name == "" {
				return nil, invalidRequest("mcp_toolset tools require mcp_server_name")
			}
			refs = append(refs, chatToolRef{kind: kind, name: name})
		default:
			return nil, invalidRequest(chatSupportedToolsMessage(capabilities))
		}
	}
	return refs, nil
}

func chatSupportedToolsMessage(capabilities chatToolCapabilities) string {
	if capabilities.allowMCPToolset {
		return "Only function and mcp_toolset tools are supported"
	}
	if capabilities.allowCustom {
		return "Only function and custom tools are supported"
	}
	return "Only function tools are supported"
}

func validateMCPToolsetTool(tool map[string]json.RawMessage) error {
	for name := range tool {
		switch name {
		case "type", "mcp_server_name", "default_config", "configs", "cache_control":
		default:
			return invalidRequest("mcp_toolset." + name + " is not supported by Stogas API")
		}
	}
	if raw, ok := tool["default_config"]; ok {
		if err := validateMCPToolsetConfig(raw, "mcp_toolset.default_config"); err != nil {
			return err
		}
	}
	if raw, ok := tool["configs"]; ok {
		configs, ok := rawObject(raw)
		if !ok {
			return invalidRequest("mcp_toolset.configs must be an object")
		}
		for name, config := range configs {
			if strings.TrimSpace(name) == "" {
				return invalidRequest("mcp_toolset.configs keys must be non-empty")
			}
			if err := validateMCPToolsetConfig(config, "mcp_toolset.configs."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateMCPToolsetConfig(raw json.RawMessage, name string) error {
	config, ok := rawObject(raw)
	if !ok {
		return invalidRequest(name + " must be an object")
	}
	for key, value := range config {
		switch key {
		case "enabled", "defer_loading":
			if err := validateRawJSONBool(value, name+"."+key); err != nil {
				return err
			}
		default:
			return invalidRequest(name + "." + key + " is not supported by Stogas API")
		}
	}
	return nil
}

func validateChatMCPServers(raw json.RawMessage, tools []chatToolRef) error {
	toolsetCounts := map[string]int{}
	for _, tool := range tools {
		if tool.kind == "mcp_toolset" {
			toolsetCounts[tool.name]++
		}
	}
	if !rawJSONValueSet(raw) {
		if len(toolsetCounts) > 0 {
			return invalidRequest("mcp_toolset tools require matching mcp_servers")
		}
		return nil
	}
	var servers []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &servers); err != nil {
		return invalidRequest("mcp_servers must be an array")
	}
	if len(servers) == 0 {
		return invalidRequest("mcp_servers must contain at least one server")
	}
	names := map[string]struct{}{}
	for _, server := range servers {
		name, err := validateMCPServer(server)
		if err != nil {
			return err
		}
		if _, exists := names[name]; exists {
			return invalidRequest("mcp_servers names must be unique")
		}
		names[name] = struct{}{}
		if toolsetCounts[name] != 1 {
			return invalidRequest("mcp_servers must match mcp_toolset tools one-to-one")
		}
	}
	for name := range toolsetCounts {
		if _, ok := names[name]; !ok {
			return invalidRequest("mcp_toolset tools require matching mcp_servers")
		}
		if toolsetCounts[name] != 1 {
			return invalidRequest("mcp_servers must match mcp_toolset tools one-to-one")
		}
	}
	return nil
}

func validateMCPServer(server map[string]json.RawMessage) (string, error) {
	for name := range server {
		switch name {
		case "type", "url", "name", "authorization_token":
		default:
			return "", invalidRequest("mcp_servers[]." + name + " is not supported by Stogas API")
		}
	}
	if rawString(server["type"]) != "url" {
		return "", invalidRequest(`mcp_servers[].type must be "url"`)
	}
	endpoint := strings.TrimSpace(rawString(server["url"]))
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", invalidRequest("mcp_servers[].url must be an HTTPS URL")
	}
	name := strings.TrimSpace(rawString(server["name"]))
	if name == "" || strings.ContainsAny(name, "\x00\r\n") || !utf8.ValidString(name) {
		return "", invalidRequest("mcp_servers[].name must be a non-empty string")
	}
	if tokenRaw, ok := server["authorization_token"]; ok {
		token := rawString(tokenRaw)
		if token == "" || len(token) > maxMCPAuthTokenBytes || strings.ContainsAny(token, "\x00\r\n") || !utf8.ValidString(token) {
			return "", invalidRequest("mcp_servers[].authorization_token must be a non-empty string up to 4096 bytes without control line breaks")
		}
	}
	return name, nil
}

func validateChatToolChoice(raw json.RawMessage, tools []chatToolRef, capabilities chatToolCapabilities) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var choice string
	if err := sonic.Unmarshal(raw, &choice); err == nil {
		switch choice {
		case "auto", "none":
			return nil
		case "required":
			if len(tools) == 0 {
				return invalidRequest("tool_choice requires supported tools")
			}
			return nil
		default:
			return invalidRequest("tool_choice must be auto, none, required, or a supported tool object")
		}
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err != nil {
		return invalidRequest("tool_choice must be auto, none, required, or a supported tool object")
	}
	kind := rawString(object["type"])
	switch kind {
	case "function":
		if len(tools) == 0 {
			return invalidRequest("tool_choice requires supported tools")
		}
		name := chatToolChoiceName(object, kind)
		if name == "" {
			return invalidRequest("tool_choice must name a " + kind + " tool")
		}
		if !chatToolExists(tools, kind, name) {
			return invalidRequest("tool_choice selects an unknown " + kind + " tool")
		}
		return nil
	case "custom":
		if !capabilities.allowCustom {
			return invalidRequest("custom tool_choice is only supported for OpenAI Chat deployments")
		}
		if len(tools) == 0 {
			return invalidRequest("tool_choice requires supported tools")
		}
		name := chatToolChoiceName(object, kind)
		if name == "" {
			return invalidRequest("tool_choice must name a custom tool")
		}
		if !chatToolExists(tools, kind, name) {
			return invalidRequest("tool_choice selects an unknown custom tool")
		}
		return nil
	default:
		return invalidRequest("tool_choice must be auto, none, required, or a supported tool object")
	}
}

func chatToolName(tool map[string]json.RawMessage, kind string) string {
	if name := strings.TrimSpace(rawString(tool["name"])); name != "" {
		return name
	}
	if nested, ok := rawObject(tool[kind]); ok {
		return strings.TrimSpace(rawString(nested["name"]))
	}
	return ""
}

func chatToolChoiceName(choice map[string]json.RawMessage, kind string) string {
	if name := strings.TrimSpace(rawString(choice["name"])); name != "" {
		return name
	}
	if nested, ok := rawObject(choice[kind]); ok {
		return strings.TrimSpace(rawString(nested["name"]))
	}
	return ""
}

func chatToolExists(tools []chatToolRef, kind string, name string) bool {
	for _, tool := range tools {
		if tool.kind == kind && tool.name == name {
			return true
		}
	}
	return false
}

func rawString(raw json.RawMessage) string {
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}
