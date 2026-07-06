package stogas

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	defaultResponsesHostedToolCalls = 50
	maxResponsesToolCalls           = 128
)

func validateCommonResponsesPolicy(state *State) error {
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
		"conversation",
		"fallbacks",
		"previous_response_id",
		"safety_identifier",
		"store",
		"user",
	} {
		if _, ok := raw[name]; ok {
			return unsupportedParameterError(name)
		}
	}
	if err := validateJSONBool(raw, "stream"); err != nil {
		return err
	}
	if err := validateStreamOptions(raw, false, true); err != nil {
		return err
	}
	if err := validateJSONBool(raw, "parallel_tool_calls"); err != nil {
		return err
	}
	if err := validateString(raw, "instructions"); err != nil {
		return err
	}
	if err := validateNumber(raw, "temperature"); err != nil {
		return err
	}
	if err := validateNumber(raw, "top_p"); err != nil {
		return err
	}
	if err := validateInteger(raw, "max_output_tokens"); err != nil {
		return err
	}
	if err := validateIntegerRange(raw, "max_tool_calls", 1, maxResponsesToolCalls); err != nil {
		return err
	}
	if err := validateMetadata(raw["metadata"]); err != nil {
		return err
	}
	if err := validateResponsesReasoning(raw); err != nil {
		return err
	}
	if err := validateResponsesTruncation(raw["truncation"]); err != nil {
		return err
	}
	return validateResponsesInputTextOnly(state, raw["input"])
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

func rawInteger(valueRaw json.RawMessage, name string) (int, bool, error) {
	if len(valueRaw) == 0 {
		return 0, false, nil
	}
	var value int
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return 0, true, invalidRequest(name + " must be an integer")
	}
	return value, true, nil
}

func validateResponsesReasoning(raw map[string]json.RawMessage) error {
	if err := validateReasoningParameters(raw, responsesReasoningFields); err != nil {
		return err
	}
	reasoning, hasReasoning := rawObject(raw["reasoning"])
	if effortRaw, ok := raw["reasoning.effort"]; ok {
		if err := validateReasoningEffortValue(effortRaw, "reasoning.effort"); err != nil {
			return err
		}
	}
	if _, ok := raw["reasoning.effort"]; ok && hasReasoning {
		if _, exists := reasoning["effort"]; exists {
			return invalidRequest("reasoning.effort conflicts with reasoning.effort")
		}
	}
	return nil
}

func validateResponsesTruncation(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return invalidRequest("truncation must be a string")
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
		case schemas.ResponsesToolTypeMCP:
			if err := validateResponsesMCPTool(raw, tool); err != nil {
				return nil, err
			}
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
		default:
			return nil, invalidRequest("Only function, custom, mcp, web_fetch, and priced hosted web search tools are supported")
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
		return invalidRequest("Only function, custom, mcp, and priced hosted web search tools are supported")
	}
	if state.Adapter == nil {
		return invalidRequest("Only function, custom, mcp, and priced hosted web search tools are supported")
	}
	return state.Adapter.ValidateRawResponsesToolType(state, tool)
}

func validateResponsesMCPTool(rawTools json.RawMessage, selected schemas.ResponsesTool) error {
	if selected.ResponsesToolMCP == nil {
		return invalidRequest("mcp tools require server_label and server_url")
	}
	label := strings.TrimSpace(selected.ResponsesToolMCP.ServerLabel)
	if label == "" || strings.ContainsAny(label, "\x00\r\n") || !utf8.ValidString(label) {
		return invalidRequest("mcp tools require a non-empty server_label")
	}
	if selected.ResponsesToolMCP.ServerURL == nil {
		return invalidRequest("mcp tools require server_url")
	}
	endpoint := strings.TrimSpace(*selected.ResponsesToolMCP.ServerURL)
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return invalidRequest("mcp tools require an HTTPS server_url")
	}
	if selected.ResponsesToolMCP.Authorization != nil {
		token := *selected.ResponsesToolMCP.Authorization
		if token == "" || len(token) > maxMCPAuthTokenBytes || strings.ContainsAny(token, "\x00\r\n") || !utf8.ValidString(token) {
			return invalidRequest("mcp authorization must be a non-empty string up to 4096 bytes without control line breaks")
		}
	}
	if err := validateResponsesMCPAllowedTools(selected.ResponsesToolMCP.AllowedTools); err != nil {
		return err
	}

	var rawList []map[string]json.RawMessage
	if err := sonic.Unmarshal(rawTools, &rawList); err != nil {
		return invalidRequest("tools must be an array")
	}
	matchedRawTool := false
	for _, rawTool := range rawList {
		if rawString(rawTool["type"]) != string(schemas.ResponsesToolTypeMCP) {
			continue
		}
		if rawString(rawTool["server_label"]) != label {
			continue
		}
		matchedRawTool = true
		for name := range rawTool {
			switch name {
			case "type", "name", "server_label", "server_url", "server_description", "authorization", "allowed_tools", "require_approval", "cache_control":
			default:
				return invalidRequest("mcp." + name + " is not supported by Stogas API")
			}
		}
		if _, ok := rawTool["allowed_tools"]; !ok {
			return invalidRequest("mcp tools require allowed_tools")
		}
		var allowed schemas.ResponsesToolMCPAllowedTools
		if err := sonic.Unmarshal(rawTool["allowed_tools"], &allowed); err != nil {
			return invalidRequest("mcp allowed_tools must be a non-empty string array or narrowing filter")
		}
		if err := validateResponsesMCPAllowedTools(&allowed); err != nil {
			return err
		}
	}
	if !matchedRawTool {
		return invalidRequest("mcp tools require server_label")
	}
	return nil
}

func validateResponsesMCPAllowedTools(allowed *schemas.ResponsesToolMCPAllowedTools) error {
	if allowed == nil {
		return invalidRequest("mcp tools require allowed_tools")
	}
	if len(allowed.ToolNames) > 0 {
		return validateResponsesMCPToolNames(allowed.ToolNames)
	}
	if allowed.Filter == nil {
		return invalidRequest("mcp allowed_tools must be a non-empty string array or narrowing filter")
	}
	if len(allowed.Filter.ToolNames) == 0 && (allowed.Filter.ReadOnly == nil || !*allowed.Filter.ReadOnly) {
		return invalidRequest("mcp allowed_tools filter must narrow by tool_names or read_only=true")
	}
	return validateResponsesMCPToolNames(allowed.Filter.ToolNames)
}

func validateResponsesMCPToolNames(names []string) error {
	for _, name := range names {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\x00\r\n") || !utf8.ValidString(name) {
			return invalidRequest("mcp allowed_tools values must be non-empty strings")
		}
	}
	return nil
}

func responsesHasHostedTool(tools []schemas.ResponsesTool) bool {
	for _, tool := range tools {
		switch tool.Type {
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
			return true
		}
	}
	return false
}

func responsesHostedToolChoiceAllowsCalls(raw map[string]json.RawMessage) bool {
	if raw == nil {
		return true
	}
	choiceRaw, ok := raw["tool_choice"]
	if !ok || len(choiceRaw) == 0 || string(choiceRaw) == "null" {
		return true
	}
	trimmed := strings.TrimSpace(string(choiceRaw))
	if trimmed == "" {
		return true
	}
	if trimmed[0] == '"' {
		return rawString(choiceRaw) != "none"
	}
	choice, ok := rawObject(choiceRaw)
	if !ok {
		return true
	}
	if rawString(choice["type"]) == "allowed_tools" {
		rawAllowed := choice["tools"]
		var allowed []map[string]json.RawMessage
		if err := sonic.Unmarshal(rawAllowed, &allowed); err != nil {
			return true
		}
		for _, tool := range allowed {
			switch canonicalResponsesToolType(rawString(tool["type"])) {
			case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
				return true
			}
		}
		return false
	}
	switch canonicalResponsesToolType(rawString(choice["type"])) {
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
		return true
	default:
		return false
	}
}

func effectiveResponsesToolTypes(rawBody map[string]json.RawMessage, declared []string) []string {
	if rawBody == nil {
		return declared
	}
	choiceRaw, ok := rawBody["tool_choice"]
	if !ok || len(choiceRaw) == 0 || string(choiceRaw) == "null" {
		return declared
	}
	trimmed := strings.TrimSpace(string(choiceRaw))
	if trimmed == "" {
		return declared
	}
	if trimmed[0] == '"' {
		switch rawString(choiceRaw) {
		case "none":
			return nil
		case "auto", "required":
			return declared
		default:
			return declared
		}
	}
	choice, ok := rawObject(choiceRaw)
	if !ok {
		return declared
	}
	if rawString(choice["type"]) == "allowed_tools" {
		rawAllowed, ok := choice["tools"]
		if !ok {
			return declared
		}
		var allowed []map[string]json.RawMessage
		if err := sonic.Unmarshal(rawAllowed, &allowed); err != nil {
			return declared
		}
		return matchingDeclaredResponsesToolTypes(declared, allowedResponsesToolTypes(allowed))
	}
	return matchingDeclaredResponsesToolTypes(declared, []schemas.ResponsesToolType{canonicalResponsesToolType(rawString(choice["type"]))})
}

func allowedResponsesToolTypes(tools []map[string]json.RawMessage) []schemas.ResponsesToolType {
	out := make([]schemas.ResponsesToolType, 0, len(tools))
	for _, tool := range tools {
		out = append(out, canonicalResponsesToolType(rawString(tool["type"])))
	}
	return out
}

func matchingDeclaredResponsesToolTypes(declared []string, allowed []schemas.ResponsesToolType) []string {
	if len(allowed) == 0 {
		return nil
	}
	matches := []string{}
	seen := map[schemas.ResponsesToolType]bool{}
	for _, allowedType := range allowed {
		if allowedType == "" || seen[allowedType] {
			continue
		}
		seen[allowedType] = true
		for _, declaredType := range declared {
			if canonicalResponsesToolType(declaredType) == allowedType {
				matches = append(matches, string(allowedType))
				break
			}
		}
	}
	return matches
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
		return validateResponsesAllowedToolChoice(rawAllowed, tools)
	}
	var selected schemas.ResponsesTool
	if err := sonic.Unmarshal(raw, &selected); err != nil {
		return invalidRequest("tool_choice must select a supported tool")
	}
	selected.Type = canonicalResponsesToolType(rawString(choice["type"]))
	switch selected.Type {
	case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
		name := strings.TrimSpace(rawString(choice["name"]))
		if name == "" {
			name = strings.TrimSpace(rawString(choice["function"]))
		}
		if name == "" {
			return invalidRequest("tool_choice must name a " + string(selected.Type) + " tool")
		}
		if !responsesNamedToolExists(tools, selected.Type, name) {
			return invalidRequest("tool_choice selects an unknown " + string(selected.Type) + " tool")
		}
		return nil
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
		if !responsesToolTypeExists(tools, selected.Type) {
			return invalidRequest("tool_choice selects an unknown " + string(selected.Type) + " tool")
		}
		return nil
	case schemas.ResponsesToolTypeMCP:
		label := strings.TrimSpace(rawString(choice["server_label"]))
		if label == "" {
			return invalidRequest("tool_choice must name an mcp server_label")
		}
		if !responsesMCPToolExists(tools, label) {
			return invalidRequest("tool_choice selects an unknown mcp tool")
		}
		return nil
	default:
		return invalidRequest("tool_choice must select a supported tool")
	}
}

func validateResponsesAllowedToolChoice(raw json.RawMessage, tools []schemas.ResponsesTool) error {
	var allowedTools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &allowedTools); err != nil {
		return invalidRequest("tool_choice.allowed_tools requires tools")
	}
	for _, allowed := range allowedTools {
		switch toolType := canonicalResponsesToolType(rawString(allowed["type"])); toolType {
		case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
			name := strings.TrimSpace(rawString(allowed["name"]))
			if name == "" {
				return invalidRequest("tool_choice.allowed_tools " + string(toolType) + " entries require name")
			}
			if !responsesNamedToolExists(tools, toolType, name) {
				return invalidRequest("tool_choice selects an unknown " + string(toolType) + " tool")
			}
		case schemas.ResponsesToolTypeMCP:
			label := strings.TrimSpace(rawString(allowed["server_label"]))
			if label == "" {
				return invalidRequest("tool_choice.allowed_tools mcp entries require server_label")
			}
			if !responsesMCPToolExists(tools, label) {
				return invalidRequest("tool_choice selects an unknown mcp tool")
			}
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
			if !responsesToolTypeExists(tools, toolType) {
				return invalidRequest("tool_choice selects an unknown " + string(toolType) + " tool")
			}
		default:
			return invalidRequest("tool_choice must select a supported tool")
		}
	}
	return nil
}

func canonicalResponsesToolType(rawType string) schemas.ResponsesToolType {
	toolType := schemas.ResponsesToolType(strings.TrimSpace(rawType))
	switch {
	case toolType == schemas.ResponsesToolTypeWebSearchPreview:
		return toolType
	case strings.HasPrefix(string(toolType), "web_search_preview"):
		return schemas.ResponsesToolTypeWebSearchPreview
	case toolType == schemas.ResponsesToolTypeWebSearch:
		return toolType
	case strings.HasPrefix(string(toolType), "web_search"):
		return schemas.ResponsesToolTypeWebSearch
	case strings.HasPrefix(string(toolType), "web_fetch"):
		return schemas.ResponsesToolTypeWebFetch
	case strings.HasPrefix(string(toolType), "code_execution"):
		return schemas.ResponsesToolTypeCodeInterpreter
	case strings.HasPrefix(string(toolType), "computer") && toolType != schemas.ResponsesToolTypeComputerUsePreview:
		return schemas.ResponsesToolTypeComputerUsePreview
	default:
		return toolType
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

func responsesMCPToolExists(tools []schemas.ResponsesTool, serverLabel string) bool {
	for _, tool := range tools {
		if tool.Type == schemas.ResponsesToolTypeMCP && tool.ResponsesToolMCP != nil && tool.ResponsesToolMCP.ServerLabel == serverLabel {
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

func validateResponsesInputTextOnly(state *State, raw json.RawMessage) error {
	if len(raw) == 0 {
		return invalidRequest("input is required")
	}
	return walkRawJSON(raw, func(object map[string]json.RawMessage) error {
		if rawString(object["type"]) == "reasoning" {
			if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.OpenAI || !state.Resolution.Deployment.ReasoningSupported {
				return invalidRequest("reasoning input items are only supported for OpenAI reasoning deployments")
			}
			if strings.TrimSpace(rawString(object["encrypted_content"])) == "" {
				return invalidRequest("reasoning input items require encrypted_content")
			}
			return errSkipRawJSONChildren
		}
		if err := validateTextOnlyMediaFields(object, "Only text input is supported"); err != nil {
			return err
		}
		switch rawString(object["type"]) {
		case "", "message", "input_text", "output_text", "refusal":
			return nil
		case "input_file":
			return invalidRequest("file inputs are not supported")
		default:
			return invalidRequest("Only text input is supported")
		}
	})
}

var errSkipRawJSONChildren = errors.New("skip raw JSON children")

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
			if errors.Is(err, errSkipRawJSONChildren) {
				return nil
			}
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
