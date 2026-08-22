package stogas

import (
	"encoding/json"
	"fmt"
	"strings"

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
		"stop",
	} {
		if _, ok := raw[name]; ok {
			return unsupportedParameterError(name)
		}
	}
	if err := validateFalseOnlyBoolean(raw, "store"); err != nil {
		return err
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
	if err := validateResponsesTextConfig(state, raw["text"]); err != nil {
		return err
	}
	if err := validateResponsesReasoning(raw); err != nil {
		return err
	}
	if err := validateResponsesTruncation(state, raw["truncation"]); err != nil {
		return err
	}
	return validateResponsesInputTextOnly(state, raw["input"])
}

func validateResponsesTextConfig(state *State, raw json.RawMessage) error {
	if !rawJSONValueSet(raw) {
		return nil
	}
	text, ok := rawObject(raw)
	if !ok || !onlyRawKeysOptional(text, "format", "verbosity") {
		return invalidRequest("text must contain only format and verbosity")
	}
	if verbosity, exists := text["verbosity"]; exists && rawJSONValueSet(verbosity) {
		if responsesUsesAnthropicWire(state) {
			return invalidRequest("text.verbosity cannot be preserved on Anthropic-format deployments")
		}
		if _, ok := rawStringValue(verbosity); !ok {
			return invalidRequest("text.verbosity must be a string")
		}
	}
	formatRaw, exists := text["format"]
	if !exists || !rawJSONValueSet(formatRaw) {
		return nil
	}
	format, ok := rawObject(formatRaw)
	if !ok {
		return invalidRequest("text.format must be an object")
	}
	formatType, ok := rawStringValue(format["type"])
	if !ok {
		return invalidRequest("text.format.type must be a string")
	}
	if responsesUsesAnthropicWire(state) && formatType != "json_schema" {
		return invalidRequest("text.format.type must be json_schema for Anthropic-format deployments")
	}
	switch formatType {
	case "text", "json_object":
		if !onlyRawKeys(format, "type") {
			return invalidRequest("text.format type " + formatType + " supports only type")
		}
	case "json_schema":
		if !onlyRawKeysOptional(format, "type", "name", "description", "schema", "strict") {
			return invalidRequest("text.format json_schema contains an unsupported field")
		}
		definition := make(map[string]json.RawMessage, len(format)-1)
		for name, value := range format {
			if name != "type" {
				definition[name] = value
			}
		}
		if err := validateStructuredOutputDefinitionMap(definition, "text.format"); err != nil {
			return err
		}
	default:
		return invalidRequest("text.format.type must be text, json_object, or json_schema")
	}
	return nil
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

func validateResponsesTruncation(state *State, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return invalidRequest("truncation must be a string")
	}
	if responsesUsesAnthropicWire(state) {
		return invalidRequest("truncation is not supported for Anthropic-format deployments")
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
	if len(rawTools) > maxClientTools {
		return nil, invalidRequest("tools must contain at most 128 definitions")
	}
	seenNames := make(map[string]bool, len(rawTools))
	seenHostedTypes := make(map[schemas.ResponsesToolType]bool, len(rawTools))
	for index, rawTool := range rawTools {
		if err := validateRawResponsesToolType(state, rawTool); err != nil {
			return nil, err
		}
		toolType, name, err := validateRawResponsesToolShape(state, rawTool, index)
		if err != nil {
			return nil, err
		}
		switch toolType {
		case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
			if seenNames[name] {
				return nil, invalidRequest(fmt.Sprintf("tools[%d].name duplicates another client tool", index))
			}
			seenNames[name] = true
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
			if seenHostedTypes[toolType] {
				return nil, invalidRequest(fmt.Sprintf("tools[%d].type duplicates another hosted tool", index))
			}
			seenHostedTypes[toolType] = true
		}
	}
	var tools []schemas.ResponsesTool
	if err := sonic.Unmarshal(raw, &tools); err != nil {
		return nil, invalidRequest("tools must be an array")
	}
	for _, tool := range tools {
		switch tool.Type {
		case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
		default:
			return nil, invalidRequest("Only function, custom, web_fetch, and priced hosted web search tools are supported")
		}
	}
	return tools, nil
}

func validateResponsesToolPolicy(
	state *State,
	raw map[string]json.RawMessage,
	validateNonempty func([]schemas.ResponsesTool) error,
) error {
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
	} else if err := validateNonempty(tools); err != nil {
		return err
	}
	return validateResponsesToolChoice(state, raw["tool_choice"], tools)
}

func validateRawResponsesToolShape(state *State, tool map[string]json.RawMessage, index int) (schemas.ResponsesToolType, string, error) {
	path := fmt.Sprintf("tools[%d]", index)
	toolType := canonicalResponsesToolType(rawString(tool["type"]))
	switch toolType {
	case schemas.ResponsesToolTypeFunction:
		name, err := validateResponsesFunctionTool(tool, path)
		return toolType, name, err
	case schemas.ResponsesToolTypeCustom:
		name, err := validateResponsesCustomTool(tool, path)
		return toolType, name, err
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview:
		return toolType, "", validateResponsesWebSearchTool(state, tool, path, toolType)
	case schemas.ResponsesToolTypeWebFetch:
		return toolType, "", validateResponsesWebFetchTool(state, tool, path)
	default:
		return toolType, "", nil
	}
}

func validateResponsesFunctionTool(tool map[string]json.RawMessage, path string) (string, error) {
	name, err := validateNamedResponsesTool(tool, path, "parameters", "strict")
	if err != nil {
		return "", err
	}
	if parameters, ok := tool["parameters"]; ok {
		var schema map[string]json.RawMessage
		if err := sonic.Unmarshal(parameters, &schema); err != nil || schema == nil {
			return "", invalidRequest(path + ".parameters must be an object")
		}
	}
	if strict, ok := tool["strict"]; ok {
		var value bool
		if err := sonic.Unmarshal(strict, &value); err != nil {
			return "", invalidRequest(path + ".strict must be a boolean")
		}
	}
	if err := validateResponsesToolCacheControl(tool["cache_control"], path+".cache_control"); err != nil {
		return "", err
	}
	return name, nil
}

func validateResponsesCustomTool(tool map[string]json.RawMessage, path string) (string, error) {
	name, err := validateNamedResponsesTool(tool, path, "format")
	if err != nil {
		return "", err
	}
	if formatRaw, ok := tool["format"]; ok {
		format, ok := rawObject(formatRaw)
		if !ok || format == nil {
			return "", invalidRequest(path + ".format must be an object")
		}
		switch rawString(format["type"]) {
		case "text":
			if err := rejectUnsupportedResponsesToolKeys(format, path+".format", "type"); err != nil {
				return "", err
			}
		case "grammar":
			if err := rejectUnsupportedResponsesToolKeys(format, path+".format", "type", "definition", "syntax"); err != nil {
				return "", err
			}
			if _, err := requiredInputString(format, "definition", path+".format", false); err != nil {
				return "", err
			}
			syntax, err := requiredInputString(format, "syntax", path+".format", false)
			if err != nil {
				return "", err
			}
			if syntax != "lark" && syntax != "regex" {
				return "", invalidRequest(path + ".format.syntax must be lark or regex")
			}
		default:
			return "", invalidRequest(path + ".format.type must be text or grammar")
		}
	}
	if err := validateResponsesToolCacheControl(tool["cache_control"], path+".cache_control"); err != nil {
		return "", err
	}
	return name, nil
}

func validateNamedResponsesTool(tool map[string]json.RawMessage, path string, additionalKeys ...string) (string, error) {
	keys := append([]string{"type", "name", "description", "cache_control"}, additionalKeys...)
	if err := rejectUnsupportedResponsesToolKeys(tool, path, keys...); err != nil {
		return "", err
	}
	name, err := requiredInputString(tool, "name", path, false)
	if err != nil {
		return "", err
	}
	if !validClientToolName(name) {
		return "", invalidRequest(path + ".name must contain 1 to 64 letters, digits, underscores, or hyphens")
	}
	if err := validateResponsesToolDescription(tool["description"], path+".description"); err != nil {
		return "", err
	}
	return name, nil
}

func validateResponsesWebSearchTool(state *State, tool map[string]json.RawMessage, path string, toolType schemas.ResponsesToolType) error {
	if responsesUsesAnthropicWire(state) {
		if toolType == schemas.ResponsesToolTypeWebSearchPreview {
			return invalidRequest("web_search_preview tools are not supported for Anthropic-format deployments")
		}
		if err := rejectUnsupportedResponsesToolKeys(tool, path, "type", "name", "max_uses", "filters", "user_location", "cache_control"); err != nil {
			return err
		}
		if err := validateHostedToolName(tool["name"], path+".name", "web_search"); err != nil {
			return err
		}
		if err := validateResponsesHostedToolMaxUses(tool["max_uses"], path+".max_uses"); err != nil {
			return err
		}
		if err := validateResponsesDomainFilters(tool["filters"], path+".filters", true); err != nil {
			return err
		}
		if err := validateResponsesUserLocation(tool["user_location"], path+".user_location", false); err != nil {
			return err
		}
		return validateResponsesToolCacheControl(tool["cache_control"], path+".cache_control")
	}

	allowed := []string{"type", "search_context_size", "user_location"}
	if toolType == schemas.ResponsesToolTypeWebSearch {
		allowed = append(allowed, "filters")
	}
	if err := rejectUnsupportedResponsesToolKeys(tool, path, allowed...); err != nil {
		return err
	}
	if err := validateResponsesSearchContextSize(tool["search_context_size"], path+".search_context_size"); err != nil {
		return err
	}
	if err := validateResponsesUserLocation(tool["user_location"], path+".user_location", true); err != nil {
		return err
	}
	if toolType == schemas.ResponsesToolTypeWebSearch {
		return validateResponsesDomainFilters(tool["filters"], path+".filters", false)
	}
	return nil
}

func validateResponsesWebFetchTool(state *State, tool map[string]json.RawMessage, path string) error {
	if !responsesUsesAnthropicWire(state) {
		return nil
	}
	if err := rejectUnsupportedResponsesToolKeys(tool, path, "type", "name", "max_uses", "max_content_tokens", "filters", "cache_control"); err != nil {
		return err
	}
	if err := validateHostedToolName(tool["name"], path+".name", "web_fetch"); err != nil {
		return err
	}
	if err := validateResponsesHostedToolMaxUses(tool["max_uses"], path+".max_uses"); err != nil {
		return err
	}
	if value, exists, err := rawInteger(tool["max_content_tokens"], path+".max_content_tokens"); err != nil {
		return err
	} else if exists {
		maximum := 0
		if state != nil && state.Resolution != nil {
			maximum = state.Resolution.Deployment.ContextWindowTokens
		}
		if value < 1 || maximum > 0 && value > maximum {
			return invalidRequest(path + ".max_content_tokens is outside the supported range")
		}
	}
	if err := validateResponsesDomainFilters(tool["filters"], path+".filters", true); err != nil {
		return err
	}
	return validateResponsesToolCacheControl(tool["cache_control"], path+".cache_control")
}

func validateResponsesToolDescription(raw json.RawMessage, path string) error {
	if len(raw) == 0 {
		return nil
	}
	value, ok := rawStringValue(raw)
	if !ok {
		return invalidRequest(path + " must be a string")
	}
	if len(value) > maxToolDescriptionBytes {
		return invalidRequest(path + " exceeds 1024 bytes")
	}
	return nil
}

func validateResponsesToolCacheControl(raw json.RawMessage, path string) error {
	if len(raw) == 0 {
		return nil
	}
	value, ok := rawObject(raw)
	if !ok || value == nil {
		return invalidRequest(path + " must be an object")
	}
	return nil
}

func validateHostedToolName(raw json.RawMessage, path string, expected string) error {
	if len(raw) == 0 {
		return nil
	}
	name, ok := rawStringValue(raw)
	if !ok || name != expected {
		return invalidRequest(path + " must be " + expected)
	}
	return nil
}

func validateResponsesHostedToolMaxUses(raw json.RawMessage, path string) error {
	value, exists, err := rawInteger(raw, path)
	if err != nil || !exists {
		return err
	}
	if value < 1 || value > maxResponsesToolCalls {
		return invalidRequest(path + " is outside the supported range")
	}
	return nil
}

func validateResponsesSearchContextSize(raw json.RawMessage, path string) error {
	if len(raw) == 0 {
		return nil
	}
	value, ok := rawStringValue(raw)
	if !ok {
		return invalidRequest(path + " must be a string")
	}
	if value != "low" && value != "medium" && value != "high" {
		return invalidRequest(path + " must be low, medium, or high")
	}
	return nil
}

func validateResponsesUserLocation(raw json.RawMessage, path string, allowRegion bool) error {
	if len(raw) == 0 {
		return nil
	}
	location, ok := rawObject(raw)
	if !ok || location == nil {
		return invalidRequest(path + " must be an object")
	}
	allowed := []string{"type", "city", "country", "timezone"}
	if allowRegion {
		allowed = append(allowed, "region")
	}
	if err := rejectUnsupportedResponsesToolKeys(location, path, allowed...); err != nil {
		return err
	}
	if rawString(location["type"]) != "approximate" {
		return invalidRequest(path + ".type must be approximate")
	}
	for _, key := range []string{"city", "region", "timezone"} {
		if value, exists := location[key]; exists {
			if text, ok := rawStringValue(value); !ok || strings.TrimSpace(text) == "" {
				return invalidRequest(path + "." + key + " must be a non-empty string")
			}
		}
	}
	if country, exists := location["country"]; exists {
		value, ok := rawStringValue(country)
		if !ok || len(value) != 2 || !isASCIIAlpha(value[0]) || !isASCIIAlpha(value[1]) {
			return invalidRequest(path + ".country must be a two-letter country code")
		}
	}
	return nil
}

func validateResponsesDomainFilters(raw json.RawMessage, path string, allowBlocked bool) error {
	if len(raw) == 0 {
		return nil
	}
	filters, ok := rawObject(raw)
	if !ok || filters == nil {
		return invalidRequest(path + " must be an object")
	}
	allowed := []string{"allowed_domains"}
	if allowBlocked {
		allowed = append(allowed, "blocked_domains")
	}
	if err := rejectUnsupportedResponsesToolKeys(filters, path, allowed...); err != nil {
		return err
	}
	seen := make(map[string]string)
	count := 0
	for _, key := range allowed {
		rawDomains, exists := filters[key]
		if !exists {
			continue
		}
		var domains []string
		if err := sonic.Unmarshal(rawDomains, &domains); err != nil || len(domains) == 0 || len(domains) > 100 {
			return invalidRequest(path + "." + key + " must contain 1 to 100 domains")
		}
		for _, domain := range domains {
			normalized := strings.ToLower(strings.TrimSpace(domain))
			if !validWebSearchDomain(normalized) {
				return invalidRequest(path + "." + key + " contains an invalid domain")
			}
			if previous, duplicate := seen[normalized]; duplicate {
				return invalidRequest(path + "." + key + " duplicates a domain from " + previous)
			}
			seen[normalized] = key
			count++
		}
	}
	if count == 0 {
		return invalidRequest(path + " must contain a domain list")
	}
	return nil
}

func validWebSearchDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			value := label[index]
			if !isASCIIAlpha(value) && (value < '0' || value > '9') && value != '-' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func rejectUnsupportedResponsesToolKeys(object map[string]json.RawMessage, path string, keys ...string) error {
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range object {
		if !allowed[key] {
			return invalidRequest(path + "." + key + " is not supported")
		}
	}
	return nil
}

func responsesUsesAnthropicWire(state *State) bool {
	return state != nil && state.Resolution != nil &&
		(state.Resolution.Provider == schemas.Anthropic ||
			(state.Resolution.Provider == schemas.Azure && azureDeploymentUsesAnthropicWire(state)))
}

func validateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	rawType := rawString(tool["type"])
	if rawType == "" {
		return invalidRequest("tools must declare a type")
	}
	if state == nil || state.Resolution == nil {
		return invalidRequest("Only function, custom, and priced hosted web search tools are supported")
	}
	if state.Adapter == nil {
		return invalidRequest("Only function, custom, and priced hosted web search tools are supported")
	}
	return state.Adapter.ValidateRawResponsesToolType(state, tool)
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
	rawType := rawString(choice["type"])
	if rawType == "allowed_tools" {
		if responsesUsesAnthropicWire(state) {
			return invalidRequest("tool_choice.allowed_tools is supported only for OpenAI-format deployments")
		}
		if err := rejectUnsupportedResponsesToolKeys(choice, "tool_choice", "type", "mode", "tools"); err != nil {
			return err
		}
		mode, err := requiredInputString(choice, "mode", "tool_choice", false)
		if err != nil {
			return err
		}
		if mode != "auto" && mode != "required" {
			return invalidRequest("tool_choice.mode must be auto or required")
		}
		rawAllowed, ok := choice["tools"]
		if !ok {
			return invalidRequest("tool_choice.allowed_tools requires tools")
		}
		return validateResponsesAllowedToolChoice(state, rawAllowed, tools)
	}
	selectedType, err := validateResponsesToolSelectorType(state, rawType)
	if err != nil {
		return err
	}
	switch selectedType {
	case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
		if err := rejectUnsupportedResponsesToolKeys(choice, "tool_choice", "type", "name"); err != nil {
			return err
		}
		name := strings.TrimSpace(rawString(choice["name"]))
		if !validClientToolName(name) {
			return invalidRequest("tool_choice must name a " + string(selectedType) + " tool")
		}
		if !responsesNamedToolExists(tools, selectedType, name) {
			return invalidRequest("tool_choice selects an unknown " + string(selectedType) + " tool")
		}
		return nil
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
		if err := rejectUnsupportedResponsesToolKeys(choice, "tool_choice", "type"); err != nil {
			return err
		}
		if !responsesToolTypeExists(tools, selectedType) || !responsesRawHostedToolExists(state, rawType) {
			return invalidRequest("tool_choice selects an undeclared hosted tool version")
		}
		return nil
	default:
		return invalidRequest("tool_choice must select a supported tool")
	}
}

func validateResponsesAllowedToolChoice(state *State, raw json.RawMessage, tools []schemas.ResponsesTool) error {
	var allowedTools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &allowedTools); err != nil || len(allowedTools) == 0 || len(allowedTools) > maxClientTools {
		return invalidRequest("tool_choice.allowed_tools requires 1 to 128 tools")
	}
	seen := make(map[string]bool, len(allowedTools))
	for index, allowed := range allowedTools {
		path := fmt.Sprintf("tool_choice.tools[%d]", index)
		toolType, err := validateResponsesToolSelectorType(state, rawString(allowed["type"]))
		if err != nil {
			return err
		}
		switch toolType {
		case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
			if err := rejectUnsupportedResponsesToolKeys(allowed, path, "type", "name"); err != nil {
				return err
			}
			name := strings.TrimSpace(rawString(allowed["name"]))
			if !validClientToolName(name) {
				return invalidRequest("tool_choice.allowed_tools " + string(toolType) + " entries require name")
			}
			if !responsesNamedToolExists(tools, toolType, name) {
				return invalidRequest("tool_choice selects an unknown " + string(toolType) + " tool")
			}
			identity := string(toolType) + ":" + name
			if seen[identity] {
				return invalidRequest(path + " duplicates another allowed tool")
			}
			seen[identity] = true
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
			if err := rejectUnsupportedResponsesToolKeys(allowed, path, "type"); err != nil {
				return err
			}
			if !responsesToolTypeExists(tools, toolType) || !responsesRawHostedToolExists(state, rawString(allowed["type"])) {
				return invalidRequest("tool_choice selects an undeclared hosted tool version")
			}
			identity := string(toolType)
			if seen[identity] {
				return invalidRequest(path + " duplicates another allowed tool")
			}
			seen[identity] = true
		default:
			return invalidRequest("tool_choice must select a supported tool")
		}
	}
	return nil
}

func responsesRawHostedToolExists(state *State, rawType string) bool {
	if state == nil || state.Resolution == nil {
		return false
	}
	rawType = strings.TrimSpace(rawType)
	for _, tool := range state.Resolution.RawTools() {
		if strings.TrimSpace(rawString(tool["type"])) == rawType {
			return true
		}
	}
	return false
}

func validateResponsesToolSelectorType(state *State, rawType string) (schemas.ResponsesToolType, error) {
	rawType = strings.TrimSpace(rawType)
	toolType := canonicalResponsesToolType(rawType)
	if responsesUsesAnthropicWire(state) && rawType != "function" {
		return toolType, invalidRequest("Anthropic-format deployments support only string tool_choice modes or named function selectors")
	}
	switch toolType {
	case schemas.ResponsesToolTypeFunction:
		if rawType == "function" {
			return toolType, nil
		}
	case schemas.ResponsesToolTypeCustom:
		if rawType == "custom" && !responsesUsesAnthropicWire(state) {
			return toolType, nil
		}
	case schemas.ResponsesToolTypeWebSearch:
		if state != nil && state.Resolution != nil && state.Resolution.Provider == schemas.OpenAI && openAIWebSearchToolType(rawType) {
			return toolType, nil
		}
	case schemas.ResponsesToolTypeWebSearchPreview:
		if state != nil && state.Resolution != nil && state.Resolution.Provider == schemas.OpenAI && openAIWebSearchToolType(rawType) {
			return toolType, nil
		}
	}
	return toolType, invalidRequest("tool_choice must select a supported tool")
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

type responsesInputValidation struct {
	calls            map[string]string
	meaningful       bool
	outputs          map[string]bool
	pendingCalls     int
	seenConversation bool
}

func validateResponsesInputTextOnly(state *State, raw json.RawMessage) error {
	if len(raw) == 0 {
		return invalidRequest("input is required")
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return invalidRequest("input must be a non-empty string or array")
	}
	if trimmed[0] == '"' {
		var input string
		if err := sonic.Unmarshal(raw, &input); err != nil {
			return invalidRequest("input must be a string or array")
		}
		if strings.TrimSpace(input) == "" {
			return invalidRequest("input must contain non-empty text")
		}
		return nil
	}
	if trimmed[0] != '[' {
		return invalidRequest("input must be a string or array")
	}
	var items []json.RawMessage
	if err := sonic.Unmarshal(raw, &items); err != nil {
		return invalidRequest("input must be a string or array")
	}
	if len(items) == 0 {
		return invalidRequest("input must contain at least one item")
	}
	validation := responsesInputValidation{
		calls:   make(map[string]string),
		outputs: make(map[string]bool),
	}
	for index, itemRaw := range items {
		var item map[string]json.RawMessage
		if err := sonic.Unmarshal(itemRaw, &item); err != nil || item == nil {
			return invalidRequest("input items must be objects")
		}
		path := fmt.Sprintf("input[%d]", index)
		itemType := rawString(item["type"])
		role := rawString(item["role"])
		isSystemMessage := (itemType == "" || itemType == "message") && (role == "system" || role == "developer")
		if rawType, exists := item["type"]; exists {
			value, ok := rawStringValue(rawType)
			if !ok || strings.TrimSpace(value) == "" {
				return invalidRequest(path + ".type must be a string")
			}
		}
		if validation.pendingCalls > 0 {
			switch itemType {
			case "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output":
			default:
				return invalidRequest(path + " must resolve the preceding client tool calls before adding another input item")
			}
		}
		switch itemType {
		case "", "message":
			if err := validateResponsesMessageInput(state, item, path, &validation); err != nil {
				return err
			}
			if responsesUsesAnthropicWire(state) && index == len(items)-1 && role == "assistant" {
				if err := rejectTrailingAssistantWhitespace(item["content"], path+".content"); err != nil {
					return err
				}
			}
		case "function_call":
			if err := validateResponsesToolCallInput(state, item, path, "function", &validation); err != nil {
				return err
			}
		case "function_call_output":
			if err := validateResponsesToolCallOutputInput(item, path, "function", &validation); err != nil {
				return err
			}
		case "custom_tool_call":
			if !responsesCustomCallInputSupported(state) {
				return invalidRequest("custom_tool_call input items are supported only for OpenAI-format deployments")
			}
			if err := validateResponsesToolCallInput(state, item, path, "custom", &validation); err != nil {
				return err
			}
		case "custom_tool_call_output":
			if !responsesCustomCallInputSupported(state) {
				return invalidRequest("custom_tool_call_output input items are supported only for OpenAI-format deployments")
			}
			if err := validateResponsesToolCallOutputInput(item, path, "custom", &validation); err != nil {
				return err
			}
		case "reasoning":
			if err := validateResponsesReasoningInput(state, item, path); err != nil {
				return err
			}
		case "input_file":
			return invalidRequest("file inputs are not supported")
		default:
			if err := validateTextOnlyMediaFields(item, "Only text input is supported"); err != nil {
				return err
			}
			return invalidRequest("Only text messages, client tool calls and outputs, and encrypted reasoning input are supported")
		}
		if responsesUsesAnthropicWire(state) {
			if isSystemMessage && validation.seenConversation {
				if !anthropicWireSupportsMidConversationSystem(state) {
					return invalidRequest(path + ".role cannot be preserved after the conversation starts on this Anthropic-format deployment")
				}
				if index+1 < len(items) && !responsesInputCreatesAnthropicAssistantTurn(items[index+1]) {
					return invalidRequest(path + ".role must be last or immediately precede an assistant turn on this Anthropic-format deployment")
				}
			} else if !isSystemMessage {
				validation.seenConversation = true
			}
		}
	}
	for callID, kind := range validation.calls {
		if !validation.outputs[callID] {
			return invalidRequest(kind + " tool calls require one matching output in the same stateless input")
		}
	}
	if !validation.meaningful {
		return invalidRequest("input must contain non-empty text or a client tool result")
	}
	return nil
}

func validateResponsesMessageInput(state *State, item map[string]json.RawMessage, path string, validation *responsesInputValidation) error {
	if err := rejectUnsupportedInputKeys(item, path, "type", "id", "status", "role", "content"); err != nil {
		return err
	}
	if err := validateResponsesInputItemIdentity(item, path); err != nil {
		return err
	}
	if rawType, exists := item["type"]; exists && rawString(rawType) != "message" {
		return invalidRequest(path + ".type must be message")
	}
	role, ok := rawStringValue(item["role"])
	if !ok {
		return invalidRequest(path + ".role must be a string")
	}
	switch role {
	case "assistant", "developer", "system", "user":
	default:
		return invalidRequest(path + ".role is not supported")
	}
	content, ok := item["content"]
	if !ok {
		return invalidRequest(path + ".content is required")
	}
	meaningful, err := validateResponsesMessageContent(state, content, path+".content", role)
	if err != nil {
		return err
	}
	validation.meaningful = validation.meaningful || meaningful
	return nil
}

func validateResponsesMessageContent(state *State, raw json.RawMessage, path string, role string) (bool, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return false, invalidRequest(path + " must contain text")
	}
	if trimmed[0] == '"' {
		var text string
		if err := sonic.Unmarshal(raw, &text); err != nil {
			return false, invalidRequest(path + " must be text or an array of text blocks")
		}
		if strings.TrimSpace(text) == "" {
			return false, invalidRequest(path + " must contain non-empty text")
		}
		return true, nil
	}
	var blocks []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &blocks); err != nil || len(blocks) == 0 {
		return false, invalidRequest(path + " must be text or a non-empty array of text blocks")
	}
	meaningful := false
	for index, block := range blocks {
		blockPath := fmt.Sprintf("%s[%d]", path, index)
		switch rawString(block["type"]) {
		case "input_text":
			if err := rejectUnsupportedInputKeys(block, blockPath, "type", "text", "cache_control", "prompt_cache_breakpoint"); err != nil {
				return false, err
			}
			if role == "assistant" {
				return false, invalidRequest(blockPath + ".type must be output_text or refusal for assistant history")
			}
			text, ok := rawStringValue(block["text"])
			if !ok {
				return false, invalidRequest(blockPath + ".text must be a string")
			}
			meaningful = meaningful || strings.TrimSpace(text) != ""
		case "output_text":
			if err := rejectUnsupportedInputKeys(block, blockPath, "type", "text", "annotations", "logprobs", "cache_control"); err != nil {
				return false, err
			}
			if role != "assistant" {
				return false, invalidRequest(blockPath + ".type is supported only for assistant history")
			}
			text, ok := rawStringValue(block["text"])
			if !ok {
				return false, invalidRequest(blockPath + ".text must be a string")
			}
			if err := validateResponsesOutputAnnotations(state, block["annotations"], blockPath+".annotations"); err != nil {
				return false, err
			}
			if err := validateResponsesOutputLogProbs(state, block["logprobs"], blockPath+".logprobs"); err != nil {
				return false, err
			}
			meaningful = meaningful || strings.TrimSpace(text) != ""
		case "refusal":
			if err := rejectUnsupportedInputKeys(block, blockPath, "type", "refusal"); err != nil {
				return false, err
			}
			if role != "assistant" {
				return false, invalidRequest(blockPath + ".type is supported only for assistant history")
			}
			if responsesUsesAnthropicWire(state) {
				return false, invalidRequest("refusal history is not supported for Anthropic-format deployments")
			}
			text, ok := rawStringValue(block["refusal"])
			if !ok {
				return false, invalidRequest(blockPath + ".refusal must be a string")
			}
			meaningful = meaningful || strings.TrimSpace(text) != ""
		case "input_file":
			return false, invalidRequest("file inputs are not supported")
		default:
			if err := validateTextOnlyMediaFields(block, "Only text input is supported"); err != nil {
				return false, err
			}
			return false, invalidRequest("Only input_text, output_text, and refusal content blocks are supported")
		}
	}
	if !meaningful {
		return false, invalidRequest(path + " must contain non-empty text")
	}
	return true, nil
}

func validateResponsesOutputAnnotations(state *State, raw json.RawMessage, path string) error {
	if len(raw) == 0 {
		return nil
	}
	var annotations []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &annotations); err != nil || annotations == nil {
		return invalidRequest(path + " must be an array")
	}
	for index, annotation := range annotations {
		annotationPath := fmt.Sprintf("%s[%d]", path, index)
		allowed := []string{"type", "start_index", "end_index", "title", "url"}
		if responsesUsesAnthropicWire(state) {
			allowed = append(allowed, "text", "encrypted_index")
		}
		if err := rejectUnsupportedInputKeys(annotation, annotationPath, allowed...); err != nil {
			return err
		}
		if rawString(annotation["type"]) != "url_citation" {
			return invalidRequest(annotationPath + ".type must be url_citation")
		}
		start, startExists, startErr := rawInteger(annotation["start_index"], annotationPath+".start_index")
		if startErr != nil || !startExists || start < 0 {
			return invalidRequest(annotationPath + ".start_index must be a non-negative integer")
		}
		end, endExists, endErr := rawInteger(annotation["end_index"], annotationPath+".end_index")
		if endErr != nil || !endExists || end < start {
			return invalidRequest(annotationPath + ".end_index must be an integer at or after start_index")
		}
		if _, err := requiredInputString(annotation, "url", annotationPath, false); err != nil {
			return err
		}
		if _, err := requiredInputString(annotation, "title", annotationPath, true); err != nil {
			return err
		}
		for _, key := range []string{"text", "encrypted_index"} {
			if value, exists := annotation[key]; exists {
				if _, ok := rawStringValue(value); !ok {
					return invalidRequest(annotationPath + "." + key + " must be a string")
				}
			}
		}
	}
	return nil
}

func validateResponsesOutputLogProbs(state *State, raw json.RawMessage, path string) error {
	if len(raw) == 0 {
		return nil
	}
	var entries []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &entries); err != nil || entries == nil {
		return invalidRequest(path + " must be an array")
	}
	if responsesUsesAnthropicWire(state) && len(entries) > 0 {
		return invalidRequest(path + " cannot be preserved on Anthropic-format deployments")
	}
	for index, entry := range entries {
		if err := validateResponsesOutputLogProb(entry, fmt.Sprintf("%s[%d]", path, index), true); err != nil {
			return err
		}
	}
	return nil
}

func validateResponsesOutputLogProb(entry map[string]json.RawMessage, path string, allowTop bool) error {
	allowed := []string{"token", "logprob", "bytes"}
	if allowTop {
		allowed = append(allowed, "top_logprobs")
	}
	if err := rejectUnsupportedInputKeys(entry, path, allowed...); err != nil {
		return err
	}
	if _, err := requiredInputString(entry, "token", path, true); err != nil {
		return err
	}
	var probability float64
	if value, exists := entry["logprob"]; !exists || sonic.Unmarshal(value, &probability) != nil {
		return invalidRequest(path + ".logprob must be a number")
	}
	if rawBytes, exists := entry["bytes"]; exists && strings.TrimSpace(string(rawBytes)) != "null" {
		var values []int
		if err := sonic.Unmarshal(rawBytes, &values); err != nil {
			return invalidRequest(path + ".bytes must be an array of bytes or null")
		}
		for _, value := range values {
			if value < 0 || value > 255 {
				return invalidRequest(path + ".bytes must contain integers from 0 to 255")
			}
		}
	}
	if !allowTop {
		return nil
	}
	if rawTop, exists := entry["top_logprobs"]; exists && strings.TrimSpace(string(rawTop)) != "null" {
		var top []map[string]json.RawMessage
		if err := sonic.Unmarshal(rawTop, &top); err != nil {
			return invalidRequest(path + ".top_logprobs must be an array or null")
		}
		for index, candidate := range top {
			if err := validateResponsesOutputLogProb(candidate, fmt.Sprintf("%s.top_logprobs[%d]", path, index), false); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateResponsesToolCallInput(state *State, item map[string]json.RawMessage, path string, kind string, validation *responsesInputValidation) error {
	allowed := []string{"type", "id", "status", "call_id", "name"}
	payloadField := "arguments"
	if kind == "custom" {
		payloadField = "input"
	}
	allowed = append(allowed, payloadField)
	if err := rejectUnsupportedInputKeys(item, path, allowed...); err != nil {
		return err
	}
	if err := validateResponsesInputItemIdentity(item, path); err != nil {
		return err
	}
	callID, err := requiredInputString(item, "call_id", path, false)
	if err != nil {
		return err
	}
	if err := validateProviderToolCallID(state, callID, path+".call_id"); err != nil {
		return err
	}
	if _, exists := validation.calls[callID]; exists {
		return invalidRequest(path + ".call_id duplicates another client tool call")
	}
	name, err := requiredInputString(item, "name", path, false)
	if err != nil {
		return err
	}
	if !validClientToolName(name) {
		return invalidRequest(path + ".name must contain 1 to 64 letters, digits, underscores, or hyphens")
	}
	payload, err := requiredInputString(item, payloadField, path, true)
	if err != nil {
		return err
	}
	if kind == "function" {
		if !catalog.ValidateJSONObjectText(payload) {
			return invalidRequest(path + ".arguments must encode a JSON object")
		}
	}
	validation.calls[callID] = kind
	validation.pendingCalls++
	return nil
}

func responsesInputCreatesAnthropicAssistantTurn(raw json.RawMessage) bool {
	var item map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &item); err != nil || item == nil {
		return false
	}
	switch rawString(item["type"]) {
	case "function_call":
		return true
	case "", "message":
		return rawString(item["role"]) == "assistant"
	default:
		return false
	}
}

func validateResponsesToolCallOutputInput(item map[string]json.RawMessage, path string, kind string, validation *responsesInputValidation) error {
	if err := rejectUnsupportedInputKeys(item, path, "type", "id", "status", "call_id", "output"); err != nil {
		return err
	}
	if err := validateResponsesInputItemIdentity(item, path); err != nil {
		return err
	}
	callID, err := requiredInputString(item, "call_id", path, false)
	if err != nil {
		return err
	}
	callKind, exists := validation.calls[callID]
	if !exists {
		return invalidRequest(path + ".call_id must match an earlier client tool call")
	}
	if callKind != kind {
		return invalidRequest(path + ".call_id selects a different client tool type")
	}
	if validation.outputs[callID] {
		return invalidRequest(path + ".call_id duplicates a client tool output")
	}
	if _, err := requiredInputString(item, "output", path, true); err != nil {
		return err
	}
	validation.outputs[callID] = true
	validation.pendingCalls--
	validation.meaningful = true
	return nil
}

func validateResponsesReasoningInput(state *State, item map[string]json.RawMessage, path string) error {
	if state == nil || state.Resolution == nil || state.Resolution.Provider != schemas.OpenAI || !state.Resolution.Deployment.ReasoningSupported {
		return invalidRequest("reasoning input items are only supported for OpenAI reasoning deployments")
	}
	if err := rejectUnsupportedInputKeys(item, path, "type", "id", "status", "summary", "content", "encrypted_content"); err != nil {
		return err
	}
	if err := validateResponsesInputItemIdentity(item, path); err != nil {
		return err
	}
	if _, err := requiredInputString(item, "encrypted_content", path, false); err != nil {
		return invalidRequest("reasoning input items require encrypted_content")
	}
	if raw, ok := item["summary"]; ok {
		if err := validateResponsesReasoningTextBlocks(raw, path+".summary", "summary_text"); err != nil {
			return err
		}
	}
	if raw, ok := item["content"]; ok {
		if err := validateResponsesReasoningTextBlocks(raw, path+".content", "reasoning_text"); err != nil {
			return err
		}
	}
	return nil
}

func validateResponsesReasoningTextBlocks(raw json.RawMessage, path string, expectedType string) error {
	var blocks []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &blocks); err != nil {
		return invalidRequest(path + " must be an array")
	}
	for index, block := range blocks {
		blockPath := fmt.Sprintf("%s[%d]", path, index)
		if err := rejectUnsupportedInputKeys(block, blockPath, "type", "text"); err != nil {
			return err
		}
		if rawString(block["type"]) != expectedType {
			return invalidRequest(blockPath + ".type must be " + expectedType)
		}
		if _, err := requiredInputString(block, "text", blockPath, true); err != nil {
			return err
		}
	}
	return nil
}

func validateResponsesInputItemIdentity(item map[string]json.RawMessage, path string) error {
	if raw, ok := item["id"]; ok {
		if _, err := requiredInputString(map[string]json.RawMessage{"id": raw}, "id", path, false); err != nil {
			return err
		}
	}
	if raw, ok := item["status"]; ok {
		status, ok := rawStringValue(raw)
		if !ok {
			return invalidRequest(path + ".status must be a string")
		}
		switch status {
		case "completed", "in_progress", "incomplete":
		default:
			return invalidRequest(path + ".status is not supported")
		}
	}
	return nil
}

func responsesCustomCallInputSupported(state *State) bool {
	if state == nil || state.Resolution == nil {
		return false
	}
	return state.Resolution.Provider == schemas.OpenAI ||
		(state.Resolution.Provider == schemas.Azure && !azureDeploymentUsesAnthropicWire(state))
}
