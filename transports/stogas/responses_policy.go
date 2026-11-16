package stogas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bytedance/sonic"
	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

const (
	// The hosted tool calls that a hold covers when the client sets no cap. The provider receives
	// no cap either, so the model decides how many it makes and settlement charges those.
	defaultResponsesHostedToolCalls = 10
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
	if _, ok := raw["input"]; !ok {
		return invalidRequest("input is required")
	}
	for _, name := range catalog.ResponsesRefusedFields {
		if _, ok := raw[name]; ok {
			return unsupportedParameterError(name)
		}
	}
	if state.Resolution.Bridged() {
		// Chat Completions takes them as stop, which Responses lacks.
		if err := validateStopSequenceArray(raw["stop_sequences"], "stop_sequences", maxPortableStopSequences); err != nil {
			return err
		}
		// The Chat Completions body keeps only the function tools that tool_choice allows, so its
		// checks cannot tell what tool_choice asked, and the reply checks hold the reply to it.
		var tools []schemas.ResponsesTool
		if rawJSONValueSet(raw["tools"]) {
			if err := sonic.Unmarshal(raw["tools"], &tools); err != nil {
				return invalidRequest("tools must be an array")
			}
			if err := validateBridgedResponsesNamespaces(raw["tools"]); err != nil {
				return err
			}
		}
		if err := validateResponsesToolChoice(state, raw["tool_choice"], tools); err != nil {
			return err
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
	if err := validatePromptCacheKey(raw["prompt_cache_key"]); err != nil {
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
	metadata, err := parseMetadata(raw["metadata"], state.MetadataHeader)
	if err != nil {
		return err
	}
	state.Metadata = metadata
	if err := validateResponsesTextConfig(state, raw["text"]); err != nil {
		return err
	}
	if err := validateResponsesTruncation(state, raw["truncation"]); err != nil {
		return err
	}
	if err := validateResponsesAccessPrograms(state, raw["access_programs"]); err != nil {
		return err
	}
	return validateResponsesInput(state, raw["input"])
}

// validateBridgedResponsesNamespaces checks the namespaces of a request that its deployment takes
// through Chat Completions. The translation turns their tools into function tools, whose checks
// cannot tell what the namespaces held.
func validateBridgedResponsesNamespaces(raw json.RawMessage) error {
	tools, _ := rawjson.Array(raw)
	seen := make(map[string]bool)
	for index, rawTool := range tools {
		tool, err := rawjson.Object(rawTool)
		if err != nil || catalog.CanonicalResponsesToolType(rawString(tool["type"])) != schemas.ResponsesToolTypeNamespace {
			continue
		}
		path := fmt.Sprintf("tools[%d]", index)
		name, err := validateResponsesNamespaceTool(tool, path)
		if err != nil {
			return err
		}
		if seen[name] {
			return invalidRequest(path + ".name duplicates another namespace")
		}
		seen[name] = true
	}
	return nil
}

// validateResponsesAccessPrograms accepts OpenAI's cyber access program
// selection. Only OpenAI runs these programs: Azure OpenAI refuses the field
// and Claude has no equivalent, so a program selected for another provider is
// refused rather than dropped.
func validateResponsesAccessPrograms(state *State, raw json.RawMessage) error {
	program, err := responsesCyberAccessProgram(raw)
	if err != nil || program == "" {
		return err
	}
	if state.Resolution.Provider != schemas.OpenAI {
		return invalidRequest("access_programs is supported only on OpenAI deployments")
	}
	return nil
}

// responsesCyberAccessProgram returns access_programs.cyber, or "" when the
// request selects no program. OpenAI treats an empty object as omission.
func responsesCyberAccessProgram(raw json.RawMessage) (string, error) {
	if !rawJSONValueSet(raw) {
		return "", nil
	}
	programs, ok := rawObject(raw)
	if !ok {
		return "", invalidRequest("access_programs must be an object")
	}
	if err := rejectUnsupportedInputKeys(programs, "access_programs", "cyber"); err != nil {
		return "", err
	}
	cyber, exists := programs["cyber"]
	if !exists {
		return "", nil
	}
	switch program, _ := rawStringValue(cyber); program {
	case "standard", "daybreak_blue", "daybreak_red":
		return program, nil
	}
	return "", invalidRequest("access_programs.cyber must be standard, daybreak_blue or daybreak_red")
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
	seenNames := make(map[string]bool, len(rawTools))
	seenNamespaces := make(map[string]bool)
	seenHostedTypes := make(map[schemas.ResponsesToolType]bool, len(rawTools))
	seenServers := make(map[string]bool)
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
		case schemas.ResponsesToolTypeNamespace:
			if seenNamespaces[name] {
				return nil, invalidRequest(fmt.Sprintf("tools[%d].name duplicates another namespace", index))
			}
			seenNamespaces[name] = true
			for member, entry := range catalog.ResponsesToolList([]map[string]json.RawMessage{rawTool}) {
				if err := validateRawResponsesToolType(state, entry.Tool); err != nil {
					return nil, err
				}
				if entry.Namespace != "" {
					continue
				}
				// The namespace functions holds top-level tools, so its tools share their names.
				memberName := rawString(entry.Tool["name"])
				if seenNames[memberName] {
					return nil, invalidRequest(fmt.Sprintf("tools[%d].tools[%d].name duplicates another client tool", index, member))
				}
				seenNames[memberName] = true
			}
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
			if seenHostedTypes[toolType] {
				return nil, invalidRequest(fmt.Sprintf("tools[%d].type duplicates another hosted tool", index))
			}
			seenHostedTypes[toolType] = true
		case schemas.ResponsesToolTypeMCP:
			// A response names each MCP server by its label, so labels must differ.
			if seenServers[name] {
				return nil, invalidRequest(fmt.Sprintf("tools[%d].server_label duplicates another MCP server", index))
			}
			seenServers[name] = true
		}
	}
	var tools []schemas.ResponsesTool
	if err := sonic.Unmarshal(raw, &tools); err != nil {
		return nil, invalidRequest("tools must be an array")
	}
	for _, tool := range tools {
		switch tool.Type {
		case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom, schemas.ResponsesToolTypeNamespace:
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
		case schemas.ResponsesToolTypeMCP:
		case schemas.ResponsesToolTypeShell, schemas.ResponsesToolTypeApplyPatch:
		case catalog.AnthropicBashToolType, catalog.AnthropicTextEditorToolType:
		default:
			return nil, invalidRequest("Only function, custom, namespace, shell, apply_patch, web_fetch, and priced hosted web search tools are supported")
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
	} else if err := validateNonempty(tools); err != nil {
		return err
	}
	return validateResponsesToolChoice(state, raw["tool_choice"], tools)
}

func validateRawResponsesToolShape(state *State, tool map[string]json.RawMessage, index int) (schemas.ResponsesToolType, string, error) {
	path := fmt.Sprintf("tools[%d]", index)
	toolType := catalog.CanonicalResponsesToolType(rawString(tool["type"]))
	if name, ok := catalog.AnthropicClientToolName(rawString(tool["type"])); ok {
		return toolType, name, validateAnthropicClientTool(tool, path, name)
	}
	switch toolType {
	case schemas.ResponsesToolTypeFunction:
		name, err := validateResponsesFunctionTool(tool, path, maxClientToolName)
		return toolType, name, err
	case schemas.ResponsesToolTypeCustom:
		name, err := validateResponsesCustomTool(tool, path, maxClientToolName)
		return toolType, name, err
	case schemas.ResponsesToolTypeNamespace:
		name, err := validateResponsesNamespaceTool(tool, path)
		return toolType, name, err
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview:
		return toolType, "", validateResponsesWebSearchTool(state, tool, path, toolType)
	case schemas.ResponsesToolTypeWebFetch:
		return toolType, "", validateResponsesWebFetchTool(state, tool, path)
	case schemas.ResponsesToolTypeMCP:
		server, err := validateResponsesMCPTool(tool, path)
		return toolType, server.label, err
	case schemas.ResponsesToolTypeShell:
		return toolType, "", validateResponsesShellTool(tool, path)
	case schemas.ResponsesToolTypeApplyPatch:
		return toolType, "", rejectUnsupportedResponsesToolKeys(tool, path, "type")
	default:
		return toolType, "", nil
	}
}

// validateAnthropicClientTool checks one of Anthropic's bash and text editor tools. Anthropic
// fixes its name, which joins the names of the request's function tools.
func validateAnthropicClientTool(tool map[string]json.RawMessage, path, name string) error {
	keys := []string{"type", "name", "cache_control"}
	if rawString(tool["type"]) == catalog.AnthropicTextEditorToolType {
		keys = append(keys, "max_characters")
	}
	if err := rejectUnsupportedResponsesToolKeys(tool, path, keys...); err != nil {
		return err
	}
	if declared, _ := rawStringValue(tool["name"]); declared != name {
		return invalidRequest(path + ".name must be " + name)
	}
	if raw, ok := tool["max_characters"]; ok {
		if value, ok := rawIntegerValue(raw); !ok || value < 1 {
			return invalidRequest(path + ".max_characters must be a positive integer")
		}
	}
	return validateResponsesToolCacheControl(tool["cache_control"], path+".cache_control")
}

// responsesLocalToolsSupported reports whether the deployment takes OpenAI's shell and apply_patch
// tools. The client runs both, they cost only their tokens, and their calls and results replay in
// input without stored state (live, November 12, 2026). Azure's are unreviewed.
func responsesLocalToolsSupported(state *State) bool {
	return state != nil && state.Resolution != nil && state.Resolution.Route == catalog.RouteResponses &&
		state.Resolution.Provider == schemas.OpenAI
}

// validateResponsesShellTool accepts only a shell that the client runs. A hosted environment
// starts a container that bills by the minute for longer than the request, and OpenAI starts it
// even when tool_choice is none (live, November 12, 2026). An omitted environment is local.
func validateResponsesShellTool(tool map[string]json.RawMessage, path string) error {
	if err := rejectUnsupportedResponsesToolKeys(tool, path, "type", "environment"); err != nil {
		return err
	}
	raw, ok := tool["environment"]
	if !ok || !rawJSONValueSet(raw) {
		return nil
	}
	path += ".environment"
	environment, ok := rawObject(raw)
	if !ok {
		return invalidRequest(path + " must be an object")
	}
	if kind, _ := rawStringValue(environment["type"]); kind != "local" {
		return invalidRequest(path + ".type must be local; hosted shell containers are not supported because their time is billed outside the request")
	}
	if err := rejectUnsupportedResponsesToolKeys(environment, path, "type", "skills"); err != nil {
		return err
	}
	rawSkills, ok := environment["skills"]
	if !ok || !rawJSONValueSet(rawSkills) {
		return nil
	}
	var skills []map[string]json.RawMessage
	if err := sonic.Unmarshal(rawSkills, &skills); err != nil {
		return invalidRequest(path + ".skills must be an array of objects")
	}
	for index, skill := range skills {
		skillPath := fmt.Sprintf("%s.skills[%d]", path, index)
		if err := rejectUnsupportedResponsesToolKeys(skill, skillPath, "name", "description", "path"); err != nil {
			return err
		}
		for _, key := range []string{"name", "description", "path"} {
			if _, err := requiredInputString(skill, key, skillPath, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateResponsesNamespaceTool checks a namespace and its tools. A namespace holds only function
// and custom tools, as on OpenAI, whose names may be longer than top-level ones. The tools of a
// namespace need different names, so that a call names one of them.
func validateResponsesNamespaceTool(tool map[string]json.RawMessage, path string) (string, error) {
	if err := rejectUnsupportedResponsesToolKeys(tool, path, "type", "name", "description", "tools"); err != nil {
		return "", err
	}
	name, err := requiredInputString(tool, "name", path, false)
	if err != nil {
		return "", err
	}
	if err := validateResponsesToolDescription(tool["description"], path+".description"); err != nil {
		return "", err
	}
	members, err := rawjson.Array(tool["tools"])
	if err != nil || len(members) == 0 {
		return "", invalidRequest(path + ".tools must be a non-empty array")
	}
	seen := make(map[string]bool, len(members))
	for index, raw := range members {
		memberPath := fmt.Sprintf("%s.tools[%d]", path, index)
		member, err := rawjson.Object(raw)
		if err != nil {
			return "", invalidRequest(memberPath + " must be an object")
		}
		memberType := rawString(member["type"])
		if memberType != "function" && memberType != "custom" {
			return "", invalidRequest(memberPath + ".type must be function or custom")
		}
		if _, ok := member["cache_control"]; ok {
			return "", invalidRequest(memberPath + ".cache_control is not supported")
		}
		var memberName string
		if memberType == "function" {
			memberName, err = validateResponsesFunctionTool(member, memberPath, maxNamespacedToolName)
		} else {
			memberName, err = validateResponsesCustomTool(member, memberPath, maxNamespacedToolName)
		}
		if err != nil {
			return "", err
		}
		if seen[memberName] {
			return "", invalidRequest(memberPath + ".name duplicates another tool in the namespace")
		}
		seen[memberName] = true
	}
	return name, nil
}

func validateResponsesFunctionTool(tool map[string]json.RawMessage, path string, maxName int) (string, error) {
	name, err := validateNamedResponsesTool(tool, path, maxName, "parameters", "strict")
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

func validateResponsesCustomTool(tool map[string]json.RawMessage, path string, maxName int) (string, error) {
	name, err := validateNamedResponsesTool(tool, path, maxName, "format")
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

func validateNamedResponsesTool(tool map[string]json.RawMessage, path string, maxName int, additionalKeys ...string) (string, error) {
	keys := append([]string{"type", "name", "description", "cache_control"}, additionalKeys...)
	if err := rejectUnsupportedResponsesToolKeys(tool, path, keys...); err != nil {
		return "", err
	}
	name, err := requiredInputString(tool, "name", path, false)
	if err != nil {
		return "", err
	}
	if err := validateToolName(name, path+".name", maxName); err != nil {
		return "", err
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
		if err := rejectUnsupportedResponsesToolKeys(tool, path, "type", "name", "max_uses", "filters", "user_location", "cache_control", "external_web_access"); err != nil {
			return err
		}
		// Claude searches only the live web. Codex asks for cached pages by default, which keep
		// live pages and the instructions they can hold away from the model.
		if access, ok := tool["external_web_access"]; ok && !rawBool(access) {
			return invalidRequest(path + ".external_web_access must be true for Anthropic-format deployments, which search only the live web")
		}
		if err := validateHostedToolName(tool["name"], path+".name", "web_search"); err != nil {
			return err
		}
		if err := validateResponsesHostedToolMaxUses(tool["max_uses"], path+".max_uses"); err != nil {
			return err
		}
		if err := validateResponsesDomainFilters(tool["filters"], path+".filters"); err != nil {
			return err
		}
		if err := validateResponsesUserLocation(tool["user_location"], path+".user_location", false); err != nil {
			return err
		}
		return validateResponsesToolCacheControl(tool["cache_control"], path+".cache_control")
	}

	allowed := []string{"type", "search_context_size", "user_location"}
	if toolType == schemas.ResponsesToolTypeWebSearch {
		// Searching only cached pages changes neither the call fee nor the content billed.
		allowed = append(allowed, "filters", "external_web_access")
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
		return validateResponsesDomainFilters(tool["filters"], path+".filters")
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
	if err := validateResponsesDomainFilters(tool["filters"], path+".filters"); err != nil {
		return err
	}
	return validateResponsesToolCacheControl(tool["cache_control"], path+".cache_control")
}

func validateResponsesToolDescription(raw json.RawMessage, path string) error {
	if len(raw) == 0 {
		return nil
	}
	if _, ok := rawStringValue(raw); !ok {
		return invalidRequest(path + " must be a string")
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
			if text, ok := rawStringValue(value); !ok || !hasNonWhitespace(text) {
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

func validateResponsesDomainFilters(raw json.RawMessage, path string) error {
	if len(raw) == 0 {
		return nil
	}
	filters, ok := rawObject(raw)
	if !ok || filters == nil {
		return invalidRequest(path + " must be an object")
	}
	allowed := []string{"allowed_domains", "blocked_domains"}
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
		if err := sonic.Unmarshal(rawDomains, &domains); err != nil || len(domains) == 0 {
			return invalidRequest(path + "." + key + " must be a non-empty array of domains")
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

// A filter names a domain, and a name that ends in a number is an IPv4 address
// to browsers, which domain filters do not cover.
func validWebSearchDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		hostEndsInNumber(domain) {
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
	return stateUsesClaudeWire(state)
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

// hostedToolOffered refuses a hosted tool that the deployment's route does not run for it, whose
// price and data handling the catalog therefore does not state. Routing already skips such
// deployments, so this guards the adapters.
func hostedToolOffered(state *State, rawType string) error {
	tool, hosted := catalog.HostedToolForType(rawType)
	if !hosted || state == nil || state.Resolution == nil {
		return nil
	}
	deployment := state.Resolution.Deployment
	if _, ok := deployment.HostedTools[tool]; ok {
		return nil
	}
	return invalidRequest(string(tool) + " is not available on deployment " + deployment.ID + ". Remove the tool or choose another deployment.")
}

func responsesHasHostedTool(tools []schemas.ResponsesTool) bool {
	for _, tool := range tools {
		switch tool.Type {
		case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch,
			schemas.ResponsesToolTypeMCP:
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
			switch catalog.CanonicalResponsesToolType(rawString(tool["type"])) {
			case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch,
				schemas.ResponsesToolTypeMCP:
				return true
			}
		}
		return false
	}
	switch catalog.CanonicalResponsesToolType(rawString(choice["type"])) {
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch,
		schemas.ResponsesToolTypeMCP:
		return true
	default:
		return false
	}
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
		if responsesNamedTools(tools)[name] != selectedType {
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
	case schemas.ResponsesToolTypeMCP:
		return validateResponsesMCPToolSelector(choice, "tool_choice", tools)
	case schemas.ResponsesToolTypeShell, schemas.ResponsesToolTypeApplyPatch:
		if err := rejectUnsupportedResponsesToolKeys(choice, "tool_choice", "type"); err != nil {
			return err
		}
		if !responsesToolTypeExists(tools, selectedType) {
			return invalidRequest("tool_choice selects an undeclared " + string(selectedType) + " tool")
		}
		return nil
	default:
		return invalidRequest("tool_choice must select a supported tool")
	}
}

// validateResponsesMCPToolSelector checks a tool_choice entry that selects a declared MCP
// server, and optionally one of its tools by name.
func validateResponsesMCPToolSelector(selector map[string]json.RawMessage, path string, tools []schemas.ResponsesTool) error {
	if err := rejectUnsupportedResponsesToolKeys(selector, path, "type", "server_label", "name"); err != nil {
		return err
	}
	label, _ := rawStringValue(selector["server_label"])
	if !responsesMCPServerDeclared(tools, label) {
		return invalidRequest(path + " selects an undeclared MCP server")
	}
	if raw := selector["name"]; rawJSONValueSet(raw) {
		if name, ok := rawStringValue(raw); !ok || strings.TrimSpace(name) == "" {
			return invalidRequest(path + ".name must name a tool")
		}
	}
	return nil
}

func responsesMCPServerDeclared(tools []schemas.ResponsesTool, label string) bool {
	for _, tool := range tools {
		if tool.Type == schemas.ResponsesToolTypeMCP && tool.ResponsesToolMCP != nil && tool.ResponsesToolMCP.ServerLabel == label && label != "" {
			return true
		}
	}
	return false
}

func validateResponsesAllowedToolChoice(state *State, raw json.RawMessage, tools []schemas.ResponsesTool) error {
	var allowedTools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &allowedTools); err != nil || len(allowedTools) == 0 {
		return invalidRequest("tool_choice.allowed_tools requires at least one tool")
	}
	named := responsesNamedTools(tools)
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
			if named[name] != toolType {
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
		case schemas.ResponsesToolTypeMCP:
			if err := validateResponsesMCPToolSelector(allowed, path, tools); err != nil {
				return err
			}
			identity := string(toolType) + ":" + rawString(allowed["server_label"]) + ":" + rawString(allowed["name"])
			if seen[identity] {
				return invalidRequest(path + " duplicates another allowed tool")
			}
			seen[identity] = true
		case schemas.ResponsesToolTypeShell, schemas.ResponsesToolTypeApplyPatch:
			if err := rejectUnsupportedResponsesToolKeys(allowed, path, "type"); err != nil {
				return err
			}
			if !responsesToolTypeExists(tools, toolType) {
				return invalidRequest("tool_choice selects an undeclared " + string(toolType) + " tool")
			}
			if seen[string(toolType)] {
				return invalidRequest(path + " duplicates another allowed tool")
			}
			seen[string(toolType)] = true
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
	toolType := catalog.CanonicalResponsesToolType(rawType)
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
	case schemas.ResponsesToolTypeMCP:
		if rawType == "mcp" && responsesMCPSupported(state) {
			return toolType, nil
		}
	case schemas.ResponsesToolTypeShell, schemas.ResponsesToolTypeApplyPatch:
		if responsesLocalToolsSupported(state) {
			return toolType, nil
		}
	}
	return toolType, invalidRequest("tool_choice must select a supported tool")
}

func responsesToolTypeExists(tools []schemas.ResponsesTool, toolType schemas.ResponsesToolType) bool {
	for _, tool := range tools {
		if tool.Type == toolType {
			return true
		}
	}
	return false
}

// responsesNamedTools maps the name of each top-level function or custom tool, including those in
// the namespace functions, to its type. The two types share one name space, so a name finds at most
// one declared tool. tool_choice can name only these tools, as on OpenAI.
func responsesNamedTools(tools []schemas.ResponsesTool) map[string]schemas.ResponsesToolType {
	named := make(map[string]schemas.ResponsesToolType, len(tools))
	for _, tool := range tools {
		switch {
		case tool.Name == nil:
		case tool.Type == schemas.ResponsesToolTypeFunction || tool.Type == schemas.ResponsesToolTypeCustom:
			named[*tool.Name] = tool.Type
		// tool_choice names one of Anthropic's client tools as a function.
		case catalog.CanonicalResponsesToolType(string(tool.Type)) == schemas.ResponsesToolTypeFunction:
			named[*tool.Name] = schemas.ResponsesToolTypeFunction
		case tool.Type == schemas.ResponsesToolTypeNamespace && *tool.Name == providerutils.DefaultToolNamespace && tool.ResponsesToolNamespace != nil:
			for _, member := range tool.ResponsesToolNamespace.Tools {
				if member.Name != nil {
					named[*member.Name] = member.Type
				}
			}
		}
	}
	return named
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
	calls         map[string]string
	meaningful    bool
	outputs       map[string]bool
	pendingCalls  int
	claudeSystems claudeSystemPlacement
}

func validateResponsesInput(state *State, raw json.RawMessage) error {
	if len(raw) == 0 {
		return invalidRequest("input is required")
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return invalidRequest("input must be a non-empty string or array")
	}
	if trimmed[0] == '"' {
		var input string
		if err := sonic.Unmarshal(raw, &input); err != nil {
			return invalidRequest("input must be a string or array")
		}
		if !hasNonWhitespace(input) {
			return invalidRequest("input must contain non-empty text")
		}
		return nil
	}
	if trimmed[0] != '[' {
		return invalidRequest("input must be a string or array")
	}
	items, err := rawjson.Array(raw)
	if err != nil {
		return invalidRequest("input must be a string or array")
	}
	if len(items) == 0 {
		return invalidRequest("input must contain at least one item")
	}
	validation := responsesInputValidation{
		calls:   make(map[string]string),
		outputs: make(map[string]bool),
	}
	var turn inputTurn
	for index, itemRaw := range items {
		item, err := rawjson.Object(itemRaw)
		if err != nil {
			return invalidRequest("input items must be objects")
		}
		path := fmt.Sprintf("input[%d]", index)
		itemType := rawString(item["type"])
		role := rawString(item["role"])
		isSystemMessage := (itemType == "" || itemType == "message") && (role == "system" || role == "developer")
		if rawType, exists := item["type"]; exists {
			value, ok := rawStringValue(rawType)
			if !ok || !hasNonWhitespace(value) {
				return invalidRequest(path + ".type must be a string")
			}
		}
		if validation.pendingCalls > 0 {
			switch itemType {
			case "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output",
				"shell_call", "shell_call_output", "apply_patch_call", "apply_patch_call_output":
			// Reasoning and MCP items are the provider's own steps, which a response can interleave with
			// client calls, as Claude does with a progress update before each call.
			case "reasoning", "mcp_list_tools", "mcp_call", "mcp_approval_request", "mcp_approval_response":
			default:
				return invalidRequest(path + " must resolve the preceding client tool calls before adding another input item")
			}
		}
		switch itemType {
		case "", "message":
			if err := validateResponsesMessageInput(state, item, path, &validation); err != nil {
				return err
			}
			if role == "assistant" {
				turn.output()
			} else {
				turn.message()
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
			turn.call()
		case "function_call_output":
			if err := validateResponsesToolCallOutputInput(item, path, "function", &validation); err != nil {
				return err
			}
			turn.result(rawString(item["call_id"]))
		case "custom_tool_call":
			if !responsesCustomCallInputSupported(state) {
				return invalidRequest("custom_tool_call input items are supported only for OpenAI-format deployments")
			}
			if err := validateResponsesToolCallInput(state, item, path, "custom", &validation); err != nil {
				return err
			}
			turn.call()
		case "custom_tool_call_output":
			if !responsesCustomCallInputSupported(state) {
				return invalidRequest("custom_tool_call_output input items are supported only for OpenAI-format deployments")
			}
			if err := validateResponsesToolCallOutputInput(item, path, "custom", &validation); err != nil {
				return err
			}
			turn.result(rawString(item["call_id"]))
		case "shell_call", "apply_patch_call":
			if !responsesLocalToolsSupported(state) {
				return invalidRequest(itemType + " input items are supported only for OpenAI deployments")
			}
			if err := validateResponsesLocalToolCallInput(item, path, itemType, &validation); err != nil {
				return err
			}
			turn.call()
		case "shell_call_output", "apply_patch_call_output":
			if !responsesLocalToolsSupported(state) {
				return invalidRequest(itemType + " input items are supported only for OpenAI deployments")
			}
			if err := validateResponsesLocalToolOutputInput(item, path, itemType, &validation); err != nil {
				return err
			}
			turn.result(rawString(item["call_id"]))
		case "reasoning":
			if err := validateResponsesReasoningInput(item, path); err != nil {
				return err
			}
			turn.output()
		case "mcp_list_tools", "mcp_call", "mcp_approval_request", "mcp_approval_response":
			if !responsesMCPSupported(state) {
				return invalidRequest(itemType + " input items are supported only for OpenAI deployments")
			}
			if err := validateResponsesMCPInput(item, path, itemType); err != nil {
				return err
			}
			if itemType == "mcp_approval_response" {
				// An approval answers the model as a client tool result does.
				validation.meaningful = true
				turn.result(rawString(item["approval_request_id"]))
			} else {
				turn.call()
			}
		case "input_file":
			return invalidRequest("file inputs are not supported")
		default:
			if err := validateTextOnlyMediaFields(item, "Only text input is supported"); err != nil {
				return err
			}
			return invalidRequest("Only text messages, client tool calls and outputs, and reasoning items are supported")
		}
		if responsesUsesAnthropicWire(state) {
			side := claudeUserItem
			switch {
			case isSystemMessage:
				side = claudeSystemItem
			case itemType == "function_call", itemType == "reasoning", role == "assistant":
				side = claudeAssistantItem
			}
			if err := validation.claudeSystems.next(state, side, path); err != nil {
				return err
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
	if responsesMCPSupported(state) {
		if err := validateResponsesMCPApprovals(raw, state.Resolution.RawTools()); err != nil {
			return err
		}
	}
	if state != nil {
		state.answeredCallIDs = turn.answered
	}
	return nil
}

func validateResponsesMessageInput(state *State, item map[string]json.RawMessage, path string, validation *responsesInputValidation) error {
	if err := rejectUnsupportedInputKeys(item, path, "type", "id", "status", "role", "phase", "content"); err != nil {
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
	// OpenAI's newer models label each message of a reply as commentary or the final answer, and a
	// client that sends the reply back keeps the label.
	if raw, ok := item["phase"]; ok {
		if phase, ok := rawStringValue(raw); !ok || role != "assistant" || phase != "commentary" && phase != "final_answer" {
			return invalidRequest(path + ".phase must be commentary or final_answer on an assistant message")
		}
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
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return false, invalidRequest(path + " must contain text")
	}
	if trimmed[0] == '"' {
		var text string
		if err := sonic.Unmarshal(raw, &text); err != nil {
			return false, invalidRequest(path + " must be text or an array of text blocks")
		}
		if !hasNonWhitespace(text) {
			return false, invalidRequest(path + " must contain non-empty text")
		}
		return true, nil
	}
	blocks, err := rawjson.Array(raw)
	if err != nil || len(blocks) == 0 {
		return false, invalidRequest(path + " must be text or a non-empty array of text blocks")
	}
	meaningful := false
	for index, blockRaw := range blocks {
		blockPath := fmt.Sprintf("%s[%d]", path, index)
		block, err := rawjson.Object(blockRaw)
		if err != nil {
			return false, invalidRequest(blockPath + " must be an object")
		}
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
			meaningful = meaningful || hasNonWhitespace(text)
		case "output_text":
			if err := rejectUnsupportedInputKeys(block, blockPath, "type", "text", "annotations", "logprobs", "cache_control", "prompt_cache_breakpoint"); err != nil {
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
			meaningful = meaningful || hasNonWhitespace(text)
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
			meaningful = meaningful || hasNonWhitespace(text)
		case "input_file", "input_image":
			if role != "user" {
				return false, invalidRequest(blockPath + " attachments require a user message")
			}
			if err := validateNativeAttachment(state, block, blockPath, true); err != nil {
				return false, err
			}
			meaningful = true
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
	allowed := []string{"type", "id", "status", "call_id", "name", "namespace"}
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
	namespace := responsesCallNamespace(item)
	maxName := maxClientToolName
	if namespace != "" {
		maxName = maxNamespacedToolName
	}
	if err := validateToolName(name, path+".name", maxName); err != nil {
		return err
	}
	// The flattened tools keep no namespace, so a call to an undeclared one would lose its own.
	if namespace != "" && responsesUsesAnthropicWire(state) && !responsesNamespaceDeclares(state, namespace, name) {
		return invalidRequest(path + ".name must name a tool in namespace " + namespace + " in tools for Anthropic-format deployments")
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

// validateResponsesLocalToolCallInput checks a replayed shell_call or apply_patch_call. Each key
// holds the type that OpenAI returns it with; OpenAI decides the rest, such as which statuses and
// operations it takes back.
func validateResponsesLocalToolCallInput(item map[string]json.RawMessage, path, itemType string, validation *responsesInputValidation) error {
	payloadKey, kind := "action", "shell"
	allowed := []string{"type", "id", "status", "call_id", "action", "environment"}
	if itemType == "apply_patch_call" {
		payloadKey, kind = "operation", "apply_patch"
		allowed = []string{"type", "id", "status", "call_id", "operation"}
	}
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
	if len(callID) > 64 {
		return invalidRequest(path + ".call_id must contain at most 64 bytes")
	}
	if _, exists := validation.calls[callID]; exists {
		return invalidRequest(path + ".call_id duplicates another client tool call")
	}
	payload, ok := rawObject(item[payloadKey])
	if !ok {
		return invalidRequest(path + "." + payloadKey + " must be an object")
	}
	payloadPath := path + "." + payloadKey
	if kind == "shell" {
		if err := rejectUnsupportedInputKeys(payload, payloadPath, "commands", "timeout_ms", "max_output_length"); err != nil {
			return err
		}
		var commands []string
		if raw, ok := payload["commands"]; !ok || sonic.Unmarshal(raw, &commands) != nil {
			return invalidRequest(payloadPath + ".commands must be an array of strings")
		}
		for _, key := range []string{"timeout_ms", "max_output_length"} {
			if raw, ok := payload[key]; ok {
				if value, ok := rawIntegerValue(raw); !ok || value < 0 {
					return invalidRequest(payloadPath + "." + key + " must be a non-negative integer")
				}
			}
		}
		// A replayed call names the environment that ran it, which is only the client's.
		if raw, ok := item["environment"]; ok {
			environment, ok := rawObject(raw)
			if !ok || rawString(environment["type"]) != "local" || len(environment) != 1 {
				return invalidRequest(path + ".environment must be {\"type\": \"local\"}")
			}
		}
	} else {
		if err := rejectUnsupportedInputKeys(payload, payloadPath, "type", "path", "diff"); err != nil {
			return err
		}
		for _, key := range []string{"type", "path"} {
			if _, err := requiredInputString(payload, key, payloadPath, false); err != nil {
				return err
			}
		}
		if raw, ok := payload["diff"]; ok {
			if _, ok := rawStringValue(raw); !ok {
				return invalidRequest(payloadPath + ".diff must be a string")
			}
		}
	}
	validation.calls[callID] = kind
	validation.pendingCalls++
	return nil
}

// validateResponsesLocalToolOutputInput checks the client's result of a shell_call or
// apply_patch_call.
func validateResponsesLocalToolOutputInput(item map[string]json.RawMessage, path, itemType string, validation *responsesInputValidation) error {
	kind := "shell"
	allowed := []string{"type", "id", "status", "call_id", "output", "max_output_length"}
	if itemType == "apply_patch_call_output" {
		kind = "apply_patch"
		allowed = []string{"type", "id", "status", "call_id", "output"}
	}
	if err := rejectUnsupportedInputKeys(item, path, allowed...); err != nil {
		return err
	}
	if raw, ok := item["id"]; ok {
		if _, err := requiredInputString(map[string]json.RawMessage{"id": raw}, "id", path, false); err != nil {
			return err
		}
	}
	if raw, ok := item["status"]; ok {
		if _, ok := rawStringValue(raw); !ok {
			return invalidRequest(path + ".status must be a string")
		}
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
	if kind == "apply_patch" {
		if raw, ok := item["output"]; ok {
			if _, ok := rawStringValue(raw); !ok {
				return invalidRequest(path + ".output must be a string")
			}
		}
	} else {
		var outputs []map[string]json.RawMessage
		if raw, ok := item["output"]; !ok || sonic.Unmarshal(raw, &outputs) != nil {
			return invalidRequest(path + ".output must be an array of objects")
		}
		for index, output := range outputs {
			outputPath := fmt.Sprintf("%s.output[%d]", path, index)
			if err := rejectUnsupportedInputKeys(output, outputPath, "stdout", "stderr", "outcome"); err != nil {
				return err
			}
			for _, key := range []string{"stdout", "stderr"} {
				if _, err := requiredInputString(output, key, outputPath, true); err != nil {
					return err
				}
			}
			outcome, ok := rawObject(output["outcome"])
			if !ok {
				return invalidRequest(outputPath + ".outcome must be an object")
			}
			if err := rejectUnsupportedInputKeys(outcome, outputPath+".outcome", "type", "exit_code"); err != nil {
				return err
			}
			if _, err := requiredInputString(outcome, "type", outputPath+".outcome", false); err != nil {
				return err
			}
			if raw, ok := outcome["exit_code"]; ok {
				if _, ok := rawIntegerValue(raw); !ok {
					return invalidRequest(outputPath + ".outcome.exit_code must be an integer")
				}
			}
		}
		if raw, ok := item["max_output_length"]; ok {
			if value, ok := rawIntegerValue(raw); !ok || value < 0 {
				return invalidRequest(path + ".max_output_length must be a non-negative integer")
			}
		}
	}
	validation.outputs[callID] = true
	validation.pendingCalls--
	validation.meaningful = true
	return nil
}

// responsesCallNamespace reads the namespace of a call to a client tool, which the request's parse
// found to be a string. The namespace functions holds top-level tools, so it reads as none, as an
// empty one does.
func responsesCallNamespace(item map[string]json.RawMessage) string {
	namespace, _ := rawStringValue(item["namespace"])
	if namespace == providerutils.DefaultToolNamespace {
		return ""
	}
	return namespace
}

// responsesNamespaceDeclares reports whether a request declares a function tool in a namespace.
func responsesNamespaceDeclares(state *State, namespace, name string) bool {
	for _, entry := range catalog.ResponsesToolList(state.Resolution.RawTools()) {
		if entry.Namespace == namespace && rawString(entry.Tool["name"]) == name && rawString(entry.Tool["type"]) == "function" {
			return true
		}
	}
	return false
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

// validateResponsesReasoningInput checks a reasoning item that a reply returned. Its encrypted
// content holds OpenAI's encrypted reasoning or a Claude block, and without it, its content holds
// plain reasoning text. An item with neither holds nothing to continue from, such as one whose
// encrypted content a client dropped or a stored reply never had. The checks are the same on every
// deployment, and each deployment gets only the items that it takes back
// (catalog.ResolvedRequest.KeepReadableReasoning).
func validateResponsesReasoningInput(item map[string]json.RawMessage, path string) error {
	if err := rejectUnsupportedInputKeys(item, path, "type", "id", "status", "summary", "content", "encrypted_content"); err != nil {
		return err
	}
	if err := validateResponsesInputItemIdentity(item, path); err != nil {
		return err
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
	if rawJSONValueSet(item["encrypted_content"]) {
		encrypted, err := requiredInputString(item, "encrypted_content", path, false)
		if err != nil {
			return err
		}
		// A Claude block and OpenAI's bound encrypted reasoning come back as a reply returned them.
		intact := catalog.IntactEncryptedReasoning(encrypted)
		if anthropicprovider.HoldsThinkingBlock(encrypted) {
			_, intact = anthropicprovider.DecodeThinkingBlock(encrypted)
		}
		if !intact {
			return invalidRequest(path + ".encrypted_content must be sent back unchanged")
		}
		return nil
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
