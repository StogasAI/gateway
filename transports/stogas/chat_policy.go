package stogas

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	maxMetadataKeys          = 16
	maxMetadataKeyBytes      = 64
	maxMetadataValueBytes    = 512
	maxPromptCacheKeyBytes   = 256
	maxClientTools           = 128
	maxToolDescriptionBytes  = 1024
	maxPortableStopSequences = 16
	maxStopSequenceBytes     = 1024
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
	for _, name := range []string{"audio", "function_call", "functions", "container", "fallbacks", "prompt_cache_isolation_key"} {
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
	if err := validateChatResponseFormat(raw["response_format"]); err != nil {
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
	if err := validateChatMessagesTextOnly(state, raw["messages"]); err != nil {
		return err
	}
	return nil
}

type chatToolRef struct {
	kind string
	name string
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
	return validateStopSequenceValues(values, "stop", maxPortableStopSequences, "stop sequences must be non-empty strings")
}

func validateStopSequenceArray(raw json.RawMessage, path string, maxItems int) error {
	values, err := validateStringArray(raw, path, maxItems)
	if err != nil {
		return err
	}
	return validateStopSequenceValues(values, path, maxItems, path+" must contain non-empty strings")
}

func validateStopSequenceValues(values []string, path string, maxItems int, emptyMessage string) error {
	if maxItems > 0 && len(values) > maxItems {
		return invalidRequest(path + " contains too many items")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return invalidRequest(emptyMessage)
		}
		if len(value) > maxStopSequenceBytes {
			return invalidRequest(path + " values must not exceed 1024 bytes")
		}
		if strings.ContainsRune(value, '\x00') {
			return invalidRequest(path + " values must not contain NUL")
		}
		if _, duplicate := seen[value]; duplicate {
			return invalidRequest(path + " must not contain duplicate values")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateStringArray(raw json.RawMessage, path string, maxItems int) ([]string, error) {
	if !rawJSONValueSet(raw) {
		return nil, nil
	}
	var values []string
	if err := sonic.Unmarshal(raw, &values); err != nil {
		return nil, invalidRequest(path + " must be an array of strings")
	}
	if maxItems > 0 && len(values) > maxItems {
		return nil, invalidRequest(path + " contains too many items")
	}
	for _, value := range values {
		if value == "" {
			return nil, invalidRequest(path + " must contain non-empty strings")
		}
	}
	return values, nil
}

func validateChatResponseFormat(raw json.RawMessage) error {
	if !rawJSONValueSet(raw) {
		return nil
	}
	format, ok := rawObject(raw)
	if !ok {
		return invalidRequest("response_format must be an object")
	}
	formatType, ok := rawStringValue(format["type"])
	if !ok {
		return invalidRequest("response_format.type must be a string")
	}
	switch formatType {
	case "text", "json_object":
		if !onlyRawKeys(format, "type") {
			return invalidRequest("response_format type " + formatType + " supports only type")
		}
	case "json_schema":
		if !onlyRawKeys(format, "type", "json_schema") {
			return invalidRequest("response_format type json_schema requires only type and json_schema")
		}
		return validateStructuredOutputDefinition(format["json_schema"], "response_format.json_schema")
	default:
		return invalidRequest("response_format.type must be text, json_object, or json_schema")
	}
	return nil
}

func validateStructuredOutputDefinition(raw json.RawMessage, path string) error {
	definition, ok := rawObject(raw)
	if !ok {
		return invalidRequest(path + " must contain only name, description, schema, and strict")
	}
	return validateStructuredOutputDefinitionMap(definition, path)
}

func validateStructuredOutputDefinitionMap(definition map[string]json.RawMessage, path string) error {
	if !onlyRawKeysOptional(definition, "name", "description", "schema", "strict") {
		return invalidRequest(path + " must contain only name, description, schema, and strict")
	}
	name, ok := rawStringValue(definition["name"])
	if !ok || !validClientToolName(name) {
		return invalidRequest(path + ".name must contain 1 to 64 letters, digits, underscores, or hyphens")
	}
	if description, exists := definition["description"]; exists {
		if _, ok := rawStringValue(description); !ok {
			return invalidRequest(path + ".description must be a string")
		}
	}
	if _, ok := rawObject(definition["schema"]); !ok {
		return invalidRequest(path + ".schema must be an object")
	}
	if strict, exists := definition["strict"]; exists {
		if err := validateRawJSONBool(strict, path+".strict"); err != nil {
			return err
		}
	}
	return nil
}

func validateChatPrediction(raw json.RawMessage) error {
	if !rawJSONValueSet(raw) {
		return nil
	}
	prediction, ok := rawObject(raw)
	if !ok || !onlyRawKeys(prediction, "type", "content") {
		return invalidRequest("prediction must contain only type and content")
	}
	if rawString(prediction["type"]) != "content" {
		return invalidRequest("prediction.type must be content")
	}
	if _, ok := rawStringValue(prediction["content"]); ok {
		return nil
	}
	var parts []map[string]json.RawMessage
	if err := sonic.Unmarshal(prediction["content"], &parts); err != nil || len(parts) == 0 {
		return invalidRequest("prediction.content must be a string or non-empty array of text parts")
	}
	for index, part := range parts {
		path := "prediction.content[" + strconv.Itoa(index) + "]"
		if !onlyRawKeys(part, "type", "text") || rawString(part["type"]) != "text" {
			return invalidRequest(path + " must contain only type=text and text")
		}
		if _, ok := rawStringValue(part["text"]); !ok {
			return invalidRequest(path + ".text must be a string")
		}
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

func validateFalseOnlyBoolean(raw map[string]json.RawMessage, name string) error {
	valueRaw, ok := raw[name]
	if !ok {
		return nil
	}
	if strings.TrimSpace(string(valueRaw)) == "null" {
		return invalidRequest(name + " must be a boolean")
	}
	var value bool
	if err := sonic.Unmarshal(valueRaw, &value); err != nil {
		return invalidRequest(name + " must be a boolean")
	}
	if value {
		return invalidRequest(name + "=true is not supported; omit " + name + " or set it to false")
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

func onlyRawKeysOptional(object map[string]json.RawMessage, keys ...string) bool {
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range object {
		if !allowed[key] {
			return false
		}
	}
	return true
}

var (
	chatReasoningFields = map[string]bool{
		"display":    true,
		"enabled":    true,
		"effort":     true,
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
		if err := validateReasoningEnabledValue(reasoning["enabled"], "reasoning.enabled"); err != nil {
			return err
		}
		if err := validateReasoningEffortValue(reasoning["effort"], "reasoning.effort"); err != nil {
			return err
		}
		if err := validateReasoningDisplayValue(reasoning["display"], "reasoning.display"); err != nil {
			return err
		}
		if err := validateReasoningMaxTokensValue(reasoning["max_tokens"], "reasoning.max_tokens"); err != nil {
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

func validateReasoningSummaryValue(raw json.RawMessage, name string) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return invalidRequest(name + " must be a string")
	}
	return nil
}

func validateReasoningDisplayValue(raw json.RawMessage, name string) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
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

type chatMessageInputValidation struct {
	allCallIDs map[string]bool
	meaningful bool
	pending    map[string]bool
}

func validateChatMessagesTextOnly(state *State, raw json.RawMessage) error {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return invalidRequest("messages must be a non-empty array")
	}
	var rawMessages []json.RawMessage
	if err := sonic.Unmarshal(raw, &rawMessages); err != nil {
		return invalidRequest("messages must be an array")
	}
	if len(rawMessages) == 0 {
		return invalidRequest("messages must contain at least one message")
	}
	validation := chatMessageInputValidation{
		allCallIDs: make(map[string]bool),
		pending:    make(map[string]bool),
	}
	seenConversation := false
	for index, messageRaw := range rawMessages {
		var message map[string]json.RawMessage
		if err := sonic.Unmarshal(messageRaw, &message); err != nil || message == nil {
			return invalidRequest("messages must contain only objects")
		}
		path := fmt.Sprintf("messages[%d]", index)
		if err := validateTextOnlyMediaFields(message, "Only text message content is supported"); err != nil {
			return err
		}
		role, ok := rawStringValue(message["role"])
		if !ok {
			return invalidRequest(path + ".role must be a string")
		}
		if len(validation.pending) > 0 && role != string(schemas.ChatMessageRoleTool) {
			return invalidRequest(path + " must be a tool result because the preceding assistant tool calls are unresolved")
		}
		if responsesUsesAnthropicWire(state) && seenConversation &&
			(role == string(schemas.ChatMessageRoleSystem) || role == string(schemas.ChatMessageRoleDeveloper)) {
			if !anthropicWireSupportsMidConversationSystem(state) {
				return invalidRequest(path + ".role cannot be preserved after the conversation starts on this Anthropic-format deployment")
			}
			if index+1 < len(rawMessages) && chatInputRole(rawMessages[index+1]) != string(schemas.ChatMessageRoleAssistant) {
				return invalidRequest(path + ".role must be last or immediately precede an assistant message on this Anthropic-format deployment")
			}
		}
		switch schemas.ChatMessageRole(role) {
		case schemas.ChatMessageRoleSystem, schemas.ChatMessageRoleDeveloper, schemas.ChatMessageRoleUser:
			if err := rejectUnsupportedInputKeys(message, path, "role", "name", "content"); err != nil {
				return err
			}
			if err := validateOptionalChatMessageName(state, message, path); err != nil {
				return err
			}
			content, ok := message["content"]
			if !ok {
				return invalidRequest(path + ".content is required")
			}
			meaningful, err := validateChatMessageTextContent(content, path+".content", true)
			if err != nil {
				return err
			}
			validation.meaningful = validation.meaningful || meaningful
		case schemas.ChatMessageRoleAssistant:
			if err := validateChatAssistantInput(state, message, path, &validation); err != nil {
				return err
			}
			if responsesUsesAnthropicWire(state) && index == len(rawMessages)-1 {
				if err := rejectTrailingAssistantWhitespace(message["content"], path+".content"); err != nil {
					return err
				}
			}
		case schemas.ChatMessageRoleTool:
			if err := validateChatToolResultInput(state, message, path, &validation); err != nil {
				return err
			}
		default:
			return invalidRequest(path + ".role is not supported")
		}
		if role != string(schemas.ChatMessageRoleSystem) && role != string(schemas.ChatMessageRoleDeveloper) {
			seenConversation = true
		}
	}
	if len(validation.pending) > 0 {
		return invalidRequest("assistant tool calls require one matching tool result each in the same stateless request")
	}
	if !validation.meaningful {
		return invalidRequest("messages must contain non-empty text or a tool result")
	}
	return nil
}

func rejectTrailingAssistantWhitespace(raw json.RawMessage, path string) error {
	if !rawJSONValueSet(raw) {
		return nil
	}
	if text, ok := rawStringValue(raw); ok {
		if strings.TrimRight(text, " \n\r\t") != text {
			return invalidRequest(path + " must not end in whitespace on an Anthropic assistant prefill")
		}
		return nil
	}
	var blocks []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &blocks); err != nil {
		return nil
	}
	for index := len(blocks) - 1; index >= 0; index-- {
		if !stringInSet(rawString(blocks[index]["type"]), "text", "output_text") {
			continue
		}
		text, ok := rawStringValue(blocks[index]["text"])
		if ok && strings.TrimRight(text, " \n\r\t") != text {
			return invalidRequest(path + " must not end in whitespace on an Anthropic assistant prefill")
		}
		return nil
	}
	return nil
}

func validateChatAssistantInput(state *State, message map[string]json.RawMessage, path string, validation *chatMessageInputValidation) error {
	if err := rejectUnsupportedInputKeys(message, path, "role", "name", "content", "refusal", "reasoning", "reasoning_content", "reasoning_details", "annotations", "tool_calls"); err != nil {
		return err
	}
	if err := validateOptionalChatMessageName(state, message, path); err != nil {
		return err
	}
	hasPayload := false
	if content, ok := message["content"]; ok && strings.TrimSpace(string(content)) != "null" {
		meaningful, err := validateChatMessageTextContent(content, path+".content", false)
		if err != nil {
			return err
		}
		hasPayload = meaningful
		validation.meaningful = validation.meaningful || meaningful
	}
	if refusal, ok := message["refusal"]; ok {
		if responsesUsesAnthropicWire(state) {
			return invalidRequest(path + ".refusal is not supported for Anthropic-format history")
		}
		value, ok := rawStringValue(refusal)
		if !ok {
			return invalidRequest(path + ".refusal must be a string")
		}
		meaningful := strings.TrimSpace(value) != ""
		hasPayload = hasPayload || meaningful
		validation.meaningful = validation.meaningful || meaningful
	}
	reasoningSet := false
	reasoningValue := ""
	if reasoning, ok := message["reasoning"]; ok {
		value, ok := rawStringValue(reasoning)
		if !ok {
			return invalidRequest(path + ".reasoning must be a string")
		}
		reasoningValue = value
		reasoningSet = strings.TrimSpace(value) != ""
		hasPayload = hasPayload || reasoningSet
	}
	if _, ok := message["reasoning_content"]; ok {
		return invalidRequest(path + ".reasoning_content is not supported; use reasoning")
	}
	reasoningDetailsSet := false
	if details, ok := message["reasoning_details"]; ok {
		if !chatReasoningDetailsInputSupported(state) {
			return invalidRequest("reasoning_details history is supported only for Anthropic-format deployments")
		}
		if err := validateChatReasoningDetails(details, path+".reasoning_details"); err != nil {
			return err
		}
		if reasoningSet && !chatReasoningMatchesDetails(reasoningValue, details) {
			return invalidRequest(path + ".reasoning must match the visible text in reasoning_details")
		}
		reasoningDetailsSet = true
		hasPayload = true
	}
	if reasoningSet && !reasoningDetailsSet && !chatPlainReasoningInputSupported(state) {
		return invalidRequest(path + ".reasoning requires signed reasoning_details for the selected deployment")
	}
	if annotations, ok := message["annotations"]; ok {
		if !chatAnnotationsInputSupported(state) {
			return invalidRequest("assistant annotations are supported only for OpenAI-format deployments")
		}
		if err := validateChatAnnotations(annotations, path+".annotations"); err != nil {
			return err
		}
		hasPayload = true
	}
	if calls, ok := message["tool_calls"]; ok {
		if err := validateChatToolCalls(state, calls, path+".tool_calls", validation); err != nil {
			return err
		}
		hasPayload = true
	}
	if !hasPayload {
		return invalidRequest(path + " must contain content, refusal, reasoning history, annotations, or tool calls")
	}
	return nil
}

func validateChatToolResultInput(state *State, message map[string]json.RawMessage, path string, validation *chatMessageInputValidation) error {
	if err := rejectUnsupportedInputKeys(message, path, "role", "name", "content", "tool_call_id"); err != nil {
		return err
	}
	if err := validateOptionalChatMessageName(state, message, path); err != nil {
		return err
	}
	callID, err := requiredInputString(message, "tool_call_id", path, false)
	if err != nil {
		return err
	}
	if !validation.pending[callID] {
		return invalidRequest(path + ".tool_call_id must match an unresolved preceding assistant tool call")
	}
	content, ok := message["content"]
	if !ok {
		return invalidRequest(path + ".content is required")
	}
	if _, err := validateChatMessageTextContent(content, path+".content", false); err != nil {
		return err
	}
	delete(validation.pending, callID)
	validation.meaningful = true
	return nil
}

func validateChatToolCalls(state *State, raw json.RawMessage, path string, validation *chatMessageInputValidation) error {
	var calls []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &calls); err != nil || len(calls) == 0 {
		return invalidRequest(path + " must be a non-empty array")
	}
	for index, call := range calls {
		callPath := fmt.Sprintf("%s[%d]", path, index)
		if err := rejectUnsupportedInputKeys(call, callPath, "type", "id", "function"); err != nil {
			return err
		}
		if rawString(call["type"]) != "function" {
			return invalidRequest(callPath + ".type must be function")
		}
		callID, err := requiredInputString(call, "id", callPath, false)
		if err != nil {
			return err
		}
		if err := validateProviderToolCallID(state, callID, callPath+".id"); err != nil {
			return err
		}
		if validation.allCallIDs[callID] {
			return invalidRequest(callPath + ".id duplicates another assistant tool call")
		}
		var function map[string]json.RawMessage
		if err := sonic.Unmarshal(call["function"], &function); err != nil || function == nil {
			return invalidRequest(callPath + ".function must be an object")
		}
		if err := rejectUnsupportedInputKeys(function, callPath+".function", "name", "arguments"); err != nil {
			return err
		}
		name, err := requiredInputString(function, "name", callPath+".function", false)
		if err != nil {
			return err
		}
		if !validClientToolName(name) {
			return invalidRequest(callPath + ".function.name must contain 1 to 64 letters, digits, underscores, or hyphens")
		}
		arguments, err := requiredInputString(function, "arguments", callPath+".function", true)
		if err != nil {
			return err
		}
		if !catalog.ValidateJSONObjectText(arguments) {
			return invalidRequest(callPath + ".function.arguments must encode a JSON object")
		}
		validation.allCallIDs[callID] = true
		validation.pending[callID] = true
	}
	return nil
}

func chatInputRole(raw json.RawMessage) string {
	var message map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &message); err != nil || message == nil {
		return ""
	}
	return rawString(message["role"])
}

func validateProviderToolCallID(state *State, value string, path string) error {
	if len(value) > 64 {
		return invalidRequest(path + " must contain at most 64 bytes")
	}
	if !responsesUsesAnthropicWire(state) {
		return nil
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return invalidRequest(path + " must contain only letters, digits, underscores, or hyphens for Anthropic-format deployments")
	}
	return nil
}

func validateChatMessageTextContent(raw json.RawMessage, path string, requireNonEmpty bool) (bool, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		if requireNonEmpty {
			return false, invalidRequest(path + " must contain non-empty text")
		}
		return false, nil
	}
	if trimmed[0] == '"' {
		var content string
		if err := sonic.Unmarshal(raw, &content); err != nil {
			return false, invalidRequest(path + " must be text or an array of text blocks")
		}
		meaningful := strings.TrimSpace(content) != ""
		if requireNonEmpty && !meaningful {
			return false, invalidRequest(path + " must contain non-empty text")
		}
		return meaningful, nil
	}
	var blocks []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &blocks); err != nil || len(blocks) == 0 {
		return false, invalidRequest(path + " must be text or a non-empty array of text blocks")
	}
	meaningful := false
	for index, block := range blocks {
		blockPath := fmt.Sprintf("%s[%d]", path, index)
		if err := validateTextOnlyMediaFields(block, "Only text message content is supported"); err != nil {
			return false, err
		}
		if err := rejectUnsupportedInputKeys(block, blockPath, "type", "text", "cache_control", "prompt_cache_breakpoint"); err != nil {
			return false, err
		}
		if rawString(block["type"]) != "text" {
			return false, invalidRequest("Only text message content is supported")
		}
		text, ok := rawStringValue(block["text"])
		if !ok {
			return false, invalidRequest(blockPath + ".text must be a string")
		}
		meaningful = meaningful || strings.TrimSpace(text) != ""
	}
	if requireNonEmpty && !meaningful {
		return false, invalidRequest(path + " must contain non-empty text")
	}
	return meaningful, nil
}

func validateChatReasoningDetails(raw json.RawMessage, path string) error {
	var details []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &details); err != nil || len(details) == 0 {
		return invalidRequest(path + " must be a non-empty array")
	}
	for index, detail := range details {
		detailPath := fmt.Sprintf("%s[%d]", path, index)
		value, exists, err := rawInteger(detail["index"], detailPath+".index")
		if err != nil || !exists {
			return invalidRequest(detailPath + ".index must be an integer")
		}
		if value != index {
			return invalidRequest(detailPath + ".index must match its array position")
		}
		switch rawString(detail["type"]) {
		case string(schemas.BifrostReasoningDetailsTypeText):
			if err := rejectUnsupportedInputKeys(detail, detailPath, "id", "index", "type", "text", "signature"); err != nil {
				return err
			}
			if _, err := requiredInputString(detail, "text", detailPath, true); err != nil {
				return err
			}
			if _, err := requiredInputString(detail, "signature", detailPath, false); err != nil {
				return err
			}
		case string(schemas.BifrostReasoningDetailsTypeEncrypted):
			if err := rejectUnsupportedInputKeys(detail, detailPath, "id", "index", "type", "data"); err != nil {
				return err
			}
			if _, err := requiredInputString(detail, "data", detailPath, false); err != nil {
				return err
			}
		default:
			return invalidRequest(detailPath + ".type is not supported for Anthropic history replay")
		}
		if id, ok := detail["id"]; ok {
			if _, ok := rawStringValue(id); !ok {
				return invalidRequest(detailPath + ".id must be a string")
			}
		}
	}
	return nil
}

func chatReasoningMatchesDetails(reasoning string, raw json.RawMessage) bool {
	var details []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &details); err != nil {
		return false
	}
	visible := make([]string, 0, len(details))
	for _, detail := range details {
		if rawString(detail["type"]) == string(schemas.BifrostReasoningDetailsTypeText) {
			visible = append(visible, rawString(detail["text"]))
		}
	}
	joined := strings.Join(visible, "\n")
	return reasoning == joined || (len(visible) > 0 && reasoning == joined+"\n")
}

func validateChatAnnotations(raw json.RawMessage, path string) error {
	var annotations []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &annotations); err != nil || len(annotations) == 0 {
		return invalidRequest(path + " must be a non-empty array")
	}
	for index, annotation := range annotations {
		annotationPath := fmt.Sprintf("%s[%d]", path, index)
		if err := rejectUnsupportedInputKeys(annotation, annotationPath, "type", "url_citation"); err != nil {
			return err
		}
		if rawString(annotation["type"]) != "url_citation" {
			return invalidRequest(annotationPath + ".type must be url_citation")
		}
		var citation map[string]json.RawMessage
		if err := sonic.Unmarshal(annotation["url_citation"], &citation); err != nil || citation == nil {
			return invalidRequest(annotationPath + ".url_citation must be an object")
		}
		if err := rejectUnsupportedInputKeys(citation, annotationPath+".url_citation", "start_index", "end_index", "title", "url"); err != nil {
			return err
		}
		start, startExists, startErr := rawInteger(citation["start_index"], annotationPath+".url_citation.start_index")
		if startErr != nil || !startExists || start < 0 {
			return invalidRequest(annotationPath + ".url_citation.start_index must be a non-negative integer")
		}
		end, endExists, endErr := rawInteger(citation["end_index"], annotationPath+".url_citation.end_index")
		if endErr != nil || !endExists || end < start {
			return invalidRequest(annotationPath + ".url_citation.end_index must be an integer at or after start_index")
		}
		for _, key := range []string{"title", "url"} {
			if _, err := requiredInputString(citation, key, annotationPath+".url_citation", true); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateOptionalChatMessageName(state *State, message map[string]json.RawMessage, path string) error {
	if _, ok := message["name"]; !ok {
		return nil
	}
	if responsesUsesAnthropicWire(state) {
		return invalidRequest(path + ".name is not supported for Anthropic-format history")
	}
	_, err := requiredInputString(message, "name", path, false)
	return err
}

func chatReasoningDetailsInputSupported(state *State) bool {
	return state != nil && state.Resolution != nil &&
		(state.Resolution.Provider == schemas.Anthropic ||
			(state.Resolution.Provider == schemas.Azure && azureDeploymentUsesAnthropicWire(state)))
}

func chatPlainReasoningInputSupported(state *State) bool {
	return state != nil && state.Resolution != nil && state.Resolution.Provider == catalog.ProviderChutes
}

func chatAnnotationsInputSupported(state *State) bool {
	return state != nil && state.Resolution != nil &&
		(state.Resolution.Provider == schemas.OpenAI ||
			(state.Resolution.Provider == schemas.Azure && !azureDeploymentUsesAnthropicWire(state)))
}

func validateTextOnlyMediaFields(object map[string]json.RawMessage, mediaMessage string) error {
	if rawJSONValueSet(object["file_id"]) {
		return invalidRequest("file_id inputs are not supported")
	}
	if rawJSONValueSet(object["file_url"]) {
		return invalidRequest("file_url inputs are not supported")
	}
	if rawJSONValueSet(object["file_data"]) {
		return invalidRequest("file inputs are not supported")
	}
	for _, name := range []string{"file", "input_file"} {
		if rawJSONValueSet(object[name]) {
			return invalidRequest("file inputs are not supported")
		}
	}
	for _, name := range []string{"audio", "image", "image_url", "input_audio", "input_image"} {
		if rawJSONValueSet(object[name]) {
			return invalidRequest(mediaMessage)
		}
	}
	return nil
}

func validateChatTools(raw json.RawMessage) ([]chatToolRef, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil, nil
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &tools); err != nil {
		return nil, invalidRequest("tools must be an array")
	}
	if len(tools) > maxClientTools {
		return nil, invalidRequest("tools must contain at most 128 definitions")
	}
	refs := make([]chatToolRef, 0, len(tools))
	seenNames := make(map[string]bool, len(tools))
	for index, tool := range tools {
		path := fmt.Sprintf("tools[%d]", index)
		kind := rawString(tool["type"])
		if kind == "custom" {
			return nil, invalidRequest("custom tools are not supported for the selected Chat deployment")
		}
		switch kind {
		case "function":
			if err := rejectUnsupportedInputKeys(tool, path, "type", "function", "cache_control"); err != nil {
				return nil, err
			}
			var function map[string]json.RawMessage
			if err := sonic.Unmarshal(tool["function"], &function); err != nil || function == nil {
				return nil, invalidRequest(path + ".function must be an object")
			}
			if err := rejectUnsupportedInputKeys(function, path+".function", "name", "description", "parameters", "strict"); err != nil {
				return nil, err
			}
			name, err := requiredInputString(function, "name", path+".function", false)
			if err != nil {
				return nil, err
			}
			if !validClientToolName(name) {
				return nil, invalidRequest(path + ".function.name must contain 1 to 64 letters, digits, underscores, or hyphens")
			}
			if seenNames[name] {
				return nil, invalidRequest(path + ".function.name duplicates another tool")
			}
			if description, ok := function["description"]; ok {
				value, ok := rawStringValue(description)
				if !ok {
					return nil, invalidRequest(path + ".function.description must be a string")
				}
				if len(value) > maxToolDescriptionBytes {
					return nil, invalidRequest(path + ".function.description exceeds 1024 bytes")
				}
			}
			if parameters, ok := function["parameters"]; ok {
				var schema map[string]json.RawMessage
				if err := sonic.Unmarshal(parameters, &schema); err != nil || schema == nil {
					return nil, invalidRequest(path + ".function.parameters must be an object")
				}
			}
			if strict, ok := function["strict"]; ok {
				var value bool
				if err := sonic.Unmarshal(strict, &value); err != nil {
					return nil, invalidRequest(path + ".function.strict must be a boolean")
				}
			}
			seenNames[name] = true
			refs = append(refs, chatToolRef{kind: kind, name: name})
		default:
			return nil, invalidRequest("Only function tools are supported")
		}
	}
	return refs, nil
}

func validClientToolName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for index := 0; index < len(name); index++ {
		value := name[index]
		if (value >= 'a' && value <= 'z') ||
			(value >= 'A' && value <= 'Z') ||
			(value >= '0' && value <= '9') || value == '_' || value == '-' {
			continue
		}
		return false
	}
	return true
}

func validateChatToolChoice(raw json.RawMessage, tools []chatToolRef) error {
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
		if err := rejectUnsupportedInputKeys(object, "tool_choice", "type", "function"); err != nil {
			return err
		}
		var function map[string]json.RawMessage
		if err := sonic.Unmarshal(object["function"], &function); err != nil || function == nil {
			return invalidRequest("tool_choice.function must be an object")
		}
		if err := rejectUnsupportedInputKeys(function, "tool_choice.function", "name"); err != nil {
			return err
		}
		name, err := requiredInputString(function, "name", "tool_choice.function", false)
		if err != nil || !validClientToolName(name) {
			return invalidRequest("tool_choice must name a function tool")
		}
		if !chatToolExists(tools, kind, name) {
			return invalidRequest("tool_choice selects an unknown " + kind + " tool")
		}
		return nil
	case "custom":
		return invalidRequest("custom tool_choice is not supported for the selected Chat deployment")
	default:
		return invalidRequest("tool_choice must be auto, none, required, or a supported tool object")
	}
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
