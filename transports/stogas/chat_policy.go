package stogas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bytedance/sonic"
	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

const (
	maxPromptCacheKeyBytes   = 256
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
	if _, ok := raw["messages"]; !ok {
		return invalidRequest("messages is required")
	}
	for _, name := range catalog.ChatRefusedFields {
		if _, ok := raw[name]; ok {
			return unsupportedParameterError(name)
		}
	}
	if !state.PreparedCredential.UsesBYOK() {
		if err := state.Resolution.ProviderState().ManagedRefusal(); err != nil {
			return err
		}
	}
	if err := validateJSONBool(raw, "store"); err != nil {
		return err
	}
	if err := validateJSONBool(raw, "stream"); err != nil {
		return err
	}
	if err := validateJSONBool(raw, "parallel_tool_calls"); err != nil {
		return err
	}
	if err := validatePromptCacheKey(raw["prompt_cache_key"]); err != nil {
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
	metadata, err := parseMetadata(raw["metadata"], state.MetadataHeader)
	if err != nil {
		return err
	}
	state.Metadata = metadata
	if err := validateModalities(raw["modalities"]); err != nil {
		return err
	}
	if err := validateN(raw["n"]); err != nil {
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
	switch name {
	case "fallbacks":
		return invalidRequest("Fallbacks are not supported")
	case "speed":
		return invalidRequest(`speed is not supported; use service_tier "fast"`)
	case "inference_geo":
		return invalidRequest("inference_geo is not supported; use a regional deployment ID or a routing filter")
	case "prompt":
		return invalidRequest("prompt is not supported; send the prompt text in instructions and input")
	case "moderation":
		// Dropping it as unknown would answer a request that asked to be blocked.
		return invalidRequest("moderation is not supported; no request or response is moderated")
	}
	if hint, ok := otherEndpointParameters[name]; ok {
		return invalidRequest(name + " is " + hint)
	}
	return invalidRequest(name + " is not supported")
}

// otherEndpointParameters names the controls that Chat Completions and
// Responses spell differently. Dropping them as unknown would silently lose
// an output limit, a system prompt or an output format, so each gets 400 with
// the name this endpoint uses.
var otherEndpointParameters = map[string]string{
	"instructions":          "a Responses field; use a system or developer message",
	"max_completion_tokens": "a Chat Completions field; use max_output_tokens",
	"max_output_tokens":     "a Responses field; use max_completion_tokens",
	"max_tokens":            "a Chat Completions field; use max_output_tokens",
	"reasoning_effort":      "a Chat Completions field; use reasoning.effort",
	"reasoning_max_tokens":  "a Chat Completions field; use reasoning.max_tokens",
	"response_format":       "a Chat Completions field; use text.format",
	"text":                  "a Responses field; use response_format and verbosity",
	"verbosity":             "a Chat Completions field; use text.verbosity",
	"web_search_options":    "a Chat Completions field; use a web_search tool",
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

// rawJSONEmptyArray reports an array without elements.
func rawJSONEmptyArray(raw json.RawMessage) bool {
	var elements []json.RawMessage
	return len(raw) > 0 && sonic.Unmarshal(raw, &elements) == nil && elements != nil && len(elements) == 0
}

func rawJSONValueSet(raw json.RawMessage) bool {
	return len(raw) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
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
	name, _ := rawStringValue(definition["name"])
	if err := validateToolName(name, path+".name", maxClientToolName); err != nil {
		return err
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
			return invalidRequest("stream_options." + name + " is not supported")
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

// MetadataHeader carries metadata for clients that can add headers but not body fields, such as
// coding agents, as Portkey's x-portkey-metadata and Cloudflare's cf-aig-metadata do.
const MetadataHeader = "Stogas-Request-Metadata"

// parseMetadata reads the metadata object that request records keep, from the body and the
// metadata header. A body key replaces the header's, since the body belongs to this one request.
// JSON writes a control character as six bytes, and PostgreSQL's jsonb refuses U+0000, so
// neither keys nor values may contain one.
func parseMetadata(raw json.RawMessage, header []string) (map[string]string, error) {
	if len(header) > 1 {
		return nil, invalidRequest(MetadataHeader + " must appear at most once")
	}
	var metadata map[string]any
	if len(header) == 1 {
		if err := sonic.UnmarshalString(header[0], &metadata); err != nil || metadata == nil {
			return nil, invalidRequest(MetadataHeader + " must be a JSON object")
		}
	}
	if len(raw) != 0 {
		var body map[string]any
		if err := sonic.Unmarshal(raw, &body); err != nil {
			return nil, invalidRequest("metadata must be an object")
		}
		if metadata == nil {
			metadata = body
		} else {
			maps.Copy(metadata, body)
		}
	}
	if metadata == nil && len(raw) == 0 {
		return nil, nil
	}
	if len(metadata) > billing.MaxMetadataEntries {
		if len(header) == 1 {
			return nil, invalidRequest("metadata supports at most 16 keys, counting those of " + MetadataHeader)
		}
		return nil, invalidRequest("metadata supports at most 16 keys")
	}
	parsed := make(map[string]string, len(metadata))
	for key, value := range metadata {
		if key == "" || len(key) > billing.MaxMetadataKeyBytes || !metadataText(key) {
			return nil, invalidRequest("metadata keys must be valid strings up to 64 bytes without control characters")
		}
		text, ok := value.(string)
		if !ok {
			return nil, invalidRequest("metadata values must be strings")
		}
		if len(text) > billing.MaxMetadataValueBytes || !metadataText(text) {
			return nil, invalidRequest("metadata values must be valid strings up to 512 bytes without control characters")
		}
		parsed[key] = text
	}
	return parsed, nil
}

func metadataText(text string) bool {
	return utf8.ValidString(text) && !strings.ContainsFunc(text, func(r rune) bool { return r < 0x20 })
}

// RequestSessionID reads the ID that groups a request with others in its
// organization's logs, as OpenRouter does: the body's session_id or else the
// X-Session-Id header. Codex sends its own Session-Id header, which counts
// only when nothing else names a session and its value is valid, so a change
// in Codex never fails its requests. Providers never receive the ID.
func RequestSessionID(body map[string]json.RawMessage, header http.Header) (string, error) {
	if raw, ok := body["session_id"]; ok {
		id, ok := rawStringValue(raw)
		if !ok || !validSessionID(id) {
			return "", invalidRequest("session_id must be a string up to 256 bytes without control characters")
		}
		if id != "" {
			return id, nil
		}
	}
	values := header.Values("X-Session-Id")
	if len(values) > 1 {
		return "", invalidRequest("X-Session-Id must appear at most once")
	}
	if len(values) == 1 {
		if !validSessionID(values[0]) {
			return "", invalidRequest("X-Session-Id must be up to 256 bytes without control characters")
		}
		if values[0] != "" {
			return values[0], nil
		}
	}
	if values := header.Values("Session-Id"); len(values) == 1 && validSessionID(values[0]) {
		return values[0], nil
	}
	return "", nil
}

func validSessionID(id string) bool {
	return len(id) <= billing.MaxSessionIDBytes && metadataText(id)
}

// App names the application that sent a request, as its attribution headers give it.
type App struct {
	Title string
	URL   string
}

// RequestApp reads the headers that name the application that sent a request: Stogas-App-Title
// and Stogas-App-URL, else the attribution headers that OpenRouter and Vercel's AI Gateway
// define, X-OpenRouter-Title, or the older X-Title, for its name and HTTP-Referer for its URL.
// Each value comes from the first of its headers that the request sends. Clients such as Cline
// and Roo Code send OpenRouter's headers on their own, so a missing, repeated or invalid header
// names nothing and never fails the request. The URL loses its credentials, query and fragment,
// which can hold secrets, and its final slash, so that one app has one URL. Providers never
// receive either value.
func RequestApp(header http.Header) App {
	var app App
	for _, name := range []string{"Stogas-App-Title", "X-Openrouter-Title", "X-Title"} {
		if title := strings.TrimSpace(singleHeader(header, name)); title != "" {
			if len(title) <= billing.MaxMetadataValueBytes && metadataText(title) {
				app.Title = title
			}
			break
		}
	}
	for _, name := range []string{"Stogas-App-Url", "Http-Referer"} {
		if value := strings.TrimSpace(singleHeader(header, name)); value != "" {
			app.URL = appURL(value)
			break
		}
	}
	return app
}

func singleHeader(header http.Header, name string) string {
	if values := header.Values(name); len(values) == 1 {
		return values[0]
	}
	return ""
}

func appURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || parsed.Opaque != "" {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	text := scheme + "://" + strings.ToLower(parsed.Host) + strings.TrimRight(parsed.EscapedPath(), "/")
	if len(text) > billing.MaxMetadataValueBytes || !metadataText(text) {
		return ""
	}
	return text
}

// Agent names the agent that sent a request. An empty ID names the session's main conversation,
// and an empty parent ID says that the main conversation started the agent.
type Agent struct {
	ID       string
	ParentID string
	Name     string
}

// RequestAgent reads which agent sent a request, from Stogas-Agent-Id, Stogas-Parent-Agent-Id and
// Stogas-Agent-Name, else from the headers that Claude Code, Codex and OpenCode send on a
// subagent's requests. The Stogas headers fail a request whose value is invalid, as X-Session-Id
// does. The clients' own headers name nothing when invalid, so a change in a client never fails
// its requests. An ID that equals the session's names the main conversation. Providers never
// receive the headers.
func RequestAgent(header http.Header, sessionID string) (Agent, error) {
	agent, err := stogasAgent(header)
	if err != nil {
		return Agent{}, err
	}
	if agent == (Agent{}) {
		agent = clientAgent(header)
	}
	if sessionID != "" && agent.ID == sessionID {
		agent.ID = ""
	}
	if agent.ID == "" || agent.ParentID == agent.ID || agent.ParentID == sessionID {
		agent.ParentID = ""
	}
	return agent, nil
}

func stogasAgent(header http.Header) (Agent, error) {
	var agent Agent
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"Stogas-Agent-Id", &agent.ID},
		{"Stogas-Parent-Agent-Id", &agent.ParentID},
		{"Stogas-Agent-Name", &agent.Name},
	} {
		values := header.Values(field.name)
		if len(values) > 1 {
			return Agent{}, invalidRequest(field.name + " must appear at most once")
		}
		if len(values) == 1 {
			if !validSessionID(values[0]) {
				return Agent{}, invalidRequest(field.name + " must be up to 256 bytes without control characters")
			}
			*field.value = values[0]
		}
	}
	if agent.ParentID != "" && agent.ID == "" {
		return Agent{}, invalidRequest("Stogas-Parent-Agent-Id needs Stogas-Agent-Id")
	}
	if agent.ParentID != "" && agent.ParentID == agent.ID {
		return Agent{}, invalidRequest("Stogas-Parent-Agent-Id must differ from Stogas-Agent-Id")
	}
	return agent, nil
}

// clientAgent reads the agent headers of coding clients, which name a subagent only. Claude Code
// sends its own; Codex marks a subagent with X-OpenAI-Subagent and names it by its thread; and
// OpenCode runs a subagent as a child session, which names its parent. Codex and OpenCode send
// their session headers on the main conversation's requests too, so those count only beside the
// subagent's mark. A parent that is the client's root session is the main conversation.
func clientAgent(header http.Header) Agent {
	value := func(name string) string {
		if text := singleHeader(header, name); validSessionID(text) {
			return text
		}
		return ""
	}
	if id := value("X-Claude-Code-Agent-Id"); id != "" {
		return Agent{ID: id, ParentID: value("X-Claude-Code-Parent-Agent-Id"), Name: value("X-Claude-Code-Agent-Type")}
	}
	if name := value("X-Openai-Subagent"); name != "" {
		agent := Agent{ID: value("Thread-Id"), ParentID: value("X-Codex-Parent-Thread-Id"), Name: name}
		if agent.ParentID == value("Session-Id") {
			agent.ParentID = ""
		}
		return agent
	}
	parent := value("X-Opencode-Parent-Session-Id")
	if parent == "" {
		parent = value("X-Parent-Session-Id")
	}
	if id := value("X-Opencode-Session-Id"); parent != "" && id != "" {
		return Agent{ID: id, ParentID: parent}
	}
	return Agent{}
}

// RequestTraceID reads the trace ID from the request's W3C traceparent
// header, which OpenTelemetry clients send, so a log can be found from the
// client's trace. A missing or invalid header names no trace and, as the W3C
// Trace Context specification asks, never fails the request. A repeated
// header names none either: HTTP would combine its values into one, which is
// not a valid traceparent. Providers never receive the header.
func RequestTraceID(header http.Header) string {
	values := header.Values("Traceparent")
	if len(values) != 1 {
		return ""
	}
	value := values[0]
	// Version 00 has exactly four fields. A later version starts with the
	// same four and may add more after a dash; version ff is invalid.
	if len(value) < 55 || !lowerHex(value[:2]) || value[:2] == "ff" ||
		(len(value) > 55 && (value[:2] == "00" || value[55] != '-')) {
		return ""
	}
	trace, parent, flags := value[3:35], value[36:52], value[53:55]
	if value[2] != '-' || value[35] != '-' || value[52] != '-' ||
		!lowerHex(trace) || !lowerHex(parent) || !lowerHex(flags) ||
		strings.Trim(trace, "0") == "" || strings.Trim(parent, "0") == "" {
		return ""
	}
	return trace
}

func lowerHex(text string) bool {
	return !strings.ContainsFunc(text, func(r rune) bool { return (r < '0' || r > '9') && (r < 'a' || r > 'f') })
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

// validatePromptCacheKey checks a prompt cache key on every deployment, although only the
// deployments that route by it receive it (catalog.ResolvedRequest.ToBifrost).
func validatePromptCacheKey(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return invalidRequest("prompt_cache_key must be a string")
	}
	if value == "" || len(value) > maxPromptCacheKeyBytes || strings.ContainsAny(value, "\x00\r\n") || !utf8.ValidString(value) {
		return invalidRequest("prompt_cache_key must be a non-empty string up to 256 bytes without control line breaks")
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

func rawObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, true
	}
	object, err := rawjson.Object(raw)
	return object, err == nil
}

type chatMessageInputValidation struct {
	allCallIDs map[string]bool
	meaningful bool
	pending    map[string]bool
}

// keepsLaterSystemMessages reports whether the deployment keeps a system message in place after the
// conversation starts. Anthropic documents the role on every platform that runs Claude, so the
// model alone decides, and a conversation keeps its messages on every hosting. Gemini takes system
// instructions only before the conversation.
func keepsLaterSystemMessages(state *State) bool {
	return stateUsesClaudeWire(state) &&
		anthropicprovider.DefaultSupportsMidConversationSystem(schemas.Anthropic, state.Resolution.Deployment.Upstream.Model)
}

// checksSystemPlacement reports whether the deployment has rules for where a system or developer
// message stands: Claude's and Gemini's. The other deployments take one anywhere.
func checksSystemPlacement(state *State) bool {
	return stateUsesClaudeWire(state) || stateRunsGemini(state)
}

// The side of the conversation that an input item belongs to. A server tool result, such as a web
// search with its results, belongs to the assistant's turn.
const (
	placementSystem = iota
	placementUser
	placementAssistant
	placementServerResult
)

// systemPlacement checks where a system or developer message stands after the conversation starts.
// Claude keeps one in place as it requires: right after a user message, tool results or an
// assistant turn that ends in a server tool result, and last or right before the assistant's turn.
// Consecutive system messages count as one. Anywhere else, and on Gemini anywhere after the start,
// it gets 400, because moving it or turning it into user text would change what it means.
type systemPlacement struct {
	started   bool   // a user or assistant item has come
	afterUser bool   // the last such item was on the user side or a server tool result
	pending   string // the path of a system message that waits for the assistant's turn
}

func (p *systemPlacement) next(state *State, side int, path string) error {
	deployment := "this Anthropic-format deployment"
	if stateRunsGemini(state) {
		deployment = "Gemini on Google Cloud"
	}
	if side == placementSystem {
		if !p.started {
			return nil
		}
		if !keepsLaterSystemMessages(state) {
			return invalidRequest(path + ".role cannot be preserved after the conversation starts on " + deployment)
		}
		if !p.afterUser {
			return invalidRequest(path + ".role must immediately follow a user message or tool result on " + deployment)
		}
		p.pending = path
		return nil
	}
	if p.pending != "" && side != placementAssistant && side != placementServerResult {
		return invalidRequest(p.pending + ".role must be last or immediately precede an assistant turn on " + deployment)
	}
	p.started, p.afterUser, p.pending = true, side == placementUser || side == placementServerResult, ""
	return nil
}

func validateChatMessagesTextOnly(state *State, raw json.RawMessage) error {
	if !rawJSONValueSet(raw) {
		return invalidRequest("messages must be a non-empty array")
	}
	rawMessages, err := rawjson.Array(raw)
	if err != nil {
		return invalidRequest("messages must be an array")
	}
	if len(rawMessages) == 0 {
		return invalidRequest("messages must contain at least one message")
	}
	validation := chatMessageInputValidation{
		allCallIDs: make(map[string]bool),
		pending:    make(map[string]bool),
	}
	var placement systemPlacement
	var turn inputTurn
	for index, messageRaw := range rawMessages {
		message, err := rawjson.Object(messageRaw)
		if err != nil {
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
		switch schemas.ChatMessageRole(role) {
		case schemas.ChatMessageRoleSystem, schemas.ChatMessageRoleDeveloper, schemas.ChatMessageRoleUser:
			if err := rejectUnsupportedInputKeys(message, path, "role", "name", "content"); err != nil {
				return err
			}
			if err := validateOptionalChatMessageName(message, path); err != nil {
				return err
			}
			content, ok := message["content"]
			if !ok {
				return invalidRequest(path + ".content is required")
			}
			meaningful, err := validateChatMessageContent(state, content, path+".content", true, role == string(schemas.ChatMessageRoleUser))
			if err != nil {
				return err
			}
			validation.meaningful = validation.meaningful || meaningful
			turn.message()
		case schemas.ChatMessageRoleAssistant:
			if err := validateChatAssistantInput(state, message, path, &validation); err != nil {
				return err
			}
			turn.output()
			if responsesUsesAnthropicWire(state) && index == len(rawMessages)-1 {
				if err := rejectTrailingAssistantWhitespace(message["content"], path+".content"); err != nil {
					return err
				}
			}
		case schemas.ChatMessageRoleTool:
			if err := validateChatToolResultInput(state, message, path, &validation); err != nil {
				return err
			}
			turn.result(rawString(message["tool_call_id"]))
		default:
			return invalidRequest(path + ".role is not supported")
		}
		if checksSystemPlacement(state) {
			side := placementUser
			switch schemas.ChatMessageRole(role) {
			case schemas.ChatMessageRoleSystem, schemas.ChatMessageRoleDeveloper:
				side = placementSystem
			case schemas.ChatMessageRoleAssistant:
				side = placementAssistant
			}
			if err := placement.next(state, side, path); err != nil {
				return err
			}
		}
	}
	if len(validation.pending) > 0 {
		return invalidRequest("assistant tool calls require one matching tool result each in the same stateless request")
	}
	if !validation.meaningful {
		return invalidRequest("messages must contain non-empty text or a tool result")
	}
	if state != nil {
		state.answeredCallIDs = turn.answered
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
	if err := validateOptionalChatMessageName(message, path); err != nil {
		return err
	}
	hasPayload := false
	if content, ok := message["content"]; ok && strings.TrimSpace(string(content)) != "null" {
		meaningful, err := validateChatMessageContent(state, content, path+".content", false, false)
		if err != nil {
			return err
		}
		hasPayload = meaningful
		validation.meaningful = validation.meaningful || meaningful
	}
	// A deployment without a refusal field gets an earlier refusal as the assistant's text
	// (catalog.ResolvedRequest.KeepCarriedPreferences).
	if refusal, ok := message["refusal"]; ok {
		value, ok := rawStringValue(refusal)
		if !ok {
			return invalidRequest(path + ".refusal must be a string")
		}
		meaningful := hasNonWhitespace(value)
		hasPayload = hasPayload || meaningful
		validation.meaningful = validation.meaningful || meaningful
	}
	// reasoning_content is another name for reasoning, which DeepSeek-style clients read and send.
	// A reply carries the text under both names, so a client that sends the reply back sends both.
	reasoningSet, reasoningGiven := false, false
	reasoningValue := ""
	for _, name := range []string{"reasoning", "reasoning_content"} {
		raw, ok := message[name]
		if !ok {
			continue
		}
		value, ok := rawStringValue(raw)
		if !ok {
			return invalidRequest(path + "." + name + " must be a string")
		}
		if reasoningGiven && value != reasoningValue {
			return invalidRequest(path + ".reasoning_content must equal reasoning")
		}
		reasoningValue, reasoningGiven = value, true
		reasoningSet = hasNonWhitespace(value)
		hasPayload = hasPayload || reasoningSet
	}
	// Reasoning history passes these checks on every deployment, and each deployment gets only the
	// history that it takes back (catalog.ResolvedRequest.KeepReadableHistory).
	// An empty array holds nothing, as a client's stream accumulator leaves it for a reply
	// without reasoning, and as OpenAI's replies carry their annotations.
	if details, ok := message["reasoning_details"]; ok && !rawJSONEmptyArray(details) {
		if err := validateChatReasoningDetails(details, path+".reasoning_details"); err != nil {
			return err
		}
		if reasoningSet && !chatReasoningMatchesDetails(reasoningValue, details) {
			return invalidRequest(path + ".reasoning must start with the visible text in reasoning_details")
		}
		hasPayload = true
	}
	// Only OpenAI's models take annotations back, and the others go without them.
	if annotations, ok := message["annotations"]; ok && !rawJSONEmptyArray(annotations) {
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
	if err := validateOptionalChatMessageName(message, path); err != nil {
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
	if _, err := validateChatMessageContent(state, content, path+".content", false, true); err != nil {
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
		// A reply's tool calls carry an index, which a client that sends the reply back keeps. No
		// provider gets it.
		if err := rejectUnsupportedInputKeys(call, callPath, "index", "type", "id", "function"); err != nil {
			return err
		}
		if rawString(call["type"]) != "function" {
			return invalidRequest(callPath + ".type must be function")
		}
		callID, err := requiredInputString(call, "id", callPath, false)
		if err != nil {
			return err
		}
		if err := validateProviderToolCallID(callID, callPath+".id"); err != nil {
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
		if err := validateToolName(name, callPath+".function.name", maxClientToolName); err != nil {
			return err
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

// validateProviderToolCallID bounds a tool call ID. Claude takes only letters, digits, "_" and "-",
// so it gets an ID with other characters under a hash (catalog.ResolvedRequest.KeepCarriedPreferences).
func validateProviderToolCallID(value string, path string) error {
	if len(value) > 64 {
		return invalidRequest(path + " must contain at most 64 bytes")
	}
	return nil
}

// Presence checks need only the leading whitespace scan. Trimming both ends
// needlessly scans large trailing padding; keep the standard ASCII fast path.
func hasNonWhitespace(text string) bool {
	return strings.TrimLeftFunc(strings.TrimLeft(text, " \t\n\r\v\f"), unicode.IsSpace) != ""
}

// validateChatMessageContent checks a message's content. Only a user message and a tool result
// take attachments, and the catalog says which of them each deployment reads there.
func validateChatMessageContent(state *State, raw json.RawMessage, path string, requireNonEmpty bool, attachments bool) (bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		if requireNonEmpty {
			return false, invalidRequest(path + " must contain non-empty text")
		}
		return false, nil
	}
	if trimmed[0] == '"' {
		var content string
		if err := json.Unmarshal(raw, &content); err != nil {
			return false, invalidRequest(path + " must be text or an array of text blocks")
		}
		meaningful := hasNonWhitespace(content)
		if requireNonEmpty && !meaningful {
			return false, invalidRequest(path + " must contain non-empty text")
		}
		return meaningful, nil
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
		if kind := rawString(block["type"]); kind == "file" || kind == "image_url" || kind == "input_audio" {
			if !attachments {
				return false, invalidRequest(blockPath + " attachments require a user message or a tool result")
			}
			if err := validateNativeAttachment(state, block, blockPath, false); err != nil {
				return false, err
			}
			meaningful = true
			continue
		}
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
		meaningful = meaningful || hasNonWhitespace(text)
	}
	if requireNonEmpty && !meaningful {
		return false, invalidRequest(path + " must contain non-empty text")
	}
	return meaningful, nil
}

// validateChatReasoningDetails checks the reasoning details that replies return: text, with
// Claude's signature or plain, and encrypted data, under the ID of OpenAI's reasoning item or as
// Claude's redacted thinking. It also takes the summaries, formats and missing indexes of
// OpenRouter's details, so that a conversation can move from OpenRouter. No provider reads a
// summary, an index or a format back, so the gateway leaves summaries out and never sends the other
// two.
func validateChatReasoningDetails(raw json.RawMessage, path string) error {
	var details []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &details); err != nil || len(details) == 0 {
		return invalidRequest(path + " must be a non-empty array")
	}
	for index, detail := range details {
		detailPath := fmt.Sprintf("%s[%d]", path, index)
		if format, ok := detail["format"]; ok {
			if _, ok := rawStringValue(format); !ok {
				return invalidRequest(detailPath + ".format must be a string")
			}
		}
		switch rawString(detail["type"]) {
		case string(schemas.BifrostReasoningDetailsTypeText):
			if err := rejectUnsupportedInputKeys(detail, detailPath, "id", "index", "format", "type", "text", "signature"); err != nil {
				return err
			}
			_, signed := detail["signature"]
			if signed {
				if _, err := requiredInputString(detail, "signature", detailPath, false); err != nil {
					return err
				}
			}
			// A stream gives Claude's hidden reasoning as a signature without text.
			if _, hasText := detail["text"]; hasText || !signed {
				if _, err := requiredInputString(detail, "text", detailPath, true); err != nil {
					return err
				}
			}
		case string(schemas.BifrostReasoningDetailsTypeSummary):
			if err := rejectUnsupportedInputKeys(detail, detailPath, "id", "index", "format", "type", "summary"); err != nil {
				return err
			}
			if _, err := requiredInputString(detail, "summary", detailPath, true); err != nil {
				return err
			}
		case string(schemas.BifrostReasoningDetailsTypeEncrypted):
			if err := rejectUnsupportedInputKeys(detail, detailPath, "id", "index", "format", "type", "data"); err != nil {
				return err
			}
			data, err := requiredInputString(detail, "data", detailPath, false)
			if err != nil {
				return err
			}
			if !catalog.IntactEncryptedReasoning(data) {
				return invalidRequest(detailPath + ".data must be sent back unchanged")
			}
		default:
			return invalidRequest(detailPath + ".type must be reasoning.text, reasoning.summary or reasoning.encrypted")
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
	return reasoningHoldsDetails(reasoning, visible)
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

// validateOptionalChatMessageName checks a message's name, which a deployment without a place for
// one goes without (catalog.ResolvedRequest.KeepCarriedPreferences).
func validateOptionalChatMessageName(message map[string]json.RawMessage, path string) error {
	if _, ok := message["name"]; !ok {
		return nil
	}
	_, err := requiredInputString(message, "name", path, false)
	return err
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
	refs := make([]chatToolRef, 0, len(tools))
	seenNames := make(map[string]bool, len(tools))
	for index, tool := range tools {
		path := fmt.Sprintf("tools[%d]", index)
		kind := rawString(tool["type"])
		if kind == "custom" {
			return nil, invalidRequest("custom tools are not supported in Chat Completions; use /v1/responses")
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
			if err := validateToolName(name, path+".function.name", maxClientToolName); err != nil {
				return nil, err
			}
			if seenNames[name] {
				return nil, invalidRequest(path + ".function.name duplicates another tool")
			}
			if description, ok := function["description"]; ok {
				if _, ok := rawStringValue(description); !ok {
					return nil, invalidRequest(path + ".function.description must be a string")
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

const (
	// maxClientToolName is the longest top-level tool name that every provider takes.
	maxClientToolName = 64
	// maxNamespacedToolName is the longest name that OpenAI takes for a tool in a namespace.
	maxNamespacedToolName = 128
)

// validateToolName refuses a tool name that is empty, longer than maxLength, or holds a character
// other than a letter, digit, underscore, or hyphen.
func validateToolName(name, path string, maxLength int) error {
	if !validToolName(name, maxLength) {
		return invalidRequest(fmt.Sprintf("%s must contain 1 to %d letters, digits, underscores, or hyphens", path, maxLength))
	}
	return nil
}

func validClientToolName(name string) bool {
	return validToolName(name, maxClientToolName)
}

func validToolName(name string, maxLength int) bool {
	if len(name) == 0 || len(name) > maxLength {
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
		return invalidRequest("custom tool_choice is not supported in Chat Completions; use /v1/responses")
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
