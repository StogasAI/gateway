package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// A Messages request reaches planning, the Responses checks, policies, redaction, holds, records
// and settlement in its Responses form, which core's typed conversion makes. Core writes it back as
// each Claude hosting's Messages body. Its names are closed at every depth: messagesBody lists every
// name that the gateway carries, and a refusal names the field as Anthropic's own API does, which
// Claude Code's recovery matches before it retries without the capability. The values are checked
// in the Responses form, as on the Responses route.

// messagesKind is the JSON kind of a Messages value that the gateway reads no deeper, such as a
// tool's input_schema (messagesAny).
type messagesKind uint8

const (
	messagesAny messagesKind = iota
	messagesString
	messagesInteger
	messagesNumber
	messagesBool
	messagesStrings
)

// messagesObject lists the keys that a Messages object may hold, with what each holds: a
// messagesKind, a nested messagesObject, a messagesList, a messagesUnion or messagesContent.
type messagesObject map[string]any

type messagesList struct{ item any }

// messagesUnion is an object whose tag field, type or role, picks its shape. An object without the
// tag takes the untagged shape when the union names one.
type messagesUnion struct {
	tag      string
	shapes   map[string]messagesObject
	untagged string
}

// messagesContent is a list of the union's objects, or a string where text allows one, or a single
// object where single allows one.
type messagesContent struct {
	messagesUnion
	text, single bool
}

var (
	messagesCacheControl = messagesObject{"type": messagesString, "ttl": messagesString}
	messagesText         = messagesObject{"type": messagesString, "text": messagesString, "cache_control": messagesCacheControl}
	messagesImage        = messagesObject{"type": messagesString, "cache_control": messagesCacheControl,
		"source": messagesUnion{tag: "type", shapes: map[string]messagesObject{
			"base64": {"type": messagesString, "media_type": messagesString, "data": messagesString},
			"url":    {"type": messagesString, "url": messagesString},
		}}}
	messagesDocument = messagesObject{"type": messagesString, "title": messagesString, "cache_control": messagesCacheControl,
		"citations": messagesObject{"enabled": messagesBool},
		"source": messagesUnion{tag: "type", shapes: map[string]messagesObject{
			"base64": {"type": messagesString, "media_type": messagesString, "data": messagesString},
			"text":   {"type": messagesString, "media_type": messagesString, "data": messagesString},
			"url":    {"type": messagesString, "url": messagesString},
			"file":   {"type": messagesString, "file_id": messagesString},
		}}}
	messagesSystemContent = messagesContent{text: true, messagesUnion: messagesUnion{tag: "type",
		shapes: map[string]messagesObject{"text": messagesText}}}
	messagesBlocks = messagesContent{text: true, messagesUnion: messagesUnion{tag: "type", shapes: map[string]messagesObject{
		"text": {"type": messagesString, "text": messagesString, "cache_control": messagesCacheControl,
			"citations": messagesList{messagesUnion{tag: "type", shapes: map[string]messagesObject{
				"web_search_result_location": {"type": messagesString, "url": messagesString, "title": messagesString,
					"encrypted_index": messagesString, "cited_text": messagesString},
			}}}},
		"image":             messagesImage,
		"document":          messagesDocument,
		"thinking":          {"type": messagesString, "thinking": messagesString, "signature": messagesString},
		"redacted_thinking": {"type": messagesString, "data": messagesString},
		"tool_use": {"type": messagesString, "id": messagesString, "name": messagesString, "input": messagesAny,
			"cache_control": messagesCacheControl},
		"tool_result": {"type": messagesString, "tool_use_id": messagesString, "is_error": messagesBool,
			"cache_control": messagesCacheControl,
			"content": messagesContent{text: true, messagesUnion: messagesUnion{tag: "type", shapes: map[string]messagesObject{
				"text":           messagesText,
				"image":          messagesImage,
				"document":       messagesDocument,
				"tool_reference": {"type": messagesString, "tool_name": messagesString},
			}}}},
		"server_tool_use": {"type": messagesString, "id": messagesString, "name": messagesString, "input": messagesAny,
			"cache_control": messagesCacheControl},
		"web_search_tool_result": {"type": messagesString, "tool_use_id": messagesString, "cache_control": messagesCacheControl,
			"content": messagesContent{single: true, messagesUnion: messagesUnion{tag: "type", shapes: map[string]messagesObject{
				"web_search_result": {"type": messagesString, "url": messagesString, "title": messagesString,
					"encrypted_content": messagesString, "page_age": messagesString},
				"web_search_tool_result_error": {"type": messagesString, "error_code": messagesString},
			}}}},
		"web_fetch_tool_result": {"type": messagesString, "tool_use_id": messagesString, "cache_control": messagesCacheControl,
			"content": messagesUnion{tag: "type", shapes: map[string]messagesObject{
				"web_fetch_result": {"type": messagesString, "url": messagesString, "retrieved_at": messagesString,
					"content": messagesDocument},
				"web_fetch_tool_result_error": {"type": messagesString, "error_code": messagesString},
			}}},
	}}}
	messagesTools = messagesList{messagesUnion{tag: "type", untagged: "custom", shapes: map[string]messagesObject{
		"custom": {"type": messagesString, "name": messagesString, "description": messagesString, "input_schema": messagesAny,
			"cache_control": messagesCacheControl, "defer_loading": messagesBool, "strict": messagesBool,
			"eager_input_streaming": messagesBool},
		anthropicWebSearchTool: {"type": messagesString, "name": messagesString, "max_uses": messagesInteger,
			"allowed_domains": messagesStrings, "blocked_domains": messagesStrings, "cache_control": messagesCacheControl,
			"user_location": messagesObject{"type": messagesString, "city": messagesString, "region": messagesString,
				"country": messagesString, "timezone": messagesString}},
		anthropicWebFetchTool: {"type": messagesString, "name": messagesString, "max_uses": messagesInteger,
			"allowed_domains": messagesStrings, "blocked_domains": messagesStrings, "max_content_tokens": messagesInteger,
			"cache_control": messagesCacheControl},
		AnthropicBashToolType:       {"type": messagesString, "name": messagesString, "cache_control": messagesCacheControl},
		AnthropicTextEditorToolType: {"type": messagesString, "name": messagesString, "max_characters": messagesInteger, "cache_control": messagesCacheControl},
	}}}
	// messagesBody lists the fields of a Messages request: Anthropic's that the gateway carries,
	// those that the Responses checks refuse with their own message (container, fallbacks and
	// inference_geo), and Stogas's own, which work as on the other routes.
	messagesBody = messagesObject{
		"model": messagesString,
		"messages": messagesList{messagesUnion{tag: "role", shapes: map[string]messagesObject{
			"user":      {"role": messagesString, "content": messagesBlocks},
			"assistant": {"role": messagesString, "content": messagesBlocks},
			"system": {"role": messagesString, "content": messagesSystemContent,
				"output_config": messagesObject{"effort": messagesString}},
		}}},
		"max_tokens":     messagesInteger,
		"system":         messagesSystemContent,
		"metadata":       messagesObject{"user_id": messagesString},
		"stop_sequences": messagesStrings,
		"stream":         messagesBool,
		"temperature":    messagesNumber,
		"top_k":          messagesInteger,
		"top_p":          messagesNumber,
		"thinking":       messagesObject{"type": messagesString, "budget_tokens": messagesInteger, "display": messagesString},
		"tools":          messagesTools,
		"tool_choice":    messagesObject{"type": messagesString, "name": messagesString, "disable_parallel_tool_use": messagesBool},
		"output_config": messagesObject{"effort": messagesString, "task_budget": messagesAny,
			"format": messagesObject{"type": messagesString, "schema": messagesAny}},
		"context_management": messagesAny,
		"cache_control":      messagesCacheControl,
		"service_tier":       messagesString,
		"speed":              messagesString,
		"container":          messagesAny,
		"fallbacks":          messagesAny,
		"inference_geo":      messagesAny,
		"mcp_servers":        messagesAny,
		"policy":             messagesAny,
		"encryption_keys":    messagesAny,
		"provider":           messagesAny,
		"session_id":         messagesAny,
	}
)

const (
	anthropicWebSearchTool = "web_search_20250305"
	anthropicWebFetchTool  = "web_fetch_20250910"
)

// messagesPassedFields keep their name in the Responses form, whose checks read them.
var messagesPassedFields = []string{
	"model", "stream", "temperature", "top_p", "top_k", "stop_sequences", "context_management", "cache_control",
	"container", "fallbacks", "inference_geo", "policy", "encryption_keys", "provider", "session_id",
}

// rawJSONValueSet reports a value that names something: present and not null.
func rawJSONValueSet(raw json.RawMessage) bool {
	return len(raw) > 0 && !rawJSONNull(raw)
}

// messagesBetas lists the anthropic-beta values that the Messages route takes, true for each that
// goes on to the hostings that take it. A value that only announces a field sends nothing: core
// sends each hosting the values that the fields of a request need, and Claude Code sends its whole
// set on every request, whether or not the request holds the fields. The route takes each value
// that core sends for a field that the route takes, as Anthropic's SDKs send it with that field.
var messagesBetas = map[string]bool{
	"context-management-2025-06-27":             false,
	"compact-2026-01-12":                        false,
	"advanced-tool-use-2025-11-20":              false,
	"tool-search-tool-2025-10-19":               false,
	"fine-grained-tool-streaming-2025-05-14":    false,
	"structured-outputs-2025-11-13":             false,
	"effort-2025-11-24":                         false,
	"task-budgets-2026-03-13":                   false,
	"fast-mode-2026-02-01":                      false,
	"extended-cache-ttl-2025-04-11":             false,
	"files-api-2025-04-14":                      false,
	"thinking-display-updates-2026-08-18":       false,
	"mid-conversation-output-config-2026-07-01": false,
	"mid-conversation-tool-changes-2026-07-01":  false,
	// Thinking between tool calls on Claude older than 4.6, and the count of thinking tokens in
	// usage. Neither changes a price.
	"interleaved-thinking-2025-05-14": true,
	"thinking-token-count-2026-05-13": true,
	// Claude Code's own value, which only the Claude API takes.
	"claude-code-20250219": true,
}

// MessagesBetas reads the anthropic-beta headers of a Messages request and returns the values that
// go on to the hostings that take them. A value that the route does not take fails with the token
// that Claude Code reads, as a gateway names a rejected capability, and Claude Code sends the
// request again without the value.
func MessagesBetas(headers []string) ([]string, error) {
	var carried []string
	for _, header := range headers {
		for value := range strings.SplitSeq(header, ",") {
			value = strings.TrimSpace(value)
			carry, taken := messagesBetas[value]
			switch {
			case value == "":
			case !taken:
				return nil, APIError{StatusCode: http.StatusBadRequest, Code: "unsupported_request", Type: ErrorTypeInvalidRequest, Message: "capability_rejected: beta_header:" + value}
			case carry && !slices.Contains(carried, value):
				carried = append(carried, value)
			}
		}
	}
	return carried, nil
}

func messagesError(path, message string) error {
	if path != "" {
		message = path + ": " + message
	}
	return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: message}
}

func messagesPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// checkMessagesObject refuses a key that the shape does not list and a value of another kind, in
// Anthropic's words. A null value counts as absent, as on the other routes. Keys are checked in
// byte order, so the same body always gets the same refusal.
func checkMessagesObject(object map[string]json.RawMessage, path string, shape messagesObject) error {
	for _, key := range slices.Sorted(maps.Keys(object)) {
		raw := object[key]
		if rawJSONNull(raw) {
			continue
		}
		value, known := shape[key]
		if !known {
			return messagesError(messagesPath(path, key), "Extra inputs are not permitted")
		}
		if err := checkMessagesValue(raw, messagesPath(path, key), value); err != nil {
			return err
		}
	}
	return nil
}

func checkMessagesValue(raw json.RawMessage, path string, shape any) error {
	switch shape := shape.(type) {
	case messagesKind:
		return checkMessagesKind(raw, path, shape)
	case messagesObject:
		object, err := rawjson.Object(raw)
		if err != nil {
			return messagesError(path, "Input should be a valid dictionary")
		}
		return checkMessagesObject(object, path, shape)
	case messagesList:
		items, err := rawjson.Array(raw)
		if err != nil {
			return messagesError(path, "Input should be a valid list")
		}
		for index, item := range items {
			if err := checkMessagesValue(item, messagesPath(path, strconv.Itoa(index)), shape.item); err != nil {
				return err
			}
		}
		return nil
	case messagesUnion:
		return shape.check(raw, path)
	case messagesContent:
		switch trimmed := bytes.TrimSpace(raw); {
		case shape.text && len(trimmed) > 0 && trimmed[0] == '"':
			return checkMessagesKind(raw, path, messagesString)
		case shape.single && len(trimmed) > 0 && trimmed[0] == '{':
			return shape.check(raw, path)
		}
		items, err := rawjson.Array(raw)
		if err != nil {
			return messagesError(path, "Input should be a valid list")
		}
		for index, item := range items {
			if err := shape.check(item, messagesPath(path, strconv.Itoa(index))); err != nil {
				return err
			}
		}
		return nil
	}
	return messagesError(path, "Extra inputs are not permitted")
}

func (u messagesUnion) check(raw json.RawMessage, path string) error {
	object, err := rawjson.Object(raw)
	if err != nil {
		return messagesError(path, "Input should be a valid dictionary")
	}
	name := u.untagged
	if tag, ok := object[u.tag]; ok && !rawJSONNull(tag) {
		if err := checkMessagesKind(tag, messagesPath(path, u.tag), messagesString); err != nil {
			return err
		}
		name = rawStringValue(tag)
	}
	shape, ok := u.shapes[name]
	if !ok {
		if name == "" {
			return messagesError(path, "Unable to extract tag using discriminator '"+u.tag+"'")
		}
		expected := make([]string, 0, len(u.shapes))
		for _, tag := range slices.Sorted(maps.Keys(u.shapes)) {
			expected = append(expected, "'"+tag+"'")
		}
		return messagesError(path, fmt.Sprintf("Input tag '%s' found using '%s' does not match any of the expected tags: %s",
			name, u.tag, strings.Join(expected, ", ")))
	}
	return checkMessagesObject(object, path, shape)
}

func checkMessagesKind(raw json.RawMessage, path string, kind messagesKind) error {
	switch kind {
	case messagesString:
		var value string
		if sonic.Unmarshal(raw, &value) != nil {
			return messagesError(path, "Input should be a valid string")
		}
	case messagesInteger:
		if _, ok := rawInteger(raw); !ok {
			return messagesError(path, "Input should be a valid integer")
		}
	case messagesNumber:
		var value float64
		if sonic.Unmarshal(raw, &value) != nil {
			return messagesError(path, "Input should be a valid number")
		}
	case messagesBool:
		var value bool
		if sonic.Unmarshal(raw, &value) != nil {
			return messagesError(path, "Input should be a valid boolean")
		}
	case messagesStrings:
		var values []string
		if sonic.Unmarshal(raw, &values) != nil {
			return messagesError(path, "Input should be a valid list of strings")
		}
	}
	return nil
}

// messagesToResponses checks a Messages request and returns its Responses form, with the values
// that core's conversion keeps on its context to write the client's own thinking, effort and
// tools back into each hosting's body.
func messagesToResponses(body []byte, fields map[string]json.RawMessage) (map[string]json.RawMessage, map[any]any, error) {
	if err := checkMessagesObject(fields, "", messagesBody); err != nil {
		return nil, nil, err
	}
	for _, name := range []string{"max_tokens", "messages"} {
		if !rawJSONValueSet(fields[name]) {
			return nil, nil, messagesError(name, "Field required")
		}
	}
	if rawJSONValueSet(fields["mcp_servers"]) {
		return nil, nil, messagesError("", "Anthropic MCP connectors are not supported")
	}
	// Both run standard: Stogas serves no Priority Tier capacity.
	switch tier := fields["service_tier"]; {
	case rawJSONValueSet(tier) && rawStringValue(tier) != "auto" && rawStringValue(tier) != "standard_only":
		return nil, nil, messagesError("service_tier", "Input should be 'auto' or 'standard_only'")
	}
	speed := rawStringValue(fields["speed"])
	if rawJSONValueSet(fields["speed"]) && speed != "standard" && speed != "fast" {
		return nil, nil, messagesError("speed", "Input should be 'standard' or 'fast'")
	}
	var request anthropicprovider.AnthropicMessageRequest
	if err := sonic.Unmarshal(body, &request); err != nil {
		return nil, nil, ErrInvalidJSON
	}
	for m, message := range request.Messages {
		for b, block := range message.Content.ContentBlocks {
			path := "messages." + strconv.Itoa(m) + ".content." + strconv.Itoa(b)
			switch {
			case block.Type == anthropicprovider.AnthropicContentBlockTypeThinking && (block.Signature == nil || *block.Signature == ""):
				return nil, nil, messagesError(path+".signature", "Field required")
			case block.Type == anthropicprovider.AnthropicContentBlockTypeRedactedThinking && (block.Data == nil || *block.Data == ""):
				return nil, nil, messagesError(path+".data", "Field required")
			}
		}
	}
	// The route serves Claude alone, so core converts every request as Claude's, whatever the
	// selector names: it keeps signed thinking in the place where the client sent it.
	request.Model = "claude"
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	converted := request.ToBifrostResponsesRequest(ctx)
	responses := make(map[string]json.RawMessage, len(fields)+4)
	for _, name := range messagesPassedFields {
		if raw := fields[name]; rawJSONValueSet(raw) {
			responses[name] = raw
		}
	}
	if raw := fields["max_tokens"]; rawJSONValueSet(raw) {
		responses["max_output_tokens"] = raw
	}
	// speed chooses the tier as service_tier does on the other routes, so standard keeps a request
	// off the Fast deployment that its model names, whose price is higher.
	if speed != "" {
		responses["service_tier"] = json.RawMessage(strconv.Quote(speed))
	}
	if output, err := rawjson.Object(fields["output_config"]); err == nil && rawJSONValueSet(output["task_budget"]) {
		responses["task_budget"] = output["task_budget"]
	}
	input, err := sonic.Marshal(messagesReasoningItems(converted.Input))
	if err != nil {
		return nil, nil, err
	}
	responses["input"] = input
	put := func(name string, value any) {
		if err == nil {
			responses[name], err = sonic.Marshal(value)
		}
	}
	if params := converted.Params; params != nil {
		if params.User != nil {
			put("user", params.User)
		}
		if reasoning := params.Reasoning; reasoning != nil {
			// Core gives a thinking budget the effort of its share of max_tokens, for providers
			// that take no budget. Claude takes the budget, so the reasoning names an effort only
			// where the client sent one.
			if reasoning.MaxTokens != nil && (request.OutputConfig == nil || request.OutputConfig.Effort == nil) {
				reasoning.Effort = nil
			}
			put("reasoning", reasoning)
		}
		if params.Text != nil {
			put("text", params.Text)
		}
		if params.ToolChoice != nil {
			put("tool_choice", params.ToolChoice)
		}
		if params.ParallelToolCalls != nil {
			put("parallel_tool_calls", params.ParallelToolCalls)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if raw := fields["tools"]; rawJSONValueSet(raw) {
		if responses["tools"], err = messagesResponsesTools(raw); err != nil {
			return nil, nil, err
		}
	}
	return responses, ctx.GetUserValues(), nil
}

// messagesReasoningItems gives each thinking and redacted_thinking block its own reasoning item, the
// form of the gateway's Responses replies, which holds the block in encrypted_content. Core joins a
// run of thinking blocks into one item.
func messagesReasoningItems(converted []schemas.ResponsesMessage) []schemas.ResponsesMessage {
	items := make([]schemas.ResponsesMessage, 0, len(converted))
	add := func(block anthropicprovider.AnthropicContentBlock) {
		encoded, _ := anthropicprovider.EncodeThinkingBlock(block)
		items = append(items, schemas.ResponsesMessage{
			Type:               schemas.Ptr(schemas.ResponsesMessageTypeReasoning),
			ResponsesReasoning: &schemas.ResponsesReasoning{Summary: []schemas.ResponsesReasoningSummary{}, EncryptedContent: &encoded},
		})
	}
	for _, item := range converted {
		if item.Type == nil || *item.Type != schemas.ResponsesMessageTypeReasoning {
			items = append(items, item)
			continue
		}
		if item.Content != nil {
			for _, block := range item.Content.ContentBlocks {
				if block.Type == schemas.ResponsesOutputMessageContentTypeReasoning && block.Text != nil {
					add(anthropicprovider.AnthropicContentBlock{Type: anthropicprovider.AnthropicContentBlockTypeThinking, Thinking: block.Text, Signature: block.Signature})
				}
			}
		}
		if item.ResponsesReasoning != nil && item.ResponsesReasoning.EncryptedContent != nil {
			add(anthropicprovider.AnthropicContentBlock{Type: anthropicprovider.AnthropicContentBlockTypeRedactedThinking, Data: item.ResponsesReasoning.EncryptedContent})
		}
	}
	return items
}

// messagesResponsesTools writes each tool as a Responses request names it for Claude: a client tool
// as a function, and web search and web fetch with their domains in filters. Anthropic's bash and
// text editor tools keep their own form. A client tool leaves out eager_input_streaming, which the
// gateway sets on every client tool of a Claude request (streamToolInput).
func messagesResponsesTools(raw json.RawMessage) (json.RawMessage, error) {
	items, err := rawjson.Array(raw)
	if err != nil {
		return nil, err
	}
	tools := make([]map[string]json.RawMessage, len(items))
	for index, item := range items {
		tool, err := rawjson.Object(item)
		if err != nil {
			return nil, err
		}
		out := make(map[string]json.RawMessage, len(tool))
		for key, value := range tool {
			if rawJSONValueSet(value) {
				out[key] = value
			}
		}
		switch rawStringValue(out["type"]) {
		case "", "custom":
			out["type"] = json.RawMessage(`"function"`)
			if schema, ok := out["input_schema"]; ok {
				out["parameters"] = schema
				delete(out, "input_schema")
			}
			delete(out, "eager_input_streaming")
		case anthropicWebSearchTool, anthropicWebFetchTool:
			filters := map[string]json.RawMessage{}
			for _, key := range []string{"allowed_domains", "blocked_domains"} {
				if value, ok := out[key]; ok {
					filters[key] = value
					delete(out, key)
				}
			}
			if len(filters) > 0 {
				if out["filters"], err = sonic.Marshal(filters); err != nil {
					return nil, err
				}
			}
		}
		tools[index] = out
	}
	return sonic.Marshal(tools)
}
