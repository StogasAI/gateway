package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// A deployment that takes only Chat Completions serves Responses requests too. The gateway calls
// the provider with Chat Completions and returns the reply as Responses. The request log keeps the
// interface that the client called, and the deployment's route names the interface on which the
// gateway called the provider. A deployment that takes Responses itself gets Responses, unless the
// model field names its Chat Completions route.
//
// Chutes and Azure take part. OpenAI's only deployment without Responses is its search model,
// whose searches only Chat Completions' web_search_options prices.
var bridgedProviders = map[schemas.ModelProvider]bool{ProviderChutes: true, schemas.Azure: true}

// ResponsesRefusedFields are the fields that a Responses request can name and that every
// deployment refuses: Chat Completions' names of Responses controls, and controls that the
// gateway does not offer. The Responses checks refuse them, each with its own message.
var ResponsesRefusedFields = []string{
	"background", "container", "conversation", "fallbacks", "inference_geo", "max_completion_tokens",
	"max_tokens", "moderation", "previous_response_id", "prompt", "reasoning_effort",
	"reasoning_max_tokens", "response_format", "speed", "stop", "verbosity", "web_search_options",
}

// PlainReasoningHistory reports whether the provider's Chat Completions take earlier reasoning as
// plain text in assistant messages.
func PlainReasoningHistory(provider schemas.ModelProvider) bool {
	return provider == ProviderChutes
}

// routeBridges reports whether a route serves requests on route only through the translation.
func routeBridges(node compiledRoute, route Route) bool {
	return route == RouteResponses && bridgedProviders[schemas.ModelProvider(node.ProviderID)] &&
		!routeSupportsInterface(node, RouteResponses) && routeSupportsInterface(node, RouteChat)
}

// routeServes reports whether a route serves requests on route, itself or through the
// translation.
func routeServes(node compiledRoute, route Route) bool {
	return routeSupportsInterface(node, route) || routeBridges(node, route)
}

// bridges reports whether the deployment serves requests on route only through the translation.
func (d Deployment) bridges(route Route) bool {
	if d.snapshot == nil {
		return false
	}
	node, ok := d.snapshot.graph.Routes[d.RouteID]
	return ok && routeBridges(node, route)
}

// WireRoute is the interface on which the gateway calls the deployment for a request on route.
func (d Deployment) WireRoute(route Route) Route {
	if d.bridges(route) {
		return RouteChat
	}
	return route
}

// Bridged reports whether the request reaches its deployment through the translation.
func (r *ResolvedRequest) Bridged() bool {
	return r != nil && r.Deployment.bridges(r.Route)
}

// WireRoute is the interface on which the gateway calls the provider: Route, or Chat Completions
// for a bridged request.
func (r *ResolvedRequest) WireRoute() Route {
	if r == nil {
		return ""
	}
	return r.Deployment.WireRoute(r.Route)
}

// WireRequestType is the request type of the provider call: RequestType, or its Chat Completions
// counterpart for a bridged request.
func (r *ResolvedRequest) WireRequestType() schemas.RequestType {
	switch {
	case r == nil:
		return ""
	case !r.Bridged():
		return r.RequestType
	case r.RequestType == schemas.ResponsesStreamRequest:
		return schemas.ChatCompletionStreamRequest
	default:
		return schemas.ChatCompletionRequest
	}
}

// WireView is the request as its provider gets it. For a bridged request that TranslateToChat
// translated, it is a copy whose route, request type and body are those of Chat Completions, so
// that the checks of the provider's Chat Completions read a Chat Completions request. The copy
// shares the typed request. Any other request is its own view.
func (r *ResolvedRequest) WireView() *ResolvedRequest {
	if !r.Bridged() || r.wireBody == nil {
		return r
	}
	view := *r
	view.Route, view.RequestType = RouteChat, r.WireRequestType()
	view.pricing = requestPricingContextForRaw(RouteChat, r.wireBody)
	view.wireBody = nil
	return &view
}

// TranslateToChat gives a bridged request its Chat Completions body, made from the Responses body
// that the request's checks accepted. It leaves any other request as it is.
func (r *ResolvedRequest) TranslateToChat() error {
	if !r.Bridged() || r.wireBody != nil {
		return nil
	}
	fields, err := chatTranslator{build: true, plainReasoning: PlainReasoningHistory(r.Provider)}.translate(r.pricing.RawBody)
	if err != nil {
		return err
	}
	body, err := sonic.Marshal(fields)
	if err != nil {
		return ErrInvalidJSON
	}
	request := &openaiprovider.OpenAIChatRequest{}
	if err := request.UnmarshalJSON(body); err != nil {
		return ErrInvalidJSON
	}
	extraParams, err := filterRequestExtraParams(fields, r.Provider, r.RequestedModel, RouteChat)
	if err != nil {
		return err
	}
	request.SetExtraParams(extraParams)
	request.Model = r.Model
	request.ChatParameters.ServiceTier = upstreamServiceTier(r.Provider, r.Deployment.Upstream)
	if err := normalizeChatReasoning(request.ChatParameters.Reasoning, r.Deployment, r.outputTokenLimit); err != nil {
		return err
	}
	r.chat, r.responses, r.wireBody = request, nil, fields
	return nil
}

// takesItself reports whether a route of the deployment that the selection allows takes requests
// on route itself. The selection decides before any policy, so that a policy only removes
// deployments and never changes the interface on which the gateway calls one.
func (s *snapshot) takesItself(sel modelSelection, route Route, id string, deployment *compiledDeployment, now time.Time) bool {
	for routeID := range deployment.Routes {
		node, ok := s.graph.Routes[routeID]
		if ok && routeSupportsInterface(node, route) && servesAt(deployment, node, now) && s.selects(sel, node, id, deployment) {
			return true
		}
	}
	return false
}

// bridgedRequestValidation checks a Responses request for bridged deployments: first what the
// provider's Chat Completions cannot carry, then the reasoning controls as Chat Completions reads
// them. The first check runs once for each provider.
func bridgedRequestValidation(raw map[string]json.RawMessage) func(schemas.ModelProvider, Deployment, int) error {
	type providerCheck struct {
		refusal   error
		reasoning *schemas.ChatReasoning
	}
	checks := make(map[schemas.ModelProvider]providerCheck, len(bridgedProviders))
	return func(provider schemas.ModelProvider, deployment Deployment, outputLimit int) error {
		check, ok := checks[provider]
		if !ok {
			check.refusal = bridgeRefusalError(raw, provider)
			if check.refusal == nil {
				// The Responses checks report malformed reasoning controls.
				check.reasoning, _ = bridgedReasoning(raw)
			}
			checks[provider] = check
		}
		if check.refusal != nil || check.reasoning == nil {
			return check.refusal
		}
		reasoning := *check.reasoning
		return normalizeChatReasoning(&reasoning, deployment, outputLimit)
	}
}

// bridgeRefusal is a control of a valid Responses request that Chat Completions cannot carry.
// Routing leaves out the bridged deployments of a request with one, so that another deployment
// can serve it, and the request gets the refusal when none can.
type bridgeRefusal struct{ APIError }

func (e bridgeRefusal) Unwrap() error { return e.APIError }

func bridgeUnsupported(field string) error {
	return bridgeRefusal{APIError{
		StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Param: field,
		Message: field + " is not supported for Chat Completions deployments",
	}}
}

// bridgeUnsupportedValue refuses a value of field, which what names.
func bridgeUnsupportedValue(field, what string) error {
	return bridgeRefusal{APIError{
		StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Param: field,
		Message: field + ": " + what + " are not supported for Chat Completions deployments",
	}}
}

// bridgeRefusalError reports why the request's Responses body cannot reach the provider's bridged
// deployments, or nil. A body that its own checks refuse is left to them.
func bridgeRefusalError(raw map[string]json.RawMessage, provider schemas.ModelProvider) error {
	_, err := chatTranslator{plainReasoning: PlainReasoningHistory(provider)}.translate(raw)
	if refusal := (bridgeRefusal{}); errors.As(err, &refusal) {
		return refusal.APIError
	}
	return nil
}

// chatTranslator turns a Responses body into a Chat Completions body. A field with the same
// meaning on both keeps its name, so that the checks of the provider's Chat Completions apply as
// they do to a Chat Completions request. The translator refuses, naming the field, each control
// that Chat Completions cannot carry, rather than dropping it.
type chatTranslator struct {
	// build makes the body. Without it, the translator only looks for what it refuses, and copies
	// no message.
	build bool
	// plainReasoning marks a provider whose Chat Completions take earlier reasoning as text.
	plainReasoning bool
}

// leftToChecks handles what the request's own checks refuse on every deployment: routing leaves
// it to them, and a translation, which follows them, never meets it.
func (t chatTranslator) leftToChecks() error {
	if t.build {
		return ErrUnsupportedRequest
	}
	return nil
}

func (t chatTranslator) translate(fields map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	chat := make(map[string]json.RawMessage, len(fields))
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		value := fields[name]
		if slices.Contains(ResponsesRefusedFields, name) {
			if err := t.leftToChecks(); err != nil {
				return nil, err
			}
			continue
		}
		switch name {
		case "cache_control", "context_management", "frequency_penalty", "metadata", "model", "parallel_tool_calls",
			"presence_penalty", "prompt_cache_key", "prompt_cache_options", "prompt_cache_retention", "provider",
			"safety_identifier", "service_tier", "session_id", "store", "stream", "task_budget", "temperature",
			"top_k", "top_p", "user":
			chat[name] = value
		case "access_programs":
			// The Responses checks refuse a program for every provider but OpenAI, which takes
			// Responses, so the field selects none here.
		case "input", "instructions", "reasoning", "reasoning.effort":
			// Translated below, as they combine.
		case "max_output_tokens":
			chat["max_completion_tokens"] = value
		case "stop_sequences":
			chat["stop"] = value
		case "stream_options":
			if err := t.streamOptions(value); err != nil {
				return nil, err
			}
		case "text":
			format, err := t.responseFormat(value)
			if err != nil {
				return nil, err
			}
			if format != nil {
				chat["response_format"] = format
			}
		case "tools":
			tools, err := t.tools(value)
			if err != nil {
				return nil, err
			}
			chat["tools"] = tools
		case "tool_choice":
			choice, err := toolChoice(value)
			if err != nil {
				return nil, err
			}
			chat["tool_choice"] = choice
		default:
			return nil, bridgeUnsupported(name)
		}
	}
	reasoning, err := bridgedReasoning(fields)
	if err != nil {
		return nil, err
	}
	if reasoning != nil && t.build {
		if chat["reasoning"], err = sonic.Marshal(reasoning); err != nil {
			return nil, ErrInvalidJSON
		}
	}
	messages, err := t.messages(fields["instructions"], fields["input"])
	if err != nil {
		return nil, err
	}
	if t.build {
		if chat["messages"], err = sonic.Marshal(messages); err != nil {
			return nil, ErrInvalidJSON
		}
	}
	return chat, nil
}

// streamOptions refuses obfuscation, which Chat Completions streams lack. The gateway asks for
// usage itself.
func (t chatTranslator) streamOptions(raw json.RawMessage) error {
	options, err := rawjson.Object(raw)
	if err != nil {
		return t.leftToChecks()
	}
	for _, name := range slices.Sorted(maps.Keys(options)) {
		value := options[name]
		if name != "include_obfuscation" {
			if err := t.leftToChecks(); err != nil {
				return err
			}
			continue
		}
		var obfuscation bool
		if err := sonic.Unmarshal(value, &obfuscation); err != nil {
			if err := t.leftToChecks(); err != nil {
				return err
			}
		} else if obfuscation {
			return bridgeUnsupported("stream_options." + name)
		}
	}
	return nil
}

// bridgedReasoning is the Chat Completions reasoning control of a Responses body: its effort or
// token budget. A reasoning mode chose the deployment already. Chat Completions returns no
// summaries, so only auto or none may ask for one; the reply carries the model's reasoning text,
// as Claude's does.
func bridgedReasoning(fields map[string]json.RawMessage) (*schemas.ChatReasoning, error) {
	object, _, err := rawReasoningObject(fields["reasoning"])
	if err != nil {
		return nil, err
	}
	var reasoning schemas.ChatReasoning
	set := false
	for _, name := range slices.Sorted(maps.Keys(object)) {
		value := object[name]
		if rawJSONNull(value) {
			continue
		}
		switch name {
		case "effort":
			effort := rawStringValue(value)
			reasoning.Effort, set = &effort, true
		case "max_tokens":
			count, ok := rawInteger(value)
			if !ok {
				return nil, ErrInvalidJSON
			}
			reasoning.MaxTokens, set = &count, true
		case "summary", "generate_summary":
			if summary := rawStringValue(value); summary != "auto" && summary != "none" {
				return nil, bridgeRefusal{APIError{
					StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Param: "reasoning." + name,
					Message: "reasoning." + name + " must be auto or none for Chat Completions deployments",
				}}
			}
		case "mode":
		default:
			// The Responses checks refuse the other fields on every deployment.
			return nil, ErrInvalidJSON
		}
	}
	// The checks refuse a request that sets both efforts.
	if value, ok := fields["reasoning.effort"]; ok && reasoning.Effort == nil && !rawJSONNull(value) {
		effort := rawStringValue(value)
		reasoning.Effort, set = &effort, true
	}
	if !set {
		return nil, nil
	}
	return &reasoning, nil
}

// responseFormat is the response_format of a Responses text configuration, or nil for plain
// text.
func (t chatTranslator) responseFormat(raw json.RawMessage) (json.RawMessage, error) {
	text, err := rawjson.Object(raw)
	if err != nil {
		return nil, t.leftToChecks()
	}
	if value, ok := text["verbosity"]; ok && !rawJSONNull(value) {
		return nil, bridgeUnsupported("text.verbosity")
	}
	formatRaw, ok := text["format"]
	if !ok || rawJSONNull(formatRaw) {
		return nil, nil
	}
	format, err := rawjson.Object(formatRaw)
	if err != nil {
		return nil, t.leftToChecks()
	}
	switch rawStringValue(format["type"]) {
	case "text":
		return nil, nil
	case "json_object":
		return json.RawMessage(`{"type":"json_object"}`), nil
	case "json_schema":
		if !t.build {
			return nil, nil
		}
		schema := maps.Clone(format)
		delete(schema, "type")
		encoded, err := sonic.Marshal(map[string]any{"type": "json_schema", "json_schema": schema})
		if err != nil {
			return nil, ErrInvalidJSON
		}
		return encoded, nil
	default:
		return nil, t.leftToChecks()
	}
}

var (
	rawFunctionType = json.RawMessage(`"function"`)
	rawTextType     = json.RawMessage(`"text"`)
)

// tools turns Responses function tools into Chat Completions ones. A tool that leaves out strict
// leaves it out on Chat Completions too, so that the provider's default holds.
func (t chatTranslator) tools(raw json.RawMessage) (json.RawMessage, error) {
	items, err := rawjson.Array(raw)
	if err != nil {
		return nil, t.leftToChecks()
	}
	tools := make([]map[string]any, 0, len(items))
	for index, item := range items {
		path := "tools[" + strconv.Itoa(index) + "]"
		tool, err := rawjson.Object(item)
		if err != nil {
			return nil, t.leftToChecks()
		}
		if toolType := rawStringValue(tool["type"]); toolType != "function" {
			return nil, bridgeUnsupportedValue(path+".type", toolType+" tools")
		}
		function := make(map[string]json.RawMessage, len(tool))
		for _, name := range slices.Sorted(maps.Keys(tool)) {
			switch value := tool[name]; name {
			case "type":
			case "name", "description", "parameters", "strict":
				function[name] = value
			case "cache_control":
				if !rawJSONNull(value) {
					return nil, bridgeUnsupported(path + "." + name)
				}
			default:
				if err := t.leftToChecks(); err != nil {
					return nil, err
				}
			}
		}
		tools = append(tools, map[string]any{"type": rawFunctionType, "function": function})
	}
	if !t.build {
		return nil, nil
	}
	encoded, err := sonic.Marshal(tools)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	return encoded, nil
}

// toolChoice turns a Responses tool choice into a Chat Completions one.
func toolChoice(raw json.RawMessage) (json.RawMessage, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '"' {
		return raw, nil
	}
	choice, err := rawjson.Object(raw)
	if err != nil {
		return raw, nil
	}
	if choiceType := rawStringValue(choice["type"]); choiceType != "function" {
		return nil, bridgeUnsupportedValue("tool_choice.type", choiceType+" tool choices")
	}
	encoded, err := sonic.Marshal(map[string]any{
		"type":     rawFunctionType,
		"function": map[string]json.RawMessage{"name": choice["name"]},
	})
	if err != nil {
		return nil, ErrInvalidJSON
	}
	return encoded, nil
}

// chatMessage is a Chat Completions message whose values stay the Responses body's bytes.
type chatMessage struct {
	Role       string          `json:"role"`
	Content    any             `json:"content,omitempty"`
	Refusal    json.RawMessage `json:"refusal,omitempty"`
	Reasoning  json.RawMessage `json:"reasoning,omitempty"`
	ToolCalls  []chatToolCall  `json:"tool_calls,omitempty"`
	ToolCallID json.RawMessage `json:"tool_call_id,omitempty"`
	// turn marks an assistant message that the next items of its turn join: Chat Completions
	// holds a turn's reasoning, text and calls in one message.
	turn bool
}

// accepts reports whether the next text or reasoning of a turn joins the message. A streamed
// reply's items keep the order in which the model wrote them, which can put text after calls.
// Each joins the turn's message while its field is free, and calls always join it, so that the
// calls' results follow the message that made them.
func (m *chatMessage) accepts(reasoning bool) bool {
	if reasoning {
		return m.turn && m.Reasoning == nil
	}
	return m.turn && m.Content == nil && m.Refusal == nil
}

type chatToolCall struct {
	ID       json.RawMessage  `json:"id"`
	Type     json.RawMessage  `json:"type"`
	Function chatToolFunction `json:"function"`
}

type chatToolFunction struct {
	Name      json.RawMessage `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// messages turns instructions and input into Chat Completions messages: instructions first, as a
// system message, and developer messages as system messages, which every Chat Completions
// provider takes.
func (t chatTranslator) messages(instructions, input json.RawMessage) ([]chatMessage, error) {
	messages := make([]chatMessage, 0, 4)
	if trimmed := bytes.TrimSpace(instructions); len(trimmed) > 0 && !rawJSONNull(trimmed) && !bytes.Equal(trimmed, []byte(`""`)) {
		messages = append(messages, chatMessage{Role: "system", Content: instructions})
	}
	if trimmed := bytes.TrimSpace(input); len(trimmed) > 0 && trimmed[0] == '"' {
		return append(messages, chatMessage{Role: "user", Content: input}), nil
	}
	items, err := rawjson.Array(input)
	if err != nil {
		return nil, t.leftToChecks()
	}
	for index, raw := range items {
		path := "input[" + strconv.Itoa(index) + "]"
		item, err := rawjson.Object(raw)
		if err != nil {
			return nil, t.leftToChecks()
		}
		// The last message, which the item can join when it is the assistant's.
		var turn *chatMessage
		if last := len(messages) - 1; last >= 0 {
			turn = &messages[last]
		}
		switch itemType := rawStringValue(item["type"]); itemType {
		case "", "message":
			message, err := t.message(item, path)
			if err != nil {
				return nil, err
			}
			if message.Role == "assistant" && turn != nil && turn.accepts(false) {
				turn.Content, turn.Refusal = message.Content, message.Refusal
				continue
			}
			messages = append(messages, message)
		case "reasoning":
			reasoning, err := t.reasoning(item, path)
			if err != nil {
				return nil, err
			}
			if turn != nil && turn.accepts(true) {
				turn.Reasoning = reasoning
				continue
			}
			messages = append(messages, chatMessage{Role: "assistant", Reasoning: reasoning, turn: true})
		case "function_call":
			call := chatToolCall{ID: item["call_id"], Type: rawFunctionType, Function: chatToolFunction{Name: item["name"], Arguments: item["arguments"]}}
			if turn != nil && turn.turn {
				turn.ToolCalls = append(turn.ToolCalls, call)
				continue
			}
			messages = append(messages, chatMessage{Role: "assistant", ToolCalls: []chatToolCall{call}, turn: true})
		case "function_call_output":
			messages = append(messages, chatMessage{Role: "tool", ToolCallID: item["call_id"], Content: item["output"]})
		default:
			return nil, bridgeUnsupportedValue(path+".type", itemType+" input items")
		}
	}
	return messages, nil
}

// message turns a Responses message into a Chat Completions message.
func (t chatTranslator) message(item map[string]json.RawMessage, path string) (chatMessage, error) {
	message := chatMessage{Role: rawStringValue(item["role"])}
	switch message.Role {
	case "assistant":
		message.turn = true
	case "developer":
		message.Role = "system"
	}
	content := item["content"]
	if trimmed := bytes.TrimSpace(content); len(trimmed) > 0 && trimmed[0] == '"' {
		message.Content = content
		return message, nil
	}
	blocks, err := rawjson.Array(content)
	if err != nil {
		return chatMessage{}, t.leftToChecks()
	}
	if message.Role == "assistant" {
		return t.assistantContent(message, blocks, path+".content")
	}
	parts := make([]map[string]any, 0, len(blocks))
	for index, raw := range blocks {
		blockPath := path + ".content[" + strconv.Itoa(index) + "]"
		block, err := rawjson.Object(raw)
		if err != nil {
			return chatMessage{}, t.leftToChecks()
		}
		if err := refuseCacheMarks(block, blockPath); err != nil {
			return chatMessage{}, err
		}
		part, err := t.contentPart(block)
		if err != nil {
			return chatMessage{}, err
		}
		parts = append(parts, part)
	}
	message.Content = parts
	return message, nil
}

// refuseCacheMarks refuses explicit prompt cache marks, which no bridged provider takes.
func refuseCacheMarks(block map[string]json.RawMessage, path string) error {
	for _, name := range []string{"cache_control", "prompt_cache_breakpoint"} {
		if value, ok := block[name]; ok && !rawJSONNull(value) {
			return bridgeUnsupported(path + "." + name)
		}
	}
	return nil
}

// contentPart turns a part of a user or system message into a Chat Completions part. The
// attachment checks refuse the sources that Chat Completions lacks: image file IDs and file
// URLs.
func (t chatTranslator) contentPart(block map[string]json.RawMessage) (map[string]any, error) {
	switch rawStringValue(block["type"]) {
	case "input_text":
		return map[string]any{"type": rawTextType, "text": block["text"]}, nil
	case "input_image":
		if _, ok := block["file_id"]; ok {
			return nil, t.leftToChecks()
		}
		image := map[string]json.RawMessage{"url": block["image_url"]}
		if detail, ok := block["detail"]; ok {
			image["detail"] = detail
		}
		return map[string]any{"type": json.RawMessage(`"image_url"`), "image_url": image}, nil
	case "input_file":
		if _, ok := block["file_url"]; ok {
			return nil, t.leftToChecks()
		}
		file := make(map[string]json.RawMessage, 4)
		for _, name := range []string{"file_data", "file_id", "filename", "file_type"} {
			if value, ok := block[name]; ok {
				file[name] = value
			}
		}
		return map[string]any{"type": json.RawMessage(`"file"`), "file": file}, nil
	default:
		return nil, t.leftToChecks()
	}
}

// assistantContent gives an assistant message the text and refusal of its history. Annotations
// and log probabilities describe the earlier reply and stay out of the prompt.
func (t chatTranslator) assistantContent(message chatMessage, blocks []json.RawMessage, path string) (chatMessage, error) {
	var texts, refusals []json.RawMessage
	for index, raw := range blocks {
		blockPath := path + "[" + strconv.Itoa(index) + "]"
		block, err := rawjson.Object(raw)
		if err != nil {
			return chatMessage{}, t.leftToChecks()
		}
		if err := refuseCacheMarks(block, blockPath); err != nil {
			return chatMessage{}, err
		}
		switch rawStringValue(block["type"]) {
		case "output_text":
			texts = append(texts, block["text"])
		case "refusal":
			refusals = append(refusals, block["refusal"])
		default:
			return chatMessage{}, t.leftToChecks()
		}
	}
	if !t.build {
		return message, nil
	}
	refusal, err := joinedText(refusals)
	if err != nil {
		return chatMessage{}, err
	}
	content, err := joinedText(texts)
	if err != nil {
		return chatMessage{}, err
	}
	message.Refusal = refusal
	if content != nil {
		message.Content = content
	}
	return message, nil
}

// reasoning is the text of a reasoning item that an earlier reply returned, for a provider that
// takes earlier reasoning as text. The Responses checks accept only reasoning text from it.
func (t chatTranslator) reasoning(item map[string]json.RawMessage, path string) (json.RawMessage, error) {
	if !t.plainReasoning {
		return nil, bridgeUnsupportedValue(path+".type", "reasoning input items")
	}
	if !t.build {
		return nil, nil
	}
	blocks, err := rawjson.Array(item["content"])
	if err != nil {
		return nil, ErrUnsupportedRequest
	}
	texts := make([]json.RawMessage, 0, len(blocks))
	for _, raw := range blocks {
		block, err := rawjson.Object(raw)
		if err != nil {
			return nil, ErrUnsupportedRequest
		}
		texts = append(texts, block["text"])
	}
	return joinedText(texts)
}

// joinedText joins JSON strings into one, or is nil for none. One string keeps its bytes.
func joinedText(texts []json.RawMessage) (json.RawMessage, error) {
	switch len(texts) {
	case 0:
		return nil, nil
	case 1:
		return texts[0], nil
	}
	var joined bytes.Buffer
	for _, raw := range texts {
		var text string
		if err := sonic.Unmarshal(raw, &text); err != nil {
			return nil, ErrInvalidJSON
		}
		joined.WriteString(text)
	}
	encoded, err := sonic.Marshal(joined.String())
	if err != nil {
		return nil, ErrInvalidJSON
	}
	return encoded, nil
}
