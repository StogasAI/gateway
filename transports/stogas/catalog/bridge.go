package catalog

import (
	"encoding/json"
	"maps"
	"net/http"
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

// TranslateToChat gives a bridged request its Chat Completions body, which Bifrost converts from
// the Responses request that the request's checks accepted. It leaves any other request as it is.
func (r *ResolvedRequest) TranslateToChat() error {
	if !r.Bridged() || r.wireBody != nil {
		return nil
	}
	if r.responses == nil {
		return ErrUnsupportedRequest
	}
	responses := r.responses.ToBifrostResponsesRequest(nil)
	if err := chatCompletionsGapError(responses.ChatCompletionsGap()); err != nil {
		return err
	}
	converted := responses.ToChatRequest()
	fields, err := chatWireFields(converted, r.responses.Stream, chatReasoning(r.responses.Reasoning), r.pricing.RawBody)
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
	extraParams, err := filterRequestExtraParams(fields, r.Provider, RouteChat)
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

// chatCompletionsGapError refuses a request with a part that Chat Completions cannot carry.
func chatCompletionsGapError(gap *schemas.ConversionGap) error {
	if gap == nil {
		return nil
	}
	return APIError{
		StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Param: gap.Param,
		Message: gap.Param + ": Chat Completions deployments do not support " + gap.Feature,
	}
}

// rawChatCompletionsGap refuses a Responses body that Chat Completions cannot carry whole, so that
// routing leaves out bridged deployments for it. The Responses checks refuse a malformed body, and
// the fields that every deployment refuses, with their own messages.
func rawChatCompletionsGap(raw map[string]json.RawMessage) error {
	params := maps.Clone(raw)
	delete(params, "input")
	for _, name := range ResponsesRefusedFields {
		delete(params, name)
	}
	body, err := sonic.Marshal(params)
	if err != nil {
		return nil
	}
	var request openaiprovider.OpenAIResponsesRequest
	if sonic.Unmarshal(body, &request) != nil {
		return nil
	}
	if input, ok := raw["input"]; ok && request.Input.UnmarshalJSON(input) != nil {
		return nil
	}
	return chatCompletionsGapError(request.ToBifrostResponsesRequest(nil).ChatCompletionsGap())
}

// chatReasoning is the Chat Completions reasoning control of a Responses request: its effort and
// token budget. Its mode selected the deployment, and Chat Completions return the model's
// reasoning text whatever summary it asks for.
func chatReasoning(reasoning *schemas.ResponsesParametersReasoning) *schemas.ChatReasoning {
	if reasoning == nil || (reasoning.Effort == nil && reasoning.MaxTokens == nil) {
		return nil
	}
	return &schemas.ChatReasoning{Effort: reasoning.Effort, MaxTokens: reasoning.MaxTokens}
}

// chatWireFields are the fields of a Chat Completions request in the form in which a Chat
// Completions client sends them, so that the checks of the provider's Chat Completions read the
// translation as they read a client's body. The Responses body raw gives the fields that both
// interfaces share and that Bifrost's Responses parameters lack, with the values that the client
// sent.
func chatWireFields(converted *schemas.BifrostChatRequest, stream *bool, reasoning *schemas.ChatReasoning, raw map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	params := schemas.ChatParameters{}
	if converted.Params != nil {
		params = *converted.Params
	}
	params.Reasoning, params.ServiceTier, params.ExtraParams = reasoning, nil, nil
	// The gateway asks every Chat Completions stream for its usage, and a converted stream carries no
	// obfuscation, so only a request for obfuscation reaches the Chat Completions checks.
	if options := params.StreamOptions; options == nil || options.IncludeObfuscation == nil || !*options.IncludeObfuscation {
		params.StreamOptions = nil
	} else {
		params.StreamOptions = &schemas.ChatStreamOptions{IncludeObfuscation: options.IncludeObfuscation}
	}
	encoded, err := sonic.Marshal(&params)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	fields, err := rawjson.Object(encoded)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	messages := make([]chatWireMessage, len(converted.Input))
	for i := range converted.Input {
		messages[i] = newChatWireMessage(&converted.Input[i])
	}
	if fields["messages"], err = sonic.Marshal(messages); err != nil {
		return nil, ErrInvalidJSON
	}
	if stream != nil {
		fields["stream"] = json.RawMessage(strconv.FormatBool(*stream))
	}
	for responsesName, chatName := range chatSharedFields {
		if value, ok := raw[responsesName]; ok {
			fields[chatName] = value
		}
	}
	return fields, nil
}

// chatSharedFields maps the Responses names of the fields that a Chat Completions body takes as
// they are to their Chat Completions names: the gateway's own fields, and the model and service
// tier that the client asked for, which the typed request holds for the provider.
var chatSharedFields = map[string]string{
	"cache_control": "cache_control", "model": "model", "provider": "provider", "service_tier": "service_tier",
	"session_id": "session_id", "stop_sequences": "stop", "task_budget": "task_budget", "top_k": "top_k",
}

// chatWireMessage is a Chat Completions message in the form in which a client sends it. Bifrost's
// own form writes the reasoning under two names and adds fields that no client sends.
type chatWireMessage struct {
	Role             schemas.ChatMessageRole        `json:"role"`
	Content          *schemas.ChatMessageContent    `json:"content,omitempty"`
	Refusal          *string                        `json:"refusal,omitempty"`
	Reasoning        *string                        `json:"reasoning,omitempty"`
	ReasoningDetails []schemas.ChatReasoningDetails `json:"reasoning_details,omitempty"`
	ToolCalls        []chatWireToolCall             `json:"tool_calls,omitempty"`
	ToolCallID       *string                        `json:"tool_call_id,omitempty"`
}

type chatWireToolCall struct {
	ID           *string                                      `json:"id,omitempty"`
	Type         *string                                      `json:"type,omitempty"`
	Function     schemas.ChatAssistantMessageToolCallFunction `json:"function"`
	CacheControl *schemas.CacheControl                        `json:"cache_control,omitempty"`
}

// newChatWireMessage writes a message without the error mark of a tool's output, which Chat
// Completions lack.
func newChatWireMessage(message *schemas.ChatMessage) chatWireMessage {
	wire := chatWireMessage{Role: message.Role, Content: message.Content}
	if tool := message.ChatToolMessage; tool != nil {
		wire.ToolCallID = tool.ToolCallID
	}
	if assistant := message.ChatAssistantMessage; assistant != nil {
		wire.Refusal, wire.Reasoning, wire.ReasoningDetails = assistant.Refusal, assistant.Reasoning, assistant.ReasoningDetails
		for _, call := range assistant.ToolCalls {
			wire.ToolCalls = append(wire.ToolCalls, chatWireToolCall{ID: call.ID, Type: call.Type, Function: call.Function, CacheControl: call.CacheControl})
		}
	}
	return wire
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
