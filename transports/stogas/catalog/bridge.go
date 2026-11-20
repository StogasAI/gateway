package catalog

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// A deployment that takes only one of Chat Completions and Responses serves requests on the other
// too. The gateway calls the provider on the interface that the deployment takes and returns the
// reply on the interface that the client called. The request log keeps the client's interface, and
// the deployment's route names the interface on which the gateway called the provider. A deployment
// that takes the client's interface itself gets it, unless the model field names its route for the
// other interface or the request is a Chat Completions request with tools, summarized reasoning or
// reasoning history (chatThroughResponses).
//
// bridgedProviders names, for each interface, the providers whose deployments serve it through the
// other. Chutes, Azure, AWS and Google Cloud serve Responses through Chat Completions. OpenAI's only deployment without
// Responses is its search model, whose searches only Chat Completions' web_search_options prices.
// OpenAI and Azure serve Chat Completions through Responses, for the deployments that take only
// Responses, such as Pro, and for requests with tools, summarized reasoning or reasoning history.
var bridgedProviders = map[Route]map[schemas.ModelProvider]bool{
	RouteChat:      {schemas.OpenAI: true, schemas.Azure: true},
	RouteResponses: {ProviderChutes: true, schemas.Azure: true, ProviderAWS: true, ProviderGoogleCloud: true},
}

// bridgeWire is the interface on which a bridged deployment takes the requests on an interface.
var bridgeWire = map[Route]Route{RouteChat: RouteResponses, RouteResponses: RouteChat}

// ChatRefusedFields are the fields that a Chat Completions request can name and that every
// deployment refuses: Responses' names of Chat Completions controls, and controls that the gateway
// does not offer. The Chat Completions checks refuse them, each with its own message.
var ChatRefusedFields = []string{
	"audio", "function_call", "functions", "container", "fallbacks", "inference_geo", "instructions",
	"max_output_tokens", "moderation", "prompt_cache_isolation_key", "speed", "text",
}

// ResponsesRefusedFields are the fields that a Responses request can name and that every
// deployment refuses: Chat Completions' names of Responses controls, and controls that the
// gateway does not offer. The Responses checks refuse them, each with its own message.
var ResponsesRefusedFields = []string{
	"background", "container", "fallbacks", "inference_geo", "max_completion_tokens", "max_tokens",
	"moderation", "prompt", "reasoning_effort", "reasoning_max_tokens", "response_format", "speed",
	"stop", "verbosity", "web_search_options",
}

// chatReasoningFields are the reasoning controls of a Chat Completions body, which the reasoning
// checks normalize for each deployment before the translation reads them.
var chatReasoningFields = []string{"reasoning", "reasoning_display", "reasoning_effort", "reasoning_max_tokens"}

// routeBridges reports whether a route serves requests on route only through the translation.
func routeBridges(node compiledRoute, route Route) bool {
	wire, ok := bridgeWire[route]
	return ok && bridgedProviders[route][schemas.ModelProvider(node.ProviderID)] &&
		!routeSupportsInterface(node, route) && routeSupportsInterface(node, wire)
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
		return bridgeWire[route]
	}
	return route
}

// Bridged reports whether the request reaches its deployment through the translation.
func (r *ResolvedRequest) Bridged() bool {
	return r != nil && r.Deployment.bridges(r.Route)
}

// WireRoute is the interface on which the gateway calls the provider: Route, or the other
// interface for a bridged request.
func (r *ResolvedRequest) WireRoute() Route {
	if r == nil {
		return ""
	}
	return r.Deployment.WireRoute(r.Route)
}

// bridgeRequestTypes are the request types of the provider calls that serve bridged requests.
var bridgeRequestTypes = map[schemas.RequestType]schemas.RequestType{
	schemas.ChatCompletionRequest:       schemas.ResponsesRequest,
	schemas.ChatCompletionStreamRequest: schemas.ResponsesStreamRequest,
	schemas.ResponsesRequest:            schemas.ChatCompletionRequest,
	schemas.ResponsesStreamRequest:      schemas.ChatCompletionStreamRequest,
}

// WireRequestType is the request type of the provider call: RequestType, or its counterpart on the
// other interface for a bridged request.
func (r *ResolvedRequest) WireRequestType() schemas.RequestType {
	if r == nil {
		return ""
	}
	if wire, ok := bridgeRequestTypes[r.RequestType]; ok && r.Bridged() {
		return wire
	}
	return r.RequestType
}

// WireView is the request as its provider gets it, which the checks of the provider's request and
// reply read. For a bridged request that Translate translated, it is a copy whose route, request
// type and body are those of the interface that the provider takes. The copy shares the typed
// request. Any other request is its own view.
func (r *ResolvedRequest) WireView() *ResolvedRequest {
	if r == nil || r.wire == nil {
		return r
	}
	return r.wire
}

// ClientView is the request as its client sent it, on which the checks of a reply that Bifrost
// converted to the client's interface read the request: a copy of a translated request whose wire
// view is itself. Any other request is its own view.
func (r *ResolvedRequest) ClientView() *ResolvedRequest {
	if r == nil || r.wire == nil {
		return r
	}
	view := *r
	view.wire = nil
	return &view
}

// wireView makes the wire view of a request that Translate translated.
func (r *ResolvedRequest) wireView() *ResolvedRequest {
	view := *r
	view.Route, view.RequestType = r.WireRoute(), r.WireRequestType()
	view.pricing = requestPricingContextForRaw(view.Route, r.wireBody)
	view.wireBody, view.wire = nil, nil
	return &view
}

// Translate gives a bridged request the body of the interface that its provider takes, which
// Bifrost converts from the request that the request's checks accepted. It leaves any other
// request as it is.
func (r *ResolvedRequest) Translate() error {
	if !r.Bridged() || r.wire != nil {
		return nil
	}
	translate := r.translateToChat
	if r.Route == RouteChat {
		translate = r.translateToResponses
	}
	if err := translate(); err != nil {
		return err
	}
	r.wire = r.wireView()
	return nil
}

// translateToChat gives a Responses request the Chat Completions body of a deployment that takes
// only Chat Completions.
func (r *ResolvedRequest) translateToChat() error {
	if r.responses == nil {
		return ErrUnsupportedRequest
	}
	responses := r.responses.ToBifrostResponsesRequest(nil)
	if err := conversionGapError(responses.ChatCompletionsGap(), "Chat Completions"); err != nil {
		return err
	}
	responses, err := FlattenNamespaces(nil, responses)
	if err != nil {
		return err
	}
	r.namespaceAliases = responses.NamespaceToolAliases
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
	request.ChatParameters.ServiceTier = upstreamServiceTier(r.Provider, r.Deployment)
	if err := normalizeChatReasoning(request.ChatParameters.Reasoning, r.Deployment, r.outputTokenLimit); err != nil {
		return err
	}
	r.chat, r.responses, r.wireBody = request, nil, fields
	return nil
}

// UnwrapDefaultNamespace gives a Responses request the tools of its namespace functions as top-level
// tools, which is how OpenAI's models call them.
func UnwrapDefaultNamespace(request *schemas.BifrostResponsesRequest) (*schemas.BifrostResponsesRequest, error) {
	request, bifrostErr := providerutils.UnwrapDefaultNamespaceTools(request)
	return request, namespaceToolsError(bifrostErr)
}

// FlattenNamespaces gives a Responses request the tools of an interface without namespaces, as
// core's flattening does: each function in a namespace becomes a top-level function named
// <namespace>__<name>, or a hash and the name when that is too long for the interface, with the
// namespace's description before its own, and an input call to it takes that name. The tools of the
// namespace functions, in which OpenAI's models call top-level tools, keep their names. The request
// that comes back maps each new name to the namespace and name that a call returns with
// (NamespaceToolAliases). ctx may be nil, which gives the 64-character name limit of OpenAI's
// interfaces.
func FlattenNamespaces(ctx *schemas.BifrostContext, request *schemas.BifrostResponsesRequest) (*schemas.BifrostResponsesRequest, error) {
	request, err := UnwrapDefaultNamespace(request)
	if err != nil {
		return nil, err
	}
	request, bifrostErr := providerutils.FlattenResponsesNamespaceTools(ctx, request)
	return request, namespaceToolsError(bifrostErr)
}

func namespaceToolsError(bifrostErr *schemas.BifrostError) error {
	if bifrostErr == nil {
		return nil
	}
	message := "tools cannot be flattened"
	if bifrostErr.Error != nil {
		message = bifrostErr.Error.Message
	}
	return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Param: "tools", Message: message}
}

// NamespaceToolAliases maps each name that a bridged request's flattened namespace tools take on
// Chat Completions to the namespace and name that a call to it returns with.
func (r *ResolvedRequest) NamespaceToolAliases() map[string]schemas.NamespaceToolAlias {
	if r == nil {
		return nil
	}
	return r.namespaceAliases
}

// translateToResponses gives a Chat Completions request the Responses body of a deployment that
// serves it through Responses. The request's checks normalized its reasoning controls, and the
// deployment gives the reasoning mode.
func (r *ResolvedRequest) translateToResponses() error {
	if r.chat == nil {
		return ErrUnsupportedRequest
	}
	chat := r.chat.ToBifrostChatRequest(nil)
	if err := conversionGapError(chat.ResponsesGap(), "Responses"); err != nil {
		return err
	}
	converted := chat.ToResponsesRequest()
	textToolOutputs(converted.Input)
	params := converted.Params
	params.Reasoning = deploymentReasoning(params.Reasoning, r.Deployment)
	params.Include = r.includeEncryptedReasoning(params.Include)
	fields, err := responsesWireFields(converted, r.chat.Stream, r.pricing.RawBody)
	if err != nil {
		return err
	}
	body, err := sonic.Marshal(fields)
	if err != nil {
		return ErrInvalidJSON
	}
	request := &openaiprovider.OpenAIResponsesRequest{}
	if err := sonic.Unmarshal(body, request); err != nil {
		return ErrInvalidJSON
	}
	extraParams, err := filterRequestExtraParams(fields, r.Provider, RouteResponses)
	if err != nil {
		return err
	}
	request.SetExtraParams(extraParams)
	request.Model = r.Model
	request.ResponsesParameters.ServiceTier = upstreamServiceTier(r.Provider, r.Deployment)
	r.chat, r.responses, r.wireBody = nil, request, fields
	return nil
}

// responsesIncludeEncryptedReasoning asks a Responses reply for its reasoning's encrypted content.
const responsesIncludeEncryptedReasoning = "reasoning.encrypted_content"

// includeEncryptedReasoning returns a Responses include that asks for the encrypted reasoning that
// the deployment takes back. The gateway stores no reply, so a client continues the model's
// reasoning in a later turn only by sending that content back.
func (r *ResolvedRequest) includeEncryptedReasoning(include []string) []string {
	if !r.ReadsReasoning(EncryptedReasoning) || slices.Contains(include, responsesIncludeEncryptedReasoning) {
		return include
	}
	return append(slices.Clip(include), responsesIncludeEncryptedReasoning)
}

// textToolOutputs gives each tool output whose parts are all text as their text in order, which
// every Responses deployment takes. An output with an image or a file keeps its parts, and only a
// deployment that takes them in a tool result gets it (Capabilities.ToolResultImages and
// ToolResultDocuments).
func textToolOutputs(input []schemas.ResponsesMessage) {
	for _, item := range input {
		tool := item.ResponsesToolMessage
		if tool == nil || tool.Output == nil || tool.Output.ResponsesFunctionToolCallOutputBlocks == nil {
			continue
		}
		blocks := tool.Output.ResponsesFunctionToolCallOutputBlocks
		if slices.ContainsFunc(blocks, func(block schemas.ResponsesMessageContentBlock) bool { return block.Text == nil }) {
			continue
		}
		var text strings.Builder
		for _, block := range blocks {
			text.WriteString(*block.Text)
		}
		tool.Output.ResponsesToolCallOutputStr = schemas.Ptr(text.String())
		tool.Output.ResponsesFunctionToolCallOutputBlocks = nil
	}
}

// conversionGapError refuses a request with a part that the interface that its provider takes
// cannot carry.
func conversionGapError(gap *schemas.ConversionGap, wire string) error {
	if gap == nil {
		return nil
	}
	return APIError{
		StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Param: gap.Param,
		Message: gap.Param + ": " + wire + " deployments do not support " + gap.Feature,
	}
}

// ResponsesGap names the field of a Chat Completions request that Responses cannot carry, or
// returns "" when they carry the request whole.
func (r *ResolvedRequest) ResponsesGap() string {
	var gap APIError
	if errors.As(rawResponsesGap(r.RawBody()), &gap) {
		return gap.Param
	}
	return ""
}

// rawConversionGap refuses a body whose requirements the other interface cannot carry whole, so
// that routing leaves out bridged deployments for it. A preference that the other interface has
// no field for is no gap, since the deployment serves the request without it
// (KeepCarriedPreferences). The checks of the client's interface refuse a malformed body, and the
// fields that every deployment refuses, with their own messages.
func rawConversionGap(raw map[string]json.RawMessage, route Route) error {
	if route == RouteChat {
		return rawResponsesGap(raw)
	}
	return rawChatCompletionsGap(raw)
}

// rawChatCompletionsGap refuses a Responses body that Chat Completions cannot carry whole.
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
	withoutResponsesPreferences(&request)
	return conversionGapError(request.ToBifrostResponsesRequest(nil).ChatCompletionsGap(), "Chat Completions")
}

// rawResponsesGap refuses a Chat Completions body that Responses cannot carry whole. The reasoning
// checks normalize the reasoning controls for each deployment, so they stay out.
func rawResponsesGap(raw map[string]json.RawMessage) error {
	params := maps.Clone(raw)
	for _, name := range slices.Concat(ChatRefusedFields, chatReasoningFields) {
		delete(params, name)
	}
	body, err := sonic.Marshal(params)
	if err != nil {
		return nil
	}
	var request openaiprovider.OpenAIChatRequest
	if request.UnmarshalJSON(body) != nil {
		return nil
	}
	withoutChatPreferences(&request)
	return conversionGapError(request.ToBifrostChatRequest(nil).ResponsesGap(), "Responses")
}

// chatReasoning is the Chat Completions reasoning control of a Responses request: its effort, its
// token budget, and the display that its summary asks for, as Claude's names and OpenAI's map to
// Claude's displays. Its mode selected the deployment. Of the deployments that take Chat
// Completions alone, only Gemini has a display to choose, and the others return their reasoning
// whole whatever the display.
func chatReasoning(reasoning *schemas.ResponsesParametersReasoning) *schemas.ChatReasoning {
	if reasoning == nil {
		return nil
	}
	var display *string
	if reasoning.Summary != nil {
		switch *reasoning.Summary {
		case "auto", "concise", "detailed":
			display = schemas.Ptr("summarized")
		case "none":
			display = schemas.Ptr("omitted")
		case "updates":
			display = schemas.Ptr("updates")
		}
	}
	if reasoning.Effort == nil && reasoning.MaxTokens == nil && display == nil {
		return nil
	}
	return &schemas.ChatReasoning{Effort: reasoning.Effort, MaxTokens: reasoning.MaxTokens, Display: display}
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

// responsesWireFields are the fields of a Responses request in the form in which a Responses client
// sends them, so that the checks of the provider's Responses read the translation as they read a
// client's body. The Chat Completions body raw gives the gateway's own fields, and the model and
// service tier that the client asked for, which the typed request holds for the provider.
func responsesWireFields(converted *schemas.BifrostResponsesRequest, stream *bool, raw map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	params := *converted.Params
	params.ServiceTier, params.ExtraParams = nil, nil
	encoded, err := sonic.Marshal(&params)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	fields, err := rawjson.Object(encoded)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	if fields["input"], err = sonic.Marshal(converted.Input); err != nil {
		return nil, ErrInvalidJSON
	}
	if stream != nil {
		fields["stream"] = json.RawMessage(strconv.FormatBool(*stream))
	}
	for _, name := range []string{"model", "provider", "service_tier", "session_id"} {
		if value, ok := raw[name]; ok {
			fields[name] = value
		}
	}
	return fields, nil
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

// servedElsewhere reports whether another route of the deployment that the selection allows
// serves the request instead of the one that routing visits, which bridges the interface or takes
// it itself. A deployment serves a request on a route that takes its interface itself, unless the
// request is one that the deployment serves through Responses (chatThroughResponses). The selection
// decides before any policy, so that a policy only removes deployments and never changes the
// interface on which the gateway calls one.
func (s *snapshot) servedElsewhere(sel modelSelection, route Route, bridging bool, id string, deployment *compiledDeployment, throughResponses func() bool, now time.Time) bool {
	other := false
	for routeID := range deployment.Routes {
		node, ok := s.graph.Routes[routeID]
		if ok && routeBridges(node, route) != bridging && (routeBridges(node, route) || routeSupportsInterface(node, route)) &&
			servesAt(deployment, node, now) && s.selects(sel, node, id, deployment) {
			other = true
			break
		}
	}
	if !other {
		return false
	}
	translated := route == RouteChat && throughResponses != nil && throughResponses()
	return bridging != translated
}

// chatThroughResponses reports whether the OpenAI and Azure deployments that take both interfaces
// serve a Chat Completions request through Responses: one that declares tools or asks for
// summarized reasoning while the model reasons, or that carries OpenAI's encrypted reasoning, when
// Responses carry it whole. OpenAI's Chat Completions refuse function tools while the newest models
// reason, and only Responses return reasoning summaries and the encrypted reasoning that a tool turn
// needs back, and take the latter back. A request that turns reasoning off has no reasoning to
// summarize, and Chat Completions serve its tools as the client sent them. A request that Responses
// cannot carry whole keeps Chat Completions, and its provider decides.
func chatThroughResponses(raw map[string]json.RawMessage, gap func() error) bool {
	reasoning, err := chatRawReasoning(raw)
	if err != nil {
		reasoning = nil
	}
	off := reasoning != nil && (reasoning.Effort != nil && *reasoning.Effort == "none" || reasoning.Enabled != nil && !*reasoning.Enabled)
	summarized := reasoning != nil && reasoning.Display != nil && *reasoning.Display == "summarized"
	tools := len(raw["tools"]) > 0 && !rawJSONNullOrEmptyArray(raw["tools"])
	return (!off && (tools || summarized) || chatEncryptedReasoningHistory(raw["messages"])) && gap() == nil
}
