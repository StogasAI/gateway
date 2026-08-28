package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

const (
	ErrorTypeInvalidRequest = "invalid_request_error"
	ErrorTypeInternal       = "internal_error"
	maxProviderRoutingItems = 32
	maxProviderNameBytes    = 64
)

var (
	ErrCatalogUnavailable     = APIError{StatusCode: http.StatusInternalServerError, Type: ErrorTypeInternal, Message: "Catalog unavailable"}
	ErrInvalidJSON            = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid JSON body"}
	ErrModelAmbiguous         = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Model is ambiguous; use a provider-qualified model slug"}
	ErrModelUnavailable       = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Model is not available"}
	ErrProviderUnavailable    = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Provider is not available"}
	ErrRouteUnavailable       = APIError{StatusCode: http.StatusNotFound, Type: ErrorTypeInvalidRequest, Message: "Route not found"}
	ErrUnsupportedMethod      = APIError{StatusCode: http.StatusMethodNotAllowed, Type: ErrorTypeInvalidRequest, Message: "Method is not supported for this route"}
	ErrUnsupportedRequest     = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Unsupported request type"}
	ErrParameterTooLarge      = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Parameter exceeds catalog limit"}
	ErrUnsupportedTool        = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Tool is not supported by Stogas pricing"}
	ErrUnsupportedServiceTier = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "service_tier is not supported by Stogas"}
)

type APIError struct {
	StatusCode int
	Type       string
	Message    string
}

func (e APIError) Error() string {
	return e.Message
}

func PublicError(err error) APIError {
	if err == nil {
		return APIError{}
	}
	var apiErr APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return APIError{StatusCode: http.StatusInternalServerError, Type: ErrorTypeInternal, Message: "Internal server error"}
}

type RequestInput struct {
	Body   []byte
	Method string
	Path   string
}

type ResolvedRequest struct {
	Route          Route
	RequestType    schemas.RequestType
	Provider       schemas.ModelProvider
	RequestedModel string
	Model          string
	Deployment     Deployment

	chat             *openaiprovider.OpenAIChatRequest
	inputTokenLimit  int
	outputTokenLimit int
	pricing          requestPricingContext
	redactionSummary redaction.Summary
	responses        *openaiprovider.OpenAIResponsesRequest
}

type requestPricingContext struct {
	Route               Route
	HasWebSearchOptions bool
	SearchContextSize   string
	ToolsParseFailed    bool
	RawBody             map[string]json.RawMessage
	RawTools            []map[string]json.RawMessage
	ToolTypes           []string
}

type ProviderRoutingPreference struct {
	Only  []string
	Order []string
}

func (p ProviderRoutingPreference) Empty() bool {
	return len(p.Only) == 0 && len(p.Order) == 0
}

type requestWithSettableExtraParams interface {
	SetExtraParams(params map[string]interface{})
}

func ResolveRequest(input RequestInput) (*ResolvedRequest, error) {
	activationMu.RLock()
	defer activationMu.RUnlock()

	route, ok, methodOK := routeForInput(input)
	if !ok {
		return nil, ErrRouteUnavailable
	}
	if !methodOK {
		return nil, ErrUnsupportedMethod
	}

	switch route {
	case RouteChat:
		return resolveChatRequest(input.Body, route)
	case RouteResponses:
		return resolveResponsesRequest(input.Body, route)
	default:
		return nil, ErrUnsupportedRequest
	}
}

func (r *ResolvedRequest) ToBifrost(ctx *schemas.BifrostContext) (*schemas.BifrostRequest, error) {
	if r == nil {
		return nil, ErrUnsupportedRequest
	}
	converted := false
	if ctx != nil {
		if !schemas.SetRequestModelInfo(ctx, schemas.RequestModelInfo{
			Provider:        r.Provider,
			WireModel:       r.Model,
			CanonicalModel:  r.Deployment.ModelID,
			MaxOutputTokens: r.outputTokenLimit,
		}) {
			return nil, ErrUnsupportedRequest
		}
		defer func() {
			if !converted {
				ctx.ClearValue(schemas.BifrostContextKeyRequestModelInfo)
			}
		}()
	}
	if ctx != nil && r.Provider == ProviderChutes {
		ctx.SetValue(schemas.BifrostContextKeyPassthroughExtraParams, true)
	}
	switch {
	case r.chat != nil:
		body := r.chat.ToBifrostChatRequest(ctx)
		if body == nil {
			return nil, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid chat completion request"}
		}
		body.Provider = r.Provider
		body.Model = r.Model
		body.Fallbacks = nil
		converted = true
		return &schemas.BifrostRequest{RequestType: r.RequestType, ChatRequest: body}, nil
	case r.responses != nil:
		body := r.responses.ToBifrostResponsesRequest(ctx)
		if body == nil {
			return nil, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid responses request"}
		}
		body.Provider = r.Provider
		body.Model = r.Model
		body.Fallbacks = nil
		converted = true
		return &schemas.BifrostRequest{RequestType: r.RequestType, ResponsesRequest: body}, nil
	default:
		return nil, ErrUnsupportedRequest
	}
}

func (r *ResolvedRequest) CatalogNodeIDs() []string {
	if r == nil {
		return nil
	}
	return r.CatalogNodeIDsForDeployment(r.Deployment)
}

func (r *ResolvedRequest) CatalogNodeIDsForDeployment(deployment Deployment) []string {
	if r == nil {
		return nil
	}
	ids := []string{}
	snap := deployment.snapshot
	if snap == nil {
		snap = r.Deployment.snapshot
	}
	if snap != nil {
		if model, ok := snap.graph.Models[deployment.ModelID]; ok && model.AuthorID != "" {
			ids = append(ids, "author:"+model.AuthorID)
		}
	}
	if deployment.ModelID != "" {
		ids = append(ids, "model:"+deployment.ModelID)
	}
	if deployment.ID != "" {
		ids = append(ids, "deployment:"+deployment.ID)
	}
	for _, routeID := range sortedStrings(deployment.RouteIDs) {
		if routeID != "" {
			ids = append(ids, "route:"+routeID)
			if snap != nil {
				if route, ok := snap.graph.Routes[routeID]; ok && route.ProviderID != "" {
					ids = append(ids, "provider:"+route.ProviderID)
				}
			} else if r.Provider != "" {
				ids = append(ids, "provider:"+string(r.Provider))
			}
		}
	}
	return ids
}

func (r *ResolvedRequest) CatalogIdentity() Identity {
	if r == nil || r.Deployment.snapshot == nil {
		return Identity{}
	}
	return r.Deployment.snapshot.identity
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func (r *ResolvedRequest) InputTokenLimit() int {
	if r == nil {
		return 0
	}
	return r.inputTokenLimit
}

func (r *ResolvedRequest) OutputTokenLimit() int {
	if r == nil {
		return 0
	}
	return r.outputTokenLimit
}

func (r *ResolvedRequest) StructuredPIIRedactionSummary() redaction.Summary {
	if r == nil {
		return redaction.Summary{}
	}
	return r.redactionSummary
}

// SetWireModel binds the already authorized catalog deployment to the exact
// customer deployment name used on the provider request. It does not change
// the catalog deployment, pricing, or receipt identity.
func (r *ResolvedRequest) SetWireModel(model string) error {
	if r == nil {
		return ErrUnsupportedRequest
	}
	model = strings.TrimSpace(model)
	if model == "" || len(model) > 256 || strings.ContainsAny(model, "\x00\r\n") {
		return ErrModelUnavailable
	}
	r.Model = model
	return nil
}

func (r *ResolvedRequest) NormalizeMinimumOutputTokenLimit(min int) {
	if r == nil || min <= 0 || r.outputTokenLimit <= 0 || r.outputTokenLimit >= min {
		return
	}
	r.outputTokenLimit = min
	if r.chat != nil && r.chat.ChatParameters.MaxCompletionTokens != nil {
		r.chat.ChatParameters.MaxCompletionTokens = &r.outputTokenLimit
	}
	if r.responses != nil && r.responses.ResponsesParameters.MaxOutputTokens != nil {
		r.responses.ResponsesParameters.MaxOutputTokens = &r.outputTokenLimit
	}
}

func (r *ResolvedRequest) HasWebSearchOptions() bool {
	return r != nil && r.pricing.HasWebSearchOptions
}

func (r *ResolvedRequest) SearchContextSize() string {
	if r == nil {
		return ""
	}
	return r.pricing.SearchContextSize
}

func (r *ResolvedRequest) ToolsParseFailed() bool {
	return r != nil && r.pricing.ToolsParseFailed
}

func (r *ResolvedRequest) RawBody() map[string]json.RawMessage {
	if r == nil {
		return nil
	}
	return r.pricing.RawBody
}

func (r *ResolvedRequest) RawTools() []map[string]json.RawMessage {
	if r == nil {
		return nil
	}
	return r.pricing.RawTools
}

func (r *ResolvedRequest) ToolTypes() []string {
	if r == nil {
		return nil
	}
	return r.pricing.ToolTypes
}

func (r *ResolvedRequest) SanitizeClientMetadata() {
	if r == nil {
		return
	}
	if r.chat != nil {
		r.chat.ChatParameters.Metadata = nil
	}
	if r.responses != nil {
		r.responses.ResponsesParameters.Metadata = nil
	}
}

func (r *ResolvedRequest) RequireUpstreamUsage() {
	if r == nil || r.chat == nil || !r.chat.IsStreamingRequested() {
		return
	}
	if r.chat.ChatParameters.StreamOptions == nil {
		r.chat.ChatParameters.StreamOptions = &schemas.ChatStreamOptions{}
	}
	r.chat.ChatParameters.StreamOptions.IncludeUsage = schemas.Ptr(true)
}

func (r *ResolvedRequest) ApplyProviderSamplingParameters() {
	if r == nil {
		return
	}
	if topK, ok := rawIntValue(r.pricing.RawBody["top_k"]); ok {
		if r.chat != nil {
			r.chat.ChatParameters.TopK = &topK
		} else if r.responses != nil {
			r.SetExtraParam("top_k", topK)
		}
	}
	if stopSequences, ok := rawStringListValue(r.pricing.RawBody["stop_sequences"]); ok {
		if r.chat != nil {
			r.chat.ChatParameters.Stop = stopSequences
		} else if r.responses != nil {
			r.SetExtraParam("stop", stopSequences)
		}
	}
}

func (r *ResolvedRequest) SetSpeed(speed string) {
	if r == nil {
		return
	}
	normalized := strings.ToLower(strings.TrimSpace(speed))
	if r.chat != nil {
		if normalized == "fast" {
			r.chat.ChatParameters.Speed = &normalized
		} else {
			r.chat.ChatParameters.Speed = nil
		}
	}
	if r.responses != nil {
		params := copyStringAnyMap(r.responses.ExtraParams)
		if normalized == "fast" {
			params["speed"] = normalized
		} else {
			delete(params, "speed")
		}
		r.responses.SetExtraParams(params)
	}
}

func (r *ResolvedRequest) EnsureResponsesMaxToolCalls(maxToolCalls int) {
	if r == nil || r.responses == nil || maxToolCalls < 1 {
		return
	}
	if r.responses.ResponsesParameters.MaxToolCalls == nil {
		r.responses.ResponsesParameters.MaxToolCalls = schemas.Ptr(maxToolCalls)
	}
	setRawIntIfMissing(r.pricing.RawBody, "max_tool_calls", maxToolCalls)
}

func (r *ResolvedRequest) EnsureResponsesToolMaxUses(maxUses int, toolTypes ...schemas.ResponsesToolType) {
	if r == nil || r.responses == nil || maxUses < 1 {
		return
	}
	allowed := make(map[schemas.ResponsesToolType]struct{}, len(toolTypes))
	for _, toolType := range toolTypes {
		allowed[toolType] = struct{}{}
	}
	for i := range r.responses.ResponsesParameters.Tools {
		tool := &r.responses.ResponsesParameters.Tools[i]
		if _, ok := allowed[tool.Type]; !ok {
			continue
		}
		switch tool.Type {
		case schemas.ResponsesToolTypeWebSearch:
			if tool.ResponsesToolWebSearch == nil {
				tool.ResponsesToolWebSearch = &schemas.ResponsesToolWebSearch{}
			}
			if tool.ResponsesToolWebSearch.MaxUses == nil {
				tool.ResponsesToolWebSearch.MaxUses = schemas.Ptr(maxUses)
			}
		case schemas.ResponsesToolTypeWebFetch:
			if tool.ResponsesToolWebFetch == nil {
				tool.ResponsesToolWebFetch = &schemas.ResponsesToolWebFetch{}
			}
			if tool.ResponsesToolWebFetch.MaxUses == nil {
				tool.ResponsesToolWebFetch.MaxUses = schemas.Ptr(maxUses)
			}
		}
	}
	for _, tool := range r.pricing.RawTools {
		if _, ok := allowed[rawResponsesServerToolFamily(rawjson.NormalizedStringField(tool, "type"))]; !ok {
			continue
		}
		setRawIntIfMissing(tool, "max_uses", maxUses)
	}
}

func rawResponsesServerToolFamily(rawType string) schemas.ResponsesToolType {
	rawType = strings.TrimSpace(rawType)
	switch {
	case rawType == "web_search" || strings.HasPrefix(rawType, "web_search_"):
		return schemas.ResponsesToolTypeWebSearch
	case rawType == "web_fetch" || strings.HasPrefix(rawType, "web_fetch_"):
		return schemas.ResponsesToolTypeWebFetch
	default:
		return schemas.ResponsesToolType(rawType)
	}
}

func (r *ResolvedRequest) SetExtraParam(name string, value any) {
	if r == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	if r.chat != nil {
		params := copyStringAnyMap(r.chat.ExtraParams)
		params[name] = value
		r.chat.SetExtraParams(params)
		return
	}
	if r.responses != nil {
		params := copyStringAnyMap(r.responses.ExtraParams)
		params[name] = value
		r.responses.SetExtraParams(params)
	}
}

func setRawIntIfMissing(raw map[string]json.RawMessage, name string, value int) {
	if raw == nil {
		return
	}
	if _, ok := raw[name]; ok {
		return
	}
	encoded, err := sonic.Marshal(value)
	if err != nil {
		return
	}
	raw[name] = encoded
}

func rawIntValue(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var value int
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}

func rawStringListValue(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var values []string
	if err := sonic.Unmarshal(raw, &values); err != nil {
		return nil, false
	}
	return values, true
}

func resolveChatRequest(body []byte, route Route) (*ResolvedRequest, error) {
	rawData, err := rawRequestBody(body)
	if err != nil {
		return nil, err
	}
	if err := dropUnknownTopLevelFields(rawData, route); err != nil {
		return nil, err
	}
	dropNoOpCompatibilityFields(rawData, route)
	if _, err := normalizeChatStopString(rawData); err != nil {
		return nil, err
	}
	redactor := redaction.New()
	if err := redactor.RedactRequestFields(rawData, redaction.SurfaceChat); err != nil {
		return nil, piiRedactionError(err)
	}
	body, err = sonic.Marshal(rawData)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	if err := validateChatRawAliases(rawData); err != nil {
		return nil, err
	}
	if err := validateRawReasoningParameters(rawData, chatRawReasoningFields, true, false); err != nil {
		return nil, err
	}
	var request openaiprovider.OpenAIChatRequest
	if err := sonic.Unmarshal(body, &request); err != nil {
		return nil, ErrInvalidJSON
	}
	requestType := schemas.ChatCompletionRequest
	if request.IsStreamingRequested() {
		requestType = schemas.ChatCompletionStreamRequest
	}
	resolution, err := resolveOpenAIRequest(
		body,
		rawData,
		route,
		requestType,
		request.Model,
		&request.Model,
		&request.ChatParameters.ServiceTier,
		func() { applyChatAliases(&request) },
		func() *int { return request.ChatParameters.MaxCompletionTokens },
		&request,
	)
	if err != nil {
		return nil, err
	}
	if request.ChatParameters.Reasoning != nil {
		if err := normalizeChatReasoning(
			request.ChatParameters.Reasoning,
			resolution.Deployment,
			resolution.outputTokenLimit,
		); err != nil {
			return nil, err
		}
	}
	resolution.chat = &request
	resolution.redactionSummary = redactor.Summary()
	return resolution, nil
}

func normalizeChatStopString(rawData map[string]json.RawMessage) (bool, error) {
	rawStop, ok := rawData["stop"]
	if !ok || len(rawStop) == 0 || string(rawStop) == "null" {
		return false, nil
	}
	var stop string
	if err := sonic.Unmarshal(rawStop, &stop); err != nil {
		var stops []string
		if err := sonic.Unmarshal(rawStop, &stops); err != nil {
			return false, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "stop must be a string or array of strings"}
		}
		return false, nil
	}
	encoded, err := sonic.Marshal([]string{stop})
	if err != nil {
		return false, ErrInvalidJSON
	}
	rawData["stop"] = encoded
	return true, nil
}

func resolveResponsesRequest(body []byte, route Route) (*ResolvedRequest, error) {
	rawData, err := rawRequestBody(body)
	if err != nil {
		return nil, err
	}
	if err := dropUnknownTopLevelFields(rawData, route); err != nil {
		return nil, err
	}
	dropNoOpCompatibilityFields(rawData, route)
	redactor := redaction.New()
	if err := redactor.RedactRequestFields(rawData, redaction.SurfaceResponses); err != nil {
		return nil, piiRedactionError(err)
	}
	body, err = sonic.Marshal(rawData)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	if err := validateRawReasoningParameters(rawData, responsesRawReasoningFields, false, true); err != nil {
		return nil, err
	}
	var request openaiprovider.OpenAIResponsesRequest
	if err := sonic.Unmarshal(body, &request); err != nil {
		return nil, ErrInvalidJSON
	}
	requestType := schemas.ResponsesRequest
	if request.IsStreamingRequested() {
		requestType = schemas.ResponsesStreamRequest
	}
	resolution, err := resolveOpenAIRequest(
		body,
		rawData,
		route,
		requestType,
		request.Model,
		&request.Model,
		&request.ResponsesParameters.ServiceTier,
		func() { applyResponsesAliases(rawData, &request) },
		func() *int { return request.ResponsesParameters.MaxOutputTokens },
		&request,
	)
	if err != nil {
		return nil, err
	}
	if request.ResponsesParameters.Reasoning != nil && request.ResponsesParameters.Reasoning.Effort != nil {
		selection, err := normalizeReasoningEffort(
			*request.ResponsesParameters.Reasoning.Effort,
			resolution.Deployment,
		)
		if err != nil {
			return nil, err
		}
		if selection.Enabled != nil {
			return nil, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "the selected Responses deployment exposes only a reasoning on/off control"}
		}
		request.ResponsesParameters.Reasoning.Effort = selection.Effort
	}
	if request.ResponsesParameters.Reasoning != nil {
		if err := validateReasoningMaxTokens(
			request.ResponsesParameters.Reasoning.Effort,
			nil,
			request.ResponsesParameters.Reasoning.MaxTokens,
			resolution.Deployment,
			resolution.outputTokenLimit,
		); err != nil {
			return nil, err
		}
	}
	if mode := resolution.Deployment.Upstream.ReasoningMode; mode != "" {
		if request.ResponsesParameters.Reasoning == nil {
			request.ResponsesParameters.Reasoning = &schemas.ResponsesParametersReasoning{}
		}
		request.ResponsesParameters.Reasoning.Mode = &mode
	}
	resolution.responses = &request
	resolution.redactionSummary = redactor.Summary()
	return resolution, nil
}

func piiRedactionError(err error) error {
	if errors.Is(err, redaction.ErrMatchLimit) || errors.Is(err, redaction.ErrNestingLimit) {
		return APIError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Type:       ErrorTypeInvalidRequest,
			Message:    "Request exceeds PII redaction limits",
		}
	}
	return err
}

func resolveOpenAIRequest(
	body []byte,
	rawData map[string]json.RawMessage,
	route Route,
	requestType schemas.RequestType,
	requestedModel string,
	modelField *string,
	serviceTier **schemas.BifrostServiceTier,
	applyRequestAliases func(),
	requestedOutputLimit func() *int,
	extraParams requestWithSettableExtraParams,
) (*ResolvedRequest, error) {
	providerPreference, err := requestProviderPreference(rawData)
	if err != nil {
		return nil, err
	}
	provider, ok, err := ProviderForRouteModelRouting(route, requestedModel, providerPreference)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrModelUnavailable
	}
	if _, ok = catalogRouteForRequest(provider, route); !ok {
		return nil, ErrRouteUnavailable
	}
	model := requestedModel
	var requestedServiceTier *schemas.BifrostServiceTier
	if serviceTier != nil && *serviceTier != nil {
		requestedServiceTier = *serviceTier
	}
	if err := validateRequestedServiceTier(provider, requestedServiceTier); err != nil {
		return nil, err
	}
	deployment, ok := DeploymentForRouteServiceTier(provider, model, route, requestedServiceTier)
	if !ok {
		return nil, ErrModelUnavailable
	}
	if !applyResolvedDeployment(provider, modelField, serviceTier, deployment) {
		return nil, ErrModelUnavailable
	}
	if applyRequestAliases != nil {
		applyRequestAliases()
	}
	outputTokenLimit, err := effectiveOutputTokenLimit(requestedOutputLimit(), deployment.MaxOutputTokens)
	if err != nil {
		return nil, err
	}

	filtered, err := filterRequestExtraParams(rawData, provider, model, route)
	if err != nil {
		return nil, err
	}
	if extraParams != nil {
		extraParams.SetExtraParams(filtered)
	}
	pricing := requestPricingContextForRaw(route, rawData)
	if provider == schemas.OpenAI && route == RouteResponses && deployment.ReasoningSupported && responsesInputHasEncryptedReasoning(rawData["input"]) {
		return resolvedRequest(route, requestType, provider, requestedModel, *modelField, deployment, filtered, outputTokenLimit, maxInputTokenHold(deployment.ContextWindowTokens, outputTokenLimit), pricing), nil
	}
	inputTokenEstimate := inputTokenHoldEstimate(body, rawData, provider, *modelField, route, deployment.ContextWindowTokens)
	return resolvedRequest(route, requestType, provider, requestedModel, *modelField, deployment, filtered, outputTokenLimit, inputTokenEstimate, pricing), nil
}

func validateRequestedServiceTier(provider schemas.ModelProvider, requested *schemas.BifrostServiceTier) error {
	if requested == nil {
		return nil
	}
	value := strings.ToLower(strings.TrimSpace(string(*requested)))
	if value == "" {
		return nil
	}
	switch provider {
	case schemas.OpenAI:
		switch value {
		case "auto", "default", "fast", "flex", "priority":
			return nil
		case "scale", "provisioned":
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "OpenAI " + value + " service_tier is not supported by Stogas"}
		default:
			return ErrUnsupportedServiceTier
		}
	case schemas.Azure:
		switch value {
		case "auto", "default", "fast", "priority":
			return nil
		default:
			return ErrUnsupportedServiceTier
		}
	case schemas.Anthropic:
		switch value {
		case "default", "standard", "standard_only":
			return nil
		case "auto", "priority":
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Anthropic " + value + " service_tier requires an uncataloged Priority Tier contract"}
		case "flex":
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Anthropic flex service_tier does not exist"}
		default:
			return ErrUnsupportedServiceTier
		}
	default:
		return ErrUnsupportedServiceTier
	}
}

func requestProviderPreference(rawData map[string]json.RawMessage) (ProviderRoutingPreference, error) {
	raw, name, ok, err := requestRoutingPreferenceRaw(rawData)
	if err != nil {
		return ProviderRoutingPreference{}, err
	}
	if !ok {
		return ProviderRoutingPreference{}, nil
	}
	var provider string
	if err := sonic.Unmarshal(raw, &provider); err == nil {
		provider = strings.TrimSpace(provider)
		if provider == "" {
			return ProviderRoutingPreference{}, providerPreferenceShapeError(name)
		}
		return ProviderRoutingPreference{Only: []string{provider}}, nil
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err != nil || object == nil {
		return ProviderRoutingPreference{}, providerPreferenceShapeError(name)
	}
	for key := range object {
		switch key {
		case "only", "order":
		default:
			return ProviderRoutingPreference{}, providerPreferenceShapeError(name)
		}
	}
	only, err := providerStringList(name, object["only"])
	if err != nil {
		return ProviderRoutingPreference{}, err
	}
	order, err := providerStringList(name, object["order"])
	if err != nil {
		return ProviderRoutingPreference{}, err
	}
	preference := ProviderRoutingPreference{Only: only, Order: order}
	if preference.Empty() {
		return ProviderRoutingPreference{}, providerPreferenceShapeError(name)
	}
	return preference, nil
}

func requestRoutingPreferenceRaw(rawData map[string]json.RawMessage) (json.RawMessage, string, bool, error) {
	providerRaw, hasProvider := rawData["provider"]
	rulesRaw, hasRules := rawData["rules"]
	if hasProvider && hasRules {
		return nil, "", false, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "provider and rules cannot both be set"}
	}
	if hasProvider {
		return providerRaw, "provider", true, nil
	}
	if hasRules {
		return rulesRaw, "rules", true, nil
	}
	return nil, "", false, nil
}

func providerStringList(name string, raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var values []string
	if err := sonic.Unmarshal(raw, &values); err != nil || len(values) == 0 || len(values) > maxProviderRoutingItems {
		return nil, providerPreferenceShapeError(name)
	}
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" || len(normalized) > maxProviderNameBytes {
			return nil, providerPreferenceShapeError(name)
		}
		key := strings.ToLower(normalized)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, normalized)
	}
	return out, nil
}

func providerPreferenceShapeError(name string) APIError {
	if name == "" {
		name = "provider"
	}
	return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be a non-empty string or an object with provider only/order lists"}
}

func resolvedRequest(
	route Route,
	requestType schemas.RequestType,
	provider schemas.ModelProvider,
	requestedModel string,
	model string,
	deployment Deployment,
	extraParams map[string]interface{},
	outputTokenLimit int,
	inputTokenLimit int,
	pricing requestPricingContext,
) *ResolvedRequest {
	return &ResolvedRequest{
		Route:            route,
		RequestType:      requestType,
		Provider:         provider,
		RequestedModel:   requestedModel,
		Model:            model,
		Deployment:       deployment,
		inputTokenLimit:  inputTokenLimit,
		outputTokenLimit: outputTokenLimit,
		pricing:          pricing,
	}
}

func maxInputTokenHold(contextWindowTokens int, outputTokenLimit int) int {
	if contextWindowTokens <= 0 {
		return 0
	}
	remaining := contextWindowTokens - outputTokenLimit
	if remaining < 0 {
		return 0
	}
	return remaining
}

func responsesInputHasEncryptedReasoning(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	return rawJSONContainsObject(raw, func(object map[string]json.RawMessage) bool {
		if rawStringValue(object["type"]) != "reasoning" {
			return false
		}
		return strings.TrimSpace(rawStringValue(object["encrypted_content"])) != ""
	})
}

func rawJSONContainsObject(raw json.RawMessage, match func(map[string]json.RawMessage) bool) bool {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return false
	}
	switch trimmed[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := sonic.Unmarshal(raw, &object); err != nil {
			return false
		}
		if match(object) {
			return true
		}
		for _, child := range object {
			if rawJSONContainsObject(child, match) {
				return true
			}
		}
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return false
		}
		for _, child := range array {
			if rawJSONContainsObject(child, match) {
				return true
			}
		}
	}
	return false
}

func rawStringValue(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

func requestPricingContextForRaw(route Route, rawData map[string]json.RawMessage) requestPricingContext {
	searchContextSize := ""
	hasWebSearchOptions := false
	if rawOptions, ok := rawData["web_search_options"]; ok {
		hasWebSearchOptions = true
		var options map[string]json.RawMessage
		if err := sonic.Unmarshal(rawOptions, &options); err == nil {
			searchContextSize = rawjson.NormalizedStringField(options, "search_context_size")
		}
	}
	rawTools, ok := rawData["tools"]
	if !ok {
		return requestPricingContext{Route: route, HasWebSearchOptions: hasWebSearchOptions, SearchContextSize: searchContextSize, RawBody: rawData}
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(rawTools, &tools); err != nil {
		return requestPricingContext{Route: route, HasWebSearchOptions: hasWebSearchOptions, SearchContextSize: searchContextSize, ToolsParseFailed: true, RawBody: rawData}
	}
	toolTypes := make([]string, 0, len(tools))
	if route == RouteResponses {
		var normalizedTools []schemas.ResponsesTool
		if err := sonic.Unmarshal(rawTools, &normalizedTools); err == nil {
			for _, tool := range normalizedTools {
				if tool.Type != "" {
					toolTypes = append(toolTypes, string(tool.Type))
				}
			}
		}
	} else {
		for _, tool := range tools {
			toolType := rawjson.NormalizedStringField(tool, "type")
			if toolType != "" {
				toolTypes = append(toolTypes, toolType)
			}
		}
	}
	return requestPricingContext{Route: route, HasWebSearchOptions: hasWebSearchOptions, SearchContextSize: searchContextSize, RawBody: rawData, RawTools: tools, ToolTypes: toolTypes}
}

func effectiveOutputTokenLimit(requested *int, max int) (int, error) {
	if max <= 0 {
		return 0, ErrCatalogUnavailable
	}
	if requested == nil {
		return max, nil
	}
	if *requested < 0 {
		return 0, ErrParameterTooLarge
	}
	if *requested > max {
		return 0, ErrParameterTooLarge
	}
	return *requested, nil
}

func routeForInput(input RequestInput) (Route, bool, bool) {
	normalizedPath := strings.TrimSpace(input.Path)
	normalizedMethod := strings.ToUpper(strings.TrimSpace(input.Method))
	route, ok := routeByPath[normalizedPath]
	if !ok {
		return "", false, false
	}
	spec, ok := specForRoute(route)
	if !ok {
		return "", false, false
	}
	return route, true, strings.ToUpper(spec.Method) == normalizedMethod
}

func filterRequestExtraParams(rawData map[string]json.RawMessage, provider schemas.ModelProvider, model string, route Route) (map[string]interface{}, error) {
	typedFields := typedOpenAIRequestFields(provider, route)
	if len(typedFields) == 0 {
		return nil, ErrCatalogUnavailable
	}
	// Typed request decoding ignores unknown OpenAI-compatible extension fields.
	// Keep that compatibility at the public boundary, but forward only the small
	// provider-specific allowlist below. A client extension must never become an
	// upstream parameter merely because Bifrost learns it later.
	extraParams := extractExtraParams(rawData, typedFields)
	return FilterExtraParams(provider, model, route, extraParams), nil
}

func dropUnknownTopLevelFields(rawData map[string]json.RawMessage, route Route) error {
	knownFields := KnownFields(route)
	if len(knownFields) == 0 {
		return ErrCatalogUnavailable
	}
	for name := range rawData {
		if !knownFields[name] {
			delete(rawData, name)
		}
	}
	return nil
}

// dropNoOpCompatibilityFields accepts common SDK defaults without letting
// those fields select provider storage, routing, identity, or non-text output.
// JSON null is omission for every optional top-level request field. Required
// fields remain so the normal request validator can report them accurately.
// Meaningful unsupported values remain and are rejected by route policy.
func dropNoOpCompatibilityFields(rawData map[string]json.RawMessage, route Route) {
	for name, raw := range rawData {
		if name != "model" && name != "messages" && name != "input" && rawJSONNull(raw) {
			delete(rawData, name)
		}
	}
	delete(rawData, "user")
	delete(rawData, "safety_identifier")

	switch route {
	case RouteChat:
		dropRawFieldIf(rawData, "fallbacks", rawJSONNullOrEmptyArray)
		dropRawFieldIf(rawData, "functions", rawJSONNullOrEmptyArray)
		dropRawFieldIf(rawData, "modalities", rawJSONNullOrEmptyArray)
		dropRawFieldIf(rawData, "prompt_cache_isolation_key", rawJSONNullOrEmptyString)
	case RouteResponses:
		dropRawFieldIf(rawData, "background", rawJSONFalse)
		dropRawFieldIf(rawData, "fallbacks", rawJSONNullOrEmptyArray)
		dropRawFieldIf(rawData, "previous_response_id", rawJSONNullOrEmptyString)
	}
}

func dropRawFieldIf(rawData map[string]json.RawMessage, name string, noOp func(json.RawMessage) bool) {
	if raw, ok := rawData[name]; ok && noOp(raw) {
		delete(rawData, name)
	}
}

func rawJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func rawJSONFalse(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("false"))
}

func rawJSONNullOrEmptyArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("[]"))
}

func rawJSONNullOrEmptyString(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte(`""`))
}

func extractExtraParams(rawData map[string]json.RawMessage, knownFields map[string]bool) map[string]interface{} {
	extraParams := make(map[string]interface{})
	for key, value := range rawData {
		if knownFields[key] {
			continue
		}
		var decoded any
		if err := sonic.Unmarshal(value, &decoded); err != nil {
			continue
		}
		extraParams[key] = decoded
	}
	return extraParams
}

func typedOpenAIRequestFields(provider schemas.ModelProvider, route Route) map[string]bool {
	fields := KnownFields(route)
	if provider == ProviderChutes && route == RouteChat {
		fields = copyBoolMap(fields)
		delete(fields, "repetition_penalty")
	}
	if route != RouteResponses {
		return fields
	}
	fields = copyBoolMap(fields)
	delete(fields, "cache_control")
	delete(fields, "context_management")
	delete(fields, "reasoning.effort")
	delete(fields, "task_budget")
	return fields
}

func copyBoolMap(values map[string]bool) map[string]bool {
	out := make(map[string]bool, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func copyStringAnyMap(values map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

// ReasoningEffort returns the admitted canonical reasoning effort.
func (r *ResolvedRequest) ReasoningEffort() (string, bool) {
	if r == nil || r.chat == nil || r.chat.ChatParameters.Reasoning == nil ||
		r.chat.ChatParameters.Reasoning.Effort == nil {
		return "", false
	}
	return *r.chat.ChatParameters.Reasoning.Effort, true
}

// ReasoningEnabled returns an admitted binary reasoning control.
func (r *ResolvedRequest) ReasoningEnabled() (bool, bool) {
	if r == nil || r.chat == nil || r.chat.ChatParameters.Reasoning == nil ||
		r.chat.ChatParameters.Reasoning.Enabled == nil {
		return false, false
	}
	return *r.chat.ChatParameters.Reasoning.Enabled, true
}

// PrepareChutesChatWire applies Chutes-specific output and reasoning fields.
// The resolved output limit remains the billing hold limit.
func (r *ResolvedRequest) PrepareChutesChatWire(
	defaultOutputTokens int,
	upstreamReasoningEffort string,
	thinking *bool,
) {
	if r == nil || r.chat == nil || r.Route != RouteChat {
		return
	}
	if _, maxTokensSet := rawIntValue(r.pricing.RawBody["max_tokens"]); !maxTokensSet {
		if _, maxCompletionTokensSet := rawIntValue(r.pricing.RawBody["max_completion_tokens"]); !maxCompletionTokensSet &&
			defaultOutputTokens >= 0 && defaultOutputTokens < r.outputTokenLimit {
			r.outputTokenLimit = defaultOutputTokens
			r.inputTokenLimit = maxInputTokenHold(r.Deployment.ContextWindowTokens, defaultOutputTokens)
		}
	}
	limit := r.outputTokenLimit
	r.chat.ChatParameters.MaxCompletionTokens = nil
	r.chat.MaxTokens = nil
	r.chat.ChatParameters.Reasoning = nil
	r.SetExtraParam("max_tokens", limit)
	if upstreamReasoningEffort != "" {
		r.SetExtraParam("reasoning_effort", upstreamReasoningEffort)
	}
	if thinking != nil {
		r.SetExtraParam("chat_template_kwargs", map[string]interface{}{
			"enable_thinking": *thinking,
			"thinking":        *thinking,
		})
	}
}

func applyChatAliases(request *openaiprovider.OpenAIChatRequest) {
	if request.ChatParameters.MaxCompletionTokens != nil {
		return
	}
	if request.MaxTokens != nil {
		request.ChatParameters.MaxCompletionTokens = request.MaxTokens
		return
	}
	if request.ExtraParams == nil {
		return
	}
	maxTokensVal, exists := request.ExtraParams["max_tokens"]
	if !exists {
		return
	}
	switch value := maxTokensVal.(type) {
	case float64:
		maxTokens := int(value)
		request.ChatParameters.MaxCompletionTokens = &maxTokens
		delete(request.ExtraParams, "max_tokens")
		request.ChatParameters.ExtraParams = request.ExtraParams
	case int:
		request.ChatParameters.MaxCompletionTokens = &value
		delete(request.ExtraParams, "max_tokens")
		request.ChatParameters.ExtraParams = request.ExtraParams
	}
}

func applyResponsesAliases(rawData map[string]json.RawMessage, request *openaiprovider.OpenAIResponsesRequest) {
	if request == nil {
		return
	}
	rawEffort, ok := rawData["reasoning.effort"]
	if !ok {
		return
	}
	if request.ResponsesParameters.Reasoning != nil && request.ResponsesParameters.Reasoning.Effort != nil {
		return
	}
	var effort string
	if err := sonic.Unmarshal(rawEffort, &effort); err != nil {
		return
	}
	if request.ResponsesParameters.Reasoning == nil {
		request.ResponsesParameters.Reasoning = &schemas.ResponsesParametersReasoning{}
	}
	request.ResponsesParameters.Reasoning.Effort = &effort
}

func validateChatTokenAliases(rawData map[string]json.RawMessage) error {
	maxTokensRaw, hasMaxTokens := rawData["max_tokens"]
	maxCompletionTokensRaw, hasMaxCompletionTokens := rawData["max_completion_tokens"]
	if !hasMaxTokens || !hasMaxCompletionTokens {
		return nil
	}
	maxTokens, ok := rawInteger(maxTokensRaw)
	if !ok {
		return nil
	}
	maxCompletionTokens, ok := rawInteger(maxCompletionTokensRaw)
	if !ok {
		return nil
	}
	if maxTokens == maxCompletionTokens {
		return nil
	}
	return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "max_tokens conflicts with max_completion_tokens"}
}

func validateChatRawAliases(rawData map[string]json.RawMessage) error {
	if err := validateChatTokenAliases(rawData); err != nil {
		return err
	}
	reasoningRaw, hasReasoning := rawData["reasoning"]
	if !hasReasoning {
		return nil
	}
	var reasoning map[string]json.RawMessage
	if err := sonic.Unmarshal(reasoningRaw, &reasoning); err != nil {
		return nil
	}
	for _, item := range []struct {
		alias string
		field string
	}{
		{"reasoning_effort", "effort"},
		{"reasoning_max_tokens", "max_tokens"},
		{"reasoning_display", "display"},
	} {
		if _, ok := rawData[item.alias]; !ok {
			continue
		}
		if _, ok := reasoning[item.field]; ok {
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: item.alias + " conflicts with reasoning." + item.field}
		}
	}
	return nil
}

func rawInteger(raw json.RawMessage) (int, bool) {
	var value int
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}
