package catalog

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
)

const (
	ErrorTypeInvalidRequest = "invalid_request_error"
	ErrorTypeInternal       = "internal_error"
)

var (
	ErrCatalogUnavailable      = APIError{StatusCode: http.StatusInternalServerError, Type: ErrorTypeInternal, Message: "Catalog unavailable"}
	ErrInvalidJSON             = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid JSON body"}
	ErrModelAmbiguous          = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Model is ambiguous; use a provider-qualified model slug"}
	ErrModelUnavailable        = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Model is not available"}
	ErrProviderUnavailable     = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Provider is not available"}
	ErrRouteUnavailable        = APIError{StatusCode: http.StatusNotFound, Type: ErrorTypeInvalidRequest, Message: "Route not found"}
	ErrUnsupportedMethod       = APIError{StatusCode: http.StatusMethodNotAllowed, Type: ErrorTypeInvalidRequest, Message: "Method is not supported for this route"}
	ErrUnsupportedRequest      = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Unsupported request type"}
	ErrParameterTooLarge       = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Parameter exceeds catalog limit"}
	ErrUnsupportedTool         = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Tool is not supported by Stogas pricing"}
	ErrUnsupportedServiceTier  = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "service_tier is not supported by Stogas"}
	ErrUnsupportedInferenceGeo = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "inference_geo is not supported by Stogas"}
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
	switch {
	case r.chat != nil:
		body := r.chat.ToBifrostChatRequest(ctx)
		if body == nil {
			return nil, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid chat completion request"}
		}
		body.Provider = r.Provider
		body.Model = r.Model
		body.Fallbacks = nil
		return &schemas.BifrostRequest{RequestType: r.RequestType, ChatRequest: body}, nil
	case r.responses != nil:
		body := r.responses.ToBifrostResponsesRequest(ctx)
		if body == nil {
			return nil, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid responses request"}
		}
		body.Provider = r.Provider
		body.Model = r.Model
		body.Fallbacks = nil
		return &schemas.BifrostRequest{RequestType: r.RequestType, ResponsesRequest: body}, nil
	default:
		return nil, ErrUnsupportedRequest
	}
}

func (r *ResolvedRequest) CatalogNodeIDs() []string {
	if r == nil {
		return nil
	}
	ids := []string{
		"stogas_endpoint:" + string(r.Route),
		"provider:" + string(r.Provider),
	}
	if r.Model != "" {
		ids = append(ids, "model:"+r.Model)
	}
	if r.Deployment.ModelID != "" && r.Deployment.ModelID != r.Model {
		ids = append(ids, "model_node:"+r.Deployment.ModelID)
	}
	if r.Deployment.ID != "" {
		ids = append(ids, "deployment:"+r.Deployment.ID)
	}
	for _, endpointID := range sortedStrings(r.Deployment.ProviderEndpointIDs) {
		if endpointID != "" {
			ids = append(ids, "provider_endpoint:"+endpointID)
		}
	}
	return ids
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

func (r *ResolvedRequest) SetUpstreamUser(user string) {
	if r == nil {
		return
	}
	user = strings.TrimSpace(user)
	if user == "" {
		return
	}
	if r.chat != nil {
		r.chat.ChatParameters.User = &user
	}
	if r.responses != nil {
		r.responses.ResponsesParameters.User = &user
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

func (r *ResolvedRequest) NormalizePromptCacheRetention() {
	if r == nil {
		return
	}
	if r.chat != nil {
		if normalized, ok := normalizePromptCacheRetention(r.chat.ChatParameters.PromptCacheRetention); ok {
			r.chat.ChatParameters.PromptCacheRetention = &normalized
			setRawString(r.pricing.RawBody, "prompt_cache_retention", normalized)
		}
		return
	}
	if r.responses != nil {
		if normalized, ok := normalizePromptCacheRetention(r.responses.ResponsesParameters.PromptCacheRetention); ok {
			r.responses.ResponsesParameters.PromptCacheRetention = &normalized
			setRawString(r.pricing.RawBody, "prompt_cache_retention", normalized)
		}
	}
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
		if _, ok := allowed[rawResponsesServerToolFamily(rawStringField(tool, "type"))]; !ok {
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

func setRawString(raw map[string]json.RawMessage, name string, value string) {
	if raw == nil {
		return
	}
	encoded, err := sonic.Marshal(value)
	if err != nil {
		return
	}
	raw[name] = encoded
}

func normalizePromptCacheRetention(value *string) (string, bool) {
	if value == nil {
		return "", false
	}
	switch strings.TrimSpace(*value) {
	case "24h":
		return "24h", true
	case "in-memory", "in_memory":
		return "in-memory", true
	default:
		return "", false
	}
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
	if normalized, err := normalizeChatStopString(rawData); err != nil {
		return nil, err
	} else if normalized {
		body, err = sonic.Marshal(rawData)
		if err != nil {
			return nil, ErrInvalidJSON
		}
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
	resolution.chat = &request
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
	resolution.responses = &request
	return resolution, nil
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
	if err := validateAllowedRequestFields(rawData, route); err != nil {
		return nil, err
	}
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
	if _, ok = providerEndpointForRoute(provider, route); !ok {
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
	requestedRegion, err := requestedInferenceGeo(provider, rawData)
	if err != nil {
		return nil, err
	}
	requestedSpeed, err := requestedAnthropicSpeed(provider, rawData, requestedServiceTier)
	if err != nil {
		return nil, err
	}
	deployment, ok := DeploymentForRouteServiceTierRegionSpeed(provider, model, route, requestedServiceTier, requestedRegion, requestedSpeed)
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
	inputTokenEstimate := inputTokenHoldEstimate(body, provider, deployment.ContextWindowTokens)
	return resolvedRequest(route, requestType, provider, requestedModel, *modelField, deployment, filtered, outputTokenLimit, inputTokenEstimate, pricing), nil
}

func requestedInferenceGeo(provider schemas.ModelProvider, rawData map[string]json.RawMessage) (string, error) {
	raw, ok := rawData["inference_geo"]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return "", APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "inference_geo must be a string"}
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "", ErrUnsupportedInferenceGeo
	}
	if provider != schemas.Anthropic {
		return "", APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "inference_geo is only supported for Anthropic deployments"}
	}
	switch normalized {
	case "global":
		return "multi-region", nil
	case "us":
		return normalized, nil
	default:
		return "", ErrUnsupportedInferenceGeo
	}
}

func requestedAnthropicSpeed(provider schemas.ModelProvider, rawData map[string]json.RawMessage, requestedTier *schemas.BifrostServiceTier) (string, error) {
	raw, ok := rawData["speed"]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return "", APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "speed must be a string"}
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	if provider != schemas.Anthropic {
		return "", APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "speed is only supported for Anthropic deployments"}
	}
	switch normalized {
	case "fast":
		if requestedTier != nil {
			switch strings.ToLower(strings.TrimSpace(string(*requestedTier))) {
			case "auto", "priority":
				return "", APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Anthropic " + strings.ToLower(strings.TrimSpace(string(*requestedTier))) + " service_tier is not supported with speed fast"}
			}
		}
		return "fast", nil
	case "standard":
		return "standard", nil
	default:
		return "", APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "speed is not supported by Stogas"}
	}
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
		case "auto", "default", "flex", "priority":
			return nil
		case "scale", "provisioned":
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "OpenAI " + value + " service_tier is not supported by Stogas"}
		default:
			return ErrUnsupportedServiceTier
		}
	case schemas.Anthropic:
		switch value {
		case "auto", "priority", "default", "flex", "standard", "standard_only":
			return nil
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
	if err := sonic.Unmarshal(raw, &values); err != nil || len(values) == 0 {
		return nil, providerPreferenceShapeError(name)
	}
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
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

func rawRequestBody(body []byte) (map[string]json.RawMessage, error) {
	var rawData map[string]json.RawMessage
	if err := sonic.Unmarshal(body, &rawData); err != nil {
		return nil, ErrInvalidJSON
	}
	return rawData, nil
}

func inputTokenHoldEstimate(body []byte, provider schemas.ModelProvider, maxInputTokens int) int {
	estimate := roughInputTokenEstimate(body, provider)
	if maxInputTokens < 0 {
		maxInputTokens = 0
	}
	if maxInputTokens > 0 && estimate > maxInputTokens {
		return maxInputTokens
	}
	return estimate
}

func roughInputTokenEstimate(body []byte, provider schemas.ModelProvider) int {
	if len(body) == 0 {
		return 0
	}
	base := ceilDiv(len(body), 4)
	estimate := base
	if provider == schemas.Anthropic {
		estimate = ceilMulDiv(base, 135, 100)
	}
	if highRawNonASCIIRatio(body) {
		estimate = maxInt(estimate, ceilMulDiv(base, 150, 100))
	}
	return maxInt(estimate, 1)
}

func highRawNonASCIIRatio(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	nonASCII := 0
	for _, b := range body {
		if b >= 0x80 {
			nonASCII++
		}
	}
	return nonASCII*10 >= len(body)
}

func ceilDiv(value int, divisor int) int {
	if value <= 0 {
		return 0
	}
	return (value + divisor - 1) / divisor
}

func ceilMulDiv(value int, multiplier int, divisor int) int {
	if value <= 0 {
		return 0
	}
	return (value*multiplier + divisor - 1) / divisor
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}

func requestPricingContextForRaw(route Route, rawData map[string]json.RawMessage) requestPricingContext {
	searchContextSize := ""
	hasWebSearchOptions := false
	if rawOptions, ok := rawData["web_search_options"]; ok {
		hasWebSearchOptions = true
		var options map[string]json.RawMessage
		if err := sonic.Unmarshal(rawOptions, &options); err == nil {
			searchContextSize = rawStringField(options, "search_context_size")
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
			toolType := rawStringField(tool, "type")
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

func validateAllowedRequestFields(rawData map[string]json.RawMessage, route Route) error {
	knownFields := KnownFields(route)
	if len(knownFields) == 0 {
		return ErrCatalogUnavailable
	}
	for name := range rawData {
		if !knownFields[name] {
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " is not supported by Stogas API"}
		}
	}
	return nil
}

func filterRequestExtraParams(rawData map[string]json.RawMessage, provider schemas.ModelProvider, model string, route Route) (map[string]interface{}, error) {
	typedFields := typedOpenAIRequestFields(route)
	if len(typedFields) == 0 {
		return nil, ErrCatalogUnavailable
	}
	extraParams := extractExtraParams(rawData, typedFields)
	return FilterExtraParams(provider, model, route, extraParams), nil
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

func typedOpenAIRequestFields(route Route) map[string]bool {
	fields := KnownFields(route)
	if route != RouteResponses {
		return fields
	}
	fields = copyBoolMap(fields)
	delete(fields, "cache_control")
	delete(fields, "context_management")
	delete(fields, "reasoning.effort")
	delete(fields, "speed")
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

var (
	chatRawReasoningFields = map[string]bool{
		"display":    true,
		"effort":     true,
		"enabled":    true,
		"max_tokens": true,
	}
	responsesRawReasoningFields = map[string]bool{
		"effort":           true,
		"generate_summary": true,
		"max_tokens":       true,
		"summary":          true,
	}
)

func validateRawReasoningParameters(rawData map[string]json.RawMessage, allowedFields map[string]bool, allowAliases bool, allowDottedEffort bool) error {
	reasoning, hasReasoning, err := rawReasoningObject(rawData["reasoning"])
	if err != nil {
		return err
	}
	if hasReasoning {
		for name := range reasoning {
			if !allowedFields[name] {
				return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning." + name + " is not supported by Stogas API"}
			}
		}
	}
	if allowAliases {
		for _, item := range []struct {
			alias string
			field string
		}{
			{"reasoning_effort", "effort"},
			{"reasoning_max_tokens", "max_tokens"},
			{"reasoning_display", "display"},
		} {
			if _, ok := rawData[item.alias]; ok && hasReasoning {
				if _, exists := reasoning[item.field]; exists {
					return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: item.alias + " conflicts with reasoning." + item.field}
				}
			}
		}
		if err := validateRawReasoningEffort(rawData["reasoning_effort"], "reasoning_effort"); err != nil {
			return err
		}
		if err := validateRawReasoningDisplay(rawData["reasoning_display"], "reasoning_display"); err != nil {
			return err
		}
		if err := validateRawReasoningPositiveInteger(rawData["reasoning_max_tokens"], "reasoning_max_tokens"); err != nil {
			return err
		}
	}
	if allowDottedEffort {
		if err := validateRawReasoningEffort(rawData["reasoning.effort"], "reasoning.effort"); err != nil {
			return err
		}
		if _, ok := rawData["reasoning.effort"]; ok && hasReasoning {
			if _, exists := reasoning["effort"]; exists {
				return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning.effort conflicts with reasoning.effort"}
			}
		}
	}
	if hasReasoning {
		if err := validateRawReasoningEffort(reasoning["effort"], "reasoning.effort"); err != nil {
			return err
		}
		if err := validateRawReasoningDisplay(reasoning["display"], "reasoning.display"); err != nil {
			return err
		}
		if err := validateRawReasoningPositiveInteger(reasoning["max_tokens"], "reasoning.max_tokens"); err != nil {
			return err
		}
		if err := validateRawReasoningBoolean(reasoning["enabled"], "reasoning.enabled"); err != nil {
			return err
		}
		if err := validateRawReasoningSummary(reasoning["summary"], "reasoning.summary"); err != nil {
			return err
		}
		if err := validateRawReasoningSummary(reasoning["generate_summary"], "reasoning.generate_summary"); err != nil {
			return err
		}
	}
	return nil
}

func rawReasoningObject(raw json.RawMessage) (map[string]json.RawMessage, bool, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil, false, nil
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err != nil {
		return nil, false, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "reasoning must be an object"}
	}
	return object, true, nil
}

func validateRawReasoningEffort(raw json.RawMessage, name string) error {
	value, ok, err := rawReasoningString(raw, name)
	if err != nil || !ok {
		return err
	}
	if strings.TrimSpace(value) == "" {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be a string"}
	}
	return nil
}

func validateRawReasoningDisplay(raw json.RawMessage, name string) error {
	_, _, err := rawReasoningString(raw, name)
	return err
}

func validateRawReasoningSummary(raw json.RawMessage, name string) error {
	_, _, err := rawReasoningString(raw, name)
	return err
}

func rawReasoningString(raw json.RawMessage, name string) (string, bool, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return "", false, nil
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", true, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be a string"}
	}
	return value, true, nil
}

func validateRawReasoningPositiveInteger(raw json.RawMessage, name string) error {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	var value int
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be an integer"}
	}
	if value < 1 {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " is outside the supported range"}
	}
	return nil
}

func validateRawReasoningBoolean(raw json.RawMessage, name string) error {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	var value bool
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be a boolean"}
	}
	return nil
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
