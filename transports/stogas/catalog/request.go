package catalog

import (
	"encoding/json"
	"errors"
	"net/http"
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
	ErrCatalogUnavailable = APIError{StatusCode: http.StatusInternalServerError, Type: ErrorTypeInternal, Message: "Catalog unavailable"}
	ErrInvalidJSON        = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid JSON body"}
	ErrModelAmbiguous     = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Model is ambiguous; use a provider-qualified model slug"}
	ErrModelUnavailable   = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Model is not available"}
	ErrRouteUnavailable   = APIError{StatusCode: http.StatusNotFound, Type: ErrorTypeInvalidRequest, Message: "Route not found"}
	ErrUnsupportedMethod  = APIError{StatusCode: http.StatusMethodNotAllowed, Type: ErrorTypeInvalidRequest, Message: "Method is not supported for this route"}
	ErrUnsupportedRequest = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Unsupported request type"}
	ErrFallbacksDisabled  = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Fallbacks are not supported"}
	ErrParameterTooLarge  = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Parameter exceeds catalog limit"}
	ErrUnsupportedTool    = APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Tool is not supported by Stogas billing policy"}
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
	Route             Route
	RequestType       schemas.RequestType
	Provider          schemas.ModelProvider
	RequestedModel    string
	Model             string
	Deployment        Deployment
	PolicyChain       []PolicyNode
	AllowedParameters []string

	chat             *openaiprovider.OpenAIChatRequest
	inputTokenLimit  int
	outputTokenLimit int
	pricing          requestPricingContext
	responses        *openaiprovider.OpenAIResponsesRequest
}

type PolicyNode struct {
	Kind string
	ID   string
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

func (r *ResolvedRequest) SetProviderExtraParam(name string, value any) {
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

func resolveChatRequest(body []byte, route Route) (*ResolvedRequest, error) {
	rawData, err := rawRequestBody(body)
	if err != nil {
		return nil, err
	}
	if err := validateChatRawAliases(rawData); err != nil {
		return nil, err
	}
	var request openaiprovider.OpenAIChatRequest
	if err := sonic.Unmarshal(body, &request); err != nil {
		return nil, ErrInvalidJSON
	}
	if _, ok := rawData["fallbacks"]; ok {
		return nil, ErrFallbacksDisabled
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

func resolveResponsesRequest(body []byte, route Route) (*ResolvedRequest, error) {
	rawData, err := rawRequestBody(body)
	if err != nil {
		return nil, err
	}
	var request openaiprovider.OpenAIResponsesRequest
	if err := sonic.Unmarshal(body, &request); err != nil {
		return nil, ErrInvalidJSON
	}
	if _, ok := rawData["fallbacks"]; ok {
		return nil, ErrFallbacksDisabled
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
		nil,
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
	applyPolicyAliases func(),
	requestedOutputLimit func() *int,
	extraParams requestWithSettableExtraParams,
) (*ResolvedRequest, error) {
	if err := validateAllowedRequestFields(rawData, route); err != nil {
		return nil, err
	}
	provider, ok, err := ProviderForRouteModel(route, requestedModel)
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
	deployment, ok := DeploymentForRoute(provider, model, route)
	if !ok {
		return nil, ErrModelUnavailable
	}
	if !applyResolvedDeployment(provider, modelField, serviceTier, deployment) {
		return nil, ErrModelUnavailable
	}
	if applyPolicyAliases != nil {
		applyPolicyAliases()
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
	return resolvedRequest(route, requestType, provider, requestedModel, *modelField, deployment, filtered, outputTokenLimit, len(body), pricing), nil
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
		Route:             route,
		RequestType:       requestType,
		Provider:          provider,
		RequestedModel:    requestedModel,
		Model:             model,
		Deployment:        deployment,
		PolicyChain:       requestPolicyChain(provider, route, deployment),
		AllowedParameters: allowedParameterNames(route, extraParams),
		inputTokenLimit:   inputTokenLimit,
		outputTokenLimit:  outputTokenLimit,
		pricing:           pricing,
	}
}

func rawRequestBody(body []byte) (map[string]json.RawMessage, error) {
	var rawData map[string]json.RawMessage
	if err := sonic.Unmarshal(body, &rawData); err != nil {
		return nil, ErrInvalidJSON
	}
	return rawData, nil
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
	for _, tool := range tools {
		toolType := rawStringField(tool, "type")
		if toolType != "" {
			toolTypes = append(toolTypes, toolType)
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
	if *requested <= 0 {
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

func requestPolicyChain(provider schemas.ModelProvider, route Route, deployment Deployment) []PolicyNode {
	chain := []PolicyNode{{Kind: "provider", ID: string(provider)}, {Kind: "route", ID: string(provider) + "-" + string(route)}}
	if deployment.ID != "" {
		chain = append(chain, PolicyNode{Kind: "deployment", ID: deployment.ID})
	}
	if deployment.ModelID != "" {
		chain = append(chain, PolicyNode{Kind: "model", ID: deployment.ModelID})
	}
	return chain
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

func allowedParameterNames(route Route, extraParams map[string]interface{}) []string {
	fields := KnownFields(route)
	names := make([]string, 0, len(fields)+len(extraParams))
	for name := range fields {
		names = append(names, name)
	}
	for name := range extraParams {
		names = append(names, name)
	}
	return stableStrings(names)
}

func typedOpenAIRequestFields(route Route) map[string]bool {
	fields := KnownFields(route)
	if route != RouteResponses {
		return fields
	}
	fields = copyBoolMap(fields)
	delete(fields, "frequency_penalty")
	delete(fields, "presence_penalty")
	delete(fields, "prompt_cache_retention")
	delete(fields, "reasoning.effort")
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
