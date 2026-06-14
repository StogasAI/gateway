package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
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
	Hold              HoldEstimate

	chat      *openaiprovider.OpenAIChatRequest
	pricing   requestPricingContext
	responses *openaiprovider.OpenAIResponsesRequest
}

type HoldEstimate struct {
	MaxUSDAtoms string
	ProductKey  string
	ProviderKey string
	Meters      []MeterEstimate
}

type PolicyNode struct {
	Kind string
	ID   string
}

type requestPricingContext struct {
	Route     Route
	ToolTypes []string
}

type requestWithSettableExtraParams interface {
	SetExtraParams(params map[string]interface{})
}

func ResolveRequest(input RequestInput) (*ResolvedRequest, error) {
	route, routeNode, schemaNode, ok := routeForInput(input)
	if !ok {
		return nil, ErrRouteUnavailable
	}

	switch route {
	case RouteChat:
		return resolveChatRequest(input.Body, route, routeNode, schemaNode)
	case RouteResponses:
		return resolveResponsesRequest(input.Body, route, routeNode, schemaNode)
	default:
		return nil, ErrUnsupportedRequest
	}
}

func CheckBifrostRequest(requestType schemas.RequestType, req *schemas.BifrostRequest) (*ResolvedRequest, error) {
	if req == nil {
		return nil, ErrUnsupportedRequest
	}
	route, ok := RouteForRequestType(requestType)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedRequest, requestType)
	}

	provider, model, fallbacks := req.GetRequestFields()
	if len(fallbacks) > 0 {
		return nil, ErrFallbacksDisabled
	}
	deployment, ok := DeploymentForRoute(provider, model, route)
	if !ok {
		return nil, ErrModelUnavailable
	}
	outputTokenLimit, err := effectiveOutputTokenLimit(outputLimitFromBifrost(req), deployment.MaxOutputTokens, compiledParameter{})
	if err != nil {
		return nil, err
	}
	return resolvedRequest(route, requestType, provider, model, model, deployment, nil, nil, outputTokenLimit, 0, requestPricingContext{}), nil
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
		body.Fallbacks = nil
		return &schemas.BifrostRequest{RequestType: r.RequestType, ChatRequest: body}, nil
	case r.responses != nil:
		body := r.responses.ToBifrostResponsesRequest(ctx)
		if body == nil {
			return nil, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid responses request"}
		}
		body.Fallbacks = nil
		return &schemas.BifrostRequest{RequestType: r.RequestType, ResponsesRequest: body}, nil
	default:
		return nil, ErrUnsupportedRequest
	}
}

func RouteForRequestType(requestType schemas.RequestType) (Route, bool) {
	switch requestType {
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
		return RouteChat, true
	case schemas.ResponsesRequest, schemas.ResponsesStreamRequest:
		return RouteResponses, true
	default:
		return "", false
	}
}

func resolveChatRequest(body []byte, route Route, routeNode compiledProviderEndpoint, schemaNode compiledStogasEndpoint) (*ResolvedRequest, error) {
	var request openaiprovider.OpenAIChatRequest
	if err := sonic.Unmarshal(body, &request); err != nil {
		return nil, ErrInvalidJSON
	}
	if len(request.Fallbacks) > 0 {
		return nil, ErrFallbacksDisabled
	}
	requestType := schemas.ChatCompletionRequest
	if request.IsStreamingRequested() {
		requestType = schemas.ChatCompletionStreamRequest
	}
	resolution, err := resolveOpenAIRequest(
		body,
		route,
		routeNode,
		schemaNode,
		requestType,
		request.Model,
		&request.Model,
		&request.ChatParameters.ServiceTier,
		func(parameters map[string]compiledParameter) { applyChatAliases(&request, parameters) },
		func() *int { return request.ChatParameters.MaxCompletionTokens },
		&request,
	)
	if err != nil {
		return nil, err
	}
	resolution.chat = &request
	return resolution, nil
}

func resolveResponsesRequest(body []byte, route Route, routeNode compiledProviderEndpoint, schemaNode compiledStogasEndpoint) (*ResolvedRequest, error) {
	var request openaiprovider.OpenAIResponsesRequest
	if err := sonic.Unmarshal(body, &request); err != nil {
		return nil, ErrInvalidJSON
	}
	if len(request.Fallbacks) > 0 {
		return nil, ErrFallbacksDisabled
	}
	requestType := schemas.ResponsesRequest
	if request.IsStreamingRequested() {
		requestType = schemas.ResponsesStreamRequest
	}
	resolution, err := resolveOpenAIRequest(
		body,
		route,
		routeNode,
		schemaNode,
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
	route Route,
	routeNode compiledProviderEndpoint,
	schemaNode compiledStogasEndpoint,
	requestType schemas.RequestType,
	requestedModel string,
	modelField *string,
	serviceTier **schemas.BifrostServiceTier,
	applyPolicyAliases func(map[string]compiledParameter),
	requestedOutputLimit func() *int,
	extraParams requestWithSettableExtraParams,
) (*ResolvedRequest, error) {
	provider, model := schemas.ParseModelString(requestedModel, schemas.ModelProvider(routeNode.ProviderID))
	deployment, ok := DeploymentForRoute(provider, model, route)
	if !ok {
		return nil, ErrModelUnavailable
	}
	effectiveParameters := effectiveParameterPolicies(schemaNode.Schema, routeNode, deployment)
	if !applyResolvedDeployment(modelField, serviceTier, deployment, effectiveParameters) {
		return nil, ErrModelUnavailable
	}
	if applyPolicyAliases != nil {
		applyPolicyAliases(effectiveParameters)
	}
	outputTokenLimit, err := effectiveOutputTokenLimit(requestedOutputLimit(), deployment.MaxOutputTokens, outputLimitPolicy(route, effectiveParameters))
	if err != nil {
		return nil, err
	}

	if err := validateRequestParameterRules(body, routeNode, effectiveParameters, deployment); err != nil {
		return nil, err
	}

	filtered, err := filterRequestExtraParams(body, provider, model, route, effectiveParameters)
	if err != nil {
		return nil, err
	}
	if extraParams != nil {
		extraParams.SetExtraParams(filtered)
	}
	pricing := requestPricingContextForBody(route, body)
	return resolvedRequest(route, requestType, provider, requestedModel, *modelField, deployment, effectiveParameters, filtered, outputTokenLimit, len(body), pricing), nil
}

func resolvedRequest(
	route Route,
	requestType schemas.RequestType,
	provider schemas.ModelProvider,
	requestedModel string,
	model string,
	deployment Deployment,
	parameters map[string]compiledParameter,
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
		AllowedParameters: allowedParameterNames(parameters, extraParams),
		Hold:              estimateHold(provider, deployment, outputTokenLimit, inputTokenLimit, pricing),
		pricing:           pricing,
	}
}

func requestPricingContextForBody(route Route, body []byte) requestPricingContext {
	var rawData map[string]json.RawMessage
	if err := sonic.Unmarshal(body, &rawData); err != nil {
		return requestPricingContext{Route: route}
	}
	rawTools, ok := rawData["tools"]
	if !ok {
		return requestPricingContext{Route: route}
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(rawTools, &tools); err != nil {
		return requestPricingContext{Route: route}
	}
	toolTypes := make([]string, 0, len(tools))
	for _, tool := range tools {
		toolType := rawStringField(tool, "type")
		if toolType != "" {
			toolTypes = append(toolTypes, toolType)
		}
	}
	return requestPricingContext{Route: route, ToolTypes: toolTypes}
}

func effectiveOutputTokenLimit(requested *int, max int, policy compiledParameter) (int, error) {
	if max <= 0 {
		return 0, ErrCatalogUnavailable
	}
	if requested == nil {
		return max, nil
	}
	if *requested <= 0 {
		return 0, ErrParameterTooLarge
	}
	if policy.Min != nil && float64(*requested) < *policy.Min {
		return 0, ErrParameterTooLarge
	}
	if policy.Max != nil && float64(*requested) > *policy.Max {
		return 0, ErrParameterTooLarge
	}
	if *requested > max {
		return 0, ErrParameterTooLarge
	}
	return *requested, nil
}

func outputLimitPolicy(route Route, parameters map[string]compiledParameter) compiledParameter {
	switch route {
	case RouteChat:
		return parameters["max_completion_tokens"]
	case RouteResponses:
		return parameters["max_output_tokens"]
	default:
		return compiledParameter{}
	}
}

func outputLimitFromBifrost(req *schemas.BifrostRequest) *int {
	if req == nil {
		return nil
	}
	if req.ChatRequest != nil && req.ChatRequest.Params != nil {
		return req.ChatRequest.Params.MaxCompletionTokens
	}
	if req.ResponsesRequest != nil && req.ResponsesRequest.Params != nil {
		return req.ResponsesRequest.Params.MaxOutputTokens
	}
	return nil
}

func routeForInput(input RequestInput) (Route, compiledProviderEndpoint, compiledStogasEndpoint, bool) {
	snap := active.Load()
	if snap == nil {
		return "", compiledProviderEndpoint{}, compiledStogasEndpoint{}, false
	}
	normalizedPath := strings.TrimSpace(input.Path)
	normalizedMethod := strings.ToUpper(strings.TrimSpace(input.Method))
	for routeID, routeNode := range snap.graph.ProviderEndpoints {
		schemaNode, ok := snap.graph.StogasEndpoints[routeNode.StogasEndpointID]
		if !ok || schemaNode.Schema.Path != normalizedPath {
			continue
		}
		if strings.ToUpper(schemaNode.Schema.Method) != normalizedMethod {
			return "", compiledProviderEndpoint{}, compiledStogasEndpoint{}, false
		}
		return publicRouteName(routeID, routeNode.ProviderID), routeNode, schemaNode, true
	}
	return "", compiledProviderEndpoint{}, compiledStogasEndpoint{}, false
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

func filterRequestExtraParams(body []byte, provider schemas.ModelProvider, model string, route Route, parameters map[string]compiledParameter) (map[string]interface{}, error) {
	knownFields := knownFields(parameters)
	if len(knownFields) == 0 {
		return nil, ErrCatalogUnavailable
	}
	extraParams, err := extractExtraParams(body, knownFields)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	return FilterExtraParams(provider, model, route, extraParams), nil
}

func extractExtraParams(data []byte, knownFields map[string]bool) (map[string]interface{}, error) {
	var rawData map[string]json.RawMessage
	if err := sonic.Unmarshal(data, &rawData); err != nil {
		return nil, err
	}

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
	return extraParams, nil
}

func allowedParameterNames(parameters map[string]compiledParameter, extraParams map[string]interface{}) []string {
	names := make([]string, 0, len(parameters)+len(extraParams))
	for name := range parameters {
		names = append(names, name)
	}
	for name := range extraParams {
		names = append(names, name)
	}
	return stableStrings(names)
}

func knownFields(parameters map[string]compiledParameter) map[string]bool {
	fields := make(map[string]bool, len(parameters))
	for name := range parameters {
		fields[name] = true
	}
	return fields
}

func applyChatAliases(request *openaiprovider.OpenAIChatRequest, parameters map[string]compiledParameter) {
	aliasTarget, ok := parameterAlias(parameters["max_tokens"])
	if !ok || aliasTarget != "max_completion_tokens" {
		return
	}
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
