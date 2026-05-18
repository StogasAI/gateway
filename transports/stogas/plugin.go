package stogas

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

const Name = "stogas"

const maxAuthorizeRequestIDAttempts = 3

type contextKey string

const (
	apiKeyContextKey        contextKey = "stogas.api_key"
	holdContextKey          contextKey = "stogas.hold"
	holdFinalizedContextKey contextKey = "stogas.hold_finalized"
	holdReleasedContextKey  contextKey = "stogas.hold_released"
	requestModelContextKey  contextKey = "stogas.request_model"
	requestStartContextKey  contextKey = "stogas.request_start"
	requestTypeContextKey   contextKey = "stogas.request_type"
)

type Plugin struct {
	holds holdAuthorizer
}

type holdAuthorizer interface {
	AuthorizePlaceholderHold(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string) (*HoldAuthorization, error)
	FinalizePlaceholderHold(ctx context.Context, authorization *HoldAuthorization, event GatewayRequestEvent) error
	ReleaseHold(ctx context.Context, authorization *HoldAuthorization) error
}

func NewPlugin(holds *HoldService) *Plugin {
	return &Plugin{holds: holds}
}

func (p *Plugin) GetName() string {
	return Name
}

func (p *Plugin) Cleanup() error {
	return nil
}

func (p *Plugin) PreLLMHook(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
	if req == nil {
		return req, errorShortCircuit(400, "invalid_request_error", "Request is required"), nil
	}

	provider, model, fallbacks := req.GetRequestFields()
	ctx.SetValue(requestStartContextKey, time.Now().UTC())
	ctx.SetValue(requestTypeContextKey, string(req.RequestType))
	ctx.SetValue(requestModelContextKey, model)
	if !resolveCatalogModel(provider, model) {
		return req, errorShortCircuit(400, "invalid_request_error", "Model is not available"), nil
	}
	for _, fallback := range fallbacks {
		if !resolveCatalogModel(fallback.Provider, fallback.Model) {
			return req, errorShortCircuit(400, "invalid_request_error", "Fallback model is not available"), nil
		}
	}

	switch req.RequestType {
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest,
		schemas.ResponsesRequest, schemas.ResponsesStreamRequest:
	default:
		return req, errorShortCircuit(400, "invalid_request_error", fmt.Sprintf("Unsupported request type: %s", req.RequestType)), nil
	}

	rawAPIKey, ok := APIKey(ctx)
	if !ok {
		return req, errorShortCircuit(401, "authentication_error", "Missing API key bearer token"), nil
	}

	requestID, ok := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if !ok || requestID == "" {
		return req, errorShortCircuit(500, "internal_error", "Missing request ID"), nil
	}

	authorization, err := p.holds.AuthorizePlaceholderHold(ctx, rawAPIKey, requestID, string(provider), model)
	if err != nil {
		authorization, err = p.authorizeWithFreshRequestID(ctx, rawAPIKey, requestID, string(provider), model, err)
	}
	if err != nil {
		return req, holdErrorShortCircuit(err), nil
	}

	setHoldAuthorization(ctx, authorization)
	return req, nil, nil
}

func (p *Plugin) PostLLMHook(ctx *schemas.BifrostContext, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	authorization, ok := holdAuthorization(ctx)
	if !ok {
		return resp, bifrostErr, nil
	}

	if contextBool(ctx, holdFinalizedContextKey) || contextBool(ctx, holdReleasedContextKey) {
		return resp, bifrostErr, nil
	}

	if bifrostErr == nil && isStreamingContext(ctx) && !contextBool(ctx, schemas.BifrostContextKeyStreamEndIndicator) {
		return resp, bifrostErr, nil
	}

	ctx.SetValue(holdFinalizedContextKey, true)
	metrics := usageMetrics(resp)
	event := gatewayRequestEvent(ctx, authorization, resp, bifrostErr, metrics)
	if err := p.holds.FinalizePlaceholderHold(context.WithoutCancel(ctx), authorization, event); err != nil {
		fmt.Printf("stogas billing settlement scheduling failed: request_id=%s err=%v\n", authorization.RequestID, err)
	}
	return resp, bifrostErr, nil
}

func gatewayRequestEvent(ctx *schemas.BifrostContext, authorization *HoldAuthorization, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError, metrics map[string]any) GatewayRequestEvent {
	startedAt, _ := ctx.Value(requestStartContextKey).(time.Time)
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	createdAt := startedAt
	if !authorization.CreatedAt.IsZero() {
		createdAt = authorization.CreatedAt
	}
	totalTimeMS := uint32Duration(time.Since(startedAt))
	upstreamTimeMS := totalTimeMS
	if extra := responseExtraFields(resp); extra != nil && extra.Latency > 0 {
		upstreamTimeMS = uint32FromInt64(extra.Latency)
	}

	requestType, _ := ctx.Value(requestTypeContextKey).(string)
	model, _ := ctx.Value(requestModelContextKey).(string)
	upstreamStatus := normalizeUpstreamStatus(bifrostErr)
	statusCode := providerStatusCode(bifrostErr)

	return GatewayRequestEvent{
		RequestID:                    authorization.RequestID,
		CreatedAt:                    createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		StogasAPIKeyID:               authorization.KeyID,
		RequestType:                  normalizeRequestType(requestType),
		ProviderAttempts:             []ProviderAttempt{{Provider: authorization.ProviderKey, Status: upstreamStatus, StatusCode: statusCode, LatencyMS: upstreamTimeMS, ProviderTTFBMS: nil, IsBYOK: false}},
		StogasProcessingSuccess:      true,
		StogasBillingStatus:          settlementStatus(authorization, placeholderChargeUsdAtoms),
		UpstreamProviderFinishReason: finishReason(resp),
		ProviderRequestID:            upstreamRequestID(resp),
		TotalTimeMS:                  totalTimeMS,
		UpstreamProviderTimeMS:       upstreamTimeMS,
		TTFBMS:                       0,
		TotalCostUSDAtoms:            placeholderChargeUsdAtoms,
		Metrics:                      metricsObject(model, metrics),
	}
}

func providerStatusCode(bifrostErr *schemas.BifrostError) *int {
	if bifrostErr == nil {
		status := 200
		return &status
	}
	if bifrostErr.StatusCode == nil {
		return nil
	}
	status := *bifrostErr.StatusCode
	return &status
}

func normalizeUpstreamStatus(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil {
		return "success"
	}

	statusCode := 0
	if bifrostErr.StatusCode != nil {
		statusCode = *bifrostErr.StatusCode
	}
	text := strings.ToLower(errorText(bifrostErr))

	switch {
	case strings.Contains(text, "content_filter") ||
		strings.Contains(text, "content filter") ||
		strings.Contains(text, "safety") ||
		strings.Contains(text, "policy"):
		return "content_filter"
	case statusCode == 429 || strings.Contains(text, "rate limit") || strings.Contains(text, "rate_limit"):
		return "rate_limited"
	case statusCode == 402 ||
		strings.Contains(text, "budget") ||
		strings.Contains(text, "quota") ||
		strings.Contains(text, "insufficient_quota"):
		return "over_budget"
	case statusCode == 400 || statusCode == 404 || statusCode == 422:
		return "invalid_request"
	case statusCode == 408 || statusCode == 504 ||
		strings.Contains(text, "timeout") ||
		strings.Contains(text, "timed out") ||
		strings.Contains(text, "connection") ||
		strings.Contains(text, "network") ||
		strings.Contains(text, "eof"):
		return "network_error"
	default:
		return "provider_error"
	}
}

func errorText(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil {
		return ""
	}
	parts := []string{}
	if bifrostErr.Type != nil {
		parts = append(parts, *bifrostErr.Type)
	}
	if bifrostErr.Error != nil {
		if bifrostErr.Error.Type != nil {
			parts = append(parts, *bifrostErr.Error.Type)
		}
		if bifrostErr.Error.Code != nil {
			parts = append(parts, *bifrostErr.Error.Code)
		}
		parts = append(parts, bifrostErr.Error.Message)
		if bifrostErr.Error.Error != nil {
			parts = append(parts, bifrostErr.Error.Error.Error())
		}
	}
	return strings.Join(parts, " ")
}

func normalizeRequestType(requestType string) string {
	switch requestType {
	case string(schemas.ChatCompletionRequest):
		return "chat_completion_request"
	case string(schemas.ResponsesRequest):
		return "responses_request"
	default:
		return requestType
	}
}

func metricsObject(model string, usage map[string]any) map[string]any {
	tokens := map[string]any{
		"prompt":     numberMetric(usage, "promptTokens"),
		"completion": numberMetric(usage, "completionTokens"),
		"reasoning":  nil,
		"cached":     nil,
	}
	return map[string]any{
		"model":  model,
		"tokens": tokens,
	}
}

func numberMetric(metrics map[string]any, key string) any {
	value, ok := metrics[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return typed
	case uint:
		return typed
	case uint64:
		return typed
	case float64:
		return typed
	default:
		return 0
	}
}

func (p *Plugin) authorizeWithFreshRequestID(ctx *schemas.BifrostContext, rawAPIKey string, requestID string, provider string, model string, authorizeErr error) (*HoldAuthorization, error) {
	if ErrorStatus(authorizeErr) != 409 {
		return nil, authorizeErr
	}

	for attempt := 1; attempt < maxAuthorizeRequestIDAttempts; attempt++ {
		nextRequestID, idErr := newUUIDV7String()
		if idErr != nil {
			return nil, fmt.Errorf("generate retry request id: %w", idErr)
		}
		requestID = nextRequestID
		ctx.SetValue(schemas.BifrostContextKeyRequestID, requestID)

		authorization, err := p.holds.AuthorizePlaceholderHold(ctx, rawAPIKey, requestID, provider, model)
		if err == nil {
			return authorization, nil
		}
		if ErrorStatus(err) != 409 {
			return nil, err
		}
		authorizeErr = err
	}

	return nil, authorizeErr
}

func SetAPIKey(ctx *schemas.BifrostContext, apiKey string) {
	if ctx == nil {
		return
	}
	ctx.SetValue(apiKeyContextKey, apiKey)
}

func APIKey(ctx *schemas.BifrostContext) (string, bool) {
	if ctx == nil {
		return "", false
	}
	apiKey, ok := ctx.Value(apiKeyContextKey).(string)
	return apiKey, ok && apiKey != ""
}

func holdAuthorization(ctx *schemas.BifrostContext) (*HoldAuthorization, bool) {
	if ctx == nil {
		return nil, false
	}
	authorization, ok := ctx.Value(holdContextKey).(*HoldAuthorization)
	return authorization, ok && authorization != nil
}

func setHoldAuthorization(ctx *schemas.BifrostContext, authorization *HoldAuthorization) {
	if ctx == nil || authorization == nil {
		return
	}
	ctx.SetValue(holdContextKey, authorization)
}

func contextBool(ctx *schemas.BifrostContext, key any) bool {
	if ctx == nil {
		return false
	}
	value, ok := ctx.Value(key).(bool)
	return ok && value
}

func isStreamingContext(ctx *schemas.BifrostContext) bool {
	return ctx != nil && ctx.Value(schemas.BifrostContextKeyStreamStartTime) != nil
}

func usageMetrics(resp *schemas.BifrostResponse) map[string]any {
	metrics := map[string]any{}
	usage := llmUsage(resp)
	if usage == nil {
		return metrics
	}
	metrics["promptTokens"] = usage.PromptTokens
	metrics["completionTokens"] = usage.CompletionTokens
	metrics["totalTokens"] = usage.TotalTokens
	return metrics
}

func llmUsage(resp *schemas.BifrostResponse) *schemas.BifrostLLMUsage {
	if resp == nil {
		return nil
	}
	if resp.ChatResponse != nil {
		return resp.ChatResponse.Usage
	}
	if resp.TextCompletionResponse != nil {
		return resp.TextCompletionResponse.Usage
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.Usage != nil {
		return resp.ResponsesResponse.Usage.ToBifrostLLMUsage()
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.Usage != nil {
		return resp.ResponsesStreamResponse.Response.Usage.ToBifrostLLMUsage()
	}
	return nil
}

func responseExtraFields(resp *schemas.BifrostResponse) *schemas.BifrostResponseExtraFields {
	if resp == nil {
		return nil
	}
	return resp.GetExtraFields()
}

func finishReason(resp *schemas.BifrostResponse) string {
	if resp == nil {
		return ""
	}
	choices := []schemas.BifrostResponseChoice{}
	if resp.ChatResponse != nil {
		choices = resp.ChatResponse.Choices
	} else if resp.TextCompletionResponse != nil {
		choices = resp.TextCompletionResponse.Choices
	}
	for _, choice := range choices {
		if choice.FinishReason != nil {
			return *choice.FinishReason
		}
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.StopReason != nil {
		return *resp.ResponsesResponse.StopReason
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.StopReason != nil {
		return *resp.ResponsesStreamResponse.Response.StopReason
	}
	return ""
}

func upstreamRequestID(resp *schemas.BifrostResponse) string {
	if resp == nil {
		return ""
	}
	if resp.ChatResponse != nil {
		return resp.ChatResponse.ID
	}
	if resp.TextCompletionResponse != nil {
		return resp.TextCompletionResponse.ID
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.ID != nil {
		return *resp.ResponsesResponse.ID
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.ID != nil {
		return *resp.ResponsesStreamResponse.Response.ID
	}
	return ""
}

func uint32Duration(value time.Duration) uint32 {
	if value <= 0 {
		return 0
	}
	return uint32FromInt64(value.Milliseconds())
}

func uint32FromInt64(value int64) uint32 {
	if value <= 0 {
		return 0
	}
	if value > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}

func errorShortCircuit(statusCode int, errorType string, message string) *schemas.LLMPluginShortCircuit {
	status := statusCode
	return &schemas.LLMPluginShortCircuit{
		Error: &schemas.BifrostError{
			Error:          &schemas.ErrorField{Message: message, Type: schemas.Ptr(errorType)},
			IsBifrostError: true,
			StatusCode:     &status,
		},
	}
}

func holdErrorShortCircuit(err error) *schemas.LLMPluginShortCircuit {
	statusCode := ErrorStatus(err)
	errorType := "internal_error"
	switch statusCode {
	case 400:
		errorType = "invalid_request_error"
	case 401:
		errorType = "authentication_error"
	case 402, 403:
		errorType = "permission_denied"
	case 409:
		errorType = "invalid_request_error"
	case 429:
		errorType = "rate_limit_error"
	case 503:
		errorType = "gateway_error"
	}

	message := err.Error()
	if errors.Is(err, ErrInvalidAPIKey) {
		message = "Invalid API key"
	}

	return errorShortCircuit(statusCode, errorType, message)
}

func billingBifrostError(err error) *schemas.BifrostError {
	status := 500
	allowFallbacks := false
	return &schemas.BifrostError{
		AllowFallbacks: &allowFallbacks,
		Error: &schemas.ErrorField{
			Message: fmt.Sprintf("Billing settlement failed: %s", err.Error()),
			Type:    schemas.Ptr("internal_error"),
		},
		IsBifrostError: true,
		StatusCode:     &status,
	}
}
