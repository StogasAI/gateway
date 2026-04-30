package stogas

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
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
)

type Plugin struct {
	holds holdAuthorizer
}

type holdAuthorizer interface {
	AuthorizePlaceholderHold(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string) (*HoldAuthorization, error)
	FinalizePlaceholderHold(ctx context.Context, authorization *HoldAuthorization, metrics map[string]any) error
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
	if !resolveCatalogModel(provider, model) {
		return req, errorShortCircuit(400, "invalid_request_error", "Model is not available"), nil
	}
	for _, fallback := range fallbacks {
		if !resolveCatalogModel(fallback.Provider, fallback.Model) {
			return req, errorShortCircuit(400, "invalid_request_error", "Fallback model is not available"), nil
		}
	}

	switch req.RequestType {
	case schemas.TextCompletionRequest, schemas.TextCompletionStreamRequest,
		schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest,
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

	if bifrostErr != nil {
		if !contextBool(ctx, holdReleasedContextKey) && !contextBool(ctx, holdFinalizedContextKey) {
			ctx.SetValue(holdReleasedContextKey, true)
			if err := p.holds.ReleaseHold(context.WithoutCancel(ctx), authorization); err != nil {
				return resp, billingBifrostError(err), nil
			}
		}
		return resp, bifrostErr, nil
	}

	if contextBool(ctx, holdFinalizedContextKey) || contextBool(ctx, holdReleasedContextKey) {
		return resp, bifrostErr, nil
	}

	if isStreamingContext(ctx) && !contextBool(ctx, schemas.BifrostContextKeyStreamEndIndicator) {
		return resp, bifrostErr, nil
	}

	ctx.SetValue(holdFinalizedContextKey, true)
	if err := p.holds.FinalizePlaceholderHold(context.WithoutCancel(ctx), authorization, usageMetrics(resp)); err != nil {
		return resp, billingBifrostError(err), nil
	}
	return resp, bifrostErr, nil
}

func (p *Plugin) authorizeWithFreshRequestID(ctx *schemas.BifrostContext, rawAPIKey string, requestID string, provider string, model string, authorizeErr error) (*HoldAuthorization, error) {
	if ErrorStatus(authorizeErr) != 409 {
		return nil, authorizeErr
	}

	for attempt := 1; attempt < maxAuthorizeRequestIDAttempts; attempt++ {
		requestID = uuid.NewString()
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
