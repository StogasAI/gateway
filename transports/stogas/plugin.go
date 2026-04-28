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
	apiKeyContextKey contextKey = "stogas.api_key"
	holdContextKey   contextKey = "stogas.hold"
)

type Plugin struct {
	holds holdAuthorizer
}

type holdAuthorizer interface {
	AuthorizePlaceholderHold(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string) (*HoldAuthorization, error)
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

func setHoldAuthorization(ctx *schemas.BifrostContext, authorization *HoldAuthorization) {
	if ctx == nil || authorization == nil {
		return
	}
	ctx.SetValue(holdContextKey, authorization)
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
