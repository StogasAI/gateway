package stogas

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/apikey"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const Name = "stogas"

const maxAuthorizeRequestIDAttempts = 3

type contextKey string

const (
	apiKeyContextKey            contextKey = "stogas.api_key"
	apiKeyClaimsContextKey      contextKey = "stogas.api_key_claims"
	billingContextKey           contextKey = "stogas.billing_authorization"
	billingFinalizedContextKey  contextKey = "stogas.billing_finalized"
	catalogResolutionContextKey contextKey = "stogas.catalog_resolution"
	requestModelContextKey      contextKey = "stogas.request_model"
	requestStartContextKey      contextKey = "stogas.request_start"
	requestTypeContextKey       contextKey = "stogas.request_type"
)

type Plugin struct {
	billing billingAuthorizer
}

type billingAuthorizer interface {
	AuthorizeRequest(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string) (*BillingAuthorization, error)
	FinalizeRequest(ctx context.Context, authorization *BillingAuthorization, event GatewayRequestEvent) error
}

func NewPlugin(billing *BillingService) *Plugin {
	return &Plugin{billing: billing}
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

	resolution := catalogResolution(ctx)
	if resolution == nil {
		var err error
		resolution, err = catalog.CheckBifrostRequest(req.RequestType, req)
		if err != nil {
			return req, catalogErrorShortCircuit(err), nil
		}
	}
	ctx.SetValue(requestStartContextKey, time.Now().UTC())
	ctx.SetValue(requestTypeContextKey, string(req.RequestType))
	ctx.SetValue(requestModelContextKey, resolution.Model)
	ctx.SetValue(catalogResolutionContextKey, resolution)

	rawAPIKey, ok := APIKey(ctx)
	if !ok {
		return req, errorShortCircuit(401, "authentication_error", "Missing API key bearer token"), nil
	}

	requestID, ok := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if !ok || requestID == "" {
		return req, errorShortCircuit(500, "internal_error", "Missing request ID"), nil
	}

	authorization, err := p.billing.AuthorizeRequest(ctx, rawAPIKey, requestID, resolution.Hold.ProviderKey, resolution.Hold.ProductKey, resolution.Hold.MaxUSDAtoms)
	if err != nil {
		authorization, err = p.authorizeWithFreshRequestID(ctx, rawAPIKey, requestID, resolution.Hold, err)
	}
	if err != nil {
		return req, billingErrorShortCircuit(err), nil
	}

	setBillingAuthorization(ctx, authorization)
	SeedBifrostModelParams(resolution)
	return req, nil, nil
}

func (p *Plugin) PostLLMHook(ctx *schemas.BifrostContext, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	authorization, ok := billingAuthorization(ctx)
	if !ok {
		return resp, bifrostErr, nil
	}

	if contextBool(ctx, billingFinalizedContextKey) {
		return resp, bifrostErr, nil
	}

	if bifrostErr == nil && isStreamingContext(ctx) && !contextBool(ctx, schemas.BifrostContextKeyStreamEndIndicator) {
		return resp, bifrostErr, nil
	}

	ctx.SetValue(billingFinalizedContextKey, true)
	metrics := usageMetrics(resp)
	actualCost := finalSettlementCost(ctx, authorization, resp, bifrostErr)
	event := gatewayRequestEvent(ctx, authorization, resp, bifrostErr, metrics, actualCost)
	if err := p.billing.FinalizeRequest(context.WithoutCancel(ctx), authorization, event); err != nil {
		fmt.Printf("stogas billing settlement scheduling failed: request_id=%s err=%v\n", authorization.RequestID, err)
	}
	return resp, bifrostErr, nil
}

func finalSettlementCost(ctx *schemas.BifrostContext, authorization *BillingAuthorization, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) string {
	if usage := llmUsage(resp); usage != nil {
		return catalog.SettlementCost(catalogResolution(ctx), usage)
	}
	if bifrostErr == nil || providerErrorIsInsured(bifrostErr) {
		return "0"
	}
	if authorization != nil && authorization.AuthorizedAmount != nil {
		return authorization.AuthorizedAmount.String()
	}
	return "0"
}

func providerErrorIsInsured(bifrostErr *schemas.BifrostError) bool {
	switch normalizeUpstreamStatus(bifrostErr) {
	case "network_error", "provider_error", "rate_limited", "over_budget":
		return true
	default:
		return false
	}
}

func catalogResolution(ctx *schemas.BifrostContext) *catalog.ResolvedRequest {
	if ctx == nil {
		return nil
	}
	resolution, _ := ctx.Value(catalogResolutionContextKey).(*catalog.ResolvedRequest)
	return resolution
}

func SetCatalogResolution(ctx *schemas.BifrostContext, resolution *catalog.ResolvedRequest) {
	if ctx == nil || resolution == nil {
		return
	}
	ctx.SetValue(catalogResolutionContextKey, resolution)
}

func (p *Plugin) authorizeWithFreshRequestID(ctx *schemas.BifrostContext, rawAPIKey string, requestID string, hold catalog.HoldEstimate, authorizeErr error) (*BillingAuthorization, error) {
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

		authorization, err := p.billing.AuthorizeRequest(ctx, rawAPIKey, requestID, hold.ProviderKey, hold.ProductKey, hold.MaxUSDAtoms)
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

func SetAPIKey(ctx *schemas.BifrostContext, apiKey string, claims *apikey.Claims) {
	if ctx == nil {
		return
	}
	ctx.SetValue(apiKeyContextKey, apiKey)
	if claims != nil {
		ctx.SetValue(apiKeyClaimsContextKey, claims)
	}
}

func APIKey(ctx *schemas.BifrostContext) (string, bool) {
	if ctx == nil {
		return "", false
	}
	apiKey, ok := ctx.Value(apiKeyContextKey).(string)
	return apiKey, ok && apiKey != ""
}

func APIKeyClaims(ctx *schemas.BifrostContext) (*apikey.Claims, bool) {
	if ctx == nil {
		return nil, false
	}
	claims, ok := ctx.Value(apiKeyClaimsContextKey).(*apikey.Claims)
	return claims, ok && claims != nil
}

func billingAuthorization(ctx *schemas.BifrostContext) (*BillingAuthorization, bool) {
	if ctx == nil {
		return nil, false
	}
	authorization, ok := ctx.Value(billingContextKey).(*BillingAuthorization)
	return authorization, ok && authorization != nil
}

func setBillingAuthorization(ctx *schemas.BifrostContext, authorization *BillingAuthorization) {
	if ctx == nil || authorization == nil {
		return
	}
	ctx.SetValue(billingContextKey, authorization)
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

func catalogErrorShortCircuit(err error) *schemas.LLMPluginShortCircuit {
	apiErr := catalog.PublicError(err)
	return errorShortCircuit(apiErr.StatusCode, apiErr.Type, apiErr.Message)
}

func billingErrorShortCircuit(err error) *schemas.LLMPluginShortCircuit {
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
