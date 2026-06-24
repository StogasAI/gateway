package stogas

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	gatewaybilling "github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const maxAuthorizeRequestIDAttempts = 3

type PublicBillingError struct {
	StatusCode int
	Type       string
	Message    string
}

type billingAuthorizer interface {
	AuthorizeRequest(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string) (*gatewaybilling.Authorization, error)
	AuthorizeRequestWithDuration(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string, requestLifetime time.Duration) (*gatewaybilling.Authorization, error)
	FinalizeRequest(ctx context.Context, authorization *gatewaybilling.Authorization, event gatewaybilling.RequestEvent) error
}

func (e PublicBillingError) Error() string {
	return e.Message
}

func PublicBillingErrorFor(err error) PublicBillingError {
	statusCode := gatewaybilling.ErrorStatus(err)
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
	if errors.Is(err, gatewaybilling.ErrInvalidAPIKey) {
		message = "Invalid API key"
	}
	return PublicBillingError{StatusCode: statusCode, Type: errorType, Message: message}
}

func AuthorizeState(ctx *schemas.BifrostContext, billing billingAuthorizer, state *State) error {
	if billing == nil {
		return gatewaybilling.ErrGatewayUnavailable
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	state.StartedAt = time.Now().UTC()
	state.RequestType = string(state.Resolution.RequestType)
	state.Model = state.Resolution.Model

	if state.RawAPIKey == "" {
		return gatewaybilling.ErrInvalidAPIKey
	}
	requestID, ok := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if !ok || requestID == "" {
		return fmt.Errorf("missing request ID")
	}
	hold := state.Hold
	if hold.MaxUSDAtoms == "" {
		hold = baseHoldEstimate(state)
		state.Hold = hold
	}

	authorization, err := billing.AuthorizeRequestWithDuration(ctx, state.RawAPIKey, requestID, hold.ProviderKey, hold.ProductKey, hold.MaxUSDAtoms, state.RequestLifetime)
	if err != nil {
		authorization, err = authorizeWithFreshRequestID(ctx, billing, state.RawAPIKey, requestID, hold, state.RequestLifetime, err)
	}
	if err != nil {
		return err
	}
	state.Authorization = authorization
	SeedBifrostModelParams(state.Resolution)
	return nil
}

func FinalizeState(ctx context.Context, billing billingAuthorizer, state *State) {
	if billing == nil || state == nil || state.Authorization == nil || state.BillingFinalized {
		return
	}
	state.BillingFinalized = true
	if state.FinalCostUSDAtoms == "" {
		adapter := state.Adapter
		if adapter == nil {
			adapter = DefaultAdapter{}
		}
		if err := adapter.FinalPrice(state); err != nil {
			fmt.Printf("stogas final price calculation failed: request_id=%s err=%v\n", state.Authorization.RequestID, err)
		}
	}
	metrics := gatewaybilling.UsageMetrics(state.Response)
	event := gatewaybilling.NewRequestEvent(gatewaybilling.EventInput{
		ActualCostUSDAtoms: state.FinalCostUSDAtoms,
		Authorization:      state.Authorization,
		Error:              state.BifrostError,
		Metrics:            metrics,
		Model:              state.Model,
		RequestType:        state.RequestType,
		Response:           state.Response,
		StartedAt:          state.StartedAt,
	})
	if err := billing.FinalizeRequest(context.WithoutCancel(ctx), state.Authorization, event); err != nil {
		fmt.Printf("stogas billing settlement scheduling failed: request_id=%s err=%v\n", state.Authorization.RequestID, err)
	}
}

func authorizeWithFreshRequestID(ctx *schemas.BifrostContext, billing billingAuthorizer, rawAPIKey string, requestID string, hold HoldEstimate, requestLifetime time.Duration, authorizeErr error) (*gatewaybilling.Authorization, error) {
	if gatewaybilling.ErrorStatus(authorizeErr) != 409 {
		return nil, authorizeErr
	}

	for attempt := 1; attempt < maxAuthorizeRequestIDAttempts; attempt++ {
		nextRequestID, idErr := uuid.NewV7()
		if idErr != nil {
			return nil, fmt.Errorf("generate retry request id: %w", idErr)
		}
		requestID = nextRequestID.String()
		ctx.SetValue(schemas.BifrostContextKeyRequestID, requestID)

		authorization, err := billing.AuthorizeRequestWithDuration(ctx, rawAPIKey, requestID, hold.ProviderKey, hold.ProductKey, hold.MaxUSDAtoms, requestLifetime)
		if err == nil {
			return authorization, nil
		}
		if gatewaybilling.ErrorStatus(err) != 409 {
			return nil, err
		}
		authorizeErr = err
	}

	return nil, authorizeErr
}

// SeedBifrostModelParams supplies Bifrost provider helpers with catalog-owned model limits.
func SeedBifrostModelParams(resolution *catalog.ResolvedRequest) {
	if resolution == nil || resolution.Model == "" || resolution.Deployment.MaxOutputTokens <= 0 {
		return
	}

	maxOutputTokens := resolution.Deployment.MaxOutputTokens
	params, _ := providerUtils.GetModelParams(resolution.Model)
	params.MaxOutputTokens = &maxOutputTokens
	providerUtils.SetModelParams(resolution.Model, params)
}
