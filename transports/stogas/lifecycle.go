package stogas

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
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
	AuthorizeRequestWithPassthrough(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, estimatedUpstreamCostUSDAtoms string, passthroughSecret string, upstreamTarget *gatewaybilling.UpstreamTarget, requestLifetime time.Duration, singleUse bool) (*gatewaybilling.Authorization, error)
	AuthorizeDashboardRequestWithDuration(ctx context.Context, credential *gatewaybilling.DashboardCredential, requestID string, providerKey string, productKey string, estimatedUpstreamCostUSDAtoms string, upstreamTarget *gatewaybilling.UpstreamTarget, requestLifetime time.Duration) (*gatewaybilling.Authorization, error)
	FinalizeRequest(ctx context.Context, authorization *gatewaybilling.Authorization, event gatewaybilling.RequestEvent) error
}

type passthroughDashboardError struct{}

func (passthroughDashboardError) Error() string {
	return "Pass-through BYOK requires a standard Stogas API key"
}

func (passthroughDashboardError) StatusCode() int {
	return 400
}

func PublicBillingErrorFor(err error) PublicBillingError {
	statusCode := gatewaybilling.ErrorStatus(err)
	errorType := "internal_error"
	switch statusCode {
	case 400:
		errorType = "invalid_request_error"
	case 401:
		errorType = "authentication_error"
	case 402:
		errorType = "billing_error"
	case 403:
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
	passthroughSecret := state.PassthroughByokSecret
	defer func() {
		state.PassthroughByokSecret = ""
	}()
	if state.StartedAt.IsZero() {
		state.StartedAt = time.Now()
	}
	state.RequestType = string(state.Resolution.RequestType)
	state.Model = state.Resolution.Model

	if state.RawAPIKey == "" && state.DashboardCredential == nil {
		return gatewaybilling.ErrInvalidAPIKey
	}
	requestID, ok := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if !ok || requestID == "" {
		return fmt.Errorf("missing request ID")
	}
	hold := state.Hold
	if hold.EstimatedUpstreamCostUSDAtoms == "" {
		var holdErr error
		hold, holdErr = baseHoldEstimate(state)
		if holdErr != nil {
			return holdErr
		}
		state.Hold = hold
	}

	var authorization *gatewaybilling.Authorization
	var err error
	upstreamTarget := billingUpstreamTarget(state.Resolution)
	if state.DashboardCredential != nil {
		if passthroughSecret != "" {
			return passthroughDashboardError{}
		}
		authorization, err = billing.AuthorizeDashboardRequestWithDuration(
			ctx,
			state.DashboardCredential,
			requestID,
			hold.ProviderKey,
			hold.ProductKey,
			hold.EstimatedUpstreamCostUSDAtoms,
			upstreamTarget,
			state.RequestLifetime,
		)
	} else {
		authorization, err = billing.AuthorizeRequestWithPassthrough(ctx, state.RawAPIKey, requestID, hold.ProviderKey, hold.ProductKey, hold.EstimatedUpstreamCostUSDAtoms, passthroughSecret, upstreamTarget, state.RequestLifetime, state.SingleUseRequestID)
	}
	if err != nil && authorization != nil {
		state.Authorization = authorization
		return err
	}
	if err != nil && !state.SingleUseRequestID {
		authorization, err = authorizeWithFreshRequestID(ctx, billing, state.RawAPIKey, hold, passthroughSecret, upstreamTarget, state.RequestLifetime, err)
	}
	if err != nil {
		return err
	}
	state.Authorization = authorization
	return nil
}

func billingUpstreamTarget(resolution *catalog.ResolvedRequest) *gatewaybilling.UpstreamTarget {
	if resolution == nil || resolution.Provider != schemas.Azure {
		return nil
	}
	upstream := resolution.Deployment.Upstream
	return &gatewaybilling.UpstreamTarget{
		DeploymentType:     upstream.DeploymentType,
		Hosting:            upstream.Hosting,
		Model:              upstream.Model,
		ModelFormat:        upstream.ModelFormat,
		ModelVersion:       upstream.ModelVersion,
		ProcessingLocation: resolution.Deployment.DataHandling.ProcessingLocation,
		StorageLocation:    resolution.Deployment.DataHandling.StorageLocation,
	}
}

// ApplyUpstreamCredentials installs the request-scoped provider credential and
// binds provider-owned target names before the provider body is serialized.
func ApplyUpstreamCredentials(
	ctx *schemas.BifrostContext,
	state *State,
) error {
	if ctx == nil || state == nil || state.Authorization == nil || state.Resolution == nil {
		return gatewaybilling.ErrByok
	}
	authorization := state.Authorization
	managed := authorization.UpstreamByok == gatewaybilling.ManagedUpstreamByok
	if managed && state.Resolution.Provider != catalog.ProviderChutes {
		return gatewaybilling.ErrByokRequired
	}
	if !managed {
		if authorization.UpstreamByok == "" || authorization.UpstreamByokSecret == "" {
			return gatewaybilling.ErrByok
		}
		if state.Resolution.Provider != schemas.Azure && !validUpstreamAPIKey(authorization.UpstreamByokSecret) {
			return gatewaybilling.ErrByok
		}
		credentialID := authorization.UpstreamByok
		if credentialID == "" {
			return gatewaybilling.ErrByok
		}
		directKey := schemas.Key{
			ID:      credentialID,
			Name:    credentialID,
			Value:   *schemas.NewSecretVar(authorization.UpstreamByokSecret),
			Models:  schemas.WhiteList{"*"},
			Weight:  1,
			Enabled: schemas.Ptr(true),
		}
		if state.Resolution.Provider == schemas.Azure {
			var err error
			var deploymentName string
			directKey, deploymentName, err = azureDirectKey(authorization, state.Resolution)
			if err != nil {
				return err
			}
			if err := state.Resolution.SetWireModel(deploymentName); err != nil {
				return gatewaybilling.ErrByok
			}
		}
		ctx.SetValue(schemas.BifrostContextKeyDirectKey, directKey)
	}
	return nil
}

func FinalizeState(ctx context.Context, billing billingAuthorizer, state *State) {
	if billing == nil || state == nil || state.Authorization == nil || state.BillingFinalized {
		return
	}
	state.BillingFinalized = true
	event := PrepareFinalState(state)
	if event == nil {
		return
	}
	if err := billing.FinalizeRequest(context.WithoutCancel(ctx), state.Authorization, *event); err != nil {
		writeOperationalLog(operationalLogEvent{
			ErrorType:  safeOperationalErrorType(err),
			Event:      "billing_settlement_schedule_failed",
			ReasonCode: "finalization_failed",
			RequestID:  state.Authorization.RequestID,
			Severity:   "error",
		})
	}
}

// PrepareFinalState captures the upstream cost and request timing once. The same
// immutable values are used by the signed response proof and billing telemetry.
func PrepareFinalState(state *State) *gatewaybilling.RequestEvent {
	if state == nil || state.Authorization == nil {
		return nil
	}
	if state.FinalEvent != nil {
		return state.FinalEvent
	}
	pricingFailed := false
	if state.UpstreamCostUSDAtoms == "" {
		adapter := state.Adapter
		if adapter == nil {
			adapter = DefaultAdapter{}
		}
		if err := adapter.CalculateUpstreamCost(state); err != nil {
			markFinalPricingFailure(state, err)
			pricingFailed = true
		}
	}
	if !pricingFailed {
		if err := validateCanonicalMeterSummary(
			state.FinalMeters,
			effectivePricingForState(state),
			state.UpstreamCostUSDAtoms,
		); err != nil {
			markFinalPricingFailure(state, err)
			pricingFailed = true
		}
	}
	if discardUpstreamCostOutsideHold(state) {
		pricingFailed = true
	}
	var cacheSavings *string
	var cacheWriteOverhead *string
	if !pricingFailed {
		var cacheSavingsErr error
		cacheSavings, cacheSavingsErr = cacheReadSavingsUSDAtoms(state)
		if cacheSavingsErr != nil {
			writeOperationalLog(operationalLogEvent{
				ErrorType:  safeOperationalErrorType(cacheSavingsErr),
				Event:      "cache_read_savings_projection_failed",
				ReasonCode: "cache_read_savings_unavailable",
				RequestID:  state.Authorization.RequestID,
				Severity:   "warning",
			})
		}
		var cacheWriteOverheadErr error
		cacheWriteOverhead, cacheWriteOverheadErr = cacheWriteOverheadUSDAtoms(state)
		if cacheWriteOverheadErr != nil {
			writeOperationalLog(operationalLogEvent{
				ErrorType:  safeOperationalErrorType(cacheWriteOverheadErr),
				Event:      "cache_write_overhead_projection_failed",
				ReasonCode: "cache_write_overhead_unavailable",
				RequestID:  state.Authorization.RequestID,
				Severity:   "warning",
			})
		}
	}
	catalogIdentity := state.Resolution.CatalogIdentity()
	executionDeployment := ExecutionDeployment(state)
	event, err := gatewaybilling.NewRequestEvent(gatewaybilling.EventInput{
		UpstreamCostUSDAtoms:       state.UpstreamCostUSDAtoms,
		Authorization:              state.Authorization,
		Cancelled:                  state.Cancelled,
		ClientStoppedAt:            state.ClientStoppedAt,
		CatalogDigest:              catalogIdentity.Digest,
		Error:                      state.BifrostError,
		Pricing:                    pricingForState(state),
		Plugins:                    state.PluginMetrics,
		ProviderAttempts:           state.providerAttemptInputs(),
		ProviderCompletedAt:        state.ProviderCompletedAt,
		ProviderStartedAt:          state.ProviderStartedAt,
		TTFTMS:                     state.TTFTMS,
		ProviderOutputObserved:     state.ProviderOutputObserved,
		CacheReadSavingsUSDAtoms:   cacheSavings,
		CacheWriteOverheadUSDAtoms: cacheWriteOverhead,
		NodeID:                     state.NodeID,
		GatewayVersion:             state.GatewayVersion,
		RequestType:                state.RequestType,
		CatalogNodeIDs:             state.Resolution.CatalogNodeIDsForDeployment(executionDeployment),
		Response:                   state.Response,
		StartedAt:                  state.StartedAt,
	})
	if err != nil {
		markFinalPricingFailure(state, err)
		pricingFailed = true
		event, err = gatewaybilling.NewRequestEvent(gatewaybilling.EventInput{
			UpstreamCostUSDAtoms:   gatewaybilling.ZeroChargeUSDAtoms,
			Authorization:          state.Authorization,
			Cancelled:              state.Cancelled,
			ClientStoppedAt:        state.ClientStoppedAt,
			CatalogDigest:          catalogIdentity.Digest,
			Error:                  state.BifrostError,
			ProviderAttempts:       state.providerAttemptInputs(),
			Plugins:                state.PluginMetrics,
			ProviderCompletedAt:    state.ProviderCompletedAt,
			ProviderStartedAt:      state.ProviderStartedAt,
			TTFTMS:                 state.TTFTMS,
			ProviderOutputObserved: state.ProviderOutputObserved,
			NodeID:                 state.NodeID,
			GatewayVersion:         state.GatewayVersion,
			RequestType:            state.RequestType,
			CatalogNodeIDs:         state.Resolution.CatalogNodeIDsForDeployment(executionDeployment),
			Response:               state.Response,
			StartedAt:              state.StartedAt,
		})
		if err != nil {
			return nil
		}
	}
	if pricingFailed {
		event.StogasProcessingSuccess = false
	}
	state.FinalEvent = &event
	return state.FinalEvent
}

func markFinalPricingFailure(state *State, err error) {
	writeOperationalLog(operationalLogEvent{
		ErrorType:  safeOperationalErrorType(err),
		Event:      "billing_final_price_failed",
		ReasonCode: "price_calculation_failed",
		RequestID:  state.Authorization.RequestID,
		Severity:   "error",
	})
	statusCode := 500
	errorType := "internal_error"
	code := "billing_price_invalid"
	allowFallbacks := false
	state.BifrostError = &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &statusCode,
		Type:           &errorType,
		AllowFallbacks: &allowFallbacks,
		Error: &schemas.ErrorField{
			Type:    &errorType,
			Code:    &code,
			Message: "Internal server error",
		},
	}
	state.Signals = nil
	state.FinalMeters = nil
	state.UpstreamCostUSDAtoms = gatewaybilling.ZeroChargeUSDAtoms
}

func discardUpstreamCostOutsideHold(state *State) bool {
	if state == nil || state.UpstreamCostUSDAtoms == "" {
		return false
	}
	estimatedUpstreamCost, estimateOK := new(big.Int).SetString(state.Hold.EstimatedUpstreamCostUSDAtoms, 10)
	upstreamCost, upstreamCostOK := new(big.Int).SetString(state.UpstreamCostUSDAtoms, 10)
	zeroCost := upstreamCostOK && upstreamCost.Sign() == 0 && len(state.FinalMeters) == 0
	costWithinEstimate := estimateOK && upstreamCostOK && estimatedUpstreamCost.Sign() >= 0 && upstreamCost.Sign() > 0 && upstreamCost.Cmp(estimatedUpstreamCost) <= 0 &&
		len(state.FinalMeters) > 0 && finalMeterQuantitiesWithinHold(state.Hold.Meters, state.FinalMeters)
	if zeroCost || costWithinEstimate {
		return false
	}
	requestID := state.RequestID
	if state.Authorization != nil {
		requestID = state.Authorization.RequestID
	}
	writeOperationalLog(operationalLogEvent{
		ErrorType:  "billing_error",
		Event:      "billing_upstream_cost_outside_hold",
		ReasonCode: "upstream_cost_outside_hold",
		RequestID:  requestID,
		Severity:   "error",
	})
	state.Signals = nil
	state.FinalMeters = nil
	state.UpstreamCostUSDAtoms = gatewaybilling.ZeroChargeUSDAtoms
	return true
}

func finalMeterQuantitiesWithinHold(holdMeters []catalog.MeterEstimate, finalMeters []catalog.MeterEstimate) bool {
	capacities := map[string]*big.Int{}
	for _, meter := range holdMeters {
		if !meter.HoldRequired {
			continue
		}
		class, ok := meterQuantityClass(meter.MeterKey)
		quantity, quantityOK := new(big.Int).SetString(meter.Quantity, 10)
		if !ok || !quantityOK || quantity.Sign() < 0 {
			return false
		}
		if capacities[class] == nil {
			capacities[class] = big.NewInt(0)
		}
		capacities[class].Add(capacities[class], quantity)
	}
	used := map[string]*big.Int{}
	for _, meter := range finalMeters {
		class, ok := meterQuantityClass(meter.MeterKey)
		quantity, quantityOK := new(big.Int).SetString(meter.Quantity, 10)
		if !ok || !quantityOK || quantity.Sign() < 0 {
			return false
		}
		if used[class] == nil {
			used[class] = big.NewInt(0)
		}
		used[class].Add(used[class], quantity)
	}
	for class, quantity := range used {
		capacity := capacities[class]
		if capacity == nil || quantity.Cmp(capacity) > 0 {
			return false
		}
	}
	return true
}

func meterQuantityClass(meterKey string) (string, bool) {
	switch {
	case isInputTokenMeter(meterKey):
		return "input_tokens", true
	case isOutputTokenMeter(meterKey):
		return "output_tokens", true
	case strings.TrimSpace(meterKey) != "":
		return "meter:" + meterKey, true
	default:
		return "", false
	}
}

func pricingForState(state *State) gatewaybilling.EventPricing {
	out := gatewaybilling.EventPricing{}
	if state == nil {
		return out
	}
	for _, meter := range state.FinalMeters {
		key := meter.MeterKey
		if existing, ok := out[key]; ok {
			if existing.RateKey != meter.RateKey {
				key = meter.MeterKey + ":" + meter.RateKey
			}
		}
		out[key] = gatewaybilling.EventMeter{
			Quantity:     meter.Quantity,
			RateKey:      meter.RateKey,
			RateUSDAtoms: meter.RateUSDAtoms,
			USDAtoms:     meter.AmountUSDAtoms,
		}
	}
	return out
}

func authorizeWithFreshRequestID(ctx *schemas.BifrostContext, billing billingAuthorizer, rawAPIKey string, hold HoldEstimate, passthroughSecret string, upstreamTarget *gatewaybilling.UpstreamTarget, requestLifetime time.Duration, authorizeErr error) (*gatewaybilling.Authorization, error) {
	if gatewaybilling.ErrorStatus(authorizeErr) != 409 {
		return nil, authorizeErr
	}

	for attempt := 1; attempt < maxAuthorizeRequestIDAttempts; attempt++ {
		nextRequestID, idErr := uuid.NewV7()
		if idErr != nil {
			return nil, fmt.Errorf("generate retry request id: %w", idErr)
		}
		requestID := nextRequestID.String()
		ctx.SetValue(schemas.BifrostContextKeyRequestID, requestID)

		authorization, err := billing.AuthorizeRequestWithPassthrough(ctx, rawAPIKey, requestID, hold.ProviderKey, hold.ProductKey, hold.EstimatedUpstreamCostUSDAtoms, passthroughSecret, upstreamTarget, requestLifetime, false)
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
