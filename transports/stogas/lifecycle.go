package stogas

import (
	"context"
	"errors"
	"fmt"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"strconv"
	"time"

	azureprovider "github.com/maximhq/bifrost/core/providers/azure"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	gatewaybilling "github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

type PublicBillingError struct {
	StatusCode int
	Code       string
	Type       string
	Message    string
}

type billingAuthorizer interface {
	AuthorizeRequestWithEncryptionKeys(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, estimatedUpstreamCostUSD string, usage gatewaybilling.UsageReservation, snapshot *gatewaybilling.KeyConfigSnapshot, prepared *gatewaybilling.PreparedCredential, activeRules []policy.RuleMatch, encryptionKeys customerkey.Keys, upstreamTarget *gatewaybilling.UpstreamTarget, requestLifetime time.Duration, singleUse bool) (*gatewaybilling.Authorization, error)
	AuthorizeDashboardRequestWithDuration(ctx context.Context, credential *gatewaybilling.DashboardCredential, requestID string, providerKey string, productKey string, estimatedUpstreamCostUSD string, usage gatewaybilling.UsageReservation, snapshot *gatewaybilling.KeyConfigSnapshot, prepared *gatewaybilling.PreparedCredential, activeRules []policy.RuleMatch, encryptionKeys customerkey.Keys, upstreamTarget *gatewaybilling.UpstreamTarget, requestLifetime time.Duration) (*gatewaybilling.Authorization, error)
	FinalizeRequest(ctx context.Context, authorization *gatewaybilling.Authorization, event gatewaybilling.RequestEvent, retain gatewaybilling.RetainMemory) error
}

func PublicBillingErrorFor(err error) PublicBillingError {
	if errors.Is(err, context.DeadlineExceeded) {
		return PublicBillingError{504, "request_timeout", schemas.RequestTimedOut, "The request exceeded its time limit."}
	}
	if errors.Is(err, policy.ErrSourceBudget) || errors.Is(err, policy.ErrPolicyWorkLimit) {
		return PublicBillingError{400, "policy_work_limit_exceeded", "invalid_request_error", "The applicable policies exceed the request's policy work limit. Reduce distinct policy content or expressions."}
	}
	if errors.Is(err, policy.ErrInvalidConfig) {
		return PublicBillingError{400, "invalid_request", "invalid_request_error", "The applicable policy configuration is invalid. Review the saved policies and encrypted plugin content."}
	}
	statusCode := gatewaybilling.ErrorStatus(err)
	errorType := "internal_error"
	message := "Internal server error"
	switch statusCode {
	case 400:
		errorType = "invalid_request_error"
		message = "Invalid request"
	case 401:
		errorType = "authentication_error"
		message = "Invalid API key"
	case 402:
		errorType = "billing_error"
		message = "Billing rejected the request"
	case 403:
		errorType = "permission_denied"
		message = "Permission denied"
	case 409:
		errorType = "invalid_request_error"
		message = "Request conflicts with an existing authorization"
	case 429:
		errorType = "rate_limit_error"
		message = "Rate limit exceeded"
	case 503:
		errorType = "gateway_error"
		message = "Stogas is temporarily unavailable. Retry the request later."
	}

	code := errorType
	var requestError *gatewaybilling.RequestError
	if errors.As(err, &requestError) {
		code, message = requestError.Code, requestError.Message
	} else if errors.Is(err, customerkey.ErrKey) {
		code, message = "encryption_key_required", customerkey.ErrKey.Error()
	} else if errors.Is(err, customerkey.ErrEnvelope) {
		code, message = "encrypted_content_invalid", customerkey.ErrEnvelope.Error()
	}
	return PublicBillingError{StatusCode: statusCode, Code: code, Type: errorType, Message: message}
}

func AuthorizeState(ctx *schemas.BifrostContext, billing billingAuthorizer, state *State) error {
	if billing == nil {
		return gatewaybilling.ErrGatewayUnavailable
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	encryptionKeys := state.EncryptionKeys
	defer func() {
		state.EncryptionKeys = nil
		// Routing and credential selection are finished when authorization returns.
		// Long inference streams retain only the selected dispatch credential.
		state.KeyConfig = nil
		state.PreparedCredential.Clear()
		state.PreparedCredential = nil
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
	if hold.EstimatedUpstreamCostUSD == "" {
		var holdErr error
		hold, holdErr = baseHoldEstimate(state)
		if holdErr != nil {
			return holdErr
		}
		state.Hold = hold
	}

	var authorization *gatewaybilling.Authorization
	var err error
	textBytes, _ := state.Resolution.InputTextBytes()
	usage := gatewaybilling.UsageReservation{Tokens: hold.ReservedTokens, InputTextBytes: int64(textBytes)}
	upstreamTarget := billingUpstreamTarget(state.Resolution)
	if state.DashboardCredential != nil {
		authorization, err = billing.AuthorizeDashboardRequestWithDuration(
			ctx,
			state.DashboardCredential,
			requestID,
			hold.ProviderKey,
			hold.ProductKey,
			hold.EstimatedUpstreamCostUSD,
			usage,
			state.KeyConfig,
			state.PreparedCredential,
			state.Resolution.ActivePolicyRules(),
			encryptionKeys,
			upstreamTarget,
			state.RequestLifetime,
		)
	} else {
		authorization, err = billing.AuthorizeRequestWithEncryptionKeys(ctx, state.RawAPIKey, requestID, hold.ProviderKey, hold.ProductKey, hold.EstimatedUpstreamCostUSD, usage, state.KeyConfig, state.PreparedCredential, state.Resolution.ActivePolicyRules(), encryptionKeys, upstreamTarget, state.RequestLifetime, state.SingleUseRequestID)
	}
	if err != nil && authorization != nil {
		state.Authorization = authorization
		return err
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

type azureTokenSource interface {
	Token(context.Context, azureauth.Credential) (string, error)
}

// applyUpstreamCredentials installs the request-scoped provider credential and
// binds provider-owned target names before the provider body is serialized.
func applyUpstreamCredentials(
	ctx *schemas.BifrostContext,
	state *State,
	azureTokens azureTokenSource,
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
			if azureTokens == nil {
				return gatewaybilling.ErrGatewayUnavailable
			}
			azure := directKey.AzureKeyConfig
			token, err := azureTokens.Token(ctx, azureauth.Credential{
				TenantID: azure.TenantID.GetValue(),
				ClientID: azure.ClientID.GetValue(),
				Secret:   azure.ClientSecret.GetValue(),
				Scope:    azure.Scopes[0],
			})
			if err != nil {
				if errors.Is(err, azureauth.ErrCredential) {
					return gatewaybilling.ErrByok
				}
				return gatewaybilling.ErrGatewayUnavailable
			}
			// Bifrost's supported context-token path avoids its process-lifetime
			// SDK credential cache. The provider never receives the client secret.
			azure.ClientID, azure.ClientSecret, azure.TenantID = nil, nil, nil
			ctx.SetValue(azureprovider.AzureAuthorizationTokenKey, token)
		}
		ctx.SetValue(schemas.BifrostContextKeyDirectKey, directKey)
	}
	return nil
}

func FinalizeState(ctx context.Context, billing billingAuthorizer, state *State) {
	defer FinalizeExportState(ctx, state)
	if billing == nil || state == nil || state.Authorization == nil || state.BillingFinalized {
		return
	}
	state.BillingFinalized = true
	event := PrepareFinalState(state)
	if event == nil {
		return
	}
	finalizeExportMetrics(state)
	if err := billing.FinalizeRequest(context.WithoutCancel(ctx), state.Authorization, *event, state.RetainMemory); err != nil {
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
	if state.UpstreamCostUSD == "" {
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
			state.UpstreamCostUSD,
		); err != nil {
			markFinalPricingFailure(state, err)
			pricingFailed = true
		}
	}
	var cacheSavings *string
	var cacheWriteOverhead *string
	if !pricingFailed {
		var cacheSavingsErr error
		cacheSavings, cacheSavingsErr = cacheReadSavingsUSD(state)
		if cacheSavingsErr != nil {
			writeOperationalLog(operationalLogEvent{
				ErrorType:  safeOperationalErrorType(cacheSavingsErr),
				Event:      "cache_read_savings_projection_failed",
				ReasonCode: "cache_read_savings_unavailable",
				RequestID:  state.Authorization.RequestID,
				Severity:   "warn",
			})
		}
		var cacheWriteOverheadErr error
		cacheWriteOverhead, cacheWriteOverheadErr = cacheWriteOverheadUSD(state)
		if cacheWriteOverheadErr != nil {
			writeOperationalLog(operationalLogEvent{
				ErrorType:  safeOperationalErrorType(cacheWriteOverheadErr),
				Event:      "cache_write_overhead_projection_failed",
				ReasonCode: "cache_write_overhead_unavailable",
				RequestID:  state.Authorization.RequestID,
				Severity:   "warn",
			})
		}
	}
	catalogIdentity := state.Resolution.CatalogIdentity()
	executionDeployment := ExecutionDeployment(state)
	selectedChainHash := ""
	if state.Resolution != nil {
		selectedChainHash = state.Resolution.Deployment.ChainHash
	}
	cancelled, clientStoppedAt := state.ClientStatus()
	event, err := gatewaybilling.NewRequestEvent(gatewaybilling.EventInput{
		UpstreamCostUSD:          state.UpstreamCostUSD,
		Authorization:            state.Authorization,
		Cancelled:                cancelled,
		ClientStoppedAt:          clientStoppedAt,
		CatalogVersion:           catalogIdentity.Sequence,
		PolicyVersions:           state.PolicyVersions,
		CatalogChainHash:         executionDeployment.ChainHash,
		SelectedCatalogChainHash: selectedChainHash,
		Error:                    state.BifrostError,
		Meters:                   metersForState(state),
		Plugins:                  state.PluginMetrics,
		ProviderAttempts:         state.providerAttemptInputs(),
		ProviderCompletedAt:      state.ProviderCompletedAt,
		ProviderStartedAt:        state.ProviderStartedAt,
		TTFTMS:                   state.TTFTMS,
		FirstOutputAt:            state.FirstOutputAt,
		ProviderOutputObserved:   state.ProviderOutputObserved,
		CacheReadSavingsUSD:      cacheSavings,
		CacheWriteOverheadUSD:    cacheWriteOverhead,
		NodeID:                   state.NodeID,
		GatewayVersion:           state.GatewayVersion,
		RequestType:              state.RequestType,
		Response:                 state.Response,
		StartedAt:                state.StartedAt,
	})
	if err != nil {
		markFinalPricingFailure(state, err)
		pricingFailed = true
		event, err = gatewaybilling.NewRequestEvent(gatewaybilling.EventInput{
			UpstreamCostUSD:          gatewaybilling.ZeroChargeUSD,
			Authorization:            state.Authorization,
			Cancelled:                cancelled,
			ClientStoppedAt:          clientStoppedAt,
			CatalogVersion:           catalogIdentity.Sequence,
			PolicyVersions:           state.PolicyVersions,
			CatalogChainHash:         executionDeployment.ChainHash,
			SelectedCatalogChainHash: selectedChainHash,
			Error:                    state.BifrostError,
			ProviderAttempts:         state.providerAttemptInputs(),
			Plugins:                  state.PluginMetrics,
			ProviderCompletedAt:      state.ProviderCompletedAt,
			ProviderStartedAt:        state.ProviderStartedAt,
			TTFTMS:                   state.TTFTMS,
			FirstOutputAt:            state.FirstOutputAt,
			ProviderOutputObserved:   state.ProviderOutputObserved,
			NodeID:                   state.NodeID,
			GatewayVersion:           state.GatewayVersion,
			RequestType:              state.RequestType,
			Response:                 state.Response,
			StartedAt:                state.StartedAt,
		})
		if err != nil {
			return nil
		}
	}
	if state.ProcessingError != nil {
		status := 500
		if state.ProcessingError.StatusCode != nil && *state.ProcessingError.StatusCode >= 400 && *state.ProcessingError.StatusCode <= 599 {
			status = *state.ProcessingError.StatusCode
		}
		code := ""
		if state.ProcessingError.Error != nil && state.ProcessingError.Error.Code != nil {
			code = *state.ProcessingError.Error.Code
		}
		event.GatewayError = &gatewaybilling.EventError{Code: gatewaybilling.NormalizeStogasErrorCode(code, status), Status: status}
	}
	// A local failure can interrupt a provider stream before its outcome is
	// known. Keep completed provider results; do not invent success or HTTP 500.
	if state.ProcessingError != nil && len(event.ProviderAttempts) > 0 {
		streaming := state.RequestType == string(schemas.ChatCompletionStreamRequest) || state.RequestType == string(schemas.ResponsesStreamRequest)
		completed := state.Response != nil && (!streaming || state.chatStreamFinished || state.responsesStreamEnded)
		last := &event.ProviderAttempts[len(event.ProviderAttempts)-1]
		if !completed && last.Status == "success" {
			last.Status, last.StatusCode = "unknown", nil
		}
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
	state.ProcessingError = &schemas.BifrostError{
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
	// Keep observed quantities in the request log when pricing cannot be used.
	state.observedUsage, _ = state.Signals.(*StandardSignals)
	state.Signals = nil
	state.FinalMeters = nil
	state.UpstreamCostUSD = gatewaybilling.ZeroChargeUSD
}

func metersForState(state *State) gatewaybilling.EventMeters {
	out := gatewaybilling.EventMeters{}
	if state == nil {
		return out
	}
	for _, meter := range state.FinalMeters {
		key := meter.MeterKey
		if existing, ok := out[key]; ok {
			if existing.RateKey != nil && *existing.RateKey != meter.RateKey {
				key = meter.MeterKey + ":" + meter.RateKey
			}
		}
		out[key] = gatewaybilling.PricedMeter(meter.Quantity, meter.RateKey, meter.RateUSD, meter.AmountUSD)
	}
	observed := state.observedUsage
	if observed == nil {
		observed, _ = state.Signals.(*StandardSignals)
	}
	addCount := func(key string, quantity int) {
		if quantity >= 0 {
			if _, priced := out[key]; !priced {
				out[key] = gatewaybilling.EventMeter{Quantity: strconv.Itoa(quantity)}
			}
		}
	}
	if estimate, known := state.Resolution.EstimatedInputTokens(); known {
		addCount(billing.MeterEstimatedInputTokens, estimate)
	}
	if textBytes, known := state.Resolution.InputTextBytes(); known {
		addCount(billing.MeterInputTextBytes, textBytes)
		files := state.Resolution.InputFiles()
		addCount(billing.MeterInputFileCount, files.Count)
		addCount(billing.MeterInputFileURLCount, files.URLs)
		addCount(billing.MeterInputInlineFileBytes, files.InlineBytes)
	}
	if state.textMaterialObserved {
		addCount(billing.MeterOutputTextBytes, state.textMaterial.output)
	}
	if textBytes, known := state.reasoningTextBytes(); known {
		addCount(billing.MeterReasoningTextBytes, textBytes)
	}
	if observed != nil {
		if observed.inputKnown {
			addCount(billing.MeterTotalInputTokens, observed.Prompt)
		}
		if observed.outputKnown {
			addCount(billing.MeterTotalOutputTokens, observed.Completion)
		}
		if observed.inputKnown && observed.outputKnown {
			if total, ok := addTokenCounts(observed.Prompt, observed.Completion); ok {
				addCount(billing.MeterTotalTokens, total)
			}
		}
		writes := saturatingTokenTotal(observed.CacheWrite, observed.CacheWrite5m, observed.CacheWrite1h)
		parts := map[string]int{
			billing.MeterCachedInputTokens:       observed.Cached,
			billing.MeterCacheWriteInputTokens:   observed.CacheWrite,
			billing.MeterCacheWrite5mInputTokens: observed.CacheWrite5m,
			billing.MeterCacheWrite1hInputTokens: observed.CacheWrite1h,
			billing.MeterReasoningTokens:         observed.Reasoning,
			billing.MeterTotalCacheWriteTokens:   writes,
		}
		for key, quantity := range parts {
			if quantity > 0 {
				addCount(key, quantity)
			}
		}
		ordinary := observed.Prompt - observed.Cached - writes
		if ordinary >= 0 && observed.inputKnown {
			addCount(billing.MeterInputTokens, ordinary)
		}
		output := observed.Completion - observed.Reasoning
		if output >= 0 && observed.outputKnown {
			addCount(billing.MeterOutputTokens, output)
		}
	}
	// Both response validators retain one identity per observed call. Terminal
	// snapshots and stream updates reuse that identity; input results never enter it.
	clientCalls := state.responsesClientCalls + len(state.chatToolCalls)
	hostedCalls := state.responsesToolCalls - state.responsesClientCalls
	completedOutput := state.Response != nil && state.BifrostError == nil &&
		(state.RequestType == string(schemas.ChatCompletionRequest) || state.RequestType == string(schemas.ResponsesRequest) || state.chatStreamFinished || state.responsesStreamEnded)
	if clientCalls > 0 || completedOutput {
		addCount(billing.MeterClientToolCalls, clientCalls)
	}
	if hostedCalls > 0 || completedOutput {
		addCount(billing.MeterHostedToolCalls, hostedCalls)
	}

	return out
}
