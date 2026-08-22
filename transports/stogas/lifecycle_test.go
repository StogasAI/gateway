package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func testDeploymentForRoute(provider schemas.ModelProvider, model string, route catalog.Route) (catalog.Deployment, bool) {
	return catalog.DeploymentForRouteServiceTier(provider, model, route, nil)
}

type statusError struct {
	err        error
	statusCode int
}

func (e *statusError) Error() string { return e.err.Error() }
func (e *statusError) Unwrap() error { return e.err }
func (e *statusError) StatusCode() int {
	return e.statusCode
}

type fakeBillingAuthorizer struct {
	attempts    []string
	results     []*billing.Authorization
	errors      []error
	finalEvents []billing.RequestEvent
	callCount   int
}

func (f *fakeBillingAuthorizer) authorize(requestID string) (*billing.Authorization, error) {
	f.attempts = append(f.attempts, requestID)
	idx := f.callCount
	f.callCount++
	if idx < len(f.results) && f.results[idx] != nil {
		return f.results[idx], nil
	}
	if idx < len(f.errors) {
		return nil, f.errors[idx]
	}
	return nil, nil
}

func (f *fakeBillingAuthorizer) AuthorizeRequestWithPassthrough(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string, _ string, _ *billing.UpstreamTarget, requestLifetime time.Duration, _ bool) (*billing.Authorization, error) {
	return f.authorize(requestID)
}

func (f *fakeBillingAuthorizer) AuthorizeDashboardRequestWithDuration(ctx context.Context, _ *billing.DashboardCredential, requestID string, providerKey string, productKey string, amountUSDAtoms string, _ *billing.UpstreamTarget, requestLifetime time.Duration) (*billing.Authorization, error) {
	return f.authorize(requestID)
}

func (f *fakeBillingAuthorizer) FinalizeRequest(ctx context.Context, authorization *billing.Authorization, event billing.RequestEvent) error {
	f.finalEvents = append(f.finalEvents, event)
	return nil
}

func TestPublicBillingErrorTypes(t *testing.T) {
	for _, tt := range []struct {
		name       string
		err        error
		statusCode int
		wantType   string
	}{
		{name: "insufficient balance", err: billing.ErrInsufficientBalance, statusCode: 402, wantType: "billing_error"},
		{name: "spend limit", err: billing.ErrAPIKeySpendLimit, statusCode: 402, wantType: "billing_error"},
		{name: "key disabled", err: billing.ErrAPIKeyDisabled, statusCode: 403, wantType: "permission_denied"},
		{name: "rate limit", err: billing.ErrAPIKeyRateLimit, statusCode: 429, wantType: "rate_limit_error"},
		{name: "gateway unavailable", err: billing.ErrGatewayUnavailable, statusCode: 503, wantType: "gateway_error"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := PublicBillingErrorFor(&statusError{err: tt.err, statusCode: tt.statusCode})
			if got.StatusCode != tt.statusCode || got.Type != tt.wantType {
				t.Fatalf("PublicBillingErrorFor() = %#v, want status=%d type=%s", got, tt.statusCode, tt.wantType)
			}
		})
	}
}

func TestBillingUpstreamTargetIncludesCatalogDataBoundaries(t *testing.T) {
	target := billingUpstreamTarget(&catalog.ResolvedRequest{
		Provider: schemas.Azure,
		Deployment: catalog.Deployment{
			Upstream: catalog.Upstream{
				DeploymentType: "data_zone_standard_eu",
				Hosting:        "azure",
				Model:          "gpt-5.6-sol",
				ModelFormat:    "OpenAI",
				ModelVersion:   "2026-07-09",
			},
			DataHandling: catalog.DataHandling{
				ProcessingLocation: "eu",
				StorageLocation:    "europe",
			},
		},
	})
	if target == nil || target.ProcessingLocation != "eu" || target.StorageLocation != "europe" {
		t.Fatalf("Azure billing target omitted data boundaries: %#v", target)
	}
}

func TestAuthorizeWithFreshRequestIDRetriesConflict(t *testing.T) {
	initialRequestID := "11111111-1111-1111-1111-111111111111"
	expected := &billing.Authorization{RequestID: "22222222-2222-2222-2222-222222222222"}
	authorizer := &fakeBillingAuthorizer{
		results: []*billing.Authorization{nil, expected},
		errors: []error{
			&statusError{err: billing.ErrRequestAlreadyUsed, statusCode: 409},
			nil,
		},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, initialRequestID)

	authorization, err := authorizeWithFreshRequestID(ctx, authorizer, "sk-user", HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", MaxUSDAtoms: "1000"}, "", nil, billing.GatewayRequestLifetime, authorizer.errors[0])
	if err != nil {
		t.Fatalf("authorizeWithFreshRequestID returned error: %v", err)
	}
	if authorization != expected {
		t.Fatalf("expected authorization pointer to be reused")
	}
	if len(authorizer.attempts) != 2 {
		t.Fatalf("expected 2 authorization attempts, got %d", len(authorizer.attempts))
	}
	if authorizer.attempts[0] == initialRequestID {
		t.Fatalf("expected helper retries to use fresh request IDs")
	}
	if authorizer.attempts[1] == initialRequestID || authorizer.attempts[1] == authorizer.attempts[0] {
		t.Fatalf("expected each retry to use a distinct fresh request ID")
	}
	currentRequestID, _ := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if currentRequestID != authorizer.attempts[1] {
		t.Fatalf("expected context request ID to match retried request ID, got %q want %q", currentRequestID, authorizer.attempts[1])
	}
}

func TestAuthorizeWithFreshRequestIDLeavesNonConflictErrorsUntouched(t *testing.T) {
	initialRequestID := "11111111-1111-1111-1111-111111111111"
	expectedErr := &statusError{err: billing.ErrInvalidAPIKey, statusCode: 401}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, initialRequestID)

	authorization, err := authorizeWithFreshRequestID(ctx, &fakeBillingAuthorizer{}, "sk-user", HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", MaxUSDAtoms: "1000"}, "", nil, billing.GatewayRequestLifetime, expectedErr)
	if authorization != nil {
		t.Fatalf("expected no authorization for non-conflict error")
	}
	if !errors.Is(err, billing.ErrInvalidAPIKey) {
		t.Fatalf("expected invalid API key error, got %v", err)
	}
	currentRequestID, _ := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if currentRequestID != initialRequestID {
		t.Fatalf("expected request ID to remain unchanged, got %q", currentRequestID)
	}
}

func TestAuthorizeStateNeverRewritesEncryptedRequestID(t *testing.T) {
	requestID := "11111111-1111-1111-1111-111111111111"
	replayErr := &statusError{err: billing.ErrAuthorizationClosed, statusCode: 409}
	authorizer := &fakeBillingAuthorizer{errors: []error{replayErr}}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, requestID)
	state := NewState(&catalog.ResolvedRequest{
		Route:       catalog.RouteChat,
		RequestType: schemas.ChatCompletionRequest,
		Provider:    schemas.OpenAI,
		Model:       "gpt-5",
	}, "sk-user", nil, DefaultAdapter{})
	state.SingleUseRequestID = true
	state.Hold = HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", MaxUSDAtoms: "1000"}

	if err := AuthorizeState(ctx, authorizer, state); !errors.Is(err, billing.ErrAuthorizationClosed) {
		t.Fatalf("AuthorizeState error = %v, want authorization closed", err)
	}
	if len(authorizer.attempts) != 1 || authorizer.attempts[0] != requestID {
		t.Fatalf("authorization attempts = %#v, want the bound request id exactly once", authorizer.attempts)
	}
	currentRequestID, _ := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if currentRequestID != requestID {
		t.Fatalf("encrypted request ID changed to %q", currentRequestID)
	}
}

func TestAuthorizeStateClearsPassThroughCredentialAfterFailure(t *testing.T) {
	requestID := "11111111-1111-1111-1111-111111111111"
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, requestID)
	state := NewState(&catalog.ResolvedRequest{
		Route:       catalog.RouteChat,
		RequestType: schemas.ChatCompletionRequest,
		Provider:    schemas.OpenAI,
		Model:       "gpt-5",
	}, "sk-user", nil, DefaultAdapter{})
	state.PassthroughByokSecret = "sk-upstream-secret"
	state.Hold = HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", MaxUSDAtoms: "1000"}
	authorizer := &fakeBillingAuthorizer{errors: []error{
		&statusError{err: billing.ErrInvalidAPIKey, statusCode: 401},
	}}

	if err := AuthorizeState(ctx, authorizer, state); !errors.Is(err, billing.ErrInvalidAPIKey) {
		t.Fatalf("AuthorizeState error = %v, want invalid API key", err)
	}
	if state.PassthroughByokSecret != "" {
		t.Fatal("pass-through credential remained in request state after authorization failed")
	}
}

func TestApplyUpstreamCredentialsAllowsManagedAndByokChutes(t *testing.T) {
	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic, schemas.Azure} {
		t.Run("reject "+string(provider), func(t *testing.T) {
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			state := &State{
				Authorization: &billing.Authorization{UpstreamByok: "stogas"},
				Resolution:    &catalog.ResolvedRequest{Provider: provider},
			}
			if err := ApplyUpstreamCredentials(ctx, state); !errors.Is(err, billing.ErrByokRequired) {
				t.Fatalf("ApplyUpstreamCredentials error = %v, want BYOK required", err)
			}
		})
	}

	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	state := &State{
		Authorization: &billing.Authorization{UpstreamByok: "stogas", UserID: "user-123"},
		Resolution:    &catalog.ResolvedRequest{Provider: catalog.ProviderChutes},
	}
	if err := ApplyUpstreamCredentials(ctx, state); err != nil {
		t.Fatalf("ApplyUpstreamCredentials returned error: %v", err)
	}

	byokState := &State{
		Authorization: &billing.Authorization{
			UpstreamByok:       "0198f4cc-6c25-7000-8000-000000000001",
			UpstreamByokSecret: "cpk_user",
		},
		Resolution: &catalog.ResolvedRequest{Provider: catalog.ProviderChutes},
	}
	if err := ApplyUpstreamCredentials(ctx, byokState); err != nil {
		t.Fatalf("Chutes BYOK returned error: %v", err)
	}
	directKey, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
	if !ok || directKey.Value.GetValue() != "cpk_user" {
		t.Fatalf("Chutes BYOK direct key was not installed: %#v", directKey)
	}
}

func TestApplyUpstreamCredentialsInstallsBYOKKey(t *testing.T) {
	const byokID = "0198f4cc-6c25-7000-8000-000000000001"
	const upstreamSecret = "sk-upstream-secret"

	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic} {
		t.Run(string(provider), func(t *testing.T) {
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			state := &State{
				Authorization: &billing.Authorization{
					UpstreamByok:       byokID,
					UpstreamByokSecret: upstreamSecret,
					UserID:             "stogas-user",
				},
				Resolution: &catalog.ResolvedRequest{Provider: provider},
			}

			if err := ApplyUpstreamCredentials(ctx, state); err != nil {
				t.Fatalf("ApplyUpstreamCredentials returned error: %v", err)
			}
			directKey, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
			if !ok {
				t.Fatalf("BYOK request did not install a direct provider key")
			}
			if directKey.ID != byokID || directKey.Name != byokID {
				t.Fatalf("direct key attribution = %#v, want credential %q", directKey, byokID)
			}
			if directKey.Value.GetValue() != upstreamSecret {
				t.Fatalf("direct key secret was not installed")
			}
			if directKey.Enabled == nil || !*directKey.Enabled {
				t.Fatalf("direct key was not enabled")
			}
		})
	}
}

func TestApplyUpstreamCredentialsRejectsIncompleteBYOKAuthorization(t *testing.T) {
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	state := &State{
		Authorization: &billing.Authorization{
			UpstreamByok: "0198f4cc-6c25-7000-8000-000000000001",
		},
		Resolution: &catalog.ResolvedRequest{Provider: schemas.OpenAI},
	}

	if err := ApplyUpstreamCredentials(ctx, state); !errors.Is(err, billing.ErrByok) {
		t.Fatalf("ApplyUpstreamCredentials error = %v, want BYOK failure", err)
	}
	if directKey := ctx.Value(schemas.BifrostContextKeyDirectKey); directKey != nil {
		t.Fatalf("incomplete BYOK authorization installed direct key: %#v", directKey)
	}
}

func TestApplyUpstreamCredentialsRejectsUnsafeProviderCredential(t *testing.T) {
	for _, secret := range []string{" leading", "trailing ", "line\nbreak", "nul\x00byte", "unicode-é", string([]byte{0x7f})} {
		ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
		state := &State{
			Authorization: &billing.Authorization{
				UpstreamByok:       "0198f4cc-6c25-7000-8000-000000000001",
				UpstreamByokSecret: secret,
			},
			Resolution: &catalog.ResolvedRequest{Provider: schemas.OpenAI},
		}

		if err := ApplyUpstreamCredentials(ctx, state); !errors.Is(err, billing.ErrByok) {
			t.Fatalf("credential %q: ApplyUpstreamCredentials error = %v, want BYOK failure", secret, err)
		}
		if directKey := ctx.Value(schemas.BifrostContextKeyDirectKey); directKey != nil {
			t.Fatalf("credential %q installed direct key: %#v", secret, directKey)
		}
	}
}

func TestDefaultAdapterFinalPriceUsesSignals(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				"input_tokens":  {"per_mill_tokens": "1000000"},
				"output_tokens": {"per_mill_tokens": "2000000"},
			}},
		},
		Signals: &StandardSignals{Prompt: 1000, Completion: 2000},
	}
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "5000" {
		t.Fatalf("expected signal-derived final cost 5000, got %s", state.FinalCostUSDAtoms)
	}
	if len(state.FinalMeters) != 2 {
		t.Fatalf("expected final price to retain two pricing meters, got %#v", state.FinalMeters)
	}
	if state.FinalMeters[0].MeterKey != billing.MeterInputTokens || state.FinalMeters[0].RateKey != billing.RatePerMillionTokens || state.FinalMeters[0].AmountUSDAtoms != "1000" {
		t.Fatalf("unexpected input final meter %#v", state.FinalMeters[0])
	}
	if state.FinalMeters[1].MeterKey != billing.MeterOutputTokens || state.FinalMeters[1].RateKey != billing.RatePerMillionTokens || state.FinalMeters[1].AmountUSDAtoms != "4000" {
		t.Fatalf("unexpected output final meter %#v", state.FinalMeters[1])
	}
}

func TestFinalPricePartitionsEveryInputAndOutputCategoryExactlyOnce(t *testing.T) {
	pricing := catalog.Pricing{
		billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1000000"},
		billing.MeterCachedInputTokens:       {billing.RatePerMillionTokens: "100000"},
		billing.MeterCacheWriteInputTokens:   {billing.RatePerMillionTokens: "1250000"},
		billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1250000"},
		billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "2000000"},
		billing.MeterOutputTokens:            {billing.RatePerMillionTokens: "3000000"},
		billing.MeterReasoningTokens:         {billing.RatePerMillionTokens: "4000000"},
	}
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: pricing}},
		Signals: &StandardSignals{
			Prompt:       1000,
			Cached:       100,
			CacheWrite:   50,
			CacheWrite5m: 200,
			CacheWrite1h: 300,
			Completion:   100,
			Reasoning:    40,
		},
	}
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	wantQuantities := map[string]string{
		billing.MeterInputTokens:             "350",
		billing.MeterCachedInputTokens:       "100",
		billing.MeterCacheWriteInputTokens:   "50",
		billing.MeterCacheWrite5mInputTokens: "200",
		billing.MeterCacheWrite1hInputTokens: "300",
		billing.MeterOutputTokens:            "60",
		billing.MeterReasoningTokens:         "40",
	}
	for meterKey, want := range wantQuantities {
		meter := findMeterEstimate(state.FinalMeters, meterKey)
		if meter == nil || meter.Quantity != want || meter.HoldRequired {
			t.Fatalf("%s meter = %#v, want quantity %s", meterKey, meter, want)
		}
	}
	if state.FinalCostUSDAtoms != "1613" {
		t.Fatalf("exact partition cost = %s, want 1613; meters=%#v", state.FinalCostUSDAtoms, state.FinalMeters)
	}
}

func TestFinalPriceSelectsContextTierFromActualUsage(t *testing.T) {
	longText := strings.Repeat("a", (billing.LongContextThresholdTokens+1)*4)
	body := []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"` + longText + `"}],"max_completion_tokens":16}`)
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	for _, meterKey := range []string{billing.MeterInputTokens, billing.MeterOutputTokens} {
		holdMeter := findMeterEstimate(state.Hold.Meters, meterKey)
		if holdMeter == nil || !holdMeter.HoldRequired {
			t.Fatalf("expected an authorized hold meter for %s, got %#v in %#v", meterKey, holdMeter, state.Hold.Meters)
		}
	}

	state.Signals = &StandardSignals{Prompt: 1000, Completion: 2000}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice below threshold returned error: %v", err)
	}
	for _, meterKey := range []string{billing.MeterInputTokens, billing.MeterOutputTokens} {
		finalMeter := findMeterEstimate(state.FinalMeters, meterKey)
		if finalMeter == nil || finalMeter.RateKey != billing.RatePerMillionContextLTE272K || finalMeter.HoldRequired {
			t.Fatalf("expected low-context final meter for %s, got %#v in %#v", meterKey, finalMeter, state.FinalMeters)
		}
	}

	state.Signals = &StandardSignals{Prompt: billing.LongContextThresholdTokens + 1, Completion: 1}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice above threshold returned error: %v", err)
	}
	for _, meterKey := range []string{billing.MeterInputTokens, billing.MeterOutputTokens} {
		finalMeter := findMeterEstimate(state.FinalMeters, meterKey)
		if finalMeter == nil || finalMeter.RateKey != billing.RatePerMillionContextGT272K || finalMeter.HoldRequired {
			t.Fatalf("expected high-context final meter for %s, got %#v in %#v", meterKey, finalMeter, state.FinalMeters)
		}
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover high-context final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}

	state.Signals = &StandardSignals{Prompt: 1000, Completion: billing.LongContextThresholdTokens + 1}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice large output returned error: %v", err)
	}
	for _, meterKey := range []string{billing.MeterInputTokens, billing.MeterOutputTokens} {
		finalMeter := findMeterEstimate(state.FinalMeters, meterKey)
		if finalMeter == nil || finalMeter.RateKey != billing.RatePerMillionContextLTE272K {
			t.Fatalf("expected normal-context final meter for large output %s, got %#v in %#v", meterKey, finalMeter, state.FinalMeters)
		}
	}
}

func TestFinalPricePartitionsReasoningFromAggregateOutputWithoutDoubleCounting(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				"input_tokens":  {"per_mill_tokens": "1000000"},
				"output_tokens": {"per_mill_tokens": "2000000"},
			}},
		},
	}
	setSignalsFromUsage(state, &schemas.BifrostLLMUsage{
		PromptTokens:     1000,
		CompletionTokens: 250,
		TotalTokens:      1250,
		CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
			TextTokens:               40,
			ReasoningTokens:          180,
			RejectedPredictionTokens: 20,
			AcceptedPredictionTokens: 10,
		},
	})
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "1500" {
		t.Fatalf("expected aggregate-token final cost 1500, got %s", state.FinalCostUSDAtoms)
	}
	if len(state.FinalMeters) != 3 {
		t.Fatalf("expected three final meters, got %#v", state.FinalMeters)
	}
	output := findMeterEstimate(state.FinalMeters, billing.MeterOutputTokens)
	if output == nil || output.Quantity != "70" || output.AmountUSDAtoms != "140" {
		t.Fatalf("expected non-reasoning output partition, got %#v", state.FinalMeters)
	}
	reasoning := findMeterEstimate(state.FinalMeters, billing.MeterReasoningTokens)
	if reasoning == nil || reasoning.Quantity != "180" || reasoning.AmountUSDAtoms != "360" {
		t.Fatalf("expected reasoning partition at the output fallback rate, got %#v", state.FinalMeters)
	}
}

func TestFinalPriceUsesExplicitReasoningRateAndHoldReservesTheHigherOutputRate(t *testing.T) {
	pricing := catalog.Pricing{
		billing.MeterOutputTokens:    {billing.RatePerMillionTokens: "2000000"},
		billing.MeterReasoningTokens: {billing.RatePerMillionTokens: "5000000"},
	}
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: pricing}},
	}
	setSignalsFromUsage(state, &schemas.BifrostLLMUsage{
		CompletionTokens: 250,
		CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
			ReasoningTokens: 180,
		},
	})
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "1040" {
		t.Fatalf("expected distinct output and reasoning rates to cost 1040, got %s", state.FinalCostUSDAtoms)
	}
	reasoning := findMeterEstimate(state.FinalMeters, billing.MeterReasoningTokens)
	if reasoning == nil || reasoning.Quantity != "180" || reasoning.AmountUSDAtoms != "900" {
		t.Fatalf("expected explicit reasoning rate, got %#v", state.FinalMeters)
	}
	holdMeters := appendOutputTokenHoldCost(nil, pricing, 250)
	if len(holdMeters) != 1 || holdMeters[0].MeterKey != billing.MeterReasoningTokens || holdMeters[0].AmountUSDAtoms != "1250" {
		t.Fatalf("expected the output cap held at the higher reasoning rate, got %#v", holdMeters)
	}
	outputOnly := catalog.Pricing{
		billing.MeterOutputTokens: {billing.RatePerMillionTokens: "2000000"},
	}
	withFallback := billing.WithReasoningTokenFallback(outputOnly)
	if _, exists := outputOnly[billing.MeterReasoningTokens]; exists {
		t.Fatal("reasoning fallback mutated catalog pricing")
	}
	if withFallback[billing.MeterReasoningTokens][billing.RatePerMillionTokens] != "2000000" {
		t.Fatalf("reasoning fallback did not inherit output pricing: %#v", withFallback)
	}
	fallbackHold := appendOutputTokenHoldCost(nil, withFallback, 250)
	if len(fallbackHold) != 1 || fallbackHold[0].MeterKey != billing.MeterOutputTokens || fallbackHold[0].AmountUSDAtoms != "500" {
		t.Fatalf("equal fallback rates should retain the output hold meter, got %#v", fallbackHold)
	}
}

func TestSignalsFromUsageFallsBackWhenProviderAggregateUsageIsPartial(t *testing.T) {
	t.Run("total derived completion", func(t *testing.T) {
		signals := signalsFromUsage(&schemas.BifrostLLMUsage{
			PromptTokens: 100,
			TotalTokens:  175,
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
				ReasoningTokens: 50,
			},
		})
		if signals == nil || signals.Prompt != 100 || signals.Completion != 75 || signals.Reasoning != 50 {
			t.Fatalf("signalsFromUsage() = %#v, want prompt=100 completion=75 reasoning=50", signals)
		}
	})

	t.Run("detail derived completion", func(t *testing.T) {
		signals := signalsFromUsage(&schemas.BifrostLLMUsage{
			PromptTokens: 100,
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
				TextTokens:               4,
				ReasoningTokens:          50,
				RejectedPredictionTokens: 6,
			},
		})
		if signals == nil || signals.Prompt != 100 || signals.Completion != 60 || signals.Reasoning != 50 {
			t.Fatalf("signalsFromUsage() = %#v, want prompt=100 completion=60 reasoning=50", signals)
		}
	})
}

func TestFinalPriceDefensivelyBoundsDirectInvalidReasoningSignals(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterOutputTokens: {billing.RatePerMillionTokens: "2000000"},
		}}},
	}
	setSignalsFromUsage(state, &schemas.BifrostLLMUsage{
		CompletionTokens: 10,
		CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
			ReasoningTokens: 20,
		},
	})
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if findMeterEstimate(state.FinalMeters, billing.MeterOutputTokens) != nil {
		t.Fatalf("invalid provider detail produced negative/non-reasoning output: %#v", state.FinalMeters)
	}
	reasoning := findMeterEstimate(state.FinalMeters, billing.MeterReasoningTokens)
	if reasoning == nil || reasoning.Quantity != "10" || reasoning.AmountUSDAtoms != "20" {
		t.Fatalf("reasoning detail was not clamped to aggregate completion: %#v", state.FinalMeters)
	}
}

func TestDefaultAdapterFinalPriceClassifiesNoUsageErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode *int
		message    string
		wantCost   string
	}{
		{name: "bad request captures hold", statusCode: lifecycleIntPtr(400), message: "messages.0.content is required", wantCost: "123"},
		{name: "request too large captures hold", statusCode: lifecycleIntPtr(413), message: "request exceeds maximum size", wantCost: "123"},
		{name: "bad request budget parameter captures hold", statusCode: lifecycleIntPtr(400), message: "task_budget.total is below the provider minimum", wantCost: "123"},
		{name: "bad request rate limit parameter captures hold", statusCode: lifecycleIntPtr(400), message: "rate_limit field is not valid for this model", wantCost: "123"},
		{name: "bad request timeout parameter captures hold", statusCode: lifecycleIntPtr(400), message: "timeout parameter is not supported", wantCost: "123"},
		{name: "bad request network option captures hold", statusCode: lifecycleIntPtr(400), message: "network setting is invalid", wantCost: "123"},
		{name: "conversion failure without status captures hold", message: "failed to marshal request: missing required field messages", wantCost: "123"},
		{name: "missing required field without status captures hold", message: "missing required 'type' field in ResponsesTool", wantCost: "123"},
		{name: "nil bifrost request without status captures hold", message: "bifrost request cannot be nil", wantCost: "123"},
		{name: "unsupported request without status captures hold", message: "unsupported request type: responses_stream", wantCost: "123"},
		{name: "provider auth is insured", statusCode: lifecycleIntPtr(401), message: "provider API key invalid", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "provider permission policy is insured", statusCode: lifecycleIntPtr(403), message: "organization policy disabled provider access", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "cataloged provider model not found is insured", statusCode: lifecycleIntPtr(404), message: "model not found", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "provider rate limit is insured", statusCode: lifecycleIntPtr(429), message: "rate_limit exceeded", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "provider network failure is insured", message: "dial tcp: connection refused", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "provider server failure is insured", statusCode: lifecycleIntPtr(500), message: "provider failed", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "provider server invalid request wording is insured", statusCode: lifecycleIntPtr(500), message: "provider invalid request processor failed", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "provider safety backend failure is insured", statusCode: lifecycleIntPtr(500), message: "provider safety service unavailable", wantCost: billing.ZeroChargeUSDAtoms},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &State{
				Authorization: &billing.Authorization{AuthorizedAmount: big.NewInt(123)},
				BifrostError: &schemas.BifrostError{
					StatusCode: tt.statusCode,
					Error: &schemas.ErrorField{
						Message: tt.message,
					},
				},
			}
			if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
				t.Fatalf("FinalPrice returned error: %v", err)
			}
			if state.FinalCostUSDAtoms != tt.wantCost {
				t.Fatalf("FinalCostUSDAtoms = %s, want %s", state.FinalCostUSDAtoms, tt.wantCost)
			}
		})
	}
}

func TestDefaultAdapterFinalPriceCapturesHoldForSuccessfulResponseWithoutUsage(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterOutputTokens: {billing.RatePerMillionTokens: "1000000"},
		}}},
		Authorization: &billing.Authorization{AuthorizedAmount: big.NewInt(123)},
		Signals:       &StandardSignals{},
		Hold: HoldEstimate{Meters: []catalog.MeterEstimate{{
			MeterKey:       billing.MeterOutputTokens,
			RateKey:        billing.RatePerMillionTokens,
			RateUSDAtoms:   "1000000",
			Quantity:       "123",
			AmountUSDAtoms: "123",
			HoldRequired:   true,
		}}},
	}
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "123" {
		t.Fatalf("FinalCostUSDAtoms = %s, want captured hold 123", state.FinalCostUSDAtoms)
	}
	if len(state.FinalMeters) != 1 || state.FinalMeters[0].HoldRequired {
		t.Fatalf("expected captured hold meter as a settled final meter, got %#v", state.FinalMeters)
	}
}

func TestDefaultAdapterFinalPriceChargesUsageEvenWhenProviderErrorIsInsured(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				billing.MeterInputTokens:  {billing.RatePerMillionTokens: "1000000"},
				billing.MeterOutputTokens: {billing.RatePerMillionTokens: "2000000"},
			}},
		},
		BifrostError: &schemas.BifrostError{
			StatusCode: lifecycleIntPtr(500),
			Error:      &schemas.ErrorField{Message: "provider failed after returning usage"},
		},
		Signals: &StandardSignals{Prompt: 1000, Completion: 250},
	}

	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "1500" {
		t.Fatalf("FinalCostUSDAtoms = %s, want usage-derived 1500", state.FinalCostUSDAtoms)
	}
	if len(state.FinalMeters) != 2 {
		t.Fatalf("expected usage-derived final meters despite provider error, got %#v", state.FinalMeters)
	}
	if state.FinalMeters[0].MeterKey != billing.MeterInputTokens || state.FinalMeters[0].AmountUSDAtoms != "1000" {
		t.Fatalf("unexpected input final meter %#v", state.FinalMeters[0])
	}
	if state.FinalMeters[1].MeterKey != billing.MeterOutputTokens || state.FinalMeters[1].AmountUSDAtoms != "500" {
		t.Fatalf("unexpected output final meter %#v", state.FinalMeters[1])
	}
}

func TestNoUsageClientErrorLogsCapturedHoldMetersAsFinalMeters(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterOutputTokens: {billing.RatePerMillionTokens: "2000000"},
		}}},
		Authorization: &billing.Authorization{AuthorizedAmount: big.NewInt(2000)},
		Hold: HoldEstimate{
			MaxUSDAtoms: "2000",
			Meters: []catalog.MeterEstimate{{
				MeterKey:       billing.MeterOutputTokens,
				RateKey:        billing.RatePerMillionTokens,
				RateUSDAtoms:   "2000000",
				Quantity:       "1000",
				AmountUSDAtoms: "2000",
				HoldRequired:   true,
			}},
		},
		BifrostError: &schemas.BifrostError{
			StatusCode: lifecycleIntPtr(400),
			Error:      &schemas.ErrorField{Message: "messages.0.content is required"},
		},
	}

	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "2000" {
		t.Fatalf("FinalCostUSDAtoms = %s, want 2000", state.FinalCostUSDAtoms)
	}
	if len(state.FinalMeters) != 1 {
		t.Fatalf("expected captured hold meter to be logged as final meter, got %#v", state.FinalMeters)
	}
	if state.FinalMeters[0].HoldRequired {
		t.Fatalf("final meter must not require hold: %#v", state.FinalMeters[0])
	}

	pricing := pricingForState(state)
	assertPricingBagEntry(t, pricing, billing.MeterOutputTokens, billing.RatePerMillionTokens, "1000", "2000")
}

func lifecycleIntPtr(value int) *int {
	return &value
}

func TestFinalPriceUsesActualOpenAIServiceTierWhenExplicitTierReturned(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"openai-gpt-5.5-2026-04-23-fast","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	actualTier := schemas.BifrostServiceTierPriority
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	state.Signals = &StandardSignals{Prompt: 1000, ActualServiceTier: &actualTier}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "12500000000000000" {
		t.Fatalf("expected Fast input pricing from returned priority tier, got %s", state.FinalCostUSDAtoms)
	}
}

func TestOpenAIFastDowngradeUsesActualDeploymentForBillingAndEvidence(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"openai-gpt-5.5-2026-04-23-fast","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	actualTier := schemas.BifrostServiceTierDefault
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	inputTokens, hasInputHold := tokenHoldCapacity(state, true)
	if !hasInputHold || inputTokens <= 0 {
		t.Fatalf("missing input-token authorization: %#v", state.Hold.Meters)
	}
	state.Signals = &StandardSignals{Prompt: inputTokens, ActualServiceTier: &actualTier}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	input := findMeterEstimate(state.FinalMeters, billing.MeterInputTokens)
	if input == nil || input.RateUSDAtoms != "5000000000000000000" || input.Quantity != strconv.Itoa(inputTokens) {
		t.Fatalf("expected downgraded standard input pricing, got %#v", state.FinalMeters)
	}
	actual := ExecutionDeployment(state)
	if actual.ID != "openai-gpt-5.5-2026-04-23" {
		t.Fatalf("actual deployment = %q, want standard", actual.ID)
	}

	authorizer := &fakeBillingAuthorizer{}
	authorizedAmount, ok := new(big.Int).SetString(state.Hold.MaxUSDAtoms, 10)
	if !ok {
		t.Fatalf("invalid hold amount %q", state.Hold.MaxUSDAtoms)
	}
	state.Authorization = &billing.Authorization{
		AuthorizedAmount: authorizedAmount,
		CreatedAt:        time.Now().UTC(),
		ProviderKey:      "openai",
		ProductKey:       resolution.Deployment.ID,
		RequestID:        "fast-downgrade",
	}
	state.RequestType = string(schemas.ChatCompletionRequest)
	state.StartedAt = time.Now().UTC()
	FinalizeState(context.Background(), authorizer, state)
	if len(authorizer.finalEvents) != 1 {
		t.Fatalf("final events = %d, want 1", len(authorizer.finalEvents))
	}
	wantNodeIDs := []string{
		"author:openai",
		"model:gpt-5.5-2026-04-23",
		"deployment:openai-gpt-5.5-2026-04-23",
		"route:openai-chat-completions",
		"provider:openai",
	}
	if got := authorizer.finalEvents[0].CatalogNodeIDs; strings.Join(got, ",") != strings.Join(wantNodeIDs, ",") {
		t.Fatalf("resolved catalog node IDs = %#v, want %#v", got, wantNodeIDs)
	}
}

func TestOpenAIFastHoldCoversActualPriorityServiceTier(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"openai-gpt-5.5-2026-04-23-fast","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":128}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	actualTier := schemas.BifrostServiceTierPriority
	state.Signals = &StandardSignals{
		Prompt:            resolution.InputTokenLimit(),
		Completion:        resolution.OutputTokenLimit(),
		ActualServiceTier: &actualTier,
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("Fast hold must cover the returned priority-tier cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
	if state.Hold.ProductKey != "openai-gpt-5.5-2026-04-23-fast" {
		t.Fatalf("expected Fast deployment hold product key, got %#v", state.Hold)
	}
}

func TestOpenAIDefaultAndAutoUseExplicitStandardTierAndConservativeHoldRate(t *testing.T) {
	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat omitted",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`,
		},
		{
			name: "chat auto",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"service_tier":"auto","max_completion_tokens":16}`,
		},
		{
			name: "chat default",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"service_tier":"default","max_completion_tokens":16}`,
		},
		{
			name: "responses omitted",
			path: "/v1/responses",
			body: `{"model":"gpt-5.5","input":"hi","max_output_tokens":16}`,
		},
		{
			name: "responses auto",
			path: "/v1/responses",
			body: `{"model":"gpt-5.5","input":"hi","service_tier":"auto","max_output_tokens":16}`,
		},
		{
			name: "responses default",
			path: "/v1/responses",
			body: `{"model":"gpt-5.5","input":"hi","service_tier":"default","max_output_tokens":16}`,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch item.path {
			case "/v1/chat/completions":
				if bifrostReq.ChatRequest == nil ||
					bifrostReq.ChatRequest.Params.ServiceTier == nil ||
					*bifrostReq.ChatRequest.Params.ServiceTier != schemas.BifrostServiceTierDefault {
					t.Fatalf("expected default OpenAI chat deployment to send explicit default tier, got %#v", bifrostReq)
				}
			case "/v1/responses":
				if bifrostReq.ResponsesRequest == nil ||
					bifrostReq.ResponsesRequest.Params.ServiceTier == nil ||
					*bifrostReq.ResponsesRequest.Params.ServiceTier != schemas.BifrostServiceTierDefault {
					t.Fatalf("expected default OpenAI Responses deployment to send explicit default tier, got %#v", bifrostReq)
				}
			default:
				t.Fatalf("unhandled test path %q", item.path)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			if state.Hold.ProductKey != "openai-gpt-5.5-2026-04-23" {
				t.Fatalf("expected default deployment hold product key, got %#v", state.Hold)
			}
			defaultInput := findMeterEstimate(state.Hold.Meters, billing.MeterInputTokens)
			if defaultInput == nil || defaultInput.RateKey != billing.RatePerMillionContextGT272K || defaultInput.RateUSDAtoms != "10000000000000000000" {
				t.Fatalf("default hold must reserve the deployment's highest possible input rate: %#v", state.Hold.Meters)
			}
		})
	}
}

func TestOpenAICacheReadFinalPriceStaysCoveredByNoCacheHold(t *testing.T) {
	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"prompt_cache_key":"tenant-a","max_completion_tokens":16}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","prompt_cache_key":"tenant-a","max_output_tokens":16}`,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}

			cachedTokens := resolution.InputTokenLimit() / 2
			if cachedTokens == 0 {
				t.Fatal("expected non-zero cached token quantity")
			}
			state.Signals = &StandardSignals{
				Prompt:     resolution.InputTokenLimit(),
				Completion: resolution.OutputTokenLimit(),
				Cached:     cachedTokens,
			}
			if err := state.Adapter.FinalPrice(state); err != nil {
				t.Fatalf("FinalPrice returned error: %v", err)
			}
			if findMeterEstimate(state.FinalMeters, billing.MeterCachedInputTokens) == nil {
				t.Fatalf("expected cached input final meter, got %#v", state.FinalMeters)
			}
			if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover OpenAI cached-read final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
			}
		})
	}
}

func TestAzureGPT56FinalPriceConservativelyClassifiesUnreportedCacheWrites(t *testing.T) {
	pricing := catalog.Pricing{
		billing.MeterInputTokens:           {billing.RatePerMillionTokens: "1000000"},
		billing.MeterCachedInputTokens:     {billing.RatePerMillionTokens: "100000"},
		billing.MeterCacheWriteInputTokens: {billing.RatePerMillionTokens: "2000000"},
		billing.MeterOutputTokens:          {billing.RatePerMillionTokens: "3000000"},
	}
	tests := []struct {
		name           string
		provider       schemas.ModelProvider
		prompt         int
		cached         int
		reportedWrite  int
		wantInput      string
		wantCacheWrite string
	}{
		{name: "Azure cacheable miss", provider: schemas.Azure, prompt: 2048, wantCacheWrite: "2048"},
		{name: "Azure exact cache threshold", provider: schemas.Azure, prompt: 1024, wantCacheWrite: "1024"},
		{name: "Azure partial hit", provider: schemas.Azure, prompt: 2048, cached: 512, wantCacheWrite: "1536"},
		{name: "Azure exact report wins", provider: schemas.Azure, prompt: 2048, cached: 512, reportedWrite: 1024, wantInput: "512", wantCacheWrite: "1024"},
		{name: "Azure prompt below threshold", provider: schemas.Azure, prompt: 1023, wantInput: "1023"},
		{name: "OpenAI is not inferred", provider: schemas.OpenAI, prompt: 2048, wantInput: "2048"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &State{
				Resolution: &catalog.ResolvedRequest{
					Provider: tt.provider,
					Deployment: catalog.Deployment{
						Pricing:  pricing,
						Upstream: catalog.Upstream{Model: "gpt-5.6-sol"},
					},
				},
				Signals: &StandardSignals{Prompt: tt.prompt, Cached: tt.cached, CacheWrite: tt.reportedWrite},
			}
			if _, err := baseFinalPrice(state, nil); err != nil {
				t.Fatalf("baseFinalPrice returned error: %v", err)
			}
			if meter := findMeterEstimate(state.FinalMeters, billing.MeterInputTokens); meterQuantity(meter) != tt.wantInput {
				t.Fatalf("input quantity = %q, want %q; meters=%#v", meterQuantity(meter), tt.wantInput, state.FinalMeters)
			}
			if meter := findMeterEstimate(state.FinalMeters, billing.MeterCacheWriteInputTokens); meterQuantity(meter) != tt.wantCacheWrite {
				t.Fatalf("cache-write quantity = %q, want %q; meters=%#v", meterQuantity(meter), tt.wantCacheWrite, state.FinalMeters)
			}
		})
	}
}

func meterQuantity(meter *catalog.MeterEstimate) string {
	if meter == nil {
		return ""
	}
	return meter.Quantity
}

func TestEveryActiveCatalogDeploymentHoldCoversEveryTokenCategory(t *testing.T) {
	type matrixDeployment struct {
		RouteIDs []string `json:"routeIds"`
	}
	type matrixRoute struct {
		Interfaces []string `json:"interfaces"`
		ProviderID string   `json:"providerId"`
	}
	public, ok := catalog.PublicCatalogPayload()
	if !ok {
		t.Fatal("compiled public catalog is unavailable")
	}
	deployments := map[string]matrixDeployment{}
	routes := map[string]matrixRoute{}
	if err := json.Unmarshal(public.Graph["deployments"], &deployments); err != nil {
		t.Fatalf("decode catalog deployments: %v", err)
	}
	if err := json.Unmarshal(public.Graph["routes"], &routes); err != nil {
		t.Fatalf("decode catalog routes: %v", err)
	}
	deploymentIDs := make([]string, 0, len(deployments))
	for id := range deployments {
		deploymentIDs = append(deploymentIDs, id)
	}
	slices.Sort(deploymentIDs)

	for _, deploymentID := range deploymentIDs {
		for _, routeID := range deployments[deploymentID].RouteIDs {
			routeSpec := routes[routeID]
			provider := schemas.ModelProvider(routeSpec.ProviderID)
			for _, interfaceName := range routeSpec.Interfaces {
				var (
					path  string
					route catalog.Route
				)
				requestBody := map[string]any{"model": deploymentID}
				switch interfaceName {
				case "chat_completions":
					path = "/v1/chat/completions"
					route = catalog.RouteChat
					requestBody["messages"] = []map[string]any{{"content": "hi", "role": "user"}}
					requestBody["max_completion_tokens"] = 16
				case "responses":
					path = "/v1/responses"
					route = catalog.RouteResponses
					requestBody["input"] = "hi"
					requestBody["max_output_tokens"] = 16
				default:
					t.Fatalf("%s: unsupported catalog interface %q", routeID, interfaceName)
				}
				if _, active := testDeploymentForRoute(provider, deploymentID, route); !active {
					continue
				}
				if provider == schemas.Anthropic {
					requestBody["cache_control"] = map[string]any{"type": "ephemeral", "ttl": "1h"}
				}
				body, err := json.Marshal(requestBody)
				if err != nil {
					t.Fatal(err)
				}
				resolution, err := catalog.ResolveRequest(catalog.RequestInput{
					Method: "POST",
					Path:   path,
					Body:   body,
				})
				if err != nil {
					t.Fatalf("%s/%s: resolve request: %v", deploymentID, interfaceName, err)
				}
				state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
				if err := state.Adapter.ValidateRequest(state); err != nil {
					t.Fatalf("%s/%s: validate request: %v", deploymentID, interfaceName, err)
				}
				if err := state.Adapter.SanitizeRequest(state); err != nil {
					t.Fatalf("%s/%s: sanitize request: %v", deploymentID, interfaceName, err)
				}
				if err := state.Adapter.EstimateHold(state); err != nil {
					t.Fatalf("%s/%s: estimate hold: %v", deploymentID, interfaceName, err)
				}
				if state.Hold.MaxUSDAtoms == "" || state.Hold.MaxUSDAtoms == billing.ZeroChargeUSDAtoms {
					t.Fatalf("%s/%s: token hold is empty", deploymentID, interfaceName)
				}

				inputTokens := resolution.InputTokenLimit()
				outputTokens := resolution.OutputTokenLimit()
				scenarios := []struct {
					name    string
					meter   string
					signals *StandardSignals
				}{
					{
						name:  "uncached",
						meter: billing.MeterInputTokens,
						signals: &StandardSignals{
							Prompt:     inputTokens,
							Completion: outputTokens,
							Reasoning:  outputTokens,
						},
					},
				}
				if len(resolution.Deployment.Pricing[billing.MeterCachedInputTokens]) > 0 {
					scenarios = append(scenarios, struct {
						name    string
						meter   string
						signals *StandardSignals
					}{
						name:  "cache-read",
						meter: billing.MeterCachedInputTokens,
						signals: &StandardSignals{
							Prompt:     inputTokens,
							Cached:     inputTokens,
							Completion: outputTokens,
						},
					})
				}
				if len(resolution.Deployment.Pricing[billing.MeterCacheWriteInputTokens]) > 0 {
					scenarios = append(scenarios, struct {
						name    string
						meter   string
						signals *StandardSignals
					}{
						name:  "cache-write",
						meter: billing.MeterCacheWriteInputTokens,
						signals: &StandardSignals{
							Prompt:     inputTokens,
							CacheWrite: inputTokens,
							Completion: outputTokens,
						},
					})
				}
				if provider == schemas.Anthropic {
					scenarios = append(
						scenarios,
						struct {
							name    string
							meter   string
							signals *StandardSignals
						}{
							name:  "cache-write-5m",
							meter: billing.MeterCacheWrite5mInputTokens,
							signals: &StandardSignals{
								Prompt:       inputTokens,
								CacheWrite5m: inputTokens,
								Completion:   outputTokens,
							},
						},
						struct {
							name    string
							meter   string
							signals *StandardSignals
						}{
							name:  "cache-write-1h",
							meter: billing.MeterCacheWrite1hInputTokens,
							signals: &StandardSignals{
								Prompt:       inputTokens,
								CacheWrite1h: inputTokens,
								Completion:   outputTokens,
							},
						},
					)
				}
				for _, scenario := range scenarios {
					t.Run(deploymentID+"/"+interfaceName+"/"+scenario.name, func(t *testing.T) {
						state.Signals = scenario.signals
						if err := state.Adapter.FinalPrice(state); err != nil {
							t.Fatalf("calculate final price: %v", err)
						}
						if state.FinalCostUSDAtoms == billing.ZeroChargeUSDAtoms {
							t.Fatalf("final token price is zero: meters=%#v", state.FinalMeters)
						}
						if findMeterEstimate(state.FinalMeters, scenario.meter) == nil {
							t.Fatalf("final price omitted %s: %#v", scenario.meter, state.FinalMeters)
						}
						if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
							t.Fatalf(
								"hold does not cover final price: hold=%s final=%s holdMeters=%#v finalMeters=%#v",
								state.Hold.MaxUSDAtoms,
								state.FinalCostUSDAtoms,
								state.Hold.Meters,
								state.FinalMeters,
							)
						}
					})
				}
			}
		}
	}
}

func TestFinalPriceUsesSelectedDeploymentForUnknownActualTier(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"auto","max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	actualTier := schemas.BifrostServiceTier("unexpected_vendor_tier")
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	state.Signals = &StandardSignals{Prompt: 1000, ActualServiceTier: &actualTier}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "50000000000000" {
		t.Fatalf("expected selected default deployment pricing for unknown actual tier, got %s", state.FinalCostUSDAtoms)
	}
}

func TestProviderExecutionMetadataCannotRetargetUnauthorizedDeployment(t *testing.T) {
	priority := schemas.BifrostServiceTierPriority
	tests := []struct {
		name        string
		path        string
		body        string
		actualTier  *schemas.BifrostServiceTier
		actualSpeed string
		actualModel string
	}{
		{
			name:       "OpenAI Flex cannot become Priority",
			path:       "/v1/chat/completions",
			body:       `{"model":"openai-gpt-5.5-2026-04-23-flex","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`,
			actualTier: &priority,
		},
		{
			name:       "Azure Standard cannot become Priority",
			path:       "/v1/chat/completions",
			body:       `{"model":"azure-gpt-5.6-sol","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`,
			actualTier: &priority,
		},
		{
			name:        "Anthropic Standard cannot become Fast",
			path:        "/v1/chat/completions",
			body:        `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`,
			actualSpeed: "fast",
		},
		{
			name:        "reported fallback model is diagnostic only",
			path:        "/v1/chat/completions",
			body:        `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`,
			actualModel: "gpt-5-nano-2025-08-07",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			state.ActualServiceTier = tc.actualTier
			state.ActualSpeed = tc.actualSpeed
			state.ActualModel = tc.actualModel
			actual := ExecutionDeployment(state)
			if actual.ID != resolution.Deployment.ID {
				t.Fatalf("execution metadata retargeted deployment from %q to %q", resolution.Deployment.ID, actual.ID)
			}
		})
	}
}

func TestAnthropicFinalPriceUsesReturnedServiceTierDeployment(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantHold   string
		actualTier schemas.BifrostServiceTier
	}{
		{
			name:       "auto request returned standard",
			body:       `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`,
			wantHold:   "anthropic-claude-opus-4-8",
			actualTier: schemas.BifrostServiceTier("standard_only"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(tt.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			if state.Hold.ProductKey != tt.wantHold {
				t.Fatalf("expected hold product %q, got %#v", tt.wantHold, state.Hold)
			}

			mutatedPricing := copyPricing(resolution.Deployment.Pricing)
			mutatedPricing[billing.MeterInputTokens] = map[string]string{billing.RatePerMillionTokens: "999000000000000000000"}
			mutatedPricing[billing.MeterOutputTokens] = map[string]string{billing.RatePerMillionTokens: "999000000000000000000"}
			resolution.Deployment.Pricing = mutatedPricing

			state.Signals = &StandardSignals{
				Prompt:            1000,
				Completion:        1000,
				ActualServiceTier: &tt.actualTier,
			}
			if err := state.Adapter.FinalPrice(state); err != nil {
				t.Fatalf("FinalPrice returned error: %v", err)
			}
			if state.FinalCostUSDAtoms != "30000000000000000" {
				t.Fatalf("expected cataloged actual service-tier pricing, got %s meters=%#v", state.FinalCostUSDAtoms, state.FinalMeters)
			}
		})
	}
}

func TestAnthropicMappedServiceTierHoldCoversFinalUsage(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		actualTier schemas.BifrostServiceTier
	}{
		{
			name:       "responses default sent as standard only returns standard",
			path:       "/v1/responses",
			body:       `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"default","max_output_tokens":16}`,
			actualTier: schemas.BifrostServiceTier("standard_only"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tt.path,
				Body:   []byte(tt.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			if state.Hold.ProductKey != resolution.Deployment.ID {
				t.Fatalf("hold product should be selected standard deployment %q, got %#v", resolution.Deployment.ID, state.Hold)
			}
			state.Signals = &StandardSignals{
				Prompt:            resolution.InputTokenLimit(),
				Completion:        resolution.OutputTokenLimit(),
				ActualServiceTier: &tt.actualTier,
			}
			if err := state.Adapter.FinalPrice(state); err != nil {
				t.Fatalf("FinalPrice returned error: %v", err)
			}
			if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
				t.Fatalf("Anthropic mapped service-tier hold must cover final: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
			}
		})
	}
}

func TestFinalizeStateLogsPricingMeters(t *testing.T) {
	authorizer := &fakeBillingAuthorizer{}
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Route:    catalog.RouteChat,
			Provider: schemas.OpenAI,
			Model:    "gpt-5",
			Deployment: catalog.Deployment{
				ID:       "gpt-5-standard",
				ModelID:  "gpt-5-2026-01-01",
				RouteIDs: []string{"openai-chat-completions"},
				Pricing: catalog.Pricing{
					billing.MeterInputTokens:  {billing.RatePerMillionTokens: "1000000"},
					billing.MeterOutputTokens: {billing.RatePerMillionTokens: "2000000"},
				},
			},
		},
		Authorization: &billing.Authorization{
			AuthorizedAmount: big.NewInt(3000),
			AvailableAfter:   big.NewInt(0),
			CreatedAt:        time.Now().UTC(),
			KeyID:            "key",
			OrganizationID:   "org",
			ProviderKey:      "openai",
			ProductKey:       "gpt-5",
			RequestID:        "request",
			UserID:           "user",
			WorkspaceID:      "workspace",
		},
		Hold: HoldEstimate{
			MaxUSDAtoms: "3000",
			Meters: []catalog.MeterEstimate{
				{
					MeterKey:       billing.MeterInputTokens,
					RateKey:        billing.RatePerMillionTokens,
					RateUSDAtoms:   "1000000",
					Quantity:       "1000",
					AmountUSDAtoms: "1000",
					HoldRequired:   true,
				},
				{
					MeterKey:       billing.MeterOutputTokens,
					RateKey:        billing.RatePerMillionTokens,
					RateUSDAtoms:   "2000000",
					Quantity:       "1000",
					AmountUSDAtoms: "2000",
					HoldRequired:   true,
				},
			},
		},
		RequestType:       string(schemas.ChatCompletionRequest),
		Model:             "gpt-5",
		GatewayVersion:    "v1.5.13",
		StartedAt:         time.Now().UTC(),
		FinalCostUSDAtoms: "1000",
		FinalMeters: []catalog.MeterEstimate{{
			MeterKey:       billing.MeterInputTokens,
			RateKey:        billing.RatePerMillionTokens,
			RateUSDAtoms:   "1000000",
			Quantity:       "1000",
			AmountUSDAtoms: "1000",
			HoldRequired:   false,
		}},
		Signals: &StandardSignals{Prompt: 1000, Cached: 100},
	}

	FinalizeState(context.Background(), authorizer, state)

	if len(authorizer.finalEvents) != 1 {
		t.Fatalf("expected one final event, got %d", len(authorizer.finalEvents))
	}
	event := authorizer.finalEvents[0]
	inputPricing := event.Pricing[billing.MeterInputTokens]
	if inputPricing.Quantity != "1000" {
		t.Fatalf("unexpected final pricing %#v", event.Pricing)
	}
	if _, ok := event.Pricing[billing.MeterOutputTokens]; ok {
		t.Fatalf("telemetry must not log hold-only meters: %#v", event.Pricing)
	}
	if event.UpstreamCostUSDAtoms != "1000" || event.BilledCostUSDAtoms != "1000" {
		t.Fatalf("managed costs must match final meter sum, got upstream=%s billed=%s", event.UpstreamCostUSDAtoms, event.BilledCostUSDAtoms)
	}
	if event.GatewayVersion != "v1.5.13" {
		t.Fatalf("gateway version = %q", event.GatewayVersion)
	}
	wantNodeIDs := []string{"model:gpt-5-2026-01-01", "deployment:gpt-5-standard", "route:openai-chat-completions", "provider:openai"}
	if strings.Join(event.CatalogNodeIDs, ",") != strings.Join(wantNodeIDs, ",") {
		t.Fatalf("resolved catalog node IDs = %#v, want %#v", event.CatalogNodeIDs, wantNodeIDs)
	}
}

func TestUnaryProviderLatencyDoesNotFabricateFirstOutput(t *testing.T) {
	state := &State{
		Authorization: &billing.Authorization{
			AuthorizedAmount: big.NewInt(0),
			AvailableAfter:   big.NewInt(0),
			RequestID:        "request",
		},
		FinalCostUSDAtoms: billing.ZeroChargeUSDAtoms,
		RequestType:       string(schemas.ChatCompletionRequest),
		Response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{
			ExtraFields: schemas.BifrostResponseExtraFields{Latency: 81},
		}},
		StartedAt: time.Now().UTC().Add(-100 * time.Millisecond),
	}
	authorizer := &fakeBillingAuthorizer{}
	FinalizeState(context.Background(), authorizer, state)

	if len(authorizer.finalEvents) != 1 {
		t.Fatalf("expected one final event, got %d", len(authorizer.finalEvents))
	}
	attempt := authorizer.finalEvents[0].ProviderAttempts[0]
	if attempt.LatencyMS != 81 {
		t.Fatalf("expected provider total latency 81, got %#v", attempt)
	}
	if attempt.ProviderFirstOutputMS != nil {
		t.Fatalf("buffered requests must not report streaming first output, got %#v", attempt)
	}
}

func TestProviderFirstOutputUsesGatewayClockAcrossProviderEvents(t *testing.T) {
	state := &State{ProviderStartedAt: time.Now().UTC().Add(-20 * time.Millisecond)}
	state.observeProviderFirstOutput()
	if state.ProviderFirstOutputMS == nil || *state.ProviderFirstOutputMS < 15 || *state.ProviderFirstOutputMS > 100 {
		t.Fatalf("expected the gateway provider clock, got %#v", state.ProviderFirstOutputMS)
	}
	first := *state.ProviderFirstOutputMS
	state.ProviderStartedAt = time.Now().UTC().Add(-time.Second)
	state.observeProviderFirstOutput()
	if *state.ProviderFirstOutputMS != first {
		t.Fatalf("first provider output must remain authoritative, got %#v", state.ProviderFirstOutputMS)
	}
}

func TestProviderFirstOutputIgnoresProtocolMetadata(t *testing.T) {
	state := &State{ProviderStartedAt: time.Now().UTC().Add(-20 * time.Millisecond)}
	state.ObserveChatProviderOutput(&schemas.BifrostChatResponse{
		Choices: []schemas.BifrostResponseChoice{{
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
				Delta: &schemas.ChatStreamResponseChoiceDelta{Role: stringPointer("assistant")},
			},
		}},
	})
	state.ObserveResponsesProviderOutput(&schemas.BifrostResponsesStreamResponse{
		Type: schemas.ResponsesStreamResponseTypeCreated,
	})
	if state.ProviderFirstOutputMS != nil {
		t.Fatalf("protocol metadata must not count as provider output, got %#v", state.ProviderFirstOutputMS)
	}

	text := "hello"
	state.ObserveResponsesProviderOutput(&schemas.BifrostResponsesStreamResponse{
		Delta: &text,
		Type:  schemas.ResponsesStreamResponseTypeOutputTextDelta,
	})
	if state.ProviderFirstOutputMS == nil || *state.ProviderFirstOutputMS < 15 {
		t.Fatalf("output delta did not record first provider output: %#v", state.ProviderFirstOutputMS)
	}
}

func TestProviderFirstOutputRequiresGatewayClock(t *testing.T) {
	text := "hello"
	state := &State{}
	state.ObserveChatProviderOutput(&schemas.BifrostChatResponse{
		Choices: []schemas.BifrostResponseChoice{{
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
				Delta: &schemas.ChatStreamResponseChoiceDelta{Content: &text},
			},
		}},
		ExtraFields: schemas.BifrostResponseExtraFields{Latency: 20},
	})
	if state.ProviderFirstOutputMS != nil {
		t.Fatalf("provider metadata created a gateway timing observation: %#v", state.ProviderFirstOutputMS)
	}
}

func stringPointer(value string) *string {
	return &value
}

func TestRequestLogPricingBagCompactsDuplicateMetersBeforeRounding(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				billing.MeterInputTokens: {billing.RatePerMillionTokens: "1"},
			}},
		},
		FinalMeters: []catalog.MeterEstimate{
			{
				AmountUSDAtoms: "1",
				MeterKey:       billing.MeterInputTokens,
				Quantity:       "1",
				RateKey:        billing.RatePerMillionTokens,
			},
			{
				AmountUSDAtoms: "1",
				MeterKey:       billing.MeterInputTokens,
				Quantity:       "1",
				RateKey:        billing.RatePerMillionTokens,
			},
		},
	}

	meters, total, err := canonicalizeMeters(state.FinalMeters, state.Resolution.Deployment.Pricing)
	if err != nil {
		t.Fatalf("canonicalizeMeters returned error: %v", err)
	}
	state.FinalMeters = meters
	state.FinalCostUSDAtoms = total
	pricing := pricingForState(state)
	assertPricingBagEntry(t, pricing, billing.MeterInputTokens, billing.RatePerMillionTokens, "2", "1")
	if total != "1" {
		t.Fatalf("expected compacted meter total 1 atom, got %s", total)
	}

	authorizer := &fakeBillingAuthorizer{}
	state.Authorization = &billing.Authorization{
		AuthorizedAmount: big.NewInt(2),
		AvailableAfter:   big.NewInt(0),
		RequestID:        "request",
	}
	state.Hold.MaxUSDAtoms = "2"
	state.Hold.Meters = []catalog.MeterEstimate{{
		AmountUSDAtoms: "2",
		HoldRequired:   true,
		MeterKey:       billing.MeterInputTokens,
		Quantity:       "2",
		RateKey:        billing.RatePerMillionTokens,
	}}
	state.FinalCostUSDAtoms = total
	state.StartedAt = time.Now().UTC()
	FinalizeState(context.Background(), authorizer, state)
	if len(authorizer.finalEvents) != 1 {
		t.Fatalf("expected one final event, got %d", len(authorizer.finalEvents))
	}
	event := authorizer.finalEvents[0]
	if event.UpstreamCostUSDAtoms != "1" || event.BilledCostUSDAtoms != "1" {
		t.Fatalf("managed costs must use compacted final meters, got upstream=%s billed=%s", event.UpstreamCostUSDAtoms, event.BilledCostUSDAtoms)
	}
	if event.Pricing[billing.MeterInputTokens].Quantity != "2" {
		t.Fatalf("unexpected compacted pricing %#v", event.Pricing)
	}
}

func TestCanonicalizeMetersRejectsInvalidBillingData(t *testing.T) {
	pricing := catalog.Pricing{
		billing.MeterInputTokens: {billing.RatePerMillionTokens: "1000000"},
	}
	valid := catalog.MeterEstimate{
		AmountUSDAtoms: "1",
		MeterKey:       billing.MeterInputTokens,
		Quantity:       "1",
		RateKey:        billing.RatePerMillionTokens,
		RateUSDAtoms:   "1000000",
	}
	tests := []struct {
		name   string
		meters []catalog.MeterEstimate
	}{
		{
			name: "negative quantity",
			meters: []catalog.MeterEstimate{{
				AmountUSDAtoms: "1",
				MeterKey:       billing.MeterInputTokens,
				Quantity:       "-1",
				RateKey:        billing.RatePerMillionTokens,
				RateUSDAtoms:   "1000000",
			}},
		},
		{
			name: "malformed amount mixed with valid meter",
			meters: []catalog.MeterEstimate{
				valid,
				{
					AmountUSDAtoms: "invalid",
					MeterKey:       billing.MeterInputTokens,
					Quantity:       "1",
					RateKey:        billing.RatePerMillionTokens,
					RateUSDAtoms:   "1000000",
				},
			},
		},
		{
			name: "catalog rate mismatch",
			meters: []catalog.MeterEstimate{{
				AmountUSDAtoms: "2",
				MeterKey:       billing.MeterInputTokens,
				Quantity:       "1",
				RateKey:        billing.RatePerMillionTokens,
				RateUSDAtoms:   "2000000",
			}},
		},
		{
			name: "unknown meter",
			meters: []catalog.MeterEstimate{{
				AmountUSDAtoms: "1",
				MeterKey:       "unknown",
				Quantity:       "1",
				RateKey:        billing.RatePerMillionTokens,
				RateUSDAtoms:   "1000000",
			}},
		},
		{
			name: "unknown rate",
			meters: []catalog.MeterEstimate{{
				AmountUSDAtoms: "1",
				MeterKey:       billing.MeterInputTokens,
				Quantity:       "1",
				RateKey:        "per_million_unknown",
				RateUSDAtoms:   "1000000",
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := canonicalizeMeters(tc.meters, pricing); err == nil {
				t.Fatal("canonicalizeMeters accepted invalid billing data")
			}
		})
	}
}

func TestPrepareFinalStateRejectsCostsOutsideAuthorizedHold(t *testing.T) {
	tests := []struct {
		name          string
		hold          string
		final         string
		providerError bool
		pricingError  bool
		wantError     bool
	}{
		{name: "exact hold", hold: "100", final: "100"},
		{name: "above hold", hold: "100", final: "101", wantError: true},
		{name: "provider error above hold", hold: "100", final: "101", providerError: true, wantError: true},
		{name: "missing hold", final: "1", wantError: true},
		{name: "malformed hold", hold: "invalid", final: "1", wantError: true},
		{name: "malformed final", hold: "100", final: "invalid", pricingError: true, wantError: true},
		{name: "negative final", hold: "100", final: "-1", pricingError: true, wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const rateUSDAtoms = "1000000"
			var providerErr *schemas.BifrostError
			if tc.providerError {
				status := 500
				providerErr = &schemas.BifrostError{StatusCode: &status, Error: &schemas.ErrorField{Message: "provider failed"}}
			}
			holdMeters := []catalog.MeterEstimate(nil)
			finalMeters := []catalog.MeterEstimate(nil)
			if final, ok := new(big.Int).SetString(tc.final, 10); ok && final.Sign() > 0 {
				holdMeters = []catalog.MeterEstimate{{
					AmountUSDAtoms: tc.hold,
					HoldRequired:   true,
					MeterKey:       billing.MeterInputTokens,
					Quantity:       tc.hold,
					RateKey:        billing.RatePerMillionTokens,
					RateUSDAtoms:   rateUSDAtoms,
				}}
				finalMeters = []catalog.MeterEstimate{{
					AmountUSDAtoms: tc.final,
					MeterKey:       billing.MeterInputTokens,
					Quantity:       tc.final,
					RateKey:        billing.RatePerMillionTokens,
					RateUSDAtoms:   rateUSDAtoms,
				}}
			}
			state := &State{
				Authorization: &billing.Authorization{
					AuthorizedAmount: big.NewInt(100),
					AvailableAfter:   big.NewInt(0),
					RequestID:        "request",
				},
				FinalCostUSDAtoms: tc.final,
				BifrostError:      providerErr,
				FinalMeters:       finalMeters,
				Hold:              HoldEstimate{MaxUSDAtoms: tc.hold, Meters: holdMeters},
				Resolution: &catalog.ResolvedRequest{
					Provider: schemas.OpenAI,
					Route:    catalog.RouteChat,
					Deployment: catalog.Deployment{Pricing: catalog.Pricing{
						billing.MeterInputTokens: {billing.RatePerMillionTokens: rateUSDAtoms},
					}},
				},
				Signals:   &StandardSignals{Prompt: 1},
				StartedAt: time.Now().UTC(),
			}
			event := PrepareFinalState(state)
			if event == nil {
				t.Fatal("PrepareFinalState returned nil")
			}
			if !tc.wantError {
				if state.BifrostError != nil || event.UpstreamCostUSDAtoms != tc.final {
					t.Fatalf("authorized final cost was changed: state=%#v event=%#v", state, event)
				}
				return
			}
			if state.BifrostError == nil || state.FinalCostUSDAtoms != billing.ZeroChargeUSDAtoms || event.UpstreamCostUSDAtoms != billing.ZeroChargeUSDAtoms {
				t.Fatalf("unsafe final cost did not fail closed: state=%#v event=%#v", state, event)
			}
			if tc.pricingError && event.StogasProcessingSuccess {
				t.Fatal("pricing failure was recorded as a successful request")
			}
			if providerErr != nil && state.BifrostError != providerErr {
				t.Fatal("final-cost guard replaced the original provider error")
			}
			if state.Signals != nil || len(state.FinalMeters) != 0 {
				t.Fatalf("unsafe usage remained billable: signals=%#v meters=%#v", state.Signals, state.FinalMeters)
			}
		})
	}
}

func TestFinalMeterQuantitiesStayWithinAuthorizedDimensions(t *testing.T) {
	hold := []catalog.MeterEstimate{
		{MeterKey: billing.MeterCacheWrite1hInputTokens, Quantity: "10", HoldRequired: true},
		{MeterKey: billing.MeterInputTokens, Quantity: "3", HoldRequired: true},
		{MeterKey: billing.MeterReasoningTokens, Quantity: "4", HoldRequired: true},
		{MeterKey: meterAnthropicWebSearchCalls, Quantity: "2", HoldRequired: true},
	}
	tests := []struct {
		name  string
		hold  []catalog.MeterEstimate
		final []catalog.MeterEstimate
		want  bool
	}{
		{
			name: "token partitions and tool calls at limits",
			hold: hold,
			final: []catalog.MeterEstimate{
				{MeterKey: billing.MeterInputTokens, Quantity: "6"},
				{MeterKey: billing.MeterCachedInputTokens, Quantity: "7"},
				{MeterKey: billing.MeterOutputTokens, Quantity: "3"},
				{MeterKey: billing.MeterReasoningTokens, Quantity: "1"},
				{MeterKey: meterAnthropicWebSearchCalls, Quantity: "2"},
			},
			want: true,
		},
		{
			name:  "input partitions exceed hold",
			hold:  hold,
			final: []catalog.MeterEstimate{{MeterKey: billing.MeterInputTokens, Quantity: "14"}},
		},
		{
			name:  "output partitions exceed hold",
			hold:  hold,
			final: []catalog.MeterEstimate{{MeterKey: billing.MeterOutputTokens, Quantity: "5"}},
		},
		{
			name:  "tool calls exceed hold",
			hold:  hold,
			final: []catalog.MeterEstimate{{MeterKey: meterAnthropicWebSearchCalls, Quantity: "3"}},
		},
		{
			name:  "unheld meter",
			hold:  hold,
			final: []catalog.MeterEstimate{{MeterKey: "unexpected_fee", Quantity: "1"}},
		},
		{
			name:  "malformed hold quantity",
			hold:  []catalog.MeterEstimate{{MeterKey: billing.MeterInputTokens, Quantity: "invalid", HoldRequired: true}},
			final: []catalog.MeterEstimate{{MeterKey: billing.MeterInputTokens, Quantity: "1"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := finalMeterQuantitiesWithinHold(tc.hold, tc.final); got != tc.want {
				t.Fatalf("finalMeterQuantitiesWithinHold() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestPricingMetricBagCarriesStackedCacheAndHostedToolMeters(t *testing.T) {
	state := &State{
		Hold: HoldEstimate{Meters: []catalog.MeterEstimate{
			{
				AmountUSDAtoms: "100",
				MeterKey:       billing.MeterInputTokens,
				Quantity:       "1000",
				RateKey:        billing.RatePerMillionTokens,
				HoldRequired:   true,
			},
			{
				AmountUSDAtoms: "200",
				MeterKey:       billing.MeterCacheWrite1hInputTokens,
				Quantity:       "1000",
				RateKey:        billing.RatePerMillionTokens,
				HoldRequired:   true,
			},
			{
				AmountUSDAtoms: "300",
				MeterKey:       meterAnthropicWebSearchCalls,
				Quantity:       "2",
				RateKey:        billing.RatePerThousandCalls,
				HoldRequired:   true,
			},
		}},
		FinalMeters: []catalog.MeterEstimate{
			{
				AmountUSDAtoms: "50",
				MeterKey:       billing.MeterInputTokens,
				Quantity:       "500",
				RateKey:        billing.RatePerMillionTokens,
			},
			{
				AmountUSDAtoms: "80",
				MeterKey:       billing.MeterCacheWrite1hInputTokens,
				Quantity:       "400",
				RateKey:        billing.RatePerMillionTokens,
			},
			{
				AmountUSDAtoms: "150",
				MeterKey:       meterAnthropicWebSearchCalls,
				Quantity:       "1",
				RateKey:        billing.RatePerThousandCalls,
			},
		},
	}

	pricing := pricingForState(state)
	assertPricingBagEntry(t, pricing, billing.MeterInputTokens, billing.RatePerMillionTokens, "500", "50")
	assertPricingBagEntry(t, pricing, billing.MeterCacheWrite1hInputTokens, billing.RatePerMillionTokens, "400", "80")
	assertPricingBagEntry(t, pricing, meterAnthropicWebSearchCalls, billing.RatePerThousandCalls, "1", "150")
	for _, forbidden := range []string{"hold", "final", "hold_meters", "final_meters", "total_cost_usd_atoms", "usageMetrics"} {
		if _, ok := pricing[forbidden]; ok {
			t.Fatalf("pricing bag must not expose fixed key %q: %#v", forbidden, pricing)
		}
	}
}

func assertPricingBagEntry(t *testing.T, bag billing.EventPricing, meterKey string, rateKey string, quantity string, amount string) {
	t.Helper()
	meter, ok := bag[meterKey]
	if !ok {
		t.Fatalf("missing pricing meter %s in %#v", meterKey, bag)
	}
	if meter.RateKey != rateKey || meter.Quantity != quantity || meter.USDAtoms != amount {
		t.Fatalf("unexpected pricing for %s: %#v", meterKey, meter)
	}
}

func compareMoneyStrings(left string, right string) int {
	leftValue, ok := new(big.Int).SetString(left, 10)
	if !ok {
		leftValue = big.NewInt(0)
	}
	rightValue, ok := new(big.Int).SetString(right, 10)
	if !ok {
		rightValue = big.NewInt(0)
	}
	return leftValue.Cmp(rightValue)
}

func TestOpenAIProviderHoldAddsSearchMeters(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-search-api","messages":[{"role":"user","content":"hi"}],"web_search_options":{"search_context_size":"low"},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if len(state.Hold.Meters) != 3 {
		t.Fatalf("expected token meters plus search call meter, got %#v", state.Hold.Meters)
	}
	searchMeter := state.Hold.Meters[2]
	if searchMeter.MeterKey != MeterOpenAIChatCompletionSearchModelCalls || searchMeter.RateKey != billing.RatePerThousandCalls {
		t.Fatalf("expected search model call meter, got %#v", searchMeter)
	}
	if state.Hold.MaxUSDAtoms == "" || state.Hold.MaxUSDAtoms == "0" {
		t.Fatalf("expected non-zero hold after search meter, got %#v", state.Hold)
	}
}

func TestOpenAIChatSearchModelHoldAndFinalMetersUseContextRate(t *testing.T) {
	for _, tt := range []struct {
		name     string
		body     string
		meterKey string
		rateKey  string
	}{
		{
			name:     "search api generic rate",
			body:     `{"model":"gpt-5-search-api","messages":[{"role":"user","content":"hi"}],"web_search_options":{"search_context_size":"high"},"max_completion_tokens":100}`,
			meterKey: MeterOpenAIChatCompletionSearchModelCalls,
			rateKey:  billing.RatePerThousandCalls,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(tt.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			state.Signals = &StandardSignals{
				Prompt:     resolution.InputTokenLimit(),
				Completion: resolution.OutputTokenLimit(),
			}
			if err := state.Adapter.FinalPrice(state); err != nil {
				t.Fatalf("FinalPrice returned error: %v", err)
			}
			if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover final search-model cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
			}
			holdMeter := findMeterEstimate(state.Hold.Meters, tt.meterKey)
			if holdMeter == nil {
				t.Fatalf("missing hold search meter: %#v", state.Hold.Meters)
			}
			if holdMeter.RateKey != tt.rateKey || holdMeter.Quantity != "1" || !holdMeter.HoldRequired {
				t.Fatalf("unexpected hold search meter: %#v", holdMeter)
			}
			finalMeter := findMeterEstimate(state.FinalMeters, tt.meterKey)
			if finalMeter == nil {
				t.Fatalf("missing final search meter: %#v", state.FinalMeters)
			}
			if finalMeter.RateKey != tt.rateKey || finalMeter.Quantity != "1" || finalMeter.HoldRequired {
				t.Fatalf("unexpected final search meter: %#v", finalMeter)
			}
			pricing := pricingForState(state)
			for _, meterKey := range []string{billing.MeterInputTokens, billing.MeterOutputTokens} {
				if _, ok := pricing[meterKey]; !ok {
					t.Fatalf("search-model pricing bag must include token meter %s with tool meter, got %#v", meterKey, pricing)
				}
			}
			searchPricing, ok := pricing[tt.meterKey]
			if !ok {
				t.Fatalf("missing search meter pricing bag: %#v", pricing)
			}
			if searchPricing.Quantity != "1" || searchPricing.RateKey != tt.rateKey || searchPricing.USDAtoms == "" {
				t.Fatalf("unexpected search pricing bag: %#v", searchPricing)
			}
		})
	}
}

func TestOpenAIPromptCacheHoldCoversAllPossibleWrites(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		meterKey string
	}{
		{
			name:     "implicit breakpoint",
			body:     `{"model":"gpt-5.6-luna","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":16}`,
			meterKey: billing.MeterCacheWriteInputTokens,
		},
		{
			name:     "explicit mode without breakpoints",
			body:     `{"model":"gpt-5.6-luna","messages":[{"role":"user","content":"hello"}],"prompt_cache_options":{"mode":"explicit"},"max_completion_tokens":16}`,
			meterKey: billing.MeterInputTokens,
		},
		{
			name:     "two explicit breakpoints",
			body:     `{"model":"gpt-5.6-luna","messages":[{"role":"user","content":[{"type":"text","text":"one","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"text","text":"two","prompt_cache_breakpoint":{"mode":"explicit"}}]}],"prompt_cache_options":{"mode":"explicit"},"max_completion_tokens":16}`,
			meterKey: billing.MeterCacheWriteInputTokens,
		},
		{
			name:     "implicit and four explicit breakpoints",
			body:     `{"model":"gpt-5.6-luna","messages":[{"role":"user","content":[{"type":"text","text":"one","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"text","text":"two","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"text","text":"three","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"text","text":"four","prompt_cache_breakpoint":{"mode":"explicit"}}]}],"max_completion_tokens":16}`,
			meterKey: billing.MeterCacheWriteInputTokens,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(tt.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			meter := findMeterEstimate(state.Hold.Meters, tt.meterKey)
			if meter == nil {
				t.Fatalf("missing %s hold meter: %#v", tt.meterKey, state.Hold.Meters)
			}
			expectedQuantity := big.NewInt(int64(resolution.InputTokenLimit())).String()
			if meter.Quantity != expectedQuantity {
				t.Fatalf("hold quantity = %s, want %s", meter.Quantity, expectedQuantity)
			}
			signals := &StandardSignals{Prompt: resolution.InputTokenLimit()}
			if tt.meterKey == billing.MeterCacheWriteInputTokens {
				signals.CacheWrite = resolution.InputTokenLimit()
			}
			state.Signals = signals
			if err := state.Adapter.FinalPrice(state); err != nil {
				t.Fatalf("FinalPrice returned error: %v", err)
			}
			if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover all cache writes: hold=%s final=%s", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms)
			}
		})
	}
}

func TestAnthropicProviderHoldReservesCacheWrite(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}],"cache_control":{"type":"ephemeral","ttl":"5m"},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	var found bool
	for _, meter := range state.Hold.Meters {
		if meter.MeterKey == billing.MeterCacheWrite5mInputTokens {
			found = true
			expectedQuantity := big.NewInt(int64(resolution.InputTokenLimit())).String()
			if meter.Quantity != expectedQuantity {
				t.Fatalf("expected cache write hold quantity %s, got %s", expectedQuantity, meter.Quantity)
			}
		}
	}
	if !found {
		t.Fatalf("expected Anthropic hold to include requested 5m cache write meter, got %#v", state.Hold.Meters)
	}
	if findMeterEstimate(state.Hold.Meters, billing.MeterInputTokens) != nil {
		t.Fatalf("cache-write hold must not reserve the same prompt as ordinary input: %#v", state.Hold.Meters)
	}
	if state.Hold.MaxUSDAtoms == "" || state.Hold.MaxUSDAtoms == "0" {
		t.Fatalf("expected non-zero Anthropic hold, got %#v", state.Hold)
	}
}

func TestAnthropicHoldCoversWorstCaseOneHourCacheWrite(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}],"cache_control":{"type":"ephemeral","ttl":"1h"},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	state.Signals = &StandardSignals{
		Prompt:       resolution.InputTokenLimit(),
		Completion:   resolution.OutputTokenLimit(),
		CacheWrite1h: resolution.InputTokenLimit(),
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover worst-case 1h cache write: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
}

func TestAnthropicHoldCoversDefaultFiveMinuteCacheWrite(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","content":[{"type":"input_text","text":"hello","cache_control":{"type":"ephemeral"}}]}],"max_output_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite5mInputTokens) == nil {
		t.Fatalf("expected requested cache_control to reserve 5m cache write, got %#v", state.Hold.Meters)
	}
	if findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens) != nil {
		t.Fatalf("did not expect 1h cache write hold without ttl 1h, got %#v", state.Hold.Meters)
	}
	state.Signals = &StandardSignals{
		Prompt:       resolution.InputTokenLimit(),
		Completion:   resolution.OutputTokenLimit(),
		CacheWrite5m: resolution.InputTokenLimit(),
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover default 5m cache write: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
}

func TestAnthropicHoldCoversToolSystemPromptOverhead(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":"required","max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	expectedInput := big.NewInt(int64(resolution.InputTokenLimit() + anthropicToolSystemPromptHoldTokens(resolution.Deployment.Upstream.Model, resolution.ToolTypes()))).String()
	inputMeter := findMeterEstimate(state.Hold.Meters, billing.MeterInputTokens)
	if inputMeter == nil || inputMeter.Quantity != expectedInput {
		t.Fatalf("expected one compacted Anthropic input hold of %s, got %#v", expectedInput, state.Hold.Meters)
	}
	if findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens) != nil || findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite5mInputTokens) != nil {
		t.Fatalf("did not expect cache write hold meter without cache_control, got %#v", state.Hold.Meters)
	}

	state.Signals = &StandardSignals{
		Prompt:     resolution.InputTokenLimit() + anthropicToolSystemPromptHoldTokens(resolution.Deployment.Upstream.Model, resolution.ToolTypes()),
		Completion: resolution.OutputTokenLimit(),
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover Anthropic tool overhead final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
}

func TestAnthropicHoldCoversCombinedFastUSCacheAndHostedToolPricing(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/anthropic-claude-opus-4-8-fast-us","input":[{"role":"user","content":[{"type":"input_text","text":"hello","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],"tools":[{"type":"web_search_20250305","name":"web_search"}],"max_tool_calls":2,"max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.Upstream.InferenceGeo != "us" || !strings.Contains(resolution.Deployment.ID, "fast") {
		t.Fatalf("expected fast US deployment, got %#v", resolution.Deployment)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	state.Signals = &StandardSignals{
		Prompt:       resolution.InputTokenLimit(),
		Completion:   resolution.OutputTokenLimit(),
		CacheWrite1h: resolution.InputTokenLimit(),
		WebSearch:    2,
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover combined fast US cache/tool final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
	if findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens) == nil {
		t.Fatalf("expected 1h cache write hold meter, got %#v", state.Hold.Meters)
	}
	if findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls) == nil {
		t.Fatalf("expected hosted web-search final meter, got %#v", state.FinalMeters)
	}
}

func TestSignalsFromUsageMapsSplitCacheWriteDetails(t *testing.T) {
	usage := &schemas.BifrostLLMUsage{
		PromptTokens:     1000,
		CompletionTokens: 20,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{
			CachedReadTokens: 100,
			CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
				CachedWriteTokens5m: 200,
				CachedWriteTokens1h: 300,
			},
		},
	}
	signals := signalsFromUsage(usage)
	if signals == nil {
		t.Fatal("expected signals")
	}
	if signals.Prompt != 1000 || signals.Completion != 20 || signals.Cached != 100 || signals.CacheWrite5m != 200 || signals.CacheWrite1h != 300 {
		t.Fatalf("unexpected cache signal mapping: %#v", signals)
	}
}

func TestSignalsFromUsageFallbackIncludesSplitCacheWriteDetails(t *testing.T) {
	usage := &schemas.BifrostLLMUsage{
		CompletionTokens: 20,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{
			TextTokens:       400,
			CachedReadTokens: 100,
			CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
				CachedWriteTokens5m: 200,
				CachedWriteTokens1h: 300,
			},
		},
	}
	signals := signalsFromUsage(usage)
	if signals == nil {
		t.Fatal("expected signals")
	}
	if signals.Prompt != 1000 || signals.Completion != 20 || signals.Cached != 100 || signals.CacheWrite5m != 200 || signals.CacheWrite1h != 300 {
		t.Fatalf("unexpected split cache-write fallback mapping: %#v", signals)
	}
}

func TestSignalsFromUsageKeepsProviderUnspecifiedCacheWritesGeneric(t *testing.T) {
	usage := &schemas.BifrostLLMUsage{
		PromptTokens:     1000,
		CompletionTokens: 20,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{
			CachedWriteTokens: 200,
		},
	}
	signals := signalsFromUsage(usage)
	if signals == nil {
		t.Fatal("expected signals")
	}
	if signals.CacheWrite != 200 || signals.CacheWrite5m != 0 || signals.CacheWrite1h != 0 {
		t.Fatalf("expected unspecified cache write tokens to remain generic, got %#v", signals)
	}
}
