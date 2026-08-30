package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func (f *fakeBillingAuthorizer) AuthorizeRequestWithPassthrough(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, estimatedUpstreamCostUSDAtoms string, _ int, _ string, _ *billing.UpstreamTarget, requestLifetime time.Duration, _ bool) (*billing.Authorization, error) {
	return f.authorize(requestID)
}

func (f *fakeBillingAuthorizer) AuthorizeDashboardRequestWithDuration(ctx context.Context, _ *billing.DashboardCredential, requestID string, providerKey string, productKey string, estimatedUpstreamCostUSDAtoms string, _ int, _ *billing.UpstreamTarget, requestLifetime time.Duration) (*billing.Authorization, error) {
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

	authorization, err := authorizeWithFreshRequestID(ctx, authorizer, "sk-user", HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", EstimatedUpstreamCostUSDAtoms: "1000"}, 1, "", nil, billing.GatewayRequestLifetime, authorizer.errors[0])
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

	authorization, err := authorizeWithFreshRequestID(ctx, &fakeBillingAuthorizer{}, "sk-user", HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", EstimatedUpstreamCostUSDAtoms: "1000"}, 1, "", nil, billing.GatewayRequestLifetime, expectedErr)
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

func TestAuthorizeWithFreshRequestIDDoesNotTurnAStalePolicyIntoARequestRetry(t *testing.T) {
	initialRequestID := "11111111-1111-1111-1111-111111111111"
	expectedErr := &statusError{err: billing.ErrAPIKeyConfigStale, statusCode: 503}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, initialRequestID)
	authorizer := &fakeBillingAuthorizer{}

	authorization, err := authorizeWithFreshRequestID(ctx, authorizer, "sk-user", HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", EstimatedUpstreamCostUSDAtoms: "1000"}, 1, "", nil, billing.GatewayRequestLifetime, expectedErr)
	if authorization != nil || !errors.Is(err, billing.ErrAPIKeyConfigStale) {
		t.Fatalf("authorization=%#v error=%v, want the stale configuration error", authorization, err)
	}
	if len(authorizer.attempts) != 0 {
		t.Fatalf("stale policy caused request-ID retries: %#v", authorizer.attempts)
	}
	currentRequestID, _ := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if currentRequestID != initialRequestID {
		t.Fatalf("stale policy changed request ID to %q", currentRequestID)
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
	state.Hold = HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", EstimatedUpstreamCostUSDAtoms: "1000"}

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
	state.Hold = HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", EstimatedUpstreamCostUSDAtoms: "1000"}
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

func TestAuthorizeStateRejectsPassThroughWithDashboardCredential(t *testing.T) {
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, "11111111-1111-1111-1111-111111111111")
	state := NewState(&catalog.ResolvedRequest{
		Route:       catalog.RouteChat,
		RequestType: schemas.ChatCompletionRequest,
		Provider:    schemas.OpenAI,
		Model:       "gpt-5",
	}, "", nil, DefaultAdapter{})
	state.SetDashboardCredential(&billing.DashboardCredential{
		ActorUserID: "actor",
		KeyID:       "key",
		SessionID:   "session",
	})
	state.PassthroughByokSecret = "sk-upstream-secret"
	state.Hold = HoldEstimate{
		ProviderKey:                   "openai",
		ProductKey:                    "gpt-5",
		EstimatedUpstreamCostUSDAtoms: "1000",
	}
	authorizer := &fakeBillingAuthorizer{}

	err := AuthorizeState(ctx, authorizer, state)
	var dashboardErr passthroughDashboardError
	if !errors.As(err, &dashboardErr) || dashboardErr.StatusCode() != 400 {
		t.Fatalf("AuthorizeState error = %v, want dashboard pass-through rejection", err)
	}
	if authorizer.callCount != 0 {
		t.Fatal("dashboard pass-through reached hold authorization")
	}
	if state.PassthroughByokSecret != "" {
		t.Fatal("rejected dashboard pass-through credential remained in request state")
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

func TestApplyUpstreamCredentialsUsesPassThroughCredentialHashAttribution(t *testing.T) {
	const upstreamSecret = "sk-upstream-secret"
	const credentialHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	state := &State{
		Authorization: &billing.Authorization{
			UpstreamByok:       credentialHash,
			UpstreamByokSecret: upstreamSecret,
		},
		Resolution: &catalog.ResolvedRequest{Provider: schemas.OpenAI},
	}

	if err := ApplyUpstreamCredentials(ctx, state); err != nil {
		t.Fatalf("ApplyUpstreamCredentials returned error: %v", err)
	}
	directKey, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
	if !ok {
		t.Fatal("pass-through request did not install a direct provider key")
	}
	if directKey.ID != credentialHash || directKey.Name != credentialHash {
		t.Fatalf("direct key attribution = %#v, want credential hash", directKey)
	}
	if directKey.Value.GetValue() != upstreamSecret {
		t.Fatal("pass-through secret was not installed")
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

func TestDefaultAdapterCalculateUpstreamCostUsesSignals(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				"input_tokens":  {"per_mill_tokens": "1000000"},
				"output_tokens": {"per_mill_tokens": "2000000"},
			}},
		},
		Signals: &StandardSignals{Prompt: 1000, Completion: 2000},
	}
	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != "5000" {
		t.Fatalf("expected signal-derived final cost 5000, got %s", state.UpstreamCostUSDAtoms)
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

func TestCalculateUpstreamCostPartitionsEveryInputAndOutputCategoryExactlyOnce(t *testing.T) {
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
	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
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
	if state.UpstreamCostUSDAtoms != "1613" {
		t.Fatalf("exact partition cost = %s, want 1613; meters=%#v", state.UpstreamCostUSDAtoms, state.FinalMeters)
	}
}

func TestCalculateUpstreamCostKeepsUsablePromptWhenCacheBreakdownIsImpossible(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterInputTokens:           {billing.RatePerMillionTokens: "1000000"},
			billing.MeterCachedInputTokens:     {billing.RatePerMillionTokens: "100000"},
			billing.MeterCacheWriteInputTokens: {billing.RatePerMillionTokens: "1250000"},
		}}},
		Signals: &StandardSignals{Prompt: 100, Cached: 80, CacheWrite: 30},
	}
	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != "100" {
		t.Fatalf("final cost = %s, want 100 from the usable aggregate prompt; meters=%#v", state.UpstreamCostUSDAtoms, state.FinalMeters)
	}
	if meter := findMeterEstimate(state.FinalMeters, billing.MeterInputTokens); meterQuantity(meter) != "100" {
		t.Fatalf("ordinary input meter = %#v, want quantity 100", meter)
	}
	for _, meterKey := range []string{billing.MeterCachedInputTokens, billing.MeterCacheWriteInputTokens} {
		if meter := findMeterEstimate(state.FinalMeters, meterKey); meter != nil {
			t.Fatalf("invalid cache detail must be discarded, got %s meter %#v", meterKey, meter)
		}
	}
	if savings, err := cacheReadSavingsUSDAtoms(state); err != nil || savings == nil || *savings != "0" {
		t.Fatalf("cache savings = %#v, %v; want 0", savings, err)
	}
}

func TestCalculateUpstreamCostKeepsUnpricedCacheDetailsAsOrdinaryInput(t *testing.T) {
	tests := []struct {
		name    string
		signals *StandardSignals
	}{
		{name: "cache read", signals: &StandardSignals{Prompt: 100, Cached: 100}},
		{name: "generic cache write", signals: &StandardSignals{Prompt: 100, CacheWrite: 100}},
		{name: "five-minute cache write", signals: &StandardSignals{Prompt: 100, CacheWrite5m: 100}},
		{name: "one-hour cache write", signals: &StandardSignals{Prompt: 100, CacheWrite1h: 100}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &State{
				Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
					billing.MeterInputTokens: {billing.RatePerMillionTokens: "1000000"},
				}}},
				Signals: tt.signals,
			}
			cost, err := calculateBaseUpstreamCost(state, nil)
			if err != nil {
				t.Fatalf("calculateBaseUpstreamCost returned error: %v", err)
			}
			if cost != "100" || meterQuantity(findMeterEstimate(state.FinalMeters, billing.MeterInputTokens)) != "100" {
				t.Fatalf("unpriced cache detail changed ordinary input billing: cost=%s meters=%#v", cost, state.FinalMeters)
			}
			for _, meterKey := range []string{
				billing.MeterCachedInputTokens,
				billing.MeterCacheWriteInputTokens,
				billing.MeterCacheWrite5mInputTokens,
				billing.MeterCacheWrite1hInputTokens,
			} {
				if meter := findMeterEstimate(state.FinalMeters, meterKey); meter != nil {
					t.Fatalf("unpriced cache detail produced %s meter %#v", meterKey, meter)
				}
			}
			savings, savingsErr := cacheReadSavingsUSDAtoms(state)
			overhead, overheadErr := cacheWriteOverheadUSDAtoms(state)
			if savingsErr != nil || overheadErr != nil || savings == nil || overhead == nil || *savings != "0" || *overhead != "0" {
				t.Fatalf("unpriced cache economics = savings %#v (%v), overhead %#v (%v)", savings, savingsErr, overhead, overheadErr)
			}
		})
	}
}

func TestCalculateUpstreamCostSelectsContextTierFromActualUsage(t *testing.T) {
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost below threshold returned error: %v", err)
	}
	for _, meterKey := range []string{billing.MeterInputTokens, billing.MeterOutputTokens} {
		finalMeter := findMeterEstimate(state.FinalMeters, meterKey)
		if finalMeter == nil || finalMeter.RateKey != billing.RatePerMillionContextLTE272K || finalMeter.HoldRequired {
			t.Fatalf("expected low-context final meter for %s, got %#v in %#v", meterKey, finalMeter, state.FinalMeters)
		}
	}

	state.Signals = &StandardSignals{Prompt: billing.LongContextThresholdTokens + 1, Completion: 1}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost above threshold returned error: %v", err)
	}
	for _, meterKey := range []string{billing.MeterInputTokens, billing.MeterOutputTokens} {
		finalMeter := findMeterEstimate(state.FinalMeters, meterKey)
		if finalMeter == nil || finalMeter.RateKey != billing.RatePerMillionContextGT272K || finalMeter.HoldRequired {
			t.Fatalf("expected high-context final meter for %s, got %#v in %#v", meterKey, finalMeter, state.FinalMeters)
		}
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover high-context final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}

	state.Signals = &StandardSignals{Prompt: 1000, Completion: billing.LongContextThresholdTokens + 1}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost large output returned error: %v", err)
	}
	for _, meterKey := range []string{billing.MeterInputTokens, billing.MeterOutputTokens} {
		finalMeter := findMeterEstimate(state.FinalMeters, meterKey)
		if finalMeter == nil || finalMeter.RateKey != billing.RatePerMillionContextLTE272K {
			t.Fatalf("expected normal-context final meter for large output %s, got %#v in %#v", meterKey, finalMeter, state.FinalMeters)
		}
	}
}

func TestCalculateUpstreamCostPartitionsReasoningFromAggregateOutputWithoutDoubleCounting(t *testing.T) {
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
	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != "1500" {
		t.Fatalf("expected aggregate-token final cost 1500, got %s", state.UpstreamCostUSDAtoms)
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

func TestCalculateUpstreamCostUsesExplicitReasoningRateAndHoldReservesTheHigherOutputRate(t *testing.T) {
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
	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != "1040" {
		t.Fatalf("expected distinct output and reasoning rates to cost 1040, got %s", state.UpstreamCostUSDAtoms)
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

func TestCalculateUpstreamCostIgnoresImpossibleReasoningDetailAndKeepsCompletion(t *testing.T) {
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
	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	output := findMeterEstimate(state.FinalMeters, billing.MeterOutputTokens)
	if output == nil || output.Quantity != "10" || output.AmountUSDAtoms != "20" {
		t.Fatalf("usable completion aggregate was not retained: %#v", state.FinalMeters)
	}
	if findMeterEstimate(state.FinalMeters, billing.MeterReasoningTokens) != nil {
		t.Fatalf("impossible reasoning detail was priced: %#v", state.FinalMeters)
	}
}

func TestDefaultAdapterCalculateUpstreamCostDoesNotChargeWithoutUsage(t *testing.T) {
	tests := []struct {
		name       string
		statusCode *int
		message    string
	}{
		{name: "bad request", statusCode: lifecycleIntPtr(400), message: "messages.0.content is required"},
		{name: "request too large", statusCode: lifecycleIntPtr(413), message: "request exceeds maximum size"},
		{name: "bad request budget parameter", statusCode: lifecycleIntPtr(400), message: "task_budget.total is below the provider minimum"},
		{name: "bad request rate limit parameter", statusCode: lifecycleIntPtr(400), message: "rate_limit field is not valid for this model"},
		{name: "bad request timeout parameter", statusCode: lifecycleIntPtr(400), message: "timeout parameter is not supported"},
		{name: "bad request network option", statusCode: lifecycleIntPtr(400), message: "network setting is invalid"},
		{name: "conversion failure without status", message: "failed to marshal request: missing required field messages"},
		{name: "missing required field without status", message: "missing required 'type' field in ResponsesTool"},
		{name: "nil bifrost request without status", message: "bifrost request cannot be nil"},
		{name: "unsupported request without status", message: "unsupported request type: responses_stream"},
		{name: "provider auth", statusCode: lifecycleIntPtr(401), message: "provider API key invalid"},
		{name: "provider permission policy", statusCode: lifecycleIntPtr(403), message: "organization policy disabled provider access"},
		{name: "cataloged provider model not found", statusCode: lifecycleIntPtr(404), message: "model not found"},
		{name: "provider rate limit", statusCode: lifecycleIntPtr(429), message: "rate_limit exceeded"},
		{name: "provider network failure", message: "dial tcp: connection refused"},
		{name: "provider server failure", statusCode: lifecycleIntPtr(500), message: "provider failed"},
		{name: "provider server invalid request wording", statusCode: lifecycleIntPtr(500), message: "provider invalid request processor failed"},
		{name: "provider safety backend failure", statusCode: lifecycleIntPtr(500), message: "provider safety service unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &State{
				Authorization: &billing.Authorization{AuthorizedBilledCostUSDAtoms: big.NewInt(123)},
				BifrostError: &schemas.BifrostError{
					StatusCode: tt.statusCode,
					Error: &schemas.ErrorField{
						Message: tt.message,
					},
				},
			}
			if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if state.UpstreamCostUSDAtoms != billing.ZeroChargeUSDAtoms {
				t.Fatalf("UpstreamCostUSDAtoms = %s, want 0", state.UpstreamCostUSDAtoms)
			}
			if len(state.FinalMeters) != 0 {
				t.Fatalf("no-usage request produced final meters: %#v", state.FinalMeters)
			}
		})
	}
}

func TestDefaultAdapterCalculateUpstreamCostReturnsHoldWithoutUsage(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterOutputTokens: {billing.RatePerMillionTokens: "1000000"},
		}}},
		Authorization: &billing.Authorization{AuthorizedBilledCostUSDAtoms: big.NewInt(123)},
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
	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != billing.ZeroChargeUSDAtoms {
		t.Fatalf("UpstreamCostUSDAtoms = %s, want 0", state.UpstreamCostUSDAtoms)
	}
	if len(state.FinalMeters) != 0 {
		t.Fatalf("no-usage request produced final meters: %#v", state.FinalMeters)
	}
}

func TestCalculateBaseUpstreamCostChargesProviderMetersWithoutTokenUsage(t *testing.T) {
	const meterKey = "provider_tool_calls"
	pricing := catalog.Pricing{
		meterKey: {billing.RatePerThousandCalls: "1000"},
	}
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: pricing}},
		Hold: HoldEstimate{Meters: []catalog.MeterEstimate{{
			MeterKey:     meterKey,
			Quantity:     "1",
			HoldRequired: true,
		}},
		},
	}
	extraMeters := billing.AppendCallMeterCost(nil, pricing, meterKey, 1, false)
	cost, err := calculateBaseUpstreamCost(state, extraMeters)
	if err != nil {
		t.Fatalf("calculateBaseUpstreamCost returned error: %v", err)
	}
	if cost != "1" || len(state.FinalMeters) != 1 || state.FinalMeters[0].Quantity != "1" {
		t.Fatalf("provider meter was not billed independently: cost=%s meters=%#v", cost, state.FinalMeters)
	}
}

func TestDefaultAdapterCalculateUpstreamCostChargesReportedUsageWithProviderError(t *testing.T) {
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

	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != "1500" {
		t.Fatalf("UpstreamCostUSDAtoms = %s, want usage-derived 1500", state.UpstreamCostUSDAtoms)
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

func TestEveryTelemetryErrorCategoryIsIndependentOfBestEffortSettlement(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		errorType  string
		code       string
		wantStatus string
	}{
		{name: "authentication", statusCode: 401, wantStatus: "authentication_error"},
		{name: "permission", statusCode: 403, wantStatus: "permission_error"},
		{name: "quota through rate HTTP status", statusCode: 429, code: "insufficient_quota", wantStatus: "over_budget"},
		{name: "rate limit", statusCode: 429, errorType: "rate_limit_error", wantStatus: "rate_limited"},
		{name: "cancellation", statusCode: 499, errorType: schemas.RequestCancelled, wantStatus: "cancelled"},
		{name: "timeout", statusCode: 504, errorType: schemas.RequestTimedOut, wantStatus: "network_error"},
		{name: "content filter", statusCode: 400, code: "content_filter", wantStatus: "content_filter"},
		{name: "invalid request", statusCode: 400, errorType: "invalid_request_error", wantStatus: "invalid_request"},
		{name: "server failure", statusCode: 500, errorType: "api_error", wantStatus: "provider_error"},
		{name: "unknown future rejection", statusCode: 418, errorType: "future_error", wantStatus: "provider_error"},
	}
	pricing := catalog.Pricing{
		billing.MeterInputTokens:           {billing.RatePerMillionTokens: "1000000"},
		billing.MeterCachedInputTokens:     {billing.RatePerMillionTokens: "100000"},
		billing.MeterCacheWriteInputTokens: {billing.RatePerMillionTokens: "1250000"},
		billing.MeterOutputTokens:          {billing.RatePerMillionTokens: "2000000"},
	}
	usage := &schemas.BifrostLLMUsage{
		PromptTokens:     100,
		CompletionTokens: 20,
		TotalTokens:      120,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{
			CachedReadTokens:  10,
			CachedWriteTokens: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providerErr := &schemas.BifrostError{
				StatusCode: &tt.statusCode,
				Error:      &schemas.ErrorField{Message: "untrusted provider message"},
				ExtraFields: schemas.BifrostErrorExtraFields{
					BilledUsage: usage,
				},
			}
			if tt.errorType != "" {
				providerErr.Error.Type = &tt.errorType
			}
			if tt.code != "" {
				providerErr.Error.Code = &tt.code
			}
			if got := billing.NormalizeUpstreamStatus(providerErr); got != tt.wantStatus {
				t.Fatalf("normalized status = %q, want %q", got, tt.wantStatus)
			}

			withUsage := &State{
				Adapter: OpenAIAdapter{},
				Resolution: &catalog.ResolvedRequest{
					Provider:   schemas.OpenAI,
					Route:      catalog.RouteChat,
					Deployment: catalog.Deployment{Pricing: pricing},
				},
			}
			if err := withUsage.Adapter.IngestResponse(withUsage, nil, providerErr); err != nil {
				t.Fatalf("IngestResponse returned error: %v", err)
			}
			if err := withUsage.Adapter.CalculateUpstreamCost(withUsage); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if withUsage.UpstreamCostUSDAtoms != "136" {
				t.Fatalf("usage-backed cost = %s, want 136; meters=%#v", withUsage.UpstreamCostUSDAtoms, withUsage.FinalMeters)
			}
			savings, savingsErr := cacheReadSavingsUSDAtoms(withUsage)
			overhead, overheadErr := cacheWriteOverheadUSDAtoms(withUsage)
			if savingsErr != nil || overheadErr != nil || savings == nil || overhead == nil || *savings != "9" || *overhead != "5" {
				t.Fatalf("usage-backed cache economics = %#v/%#v (%v/%v), want 9/5", savings, overhead, savingsErr, overheadErr)
			}

			withoutUsage := &State{
				Resolution:   &catalog.ResolvedRequest{Provider: schemas.OpenAI, Deployment: catalog.Deployment{Pricing: pricing}},
				BifrostError: providerErr,
			}
			providerErr.ExtraFields.BilledUsage = nil
			if err := (DefaultAdapter{}).CalculateUpstreamCost(withoutUsage); err != nil {
				t.Fatalf("zero-usage CalculateUpstreamCost returned error: %v", err)
			}
			if withoutUsage.UpstreamCostUSDAtoms != billing.ZeroChargeUSDAtoms || len(withoutUsage.FinalMeters) != 0 {
				t.Fatalf("zero-usage error was charged: cost=%s meters=%#v", withoutUsage.UpstreamCostUSDAtoms, withoutUsage.FinalMeters)
			}
			providerErr.ExtraFields.BilledUsage = usage
		})
	}
}

func TestNoUsageClientErrorHasNoFinalMeters(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterOutputTokens: {billing.RatePerMillionTokens: "2000000"},
		}}},
		Authorization: &billing.Authorization{AuthorizedBilledCostUSDAtoms: big.NewInt(2000)},
		Hold: HoldEstimate{
			EstimatedUpstreamCostUSDAtoms: "2000",
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

	if err := (DefaultAdapter{}).CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != billing.ZeroChargeUSDAtoms {
		t.Fatalf("UpstreamCostUSDAtoms = %s, want 0", state.UpstreamCostUSDAtoms)
	}
	if len(state.FinalMeters) != 0 {
		t.Fatalf("no-usage request produced final meters: %#v", state.FinalMeters)
	}

	pricing := pricingForState(state)
	if len(pricing) != 0 {
		t.Fatalf("no-usage request produced pricing: %#v", pricing)
	}
}

func lifecycleIntPtr(value int) *int {
	return &value
}

func TestCalculateUpstreamCostUsesActualOpenAIServiceTierWhenExplicitTierReturned(t *testing.T) {
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != "12500000000000000" {
		t.Fatalf("expected Fast input pricing from returned priority tier, got %s", state.UpstreamCostUSDAtoms)
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
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
	authorizedBilledCostUSDAtoms, ok := new(big.Int).SetString(state.Hold.EstimatedUpstreamCostUSDAtoms, 10)
	if !ok {
		t.Fatalf("invalid hold amount %q", state.Hold.EstimatedUpstreamCostUSDAtoms)
	}
	state.Authorization = &billing.Authorization{
		AuthorizedBilledCostUSDAtoms: authorizedBilledCostUSDAtoms,
		CreatedAt:                    time.Now().UTC(),
		ProviderKey:                  "openai",
		ProductKey:                   resolution.Deployment.ID,
		RequestID:                    "fast-downgrade",
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("Fast hold must cover the returned priority-tier cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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

func TestOpenAICacheReadCalculateUpstreamCostStaysCoveredByNoCacheHold(t *testing.T) {
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
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if findMeterEstimate(state.FinalMeters, billing.MeterCachedInputTokens) == nil {
				t.Fatalf("expected cached input final meter, got %#v", state.FinalMeters)
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover OpenAI cached-read final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
			}
		})
	}
}

func TestMissingCacheWriteUsageDoesNotInventAWritePremium(t *testing.T) {
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
		{name: "Azure cacheable miss remains ordinary input", provider: schemas.Azure, prompt: 2048, wantInput: "2048"},
		{name: "Azure partial hit retains uncached input", provider: schemas.Azure, prompt: 2048, cached: 512, wantInput: "1536"},
		{name: "Azure exact report wins", provider: schemas.Azure, prompt: 2048, cached: 512, reportedWrite: 1024, wantInput: "512", wantCacheWrite: "1024"},
		{name: "OpenAI missing write remains ordinary input", provider: schemas.OpenAI, prompt: 2048, wantInput: "2048"},
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
			if _, err := calculateBaseUpstreamCost(state, nil); err != nil {
				t.Fatalf("calculateBaseUpstreamCost returned error: %v", err)
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
				if state.Hold.EstimatedUpstreamCostUSDAtoms == "" || state.Hold.EstimatedUpstreamCostUSDAtoms == billing.ZeroChargeUSDAtoms {
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
						if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
							t.Fatalf("calculate final price: %v", err)
						}
						if state.UpstreamCostUSDAtoms == billing.ZeroChargeUSDAtoms {
							t.Fatalf("final token price is zero: meters=%#v", state.FinalMeters)
						}
						if findMeterEstimate(state.FinalMeters, scenario.meter) == nil {
							t.Fatalf("final price omitted %s: %#v", scenario.meter, state.FinalMeters)
						}
						if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
							t.Fatalf(
								"hold does not cover final price: hold=%s final=%s holdMeters=%#v finalMeters=%#v",
								state.Hold.EstimatedUpstreamCostUSDAtoms,
								state.UpstreamCostUSDAtoms,
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

func TestEveryActiveCatalogDeploymentPricesEveryTokenMeterExactly(t *testing.T) {
	type matrixDeployment struct {
		Pricing catalog.Pricing `json:"pricing"`
	}
	public, ok := catalog.PublicCatalogPayload()
	if !ok {
		t.Fatal("compiled public catalog is unavailable")
	}
	deployments := map[string]matrixDeployment{}
	if err := json.Unmarshal(public.Graph["deployments"], &deployments); err != nil {
		t.Fatalf("decode catalog deployments: %v", err)
	}

	tokenMeters := []string{
		billing.MeterInputTokens,
		billing.MeterCachedInputTokens,
		billing.MeterCacheWriteInputTokens,
		billing.MeterCacheWrite5mInputTokens,
		billing.MeterCacheWrite1hInputTokens,
		billing.MeterOutputTokens,
		billing.MeterReasoningTokens,
	}
	deploymentIDs := make([]string, 0, len(deployments))
	for deploymentID := range deployments {
		deploymentIDs = append(deploymentIDs, deploymentID)
	}
	slices.Sort(deploymentIDs)

	for _, deploymentID := range deploymentIDs {
		pricing := effectivePricingForDeployment(catalog.Deployment{Pricing: deployments[deploymentID].Pricing})
		for _, meterKey := range tokenMeters {
			standardRateKey, _, standardPriced := billing.PricingRate(
				pricing,
				meterKey,
				billing.TokenRateStandard,
			)
			if !standardPriced {
				continue
			}
			modes := []struct {
				name          string
				promptContext int
				rateMode      billing.TokenRateMode
			}{
				{name: "standard", promptContext: 1, rateMode: billing.TokenRateStandard},
			}
			longRateKey, _, longPriced := billing.PricingRate(
				pricing,
				meterKey,
				billing.TokenRateLongContext,
			)
			if longPriced && longRateKey != standardRateKey {
				modes = append(modes, struct {
					name          string
					promptContext int
					rateMode      billing.TokenRateMode
				}{
					name:          "long-context",
					promptContext: billing.LongContextThresholdTokens + 1,
					rateMode:      billing.TokenRateLongContext,
				})
			}

			for _, mode := range modes {
				t.Run(deploymentID+"/"+meterKey+"/"+mode.name, func(t *testing.T) {
					quantity := 1
					signals := &StandardSignals{}
					switch meterKey {
					case billing.MeterInputTokens:
						quantity = mode.promptContext
						signals.Prompt = quantity
					case billing.MeterCachedInputTokens:
						quantity = mode.promptContext
						signals.Prompt = quantity
						signals.Cached = quantity
					case billing.MeterCacheWriteInputTokens:
						quantity = mode.promptContext
						signals.Prompt = quantity
						signals.CacheWrite = quantity
					case billing.MeterCacheWrite5mInputTokens:
						quantity = mode.promptContext
						signals.Prompt = quantity
						signals.CacheWrite5m = quantity
					case billing.MeterCacheWrite1hInputTokens:
						quantity = mode.promptContext
						signals.Prompt = quantity
						signals.CacheWrite1h = quantity
					case billing.MeterOutputTokens:
						if mode.rateMode == billing.TokenRateLongContext {
							signals.Prompt = mode.promptContext
						}
						signals.Completion = quantity
					case billing.MeterReasoningTokens:
						if mode.rateMode == billing.TokenRateLongContext {
							signals.Prompt = mode.promptContext
						}
						signals.Completion = quantity
						signals.Reasoning = quantity
					default:
						t.Fatalf("unhandled token meter %s", meterKey)
					}

					state := &State{
						Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: deployments[deploymentID].Pricing}},
						Signals:    signals,
					}
					if _, err := calculateBaseUpstreamCost(state, nil); err != nil {
						t.Fatalf("calculateBaseUpstreamCost returned error: %v", err)
					}
					meter := findMeterEstimate(state.FinalMeters, meterKey)
					if meter == nil {
						t.Fatalf("final price omitted %s: %#v", meterKey, state.FinalMeters)
					}
					rateKey, rate, priced := billing.PricingRate(pricing, meterKey, mode.rateMode)
					if !priced {
						t.Fatalf("effective pricing omitted %s/%s", meterKey, mode.name)
					}
					wantAmount, err := calculatedMeterAmount(rateKey, big.NewInt(int64(quantity)), rate)
					if err != nil {
						t.Fatalf("calculate expected meter amount: %v", err)
					}
					if meter.Quantity != strconv.Itoa(quantity) ||
						meter.RateKey != rateKey ||
						meter.RateUSDAtoms != rate.String() ||
						meter.AmountUSDAtoms != wantAmount.String() {
						t.Fatalf(
							"%s meter = %#v, want quantity=%d rate=%s/%s amount=%s",
							meterKey,
							meter,
							quantity,
							rateKey,
							rate,
							wantAmount,
						)
					}
				})
			}
		}
	}
}

func TestCalculateUpstreamCostUsesSelectedDeploymentForUnknownActualTier(t *testing.T) {
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms != "50000000000000" {
		t.Fatalf("expected selected default deployment pricing for unknown actual tier, got %s", state.UpstreamCostUSDAtoms)
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

func TestAnthropicNoOutputRefusalDoesNotChargeInformationalUsage(t *testing.T) {
	refusal := "refusal"
	stop := "stop"
	pricing := catalog.Pricing{
		billing.MeterInputTokens:  {billing.RatePerMillionTokens: "1000000"},
		billing.MeterOutputTokens: {billing.RatePerMillionTokens: "1000000"},
	}
	tests := []struct {
		name          string
		response      *schemas.BifrostResponse
		outputEmitted bool
		wantCost      string
	}{
		{
			name: "chat refusal before output",
			response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
				FinishReason: &refusal,
			}}}},
			wantCost: billing.ZeroChargeUSDAtoms,
		},
		{
			name: "responses refusal before output",
			response: &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
				StopReason: &refusal,
			}},
			wantCost: billing.ZeroChargeUSDAtoms,
		},
		{
			name: "refusal after provider output reaches a disconnected caller",
			response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
				FinishReason: &refusal,
			}}}},
			outputEmitted: true,
			wantCost:      "13",
		},
		{
			name: "ordinary empty terminal still uses reported usage",
			response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
				FinishReason: &stop,
			}}}},
			wantCost: "13",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &State{
				Resolution: &catalog.ResolvedRequest{
					Provider:   schemas.Anthropic,
					Deployment: catalog.Deployment{Pricing: pricing},
				},
				Signals:               &StandardSignals{Prompt: 10, Completion: 3},
				Response:              tt.response,
				providerOutputEmitted: tt.outputEmitted,
			}
			if err := (AnthropicAdapter{}).CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if state.UpstreamCostUSDAtoms != tt.wantCost {
				t.Fatalf("cost = %s, want %s; meters=%#v", state.UpstreamCostUSDAtoms, tt.wantCost, state.FinalMeters)
			}
			if tt.wantCost == billing.ZeroChargeUSDAtoms && len(state.FinalMeters) != 0 {
				t.Fatalf("informational refusal usage produced priced meters: %#v", state.FinalMeters)
			}
		})
	}
}

func TestAnthropicCalculateUpstreamCostUsesReturnedServiceTierDeployment(t *testing.T) {
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
			// This test isolates execution-price selection. Authorization-bound
			// quantity clipping is covered separately.
			state.Hold.Meters = nil

			mutatedPricing := copyPricing(resolution.Deployment.Pricing)
			mutatedPricing[billing.MeterInputTokens] = map[string]string{billing.RatePerMillionTokens: "999000000000000000000"}
			mutatedPricing[billing.MeterOutputTokens] = map[string]string{billing.RatePerMillionTokens: "999000000000000000000"}
			resolution.Deployment.Pricing = mutatedPricing

			state.Signals = &StandardSignals{
				Prompt:            1000,
				Completion:        1000,
				ActualServiceTier: &tt.actualTier,
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if state.UpstreamCostUSDAtoms != "30000000000000000" {
				t.Fatalf("expected cataloged actual service-tier pricing, got %s meters=%#v", state.UpstreamCostUSDAtoms, state.FinalMeters)
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
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
				t.Fatalf("Anthropic mapped service-tier hold must cover final: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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
			AuthorizedBilledCostUSDAtoms: big.NewInt(3000),
			AvailableBalanceUSDAtoms:     big.NewInt(0),
			CreatedAt:                    time.Now().UTC(),
			KeyID:                        "key",
			OrganizationID:               "org",
			ProviderKey:                  "openai",
			ProductKey:                   "gpt-5",
			RequestID:                    "request",
			UserID:                       "user",
			WorkspaceID:                  "workspace",
		},
		Hold: HoldEstimate{
			EstimatedUpstreamCostUSDAtoms: "3000",
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
		RequestType:          string(schemas.ChatCompletionRequest),
		Model:                "gpt-5",
		GatewayVersion:       "v1.5.13",
		StartedAt:            time.Now().UTC(),
		UpstreamCostUSDAtoms: "1000",
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

func TestUnaryProviderLatencyDoesNotFabricateTTFT(t *testing.T) {
	now := time.Now().UTC()
	state := &State{
		Authorization: &billing.Authorization{
			AuthorizedBilledCostUSDAtoms: big.NewInt(0),
			AvailableBalanceUSDAtoms:     big.NewInt(0),
			RequestID:                    "request",
		},
		UpstreamCostUSDAtoms: billing.ZeroChargeUSDAtoms,
		RequestType:          string(schemas.ChatCompletionRequest),
		Response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{
			ExtraFields: schemas.BifrostResponseExtraFields{Latency: 81},
		}},
		ProviderCompletedAt: now.Add(-9 * time.Millisecond),
		ProviderStartedAt:   now.Add(-90 * time.Millisecond),
		StartedAt:           now.Add(-100 * time.Millisecond),
	}
	authorizer := &fakeBillingAuthorizer{}
	FinalizeState(context.Background(), authorizer, state)

	if len(authorizer.finalEvents) != 1 {
		t.Fatalf("expected one final event, got %d", len(authorizer.finalEvents))
	}
	event := authorizer.finalEvents[0]
	attempt := event.ProviderAttempts[0]
	if attempt.LatencyMS != 81 {
		t.Fatalf("expected provider total latency 81, got %#v", attempt)
	}
	if event.TTFTMS != nil {
		t.Fatalf("buffered requests must not report TTFT, got %#v", event.TTFTMS)
	}
}

func TestTTFTUsesRequestClockAndRemainsFirstObservation(t *testing.T) {
	state := &State{
		StartedAt:         time.Now().UTC().Add(-30 * time.Millisecond),
		ProviderStartedAt: time.Now().UTC().Add(-10 * time.Millisecond),
	}
	state.observeTTFT()
	if state.TTFTMS == nil || *state.TTFTMS < 25 || *state.TTFTMS > 100 {
		t.Fatalf("expected the gateway request clock, got %#v", state.TTFTMS)
	}
	first := *state.TTFTMS
	state.StartedAt = time.Now().UTC().Add(-time.Second)
	state.observeTTFT()
	if *state.TTFTMS != first {
		t.Fatalf("the first generated token must remain authoritative, got %#v", state.TTFTMS)
	}
}

func TestTTFTIgnoresProtocolMetadata(t *testing.T) {
	state := &State{StartedAt: time.Now().UTC().Add(-20 * time.Millisecond)}
	finishReason := "stop"
	state.ObserveChatStreamOutput(&schemas.BifrostChatResponse{
		Choices: []schemas.BifrostResponseChoice{{
			FinishReason: &finishReason,
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
				Delta: &schemas.ChatStreamResponseChoiceDelta{Role: stringPointer("assistant")},
			},
		}},
	})
	for _, eventType := range []schemas.ResponsesStreamResponseType{
		schemas.ResponsesStreamResponseTypePing,
		schemas.ResponsesStreamResponseTypeCreated,
		schemas.ResponsesStreamResponseTypeInProgress,
		schemas.ResponsesStreamResponseTypeCompleted,
		schemas.ResponsesStreamResponseTypeFailed,
		schemas.ResponsesStreamResponseTypeIncomplete,
		schemas.ResponsesStreamResponseTypeError,
	} {
		state.ObserveResponsesStreamOutput(&schemas.BifrostResponsesStreamResponse{Type: eventType})
	}
	if state.TTFTMS != nil || state.ProviderOutputObserved {
		t.Fatalf("protocol and terminal metadata must not count as provider output: %#v", state)
	}

	text := "hello"
	state.ObserveResponsesStreamOutput(&schemas.BifrostResponsesStreamResponse{
		Delta: &text,
		Type:  schemas.ResponsesStreamResponseTypeOutputTextDelta,
	})
	if state.TTFTMS == nil || *state.TTFTMS < 15 {
		t.Fatalf("output delta did not record TTFT: %#v", state.TTFTMS)
	}
}

func TestTTFTIsNarrowerThanProviderOutputObservation(t *testing.T) {
	annotationURL := "https://example.com/source"
	text := "answer"
	state := &State{StartedAt: time.Now().UTC().Add(-20 * time.Millisecond)}
	state.ObserveChatStreamOutput(&schemas.BifrostChatResponse{
		Choices: []schemas.BifrostResponseChoice{{
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &schemas.ChatStreamResponseChoiceDelta{
				Annotations: []schemas.ChatAssistantMessageAnnotation{{
					URLCitation: schemas.ChatAssistantMessageAnnotationCitation{URL: &annotationURL},
				}},
			}},
		}},
	})
	if !state.ProviderOutputObserved || state.TTFTMS != nil {
		t.Fatalf("citation output must not start TTFT: %#v", state)
	}
	state.ObserveChatStreamOutput(&schemas.BifrostChatResponse{
		Choices: []schemas.BifrostResponseChoice{{
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &schemas.ChatStreamResponseChoiceDelta{Content: &text}},
		}},
	})
	if state.TTFTMS == nil {
		t.Fatal("generated text did not start TTFT")
	}
}

func TestTTFTRejectsFutureClockAndSaturates(t *testing.T) {
	future := &State{StartedAt: time.Now().UTC().Add(time.Second)}
	future.observeTTFT()
	if future.TTFTMS != nil {
		t.Fatalf("future request clock produced TTFT: %#v", future.TTFTMS)
	}

	maximum := uint64(^uint32(0))
	saturated := &State{StartedAt: time.Now().UTC().Add(-time.Duration(maximum+1_000) * time.Millisecond)}
	saturated.observeTTFT()
	if saturated.TTFTMS == nil || *saturated.TTFTMS != ^uint32(0) {
		t.Fatalf("TTFT did not saturate: %#v", saturated.TTFTMS)
	}
}

func TestChatOutputObservationRequiresUsablePayload(t *testing.T) {
	text := "hello"
	arguments := `{"city":"Paris"}`
	refusal := "I cannot help with that"
	summary := "I should use the weather tool"
	encrypted := "encrypted"
	signature := "signature"
	toolID := "call_1"
	toolName := "lookup"
	annotationURL := "https://example.com"
	streamResponse := func(delta *schemas.ChatStreamResponseChoiceDelta) *schemas.BifrostChatResponse {
		return &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: delta},
		}}}
	}
	tests := []struct {
		name       string
		response   *schemas.BifrostChatResponse
		wantOutput bool
		wantToken  bool
	}{
		{name: "role only", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{Role: schemas.Ptr("assistant")})},
		{name: "empty audio", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{Audio: &schemas.ChatAudioMessageAudio{}})},
		{name: "empty reasoning detail", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{ReasoningDetails: []schemas.ChatReasoningDetails{{Type: schemas.BifrostReasoningDetailsTypeText}}})},
		{name: "placeholder tool call", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{ToolCalls: []schemas.ChatAssistantMessageToolCall{{}}})},
		{name: "signature only", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{ReasoningDetails: []schemas.ChatReasoningDetails{{Type: schemas.BifrostReasoningDetailsTypeEncrypted, Signature: &signature}}})},
		{name: "text", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{Content: &text}), wantOutput: true, wantToken: true},
		{name: "refusal", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{Refusal: &refusal}), wantOutput: true, wantToken: true},
		{name: "audio data", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{Audio: &schemas.ChatAudioMessageAudio{Data: "base64-audio"}}), wantOutput: true, wantToken: true},
		{name: "audio transcript", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{Audio: &schemas.ChatAudioMessageAudio{Transcript: text}}), wantOutput: true, wantToken: true},
		{name: "reasoning summary", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{ReasoningDetails: []schemas.ChatReasoningDetails{{Type: schemas.BifrostReasoningDetailsTypeSummary, Summary: &summary}}}), wantOutput: true, wantToken: true},
		{name: "reasoning text", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{Reasoning: &text}), wantOutput: true, wantToken: true},
		{name: "encrypted reasoning", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{ReasoningDetails: []schemas.ChatReasoningDetails{{Type: schemas.BifrostReasoningDetailsTypeEncrypted, Data: &encrypted}}}), wantOutput: true},
		{name: "tool ID", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{ToolCalls: []schemas.ChatAssistantMessageToolCall{{ID: &toolID}}}), wantOutput: true},
		{name: "tool name", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{ToolCalls: []schemas.ChatAssistantMessageToolCall{{Function: schemas.ChatAssistantMessageToolCallFunction{Name: &toolName}}}}), wantOutput: true, wantToken: true},
		{name: "tool arguments", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{ToolCalls: []schemas.ChatAssistantMessageToolCall{{Function: schemas.ChatAssistantMessageToolCallFunction{Arguments: arguments}}}}), wantOutput: true, wantToken: true},
		{name: "citation", response: streamResponse(&schemas.ChatStreamResponseChoiceDelta{Annotations: []schemas.ChatAssistantMessageAnnotation{{URLCitation: schemas.ChatAssistantMessageAnnotationCitation{URL: &annotationURL}}}}), wantOutput: true},
		{
			name: "complete response choice",
			response: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
				ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{Message: &schemas.ChatMessage{
					Role:    schemas.ChatMessageRoleAssistant,
					Content: &schemas.ChatMessageContent{ContentStr: &text},
				}},
			}}},
			wantOutput: true,
			wantToken:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chatResponseHasOutput(tt.response); got != tt.wantOutput {
				t.Fatalf("chatResponseHasOutput() = %v, want %v", got, tt.wantOutput)
			}
			if got := chatResponseHasToken(tt.response); got != tt.wantToken {
				t.Fatalf("chatResponseHasToken() = %v, want %v", got, tt.wantToken)
			}
		})
	}
}

func TestProviderOutputEmissionIsIndependentOfCallerDelivery(t *testing.T) {
	signature := "signed-thinking"
	streamSignature := &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
		ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &schemas.ChatStreamResponseChoiceDelta{
			ReasoningDetails: []schemas.ChatReasoningDetails{{Signature: &signature}},
		}},
	}}}
	if chatResponseHasOutput(streamSignature) {
		t.Fatal("a signature alone is not usable caller output")
	}
	if !chatResponseHasProviderOutput(streamSignature) {
		t.Fatal("a signature proves that the provider emitted generated reasoning")
	}

	text := "generated"
	buffered := &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
		ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{Message: &schemas.ChatMessage{
			Role:    schemas.ChatMessageRoleAssistant,
			Content: &schemas.ChatMessageContent{ContentStr: &text},
		}},
	}}}}
	if !providerResponseHasOutput(buffered) {
		t.Fatal("buffered assistant text was not recognized as provider output")
	}

	terminalOnly := &schemas.BifrostResponse{ResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
		Type: schemas.ResponsesStreamResponseTypeCompleted,
	}}
	if providerResponseHasOutput(terminalOnly) {
		t.Fatal("terminal protocol metadata was mistaken for provider output")
	}
}

func TestResponsesOutputObservationRequiresUsablePayload(t *testing.T) {
	text := "hello"
	empty := ""
	encrypted := "encrypted"
	toolOutput := `{"temperature":21}`
	toolType := schemas.ResponsesMessageTypeFunctionCall
	messageType := schemas.ResponsesMessageTypeMessage
	emptyToolType := schemas.ResponsesMessageTypeComputerCall
	messageWithText := func() *schemas.ResponsesMessage {
		return &schemas.ResponsesMessage{
			Type:    &messageType,
			Role:    schemas.Ptr(schemas.ResponsesInputMessageRoleAssistant),
			Content: &schemas.ResponsesMessageContent{ContentStr: &text},
		}
	}
	tests := []struct {
		name       string
		response   *schemas.BifrostResponsesStreamResponse
		wantOutput bool
		wantToken  bool
	}{
		{
			name:     "unknown event",
			response: &schemas.BifrostResponsesStreamResponse{Type: "response.future_metadata"},
		},
		{
			name:     "empty text delta",
			response: &schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDelta, Delta: &empty},
		},
		{
			name: "role-only item",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeOutputItemDone,
				Item: &schemas.ResponsesMessage{Type: &messageType, Role: schemas.Ptr(schemas.ResponsesInputMessageRoleAssistant)},
			},
		},
		{
			name: "empty tool action",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeOutputItemDone,
				Item: &schemas.ResponsesMessage{
					Type: &emptyToolType,
					ResponsesToolMessage: &schemas.ResponsesToolMessage{
						Action: &schemas.ResponsesToolMessageActionStruct{},
					},
				},
			},
		},
		{
			name: "empty computer output",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeOutputItemDone,
				Item: &schemas.ResponsesMessage{ResponsesToolMessage: &schemas.ResponsesToolMessage{
					Output: &schemas.ResponsesToolMessageOutputStruct{
						ResponsesComputerToolCallOutput: &schemas.ResponsesComputerToolCallOutputData{},
					},
				}},
			},
		},
		{
			name:     "terminal metadata with empty response",
			response: &schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeCompleted, Response: &schemas.BifrostResponsesResponse{}},
		},
		{
			name:       "text delta",
			response:   &schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDelta, Delta: &text},
			wantOutput: true,
			wantToken:  true,
		},
		{
			name:       "text done without delta",
			response:   &schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDone, Text: &text},
			wantOutput: true,
			wantToken:  true,
		},
		{
			name: "completed function call",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeOutputItemDone,
				Item: &schemas.ResponsesMessage{
					Type: &toolType,
					ResponsesToolMessage: &schemas.ResponsesToolMessage{
						Name: schemas.Ptr("lookup"), Arguments: schemas.Ptr(`{}`),
					},
				},
			},
			wantOutput: true,
			wantToken:  true,
		},
		{
			name: "function call in added item",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeOutputItemAdded,
				Item: &schemas.ResponsesMessage{
					Type:                 &toolType,
					ResponsesToolMessage: &schemas.ResponsesToolMessage{Name: schemas.Ptr("lookup")},
				},
			},
			wantOutput: true,
			wantToken:  true,
		},
		{
			name: "computer action",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeOutputItemDone,
				Item: &schemas.ResponsesMessage{ResponsesToolMessage: &schemas.ResponsesToolMessage{
					Action: &schemas.ResponsesToolMessageActionStruct{
						ResponsesComputerToolCallAction: &schemas.ResponsesComputerToolCallAction{Type: "wait"},
					},
				}},
			},
			wantOutput: true,
			wantToken:  true,
		},
		{
			name: "completed image",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeOutputItemDone,
				Item: &schemas.ResponsesMessage{ResponsesToolMessage: &schemas.ResponsesToolMessage{
					ResponsesImageGenerationCall: &schemas.ResponsesImageGenerationCall{Result: "base64-image"},
				}},
			},
			wantOutput: true,
		},
		{
			name: "search results",
			response: &schemas.BifrostResponsesStreamResponse{
				Type:          schemas.ResponsesStreamResponseTypeWebSearchCallResultsCompleted,
				SearchResults: []schemas.SearchResult{{}},
			},
			wantOutput: true,
		},
		{
			name: "rendered search content",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeContentPartDone,
				Part: &schemas.ResponsesMessageContentBlock{
					ResponsesOutputMessageContentRenderedContent: &schemas.ResponsesOutputMessageContentRenderedContent{RenderedContent: "<p>result</p>"},
				},
			},
			wantOutput: true,
		},
		{
			name: "encrypted reasoning",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeOutputItemDone,
				Item: &schemas.ResponsesMessage{ResponsesReasoning: &schemas.ResponsesReasoning{
					EncryptedContent: &encrypted,
				}},
			},
			wantOutput: true,
		},
		{
			name: "tool result",
			response: &schemas.BifrostResponsesStreamResponse{
				Type: schemas.ResponsesStreamResponseTypeOutputItemDone,
				Item: &schemas.ResponsesMessage{ResponsesToolMessage: &schemas.ResponsesToolMessage{
					Output: &schemas.ResponsesToolMessageOutputStruct{ResponsesToolCallOutputStr: &toolOutput},
				}},
			},
			wantOutput: true,
		},
		{
			name: "completed response with output",
			response: &schemas.BifrostResponsesStreamResponse{
				Type:     schemas.ResponsesStreamResponseTypeCompleted,
				Response: &schemas.BifrostResponsesResponse{Output: []schemas.ResponsesMessage{*messageWithText()}},
			},
			wantOutput: true,
			wantToken:  true,
		},
		{
			name: "incomplete response with output",
			response: &schemas.BifrostResponsesStreamResponse{
				Type:     schemas.ResponsesStreamResponseTypeIncomplete,
				Response: &schemas.BifrostResponsesResponse{Output: []schemas.ResponsesMessage{*messageWithText()}},
			},
			wantOutput: true,
			wantToken:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := responsesEventHasOutput(tt.response); got != tt.wantOutput {
				t.Fatalf("responsesEventHasOutput() = %v, want %v", got, tt.wantOutput)
			}
			if got := responsesEventHasToken(tt.response); got != tt.wantToken {
				t.Fatalf("responsesEventHasToken() = %v, want %v", got, tt.wantToken)
			}
		})
	}
}

func TestTTFTRequiresGatewayRequestClock(t *testing.T) {
	text := "hello"
	state := &State{}
	state.ObserveChatStreamOutput(&schemas.BifrostChatResponse{
		Choices: []schemas.BifrostResponseChoice{{
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
				Delta: &schemas.ChatStreamResponseChoiceDelta{Content: &text},
			},
		}},
		ExtraFields: schemas.BifrostResponseExtraFields{Latency: 20},
	})
	if state.TTFTMS != nil {
		t.Fatalf("provider metadata created a gateway timing observation: %#v", state.TTFTMS)
	}
	if !state.ProviderOutputObserved {
		t.Fatal("usable provider output must remain recorded when the timing clock is unavailable")
	}
}

func TestBufferedOutputIsObservedWithoutTTFT(t *testing.T) {
	state := &State{Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}}
	response := validUnaryChatProviderResponse()
	response.Choices[0].ChatNonStreamResponseChoice.Message.Content = &schemas.ChatMessageContent{
		ContentStr: schemas.Ptr("hello"),
	}
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
		ChatResponse: response,
	}, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}

	if !state.ProviderOutputObserved || !state.providerOutputEmitted {
		t.Fatalf("buffered provider output was not recorded: %#v", state)
	}
	if state.TTFTMS != nil {
		t.Fatalf("buffered provider output must not record TTFT: %#v", state.TTFTMS)
	}
}

func TestCacheReadSavingsUsesSettledMeterAndComparableInputRate(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterInputTokens:       {billing.RatePerMillionTokens: "1000000"},
			billing.MeterCachedInputTokens: {billing.RatePerMillionTokens: "100000"},
		}}},
		FinalMeters: []catalog.MeterEstimate{{
			MeterKey:       billing.MeterCachedInputTokens,
			RateKey:        billing.RatePerMillionTokens,
			RateUSDAtoms:   "100000",
			Quantity:       "100",
			AmountUSDAtoms: "10",
		}},
	}

	savings, err := cacheReadSavingsUSDAtoms(state)
	if err != nil {
		t.Fatalf("cacheReadSavingsUSDAtoms returned error: %v", err)
	}
	if savings == nil || *savings != "90" {
		t.Fatalf("cache savings = %#v, want 90", savings)
	}
}

func TestCacheReadSavingsUsesPromptContextTier(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterInputTokens: {
				billing.RatePerMillionContextLTE272K: "1000000",
				billing.RatePerMillionContextGT272K:  "2000000",
			},
			billing.MeterCachedInputTokens: {billing.RatePerMillionTokens: "100000"},
		}}},
		Signals: &StandardSignals{Prompt: billing.LongContextThresholdTokens + 1, Cached: 100},
		FinalMeters: []catalog.MeterEstimate{{
			MeterKey:       billing.MeterCachedInputTokens,
			RateKey:        billing.RatePerMillionTokens,
			RateUSDAtoms:   "100000",
			Quantity:       "100",
			AmountUSDAtoms: "10",
		}},
	}

	savings, err := cacheReadSavingsUSDAtoms(state)
	if err != nil {
		t.Fatalf("cacheReadSavingsUSDAtoms returned error: %v", err)
	}
	if savings == nil || *savings != "190" {
		t.Fatalf("long-context cache savings = %#v, want 190", savings)
	}
}

func TestCacheReadSavingsDoesNotTreatCacheWritesAsSavings(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterInputTokens:           {billing.RatePerMillionTokens: "1000000"},
			billing.MeterCacheWriteInputTokens: {billing.RatePerMillionTokens: "1250000"},
		}}},
		Signals: &StandardSignals{Prompt: 100, CacheWrite: 100},
		FinalMeters: []catalog.MeterEstimate{{
			MeterKey:       billing.MeterCacheWriteInputTokens,
			RateKey:        billing.RatePerMillionTokens,
			RateUSDAtoms:   "1250000",
			Quantity:       "100",
			AmountUSDAtoms: "125",
		}},
	}
	savings, err := cacheReadSavingsUSDAtoms(state)
	if err != nil || savings == nil || *savings != "0" {
		t.Fatalf("cache-write savings = %#v, %v; want 0", savings, err)
	}
	overhead, err := cacheWriteOverheadUSDAtoms(state)
	if err != nil || overhead == nil || *overhead != "25" {
		t.Fatalf("cache-write overhead = %#v, %v; want 25", overhead, err)
	}
}

func TestCacheWriteOverheadKeepsAnthropicTTLMetersSeparate(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1000000"},
			billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1250000"},
			billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "2000000"},
		}}},
		Signals: &StandardSignals{Prompt: 500, CacheWrite5m: 200, CacheWrite1h: 300},
		FinalMeters: []catalog.MeterEstimate{
			{
				MeterKey:       billing.MeterCacheWrite5mInputTokens,
				RateKey:        billing.RatePerMillionTokens,
				RateUSDAtoms:   "1250000",
				Quantity:       "200",
				AmountUSDAtoms: "250",
			},
			{
				MeterKey:       billing.MeterCacheWrite1hInputTokens,
				RateKey:        billing.RatePerMillionTokens,
				RateUSDAtoms:   "2000000",
				Quantity:       "300",
				AmountUSDAtoms: "600",
			},
		},
	}

	overhead, err := cacheWriteOverheadUSDAtoms(state)
	if err != nil || overhead == nil || *overhead != "350" {
		t.Fatalf("split cache-write overhead = %#v, %v; want 350", overhead, err)
	}
}

func TestCacheWriteOverheadUsesPromptContextTier(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
			billing.MeterInputTokens: {
				billing.RatePerMillionContextLTE272K: "1000000",
				billing.RatePerMillionContextGT272K:  "2000000",
			},
			billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "4000000"},
		}}},
		Signals: &StandardSignals{
			Prompt:       billing.LongContextThresholdTokens + 1,
			CacheWrite1h: 100,
		},
		FinalMeters: []catalog.MeterEstimate{{
			MeterKey:       billing.MeterCacheWrite1hInputTokens,
			RateKey:        billing.RatePerMillionTokens,
			RateUSDAtoms:   "4000000",
			Quantity:       "100",
			AmountUSDAtoms: "400",
		}},
	}

	overhead, err := cacheWriteOverheadUSDAtoms(state)
	if err != nil || overhead == nil || *overhead != "200" {
		t.Fatalf("long-context cache-write overhead = %#v, %v; want 200", overhead, err)
	}
}

func TestCacheEconomicsUseTheRequestLevelOrdinaryInputCounterfactual(t *testing.T) {
	t.Run("cache read savings include ordinary-meter rounding", func(t *testing.T) {
		state := &State{
			Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				billing.MeterInputTokens:       {billing.RatePerMillionTokens: "1500000"},
				billing.MeterCachedInputTokens: {billing.RatePerMillionTokens: "100000"},
			}}},
			FinalMeters: []catalog.MeterEstimate{
				{MeterKey: billing.MeterInputTokens, RateKey: billing.RatePerMillionTokens, RateUSDAtoms: "1500000", Quantity: "1", AmountUSDAtoms: "2"},
				{MeterKey: billing.MeterCachedInputTokens, RateKey: billing.RatePerMillionTokens, RateUSDAtoms: "100000", Quantity: "1", AmountUSDAtoms: "1"},
			},
		}
		savings, err := cacheReadSavingsUSDAtoms(state)
		if err != nil || savings == nil || *savings != "0" {
			t.Fatalf("cache read savings = %#v, %v; want 0", savings, err)
		}
	})

	t.Run("cache write overhead includes ordinary-meter rounding", func(t *testing.T) {
		state := &State{
			Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				billing.MeterInputTokens:           {billing.RatePerMillionTokens: "500000"},
				billing.MeterCacheWriteInputTokens: {billing.RatePerMillionTokens: "1500000"},
			}}},
			FinalMeters: []catalog.MeterEstimate{
				{MeterKey: billing.MeterInputTokens, RateKey: billing.RatePerMillionTokens, RateUSDAtoms: "500000", Quantity: "1", AmountUSDAtoms: "1"},
				{MeterKey: billing.MeterCacheWriteInputTokens, RateKey: billing.RatePerMillionTokens, RateUSDAtoms: "1500000", Quantity: "1", AmountUSDAtoms: "2"},
			},
		}
		overhead, err := cacheWriteOverheadUSDAtoms(state)
		if err != nil || overhead == nil || *overhead != "2" {
			t.Fatalf("cache write overhead = %#v, %v; want 2", overhead, err)
		}
	})
}

func TestMixedCacheEconomicsMatchRequestLevelCounterfactual(t *testing.T) {
	pricing := catalog.Pricing{
		billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1234567"},
		billing.MeterCachedInputTokens:       {billing.RatePerMillionTokens: "123456"},
		billing.MeterCacheWriteInputTokens:   {billing.RatePerMillionTokens: "1600000"},
		billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1800000"},
		billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "2500000"},
	}
	rate := func(meter string) *big.Int {
		value, ok := new(big.Int).SetString(pricing[meter][billing.RatePerMillionTokens], 10)
		if !ok {
			t.Fatalf("invalid test rate for %s", meter)
		}
		return value
	}
	ordinaryRate := rate(billing.MeterInputTokens)

	for _, ordinary := range []int{0, 1, 999, 1000} {
		for _, read := range []int{0, 1, 17} {
			for _, genericWrite := range []int{0, 1, 11} {
				for _, write5m := range []int{0, 3} {
					for _, write1h := range []int{0, 5} {
						name := fmt.Sprintf("ordinary=%d/read=%d/generic=%d/5m=%d/1h=%d", ordinary, read, genericWrite, write5m, write1h)
						t.Run(name, func(t *testing.T) {
							state := &State{
								Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: pricing}},
								Signals: &StandardSignals{
									Prompt:       ordinary + read + genericWrite + write5m + write1h,
									Cached:       read,
									CacheWrite:   genericWrite,
									CacheWrite5m: write5m,
									CacheWrite1h: write1h,
								},
							}
							if _, err := calculateBaseUpstreamCost(state, nil); err != nil {
								t.Fatalf("calculateBaseUpstreamCost returned error: %v", err)
							}

							ordinaryCost := billing.CostPerMillion(ordinary, ordinaryRate)
							readCost := billing.CostPerMillion(read, rate(billing.MeterCachedInputTokens))
							readAsOrdinary := new(big.Int).Sub(
								billing.CostPerMillion(ordinary+read, ordinaryRate),
								ordinaryCost,
							)
							wantSavings := big.NewInt(0)
							if readAsOrdinary.Cmp(readCost) > 0 {
								wantSavings.Sub(readAsOrdinary, readCost)
							}

							writeQuantity := genericWrite + write5m + write1h
							writeCost := new(big.Int).Add(
								billing.CostPerMillion(genericWrite, rate(billing.MeterCacheWriteInputTokens)),
								billing.CostPerMillion(write5m, rate(billing.MeterCacheWrite5mInputTokens)),
							)
							writeCost.Add(writeCost, billing.CostPerMillion(write1h, rate(billing.MeterCacheWrite1hInputTokens)))
							writeAsOrdinary := new(big.Int).Sub(
								billing.CostPerMillion(ordinary+writeQuantity, ordinaryRate),
								ordinaryCost,
							)
							wantOverhead := big.NewInt(0)
							if writeCost.Cmp(writeAsOrdinary) > 0 {
								wantOverhead.Sub(writeCost, writeAsOrdinary)
							}

							savings, savingsErr := cacheReadSavingsUSDAtoms(state)
							overhead, overheadErr := cacheWriteOverheadUSDAtoms(state)
							if savingsErr != nil || overheadErr != nil || savings == nil || overhead == nil {
								t.Fatalf("cache economics = savings %#v (%v), overhead %#v (%v)", savings, savingsErr, overhead, overheadErr)
							}
							if *savings != wantSavings.String() || *overhead != wantOverhead.String() {
								t.Fatalf("cache economics = savings %s overhead %s, want %s and %s", *savings, *overhead, wantSavings, wantOverhead)
							}
						})
					}
				}
			}
		}
	}
}

func FuzzCacheEconomicsMatchIndependentRequestCounterfactual(f *testing.F) {
	seeds := []struct {
		ordinary, read, genericWrite, write5m, write1h   uint32
		inputRate, readRate, genericRate, rate5m, rate1h uint32
	}{
		{},
		{ordinary: 1, read: 1, genericWrite: 1, write5m: 1, write1h: 1, inputRate: 1_500_000, readRate: 100_000, genericRate: 1_600_000, rate5m: 1_800_000, rate1h: 2_500_000},
		{ordinary: 271_996, read: 1, genericWrite: 1, write5m: 1, write1h: 1, inputRate: 999_999, readRate: 1, genericRate: 1_000_000, rate5m: 1_000_001, rate1h: 4_000_000},
		{ordinary: 271_997, read: 1, genericWrite: 1, write5m: 1, write1h: 1, inputRate: 1_000_001, readRate: 2_000_000, genericRate: 500_000, rate5m: 1_000_001, rate1h: 1},
		{ordinary: 999_999, read: 1, genericWrite: 999_999, write5m: 1, write1h: 1_000_000, inputRate: 1, readRate: 999_999, genericRate: 1_000_000, rate5m: 1_000_001, rate1h: 10_000_000},
	}
	for _, seed := range seeds {
		f.Add(seed.ordinary, seed.read, seed.genericWrite, seed.write5m, seed.write1h, seed.inputRate, seed.readRate, seed.genericRate, seed.rate5m, seed.rate1h)
	}

	f.Fuzz(func(t *testing.T, ordinaryRaw uint32, readRaw uint32, genericRaw uint32, write5mRaw uint32, write1hRaw uint32, inputRateRaw uint32, readRateRaw uint32, genericRateRaw uint32, rate5mRaw uint32, rate1hRaw uint32) {
		const quantityRange = uint32(1_000_002)
		const rateRange = uint32(10_000_001)
		ordinary := int(ordinaryRaw % quantityRange)
		read := int(readRaw % quantityRange)
		genericWrite := int(genericRaw % quantityRange)
		write5m := int(write5mRaw % quantityRange)
		write1h := int(write1hRaw % quantityRange)
		inputRate := uint64(inputRateRaw%rateRange) + 1
		readRate := uint64(readRateRaw%rateRange) + 1
		genericRate := uint64(genericRateRaw%rateRange) + 1
		rate5m := uint64(rate5mRaw%rateRange) + 1
		rate1h := uint64(rate1hRaw%rateRange) + 1

		pricing := catalog.Pricing{
			billing.MeterInputTokens:             {billing.RatePerMillionTokens: strconv.FormatUint(inputRate, 10)},
			billing.MeterCachedInputTokens:       {billing.RatePerMillionTokens: strconv.FormatUint(readRate, 10)},
			billing.MeterCacheWriteInputTokens:   {billing.RatePerMillionTokens: strconv.FormatUint(genericRate, 10)},
			billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: strconv.FormatUint(rate5m, 10)},
			billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: strconv.FormatUint(rate1h, 10)},
		}
		state := &State{
			Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: pricing}},
			Signals: &StandardSignals{
				Prompt:       ordinary + read + genericWrite + write5m + write1h,
				Cached:       read,
				CacheWrite:   genericWrite,
				CacheWrite5m: write5m,
				CacheWrite1h: write1h,
			},
		}
		actualTotal, err := calculateBaseUpstreamCost(state, nil)
		if err != nil {
			t.Fatalf("calculateBaseUpstreamCost returned error: %v", err)
		}

		ordinaryCost := referenceCostPerMillion(ordinary, inputRate)
		readCost := referenceCostPerMillion(read, readRate)
		genericCost := referenceCostPerMillion(genericWrite, genericRate)
		write5mCost := referenceCostPerMillion(write5m, rate5m)
		write1hCost := referenceCostPerMillion(write1h, rate1h)
		wantTotal := new(big.Int).Add(ordinaryCost, readCost)
		wantTotal.Add(wantTotal, genericCost)
		wantTotal.Add(wantTotal, write5mCost)
		wantTotal.Add(wantTotal, write1hCost)
		if actualTotal != wantTotal.String() {
			t.Fatalf("settled cache total = %s, want %s; meters=%#v", actualTotal, wantTotal, state.FinalMeters)
		}

		readMarginal := new(big.Int).Sub(referenceCostPerMillion(ordinary+read, inputRate), ordinaryCost)
		wantSavings := big.NewInt(0)
		if readMarginal.Cmp(readCost) > 0 {
			wantSavings.Sub(readMarginal, readCost)
		}
		writeQuantity := genericWrite + write5m + write1h
		writeMarginal := new(big.Int).Sub(referenceCostPerMillion(ordinary+writeQuantity, inputRate), ordinaryCost)
		writeCost := new(big.Int).Add(genericCost, write5mCost)
		writeCost.Add(writeCost, write1hCost)
		wantOverhead := big.NewInt(0)
		if writeCost.Cmp(writeMarginal) > 0 {
			wantOverhead.Sub(writeCost, writeMarginal)
		}

		savings, savingsErr := cacheReadSavingsUSDAtoms(state)
		overhead, overheadErr := cacheWriteOverheadUSDAtoms(state)
		if savingsErr != nil || overheadErr != nil || savings == nil || overhead == nil {
			t.Fatalf("cache economics = savings %#v (%v), overhead %#v (%v)", savings, savingsErr, overhead, overheadErr)
		}
		if *savings != wantSavings.String() || *overhead != wantOverhead.String() {
			t.Fatalf("cache economics = %s/%s, want %s/%s", *savings, *overhead, wantSavings, wantOverhead)
		}
	})
}

func TestCacheEconomicsDoNotAffectSettlementWhenComparableInputRateIsMissing(t *testing.T) {
	for _, meterKey := range []string{
		billing.MeterCachedInputTokens,
		billing.MeterCacheWriteInputTokens,
		billing.MeterCacheWrite5mInputTokens,
		billing.MeterCacheWrite1hInputTokens,
	} {
		t.Run(meterKey, func(t *testing.T) {
			state := &State{
				Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: catalog.Pricing{
					meterKey: {billing.RatePerMillionTokens: "2000000"},
				}}},
				Signals: &StandardSignals{Prompt: 100},
			}
			switch meterKey {
			case billing.MeterCachedInputTokens:
				state.Signals.(*StandardSignals).Cached = 100
			case billing.MeterCacheWriteInputTokens:
				state.Signals.(*StandardSignals).CacheWrite = 100
			case billing.MeterCacheWrite5mInputTokens:
				state.Signals.(*StandardSignals).CacheWrite5m = 100
			case billing.MeterCacheWrite1hInputTokens:
				state.Signals.(*StandardSignals).CacheWrite1h = 100
			}
			cost, err := calculateBaseUpstreamCost(state, nil)
			if err != nil || cost != "200" || len(state.FinalMeters) != 1 {
				t.Fatalf("settlement = cost %q meters %#v error %v", cost, state.FinalMeters, err)
			}
			if _, err := cacheReadSavingsUSDAtoms(state); meterKey == billing.MeterCachedInputTokens && err == nil {
				t.Fatal("cache-read derivation unexpectedly invented a comparable input rate")
			}
			if _, err := cacheWriteOverheadUSDAtoms(state); meterKey != billing.MeterCachedInputTokens && err == nil {
				t.Fatal("cache-write derivation unexpectedly invented a comparable input rate")
			}
		})
	}
}

func TestCacheEconomicsFloorNonBenefitsAtZero(t *testing.T) {
	tests := []struct {
		name         string
		meterKey     string
		meterRate    string
		wantSavings  string
		wantOverhead string
	}{
		{
			name:         "no cache usage",
			wantSavings:  "0",
			wantOverhead: "0",
		},
		{
			name:         "cache read at ordinary input rate",
			meterKey:     billing.MeterCachedInputTokens,
			meterRate:    "1000000",
			wantSavings:  "0",
			wantOverhead: "0",
		},
		{
			name:         "cache read above ordinary input rate",
			meterKey:     billing.MeterCachedInputTokens,
			meterRate:    "2000000",
			wantSavings:  "0",
			wantOverhead: "0",
		},
		{
			name:         "cache write at ordinary input rate",
			meterKey:     billing.MeterCacheWriteInputTokens,
			meterRate:    "1000000",
			wantSavings:  "0",
			wantOverhead: "0",
		},
		{
			name:         "cache write below ordinary input rate",
			meterKey:     billing.MeterCacheWriteInputTokens,
			meterRate:    "500000",
			wantSavings:  "0",
			wantOverhead: "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pricing := catalog.Pricing{
				billing.MeterInputTokens: {billing.RatePerMillionTokens: "1000000"},
			}
			signals := &StandardSignals{}
			if tt.meterKey != "" {
				pricing[tt.meterKey] = map[string]string{billing.RatePerMillionTokens: tt.meterRate}
				signals.Prompt = 100
				switch tt.meterKey {
				case billing.MeterCachedInputTokens:
					signals.Cached = 100
				case billing.MeterCacheWriteInputTokens:
					signals.CacheWrite = 100
				}
			}
			state := &State{
				Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: pricing}},
				Signals:    signals,
			}
			if _, err := calculateBaseUpstreamCost(state, nil); err != nil {
				t.Fatalf("calculateBaseUpstreamCost returned error: %v", err)
			}
			savings, savingsErr := cacheReadSavingsUSDAtoms(state)
			overhead, overheadErr := cacheWriteOverheadUSDAtoms(state)
			if savingsErr != nil || overheadErr != nil || savings == nil || overhead == nil {
				t.Fatalf("cache economics = savings %#v (%v), overhead %#v (%v)", savings, savingsErr, overhead, overheadErr)
			}
			if *savings != tt.wantSavings || *overhead != tt.wantOverhead {
				t.Fatalf("cache economics = savings %s, overhead %s; want %s, %s", *savings, *overhead, tt.wantSavings, tt.wantOverhead)
			}
		})
	}
}

func TestEveryActiveCatalogDeploymentCacheEconomics(t *testing.T) {
	type matrixDeployment struct {
		Pricing  catalog.Pricing `json:"pricing"`
		RouteIDs []string        `json:"routeIds"`
	}
	type matrixRoute struct {
		ProviderID string `json:"providerId"`
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

	cacheMeters := []string{
		billing.MeterCachedInputTokens,
		billing.MeterCacheWriteInputTokens,
		billing.MeterCacheWrite5mInputTokens,
		billing.MeterCacheWrite1hInputTokens,
	}
	providerMeters := map[string]map[string]bool{}
	deploymentIDs := make([]string, 0, len(deployments))
	for deploymentID := range deployments {
		deploymentIDs = append(deploymentIDs, deploymentID)
	}
	slices.Sort(deploymentIDs)

	for _, deploymentID := range deploymentIDs {
		deployment := deployments[deploymentID]
		if len(deployment.RouteIDs) == 0 {
			t.Fatalf("%s has no route", deploymentID)
		}
		providerID := routes[deployment.RouteIDs[0]].ProviderID
		if providerID == "" {
			t.Fatalf("%s has no provider", deploymentID)
		}
		for _, routeID := range deployment.RouteIDs[1:] {
			if routes[routeID].ProviderID != providerID {
				t.Fatalf("%s spans providers", deploymentID)
			}
		}

		for _, meterKey := range cacheMeters {
			meterRates := deployment.Pricing[meterKey]
			priced := len(meterRates) > 0
			if priced {
				if providerMeters[providerID] == nil {
					providerMeters[providerID] = map[string]bool{}
				}
				providerMeters[providerID][meterKey] = true
			}

			modes := []struct {
				name     string
				prompt   int
				rateMode billing.TokenRateMode
			}{
				{name: "standard", prompt: 1000, rateMode: billing.TokenRateStandard},
			}
			if _, inputLong := deployment.Pricing[billing.MeterInputTokens][billing.RatePerMillionContextGT272K]; inputLong {
				modes = append(modes, struct {
					name     string
					prompt   int
					rateMode billing.TokenRateMode
				}{name: "long-context", prompt: billing.LongContextThresholdTokens + 1, rateMode: billing.TokenRateLongContext})
			}

			for _, mode := range modes {
				t.Run(deploymentID+"/"+meterKey+"/"+mode.name, func(t *testing.T) {
					signals := &StandardSignals{Prompt: mode.prompt}
					switch meterKey {
					case billing.MeterCachedInputTokens:
						signals.Cached = mode.prompt
					case billing.MeterCacheWriteInputTokens:
						signals.CacheWrite = mode.prompt
					case billing.MeterCacheWrite5mInputTokens:
						signals.CacheWrite5m = mode.prompt
					case billing.MeterCacheWrite1hInputTokens:
						signals.CacheWrite1h = mode.prompt
					}
					state := &State{
						Resolution: &catalog.ResolvedRequest{Deployment: catalog.Deployment{Pricing: deployment.Pricing}},
						Signals:    signals,
					}
					if _, err := calculateBaseUpstreamCost(state, nil); err != nil {
						t.Fatalf("calculateBaseUpstreamCost returned error: %v", err)
					}
					meter := findMeterEstimate(state.FinalMeters, meterKey)
					if !priced {
						if meter != nil {
							t.Fatalf("unpriced cache detail produced %s: %#v", meterKey, state.FinalMeters)
						}
						inputMeter := findMeterEstimate(state.FinalMeters, billing.MeterInputTokens)
						if meterQuantity(inputMeter) != strconv.Itoa(mode.prompt) {
							t.Fatalf("unpriced %s did not remain ordinary input: %#v", meterKey, state.FinalMeters)
						}
						savings, savingsErr := cacheReadSavingsUSDAtoms(state)
						overhead, overheadErr := cacheWriteOverheadUSDAtoms(state)
						if savingsErr != nil || overheadErr != nil || savings == nil || overhead == nil || *savings != "0" || *overhead != "0" {
							t.Fatalf("unpriced cache economics = savings %#v (%v), overhead %#v (%v)", savings, savingsErr, overhead, overheadErr)
						}
						return
					}
					if meter == nil {
						t.Fatalf("final price omitted %s: %#v", meterKey, state.FinalMeters)
					}
					meterCostUSDAtoms, err := billing.ParseUSDAtoms(meter.AmountUSDAtoms)
					if err != nil {
						t.Fatalf("parse settled cache cost: %v", err)
					}
					_, inputRate, ok := billing.PricingRate(deployment.Pricing, billing.MeterInputTokens, mode.rateMode)
					if !ok {
						t.Fatal("deployment has no comparable ordinary input rate")
					}
					ordinaryCost := billing.CostPerMillion(mode.prompt, inputRate)
					wantSavings := big.NewInt(0)
					wantOverhead := big.NewInt(0)
					if meterKey == billing.MeterCachedInputTokens && ordinaryCost.Cmp(meterCostUSDAtoms) > 0 {
						wantSavings.Sub(ordinaryCost, meterCostUSDAtoms)
					}
					if meterKey != billing.MeterCachedInputTokens && meterCostUSDAtoms.Cmp(ordinaryCost) > 0 {
						wantOverhead.Sub(meterCostUSDAtoms, ordinaryCost)
					}
					savings, savingsErr := cacheReadSavingsUSDAtoms(state)
					overhead, overheadErr := cacheWriteOverheadUSDAtoms(state)
					if savingsErr != nil || overheadErr != nil || savings == nil || overhead == nil {
						t.Fatalf("cache economics = savings %#v (%v), overhead %#v (%v)", savings, savingsErr, overhead, overheadErr)
					}
					if *savings != wantSavings.String() || *overhead != wantOverhead.String() {
						t.Fatalf("cache economics = savings %s, overhead %s; want %s, %s", *savings, *overhead, wantSavings, wantOverhead)
					}
				})
			}
		}
	}

	wantProviderMeters := map[string][]string{
		"anthropic": {
			billing.MeterCachedInputTokens,
			billing.MeterCacheWrite5mInputTokens,
			billing.MeterCacheWrite1hInputTokens,
		},
		"azure": {
			billing.MeterCachedInputTokens,
			billing.MeterCacheWriteInputTokens,
			billing.MeterCacheWrite5mInputTokens,
			billing.MeterCacheWrite1hInputTokens,
		},
		"chutes": {
			billing.MeterCachedInputTokens,
		},
		"openai": {
			billing.MeterCachedInputTokens,
			billing.MeterCacheWriteInputTokens,
		},
	}
	if len(providerMeters) != len(wantProviderMeters) {
		t.Fatalf("cache-priced providers = %#v, want %#v", providerMeters, wantProviderMeters)
	}
	for providerID, wantMeters := range wantProviderMeters {
		actual := providerMeters[providerID]
		if len(actual) != len(wantMeters) {
			t.Fatalf("%s cache meters = %#v, want %#v", providerID, actual, wantMeters)
		}
		for _, meterKey := range wantMeters {
			if !actual[meterKey] {
				t.Fatalf("%s does not exercise %s", providerID, meterKey)
			}
		}
	}
}

func TestPrepareFinalStatePersistsBothCacheEconomics(t *testing.T) {
	pricing := catalog.Pricing{
		billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1000000"},
		billing.MeterCachedInputTokens:       {billing.RatePerMillionTokens: "100000"},
		billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1250000"},
		billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "2000000"},
	}
	state := &State{
		Authorization: &billing.Authorization{
			AuthorizedBilledCostUSDAtoms: big.NewInt(1200),
			AvailableBalanceUSDAtoms:     big.NewInt(0),
			KeyID:                        "key",
			OrganizationID:               "org",
			ProviderKey:                  "anthropic",
			ProductKey:                   "claude",
			RequestID:                    "request",
			UpstreamByok:                 "stogas",
			UserID:                       "user",
			WorkspaceID:                  "workspace",
		},
		UpstreamCostUSDAtoms: "860",
		FinalMeters: []catalog.MeterEstimate{
			{MeterKey: billing.MeterCachedInputTokens, RateKey: billing.RatePerMillionTokens, RateUSDAtoms: "100000", Quantity: "100", AmountUSDAtoms: "10"},
			{MeterKey: billing.MeterCacheWrite5mInputTokens, RateKey: billing.RatePerMillionTokens, RateUSDAtoms: "1250000", Quantity: "200", AmountUSDAtoms: "250"},
			{MeterKey: billing.MeterCacheWrite1hInputTokens, RateKey: billing.RatePerMillionTokens, RateUSDAtoms: "2000000", Quantity: "300", AmountUSDAtoms: "600"},
		},
		Hold: HoldEstimate{
			EstimatedUpstreamCostUSDAtoms: "1200",
			Meters: []catalog.MeterEstimate{{
				MeterKey:       billing.MeterCacheWrite1hInputTokens,
				RateKey:        billing.RatePerMillionTokens,
				RateUSDAtoms:   "2000000",
				Quantity:       "600",
				AmountUSDAtoms: "1200",
				HoldRequired:   true,
			}},
		},
		RequestType: string(schemas.ChatCompletionRequest),
		Resolution: &catalog.ResolvedRequest{
			Provider: schemas.Anthropic,
			Route:    catalog.RouteChat,
			Model:    "claude",
			Deployment: catalog.Deployment{
				ID:       "anthropic-claude",
				ModelID:  "claude",
				Pricing:  pricing,
				RouteIDs: []string{"anthropic-messages"},
			},
		},
		Signals:   &StandardSignals{Prompt: 600, Cached: 100, CacheWrite5m: 200, CacheWrite1h: 300},
		StartedAt: time.Now().UTC(),
	}

	event := PrepareFinalState(state)
	if event == nil {
		t.Fatal("PrepareFinalState returned nil")
	}
	if event.CacheReadSavingsUSDAtoms == nil || *event.CacheReadSavingsUSDAtoms != "90" {
		t.Fatalf("cache-read savings = %#v, want 90", event.CacheReadSavingsUSDAtoms)
	}
	if event.CacheWriteOverheadUSDAtoms == nil || *event.CacheWriteOverheadUSDAtoms != "350" {
		t.Fatalf("cache-write overhead = %#v, want 350", event.CacheWriteOverheadUSDAtoms)
	}
	if event.UpstreamCostUSDAtoms != "860" || event.BilledCostUSDAtoms != "860" {
		t.Fatalf("cache economics changed billing: upstream=%s billed=%s", event.UpstreamCostUSDAtoms, event.BilledCostUSDAtoms)
	}
	for _, meterKey := range []string{
		billing.MeterCachedInputTokens,
		billing.MeterCacheWrite5mInputTokens,
		billing.MeterCacheWrite1hInputTokens,
	} {
		if _, ok := event.Pricing[meterKey]; !ok {
			t.Fatalf("pricing bag omitted %s: %#v", meterKey, event.Pricing)
		}
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
	state.UpstreamCostUSDAtoms = total
	pricing := pricingForState(state)
	assertPricingBagEntry(t, pricing, billing.MeterInputTokens, billing.RatePerMillionTokens, "2", "1")
	if total != "1" {
		t.Fatalf("expected compacted meter total 1 atom, got %s", total)
	}

	authorizer := &fakeBillingAuthorizer{}
	state.Authorization = &billing.Authorization{
		AuthorizedBilledCostUSDAtoms: big.NewInt(2),
		AvailableBalanceUSDAtoms:     big.NewInt(0),
		RequestID:                    "request",
	}
	state.Hold.EstimatedUpstreamCostUSDAtoms = "2"
	state.Hold.Meters = []catalog.MeterEstimate{{
		AmountUSDAtoms: "2",
		HoldRequired:   true,
		MeterKey:       billing.MeterInputTokens,
		Quantity:       "2",
		RateKey:        billing.RatePerMillionTokens,
	}}
	state.UpstreamCostUSDAtoms = total
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

func TestPrepareFinalStateDiscardsCostsOutsideAuthorizedHoldWithoutChangingProviderOutcome(t *testing.T) {
	tests := []struct {
		name          string
		hold          string
		final         string
		providerError bool
		pricingError  bool
		wantDiscard   bool
	}{
		{name: "exact hold", hold: "100", final: "100"},
		{name: "above hold", hold: "100", final: "101", wantDiscard: true},
		{name: "provider error above hold", hold: "100", final: "101", providerError: true, wantDiscard: true},
		{name: "missing hold", final: "1", wantDiscard: true},
		{name: "malformed hold", hold: "invalid", final: "1", wantDiscard: true},
		{name: "malformed final", hold: "100", final: "invalid", pricingError: true, wantDiscard: true},
		{name: "negative final", hold: "100", final: "-1", pricingError: true, wantDiscard: true},
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
					AuthorizedBilledCostUSDAtoms: big.NewInt(100),
					AvailableBalanceUSDAtoms:     big.NewInt(0),
					RequestID:                    "request",
				},
				UpstreamCostUSDAtoms: tc.final,
				BifrostError:         providerErr,
				FinalMeters:          finalMeters,
				Hold:                 HoldEstimate{EstimatedUpstreamCostUSDAtoms: tc.hold, Meters: holdMeters},
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
			if !tc.wantDiscard {
				if state.BifrostError != nil || event.UpstreamCostUSDAtoms != tc.final {
					t.Fatalf("authorized final cost was changed: state=%#v event=%#v", state, event)
				}
				return
			}
			if state.UpstreamCostUSDAtoms != billing.ZeroChargeUSDAtoms || event.UpstreamCostUSDAtoms != billing.ZeroChargeUSDAtoms {
				t.Fatalf("unsafe final cost was not discarded: state=%#v event=%#v", state, event)
			}
			if event.StogasProcessingSuccess {
				t.Fatal("discarded settlement was recorded as successful Stogas processing")
			}
			if tc.pricingError && state.BifrostError == nil {
				t.Fatal("internal pricing failure did not retain its Stogas error")
			}
			if !tc.pricingError && providerErr == nil && state.BifrostError != nil {
				t.Fatalf("settlement guard changed the provider outcome: %#v", state.BifrostError)
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

func TestFinalMetersAreCappedToAuthorizedDimensions(t *testing.T) {
	pricing := catalog.Pricing{
		billing.MeterInputTokens:     {billing.RatePerMillionTokens: "1000000"},
		meterAnthropicWebSearchCalls: {billing.RatePerThousandCalls: "1000"},
	}
	final := billing.AppendTokenMeterCost(nil, pricing, billing.MeterInputTokens, 5, false, billing.TokenRateStandard)
	final = billing.AppendCallMeterCost(final, pricing, meterAnthropicWebSearchCalls, 3, false)
	hold := []catalog.MeterEstimate{
		{MeterKey: billing.MeterInputTokens, Quantity: "3", HoldRequired: true},
		{MeterKey: meterAnthropicWebSearchCalls, Quantity: "2", HoldRequired: true},
	}
	bounded, total, err := capFinalMetersToHold(final, hold, pricing)
	if err != nil {
		t.Fatalf("capFinalMetersToHold returned error: %v", err)
	}
	if total != "5" || len(bounded) != 2 || bounded[0].Quantity != "3" || bounded[1].Quantity != "2" {
		t.Fatalf("final meters were not capped exactly: total=%s meters=%#v", total, bounded)
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
	if state.Hold.EstimatedUpstreamCostUSDAtoms == "" || state.Hold.EstimatedUpstreamCostUSDAtoms == "0" {
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
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover final search-model cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatalf("CalculateUpstreamCost returned error: %v", err)
			}
			if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover all cache writes: hold=%s final=%s", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms)
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
	if state.Hold.EstimatedUpstreamCostUSDAtoms == "" || state.Hold.EstimatedUpstreamCostUSDAtoms == "0" {
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover worst-case 1h cache write: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover default 5m cache write: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover Anthropic tool overhead final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover combined fast US cache/tool final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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

func referenceCostPerMillion(quantity int, rate uint64) *big.Int {
	if quantity <= 0 || rate == 0 {
		return big.NewInt(0)
	}
	numerator := new(big.Int).Mul(big.NewInt(int64(quantity)), new(big.Int).SetUint64(rate))
	divisor := big.NewInt(billing.MillionTokens)
	quotient, remainder := new(big.Int).QuoRem(numerator, divisor, new(big.Int))
	if remainder.Sign() > 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}
