package stogas

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	openaiadapter "github.com/maximhq/bifrost/transports/stogas/providers/openai"
)

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
	attempts  []string
	results   []*billing.Authorization
	errors    []error
	callCount int
}

func (f *fakeBillingAuthorizer) AuthorizeRequest(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string) (*billing.Authorization, error) {
	return f.AuthorizeRequestWithDuration(ctx, rawAPIKey, requestID, providerKey, productKey, amountUSDAtoms, 0)
}

func (f *fakeBillingAuthorizer) AuthorizeRequestWithDuration(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string, requestLifetime time.Duration) (*billing.Authorization, error) {
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

func (f *fakeBillingAuthorizer) FinalizeRequest(ctx context.Context, authorization *billing.Authorization, event billing.RequestEvent) error {
	return nil
}

func TestAuthorizeWithFreshRequestIDRetriesConflict(t *testing.T) {
	initialRequestID := "11111111-1111-1111-1111-111111111111"
	expected := &billing.Authorization{HoldID: "hold-1"}
	authorizer := &fakeBillingAuthorizer{
		results: []*billing.Authorization{nil, expected},
		errors: []error{
			&statusError{err: billing.ErrRequestAlreadyUsed, statusCode: 409},
			nil,
		},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, initialRequestID)

	authorization, err := authorizeWithFreshRequestID(ctx, authorizer, "sk-user", initialRequestID, HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", MaxUSDAtoms: "1000"}, billing.GatewayRequestLifetime, authorizer.errors[0])
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

	authorization, err := authorizeWithFreshRequestID(ctx, &fakeBillingAuthorizer{}, "sk-user", initialRequestID, HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", MaxUSDAtoms: "1000"}, billing.GatewayRequestLifetime, expectedErr)
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
}

func TestDefaultAdapterFinalPriceCapturesUninsuredNoUsageErrors(t *testing.T) {
	status := 400
	state := &State{
		Authorization: &billing.Authorization{AuthorizedAmount: big.NewInt(123)},
		BifrostError: &schemas.BifrostError{StatusCode: &status},
	}
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "123" {
		t.Fatalf("expected uninsured no-usage error to capture hold, got %s", state.FinalCostUSDAtoms)
	}
}

func TestOpenAIAdapterEstimateHoldAddsSearchMeters(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-search-preview","messages":[],"web_search_options":{"search_context_size":"low"},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, OpenAIAdapter{DefaultAdapter: DefaultAdapter{}})
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if len(state.Hold.Meters) != 3 {
		t.Fatalf("expected token meters plus search call meter, got %#v", state.Hold.Meters)
	}
	searchMeter := state.Hold.Meters[2]
	if searchMeter.MeterKey != openaiadapter.MeterOpenAIChatCompletionSearchPreviewModelCalls || searchMeter.RateKey != openaiadapter.RatePerThousandSearchContextLowCalls {
		t.Fatalf("expected low-context search preview meter, got %#v", searchMeter)
	}
	if state.Hold.MaxUSDAtoms == "" || state.Hold.MaxUSDAtoms == "0" {
		t.Fatalf("expected non-zero hold after search meter, got %#v", state.Hold)
	}
}

func TestAnthropicAdapterEstimateHoldReservesCacheWrite(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AnthropicAdapter{DefaultAdapter: DefaultAdapter{}})
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	var found bool
	for _, meter := range state.Hold.Meters {
		if meter.MeterKey == billing.MeterCacheWrite1hInputTokens {
			found = true
			expectedQuantity := big.NewInt(int64(resolution.InputTokenLimit())).String()
			if meter.Quantity != expectedQuantity {
				t.Fatalf("expected cache write hold quantity %s, got %s", expectedQuantity, meter.Quantity)
			}
		}
	}
	if !found {
		t.Fatalf("expected Anthropic hold to include conservative 1h cache write meter, got %#v", state.Hold.Meters)
	}
	if state.Hold.MaxUSDAtoms == "" || state.Hold.MaxUSDAtoms == "0" {
		t.Fatalf("expected non-zero Anthropic hold, got %#v", state.Hold)
	}
}

func TestSeedBifrostModelParamsSetsResolvedMaxOutputTokens(t *testing.T) {
	model := "stogas-test-model-cache-set"
	defer providerUtils.DeleteModelParams(model)

	SeedBifrostModelParams(&catalog.ResolvedRequest{
		Model:      model,
		Deployment: catalog.Deployment{MaxOutputTokens: 12345},
	})

	maxOutputTokens, ok := providerUtils.GetMaxOutputTokens(model)
	if !ok || maxOutputTokens != 12345 {
		t.Fatalf("expected max output tokens 12345, got %d ok=%v", maxOutputTokens, ok)
	}
}
