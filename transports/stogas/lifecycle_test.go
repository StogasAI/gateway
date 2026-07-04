package stogas

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
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
	attempts    []string
	results     []*billing.Authorization
	errors      []error
	finalEvents []billing.RequestEvent
	callCount   int
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
		if holdMeter == nil || holdMeter.RateKey != billing.RatePerMillionContextGT272K || !holdMeter.HoldRequired {
			t.Fatalf("expected high-context hold meter for %s, got %#v in %#v", meterKey, holdMeter, state.Hold.Meters)
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

func TestFinalPriceUsesAggregateOutputTokensWithoutDoubleCountingDetails(t *testing.T) {
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
			TextTokens:                40,
			ReasoningTokens:           180,
			RejectedPredictionTokens:  20,
			AcceptedPredictionTokens:  10,
		},
	})
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "1500" {
		t.Fatalf("expected aggregate-token final cost 1500, got %s", state.FinalCostUSDAtoms)
	}
	if len(state.FinalMeters) != 2 {
		t.Fatalf("expected two final meters, got %#v", state.FinalMeters)
	}
	if state.FinalMeters[1].Quantity != "250" || state.FinalMeters[1].AmountUSDAtoms != "500" {
		t.Fatalf("expected output meter to price aggregate completion tokens once, got %#v", state.FinalMeters[1])
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
		if signals == nil || signals.Prompt != 100 || signals.Completion != 75 {
			t.Fatalf("signalsFromUsage() = %#v, want prompt=100 completion=75", signals)
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
		if signals == nil || signals.Prompt != 100 || signals.Completion != 60 {
			t.Fatalf("signalsFromUsage() = %#v, want prompt=100 completion=60", signals)
		}
	})
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
			Error:     &schemas.ErrorField{Message: "provider failed after returning usage"},
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
		Authorization: &billing.Authorization{AuthorizedAmount: big.NewInt(2000)},
		Hold: HoldEstimate{
			MaxUSDAtoms: "2000",
			Meters: []catalog.MeterEstimate{{
				MeterKey:       billing.MeterOutputTokens,
				RateKey:        billing.RatePerMillionTokens,
				Quantity:       "1000",
				AmountUSDAtoms: "2000",
				HoldRequired:   true,
			}},
		},
		BifrostError: &schemas.BifrostError{
			StatusCode: lifecycleIntPtr(400),
			Error:     &schemas.ErrorField{Message: "messages.0.content is required"},
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

	pricing := requestLogPricingBag(state)
	assertPricingBagEntry(t, pricing, billing.MeterOutputTokens, billing.RatePerMillionTokens, "1000", "2000")
}

func lifecycleIntPtr(value int) *int {
	return &value
}

func TestFinalPriceUsesActualOpenAIServiceTierWhenExplicitTierReturned(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano-priority","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
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
	if state.FinalCostUSDAtoms != "2500000000000000" {
		t.Fatalf("expected priority input pricing from actual service tier, got %s", state.FinalCostUSDAtoms)
	}
}

func TestOpenAIPriorityHoldCoversActualPriorityServiceTier(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano-priority","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":128}`),
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
		t.Fatalf("hold must cover actual priority final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
	if state.Hold.ProductKey != "gpt-5-nano-priority" {
		t.Fatalf("expected priority deployment hold product key, got %#v", state.Hold)
	}
}

func TestOpenAIDefaultAndAutoHoldUseSelectedDefaultDeployment(t *testing.T) {
	priorityResolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano-priority","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest priority returned error: %v", err)
	}
	priorityState := NewState(priorityResolution, "sk-test", nil, AdapterFor(priorityResolution.Provider))
	if err := priorityState.Adapter.EstimateHold(priorityState); err != nil {
		t.Fatalf("EstimateHold priority returned error: %v", err)
	}
	priorityInput := findMeterEstimate(priorityState.Hold.Meters, billing.MeterInputTokens)
	if priorityInput == nil {
		t.Fatalf("priority hold missing input meter: %#v", priorityState.Hold.Meters)
	}

	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat omitted",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`,
		},
		{
			name: "chat auto",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"auto","max_completion_tokens":16}`,
		},
		{
			name: "chat default",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"default","max_completion_tokens":16}`,
		},
		{
			name: "responses omitted",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","max_output_tokens":16}`,
		},
		{
			name: "responses auto",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","service_tier":"auto","max_output_tokens":16}`,
		},
		{
			name: "responses default",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","service_tier":"default","max_output_tokens":16}`,
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
			if state.Hold.ProductKey != "gpt-5-nano" {
				t.Fatalf("expected default deployment hold product key, got %#v", state.Hold)
			}
			defaultInput := findMeterEstimate(state.Hold.Meters, billing.MeterInputTokens)
			if defaultInput == nil {
				t.Fatalf("default hold missing input meter: %#v", state.Hold.Meters)
			}
			if compareMoneyStrings(defaultInput.AmountUSDAtoms, priorityInput.AmountUSDAtoms) >= 0 {
				t.Fatalf("default/auto hold must use default pricing, got default=%#v priority=%#v", defaultInput, priorityInput)
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

func TestOpenAIDefaultHoldCanSettleAtReturnedPriorityTier(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"auto","max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if state.Hold.ProductKey != "gpt-5-nano" {
		t.Fatalf("expected auto/default request to hold selected default deployment, got %#v", state.Hold)
	}
	actualTier := schemas.BifrostServiceTierPriority
	state.Signals = &StandardSignals{Prompt: 1000, ActualServiceTier: &actualTier}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "2500000000000000" {
		t.Fatalf("expected returned priority tier to drive final price, got %s", state.FinalCostUSDAtoms)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) >= 0 {
		t.Fatalf("default/auto hold should not reserve unrequested priority capacity: hold=%s final=%s", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms)
	}
	input := findMeterEstimate(state.FinalMeters, billing.MeterInputTokens)
	if input == nil || input.RateKey != billing.RatePerMillionTokens || input.AmountUSDAtoms != "2500000000000000" {
		t.Fatalf("expected final input meter to use priority pricing, got %#v", state.FinalMeters)
	}
}

func TestOpenAIResponsesFinalPriceUsesReturnedServiceTierFromUsage(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","service_tier":"auto","max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if state.Hold.ProductKey != "gpt-5-nano" {
		t.Fatalf("expected auto request to hold selected default deployment, got %#v", state.Hold)
	}

	actualTier := schemas.BifrostServiceTierPriority
	if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		ServiceTier: &actualTier,
		Usage: &schemas.ResponsesResponseUsage{
			InputTokens: 1000,
		},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "2500000000000000" {
		t.Fatalf("expected returned priority tier to drive OpenAI Responses final price, got %s", state.FinalCostUSDAtoms)
	}
	input := findMeterEstimate(state.FinalMeters, billing.MeterInputTokens)
	if input == nil || input.RateKey != billing.RatePerMillionTokens || input.AmountUSDAtoms != "2500000000000000" {
		t.Fatalf("expected final input meter to use priority pricing, got %#v", state.FinalMeters)
	}
}

func TestOpenAIResponsesStreamKeepsActualTierWhenUsageArrivesLater(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","service_tier":"auto","max_output_tokens":16,"stream":true}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}

	actualTier := schemas.BifrostServiceTierPriority
	if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:     schemas.ResponsesStreamResponseTypeInProgress,
			Response: &schemas.BifrostResponsesResponse{ServiceTier: &actualTier},
		},
	}); err != nil {
		t.Fatalf("IngestChunk tier returned error: %v", err)
	}
	if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeCompleted,
			Response: &schemas.BifrostResponsesResponse{
				Usage: &schemas.ResponsesResponseUsage{InputTokens: 1000},
			},
		},
	}); err != nil {
		t.Fatalf("IngestChunk usage returned error: %v", err)
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "2500000000000000" {
		t.Fatalf("expected earlier streamed priority tier to drive final price, got %s", state.FinalCostUSDAtoms)
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
			wantHold:   "claude-opus-4-8",
			actualTier: schemas.BifrostServiceTier("standard_only"),
		},
		{
			name:       "standard request returned priority",
			body:       `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"standard_only","max_completion_tokens":16}`,
			wantHold:   "claude-opus-4-8",
			actualTier: schemas.BifrostServiceTierPriority,
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
			name:       "chat auto sent as auto returns priority",
			path:       "/v1/chat/completions",
			body:       `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"auto","max_completion_tokens":16}`,
			actualTier: schemas.BifrostServiceTierPriority,
		},
		{
			name:       "chat priority sent as auto returns priority",
			path:       "/v1/chat/completions",
			body:       `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"priority","max_completion_tokens":16}`,
			actualTier: schemas.BifrostServiceTierPriority,
		},
		{
			name:       "responses flex sent as standard only returns standard",
			path:       "/v1/responses",
			body:       `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"flex","max_output_tokens":16}`,
			actualTier: schemas.BifrostServiceTier("standard_only"),
		},
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

func TestFinalPriceUsesActualAnthropicSpeedWhenReturned(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	state.Signals = &StandardSignals{Prompt: 1000, Completion: 1000, ActualSpeed: "standard"}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "30000000000000000" {
		t.Fatalf("expected non-fast Anthropic pricing from actual speed, got %s", state.FinalCostUSDAtoms)
	}
}

func TestFinalPriceKeepsAnthropicUSRegionWhenActualSpeedChanges(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast-us","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.RegionID != "us" {
		t.Fatalf("expected US deployment, got %#v", resolution.Deployment)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	state.Signals = &StandardSignals{Prompt: 1000, Completion: 1000, ActualSpeed: "standard"}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "33000000000000000" {
		t.Fatalf("expected non-fast Anthropic US pricing from actual speed, got %s", state.FinalCostUSDAtoms)
	}
}

func TestAnthropicResponsesStreamKeepsActualTierAndSpeedWhenUsageArrivesLater(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast-us","input":"hi","max_output_tokens":16,"stream":true}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.RegionID != "us" || !strings.Contains(resolution.Deployment.ID, "fast") {
		t.Fatalf("expected fast US deployment, got %#v", resolution.Deployment)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}

	actualTier := schemas.BifrostServiceTier("standard_only")
	actualSpeed := "standard"
	if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeInProgress,
			Response: &schemas.BifrostResponsesResponse{
				ServiceTier: &actualTier,
				Speed:       &actualSpeed,
			},
		},
	}); err != nil {
		t.Fatalf("IngestChunk tier/speed returned error: %v", err)
	}
	if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeCompleted,
			Response: &schemas.BifrostResponsesResponse{
				Usage: &schemas.ResponsesResponseUsage{
					InputTokens:  100,
					OutputTokens: 16,
				},
			},
		},
	}); err != nil {
		t.Fatalf("IngestChunk usage returned error: %v", err)
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "990000000000000" {
		t.Fatalf("expected streamed Anthropic actual standard speed US pricing, got %s", state.FinalCostUSDAtoms)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover streamed Anthropic actual tier/speed final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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
				ID:                  "gpt-5-standard",
				ModelID:             "gpt-5-2026-01-01",
				ProviderEndpointIDs: []string{"openai-chat-completions"},
			},
		},
		Authorization: &billing.Authorization{
			AuthorizedAmount: big.NewInt(2000),
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
			MaxUSDAtoms: "2000",
			Meters: []catalog.MeterEstimate{{
				MeterKey:       billing.MeterOutputTokens,
				RateKey:        billing.RatePerMillionTokens,
				Quantity:       "1000",
				AmountUSDAtoms: "2000",
				HoldRequired:   true,
			}},
		},
		RequestType:        string(schemas.ChatCompletionRequest),
		Model:              "gpt-5",
		ReleaseMeasurement: strings.Repeat("a", 64),
		StartedAt:          time.Now().UTC(),
		FinalCostUSDAtoms:  "1000",
		FinalMeters: []catalog.MeterEstimate{{
			MeterKey:       billing.MeterInputTokens,
			RateKey:        billing.RatePerMillionTokens,
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
	pricing := event.Pricing
	if _, ok := pricing["total_cost_usd_atoms"]; ok {
		t.Fatalf("pricing must not duplicate the top-level total cost: %#v", pricing)
	}
	if _, ok := pricing["hold_usd_atoms"]; ok {
		t.Fatalf("pricing must not expose a fixed hold total: %#v", pricing)
	}
	if _, ok := pricing["basis"]; ok {
		t.Fatalf("pricing must not expose a fixed pricing basis: %#v", pricing)
	}
	if _, ok := pricing["final"]; ok {
		t.Fatalf("pricing must not expose a fixed final meter schema: %#v", pricing)
	}
	if _, ok := pricing["hold"]; ok {
		t.Fatalf("pricing must not expose a fixed hold meter schema: %#v", pricing)
	}
	input, ok := pricing[billing.MeterInputTokens].(map[string]any)
	if !ok {
		t.Fatalf("expected input token pricing bag, got %#v", pricing)
	}
	if input["rateKey"] != billing.RatePerMillionTokens || input["usdAtoms"] != "1000" || input["quantity"] != "1000" {
		t.Fatalf("unexpected final input token pricing %#v", input)
	}
	if _, ok := pricing[billing.MeterOutputTokens]; ok {
		t.Fatalf("pricing bag must not log hold-only meters: %#v", pricing)
	}
	if event.TotalCostUSDAtoms != "1000" {
		t.Fatalf("total cost must match final meter sum, got %s", event.TotalCostUSDAtoms)
	}
	if event.ReleaseMeasurement != strings.Repeat("a", 64) {
		t.Fatalf("release measurement = %q", event.ReleaseMeasurement)
	}
	wantNodeIDs := []string{"stogas_endpoint:chat-completions", "provider:openai", "model:gpt-5", "model_node:gpt-5-2026-01-01", "deployment:gpt-5-standard", "provider_endpoint:openai-chat-completions"}
	if strings.Join(event.ResolvedCatalogNodeIDs, ",") != strings.Join(wantNodeIDs, ",") {
		t.Fatalf("resolved catalog node IDs = %#v, want %#v", event.ResolvedCatalogNodeIDs, wantNodeIDs)
	}
}

func TestPricingMetricBagAggregatesDuplicateMeterRateKeys(t *testing.T) {
	bag := map[string]any{}
	mergePricingMeters(bag, []catalog.MeterEstimate{
		{
			AmountUSDAtoms: "3",
			MeterKey:       billing.MeterInputTokens,
			Quantity:       "10",
			RateKey:        billing.RatePerMillionTokens,
		},
		{
			AmountUSDAtoms: "7",
			MeterKey:       billing.MeterInputTokens,
			Quantity:       "5",
			RateKey:        billing.RatePerMillionTokens,
		},
	})
	input := bag[billing.MeterInputTokens].(map[string]any)
	if input["quantity"] != "15" || input["usdAtoms"] != "10" || input["rateKey"] != billing.RatePerMillionTokens {
		t.Fatalf("unexpected aggregated pricing bag %#v", bag)
	}
}

func TestUnaryProviderLatencyPopulatesProviderAttemptTTFB(t *testing.T) {
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
	state.ObserveUnaryProviderLatency(state.Response.ChatResponse.ExtraFields)
	state.MarkFirstByte()

	authorizer := &fakeBillingAuthorizer{}
	FinalizeState(context.Background(), authorizer, state)

	if len(authorizer.finalEvents) != 1 {
		t.Fatalf("expected one final event, got %d", len(authorizer.finalEvents))
	}
	attempt := authorizer.finalEvents[0].ProviderAttempts[0]
	if attempt.LatencyMS != 81 {
		t.Fatalf("expected provider total latency 81, got %#v", attempt)
	}
	if attempt.ProviderTTFBMS == nil || *attempt.ProviderTTFBMS != 81 {
		t.Fatalf("expected unary provider ttfb to use provider latency, got %#v", attempt)
	}
	if authorizer.finalEvents[0].TTFBMS == 0 {
		t.Fatalf("expected Stogas/client ttfb to be measured separately")
	}
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

	pricing := requestLogPricingBag(state)
	assertPricingBagEntry(t, pricing, billing.MeterInputTokens, billing.RatePerMillionTokens, "2", "1")
	if got := sumMeterAmounts(compactMeterEstimates(state.FinalMeters, state.Resolution.Deployment.Pricing)); got != "1" {
		t.Fatalf("expected compacted meter total 1 atom, got %s", got)
	}

	authorizer := &fakeBillingAuthorizer{}
	state.Authorization = &billing.Authorization{
		AuthorizedAmount: big.NewInt(2),
		AvailableAfter:   big.NewInt(0),
		RequestID:        "request",
	}
	state.FinalCostUSDAtoms = "2"
	state.StartedAt = time.Now().UTC()
	FinalizeState(context.Background(), authorizer, state)
	if len(authorizer.finalEvents) != 1 {
		t.Fatalf("expected one final event, got %d", len(authorizer.finalEvents))
	}
	event := authorizer.finalEvents[0]
	if event.TotalCostUSDAtoms != "1" {
		t.Fatalf("logged total must use compacted final meters, got %s", event.TotalCostUSDAtoms)
	}
	assertPricingBagEntry(t, event.Pricing, billing.MeterInputTokens, billing.RatePerMillionTokens, "2", "1")
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

	pricing := requestLogPricingBag(state)
	assertPricingBagEntry(t, pricing, billing.MeterInputTokens, billing.RatePerMillionTokens, "500", "50")
	assertPricingBagEntry(t, pricing, billing.MeterCacheWrite1hInputTokens, billing.RatePerMillionTokens, "400", "80")
	assertPricingBagEntry(t, pricing, meterAnthropicWebSearchCalls, billing.RatePerThousandCalls, "1", "150")
	for _, forbidden := range []string{"hold", "final", "hold_meters", "final_meters", "total_cost_usd_atoms", "usageMetrics"} {
		if _, ok := pricing[forbidden]; ok {
			t.Fatalf("pricing bag must not expose fixed key %q: %#v", forbidden, pricing)
		}
	}
}

func assertPricingBagEntry(t *testing.T, bag map[string]any, meterKey string, rateKey string, quantity string, amount string) {
	t.Helper()
	meter, ok := bag[meterKey].(map[string]any)
	if !ok {
		t.Fatalf("missing pricing meter %s in %#v", meterKey, bag)
	}
	if meter["rateKey"] != rateKey || meter["quantity"] != quantity || meter["usdAtoms"] != amount {
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
		Body:   []byte(`{"model":"gpt-4o-search-preview","messages":[],"web_search_options":{"search_context_size":"low"},"max_completion_tokens":100}`),
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
	if searchMeter.MeterKey != MeterOpenAIChatCompletionSearchPreviewModelCalls || searchMeter.RateKey != RatePerThousandSearchContextLowCalls {
		t.Fatalf("expected low-context search preview meter, got %#v", searchMeter)
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
		{
			name:     "omitted defaults medium",
			body:     `{"model":"gpt-4o-search-preview","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":100}`,
			meterKey: MeterOpenAIChatCompletionSearchPreviewModelCalls,
			rateKey:  RatePerThousandSearchContextMediumCalls,
		},
		{
			name:     "low",
			body:     `{"model":"gpt-4o-search-preview","messages":[{"role":"user","content":"hi"}],"web_search_options":{"search_context_size":"low"},"max_completion_tokens":100}`,
			meterKey: MeterOpenAIChatCompletionSearchPreviewModelCalls,
			rateKey:  RatePerThousandSearchContextLowCalls,
		},
		{
			name:     "medium",
			body:     `{"model":"gpt-4o-search-preview","messages":[{"role":"user","content":"hi"}],"web_search_options":{"search_context_size":"medium"},"max_completion_tokens":100}`,
			meterKey: MeterOpenAIChatCompletionSearchPreviewModelCalls,
			rateKey:  RatePerThousandSearchContextMediumCalls,
		},
		{
			name:     "high",
			body:     `{"model":"gpt-4o-search-preview","messages":[{"role":"user","content":"hi"}],"web_search_options":{"search_context_size":"high"},"max_completion_tokens":100}`,
			meterKey: MeterOpenAIChatCompletionSearchPreviewModelCalls,
			rateKey:  RatePerThousandSearchContextHighCalls,
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
			pricing := requestLogPricingBag(state)
			for _, meterKey := range []string{billing.MeterInputTokens, billing.MeterOutputTokens} {
				if _, ok := pricing[meterKey].(map[string]any); !ok {
					t.Fatalf("search-model pricing bag must include token meter %s with tool meter, got %#v", meterKey, pricing)
				}
			}
			searchPricing, ok := pricing[tt.meterKey].(map[string]any)
			if !ok {
				t.Fatalf("missing search meter pricing bag: %#v", pricing)
			}
			if searchPricing["quantity"] != "1" || searchPricing["rateKey"] != tt.rateKey || searchPricing["usdAtoms"] == "" {
				t.Fatalf("unexpected search pricing bag: %#v", searchPricing)
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
	expectedOverhead := big.NewInt(int64(anthropicToolSystemPromptHoldTokens(resolution.Deployment.Model, resolution.ToolTypes()))).String()
	foundInputOverhead := false
	for _, meter := range state.Hold.Meters {
		if meter.Quantity != expectedOverhead {
			continue
		}
		if meter.MeterKey == billing.MeterInputTokens {
			foundInputOverhead = true
		}
	}
	if !foundInputOverhead {
		t.Fatalf("expected Anthropic tool overhead input hold meter, got %#v", state.Hold.Meters)
	}
	if findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens) != nil || findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite5mInputTokens) != nil {
		t.Fatalf("did not expect cache write hold meter without cache_control, got %#v", state.Hold.Meters)
	}

	state.Signals = &StandardSignals{
		Prompt:     resolution.InputTokenLimit() + anthropicToolSystemPromptHoldTokens(resolution.Deployment.Model, resolution.ToolTypes()),
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
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast-us","input":[{"role":"user","content":[{"type":"input_text","text":"hello","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],"tools":[{"type":"web_search_20250305","name":"web_search"}],"max_tool_calls":2,"max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.RegionID != "us" || !strings.Contains(resolution.Deployment.ID, "fast") {
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

func TestSignalsFromUsageDoesNotDropInconsistentCacheWriteDetails(t *testing.T) {
	tests := []struct {
		name             string
		aggregate        int
		split5m          int
		split1h          int
		wantPrompt       int
		wantCacheWrite5m int
		wantCacheWrite1h int
	}{
		{
			name:             "aggregate has residual",
			aggregate:        600,
			split5m:          200,
			split1h:          300,
			wantPrompt:       700,
			wantCacheWrite5m: 200,
			wantCacheWrite1h: 400,
		},
		{
			name:             "split details exceed aggregate",
			aggregate:        400,
			split5m:          200,
			split1h:          300,
			wantPrompt:       600,
			wantCacheWrite5m: 200,
			wantCacheWrite1h: 300,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signals := signalsFromUsage(&schemas.BifrostLLMUsage{
				CompletionTokens: 20,
				PromptTokensDetails: &schemas.ChatPromptTokensDetails{
					TextTokens:        100,
					CachedWriteTokens: tt.aggregate,
					CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
						CachedWriteTokens5m: tt.split5m,
						CachedWriteTokens1h: tt.split1h,
					},
				},
			})
			if signals == nil {
				t.Fatal("expected signals")
			}
			if signals.Prompt != tt.wantPrompt || signals.CacheWrite5m != tt.wantCacheWrite5m || signals.CacheWrite1h != tt.wantCacheWrite1h {
				t.Fatalf("unexpected cache-write mapping: %#v", signals)
			}
		})
	}
}

func TestSignalsFromUsageMapsLegacyCacheWriteTokensAsFiveMinute(t *testing.T) {
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
	if signals.CacheWrite5m != 200 || signals.CacheWrite1h != 0 {
		t.Fatalf("expected legacy cache write tokens to map to 5m bucket, got %#v", signals)
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
