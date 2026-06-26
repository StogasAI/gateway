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

func TestDefaultAdapterFinalPriceClassifiesNoUsageErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode *int
		message    string
		wantCost   string
	}{
		{name: "bad request captures hold", statusCode: lifecycleIntPtr(400), message: "messages.0.content is required", wantCost: "123"},
		{name: "request too large captures hold", statusCode: lifecycleIntPtr(413), message: "request exceeds maximum size", wantCost: "123"},
		{name: "conversion failure without status captures hold", message: "failed to marshal request: missing required field messages", wantCost: "123"},
		{name: "provider auth is insured", statusCode: lifecycleIntPtr(401), message: "provider API key invalid", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "provider rate limit is insured", statusCode: lifecycleIntPtr(429), message: "rate_limit exceeded", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "provider network failure is insured", message: "dial tcp: connection refused", wantCost: billing.ZeroChargeUSDAtoms},
		{name: "provider server failure is insured", statusCode: lifecycleIntPtr(500), message: "provider failed", wantCost: billing.ZeroChargeUSDAtoms},
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
	state := NewState(resolution, "sk-test", nil, OpenAIAdapter{DefaultAdapter: DefaultAdapter{}})
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
	state := NewState(resolution, "sk-test", nil, OpenAIAdapter{DefaultAdapter: DefaultAdapter{}})
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
	priorityState := NewState(priorityResolution, "sk-test", nil, OpenAIAdapter{DefaultAdapter: DefaultAdapter{}})
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
			state := NewState(resolution, "sk-test", nil, OpenAIAdapter{DefaultAdapter: DefaultAdapter{}})
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
	state := NewState(resolution, "sk-test", nil, OpenAIAdapter{DefaultAdapter: DefaultAdapter{}})
	state.Signals = &StandardSignals{Prompt: 1000, ActualServiceTier: &actualTier}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "50000000000000" {
		t.Fatalf("expected selected default deployment pricing for unknown actual tier, got %s", state.FinalCostUSDAtoms)
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
	state := NewState(resolution, "sk-test", nil, AnthropicAdapter{DefaultAdapter: DefaultAdapter{}})
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
	state := NewState(resolution, "sk-test", nil, AnthropicAdapter{DefaultAdapter: DefaultAdapter{}})
	state.Signals = &StandardSignals{Prompt: 1000, Completion: 1000, ActualSpeed: "standard"}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "33000000000000000" {
		t.Fatalf("expected non-fast Anthropic US pricing from actual speed, got %s", state.FinalCostUSDAtoms)
	}
}

func TestFinalizeStateLogsPricingMeters(t *testing.T) {
	authorizer := &fakeBillingAuthorizer{}
	state := &State{
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
	metrics := authorizer.finalEvents[0].Metrics
	pricing, ok := metrics["pricing"].(map[string]any)
	if !ok {
		t.Fatalf("expected pricing metrics, got %#v", metrics)
	}
	if pricing["total_cost_usd_atoms"] != "1000" || pricing["hold_usd_atoms"] != "2000" {
		t.Fatalf("unexpected pricing totals %#v", pricing)
	}
	finalMeters, ok := pricing["final_meters"].([]map[string]any)
	if !ok || len(finalMeters) != 1 {
		t.Fatalf("expected one final meter, got %#v", pricing["final_meters"])
	}
	if finalMeters[0]["meter_key"] != billing.MeterInputTokens || finalMeters[0]["rate_key"] != billing.RatePerMillionTokens || finalMeters[0]["amount_usd_atoms"] != "1000" {
		t.Fatalf("unexpected final meter %#v", finalMeters[0])
	}
	if _, ok := metrics["tokens"]; ok {
		t.Fatalf("metrics must not expose fixed usage token schema: %#v", metrics)
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

func TestAnthropicHoldCoversWorstCaseOneHourCacheWrite(t *testing.T) {
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

func TestAnthropicHoldCoversToolSystemPromptOverhead(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"custom","name":"lookup"}],"tool_choice":{"type":"custom","name":"lookup"},"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AnthropicAdapter{DefaultAdapter: DefaultAdapter{}})
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	foundInputOverhead := false
	foundCacheWriteOverhead := false
	for _, meter := range state.Hold.Meters {
		if meter.Quantity != "589" {
			continue
		}
		switch meter.MeterKey {
		case billing.MeterInputTokens:
			foundInputOverhead = true
		case billing.MeterCacheWrite1hInputTokens:
			foundCacheWriteOverhead = true
		}
	}
	if !foundInputOverhead || !foundCacheWriteOverhead {
		t.Fatalf("expected Anthropic tool overhead hold meters, got %#v", state.Hold.Meters)
	}

	state.Signals = &StandardSignals{
		Prompt:     resolution.InputTokenLimit() + anthropicSonnet46MaxToolOverheadTokens,
		Completion: resolution.OutputTokenLimit(),
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover Anthropic tool overhead final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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
