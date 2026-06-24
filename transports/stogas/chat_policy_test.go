package stogas

import (
	"context"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestChatPolicyRejectsUnsupportedFieldsAndRanges(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"audio", `{"model":"gpt-5.5","messages":[],"audio":{}}`, "audio is not supported"},
		{"image content block", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/x.png"}}]}]}`, "Only text message content"},
		{"modalities", `{"model":"gpt-5.5","messages":[],"modalities":["text","audio"]}`, "modalities"},
		{"n", `{"model":"gpt-5.5","messages":[],"n":2}`, "n must be 1"},
		{"temperature", `{"model":"gpt-5.5","messages":[],"temperature":3}`, "temperature"},
		{"top logprobs requires logprobs", `{"model":"gpt-5.5","messages":[],"top_logprobs":1}`, "top_logprobs requires logprobs"},
		{"hosted tool", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"web_search"}]}`, "Only function and custom tools"},
		{"tool choice string", `{"model":"gpt-5.5","messages":[],"tool_choice":"auto"}`, "tool_choice"},
		{"metadata non-string", `{"model":"gpt-5.5","messages":[],"metadata":{"a":1}}`, "metadata values"},
		{"anthropic-only cache control on openai", `{"model":"gpt-5.5","messages":[],"cache_control":{"type":"ephemeral"}}`, "only supported for Anthropic"},
		{"conflicting reasoning alias", `{"model":"gpt-5.5","messages":[],"reasoning":{"effort":"minimal"},"reasoning_effort":"minimal"}`, "conflicts"},
		{"client user", `{"model":"gpt-5.5","messages":[],"user":"u"}`, "user is not supported"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResolvedChat(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestChatPolicyAllowsAnthropicSpecificFieldsForAnthropicDeployments(t *testing.T) {
	err := validateResolvedChat(t, `{
		"model":"anthropic/claude-sonnet-4-6",
		"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],
		"cache_control":{"type":"ephemeral"},
		"mcp_servers":[],
		"task_budget":{"type":"token_budget","max_tokens":1000},
		"context_management":{"edits":[]},
		"tools":[{"type":"custom","name":"custom_tool"}],
		"tool_choice":{"type":"custom","name":"custom_tool"}
	}`)
	if err != nil {
		t.Fatalf("expected Anthropic-specific chat request to pass, got %v", err)
	}
}

func TestAnthropicFastDeploymentUsesModelSlugAndRequestedAutoTier(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast","messages":[{"role":"user","content":"hi"}]}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "claude-opus-4-8-fast" || resolution.Model != "claude-opus-4-8" {
		t.Fatalf("unexpected fast deployment resolution: %#v", resolution)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if got := bifrostReq.ChatRequest.Params.ExtraParams["speed"]; got != "fast" {
		t.Fatalf("expected fast deployment to set provider-native speed, got %#v", bifrostReq.ChatRequest.Params.ExtraParams)
	}
	if bifrostReq.ChatRequest.Params.ServiceTier == nil || *bifrostReq.ChatRequest.Params.ServiceTier != schemas.BifrostServiceTierAuto {
		t.Fatalf("expected fast deployment to imply auto service tier, got %#v", bifrostReq.ChatRequest.Params.ServiceTier)
	}
}

func TestAnthropicStandardDeploymentUsesStandardOnlyRequestTier(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast-standard","messages":[{"role":"user","content":"hi"}]}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "claude-opus-4-8-fast-standard-only" || resolution.Model != "claude-opus-4-8" {
		t.Fatalf("unexpected standard fast deployment resolution: %#v", resolution)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if got := bifrostReq.ChatRequest.Params.ExtraParams["speed"]; got != "fast" {
		t.Fatalf("expected fast deployment to set provider-native speed, got %#v", bifrostReq.ChatRequest.Params.ExtraParams)
	}
	if bifrostReq.ChatRequest.Params.ServiceTier == nil || *bifrostReq.ChatRequest.Params.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected standard deployment to imply Bifrost default service tier, got %#v", bifrostReq.ChatRequest.Params.ServiceTier)
	}
}

func TestChatPolicySanitizesMetadataBeforeUpstream(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5","messages":[],"metadata":{"tenant":"test"}}`),
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
	bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if bifrostReq.ChatRequest.Params.Metadata != nil {
		t.Fatalf("expected metadata to be sanitized before upstream, got %#v", bifrostReq.ChatRequest.Params.Metadata)
	}
}

func TestAnthropicFinalPriceUsesCacheWriteMeters(t *testing.T) {
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1000000"},
				billing.MeterCachedInputTokens:       {billing.RatePerMillionTokens: "100000"},
				billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1250000"},
				billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "2000000"},
				billing.MeterOutputTokens:            {billing.RatePerMillionTokens: "3000000"},
			}},
		},
		Signals: &StandardSignals{
			Prompt:       1000,
			Completion:   500,
			Cached:       100,
			CacheWrite5m: 200,
			CacheWrite1h: 300,
		},
	}
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "2760" {
		t.Fatalf("expected cache-aware final price 2760, got %s", state.FinalCostUSDAtoms)
	}
}

func validateResolvedChat(t *testing.T, body string) error {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(body),
	})
	if err != nil {
		return err
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	return state.Adapter.ValidateRequest(state)
}
