package stogas

import (
	"encoding/json"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestHostedToolHoldQuantity(t *testing.T) {
	cases := []struct {
		name string
		body string
		tool string
		want int
	}{
		{
			name: "default omitted cap",
			body: `{}`,
			tool: `{"type":"web_search_20260209"}`,
			want: 50,
		},
		{
			name: "top level cap",
			body: `{"max_tool_calls":7}`,
			tool: `{"type":"web_search_20250305"}`,
			want: 7,
		},
		{
			name: "tool cap overrides omitted top level",
			body: `{}`,
			tool: `{"type":"web_search_20250305","max_uses":3}`,
			want: 3,
		},
		{
			name: "largest tool cap wins",
			body: `{"max_tool_calls":2}`,
			tool: `{"type":"web_search_20250305","max_uses":9}`,
			want: 9,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req := anthropicAdapterContext{
				RawBody:  mustObject(t, tt.body),
				RawTools: []map[string]json.RawMessage{mustObject(t, tt.tool)},
			}
			if got := anthropicHostedToolHoldQuantity(req); got != tt.want {
				t.Fatalf("anthropicHostedToolHoldQuantity() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAnthropicResponsesToolAdmission(t *testing.T) {
	adapter := AnthropicAdapter{}
	state := &State{
		Resolution: &catalog.ResolvedRequest{
			Deployment: catalog.Deployment{
				Pricing: testPricing(),
			},
		},
	}
	for _, raw := range []string{
		`{"type":"web_search_20250305"}`,
		`{"type":"web_search_20260209"}`,
		`{"type":"web_search_20260318"}`,
		`{"type":"web_search"}`,
		`{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":1000}`,
		`{"type":"web_fetch_20260318","name":"web_fetch","max_content_tokens":1000}`,
		`{"type":"web_fetch_20260309","name":"web_fetch","filters":{"allowed_domains":["example.com"]}}`,
	} {
		if err := adapter.ValidateRawResponsesToolType(state, mustObject(t, raw)); err != nil {
			t.Fatalf("expected Anthropic tool %s to pass, got %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"type":"code_execution_20250825","name":"code_execution"}`,
		`{"type":"code_execution"}`,
		`{"type":"web_fetch_20260309","name":"web_fetch","use_cache":true}`,
	} {
		if err := adapter.ValidateRawResponsesToolType(state, mustObject(t, raw)); err == nil {
			t.Fatalf("expected Anthropic tool %s to reject", raw)
		}
	}
}

func TestAnthropicHoldMeters(t *testing.T) {
	req := anthropicAdapterContext{
		Route:                anthropicAdapterRouteResponses,
		Deployment:           anthropicAdapterDeployment{Model: "claude-opus-4-8", Pricing: testPricing()},
		InputTokenLimit:       1000,
		ToolChoiceAllowsCalls: true,
		ToolTypes:             []string{"web_search"},
		RawBody:               mustObject(t, `{"max_tool_calls":4}`),
		RawTools:              []map[string]json.RawMessage{mustObject(t, `{"type":"web_search_20250305"}`)},
	}

	meters := anthropicHoldMeters(req)
	if findMeter(meters, billing.MeterCacheWrite5mInputTokens, "1000") != nil || findMeter(meters, billing.MeterCacheWrite1hInputTokens, "1000") != nil {
		t.Fatalf("expected no cache write hold meter without cache_control, got %#v", meters)
	}
	if findMeter(meters, billing.MeterInputTokens, "410") == nil {
		t.Fatalf("expected Opus 4.8 tool prompt overhead input meter, got %#v", meters)
	}
	if findMeter(meters, meterAnthropicWebSearchCalls, "4") == nil {
		t.Fatalf("expected web search call hold meter, got %#v", meters)
	}
	for _, meter := range meters {
		if !meter.HoldRequired {
			t.Fatalf("expected hold meter to require hold, got %#v", meter)
		}
	}
}

func TestAnthropicWebFetchContentHoldTokens(t *testing.T) {
	cases := []struct {
		name string
		body string
		tool string
		want int
	}{
		{
			name: "explicit max uses and content tokens",
			body: `{}`,
			tool: `{"type":"web_fetch_20260309","max_uses":3,"max_content_tokens":700}`,
			want: 2100,
		},
		{
			name: "dynamic fetch version uses same token hold",
			body: `{"max_tool_calls":2}`,
			tool: `{"type":"web_fetch_20260318","max_content_tokens":700}`,
			want: 1400,
		},
		{
			name: "top level cap supplies max uses",
			body: `{"max_tool_calls":4}`,
			tool: `{"type":"web_fetch_20260309","max_content_tokens":600}`,
			want: 2400,
		},
		{
			name: "omitted cap defaults then caps to remaining context",
			body: `{}`,
			tool: `{"type":"web_fetch_20260309","max_content_tokens":1000}`,
			want: 4000,
		},
		{
			name: "omitted content limit reserves remaining context",
			body: `{"max_tool_calls":2}`,
			tool: `{"type":"web_fetch_20260309"}`,
			want: 4000,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req := anthropicAdapterContext{
				Route:                 anthropicAdapterRouteResponses,
				Deployment:            anthropicAdapterDeployment{Model: "claude-sonnet-4-6", ContextWindowTokens: 5000, Pricing: testPricing()},
				InputTokenLimit:        900,
				OutputTokenLimit:       100,
				ToolChoiceAllowsCalls: true,
				ToolTypes:             []string{"web_fetch"},
				RawBody:               mustObject(t, tt.body),
				RawTools:              []map[string]json.RawMessage{mustObject(t, tt.tool)},
			}
			if got := anthropicHostedContentHoldTokens(req); got != tt.want {
				t.Fatalf("anthropicHostedContentHoldTokens() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAnthropicHostedContentHoldMetersIncludeCacheWrite(t *testing.T) {
	req := anthropicAdapterContext{
		Route:                 anthropicAdapterRouteResponses,
		Deployment:            anthropicAdapterDeployment{Model: "claude-sonnet-4-6", ContextWindowTokens: 5000, Pricing: testPricing()},
		InputTokenLimit:        900,
		OutputTokenLimit:       100,
		ToolChoiceAllowsCalls: true,
		ToolTypes:             []string{"web_fetch"},
		RawBody:               mustObject(t, `{"cache_control":{"type":"ephemeral","ttl":"1h"},"max_tool_calls":2}`),
		RawTools:              []map[string]json.RawMessage{mustObject(t, `{"type":"web_fetch_20260309","max_content_tokens":700}`)},
	}
	meters := anthropicHoldMeters(req)
	if findMeter(meters, billing.MeterInputTokens, "1400") == nil {
		t.Fatalf("expected web_fetch fetched-content input hold meter, got %#v", meters)
	}
	if findMeter(meters, billing.MeterCacheWrite1hInputTokens, "1400") == nil {
		t.Fatalf("expected web_fetch fetched-content cache-write hold meter, got %#v", meters)
	}

	req.ToolTypes = []string{"web_search"}
	req.RawTools = []map[string]json.RawMessage{mustObject(t, `{"type":"web_search_20260318"}`)}
	meters = anthropicHoldMeters(req)
	if findMeter(meters, billing.MeterInputTokens, "4000") == nil {
		t.Fatalf("expected web_search result-content input hold meter, got %#v", meters)
	}
	if findMeter(meters, billing.MeterCacheWrite1hInputTokens, "4000") == nil {
		t.Fatalf("expected web_search result-content cache-write hold meter, got %#v", meters)
	}
}

func TestAnthropicHostedContentHoldDoesNotDoubleCountSearchAndFetch(t *testing.T) {
	req := anthropicAdapterContext{
		Route:                 anthropicAdapterRouteResponses,
		Deployment:            anthropicAdapterDeployment{Model: "claude-sonnet-4-6", ContextWindowTokens: 5000, Pricing: testPricing()},
		InputTokenLimit:        900,
		OutputTokenLimit:       100,
		ToolChoiceAllowsCalls: true,
		ToolTypes:             []string{"web_search", "web_fetch"},
		RawBody:               mustObject(t, `{"max_tool_calls":2}`),
		RawTools: []map[string]json.RawMessage{
			mustObject(t, `{"type":"web_search_20260318"}`),
			mustObject(t, `{"type":"web_fetch_20260309","max_content_tokens":700}`),
		},
	}
	if got := anthropicHostedContentHoldTokens(req); got != 4000 {
		t.Fatalf("anthropicHostedContentHoldTokens() = %d, want remaining context once", got)
	}
}

func TestAnthropicCacheWriteHoldMetersFollowRequestedTTL(t *testing.T) {
	cases := []struct {
		name      string
		route     anthropicAdapterRoute
		body      string
		tools     []string
		wantMeter string
	}{
		{
			name:      "top level defaults to five minute",
			route:     anthropicAdapterRouteChat,
			body:      `{"cache_control":{"type":"ephemeral"}}`,
			wantMeter: billing.MeterCacheWrite5mInputTokens,
		},
		{
			name:      "top level one hour",
			route:     anthropicAdapterRouteChat,
			body:      `{"cache_control":{"type":"ephemeral","ttl":"1h"}}`,
			wantMeter: billing.MeterCacheWrite1hInputTokens,
		},
		{
			name:      "chat content block one hour",
			route:     anthropicAdapterRouteChat,
			body:      `{"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}`,
			wantMeter: billing.MeterCacheWrite1hInputTokens,
		},
		{
			name:      "responses input five minute",
			route:     anthropicAdapterRouteResponses,
			body:      `{"input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"5m"}}]}]}`,
			wantMeter: billing.MeterCacheWrite5mInputTokens,
		},
		{
			name:      "tool one hour",
			route:     anthropicAdapterRouteResponses,
			body:      `{}`,
			tools:     []string{`{"type":"function","name":"lookup","cache_control":{"type":"ephemeral","ttl":"1h"}}`},
			wantMeter: billing.MeterCacheWrite1hInputTokens,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rawTools := make([]map[string]json.RawMessage, 0, len(tt.tools))
			for _, tool := range tt.tools {
				rawTools = append(rawTools, mustObject(t, tool))
			}
			req := anthropicAdapterContext{
				Route:           tt.route,
				Deployment:      anthropicAdapterDeployment{Model: "claude-sonnet-4-6", Pricing: testPricing()},
				InputTokenLimit:  1000,
				RawBody:         mustObject(t, tt.body),
				RawTools:        rawTools,
			}
			meters := anthropicHoldMeters(req)
			if findMeter(meters, tt.wantMeter, "1000") == nil {
				t.Fatalf("expected %s cache write hold meter, got %#v", tt.wantMeter, meters)
			}
			otherMeter := billing.MeterCacheWrite1hInputTokens
			if tt.wantMeter == otherMeter {
				otherMeter = billing.MeterCacheWrite5mInputTokens
			}
			if findMeter(meters, otherMeter, "1000") != nil {
				t.Fatalf("did not expect %s cache write hold meter, got %#v", otherMeter, meters)
			}
		})
	}
}

func TestAnthropicFinalMeters(t *testing.T) {
	req := anthropicAdapterContext{
		Route:               anthropicAdapterRouteResponses,
		Deployment:          anthropicAdapterDeployment{Model: "claude-opus-4-8", Pricing: testPricing()},
		ToolChoiceAllowsCalls: true,
		ToolTypes:           []string{"web_search"},
		ActualWebSearchCalls: 3,
	}

	meters := anthropicFinalMeters(req)
	meter := findMeter(meters, meterAnthropicWebSearchCalls, "3")
	if meter == nil {
		t.Fatalf("expected web search settlement meter, got %#v", meters)
	}
	if meter.HoldRequired {
		t.Fatalf("settlement meter should not require hold: %#v", meter)
	}

	req.RawBody = mustObject(t, `{"max_tool_calls":2}`)
	if meter := findMeter(anthropicFinalMeters(req), meterAnthropicWebSearchCalls, "2"); meter == nil {
		t.Fatalf("expected web search settlement meter to be capped by max_tool_calls, got %#v", anthropicFinalMeters(req))
	}

	req.ToolChoiceAllowsCalls = false
	if meters := anthropicFinalMeters(req); len(meters) != 0 {
		t.Fatalf("expected no settlement meter when tool_choice precludes hosted calls, got %#v", meters)
	}

	req.ToolChoiceAllowsCalls = true
	req.ToolTypes = []string{"web_fetch"}
	req.ActualWebSearchCalls = 3
	if meters := anthropicFinalMeters(req); len(meters) != 0 {
		t.Fatalf("expected no web-search settlement meter for web_fetch-only requests, got %#v", meters)
	}
}

func TestResponsesHostedToolChoiceAllowsCallsCanonicalizesVersionedTypes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "anthropic versioned selected web search",
			body: `{"tool_choice":{"type":"web_search_20250305"}}`,
			want: true,
		},
		{
			name: "anthropic versioned allowed web search",
			body: `{"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_20250305"}]}}`,
			want: true,
		},
		{
			name: "anthropic versioned selected web fetch",
			body: `{"tool_choice":{"type":"web_fetch_20260309"}}`,
			want: true,
		},
		{
			name: "anthropic versioned allowed web fetch",
			body: `{"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_fetch_20260309"}]}}`,
			want: true,
		},
		{
			name: "function selected",
			body: `{"tool_choice":{"type":"function","name":"lookup"}}`,
			want: false,
		},
		{
			name: "function allowed",
			body: `{"tool_choice":{"type":"allowed_tools","tools":[{"type":"function","name":"lookup"}]}}`,
			want: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := responsesHostedToolChoiceAllowsCalls(mustObject(t, tt.body)); got != tt.want {
				t.Fatalf("responsesHostedToolChoiceAllowsCalls() = %v, want %v", got, tt.want)
			}
		})
	}
}

func testPricing() billing.Pricing {
	return billing.Pricing{
		billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1000000"},
		billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1250000"},
		billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "2000000"},
		meterAnthropicWebSearchCalls:         {billing.RatePerThousandCalls: "1000000"},
	}
}

func mustObject(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func findMeter(meters []billing.MeterEstimate, meterKey string, quantity string) *billing.MeterEstimate {
	for i := range meters {
		if meters[i].MeterKey == meterKey && meters[i].Quantity == quantity {
			return &meters[i]
		}
	}
	return nil
}
