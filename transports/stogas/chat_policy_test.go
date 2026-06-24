package stogas

import (
	"context"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	openaiadapter "github.com/maximhq/bifrost/transports/stogas/providers/openai"
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

func TestResponsesPolicyRejectsUnsupportedFieldsAndInvalidShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"missing input", `{"model":"gpt-5-nano"}`, "input is required"},
		{"background", `{"model":"gpt-5-nano","input":"hi","background":true}`, "background is not supported"},
		{"conversation", `{"model":"gpt-5-nano","input":"hi","conversation":"conv_123"}`, "conversation is not supported"},
		{"include", `{"model":"gpt-5-nano","input":"hi","include":["message.output_text.logprobs"]}`, "include is not supported"},
		{"previous response", `{"model":"gpt-5-nano","input":"hi","previous_response_id":"resp_123"}`, "previous_response_id is not supported"},
		{"prompt cache retention", `{"model":"gpt-5-nano","input":"hi","prompt_cache_retention":"24h"}`, "prompt_cache_retention is not supported"},
		{"safety identifier", `{"model":"gpt-5-nano","input":"hi","safety_identifier":"user_123"}`, "safety_identifier is not supported"},
		{"stream options", `{"model":"gpt-5-nano","input":"hi","stream_options":{"include_usage":true}}`, "stream_options is not supported"},
		{"store", `{"model":"gpt-5-nano","input":"hi","store":true}`, "store is not supported"},
		{"user", `{"model":"gpt-5-nano","input":"hi","user":"user_123"}`, "user is not supported"},
		{"metadata non-string", `{"model":"gpt-5-nano","input":"hi","metadata":{"tenant":1}}`, "metadata values"},
		{"bad prompt cache key", `{"model":"gpt-5-nano","input":"hi","prompt_cache_key":"bad\nkey"}`, "prompt_cache_key"},
		{"bad text format", `{"model":"gpt-5-nano","input":"hi","text":{"format":{"type":"xml"}}}`, "text.format.type"},
		{"bad verbosity", `{"model":"gpt-5-nano","input":"hi","text":{"verbosity":"loud"}}`, "text.verbosity"},
		{"bad truncation", `{"model":"gpt-5-nano","input":"hi","truncation":"left"}`, "truncation"},
		{"max tool calls without tools", `{"model":"gpt-5-nano","input":"hi","max_tool_calls":2}`, "max_tool_calls requires supported tools"},
		{"parallel tools without tools", `{"model":"gpt-5-nano","input":"hi","parallel_tool_calls":true}`, "parallel_tool_calls requires supported tools"},
		{"tool choice without tools", `{"model":"gpt-5-nano","input":"hi","tool_choice":"auto"}`, "tool_choice requires supported tools"},
		{"unsupported tool", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"code_interpreter"}]}`, "Only function and priced hosted web search"},
		{"unsupported tool choice", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"code_interpreter"}}`, "tool_choice must select a supported tool"},
		{"image input", `{"model":"gpt-5-nano","input":[{"type":"input_image","image_url":"https://example.com/a.png"}]}`, "Only text input"},
		{"file id input", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}]}`, "Only text input"},
		{"hosted file input", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_file","file_url":"https://example.com/a.txt"}]}]}`, "Only text input"},
		{"inline file input", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]}]}`, "Only text input"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResolvedResponses(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestResponsesPolicyAllowsTextFunctionAndPricedWebSearch(t *testing.T) {
	for _, body := range []string{
		`{"model":"gpt-5-nano","input":"hi","stream":false,"instructions":"be brief","temperature":1,"top_p":1,"frequency_penalty":0,"presence_penalty":0,"text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object"},"strict":true},"verbosity":"medium"},"truncation":"auto","prompt_cache_key":"tenant-cache"}`,
		`{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"},"max_tool_calls":1,"parallel_tool_calls":false}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto","max_tool_calls":2}`,
	} {
		if err := validateResolvedResponses(t, body); err != nil {
			t.Fatalf("expected Responses request to pass: %v\nbody=%s", err, body)
		}
	}
}

func TestResponsesPolicySanitizesMetadataBeforeUpstream(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","metadata":{"tenant":"test"}}`),
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
	if bifrostReq.ResponsesRequest.Params.Metadata != nil {
		t.Fatalf("expected metadata to be sanitized before upstream, got %#v", bifrostReq.ResponsesRequest.Params.Metadata)
	}
}

func TestResponsesPolicyMaxToolCallsScalesWebSearchHold(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"max_tool_calls":3}`),
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
	found := false
	for _, meter := range state.Hold.Meters {
		if meter.MeterKey == openaiadapter.MeterOpenAIResponsesWebSearchPreviewCalls {
			found = true
			if meter.Quantity != "3" || !meter.HoldRequired {
				t.Fatalf("expected web search hold quantity 3, got %#v", meter)
			}
		}
	}
	if !found {
		t.Fatalf("expected web search preview hold meter in %#v", state.Hold.Meters)
	}
}

func TestResponsesIngestionTracksActualWebSearchCalls(t *testing.T) {
	numSearchQueries := 2
	state := &State{}
	resp := &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
	}}
	if err := (DefaultAdapter{}).IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	signals, ok := state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 2 {
		t.Fatalf("expected two web search calls from usage, got %#v", state.Signals)
	}

	webSearchType := schemas.ResponsesMessageTypeWebSearchCall
	state = &State{}
	resp = &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{
			{Type: &webSearchType},
			{Type: &webSearchType},
			{Type: schemas.Ptr(schemas.ResponsesMessageTypeMessage)},
		},
	}}
	if err := (DefaultAdapter{}).IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 2 {
		t.Fatalf("expected two web search calls from output items, got %#v", state.Signals)
	}

	state = &State{}
	if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
		},
	}); err != nil {
		t.Fatalf("IngestChunk returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 1 {
		t.Fatalf("expected one web search call from stream event, got %#v", state.Signals)
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

func validateResolvedResponses(t *testing.T, body string) error {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(body),
	})
	if err != nil {
		return err
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	return state.Adapter.ValidateRequest(state)
}
