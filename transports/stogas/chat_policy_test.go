package stogas

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
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
		{"local shell tool", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"local_shell"}]}`, "Only function and custom tools"},
		{"apply patch tool", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"apply_patch"}]}`, "Only function and custom tools"},
		{"tool choice string", `{"model":"gpt-5.5","messages":[],"tool_choice":"auto"}`, "tool_choice"},
		{"tool choice without tools", `{"model":"gpt-5.5","messages":[],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`, "tool_choice requires supported tools"},
		{"tool choice unknown function", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"function","function":{"name":"other"}}}`, "tool_choice selects an unknown function tool"},
		{"tool choice unknown custom", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"custom","name":"custom_tool"}],"tool_choice":{"type":"custom","name":"other"}}`, "tool_choice selects an unknown custom tool"},
		{"function tool missing name", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{}}]}`, "function tools require a name"},
		{"custom tool missing name", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"custom"}]}`, "custom tools require a name"},
		{"metadata non-string", `{"model":"gpt-5.5","messages":[],"metadata":{"a":1}}`, "metadata values"},
		{"anthropic-only cache control on openai", `{"model":"gpt-5.5","messages":[],"cache_control":{"type":"ephemeral"}}`, "only supported for Anthropic"},
		{"nested cache control on openai", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`, "cache_control is only supported for Anthropic"},
		{"prompt cache retention", `{"model":"gpt-5.5","messages":[],"prompt_cache_retention":"24h"}`, "prompt_cache_retention is not supported"},
		{"anthropic cache control bad ttl", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"cache_control":{"type":"ephemeral","ttl":"24h"}}`, "cache_control.ttl must be 5m or 1h"},
		{"anthropic cache control scope", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"cache_control":{"type":"ephemeral","scope":"global"}}`, "cache_control.scope is not supported"},
		{"anthropic cache control bad type", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"cache_control":{"type":"persisted","ttl":"1h"}}`, "cache_control.type must be ephemeral"},
		{"anthropic task budget", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"task_budget":{"type":"tokens","total":1000}}`, "task_budget is not supported"},
		{"anthropic context management", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"context_management":{"edits":[]}}`, "context_management is not supported"},
		{"conflicting reasoning alias", `{"model":"gpt-5.5","messages":[],"reasoning":{"effort":"minimal"},"reasoning_effort":"minimal"}`, "conflicts"},
		{"client user", `{"model":"gpt-5.5","messages":[],"user":"u"}`, "user is not supported"},
		{"client stream options", `{"model":"gpt-5.5","messages":[],"stream_options":{"include_usage":false}}`, "stream_options is not supported"},
		{"anthropic mcp servers", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"remote"}]}`, "mcp_servers is not supported"},
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
		"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],
		"cache_control":{"type":"ephemeral","ttl":"1h"},
		"tools":[{"type":"custom","name":"custom_tool","cache_control":{"type":"ephemeral"}}],
		"tool_choice":{"type":"custom","name":"custom_tool"}
	}`)
	if err != nil {
		t.Fatalf("expected Anthropic-specific chat request to pass, got %v", err)
	}
}

func TestChatPolicyAllowsDeclaredFunctionToolChoice(t *testing.T) {
	for _, body := range []string{
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`,
		`{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"custom","custom":{"name":"custom_tool"}}],"tool_choice":{"type":"custom","custom":{"name":"custom_tool"}}}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
		`{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
	} {
		if err := validateResolvedChat(t, body); err != nil {
			t.Fatalf("expected declared tool choice to pass, got %v\nbody=%s", err, body)
		}
	}
}

func TestChatPolicyRejectsUnsupportedCacheControlPositions(t *testing.T) {
	err := validateResolvedChat(t, `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","cache_control":{"type":"ephemeral"},"content":"hi"}]}`)
	if err == nil || !strings.Contains(err.Error(), "messages[].cache_control is not supported") {
		t.Fatalf("expected message-level cache_control rejection, got %v", err)
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

func TestAnthropicUSDeploymentSetsInferenceGeoInternally(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast-us-standard","messages":[{"role":"user","content":"hi"}]}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "claude-opus-4-8-fast-standard-only-us" || resolution.Deployment.RegionID != "us" {
		t.Fatalf("unexpected US deployment resolution: %#v", resolution.Deployment)
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
		t.Fatalf("expected fast US deployment to set speed, got %#v", bifrostReq.ChatRequest.Params.ExtraParams)
	}
	if got := bifrostReq.ChatRequest.Params.ExtraParams["inference_geo"]; got != "us" {
		t.Fatalf("expected US deployment to set inference_geo internally, got %#v", bifrostReq.ChatRequest.Params.ExtraParams)
	}
	if bifrostReq.ChatRequest.Params.ServiceTier == nil || *bifrostReq.ChatRequest.Params.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected US standard deployment to imply Bifrost default tier, got %#v", bifrostReq.ChatRequest.Params.ServiceTier)
	}
}

func TestAnthropicClientInferenceGeoIsRejected(t *testing.T) {
	err := validateResolvedChat(t, `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"inference_geo":"us"}`)
	if err == nil || !strings.Contains(err.Error(), "inference_geo is not supported") {
		t.Fatalf("expected client inference_geo to be rejected, got %v", err)
	}
}

func TestAnthropicOutboundServiceTierMapping(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want string
	}{
		{
			name: "chat auto",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`,
			want: "auto",
		},
		{
			name: "chat standard only",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8-standard","messages":[{"role":"user","content":"hi"}]}`,
			want: "standard_only",
		},
		{
			name: "responses auto",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_output_tokens":16}`,
			want: "auto",
		},
		{
			name: "responses standard only",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6-standard","input":"hi","max_output_tokens":16}`,
			want: "standard_only",
		},
	}

	for _, item := range cases {
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
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			bifrostReq, err := resolution.ToBifrost(bifrostCtx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}

			switch item.path {
			case "/v1/chat/completions":
				anthropicReq, err := anthropicprovider.ToAnthropicChatRequest(bifrostCtx, bifrostReq.ChatRequest)
				if err != nil {
					t.Fatalf("ToAnthropicChatRequest returned error: %v", err)
				}
				if anthropicReq.ServiceTier == nil || *anthropicReq.ServiceTier != item.want {
					t.Fatalf("expected Anthropic chat service_tier %q, got %#v", item.want, anthropicReq.ServiceTier)
				}
			case "/v1/responses":
				body, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(bifrostCtx, bifrostReq.ResponsesRequest, anthropicprovider.AnthropicRequestBuildConfig{
					Provider:    schemas.Anthropic,
					IsStreaming: bifrostReq.RequestType == schemas.ResponsesStreamRequest,
				})
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				var payload struct {
					ServiceTier string `json:"service_tier"`
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("failed to decode Anthropic Responses request body: %v\n%s", err, body)
				}
				if payload.ServiceTier != item.want {
					t.Fatalf("expected Anthropic Responses service_tier %q, got %q in %s", item.want, payload.ServiceTier, body)
				}
			}
		})
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

func TestSanitizeRequestForcesChatStreamUsage(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true}`),
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
	if bifrostReq.ChatRequest.Params.StreamOptions == nil ||
		bifrostReq.ChatRequest.Params.StreamOptions.IncludeUsage == nil ||
		!*bifrostReq.ChatRequest.Params.StreamOptions.IncludeUsage {
		t.Fatalf("expected chat stream include_usage to be forced before upstream, got %#v", bifrostReq.ChatRequest.Params.StreamOptions)
	}
}

func TestSanitizeRequestSetsUpstreamUserFromAPIKeyClaims(t *testing.T) {
	responsibleID := "019de516-b10f-786f-97f8-b95c71dfe1b6"
	claims := &billing.APIKeyClaims{ResponsibleID: responsibleID}
	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}]}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi"}`,
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
			state := NewState(resolution, "sk-test", claims, AdapterFor(resolution.Provider))
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
			switch item.path {
			case "/v1/chat/completions":
				if bifrostReq.ChatRequest.Params.User == nil || *bifrostReq.ChatRequest.Params.User != responsibleID {
					t.Fatalf("expected chat upstream user %q, got %#v", responsibleID, bifrostReq.ChatRequest.Params.User)
				}
			case "/v1/responses":
				if bifrostReq.ResponsesRequest.Params.User == nil || *bifrostReq.ResponsesRequest.Params.User != responsibleID {
					t.Fatalf("expected responses upstream user %q, got %#v", responsibleID, bifrostReq.ResponsesRequest.Params.User)
				}
			}
		})
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
		{"openai cache control", `{"model":"gpt-5-nano","input":"hi","cache_control":{"type":"ephemeral"}}`, "cache_control is only supported for Anthropic"},
		{"openai input cache control", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`, "cache_control is only supported for Anthropic"},
		{"anthropic cache control bad ttl", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"24h"}}`, "cache_control.ttl must be 5m or 1h"},
		{"anthropic cache control scope", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","scope":"global"}}`, "cache_control.scope is not supported"},
		{"anthropic message cache control unsupported", `{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","cache_control":{"type":"ephemeral"},"content":"hi"}]}`, "input[].cache_control is not supported"},
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
		{"max tool calls too large", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"max_tool_calls":129}`, "max_tool_calls is outside the supported range"},
		{"parallel tools without tools", `{"model":"gpt-5-nano","input":"hi","parallel_tool_calls":true}`, "parallel_tool_calls requires supported tools"},
		{"tool choice without tools", `{"model":"gpt-5-nano","input":"hi","tool_choice":"auto"}`, "tool_choice requires supported tools"},
		{"unsupported tool", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"code_interpreter"}]}`, "Only function, custom, local_shell"},
		{"anthropic local shell", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"local_shell"}]}`, "local_shell is only supported for OpenAI"},
		{"hosted tool without max tool calls", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}]}`, "max_tool_calls is required for priced hosted tools"},
		{"anthropic dynamic web search", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20260209","name":"web_search"}],"max_tool_calls":1}`, "Only Anthropic basic web_search_20250305"},
		{"anthropic canonical web search", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search","name":"web_search"}],"max_tool_calls":1}`, "Only Anthropic basic web_search_20250305"},
		{"anthropic web fetch", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_fetch_20260309","name":"web_fetch"}],"max_tool_calls":1}`, "Only function, custom"},
		{"anthropic code execution", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"code_execution_20250825","name":"code_execution"}],"max_tool_calls":1}`, "Only function, custom"},
		{"anthropic computer use", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"computer_20251124","name":"computer"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai web fetch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_fetch_20260309"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai code execution version", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"code_execution_20250825"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai malformed web search suffix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_latest"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai malformed web search partial date", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_202602"}],"max_tool_calls":1}`, "Only function, custom"},
		{"unsupported tool choice", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"code_interpreter"}}`, "tool_choice must select a supported tool"},
		{"hosted tool choice not declared", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"web_search_preview"},"max_tool_calls":1}`, "tool_choice selects an unknown web_search_preview tool"},
		{"allowed hosted tool choice not declared", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_preview"}]},"max_tool_calls":1}`, "tool_choice selects an unknown web_search_preview tool"},
		{"allowed tools web fetch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_fetch_20260309"}]},"max_tool_calls":1}`, "Only function, custom"},
		{"image input", `{"model":"gpt-5-nano","input":[{"type":"input_image","image_url":"https://example.com/a.png"}]}`, "Only text input"},
		{"file id input", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}]}`, "file_id inputs are not supported"},
		{"hosted file input", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_file","file_url":"https://example.com/a.txt"}]}]}`, "file_url inputs are not supported"},
		{"inline file input", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]}]}`, "file inputs are not supported"},
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
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"custom","name":"lookup"}],"tool_choice":{"type":"custom","name":"lookup"},"max_tool_calls":1}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"local_shell"}],"tool_choice":{"type":"local_shell"},"max_tool_calls":1}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_20260209"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_2026_01_01"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_20250311"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2026_01_01"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":{"type":"web_search_preview"},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_preview"}]},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto","max_tool_calls":128}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],"cache_control":{"type":"ephemeral","ttl":"1h"},"tools":[{"type":"function","name":"lookup","cache_control":{"type":"ephemeral"}}]}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}]}`,
	} {
		if err := validateResolvedResponses(t, body); err != nil {
			t.Fatalf("expected Responses request to pass: %v\nbody=%s", err, body)
		}
	}
}

func TestResponsesPolicyForwardsAnthropicCacheControl(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],
			"cache_control":{"type":"ephemeral","ttl":"1h"},
			"tools":[{"type":"function","name":"lookup","cache_control":{"type":"ephemeral"}}]
		}`),
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
	if bifrostReq.ResponsesRequest.Params.ExtraParams == nil || bifrostReq.ResponsesRequest.Params.ExtraParams["cache_control"] == nil {
		t.Fatalf("expected top-level cache_control to be forwarded through ExtraParams, got %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
	}
	if len(bifrostReq.ResponsesRequest.Input) != 1 ||
		bifrostReq.ResponsesRequest.Input[0].Content == nil ||
		len(bifrostReq.ResponsesRequest.Input[0].Content.ContentBlocks) != 1 ||
		bifrostReq.ResponsesRequest.Input[0].Content.ContentBlocks[0].CacheControl == nil {
		t.Fatalf("expected input content block cache_control to survive conversion, got %#v", bifrostReq.ResponsesRequest.Input)
	}
	if len(bifrostReq.ResponsesRequest.Params.Tools) != 1 || bifrostReq.ResponsesRequest.Params.Tools[0].CacheControl == nil {
		t.Fatalf("expected tool cache_control to survive conversion, got %#v", bifrostReq.ResponsesRequest.Params.Tools)
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

func TestOpenAIResponsesFinalHostedToolPriceIsCappedByMaxToolCalls(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"max_tool_calls":1}`),
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
	state.Signals = &StandardSignals{WebSearch: 3}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 3 {
		t.Fatalf("expected telemetry to retain three observed calls, got %d", calls)
	}
	searchMeter := findMeterEstimate(state.FinalMeters, openaiadapter.MeterOpenAIResponsesWebSearchPreviewCalls)
	if searchMeter == nil {
		t.Fatalf("expected final web search preview meter in %#v", state.FinalMeters)
	}
	if searchMeter.Quantity != "1" || searchMeter.HoldRequired {
		t.Fatalf("expected final billable web search quantity capped at 1, got %#v", searchMeter)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover capped final web search charge: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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

	numSearchQueries = 2
	state = &State{}
	resp = &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
		Output: []schemas.ResponsesMessage{
			{Type: &webSearchType},
			{Type: &webSearchType},
		},
	}}
	if err := (DefaultAdapter{}).IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse usage plus anonymous output returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 2 {
		t.Fatalf("expected usage count to avoid anonymous output double-counting, got %#v", state.Signals)
	}

	itemID := "ws_1"
	state = &State{}
	for _, eventType := range []schemas.ResponsesStreamResponseType{
		schemas.ResponsesStreamResponseTypeWebSearchCallInProgress,
		schemas.ResponsesStreamResponseTypeWebSearchCallSearching,
	} {
		if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
			BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
				Type:   eventType,
				ItemID: &itemID,
			},
		}); err != nil {
			t.Fatalf("IngestChunk non-billable search event returned error: %v", err)
		}
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected in-progress/searching events not to count as billable search calls, got %d", calls)
	}

	failedStatus := "failed"
	state = &State{}
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webSearchType, Status: &failedStatus}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse failed web search returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected failed output web search not to count as billable search call, got %d", calls)
	}

	completedStatus := "completed"
	state = &State{}
	if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeOutputItemDone,
			ItemID: &itemID,
			Item:   &schemas.ResponsesMessage{ID: &itemID, Type: &webSearchType, Status: &completedStatus},
		},
	}); err != nil {
		t.Fatalf("IngestChunk output item done returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 1 {
		t.Fatalf("expected completed output_item.done to count as one billable search call, got %d", calls)
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

	state = &State{}
	if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeOutputItemAdded,
			ItemID: &itemID,
			Item:   &schemas.ResponsesMessage{ID: &itemID, Type: &webSearchType},
		},
	}); err != nil {
		t.Fatalf("IngestChunk output item returned error: %v", err)
	}
	if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
			ItemID: &itemID,
		},
	}); err != nil {
		t.Fatalf("IngestChunk completed returned error: %v", err)
	}
	numSearchQueries = 1
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webSearchType}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse after stream returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 1 {
		t.Fatalf("expected stream/output/usage web search id to count once, got %#v", state.Signals)
	}

	state = &State{}
	for i := 0; i < 2; i++ {
		if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
			BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
				Type:   schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
				ItemID: &itemID,
			},
		}); err != nil {
			t.Fatalf("IngestChunk duplicate returned error: %v", err)
		}
	}
	resp = &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webSearchType}},
	}}
	if err := (DefaultAdapter{}).IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse duplicate returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 1 {
		t.Fatalf("expected duplicate stream/output web search id to count once, got %#v", state.Signals)
	}

	state = &State{}
	for i := 0; i < 2; i++ {
		if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
			BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
				SequenceNumber: 7,
			},
		}); err != nil {
			t.Fatalf("IngestChunk duplicate sequence returned error: %v", err)
		}
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 1 {
		t.Fatalf("expected duplicate stream sequence to count once, got %#v", state.Signals)
	}
}

func TestAnthropicResponsesWebSearchPricingUsesObservedCalls(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"max_tool_calls":3}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if !containsString(resolution.ToolTypes(), string(schemas.ResponsesToolTypeWebSearch)) {
		t.Fatalf("expected normalized web_search tool type, got %#v", resolution.ToolTypes())
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	foundHold := false
	for _, meter := range state.Hold.Meters {
		if meter.MeterKey == meterAnthropicWebSearchCalls {
			foundHold = true
			if meter.Quantity != "3" || !meter.HoldRequired {
				t.Fatalf("expected Anthropic web search hold quantity 3, got %#v", meter)
			}
		}
	}
	if !foundHold {
		t.Fatalf("expected Anthropic web search hold meter in %#v", state.Hold.Meters)
	}

	numSearchQueries := 2
	if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "20000000000000000" {
		t.Fatalf("expected Anthropic web search settlement for 2 calls, got %s", state.FinalCostUSDAtoms)
	}

	failedStatus := "failed"
	failedState := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := failedState.Adapter.IngestResponse(failedState, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{
			ID:     schemas.Ptr("ws_failed"),
			Type:   schemas.Ptr(schemas.ResponsesMessageTypeWebSearchCall),
			Status: &failedStatus,
		}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse failed Anthropic web search returned error: %v", err)
	}
	if err := failedState.Adapter.FinalPrice(failedState); err != nil {
		t.Fatalf("FinalPrice failed Anthropic web search returned error: %v", err)
	}
	if failedState.FinalCostUSDAtoms != billing.ZeroChargeUSDAtoms {
		t.Fatalf("expected failed Anthropic web search output not to settle a search charge, got %s", failedState.FinalCostUSDAtoms)
	}
}

func TestAnthropicResponsesWebSearchFinalPriceUsesActualExecutionDeployment(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"max_tool_calls":1,"max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	mutatedPricing := copyPricing(resolution.Deployment.Pricing)
	mutatedPricing[meterAnthropicWebSearchCalls] = map[string]string{
		billing.RatePerThousandCalls: "999000000000000000000",
	}
	resolution.Deployment.Pricing = mutatedPricing

	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	state.Signals = &StandardSignals{
		Prompt:      1000,
		Completion:  1000,
		ActualSpeed: "standard",
		WebSearch:   1,
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	searchMeter := findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls)
	if searchMeter == nil {
		t.Fatalf("expected final Anthropic web search meter in %#v", state.FinalMeters)
	}
	if searchMeter.AmountUSDAtoms != "10000000000000000" {
		t.Fatalf("expected actual-execution deployment search rate, got %#v", searchMeter)
	}
	if state.FinalCostUSDAtoms != "40000000000000000" {
		t.Fatalf("expected non-fast token pricing plus actual web search rate, got %s meters=%#v", state.FinalCostUSDAtoms, state.FinalMeters)
	}
}

func TestAnthropicResponsesFinalHostedToolPriceIsCappedByMaxToolCalls(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"max_tool_calls":1}`),
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
	state.Signals = &StandardSignals{WebSearch: 3}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 3 {
		t.Fatalf("expected telemetry to retain three observed calls, got %d", calls)
	}
	searchMeter := findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls)
	if searchMeter == nil {
		t.Fatalf("expected final Anthropic web search meter in %#v", state.FinalMeters)
	}
	if searchMeter.Quantity != "1" || searchMeter.HoldRequired {
		t.Fatalf("expected final billable Anthropic web search quantity capped at 1, got %#v", searchMeter)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover capped final Anthropic web search charge: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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

func findMeterEstimate(meters []catalog.MeterEstimate, key string) *catalog.MeterEstimate {
	for i := range meters {
		if meters[i].MeterKey == key {
			return &meters[i]
		}
	}
	return nil
}

func copyPricing(pricing catalog.Pricing) catalog.Pricing {
	copied := make(catalog.Pricing, len(pricing))
	for meterKey, rates := range pricing {
		rateCopy := make(map[string]string, len(rates))
		for rateKey, rate := range rates {
			rateCopy[rateKey] = rate
		}
		copied[meterKey] = rateCopy
	}
	return copied
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

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
