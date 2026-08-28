package stogas

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestChutesChatWireUsesVerifiedOpenAICompatibleFields(t *testing.T) {
	state := resolveChutesState(t, `{
		"model":"chutes/qwen3-32b",
		"provider":"chutes",
		"messages":[{"role":"system","content":"Be concise."},{"role":"user","content":"Reply with JSON."}],
		"metadata":{"tenant":"must-not-reach-provider"},
		"store":false,
		"max_completion_tokens":7,
		"temperature":3,
		"top_p":1.1,
		"top_k":0,
		"repetition_penalty":0,
		"frequency_penalty":-3,
		"presence_penalty":3,
		"seed":-1,
		"stop":"DONE",
		"response_format":{"type":"json_schema","json_schema":{"name":"answer","strict":true,"schema":{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false}}},
		"tools":[{"type":"function","function":{"name":"lookup","description":"Look up a value","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}}],
		"tool_choice":{"type":"function","function":{"name":"lookup"}}
	}`)

	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	if state.Resolution.OutputTokenLimit() != 7 {
		t.Fatalf("output token limit = %d, want 7", state.Resolution.OutputTokenLimit())
	}

	request, err := state.Resolution.ToBifrost(&schemas.BifrostContext{})
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if request.ChatRequest == nil || request.ChatRequest.Params == nil {
		t.Fatalf("expected chat request, got %#v", request)
	}
	if request.ChatRequest.Provider != catalog.ProviderChutes {
		t.Fatalf("provider = %q, want Chutes", request.ChatRequest.Provider)
	}
	if request.ChatRequest.Params.MaxCompletionTokens != nil {
		t.Fatalf("max_completion_tokens must not reach Chutes wire: %#v", request.ChatRequest.Params)
	}

	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	encoded, bifrostErr := prepareChutesChatBody(ctx, request.ChatRequest, false)
	if bifrostErr != nil {
		t.Fatalf("marshal Chutes wire request: %v", bifrostErr)
	}
	var body map[string]json.RawMessage
	if err := sonic.Unmarshal(encoded, &body); err != nil {
		t.Fatalf("decode Chutes wire request: %v", err)
	}
	assertRawNumber(t, body, "max_tokens", 7)
	assertRawNumber(t, body, "temperature", 3)
	assertRawNumber(t, body, "top_p", 1.1)
	assertRawNumber(t, body, "repetition_penalty", 0)
	assertRawNumber(t, body, "frequency_penalty", -3)
	assertRawNumber(t, body, "presence_penalty", 3)
	assertRawNumber(t, body, "seed", -1)
	assertRawNumber(t, body, "top_k", 0)
	var stops []string
	if err := sonic.Unmarshal(body["stop"], &stops); err != nil || len(stops) != 1 || stops[0] != "DONE" {
		t.Fatalf("stop = %s, want [DONE]", body["stop"])
	}
	for _, name := range []string{"max_completion_tokens", "metadata", "provider", "rules", "store"} {
		if _, exists := body[name]; exists {
			t.Fatalf("Chutes wire contains private or gateway-only field %q: %s", name, encoded)
		}
	}
	for _, name := range []string{"response_format", "tools", "tool_choice"} {
		if !rawJSONValueSet(body[name]) {
			t.Fatalf("Chutes wire omitted %s: %s", name, encoded)
		}
	}
}

func TestChutesRulesSelectTheProviderWithoutReachingItsWire(t *testing.T) {
	state := resolveChutesState(t, `{"model":"qwen3-32b","rules":{"only":["chutes"]},"messages":[{"role":"user","content":"hi"}]}`)
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	request, err := state.Resolution.ToBifrost(&schemas.BifrostContext{})
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	encoded, bifrostErr := prepareChutesChatBody(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), request.ChatRequest, false)
	if bifrostErr != nil {
		t.Fatalf("prepareChutesChatBody returned error: %v", bifrostErr)
	}
	var body map[string]json.RawMessage
	if err := sonic.Unmarshal(encoded, &body); err != nil {
		t.Fatalf("decode Chutes wire request: %v", err)
	}
	if _, exists := body["rules"]; exists {
		t.Fatalf("gateway routing rules reached Chutes wire: %s", encoded)
	}
}

func TestChutesChatWireStreamingForcesUsage(t *testing.T) {
	state := resolveChutesState(t, `{"model":"qwen3-32b","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	request, err := state.Resolution.ToBifrost(&schemas.BifrostContext{})
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	encoded, bifrostErr := prepareChutesChatBody(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), request.ChatRequest, true)
	if bifrostErr != nil {
		t.Fatalf("prepareChutesChatBody returned error: %v", bifrostErr)
	}
	var body struct {
		Stream        bool `json:"stream"`
		StreamOptions struct {
			IncludeUsage bool `json:"include_usage"`
		} `json:"stream_options"`
	}
	if err := sonic.Unmarshal(encoded, &body); err != nil {
		t.Fatalf("decode Chutes wire request: %v", err)
	}
	if !body.Stream || !body.StreamOptions.IncludeUsage {
		t.Fatalf("stream controls = %#v, want stream with usage\n%s", body, encoded)
	}
}

func TestChutesOmittedOutputLimitUsesObserved1024DefaultForWireAndHold(t *testing.T) {
	state := resolveChutesState(t, `{"model":"qwen3-32b","messages":[{"role":"user","content":"hi"}]}`)
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	if state.Resolution.OutputTokenLimit() != chutesDefaultOutputTokens {
		t.Fatalf("output token limit = %d, want %d", state.Resolution.OutputTokenLimit(), chutesDefaultOutputTokens)
	}
	wantInput := state.Resolution.Deployment.ContextWindowTokens - chutesDefaultOutputTokens
	if state.Resolution.InputTokenLimit() != wantInput {
		t.Fatalf("input token limit = %d, want %d", state.Resolution.InputTokenLimit(), wantInput)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	output := findMeterEstimate(state.Hold.Meters, billing.MeterOutputTokens)
	if output == nil || output.Quantity != "1024" || !output.HoldRequired {
		t.Fatalf("expected a 1024-token output hold, got %#v in %#v", output, state.Hold.Meters)
	}
	input := findMeterEstimate(state.Hold.Meters, billing.MeterInputTokens)
	if input == nil || input.Quantity != fmt.Sprintf("%d", wantInput) || !input.HoldRequired {
		t.Fatalf("expected a full remaining-context input hold, got %#v in %#v", input, state.Hold.Meters)
	}
}

func TestChutesNullOutputAliasesUseObservedDefault(t *testing.T) {
	for _, field := range []string{`"max_completion_tokens":null`, `"max_tokens":null`} {
		t.Run(field, func(t *testing.T) {
			state := resolveChutesState(t, chutesBody(field))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			if state.Resolution.OutputTokenLimit() != chutesDefaultOutputTokens {
				t.Fatalf("output token limit = %d, want %d", state.Resolution.OutputTokenLimit(), chutesDefaultOutputTokens)
			}
		})
	}
}

func TestChutesSamplingRangesAreProviderOwned(t *testing.T) {
	providerOwned := []string{
		`"temperature":0`,
		`"temperature":3`,
		`"temperature":-0.001`,
		`"top_p":0.0001`,
		`"top_p":1`,
		`"top_p":0`,
		`"top_p":1.001`,
		`"top_k":-1`,
		`"top_k":1`,
		`"top_k":0`,
		`"top_k":-2`,
		`"repetition_penalty":0.0001`,
		`"repetition_penalty":2`,
		`"repetition_penalty":1000000`,
		`"repetition_penalty":0`,
		`"seed":-9223372036854775808`,
		`"seed":9223372036854775807`,
		`"frequency_penalty":-2`,
		`"frequency_penalty":2`,
		`"frequency_penalty":-2.001`,
		`"frequency_penalty":2.001`,
		`"presence_penalty":-2`,
		`"presence_penalty":2`,
		`"presence_penalty":-2.001`,
		`"presence_penalty":2.001`,
	}
	for _, field := range providerOwned {
		t.Run("accept "+field, func(t *testing.T) {
			state := resolveChutesState(t, chutesBody(field))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("provider-owned Chutes parameter rejected: %v", err)
			}
		})
	}

	invalid := []string{
		`"max_completion_tokens":0`,
		`"max_tokens":0`,
		`"top_k":1.5`,
		`"seed":1.5`,
		`"seed":9223372036854775808`,
	}
	for _, field := range invalid {
		t.Run("reject "+field, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(chutesBody(field)),
			})
			if err != nil {
				return
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err == nil {
				t.Fatal("invalid Chutes bound was accepted")
			}
		})
	}
}

func TestChutesRejectsUnaccountedAndNonTextFeatures(t *testing.T) {
	cases := []string{
		`"cache_control":{"type":"ephemeral"}`,
		`"logprobs":true`,
		`"modalities":["text","audio"]`,
		`"n":2`,
		`"parallel_tool_calls":true`,
		`"prompt_cache_key":"tenant"`,
		`"service_tier":"priority"`,
		`"top_logprobs":1`,
		`"web_search_options":{}`,
	}
	for _, field := range cases {
		t.Run(field, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(chutesBody(field)),
			})
			if err != nil {
				return
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err == nil {
				t.Fatal("unsupported Chutes feature was accepted")
			}
		})
	}

	for _, content := range []string{
		`[{"type":"image_url","image_url":{"url":"https://example.com/image.png"}}]`,
		`[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]`,
	} {
		body := fmt.Sprintf(`{"model":"qwen3-32b","messages":[{"role":"user","content":%s}]}`, content)
		state := resolveChutesState(t, body)
		if err := state.Adapter.ValidateRequest(state); err == nil {
			t.Fatalf("non-text content was accepted: %s", content)
		}
	}
}

func TestChutesReasoningEffortsUseVerifiedWireMapping(t *testing.T) {
	tests := []struct {
		model        string
		requested    string
		wantEffort   string
		wantThinking bool
	}{
		{model: "qwen3-32b", requested: "none", wantThinking: false},
		{model: "qwen3-32b", requested: "low", wantThinking: true},
		{model: "qwen3-32b", requested: "high", wantThinking: true},
		{model: "qwen3.8-27b", requested: "none", wantThinking: false},
		{model: "qwen3.8-27b", requested: "low", wantEffort: "low", wantThinking: true},
		{model: "qwen3.8-27b", requested: "medium", wantEffort: "medium", wantThinking: true},
		{model: "qwen3.8-27b", requested: "xhigh", wantEffort: "xhigh", wantThinking: true},
		{model: "glm-5.2", requested: "none", wantEffort: "none", wantThinking: false},
		{model: "glm-5.2", requested: "high", wantEffort: "high", wantThinking: true},
		{model: "glm-5.2", requested: "max", wantEffort: "max", wantThinking: true},
		{model: "glm-5.2", requested: "xhigh", wantEffort: "max", wantThinking: true},
		{model: "deepseek-v4-flash-0731", requested: "max", wantEffort: "max", wantThinking: true},
		{model: "kimi-k3", requested: "low", wantEffort: "low", wantThinking: true},
		{model: "kimi-k3", requested: "minimal", wantEffort: "low", wantThinking: true},
		{model: "kimi-k3", requested: "max", wantEffort: "max", wantThinking: true},
		{model: "nemotron-3-nano-omni-30b", requested: "none", wantThinking: false},
		{model: "nemotron-3-nano-omni-30b", requested: "high", wantThinking: true},
	}
	for _, test := range tests {
		t.Run(test.model+"/"+test.requested, func(t *testing.T) {
			state := resolveChutesState(t, fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}],"reasoning":{"effort":%q}}`, test.model, test.requested))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			request, err := state.Resolution.ToBifrost(&schemas.BifrostContext{})
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			encoded, bifrostErr := prepareChutesChatBody(
				schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
				request.ChatRequest,
				false,
			)
			if bifrostErr != nil {
				t.Fatalf("prepareChutesChatBody returned error: %v", bifrostErr)
			}
			var body map[string]json.RawMessage
			if err := sonic.Unmarshal(encoded, &body); err != nil {
				t.Fatalf("decode Chutes wire request: %v", err)
			}
			if got := rawString(body["reasoning_effort"]); got != test.wantEffort {
				t.Fatalf("wire reasoning_effort = %q, want %q\n%s", got, test.wantEffort, encoded)
			}
			var template map[string]bool
			if err := sonic.Unmarshal(body["chat_template_kwargs"], &template); err != nil {
				t.Fatalf("decode chat_template_kwargs: %v\n%s", err, encoded)
			}
			if template["thinking"] != test.wantThinking || template["enable_thinking"] != test.wantThinking {
				t.Fatalf("wire thinking controls = %#v, want %t\n%s", template, test.wantThinking, encoded)
			}
			if _, exists := body["reasoning"]; exists {
				t.Fatalf("neutral reasoning object reached Chutes wire: %s", encoded)
			}
		})
	}
}

func TestChutesReasoningPolicyRejectsUnreviewedControls(t *testing.T) {
	for _, field := range []string{
		`"reasoning":{"max_tokens":100}`,
		`"reasoning_display":"summarized"`,
		`"reasoning_max_tokens":100`,
	} {
		t.Run(field, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(chutesBodyForModel("glm-5.2", field)),
			})
			if err != nil {
				return
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err == nil {
				t.Fatal("unsupported Chutes reasoning control was accepted")
			}
		})
	}

	_, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(chutesBodyForModel("mistral-nemo-instruct-2407", `"reasoning_effort":"high"`)),
	})
	if err == nil {
		t.Fatal("reasoning effort was accepted for a Chutes deployment that does not advertise it")
	}

	_, err = catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(chutesBodyForModel("kimi-k3", `"reasoning_effort":"none"`)),
	})
	if err == nil {
		t.Fatal("explicit reasoning disablement was accepted for always-reasoning Kimi K3")
	}

}

func TestChutesBinaryReasoningEnabledControl(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		state := resolveChutesState(t, chutesBodyForModel("qwen3-32b", fmt.Sprintf(`"reasoning":{"enabled":%t}`, enabled)))
		if err := state.Adapter.ValidateRequest(state); err != nil {
			t.Fatalf("ValidateRequest enabled=%t: %v", enabled, err)
		}
		if err := state.Adapter.SanitizeRequest(state); err != nil {
			t.Fatalf("SanitizeRequest enabled=%t: %v", enabled, err)
		}
		request, err := state.Resolution.ToBifrost(&schemas.BifrostContext{})
		if err != nil {
			t.Fatal(err)
		}
		encoded, bifrostErr := prepareChutesChatBody(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), request.ChatRequest, false)
		if bifrostErr != nil {
			t.Fatal(bifrostErr)
		}
		var body struct {
			ChatTemplateKwargs map[string]bool `json:"chat_template_kwargs"`
		}
		if err := sonic.Unmarshal(encoded, &body); err != nil {
			t.Fatal(err)
		}
		if body.ChatTemplateKwargs["thinking"] != enabled || body.ChatTemplateKwargs["enable_thinking"] != enabled {
			t.Fatalf("binary reasoning enabled=%t produced %#v", enabled, body.ChatTemplateKwargs)
		}
	}
}

func TestQwen38OnlyAcceptsExplicitReasoningEnablement(t *testing.T) {
	state := resolveChutesState(t, chutesBodyForModel("qwen3.8-27b", `"reasoning":{"enabled":true}`))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err == nil {
		t.Fatal("binary reasoning enablement was accepted without selecting a Qwen3.8 effort")
	}

	state = resolveChutesState(t, chutesBodyForModel("qwen3.8-27b", `"reasoning":{"enabled":true,"effort":"low"}`))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error for explicit effort: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("explicit Qwen3.8 effort returned error: %v", err)
	}

	state = resolveChutesState(t, chutesBodyForModel("qwen3.8-27b", `"reasoning":{"enabled":false}`))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("explicit reasoning disablement returned error: %v", err)
	}
}

func TestChutesFieldPolicyIsClosedOverTheSharedChatSurface(t *testing.T) {
	unsupportedValues := map[string]string{
		"audio":                      `{"format":"wav","voice":"alloy"}`,
		"cache_control":              `{"type":"ephemeral"}`,
		"container":                  `"container_123"`,
		"context_management":         `{"edits":[{"type":"compact_20260112"}]}`,
		"fallbacks":                  `["openai/gpt-5-nano"]`,
		"function_call":              `"auto"`,
		"functions":                  `[{"name":"lookup","parameters":{"type":"object"}}]`,
		"logit_bias":                 `{"42":1}`,
		"logprobs":                   `true`,
		"modalities":                 `["text"]`,
		"n":                          `2`,
		"parallel_tool_calls":        `true`,
		"prediction":                 `{"type":"content","content":"hello"}`,
		"prompt_cache_isolation_key": `"tenant-a"`,
		"prompt_cache_key":           `"tenant-a"`,
		"prompt_cache_options":       `{"type":"ephemeral"}`,
		"prompt_cache_retention":     `"24h"`,
		"reasoning_display":          `"summarized"`,
		"reasoning_max_tokens":       `1024`,
		"service_tier":               `"priority"`,
		"stop_sequences":             `["DONE"]`,
		"task_budget":                `{"type":"tokens","total":20000}`,
		"top_logprobs":               `1`,
		"verbosity":                  `"high"`,
		"web_search_options":         `{}`,
	}
	for field := range catalog.KnownFields(catalog.RouteChat) {
		if chutesAllowedChatFields[field] {
			continue
		}
		value, covered := unsupportedValues[field]
		if !covered {
			t.Fatalf("shared field %q has no Chutes policy fixture", field)
		}
		t.Run(field, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(chutesBody(fmt.Sprintf("%q:%s", field, value))),
			})
			if err != nil {
				return
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err == nil {
				t.Fatalf("shared field %q bypassed the closed Chutes policy", field)
			}
		})
	}
}

func TestChutesModelCapabilitiesGateStructuredOutput(t *testing.T) {
	state := resolveChutesState(t, `{"model":"mistral-nemo-instruct-2407","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_object"}}`)
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("Mistral structured output was rejected: %v", err)
	}
	state.Resolution.Deployment.Capabilities.StructuredOutputs = false
	if err := state.Adapter.ValidateRequest(state); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("deployment without structured output was accepted: %v", err)
	}

	state = resolveChutesState(t, `{"model":"mistral-nemo-instruct-2407","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`)
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("Mistral function tool was rejected: %v", err)
	}
}

func TestEveryChutesDeploymentHoldCoversMaximumReportedUsage(t *testing.T) {
	models := []string{
		"qwen3-32b",
		"qwen3.5-397b-a17b",
		"gemma-4-31b",
		"glm-5.1",
		"deepseek-v3.2",
		"glm-5.2",
		"qwen3.6-27b",
		"kimi-k2.6",
		"mistral-nemo-instruct-2407",
		"kimi-k3",
		"nemotron-3-nano-omni-30b",
		"deepseek-v4-flash-0731",
	}
	for _, model := range models {
		for _, limit := range []struct {
			name  string
			field string
		}{
			{name: "provider default"},
			{name: "explicit limit", field: `,"max_tokens":32`},
		} {
			t.Run(model+"/"+limit.name, func(t *testing.T) {
				state := resolveChutesState(t, fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hold coverage"}]%s}`, model, limit.field))
				if err := state.Adapter.ValidateRequest(state); err != nil {
					t.Fatalf("ValidateRequest returned error: %v", err)
				}
				if err := state.Adapter.SanitizeRequest(state); err != nil {
					t.Fatalf("SanitizeRequest returned error: %v", err)
				}
				if err := state.Adapter.EstimateHold(state); err != nil {
					t.Fatalf("EstimateHold returned error: %v", err)
				}
				input := state.Resolution.InputTokenLimit()
				output := state.Resolution.OutputTokenLimit()
				state.Signals = &StandardSignals{
					Cached:     input / 2,
					Completion: output,
					Prompt:     input,
					Reasoning:  output,
				}
				if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
					t.Fatalf("CalculateUpstreamCost returned error: %v", err)
				}
				if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
					t.Fatalf("hold under-reserved Chutes usage: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
				}
			})
		}
	}
}

func TestChutesTopLevelReasoningUsageIsAccounted(t *testing.T) {
	var usage schemas.BifrostLLMUsage
	if err := sonic.UnmarshalString(`{"prompt_tokens":5,"completion_tokens":10,"total_tokens":15,"reasoning_tokens":7}`, &usage); err != nil {
		t.Fatalf("decode Chutes usage: %v", err)
	}
	signals := signalsFromUsage(&usage)
	if signals == nil || signals.Prompt != 5 || signals.Completion != 10 || signals.Reasoning != 7 {
		t.Fatalf("top-level Chutes usage was not normalized: %#v", signals)
	}

	signals = signalsFromUsage(&schemas.BifrostLLMUsage{
		CompletionTokens: 10,
		ReasoningTokens:  7,
		CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
			ReasoningTokens: 3,
		},
	})
	if signals == nil || signals.Reasoning != 3 {
		t.Fatalf("standard nested reasoning usage must take precedence: %#v", signals)
	}
}

func resolveChutesState(t *testing.T, body string) *State {
	t.Helper()
	var request map[string]json.RawMessage
	if err := sonic.Unmarshal([]byte(body), &request); err != nil {
		t.Fatalf("decode Chutes test request: %v", err)
	}
	model := rawString(request["model"])
	if model != "" && !strings.Contains(model, "/") {
		encodedModel, err := sonic.Marshal("chutes/" + model)
		if err != nil {
			t.Fatalf("encode Chutes-qualified model: %v", err)
		}
		request["model"] = encodedModel
		encodedRequest, err := sonic.Marshal(request)
		if err != nil {
			t.Fatalf("encode Chutes test request: %v", err)
		}
		body = string(encodedRequest)
	}
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(body),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Provider != catalog.ProviderChutes {
		t.Fatalf("resolved provider = %q, want Chutes", resolution.Provider)
	}
	return NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
}

func chutesBody(field string) string {
	return chutesBodyForModel("qwen3-32b", field)
}

func chutesBodyForModel(model string, field string) string {
	return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}],%s}`, model, field)
}

func assertRawNumber(t *testing.T, body map[string]json.RawMessage, name string, want float64) {
	t.Helper()
	var got float64
	if err := sonic.Unmarshal(body[name], &got); err != nil || got != want {
		t.Fatalf("%s = %s, want %v", name, body[name], want)
	}
}
