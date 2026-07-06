package stogas

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestChatPolicyRejectsUnsupportedFields(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"audio", `{"model":"gpt-5.5","messages":[],"audio":{}}`, "audio is not supported"},
		{"message audio", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","audio":{"data":"abc"}}]}`, "Only text message content"},
		{"message file id", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","file_id":"file_123"}]}`, "file_id inputs are not supported"},
		{"message file url", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","file_url":"https://example.com/a.pdf"}]}`, "file_url inputs are not supported"},
		{"message file data", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","file_data":"data:text/plain;base64,aGk="}]}`, "file inputs are not supported"},
		{"message image url", `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi","image_url":"https://example.com/x.png"}]}`, "Only text message content"},
		{"image content block", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/x.png"}}]}]}`, "Only text message content"},
		{"input file content block", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]}]}`, "file inputs are not supported"},
		{"text block file id", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","file_id":"file_123"}]}]}`, "file_id inputs are not supported"},
		{"text block file url", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","file_url":"https://example.com/a.pdf"}]}]}`, "file_url inputs are not supported"},
		{"text block file data", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","file_data":"data:text/plain;base64,aGk="}]}]}`, "file inputs are not supported"},
		{"text block file object", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","file":{"file_data":"data:text/plain;base64,aGk="}}]}]}`, "file inputs are not supported"},
		{"text block image url", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","image_url":{"url":"https://example.com/x.png"}}]}]}`, "Only text message content"},
		{"text block input image", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","input_image":{"image_url":"https://example.com/x.png"}}]}]}`, "Only text message content"},
		{"text block input audio", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","input_audio":{"data":"abc","format":"mp3"}}]}]}`, "Only text message content"},
		{"modalities", `{"model":"gpt-5.5","messages":[],"modalities":["text","audio"]}`, "modalities"},
		{"n", `{"model":"gpt-5.5","messages":[],"n":2}`, "n must be 1"},
		{"hosted tool", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"web_search"}]}`, "Only function and custom tools"},
		{"local shell tool", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"local_shell"}]}`, "Only function and custom tools"},
		{"apply patch tool", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"apply_patch"}]}`, "Only function and custom tools"},
		{"fallbacks", `{"model":"gpt-5.5","messages":[],"fallbacks":["gpt-5.5-flex"]}`, "Fallbacks are not supported"},
		{"tool choice any string", `{"model":"gpt-5.5","messages":[],"tool_choice":"any"}`, "tool_choice must be auto, none, required"},
		{"tool choice required without tools", `{"model":"gpt-5.5","messages":[],"tool_choice":"required"}`, "tool_choice requires supported tools"},
		{"tool choice without tools", `{"model":"gpt-5.5","messages":[],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`, "tool_choice requires supported tools"},
		{"tool choice unknown function", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"function","function":{"name":"other"}}}`, "tool_choice selects an unknown function tool"},
		{"tool choice unknown custom", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"custom","name":"custom_tool"}],"tool_choice":{"type":"custom","name":"other"}}`, "tool_choice selects an unknown custom tool"},
		{"function tool missing name", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{}}]}`, "function tools require a name"},
		{"custom tool missing name", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"custom"}]}`, "custom tools require a name"},
		{"anthropic hosted tool", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"web_search"}]}`, "Only function and mcp_toolset tools"},
		{"anthropic custom tool", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"custom","name":"custom_tool"}]}`, "custom tools are only supported for OpenAI Chat deployments"},
		{"anthropic custom tool choice", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"custom","name":"custom_tool"}}`, "custom tool_choice is only supported for OpenAI Chat deployments"},
		{"metadata non-string", `{"model":"gpt-5.5","messages":[],"metadata":{"a":1}}`, "metadata values"},
		{"anthropic-only cache control on openai", `{"model":"gpt-5.5","messages":[],"cache_control":{"type":"ephemeral"}}`, "only supported for Anthropic"},
		{"nested cache control on openai", `{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`, "cache_control is only supported for Anthropic"},
		{"prompt cache retention anthropic", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"prompt_cache_retention":"24h"}`, "prompt_cache_retention is only supported for OpenAI"},
		{"anthropic cache control bad ttl", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"cache_control":{"type":"ephemeral","ttl":"24h"}}`, "cache_control.ttl must be 5m or 1h"},
		{"anthropic cache control bad type", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"cache_control":{"type":"persisted","ttl":"1h"}}`, "cache_control.type must be ephemeral"},
		{"openai task budget", `{"model":"gpt-5.5","messages":[],"task_budget":{"type":"tokens","total":20000}}`, "task_budget is only supported for Anthropic"},
		{"openai context management", `{"model":"gpt-5.5","messages":[],"context_management":{"edits":[{"type":"compact_20260112"}]}}`, "context_management is only supported for Anthropic"},
		{"anthropic frequency penalty", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"frequency_penalty":0.1}`, "frequency_penalty is only supported for OpenAI"},
		{"anthropic logit bias", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"logit_bias":{"123":1}}`, "logit_bias is only supported for OpenAI"},
		{"anthropic logprobs", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"logprobs":true}`, "logprobs is only supported for OpenAI"},
		{"anthropic prediction", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"prediction":{"type":"content","content":"hi"}}`, "prediction is only supported for OpenAI"},
		{"anthropic presence penalty", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"presence_penalty":0.1}`, "presence_penalty is only supported for OpenAI"},
		{"anthropic temperature top p conflict", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"temperature":0.7,"top_p":0.9}`, "temperature and top_p together"},
		{"anthropic prompt cache key", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"prompt_cache_key":"tenant-a"}`, "prompt_cache_key is only supported for OpenAI"},
		{"prompt cache isolation key", `{"model":"gpt-5.5","messages":[],"prompt_cache_isolation_key":"tenant-a"}`, "prompt_cache_isolation_key is not supported"},
		{"anthropic seed", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"seed":1}`, "seed is only supported for OpenAI"},
		{"anthropic top logprobs", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"top_logprobs":1}`, "top_logprobs is only supported for OpenAI"},
		{"anthropic verbosity", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"verbosity":"medium"}`, "verbosity is only supported for OpenAI"},
		{"anthropic web search options", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"web_search_options":{"search_context_size":"low"}}`, "web_search_options is only supported for OpenAI"},
		{"top k openai", `{"model":"gpt-5.5","messages":[],"top_k":40}`, "top_k is only supported for Anthropic"},
		{"stop sequences openai", `{"model":"gpt-5.5","messages":[],"stop_sequences":["END"]}`, "stop_sequences is only supported for Anthropic"},
		{"anthropic stop conflicts with stop sequences", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"stop":["DONE"],"stop_sequences":["END"]}`, "stop conflicts with stop_sequences"},
		{"conflicting reasoning alias", `{"model":"gpt-5.5","messages":[],"reasoning":{"effort":"minimal"},"reasoning_effort":"minimal"}`, "conflicts"},
		{"bad reasoning object", `{"model":"gpt-5.5","messages":[],"reasoning":"low"}`, "reasoning must be an object"},
		{"bad reasoning max tokens", `{"model":"gpt-5.5","messages":[],"reasoning_max_tokens":0}`, "reasoning_max_tokens is outside the supported range"},
		{"bad nested reasoning max tokens", `{"model":"gpt-5.5","messages":[],"reasoning":{"max_tokens":"many"}}`, "reasoning.max_tokens must be an integer"},
		{"bad reasoning enabled", `{"model":"gpt-5.5","messages":[],"reasoning":{"enabled":"yes"}}`, "reasoning.enabled must be a boolean"},
		{"chat reasoning summary", `{"model":"gpt-5.5","messages":[],"reasoning":{"summary":"auto"}}`, "reasoning.summary is not supported"},
		{"unknown reasoning field", `{"model":"gpt-5.5","messages":[],"reasoning":{"effort":"low","unknown":true}}`, "reasoning.unknown is not supported"},
		{"client user", `{"model":"gpt-5.5","messages":[],"user":"u"}`, "user is not supported"},
		{"client safety identifier", `{"model":"gpt-5.5","messages":[],"safety_identifier":"user_123"}`, "safety_identifier is not supported"},
		{"anthropic parallel tool calls", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"function","function":{"name":"lookup"}}],"parallel_tool_calls":false}`, "parallel_tool_calls is not supported for Anthropic"},
		{"stream options without stream", `{"model":"gpt-5.5","messages":[],"stream_options":{"include_usage":false}}`, "stream_options requires stream=true"},
		{"stream options unknown key", `{"model":"gpt-5.5","messages":[],"stream":true,"stream_options":{"unknown":true}}`, "stream_options.unknown is not supported"},
		{"chat stream obfuscation", `{"model":"gpt-5.5","messages":[],"stream":true,"stream_options":{"include_obfuscation":true}}`, "stream_options.include_obfuscation is not supported for Chat Completions"},
		{"openai mcp servers", `{"model":"gpt-5.5","messages":[],"mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"remote"}]}`, "mcp_servers is only supported for Anthropic"},
		{"anthropic mcp without toolset", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"remote"}]}`, "mcp_servers must match mcp_toolset tools one-to-one"},
		{"anthropic mcp toolset without server", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote"}]}`, "mcp_toolset tools require matching mcp_servers"},
		{"openai mcp toolset", `{"model":"gpt-5.5","messages":[],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote"}]}`, "mcp_toolset tools are only supported for Anthropic"},
		{"anthropic mcp http url", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"mcp_servers":[{"type":"url","url":"http://example.com/mcp","name":"remote"}],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote"}]}`, "mcp_servers[].url must be an HTTPS URL"},
		{"anthropic mcp duplicate server", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"mcp_servers":[{"type":"url","url":"https://example.com/a","name":"remote"},{"type":"url","url":"https://example.com/b","name":"remote"}],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote"}]}`, "mcp_servers names must be unique"},
		{"anthropic mcp bad token", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"remote","authorization_token":"bad\nsecret"}],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote"}]}`, "authorization_token must be a non-empty string"},
		{"anthropic mcp unsupported server field", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"remote","headers":{}}],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote"}]}`, "mcp_servers[].headers is not supported"},
		{"anthropic mcp unsupported toolset field", `{"model":"anthropic/claude-sonnet-4-6","messages":[],"mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"remote"}],"tools":[{"type":"mcp_toolset","mcp_server_name":"remote","allowed_tools":["search"]}]}`, "mcp_toolset.allowed_tools is not supported"},
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

func TestProviderOwnedScalarValidatorsCheckShapeOnly(t *testing.T) {
	if err := validateNumber(rawJSON(t, `{"temperature":"hot"}`), "temperature"); err == nil || !strings.Contains(err.Error(), "temperature must be a number") {
		t.Fatalf("expected temperature shape error, got %v", err)
	}
	if err := validateInteger(rawJSON(t, `{"top_logprobs":"many"}`), "top_logprobs"); err == nil || !strings.Contains(err.Error(), "top_logprobs must be an integer") {
		t.Fatalf("expected top_logprobs shape error, got %v", err)
	}
	if err := validateNumber(rawJSON(t, `{"temperature":999}`), "temperature"); err != nil {
		t.Fatalf("provider-owned numeric bounds should not reject in Stogas: %v", err)
	}
	if err := validateInteger(rawJSON(t, `{"top_logprobs":999}`), "top_logprobs"); err != nil {
		t.Fatalf("provider-owned integer bounds should not reject in Stogas: %v", err)
	}
	if err := validateResolvedChat(t, `{"model":"gpt-5.5","messages":[],"reasoning_display":"future-display","stop":["","","a","b","c","d","e"]}`); err != nil {
		t.Fatalf("provider-owned chat enum/list details should not reject in Stogas: %v", err)
	}
}

func TestChatPolicyAllowsAnthropicSpecificFieldsForAnthropicDeployments(t *testing.T) {
	err := validateResolvedChat(t, `{
		"model":"anthropic/claude-sonnet-4-6",
		"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],
		"cache_control":{"type":"ephemeral","ttl":"1h"},
		"top_p":0.9,
		"top_k":40,
		"stop_sequences":["END"],
		"task_budget":{"type":"future-budget","future_provider_owned_shape":{"any":true}},
		"context_management":{"edits":[{"type":"future-edit","provider_owned_settings":{"any":true}}]},
		"mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"remote","authorization_token":"secret"}],
		"tools":[
			{"type":"function","function":{"name":"lookup"},"cache_control":{"type":"ephemeral"}},
			{"type":"mcp_toolset","mcp_server_name":"remote","default_config":{"enabled":true},"configs":{"search":{"defer_loading":false}}}
		],
		"tool_choice":"required"
	}`)
	if err != nil {
		t.Fatalf("expected Anthropic-specific chat request to pass, got %v", err)
	}
}

func TestChatPolicyAllowsDeclaredFunctionToolChoice(t *testing.T) {
	for _, body := range []string{
		`{"model":"gpt-5.5","messages":[],"tool_choice":"auto"}`,
		`{"model":"gpt-5.5","messages":[],"tool_choice":"none"}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":"required"}`,
		`{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":"required"}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{"name":"lookup"}}],"parallel_tool_calls":false,"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"custom","custom":{"name":"custom_tool"}}],"tool_choice":{"type":"custom","custom":{"name":"custom_tool"}}}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
		`{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`,
	} {
		if err := validateResolvedChat(t, body); err != nil {
			t.Fatalf("expected declared tool choice to pass, got %v\nbody=%s", err, body)
		}
	}
}

func TestChatStopStringShorthandNormalizesToBifrostStopArray(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stop":"END"}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	bifrostReq, err := resolution.ToBifrost(bifrostCtx)
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if got := bifrostReq.ChatRequest.Params.Stop; len(got) != 1 || got[0] != "END" {
		t.Fatalf("expected stop string shorthand to normalize to [END], got %#v", got)
	}
}

func TestChatResponseFormatReachesProviderWireRequest(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "openai json schema",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object","properties":{"ok":{"type":"boolean"}}},"strict":true}}}`,
		},
		{
			name: "anthropic json schema",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(tc.body),
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
			switch resolution.Provider {
			case schemas.OpenAI:
				wire := openaiprovider.ToOpenAIChatRequest(bifrostCtx, bifrostReq.ChatRequest)
				wireBytes, err := json.Marshal(wire)
				if err != nil {
					t.Fatalf("marshal OpenAI chat request: %v", err)
				}
				if !strings.Contains(string(wireBytes), `"response_format"`) || !strings.Contains(string(wireBytes), `"strict":true`) {
					t.Fatalf("expected OpenAI chat response_format to reach wire request, got %s", wireBytes)
				}
			case schemas.Anthropic:
				wire, err := anthropicprovider.ToAnthropicChatRequest(bifrostCtx, bifrostReq.ChatRequest)
				if err != nil {
					t.Fatalf("ToAnthropicChatRequest returned error: %v", err)
				}
				if len(wire.Tools) != 0 {
					t.Fatalf("expected direct Anthropic structured output to avoid tool emulation, got %#v", wire.Tools)
				}
				if wire.OutputConfig == nil || len(wire.OutputConfig.Format) == 0 {
					t.Fatalf("expected Anthropic output_config.format, got %#v", wire.OutputConfig)
				}
				var outputFormat map[string]any
				if err := json.Unmarshal(wire.OutputConfig.Format, &outputFormat); err != nil {
					t.Fatalf("decode Anthropic output_config.format: %v", err)
				}
				if outputFormat["type"] != "json_schema" || outputFormat["schema"] == nil {
					t.Fatalf("unexpected Anthropic output_config.format %#v", outputFormat)
				}
				if _, hasStrict := outputFormat["strict"]; hasStrict {
					t.Fatalf("Anthropic output_config.format must not contain unsupported strict flag: %#v", outputFormat)
				}
			}
		})
	}
}

func TestChatPolicyRejectsUnsupportedCacheControlPositions(t *testing.T) {
	err := validateResolvedChat(t, `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","cache_control":{"type":"ephemeral"},"content":"hi"}]}`)
	if err == nil || !strings.Contains(err.Error(), "messages[].cache_control is not supported") {
		t.Fatalf("expected message-level cache_control rejection, got %v", err)
	}
}

func TestAnthropicCacheControlAllowsProviderOwnedFutureKeys(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"1h","scope":"future-provider-owned"},"max_completion_tokens":16}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"1h","scope":"future-provider-owned"},"max_output_tokens":16}`,
		},
	}

	for _, tc := range cases {
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
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			if findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens) == nil {
				t.Fatalf("expected ttl=1h to reserve 1h cache write despite provider-owned future keys, got %#v", state.Hold.Meters)
			}
		})
	}
}

func TestAnthropicCachePrewarmAllowsZeroOutputTokens(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat top-level cache_control",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"5m"},"max_completion_tokens":0}`,
		},
		{
			name: "chat content cache_control max_tokens alias",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],"max_tokens":0}`,
		},
		{
			name: "responses top-level cache_control",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"5m"},"max_output_tokens":0}`,
		},
		{
			name: "responses input cache_control",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],"max_output_tokens":0}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			if resolution.OutputTokenLimit() != 0 {
				t.Fatalf("expected cache-prewarm output limit 0, got %d", resolution.OutputTokenLimit())
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch tc.path {
			case "/v1/chat/completions":
				if bifrostReq.ChatRequest == nil || bifrostReq.ChatRequest.Params == nil || bifrostReq.ChatRequest.Params.MaxCompletionTokens == nil || *bifrostReq.ChatRequest.Params.MaxCompletionTokens != 0 {
					t.Fatalf("expected Bifrost chat max_completion_tokens=0, got %#v", bifrostReq.ChatRequest)
				}
			case "/v1/responses":
				if bifrostReq.ResponsesRequest == nil || bifrostReq.ResponsesRequest.Params == nil || bifrostReq.ResponsesRequest.Params.MaxOutputTokens == nil || *bifrostReq.ResponsesRequest.Params.MaxOutputTokens != 0 {
					t.Fatalf("expected Bifrost responses max_output_tokens=0, got %#v", bifrostReq.ResponsesRequest)
				}
			}
		})
	}
}

func TestZeroOutputTokensRequireAllowedAnthropicCacheControl(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat no cache_control",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":0}`,
		},
		{
			name: "chat schema property named cache_control",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}}],"max_completion_tokens":0}`,
		},
		{
			name: "responses no cache_control",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_output_tokens":0}`,
		},
		{
			name: "responses schema property named cache_control",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}],"max_output_tokens":0}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   tc.path,
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error before adapter validation: %v", err)
			}
			if resolution.OutputTokenLimit() != 0 {
				t.Fatalf("expected catalog to preserve zero output cap, got %d", resolution.OutputTokenLimit())
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			err = state.Adapter.ValidateRequest(state)
			if err == nil || !strings.Contains(err.Error(), "Parameter exceeds catalog limit") {
				t.Fatalf("expected zero output cap rejection, got %v", err)
			}
		})
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
	if got := bifrostReq.ChatRequest.Params.Speed; got == nil || *got != "fast" {
		t.Fatalf("expected fast deployment to set typed speed, got %#v", got)
	}
	if bifrostReq.ChatRequest.Params.ServiceTier == nil || *bifrostReq.ChatRequest.Params.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected fast deployment to imply standard service tier, got %#v", bifrostReq.ChatRequest.Params.ServiceTier)
	}
}

func TestAnthropicStandardDeploymentUsesStandardOnlyRequestTier(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast","messages":[{"role":"user","content":"hi"}],"service_tier":"standard_only"}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "claude-opus-4-8-fast" || resolution.Model != "claude-opus-4-8" {
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
	if got := bifrostReq.ChatRequest.Params.Speed; got == nil || *got != "fast" {
		t.Fatalf("expected fast deployment to set typed speed, got %#v", got)
	}
	if bifrostReq.ChatRequest.Params.ServiceTier == nil || *bifrostReq.ChatRequest.Params.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected standard deployment to imply Bifrost default service tier, got %#v", bifrostReq.ChatRequest.Params.ServiceTier)
	}
}

func TestAnthropicUSDeploymentSetsInferenceGeoInternally(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8-fast-us","messages":[{"role":"user","content":"hi"}]}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "claude-opus-4-8-fast-us" || resolution.Deployment.RegionID != "us" {
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
	if got := bifrostReq.ChatRequest.Params.Speed; got == nil || *got != "fast" {
		t.Fatalf("expected fast US deployment to set typed speed, got %#v", got)
	}
	if got := bifrostReq.ChatRequest.Params.ExtraParams["inference_geo"]; got != "us" {
		t.Fatalf("expected US deployment to set inference_geo internally, got %#v", bifrostReq.ChatRequest.Params.ExtraParams)
	}
	if bifrostReq.ChatRequest.Params.ServiceTier == nil || *bifrostReq.ChatRequest.Params.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected US standard deployment to imply Bifrost default tier, got %#v", bifrostReq.ChatRequest.Params.ServiceTier)
	}
}

func TestAnthropicClientSpeedSelectsAndSanitizesDeployment(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		body           string
		wantDeployment string
		wantChatSpeed  *string
		wantExtraSpeed any
	}{
		{
			name:           "chat fast from base slug",
			path:           "/v1/chat/completions",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"speed":"fast"}`,
			wantDeployment: "claude-opus-4-8-fast",
			wantChatSpeed:  schemas.Ptr("fast"),
		},
		{
			name:           "chat standard overrides fast slug",
			path:           "/v1/chat/completions",
			body:           `{"model":"anthropic/claude-opus-4-8-fast","messages":[{"role":"user","content":"hi"}],"speed":"standard"}`,
			wantDeployment: "claude-opus-4-8",
		},
		{
			name:           "responses fast from base slug",
			path:           "/v1/responses",
			body:           `{"model":"anthropic/claude-opus-4-8","input":"hi","speed":"fast","max_output_tokens":16}`,
			wantDeployment: "claude-opus-4-8-fast",
			wantExtraSpeed: "fast",
		},
		{
			name:           "responses standard overrides fast slug",
			path:           "/v1/responses",
			body:           `{"model":"anthropic/claude-opus-4-8-fast","input":"hi","speed":"standard","max_output_tokens":16}`,
			wantDeployment: "claude-opus-4-8",
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
			if resolution.Deployment.ID != tc.wantDeployment {
				t.Fatalf("expected deployment %q, got %#v", tc.wantDeployment, resolution.Deployment)
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
			switch tc.path {
			case "/v1/chat/completions":
				if tc.wantChatSpeed == nil {
					if bifrostReq.ChatRequest.Params.Speed != nil {
						t.Fatalf("expected standard speed to be omitted, got %#v", bifrostReq.ChatRequest.Params.Speed)
					}
				} else if bifrostReq.ChatRequest.Params.Speed == nil || *bifrostReq.ChatRequest.Params.Speed != *tc.wantChatSpeed {
					t.Fatalf("expected chat speed %q, got %#v", *tc.wantChatSpeed, bifrostReq.ChatRequest.Params.Speed)
				}
			case "/v1/responses":
				got := bifrostReq.ResponsesRequest.Params.ExtraParams["speed"]
				if tc.wantExtraSpeed == nil {
					if got != nil {
						t.Fatalf("expected standard speed extra param to be omitted, got %#v", got)
					}
				} else if got != tc.wantExtraSpeed {
					t.Fatalf("expected responses speed extra param %#v, got %#v", tc.wantExtraSpeed, got)
				}
			}
		})
	}
}

func TestAnthropicClientInferenceGeoSelectsUSDeployment(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"inference_geo":"us"}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "claude-opus-4-8-us" || resolution.Deployment.RegionID != "us" {
		t.Fatalf("expected client inference_geo to select US deployment, got %#v", resolution.Deployment)
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
	if got := bifrostReq.ChatRequest.Params.InferenceGeo; got == nil || *got != "us" {
		t.Fatalf("expected typed Anthropic inference_geo to reach Bifrost, got %#v", got)
	}
	if got := bifrostReq.ChatRequest.Params.ExtraParams["inference_geo"]; got != "us" {
		t.Fatalf("expected adapter to preserve provider-native inference_geo extra param, got %#v", got)
	}
}

func TestAnthropicClientInferenceGeoGlobalSelectsStandardDeployment(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8-us","messages":[{"role":"user","content":"hi"}],"inference_geo":"global"}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6-us","input":"hi","inference_geo":"global","max_output_tokens":16}`,
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
			if strings.Contains(resolution.Deployment.ID, "-us") || resolution.Deployment.RegionID != "multi-region" {
				t.Fatalf("expected global inference to select standard deployment, got %#v", resolution.Deployment)
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
			switch tc.path {
			case "/v1/chat/completions":
				if got := bifrostReq.ChatRequest.Params.InferenceGeo; got == nil || *got != "global" {
					t.Fatalf("expected typed Anthropic inference_geo global to reach Bifrost, got %#v", got)
				}
				if got := bifrostReq.ChatRequest.Params.ExtraParams["inference_geo"]; got != "global" {
					t.Fatalf("expected adapter to preserve global inference_geo extra param, got %#v", got)
				}
			case "/v1/responses":
				if got := bifrostReq.ResponsesRequest.Params.ExtraParams["inference_geo"]; got != "global" {
					t.Fatalf("expected Anthropic Responses inference_geo global extra param, got %#v", got)
				}
			}
		})
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
			want: "standard_only",
		},
		{
			name: "chat explicit auto",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"auto"}`,
			want: "auto",
		},
		{
			name: "chat priority",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"priority"}`,
			want: "auto",
		},
		{
			name: "chat default",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"default"}`,
			want: "standard_only",
		},
		{
			name: "chat flex",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"flex"}`,
			want: "standard_only",
		},
		{
			name: "chat standard",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"standard"}`,
			want: "standard_only",
		},
		{
			name: "chat standard only",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"standard_only"}`,
			want: "standard_only",
		},
		{
			name: "responses auto",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_output_tokens":16}`,
			want: "standard_only",
		},
		{
			name: "responses priority",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"priority","max_output_tokens":16}`,
			want: "auto",
		},
		{
			name: "responses default",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"default","max_output_tokens":16}`,
			want: "standard_only",
		},
		{
			name: "responses flex",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"flex","max_output_tokens":16}`,
			want: "standard_only",
		},
		{
			name: "responses standard only",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"standard_only","max_output_tokens":16}`,
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
		Body:   []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":false}}`),
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
		{
			name: "anthropic chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`,
		},
		{
			name: "anthropic responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi"}`,
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
			bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			bifrostReq, err := resolution.ToBifrost(bifrostCtx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch {
			case item.path == "/v1/chat/completions" && resolution.Provider == schemas.OpenAI:
				if bifrostReq.ChatRequest.Params.User == nil || *bifrostReq.ChatRequest.Params.User != responsibleID {
					t.Fatalf("expected chat upstream user %q, got %#v", responsibleID, bifrostReq.ChatRequest.Params.User)
				}
			case item.path == "/v1/responses" && resolution.Provider == schemas.OpenAI:
				if bifrostReq.ResponsesRequest.Params.User == nil || *bifrostReq.ResponsesRequest.Params.User != responsibleID {
					t.Fatalf("expected responses upstream user %q, got %#v", responsibleID, bifrostReq.ResponsesRequest.Params.User)
				}
			case item.path == "/v1/chat/completions" && resolution.Provider == schemas.Anthropic:
				wire, err := anthropicprovider.ToAnthropicChatRequest(bifrostCtx, bifrostReq.ChatRequest)
				if err != nil {
					t.Fatalf("ToAnthropicChatRequest returned error: %v", err)
				}
				if wire.Metadata == nil || wire.Metadata.UserID == nil || *wire.Metadata.UserID != responsibleID {
					t.Fatalf("expected Anthropic chat metadata.user_id %q, got %#v", responsibleID, wire.Metadata)
				}
			case item.path == "/v1/chat/completions":
				t.Fatalf("unexpected chat provider %q", resolution.Provider)
			case item.path == "/v1/responses" && resolution.Provider == schemas.Anthropic:
				body, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(bifrostCtx, bifrostReq.ResponsesRequest, anthropicprovider.AnthropicRequestBuildConfig{
					Provider:    schemas.Anthropic,
					IsStreaming: bifrostReq.RequestType == schemas.ResponsesStreamRequest,
				})
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				var payload struct {
					Metadata *struct {
						UserID string `json:"user_id"`
					} `json:"metadata"`
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("failed to decode Anthropic Responses request body: %v\n%s", err, body)
				}
				if payload.Metadata == nil || payload.Metadata.UserID != responsibleID {
					t.Fatalf("expected Anthropic Responses metadata.user_id %q, got %#v in %s", responsibleID, payload.Metadata, body)
				}
			case item.path == "/v1/responses":
				t.Fatalf("unexpected responses provider %q", resolution.Provider)
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
		{"fallbacks", `{"model":"gpt-5-nano","input":"hi","fallbacks":["gpt-5-nano-flex"]}`, "Fallbacks are not supported"},
		{"top-level mcp servers", `{"model":"gpt-5-nano","input":"hi","mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"remote"}]}`, "mcp_servers is not supported"},
		{"previous response", `{"model":"gpt-5-nano","input":"hi","previous_response_id":"resp_123"}`, "previous_response_id is not supported"},
		{"reasoning input item without encrypted content", `{"model":"gpt-5-nano","input":[{"type":"reasoning","summary":[]}]}`, "reasoning input items require encrypted_content"},
		{"reasoning input item on Anthropic", `{"model":"anthropic/claude-sonnet-4-6","input":[{"type":"reasoning","encrypted_content":"opaque"}]}`, "reasoning input items are only supported for OpenAI reasoning deployments"},
		{"prompt cache retention anthropic", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","prompt_cache_retention":"24h"}`, "prompt_cache_retention is only supported for OpenAI"},
		{"openai cache control", `{"model":"gpt-5-nano","input":"hi","cache_control":{"type":"ephemeral"}}`, "cache_control is only supported for Anthropic"},
		{"openai input cache control", `{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`, "cache_control is only supported for Anthropic"},
		{"openai tool cache control", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"require_approval":"never","cache_control":{"type":"ephemeral"}}]}`, "cache_control is only supported for Anthropic"},
		{"anthropic cache control bad ttl", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"24h"}}`, "cache_control.ttl must be 5m or 1h"},
		{"anthropic message cache control unsupported", `{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","cache_control":{"type":"ephemeral"},"content":"hi"}]}`, "input[].cache_control is not supported"},
		{"anthropic responses frequency penalty", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","frequency_penalty":0.1}`, "frequency_penalty is only supported for OpenAI"},
		{"anthropic responses include", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","include":["message.output_text.logprobs"]}`, "include is only supported for OpenAI"},
		{"anthropic responses presence penalty", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","presence_penalty":0.1}`, "presence_penalty is only supported for OpenAI"},
		{"anthropic responses temperature top p conflict", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","temperature":0.7,"top_p":0.9}`, "temperature and top_p together"},
		{"anthropic prompt cache key", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","prompt_cache_key":"tenant-a"}`, "prompt_cache_key is only supported for OpenAI"},
		{"top k openai", `{"model":"gpt-5-nano","input":"hi","top_k":40}`, "top_k is only supported for Anthropic"},
		{"stop sequences openai", `{"model":"gpt-5-nano","input":"hi","stop_sequences":["END"]}`, "stop_sequences is only supported for Anthropic"},
		{"responses stop unsupported before stop sequences conflict", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","stop":["DONE"],"stop_sequences":["END"]}`, "stop is not supported"},
		{"openai task budget", `{"model":"gpt-5-nano","input":"hi","task_budget":{"type":"tokens","total":20000}}`, "task_budget is only supported for Anthropic"},
		{"openai context management", `{"model":"gpt-5-nano","input":"hi","context_management":{"edits":[{"type":"compact_20260112"}]}}`, "context_management is only supported for Anthropic"},
		{"reasoning effort bad type", `{"model":"gpt-5-nano","input":"hi","reasoning.effort":3}`, "reasoning.effort must be a string"},
		{"responses bad reasoning object", `{"model":"gpt-5-nano","input":"hi","reasoning":"low"}`, "reasoning must be an object"},
		{"responses bad reasoning max tokens", `{"model":"gpt-5-nano","input":"hi","reasoning":{"max_tokens":0}}`, "reasoning.max_tokens is outside the supported range"},
		{"responses reasoning display", `{"model":"gpt-5-nano","input":"hi","reasoning":{"display":"summarized"}}`, "reasoning.display is not supported"},
		{"responses unknown reasoning field", `{"model":"gpt-5-nano","input":"hi","reasoning":{"unknown":true}}`, "reasoning.unknown is not supported"},
		{"reasoning effort conflict", `{"model":"gpt-5-nano","input":"hi","reasoning":{"effort":"low"},"reasoning.effort":"medium"}`, "reasoning.effort conflicts"},
		{"safety identifier", `{"model":"gpt-5-nano","input":"hi","safety_identifier":"user_123"}`, "safety_identifier is not supported"},
		{"stream options without stream", `{"model":"gpt-5-nano","input":"hi","stream_options":{"include_obfuscation":true}}`, "stream_options requires stream=true"},
		{"responses include usage stream option", `{"model":"gpt-5-nano","input":"hi","stream":true,"stream_options":{"include_usage":true}}`, "stream_options.include_usage is not supported for Responses"},
		{"store", `{"model":"gpt-5-nano","input":"hi","store":true}`, "store is not supported"},
		{"user", `{"model":"gpt-5-nano","input":"hi","user":"user_123"}`, "user is not supported"},
		{"metadata non-string", `{"model":"gpt-5-nano","input":"hi","metadata":{"tenant":1}}`, "metadata values"},
		{"anthropic parallel tool calls", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup"}],"parallel_tool_calls":false}`, "parallel_tool_calls is not supported for Anthropic"},
		{"anthropic max tool calls function only", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup"}],"max_tool_calls":2}`, "max_tool_calls is only supported for Anthropic hosted tools"},
		{"max tool calls without tools", `{"model":"gpt-5-nano","input":"hi","max_tool_calls":2}`, "max_tool_calls requires supported tools"},
		{"max tool calls too large", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"max_tool_calls":129}`, "max_tool_calls is outside the supported range"},
		{"parallel tools without tools", `{"model":"gpt-5-nano","input":"hi","parallel_tool_calls":true}`, "parallel_tool_calls requires supported tools"},
		{"tool choice without tools", `{"model":"gpt-5-nano","input":"hi","tool_choice":"auto"}`, "tool_choice requires supported tools"},
		{"openai file search", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"file_search"}]}`, "hosted retrieval and file storage have separate pricing"},
		{"openai code interpreter", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"code_interpreter"}]}`, "hosted containers have separate pricing and lifecycle"},
		{"openai hosted shell", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`, "hosted execution needs a container lifecycle"},
		{"openai local shell", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"local_shell"}]}`, "local execution requires provider-state continuation"},
		{"openai apply patch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"apply_patch"}]}`, "local execution requires provider-state continuation"},
		{"openai computer", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"computer_use_preview"}]}`, "text-only Stogas API"},
		{"openai image generation", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"image_generation"}]}`, "text-only Stogas API"},
		{"openai tool search", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"tool_search"}]}`, "tool-loading or provider-state lifecycle"},
		{"openai namespace", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"namespace","name":"crm","tools":[{"type":"function","name":"lookup"}]}]}`, "tool-loading or provider-state lifecycle"},
		{"openai memory", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"memory"}]}`, "tool-loading or provider-state lifecycle"},
		{"mcp http url", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"http://example.com/mcp","allowed_tools":["search"],"require_approval":"never"}]}`, "mcp tools require an HTTPS server_url"},
		{"mcp missing allowed tools", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","require_approval":"never"}]}`, "mcp tools require allowed_tools"},
		{"mcp empty filter allowed tools", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":{"read_only":false},"require_approval":"never"}]}`, "mcp allowed_tools filter must narrow"},
		{"mcp headers", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"headers":{"x-api-key":"secret"},"require_approval":"never"}]}`, "mcp.headers is not supported"},
		{"openai mcp missing approval", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"]}]}`, `OpenAI MCP tools require require_approval="never"`},
		{"openai mcp approval always", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"require_approval":"always"}]}`, `OpenAI MCP tools require require_approval="never"`},
		{"openai mcp approval object", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"require_approval":{"never":{"tool_names":["search"]}}}]}`, `OpenAI MCP tools require require_approval="never"`},
		{"anthropic mcp approval", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"require_approval":"never"}]}`, "mcp.require_approval is only supported for OpenAI"},
		{"anthropic local shell", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"local_shell"}]}`, "Only function, custom, mcp"},
		{"anthropic max uses too large", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search","max_uses":129}]}`, "tools[].max_uses is outside the supported range"},
		{"anthropic web fetch max uses too large", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_uses":129}]}`, "tools[].max_uses is outside the supported range"},
		{"anthropic max tool calls conflicts with max uses", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_tool_calls":2,"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":3}]}`, "max_tool_calls conflicts with tools[].max_uses"},
		{"anthropic web fetch max tool calls conflicts with max uses", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_tool_calls":2,"tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_uses":3}]}`, "max_tool_calls conflicts with tools[].max_uses"},
		{"anthropic code execution", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"code_execution_20250825","name":"code_execution"}],"max_tool_calls":1}`, "Explicit Anthropic code_execution tools are not supported"},
		{"anthropic computer use", `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"computer_20251124","name":"computer"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai web fetch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_fetch_20260309"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai code execution version", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"code_execution_20250825"}],"max_tool_calls":1}`, "hosted containers have separate pricing and lifecycle"},
		{"openai empty web search suffix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai separator-only web search suffix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search__"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai empty preview web search suffix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai separator-only preview web search suffix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview__"}],"max_tool_calls":1}`, "Only function, custom"},
		{"openai malformed preview web search prefix", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_previewfoo"}],"max_tool_calls":1}`, "Only function, custom"},
		{"unsupported tool choice", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"code_interpreter"}}`, "tool_choice must select a supported tool"},
		{"hosted tool choice not declared", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"web_search_preview"},"max_tool_calls":1}`, "tool_choice selects an unknown web_search_preview tool"},
		{"allowed hosted tool choice not declared", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_preview"}]},"max_tool_calls":1}`, "tool_choice selects an unknown web_search_preview tool"},
		{"allowed tools web fetch", `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_fetch_20260309"}]},"max_tool_calls":1}`, "tool_choice selects an unknown web_fetch tool"},
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

func TestResponsesReasoningEffortAliasStaysTyped(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","reasoning.effort":"future_effort"}`),
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
	reasoning := bifrostReq.ResponsesRequest.Params.Reasoning
	if reasoning == nil || reasoning.Effort == nil || *reasoning.Effort != "future_effort" {
		t.Fatalf("expected typed reasoning.effort=future_effort, got %#v", reasoning)
	}
	if _, ok := bifrostReq.ResponsesRequest.Params.ExtraParams["reasoning.effort"]; ok {
		t.Fatalf("reasoning.effort must not be forwarded as ExtraParams: %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
	}
	wireReq := openaiprovider.ToOpenAIResponsesRequest(bifrostReq.ResponsesRequest)
	wireBytes, err := json.Marshal(wireReq)
	if err != nil {
		t.Fatalf("marshal OpenAI wire request: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(wireBytes, &wire); err != nil {
		t.Fatalf("unmarshal wire request: %v", err)
	}
	var wireReasoning map[string]string
	if err := json.Unmarshal(wire["reasoning"], &wireReasoning); err != nil {
		t.Fatalf("wire reasoning not present: body=%s err=%v", wireBytes, err)
	}
	if wireReasoning["effort"] != "future_effort" {
		t.Fatalf("expected wire reasoning.effort=future_effort, got %#v body=%s", wireReasoning, wireBytes)
	}
}

func TestResponsesInputTextOnlyRejectsMultimodalAliases(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "nested image_url alias",
			body: `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]`,
			want: "Only text input",
		},
		{
			name: "top-level inline file",
			body: `[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]`,
			want: "file inputs are not supported",
		},
		{
			name: "typeless file id",
			body: `[{"role":"user","content":[{"file_id":"file_123"}]}]`,
			want: "file_id inputs are not supported",
		},
		{
			name: "typeless file url",
			body: `[{"role":"user","content":[{"file_url":"https://example.com/a.pdf"}]}]`,
			want: "file_url inputs are not supported",
		},
		{
			name: "typeless inline file",
			body: `[{"role":"user","content":[{"file_data":"data:text/plain;base64,aGk="}]}]`,
			want: "file inputs are not supported",
		},
		{
			name: "text-typed file object",
			body: `[{"role":"user","content":[{"type":"input_text","text":"hi","file":{"file_data":"data:text/plain;base64,aGk="}}]}]`,
			want: "file inputs are not supported",
		},
		{
			name: "typeless image url",
			body: `[{"role":"user","content":[{"image_url":"https://example.com/a.png"}]}]`,
			want: "Only text input",
		},
		{
			name: "text-typed input image",
			body: `[{"role":"user","content":[{"type":"input_text","text":"hi","input_image":{"image_url":"https://example.com/a.png"}}]}]`,
			want: "Only text input",
		},
		{
			name: "typeless input audio",
			body: `[{"role":"user","content":[{"input_audio":{"data":"abc","format":"mp3"}}]}]`,
			want: "Only text input",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResponsesInputTextOnly(nil, json.RawMessage(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestResponsesPolicyAllowsTextFunctionAndPricedWebSearch(t *testing.T) {
	for _, body := range []string{
		`{"model":"gpt-5-nano","input":"hi","stream":false,"instructions":"be brief","temperature":1,"top_p":1,"text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object"},"strict":true},"verbosity":"future-verbosity"},"truncation":"future-truncation","prompt_cache_key":"tenant-cache"}`,
		`{"model":"gpt-5-nano","input":"hi","reasoning":{"summary":"future-summary","generate_summary":"future-generate-summary"}}`,
		`{"model":"gpt-5-nano","input":"hi","prompt_cache_retention":"24h"}`,
		`{"model":"gpt-5-nano","input":"hi","include":["web_search_call.action.sources","web_search_call.results","message.output_text.logprobs","reasoning.encrypted_content"],"top_logprobs":3}`,
		`{"model":"gpt-5-nano","input":"hi","stream":true,"stream_options":{"include_obfuscation":false}}`,
		`{"model":"gpt-5-nano","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"},"max_tool_calls":1,"parallel_tool_calls":false}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"custom","name":"lookup"}],"tool_choice":{"type":"custom","name":"lookup"},"max_tool_calls":1}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","authorization":"secret","allowed_tools":["search"],"require_approval":"never"}],"tool_choice":{"type":"mcp","server_label":"remote"}}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","server_description":"Docs search","allowed_tools":{"read_only":true,"tool_names":["search"]},"require_approval":"never"}],"tool_choice":{"type":"mcp","server_label":"remote"}}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"require_approval":"never"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"mcp","server_label":"remote"}]}}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto"}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_20260209"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_2026_01_01"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_latest"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_20250311"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2026_01_01"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_latest"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2026_01_01"}],"tool_choice":{"type":"web_search_preview_2026_01_01"},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":{"type":"web_search_preview"},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2026_01_01"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_preview_2026_01_01"}]},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_preview"}]},"max_tool_calls":2}`,
		`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto","max_tool_calls":128}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto"}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20260209","name":"web_search"}],"tool_choice":{"type":"web_search_20260209"},"max_tool_calls":2}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search","name":"web_search"}],"tool_choice":"auto","max_tool_calls":2}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":1000}],"tool_choice":{"type":"web_fetch_20260309"}}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","authorization":"secret","allowed_tools":["search"]}],"tool_choice":{"type":"mcp","server_label":"remote"}}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],"cache_control":{"type":"ephemeral","ttl":"1h"},"tools":[{"type":"function","name":"lookup","cache_control":{"type":"ephemeral"}}]}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"cache_control":{"type":"string"}}}}]}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","top_p":0.9,"top_k":40,"stop_sequences":["END"]}`,
		`{"model":"anthropic/claude-sonnet-4-6","input":"hi","task_budget":{"type":"future-budget","future_provider_owned_shape":{"any":true}},"context_management":{"edits":[{"type":"future-edit","provider_owned_settings":{"any":true}}]}}`,
	} {
		if err := validateResolvedResponses(t, body); err != nil {
			t.Fatalf("expected Responses request to pass: %v\nbody=%s", err, body)
		}
	}
}

func TestResponsesPolicyPreservesStreamObfuscationOption(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","stream":true,"stream_options":{"include_obfuscation":false}}`),
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
	if bifrostReq.ResponsesRequest.Params.StreamOptions == nil ||
		bifrostReq.ResponsesRequest.Params.StreamOptions.IncludeObfuscation == nil ||
		*bifrostReq.ResponsesRequest.Params.StreamOptions.IncludeObfuscation {
		t.Fatalf("expected Responses include_obfuscation=false to survive conversion, got %#v", bifrostReq.ResponsesRequest.Params.StreamOptions)
	}
}

func TestResponsesMCPToolsReachProviderWireRequest(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "openai",
			body: `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","authorization":"secret","allowed_tools":["search"],"require_approval":"never"}],"tool_choice":{"type":"mcp","server_label":"remote"}}`,
		},
		{
			name: "anthropic",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","authorization":"secret","allowed_tools":["search"]}],"tool_choice":{"type":"mcp","server_label":"remote"}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
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
			if len(bifrostReq.ResponsesRequest.Params.Tools) != 1 ||
				bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolMCP == nil ||
				bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolMCP.ServerLabel != "remote" ||
				bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolMCP.Authorization == nil ||
				*bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolMCP.Authorization != "secret" ||
				!slices.Equal(bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolMCP.AllowedTools.ToolNames, []string{"search"}) {
				t.Fatalf("expected Bifrost MCP tool to survive conversion, got %#v", bifrostReq.ResponsesRequest.Params.Tools)
			}
			switch tc.name {
			case "openai":
				wire := openaiprovider.ToOpenAIResponsesRequest(bifrostReq.ResponsesRequest)
				wireBytes, err := json.Marshal(wire)
				if err != nil {
					t.Fatalf("marshal OpenAI Responses wire request: %v", err)
				}
				var wireBody map[string]any
				if err := json.Unmarshal(wireBytes, &wireBody); err != nil {
					t.Fatalf("unmarshal OpenAI Responses wire request: %v\nbody=%s", err, string(wireBytes))
				}
				tools, _ := wireBody["tools"].([]any)
				if len(tools) != 1 {
					t.Fatalf("expected OpenAI MCP tool, got %s", string(wireBytes))
				}
				tool, _ := tools[0].(map[string]any)
				allowed, _ := tool["allowed_tools"].([]any)
				if tool["type"] != "mcp" || tool["server_label"] != "remote" || tool["server_url"] != "https://example.com/mcp" || tool["authorization"] != "secret" || tool["require_approval"] != "never" || len(allowed) != 1 || allowed[0] != "search" {
					t.Fatalf("unexpected OpenAI MCP wire tool: %s", string(wireBytes))
				}
			case "anthropic":
				wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
					schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
					bifrostReq.ResponsesRequest,
					anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
				)
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				var wireBody map[string]any
				if err := json.Unmarshal(wire, &wireBody); err != nil {
					t.Fatalf("failed to unmarshal Anthropic responses wire body: %v\nbody=%s", err, string(wire))
				}
				servers, _ := wireBody["mcp_servers"].([]any)
				tools, _ := wireBody["tools"].([]any)
				if len(servers) != 1 || len(tools) != 1 {
					t.Fatalf("expected Anthropic mcp_servers and mcp_toolset, got %s", string(wire))
				}
				server, _ := servers[0].(map[string]any)
				tool, _ := tools[0].(map[string]any)
				configs, _ := tool["configs"].(map[string]any)
				searchConfig, _ := configs["search"].(map[string]any)
				if server["name"] != "remote" || server["url"] != "https://example.com/mcp" || server["authorization_token"] != "secret" ||
					tool["type"] != "mcp_toolset" || tool["mcp_server_name"] != "remote" || searchConfig["enabled"] != true {
					t.Fatalf("unexpected Anthropic MCP wire body: %s", string(wire))
				}
			}
		})
	}
}

func TestOpenAIChatWebSearchOptionsReachProviderWireRequest(t *testing.T) {
	body := `{
		"model":"gpt-4o-search-preview",
		"messages":[{"role":"user","content":"hi"}],
		"web_search_options":{
			"search_context_size":"low",
			"user_location":{
				"type":"approximate",
				"approximate":{
					"city":"San Francisco",
					"country":"US",
					"region":"California",
					"timezone":"America/Los_Angeles"
				}
			}
		},
		"max_completion_tokens":100
	}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(body),
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
	if bifrostReq.ChatRequest == nil || bifrostReq.ChatRequest.Params == nil || bifrostReq.ChatRequest.Params.WebSearchOptions == nil {
		t.Fatalf("expected Bifrost chat web_search_options, got %#v", bifrostReq.ChatRequest)
	}
	wireRequest := openaiprovider.ToOpenAIChatRequest(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), bifrostReq.ChatRequest)
	wireBytes, err := json.Marshal(wireRequest)
	if err != nil {
		t.Fatalf("marshal OpenAI Chat request: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(wireBytes, &wire); err != nil {
		t.Fatalf("unmarshal OpenAI Chat wire request: %v\nbody=%s", err, string(wireBytes))
	}
	options, _ := wire["web_search_options"].(map[string]any)
	location, _ := options["user_location"].(map[string]any)
	approximate, _ := location["approximate"].(map[string]any)
	if options["search_context_size"] != "low" ||
		location["type"] != "approximate" ||
		approximate["city"] != "San Francisco" ||
		approximate["country"] != "US" ||
		approximate["region"] != "California" ||
		approximate["timezone"] != "America/Los_Angeles" {
		t.Fatalf("unexpected OpenAI Chat web_search_options wire body: %s", string(wireBytes))
	}
}

func TestOpenAIResponsesMCPAllowedToolsFilterReachesProviderWireRequest(t *testing.T) {
	body := `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","server_description":"Docs search","allowed_tools":{"read_only":true,"tool_names":["search"]},"require_approval":"never"}],"tool_choice":{"type":"mcp","server_label":"remote"}}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(body),
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
	mcp := bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolMCP
	if mcp == nil || mcp.AllowedTools == nil || mcp.AllowedTools.Filter == nil ||
		mcp.AllowedTools.Filter.ReadOnly == nil || !*mcp.AllowedTools.Filter.ReadOnly ||
		!slices.Equal(mcp.AllowedTools.Filter.ToolNames, []string{"search"}) ||
		mcp.ServerDescription == nil || *mcp.ServerDescription != "Docs search" {
		t.Fatalf("expected Bifrost MCP filter and server_description, got %#v", bifrostReq.ResponsesRequest.Params.Tools)
	}
	wire := openaiprovider.ToOpenAIResponsesRequest(bifrostReq.ResponsesRequest)
	wireBytes, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal OpenAI Responses wire request: %v", err)
	}
	var wireBody map[string]any
	if err := json.Unmarshal(wireBytes, &wireBody); err != nil {
		t.Fatalf("unmarshal OpenAI Responses wire request: %v\nbody=%s", err, string(wireBytes))
	}
	tools, _ := wireBody["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected OpenAI MCP tool, got %s", string(wireBytes))
	}
	tool, _ := tools[0].(map[string]any)
	allowed, _ := tool["allowed_tools"].(map[string]any)
	names, _ := allowed["tool_names"].([]any)
	if tool["server_description"] != "Docs search" || allowed["read_only"] != true || len(names) != 1 || names[0] != "search" {
		t.Fatalf("unexpected OpenAI MCP filter wire tool: %s", string(wireBytes))
	}
}

func TestResponsesPolicyPreservesAllowedOpenAIInclude(t *testing.T) {
	includes := []string{
		"web_search_call.action.sources",
		"web_search_call.results",
		"message.output_text.logprobs",
		"reasoning.encrypted_content",
	}
	body := `{"model":"gpt-5-nano","input":"hi","include":["web_search_call.action.sources","web_search_call.results","message.output_text.logprobs","reasoning.encrypted_content"],"top_logprobs":3}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(body),
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
	if got := bifrostReq.ResponsesRequest.Params.Include; !slices.Equal(got, includes) {
		t.Fatalf("expected Bifrost include %#v, got %#v", includes, got)
	}
	if bifrostReq.ResponsesRequest.Params.TopLogProbs == nil || *bifrostReq.ResponsesRequest.Params.TopLogProbs != 3 {
		t.Fatalf("expected Bifrost top_logprobs=3, got %#v", bifrostReq.ResponsesRequest.Params.TopLogProbs)
	}
	wireRequest := openaiprovider.ToOpenAIResponsesRequest(bifrostReq.ResponsesRequest)
	wireBytes, err := json.Marshal(wireRequest)
	if err != nil {
		t.Fatalf("marshal OpenAI Responses request: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(wireBytes, &wire); err != nil {
		t.Fatalf("unmarshal OpenAI wire request: %v", err)
	}
	var wireIncludes []string
	if err := json.Unmarshal(wire["include"], &wireIncludes); err != nil {
		t.Fatalf("wire include not preserved: body=%s err=%v", wireBytes, err)
	}
	if !slices.Equal(wireIncludes, includes) {
		t.Fatalf("expected OpenAI wire include %#v, got %#v body=%s", includes, wireIncludes, wireBytes)
	}
	var wireTopLogProbs int
	if err := json.Unmarshal(wire["top_logprobs"], &wireTopLogProbs); err != nil {
		t.Fatalf("wire top_logprobs not preserved: body=%s err=%v", wireBytes, err)
	}
	if wireTopLogProbs != 3 {
		t.Fatalf("expected OpenAI wire top_logprobs=3, got %d body=%s", wireTopLogProbs, wireBytes)
	}
}

func TestOpenAIResponsesEncryptedReasoningInputReservesEffectiveMaxInput(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		wantContext   int
		wantSearchCap bool
	}{
		{
			name:        "standard reasoning model",
			body:        `{"model":"gpt-5-nano","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]},{"type":"reasoning","id":"rs_123","summary":[],"encrypted_content":"opaque-ciphertext"}],"max_output_tokens":16}`,
			wantContext: 272000,
		},
		{
			name:        "priority deployment context cap",
			body:        `{"model":"gpt-5.5-priority","input":[{"type":"input_text","text":"continue"},{"type":"reasoning","encrypted_content":"opaque-ciphertext"}],"max_output_tokens":16}`,
			wantContext: 272000,
		},
		{
			name:          "hosted tool content headroom is already reserved",
			body:          `{"model":"gpt-5-nano","input":[{"type":"input_text","text":"search and continue"},{"type":"reasoning","encrypted_content":"opaque-ciphertext"}],"tools":[{"type":"web_search"}],"max_tool_calls":3,"max_output_tokens":16}`,
			wantContext:   272000,
			wantSearchCap: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			if resolution.Deployment.ContextWindowTokens != tc.wantContext {
				t.Fatalf("expected deployment context cap %d, got %d for %#v", tc.wantContext, resolution.Deployment.ContextWindowTokens, resolution.Deployment)
			}
			wantInput := tc.wantContext - resolution.OutputTokenLimit()
			if resolution.InputTokenLimit() != wantInput {
				t.Fatalf("encrypted reasoning must reserve effective max input %d, got %d", wantInput, resolution.InputTokenLimit())
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
			if findMeterEstimateQuantity(state.Hold.Meters, billing.MeterInputTokens, strconv.Itoa(wantInput)) == nil {
				t.Fatalf("expected max-input hold quantity %d, got %#v", wantInput, state.Hold.Meters)
			}
			if got := countMeterEstimates(state.Hold.Meters, billing.MeterInputTokens); got != 1 {
				t.Fatalf("encrypted reasoning hold must not add a second input-token meter, got %d in %#v", got, state.Hold.Meters)
			}
			if tc.wantSearchCap {
				searchMeter := findMeterEstimate(state.Hold.Meters, MeterOpenAIResponsesWebSearchCalls)
				if searchMeter == nil || searchMeter.Quantity != "3" {
					t.Fatalf("expected web_search call hold quantity 3, got %#v in %#v", searchMeter, state.Hold.Meters)
				}
			}

			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			wireRequest := openaiprovider.ToOpenAIResponsesRequest(bifrostReq.ResponsesRequest)
			wireBytes, err := json.Marshal(wireRequest)
			if err != nil {
				t.Fatalf("marshal OpenAI Responses request: %v", err)
			}
			if !strings.Contains(string(wireBytes), `"encrypted_content":"opaque-ciphertext"`) {
				t.Fatalf("encrypted reasoning input must reach OpenAI wire request, got %s", string(wireBytes))
			}

			state.Signals = &StandardSignals{Prompt: 100, Completion: 16}
			if tc.wantSearchCap {
				state.Signals = &StandardSignals{Prompt: 100, Completion: 16, WebSearch: 2}
			}
			if err := state.Adapter.FinalPrice(state); err != nil {
				t.Fatalf("FinalPrice returned error: %v", err)
			}
			if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover actual provider usage after encrypted reasoning replay: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
			}
		})
	}
}

func TestResponsesTextFormatReachesProviderWireRequest(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "openai json schema",
			body: `{"model":"gpt-5-nano","input":"hi","text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","properties":{"ok":{"type":"boolean"}}},"strict":true}}}`,
		},
		{
			name: "anthropic json schema",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
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
			switch resolution.Provider {
			case schemas.OpenAI:
				wire := openaiprovider.ToOpenAIResponsesRequest(bifrostReq.ResponsesRequest)
				wireBytes, err := json.Marshal(wire)
				if err != nil {
					t.Fatalf("marshal OpenAI responses request: %v", err)
				}
				if !strings.Contains(string(wireBytes), `"text"`) || !strings.Contains(string(wireBytes), `"strict":true`) {
					t.Fatalf("expected OpenAI Responses text.format to reach wire request, got %s", wireBytes)
				}
			case schemas.Anthropic:
				body, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
					bifrostCtx,
					bifrostReq.ResponsesRequest,
					anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
				)
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				if strings.Contains(string(body), `"tools"`) {
					t.Fatalf("expected direct Anthropic structured output to avoid tool emulation, got %s", body)
				}
				if !strings.Contains(string(body), `"output_config"`) || !strings.Contains(string(body), `"format"`) || !strings.Contains(string(body), `"json_schema"`) {
					t.Fatalf("expected Anthropic Responses output_config.format, got %s", body)
				}
				if strings.Contains(string(body), `"strict"`) {
					t.Fatalf("Anthropic output_config.format must not contain unsupported strict flag: %s", body)
				}
			}
		})
	}
}

func TestOpenAIPromptCacheRetentionNormalizesAndReachesWireRequest(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want string
	}{
		{
			name: "chat underscore alias",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"prompt_cache_retention":"in_memory"}`,
			want: "in-memory",
		},
		{
			name: "responses hyphen value",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","prompt_cache_retention":"in-memory"}`,
			want: "in-memory",
		},
		{
			name: "responses extended value",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","prompt_cache_retention":"24h"}`,
			want: "24h",
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
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatalf("SanitizeRequest returned error: %v", err)
			}
			var rawRetention string
			if err := json.Unmarshal(resolution.RawBody()["prompt_cache_retention"], &rawRetention); err != nil {
				t.Fatalf("raw prompt_cache_retention missing after sanitize: %v", err)
			}
			if rawRetention != tc.want {
				t.Fatalf("expected normalized raw prompt_cache_retention %q, got %q", tc.want, rawRetention)
			}
			bifrostReq, err := resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			var wire any
			switch tc.path {
			case "/v1/chat/completions":
				if bifrostReq.ChatRequest.Params.PromptCacheRetention == nil || *bifrostReq.ChatRequest.Params.PromptCacheRetention != tc.want {
					t.Fatalf("expected Bifrost chat prompt_cache_retention %q, got %#v", tc.want, bifrostReq.ChatRequest.Params.PromptCacheRetention)
				}
				wire = openaiprovider.ToOpenAIChatRequest(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), bifrostReq.ChatRequest)
			case "/v1/responses":
				if bifrostReq.ResponsesRequest.Params.PromptCacheRetention == nil || *bifrostReq.ResponsesRequest.Params.PromptCacheRetention != tc.want {
					t.Fatalf("expected Bifrost responses prompt_cache_retention %q, got %#v", tc.want, bifrostReq.ResponsesRequest.Params.PromptCacheRetention)
				}
				if _, ok := bifrostReq.ResponsesRequest.Params.ExtraParams["prompt_cache_retention"]; ok {
					t.Fatalf("prompt_cache_retention must stay typed, not ExtraParams: %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
				}
				wire = openaiprovider.ToOpenAIResponsesRequest(bifrostReq.ResponsesRequest)
			}
			wireBytes, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("marshal OpenAI wire request: %v", err)
			}
			var wireMap map[string]json.RawMessage
			if err := json.Unmarshal(wireBytes, &wireMap); err != nil {
				t.Fatalf("unmarshal wire request: %v", err)
			}
			var wireRetention string
			if err := json.Unmarshal(wireMap["prompt_cache_retention"], &wireRetention); err != nil {
				t.Fatalf("wire prompt_cache_retention not preserved: body=%s err=%v", wireBytes, err)
			}
			if wireRetention != tc.want {
				t.Fatalf("expected wire prompt_cache_retention %q, got %q body=%s", tc.want, wireRetention, wireBytes)
			}
		})
	}
}

func TestAnthropicSamplingParametersNormalizeAndReachProviderRequest(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"top_k":40,"stop_sequences":["END"],"task_budget":{"type":"tokens","total":20000,"remaining":19000},"context_management":{"edits":[{"type":"compact_20260112","instructions":"keep a compact summary"}]}}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","top_k":40,"stop_sequences":["END"],"task_budget":{"type":"tokens","total":20000,"remaining":19000},"context_management":{"edits":[{"type":"compact_20260112","instructions":"keep a compact summary"}]}}`,
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
			switch tc.path {
			case "/v1/chat/completions":
				if bifrostReq.ChatRequest.Params.TopK == nil || *bifrostReq.ChatRequest.Params.TopK != 40 {
					t.Fatalf("expected Bifrost chat top_k=40, got %#v", bifrostReq.ChatRequest.Params.TopK)
				}
				if !slices.Equal(bifrostReq.ChatRequest.Params.Stop, []string{"END"}) {
					t.Fatalf("expected Bifrost chat stop_sequences alias to set stop, got %#v", bifrostReq.ChatRequest.Params.Stop)
				}
				if bifrostReq.ChatRequest.Params.TaskBudget == nil || bifrostReq.ChatRequest.Params.TaskBudget.Total != 20000 {
					t.Fatalf("expected Bifrost chat task_budget, got %#v", bifrostReq.ChatRequest.Params.TaskBudget)
				}
				if len(bifrostReq.ChatRequest.Params.ContextManagement) == 0 {
					t.Fatalf("expected Bifrost chat context_management to be retained")
				}
				wireReq, err := anthropicprovider.ToAnthropicChatRequest(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), bifrostReq.ChatRequest)
				if err != nil {
					t.Fatalf("ToAnthropicChatRequest returned error: %v", err)
				}
				if wireReq.TopK == nil || *wireReq.TopK != 40 {
					t.Fatalf("expected Anthropic chat top_k=40, got %#v", wireReq.TopK)
				}
				if !slices.Equal(wireReq.StopSequences, []string{"END"}) {
					t.Fatalf("expected Anthropic chat stop_sequences, got %#v", wireReq.StopSequences)
				}
				if wireReq.OutputConfig == nil || wireReq.OutputConfig.TaskBudget == nil || wireReq.OutputConfig.TaskBudget.Total != 20000 {
					t.Fatalf("expected Anthropic chat output_config.task_budget, got %#v", wireReq.OutputConfig)
				}
				if wireReq.ContextManagement == nil || len(wireReq.ContextManagement.Edits) != 1 {
					t.Fatalf("expected Anthropic chat context_management, got %#v", wireReq.ContextManagement)
				}
			case "/v1/responses":
				if bifrostReq.ResponsesRequest.Params.ExtraParams["top_k"] != 40 {
					t.Fatalf("expected Responses top_k provider extra, got %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
				}
				if got, _ := bifrostReq.ResponsesRequest.Params.ExtraParams["stop"].([]string); !slices.Equal(got, []string{"END"}) {
					t.Fatalf("expected Responses stop provider extra, got %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
				}
				if _, ok := bifrostReq.ResponsesRequest.Params.ExtraParams["task_budget"]; !ok {
					t.Fatalf("expected Responses task_budget provider extra, got %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
				}
				if _, ok := bifrostReq.ResponsesRequest.Params.ExtraParams["context_management"]; !ok {
					t.Fatalf("expected Responses context_management provider extra, got %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
				}
				wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
					schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
					bifrostReq.ResponsesRequest,
					anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
				)
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				var wireBody map[string]any
				if err := json.Unmarshal(wire, &wireBody); err != nil {
					t.Fatalf("failed to unmarshal Anthropic responses wire body: %v\nbody=%s", err, string(wire))
				}
				if wireBody["top_k"] != float64(40) {
					t.Fatalf("expected Anthropic responses top_k=40, got %#v", wireBody["top_k"])
				}
				if stops, ok := wireBody["stop_sequences"].([]any); !ok || len(stops) != 1 || stops[0] != "END" {
					t.Fatalf("expected Anthropic responses stop_sequences, got %#v", wireBody["stop_sequences"])
				}
				outputConfig, _ := wireBody["output_config"].(map[string]any)
				taskBudget, _ := outputConfig["task_budget"].(map[string]any)
				if taskBudget["type"] != "tokens" || taskBudget["total"] != float64(20000) || taskBudget["remaining"] != float64(19000) {
					t.Fatalf("expected Anthropic responses output_config.task_budget, got %#v", outputConfig)
				}
				contextManagement, _ := wireBody["context_management"].(map[string]any)
				edits, _ := contextManagement["edits"].([]any)
				if len(edits) != 1 {
					t.Fatalf("expected Anthropic responses context_management edit, got %#v", contextManagement)
				}
			}
		})
	}
}

func TestAnthropicChatMCPServersReachProviderRequest(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"messages":[{"role":"user","content":"hi"}],
			"mcp_servers":[{"type":"url","url":"https://example.com/mcp","name":"remote","authorization_token":"secret"}],
			"tools":[{"type":"mcp_toolset","mcp_server_name":"remote","default_config":{"enabled":true},"configs":{"search":{"defer_loading":false}}}]
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
	if len(bifrostReq.ChatRequest.Params.MCPServers) != 1 || bifrostReq.ChatRequest.Params.MCPServers[0].Name != "remote" {
		t.Fatalf("expected Bifrost MCP server, got %#v", bifrostReq.ChatRequest.Params.MCPServers)
	}
	if len(bifrostReq.ChatRequest.Params.Tools) != 1 || bifrostReq.ChatRequest.Params.Tools[0].MCPServerName != "remote" {
		t.Fatalf("expected Bifrost mcp_toolset tool, got %#v", bifrostReq.ChatRequest.Params.Tools)
	}
	wireReq, err := anthropicprovider.ToAnthropicChatRequest(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), bifrostReq.ChatRequest)
	if err != nil {
		t.Fatalf("ToAnthropicChatRequest returned error: %v", err)
	}
	if len(wireReq.MCPServers) != 1 || wireReq.MCPServers[0].Name != "remote" || wireReq.MCPServers[0].AuthorizationToken == nil || *wireReq.MCPServers[0].AuthorizationToken != "secret" {
		t.Fatalf("expected Anthropic mcp_servers to be preserved, got %#v", wireReq.MCPServers)
	}
	if len(wireReq.Tools) != 1 || wireReq.Tools[0].MCPToolset == nil || wireReq.Tools[0].MCPToolset.MCPServerName != "remote" {
		t.Fatalf("expected Anthropic mcp_toolset tool, got %#v", wireReq.Tools)
	}
}

func TestResponsesHostedToolsInjectEffectiveCapBeforeHold(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		provider schemas.ModelProvider
		meterKey string
	}{
		{
			name:     "openai top-level max_tool_calls",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto"}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "openai required hosted tool",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"required"}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "openai versioned allowed tool_choice",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_2026_01_01"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_preview_2026_01_01"}]}}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "openai future alias",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview_latest"}],"tool_choice":"auto"}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "anthropic per-tool max_uses",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto"}`,
			provider: schemas.Anthropic,
			meterKey: meterAnthropicWebSearchCalls,
		},
		{
			name:     "anthropic required hosted tool",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"required"}`,
			provider: schemas.Anthropic,
			meterKey: meterAnthropicWebSearchCalls,
		},
		{
			name:     "anthropic versioned allowed tool_choice",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_20250305"}]}}`,
			provider: schemas.Anthropic,
			meterKey: meterAnthropicWebSearchCalls,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
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
			if bifrostReq.ResponsesRequest == nil {
				t.Fatalf("expected responses request, got %#v", bifrostReq)
			}
			switch tc.provider {
			case schemas.OpenAI:
				if bifrostReq.ResponsesRequest.Params.MaxToolCalls == nil || *bifrostReq.ResponsesRequest.Params.MaxToolCalls != defaultResponsesHostedToolCalls {
					t.Fatalf("expected OpenAI max_tool_calls=%d, got %#v", defaultResponsesHostedToolCalls, bifrostReq.ResponsesRequest.Params.MaxToolCalls)
				}
			case schemas.Anthropic:
				if len(bifrostReq.ResponsesRequest.Params.Tools) != 1 ||
					bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch == nil ||
					bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch.MaxUses == nil ||
					*bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch.MaxUses != defaultResponsesHostedToolCalls {
					t.Fatalf("expected Anthropic web_search max_uses=%d, got %#v", defaultResponsesHostedToolCalls, bifrostReq.ResponsesRequest.Params.Tools)
				}
				wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
					schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
					bifrostReq.ResponsesRequest,
					anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
				)
				if bifrostErr != nil {
					t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
				}
				if !strings.Contains(string(wire), `"max_uses":50`) {
					t.Fatalf("expected Anthropic provider body to contain injected max_uses=50, got %s", string(wire))
				}
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			meter := findMeterEstimate(state.Hold.Meters, tc.meterKey)
			if meter == nil || meter.Quantity != "50" || !meter.HoldRequired {
				t.Fatalf("expected hold meter %s quantity 50, got %#v in %#v", tc.meterKey, meter, state.Hold.Meters)
			}
		})
	}
}

func TestAnthropicResponsesExplicitMaxToolCallsBecomesMaxUses(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"hi","max_tool_calls":3,"tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto"}`),
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
	if len(bifrostReq.ResponsesRequest.Params.Tools) != 1 ||
		bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch == nil ||
		bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch.MaxUses == nil ||
		*bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebSearch.MaxUses != 3 {
		t.Fatalf("expected max_tool_calls=3 to become Anthropic max_uses=3, got %#v", bifrostReq.ResponsesRequest.Params.Tools)
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	meter := findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls)
	if meter == nil || meter.Quantity != "3" || !meter.HoldRequired {
		t.Fatalf("expected Anthropic hold meter quantity 3, got %#v in %#v", meter, state.Hold.Meters)
	}
}

func TestAnthropicResponsesWebFetchOmittedCapInjectsMaxUsesAndTokenHold(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"Fetch https://example.com and summarize it.","cache_control":{"type":"ephemeral","ttl":"1h"},"tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":1000}],"max_output_tokens":64}`),
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
	if len(bifrostReq.ResponsesRequest.Params.Tools) != 1 ||
		bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebFetch == nil ||
		bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebFetch.MaxUses == nil ||
		*bifrostReq.ResponsesRequest.Params.Tools[0].ResponsesToolWebFetch.MaxUses != defaultResponsesHostedToolCalls {
		t.Fatalf("expected omitted max_tool_calls to inject Anthropic web_fetch max_uses=%d, got %#v", defaultResponsesHostedToolCalls, bifrostReq.ResponsesRequest.Params.Tools)
	}
	wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
		schemas.NewBifrostContext(context.Background(), schemas.NoDeadline),
		bifrostReq.ResponsesRequest,
		anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
	)
	if bifrostErr != nil {
		t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
	}
	if !strings.Contains(string(wire), `"max_uses":50`) {
		t.Fatalf("expected Anthropic provider body to contain injected max_uses=50, got %s", string(wire))
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls) != nil {
		t.Fatalf("web_fetch must not reserve Anthropic web-search call meters, got %#v", state.Hold.Meters)
	}
	expectedFetchInputTokens := strconv.Itoa(1000 * defaultResponsesHostedToolCalls)
	if findMeterEstimateQuantity(state.Hold.Meters, billing.MeterInputTokens, expectedFetchInputTokens) == nil {
		t.Fatalf("expected web_fetch token hold quantity %s, got %#v", expectedFetchInputTokens, state.Hold.Meters)
	}
	if findMeterEstimateQuantity(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens, expectedFetchInputTokens) == nil {
		t.Fatalf("expected web_fetch 1h cache-write hold quantity %s, got %#v", expectedFetchInputTokens, state.Hold.Meters)
	}
	state.Signals = &StandardSignals{
		Prompt:       resolution.InputTokenLimit() + 1000*defaultResponsesHostedToolCalls,
		Completion:   resolution.OutputTokenLimit(),
		CacheWrite1h: resolution.InputTokenLimit() + 1000*defaultResponsesHostedToolCalls,
		WebSearch:    defaultResponsesHostedToolCalls,
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls) != nil {
		t.Fatalf("web_fetch final price must not include Anthropic web-search call meters, got %#v", state.FinalMeters)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover token-priced Anthropic web_fetch final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
}

func TestResponsesHostedToolsDoNotInjectCapWhenToolChoicePrecludesHostedCalls(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		provider schemas.ModelProvider
		meterKey string
	}{
		{
			name:     "openai",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"none"}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "anthropic",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"none"}`,
			provider: schemas.Anthropic,
			meterKey: meterAnthropicWebSearchCalls,
		},
		{
			name:     "openai selected function",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`,
			provider: schemas.OpenAI,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "anthropic selected function",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"},{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`,
			provider: schemas.Anthropic,
			meterKey: meterAnthropicWebSearchCalls,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
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
			switch tc.provider {
			case schemas.OpenAI:
				if bifrostReq.ResponsesRequest.Params.MaxToolCalls != nil {
					t.Fatalf("expected OpenAI max_tool_calls to remain omitted, got %#v", bifrostReq.ResponsesRequest.Params.MaxToolCalls)
				}
			case schemas.Anthropic:
				webSearchTool := (*schemas.ResponsesTool)(nil)
				for i := range bifrostReq.ResponsesRequest.Params.Tools {
					if bifrostReq.ResponsesRequest.Params.Tools[i].ResponsesToolWebSearch != nil {
						webSearchTool = &bifrostReq.ResponsesRequest.Params.Tools[i]
					}
				}
				if webSearchTool == nil || webSearchTool.ResponsesToolWebSearch.MaxUses != nil {
					t.Fatalf("expected Anthropic max_uses to remain omitted, got %#v", bifrostReq.ResponsesRequest.Params.Tools)
				}
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			if meter := findMeterEstimate(state.Hold.Meters, tc.meterKey); meter != nil {
				t.Fatalf("expected no hosted-tool hold meter for tool_choice none, got %#v in %#v", meter, state.Hold.Meters)
			}
			state.Signals = &StandardSignals{WebSearch: 1}
			if err := state.Adapter.FinalPrice(state); err != nil {
				t.Fatalf("FinalPrice returned error: %v", err)
			}
			if meter := findMeterEstimate(state.FinalMeters, tc.meterKey); meter != nil {
				t.Fatalf("expected no hosted-tool final meter when tool_choice precludes hosted calls, got %#v in %#v", meter, state.FinalMeters)
			}
		})
	}
}

func TestAnthropicResponsesWebFetchToolChoiceNoneDoesNotReserveContentHeadroom(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"input":"Summarize https://example.com/article.",
			"tools":[{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":1000}],
			"tool_choice":"none",
			"max_tool_calls":2,
			"max_output_tokens":64
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
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if meter := findMeterEstimateQuantity(state.Hold.Meters, billing.MeterInputTokens, "2000"); meter != nil {
		t.Fatalf("tool_choice none must not reserve web_fetch content headroom, got %#v in %#v", meter, state.Hold.Meters)
	}
}

func TestResponsesToolChoiceRequiresNamedFunctionSelectors(t *testing.T) {
	for _, item := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "function selector missing name",
			body: `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"function","name":"lookup"}],"tool_choice":{"type":"function"}}`,
			want: "tool_choice must name a function tool",
		},
		{
			name: "custom selector missing name",
			body: `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"custom","name":"lookup"}],"tool_choice":{"type":"custom"}}`,
			want: "tool_choice must name a custom tool",
		},
		{
			name: "allowed function missing name",
			body: `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"function","name":"lookup"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"function"}]}}`,
			want: "tool_choice.allowed_tools function entries require name",
		},
		{
			name: "allowed custom missing name",
			body: `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"},{"type":"custom","name":"lookup"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"custom"}]}}`,
			want: "tool_choice.allowed_tools custom entries require name",
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			err = state.Adapter.ValidateRequest(state)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("expected %q error, got %v", item.want, err)
			}
		})
	}
}

func TestResponsesOmittedHostedToolCapBoundsFinalPrice(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		meterKey string
	}{
		{
			name:     "openai",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"auto"}`,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "openai required",
			body:     `{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search_preview"}],"tool_choice":"required"}`,
			meterKey: MeterOpenAIResponsesWebSearchPreviewCalls,
		},
		{
			name:     "anthropic",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"auto"}`,
			meterKey: meterAnthropicWebSearchCalls,
		},
		{
			name:     "anthropic required",
			body:     `{"model":"anthropic/claude-sonnet-4-6","input":"hi","tools":[{"type":"web_search_20250305","name":"web_search"}],"tool_choice":"required"}`,
			meterKey: meterAnthropicWebSearchCalls,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(tc.body),
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
			holdMeter := findMeterEstimate(state.Hold.Meters, tc.meterKey)
			if holdMeter == nil || holdMeter.Quantity != "50" || !holdMeter.HoldRequired {
				t.Fatalf("expected omitted cap to reserve 50 hosted calls, got %#v in %#v", holdMeter, state.Hold.Meters)
			}

			state.Signals = &StandardSignals{WebSearch: defaultResponsesHostedToolCalls + 25}
			if err := state.Adapter.FinalPrice(state); err != nil {
				t.Fatalf("FinalPrice returned error: %v", err)
			}
			finalMeter := findMeterEstimate(state.FinalMeters, tc.meterKey)
			if finalMeter == nil || finalMeter.Quantity != "50" || finalMeter.HoldRequired {
				t.Fatalf("expected final hosted calls to be capped at 50, got %#v in %#v", finalMeter, state.FinalMeters)
			}
			if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
				t.Fatalf("hold must cover omitted-cap final hosted-tool charge: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
			}
		})
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
		if meter.MeterKey == MeterOpenAIResponsesWebSearchPreviewCalls {
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
	searchMeter := findMeterEstimate(state.FinalMeters, MeterOpenAIResponsesWebSearchPreviewCalls)
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

func TestOpenAIResponsesFinalNonPreviewSearchCapsFixedContentTokens(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","tools":[{"type":"web_search"}],"max_tool_calls":1}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	mutatedPricing := copyPricing(resolution.Deployment.Pricing)
	mutatedPricing[billing.MeterInputTokens] = map[string]string{billing.RatePerMillionTokens: "1000000"}
	mutatedPricing[MeterOpenAIResponsesWebSearchCalls] = map[string]string{billing.RatePerThousandCalls: "10000000000000000000"}
	resolution.Deployment.Model = "gpt-4o-mini"
	resolution.Deployment.Pricing = mutatedPricing

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

	inputMeter := findMeterEstimate(state.FinalMeters, billing.MeterInputTokens)
	if inputMeter == nil || inputMeter.Quantity != "8000" || inputMeter.HoldRequired {
		t.Fatalf("expected final fixed search content tokens capped to one call, got %#v in %#v", inputMeter, state.FinalMeters)
	}
	searchMeter := findMeterEstimate(state.FinalMeters, MeterOpenAIResponsesWebSearchCalls)
	if searchMeter == nil || searchMeter.Quantity != "1" || searchMeter.HoldRequired {
		t.Fatalf("expected final non-preview search call capped to one call, got %#v in %#v", searchMeter, state.FinalMeters)
	}
	pricing := requestLogPricingBag(state)
	assertPricingBagEntry(t, pricing, billing.MeterInputTokens, billing.RatePerMillionTokens, "8000", inputMeter.AmountUSDAtoms)
	assertPricingBagEntry(t, pricing, MeterOpenAIResponsesWebSearchCalls, billing.RatePerThousandCalls, "1", searchMeter.AmountUSDAtoms)
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover capped fixed-content web search charge: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
}

func TestResponsesIngestionTracksActualWebSearchCalls(t *testing.T) {
	adapter := OpenAIAdapter{}
	numSearchQueries := 2
	state := &State{}
	resp := &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
	}}
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
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
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
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
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse usage plus anonymous output returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 2 {
		t.Fatalf("expected usage count to avoid anonymous output double-counting, got %#v", state.Signals)
	}

	numSearchQueries = 1
	firstItemID := "ws_1"
	secondItemID := "ws_2"
	state = &State{}
	resp = &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{NumSearchQueries: &numSearchQueries},
		},
		Output: []schemas.ResponsesMessage{
			{ID: &firstItemID, Type: &webSearchType},
			{ID: &secondItemID, Type: &webSearchType},
		},
	}}
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse usage plus identified output returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 2 {
		t.Fatalf("expected identified output calls to preserve conservative count when usage is lower, got %#v", state.Signals)
	}

	itemID := "ws_1"
	state = &State{}
	for _, eventType := range []schemas.ResponsesStreamResponseType{
		schemas.ResponsesStreamResponseTypeWebSearchCallInProgress,
		schemas.ResponsesStreamResponseTypeWebSearchCallSearching,
	} {
		if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
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

	completedStatus := "completed"
	webFetchType := schemas.ResponsesMessageTypeWebFetchCall
	state = &State{}
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webFetchType, Status: &completedStatus}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse completed web fetch returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected completed web fetch not to count as billable search call, got %d", calls)
	}

	state = &State{}
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeWebFetchCallCompleted,
			ItemID: &itemID,
			Item:   &schemas.ResponsesMessage{ID: &itemID, Type: &webFetchType, Status: &completedStatus},
		},
	}); err != nil {
		t.Fatalf("IngestChunk completed web fetch returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected completed web fetch stream event not to count as billable search call, got %d", calls)
	}

	codeInterpreterType := schemas.ResponsesMessageTypeCodeInterpreterCall
	state = &State{}
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &codeInterpreterType, Status: &completedStatus}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse completed code execution returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected auto-injected code execution not to count as billable search call, got %d", calls)
	}

	failedStatus := "failed"
	state = &State{}
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webSearchType, Status: &failedStatus}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse failed web search returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected failed output web search not to count as billable search call, got %d", calls)
	}

	inProgressStatus := "in_progress"
	state = &State{}
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Output: []schemas.ResponsesMessage{{ID: &itemID, Type: &webSearchType, Status: &inProgressStatus}},
	}}, nil); err != nil {
		t.Fatalf("IngestResponse in-progress web search returned error: %v", err)
	}
	if calls := actualWebSearchCalls(state); calls != 0 {
		t.Fatalf("expected in-progress output web search not to count as billable search call, got %d", calls)
	}

	state = &State{}
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
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
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
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
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeOutputItemAdded,
			ItemID: &itemID,
			Item:   &schemas.ResponsesMessage{ID: &itemID, Type: &webSearchType},
		},
	}); err != nil {
		t.Fatalf("IngestChunk output item returned error: %v", err)
	}
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: &schemas.BifrostResponsesStreamResponse{
			Type:   schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
			ItemID: &itemID,
		},
	}); err != nil {
		t.Fatalf("IngestChunk completed returned error: %v", err)
	}
	numSearchQueries = 1
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
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
		if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
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
	if err := adapter.IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse duplicate returned error: %v", err)
	}
	signals, ok = state.Signals.(SearchUsageSignals)
	if !ok || signals.WebSearchCalls() != 1 {
		t.Fatalf("expected duplicate stream/output web search id to count once, got %#v", state.Signals)
	}

	state = &State{}
	for i := 0; i < 2; i++ {
		if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
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
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"1h"},"tools":[{"type":"web_search_20250305","name":"web_search"}],"max_tool_calls":3}`),
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
	searchContentHeadroom := resolution.Deployment.ContextWindowTokens - resolution.OutputTokenLimit() - resolution.InputTokenLimit()
	if searchContentHeadroom > 0 && findMeterEstimateQuantity(state.Hold.Meters, billing.MeterInputTokens, strconv.Itoa(searchContentHeadroom)) == nil {
		t.Fatalf("expected Anthropic web search result-token hold quantity %d, got %#v", searchContentHeadroom, state.Hold.Meters)
	}
	if searchContentHeadroom > 0 && findMeterEstimateQuantity(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens, strconv.Itoa(searchContentHeadroom)) == nil {
		t.Fatalf("expected Anthropic web search 1h cache-write hold quantity %d, got %#v", searchContentHeadroom, state.Hold.Meters)
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

func TestAnthropicResponsesWebFetchIsCappedAndTokenPriced(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"input":"Summarize https://example.com/article in one sentence.",
			"tools":[{
				"type":"web_fetch_20260309",
				"name":"web_fetch",
				"max_content_tokens":1000,
				"filters":{"allowed_domains":["example.com"]}
			}],
			"max_tool_calls":4,
			"max_output_tokens":64
		}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if !containsString(resolution.ToolTypes(), string(schemas.ResponsesToolTypeWebFetch)) {
		t.Fatalf("expected normalized web_fetch tool type, got %#v", resolution.ToolTypes())
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
	if findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls) != nil {
		t.Fatalf("web_fetch must not reserve Anthropic web-search call meters, got %#v", state.Hold.Meters)
	}

	bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	bifrostReq, err := resolution.ToBifrost(bifrostCtx)
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	wire, bifrostErr := anthropicprovider.BuildAnthropicResponsesRequestBody(
		bifrostCtx,
		bifrostReq.ResponsesRequest,
		anthropicprovider.AnthropicRequestBuildConfig{Provider: schemas.Anthropic},
	)
	if bifrostErr != nil {
		t.Fatalf("BuildAnthropicResponsesRequestBody returned error: %v", bifrostErr)
	}
	var wireBody struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(wire, &wireBody); err != nil {
		t.Fatalf("failed to unmarshal Anthropic Responses request body: %v\n%s", err, wire)
	}
	if len(wireBody.Tools) != 1 {
		t.Fatalf("expected one Anthropic web_fetch tool, got %s", wire)
	}
	tool := wireBody.Tools[0]
	allowedDomains, _ := tool["allowed_domains"].([]any)
	if tool["type"] != "web_fetch_20260309" ||
		tool["name"] != "web_fetch" ||
		tool["max_uses"] != float64(4) ||
		tool["max_content_tokens"] != float64(1000) ||
		len(allowedDomains) != 1 ||
		allowedDomains[0] != "example.com" {
		t.Fatalf("unexpected Anthropic web_fetch wire tool: %s", wire)
	}

	state.Signals = &StandardSignals{Prompt: 1200, Completion: 64, WebSearch: 99}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls) != nil {
		t.Fatalf("web_fetch final price must not include Anthropic web-search call meters, got %#v", state.FinalMeters)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover token-priced Anthropic web_fetch final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
}

func TestAnthropicResponsesToolChoiceNarrowsHostedToolHold(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"input":"Fetch https://example.com and summarize it.",
			"tools":[
				{"type":"web_search_20260318","name":"web_search"},
				{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":1000}
			],
			"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_fetch_20260309"}]},
			"max_tool_calls":2,
			"max_output_tokens":64
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
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	if findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls) != nil {
		t.Fatalf("tool_choice allowed only web_fetch, so web_search call hold must not be present: %#v", state.Hold.Meters)
	}
	if findMeterEstimateQuantity(state.Hold.Meters, billing.MeterInputTokens, "2000") == nil {
		t.Fatalf("expected web_fetch content hold for max_content_tokens * max_tool_calls, got %#v", state.Hold.Meters)
	}
	state.Signals = &StandardSignals{Prompt: resolution.InputTokenLimit() + 2000, Completion: resolution.OutputTokenLimit()}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover narrowed web_fetch final token cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
}

func TestAnthropicResponsesToolChoiceNarrowsToWebSearchHold(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/claude-sonnet-4-6",
			"input":"Search for a current source, fetch it, and summarize it.",
			"tools":[
				{"type":"web_search_20260318","name":"web_search"},
				{"type":"web_fetch_20260309","name":"web_fetch","max_content_tokens":1000}
			],
			"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_20260318"}]},
			"max_tool_calls":2,
			"max_output_tokens":64
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
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	searchMeter := findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls)
	if searchMeter == nil || searchMeter.Quantity != "2" || !searchMeter.HoldRequired {
		t.Fatalf("expected web_search call hold quantity 2, got %#v in %#v", searchMeter, state.Hold.Meters)
	}
	searchContentHeadroom := resolution.Deployment.ContextWindowTokens - resolution.OutputTokenLimit() - resolution.InputTokenLimit()
	if searchContentHeadroom > 0 && findMeterEstimateQuantity(state.Hold.Meters, billing.MeterInputTokens, strconv.Itoa(searchContentHeadroom)) == nil {
		t.Fatalf("expected web_search result-token hold quantity %d, got %#v", searchContentHeadroom, state.Hold.Meters)
	}
	state.Signals = &StandardSignals{Prompt: resolution.InputTokenLimit() + searchContentHeadroom, Completion: resolution.OutputTokenLimit(), WebSearch: 2}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover narrowed web_search final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
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

func TestAnthropicStackedPricingModifiersHoldCoversFinalPrice(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path: "/v1/responses",
		Body: []byte(`{
			"model":"anthropic/claude-opus-4-8-fast-us",
			"input":[{"role":"user","content":[{"type":"input_text","text":"hi","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],
			"cache_control":{"type":"ephemeral","ttl":"1h"},
			"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":2}],
			"max_output_tokens":64,
			"service_tier":"standard_only"
		}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "claude-opus-4-8-fast-us" {
		t.Fatalf("expected fast standard-only US deployment, got %s", resolution.Deployment.ID)
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
	holdCache := findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens)
	if holdCache == nil {
		t.Fatalf("expected 1h cache-write hold meter, got %#v", state.Hold.Meters)
	}
	holdSearch := findMeterEstimate(state.Hold.Meters, meterAnthropicWebSearchCalls)
	if holdSearch == nil || holdSearch.Quantity != "2" || !holdSearch.HoldRequired {
		t.Fatalf("expected capped Anthropic web-search hold meter for two calls, got %#v in %#v", holdSearch, state.Hold.Meters)
	}

	state.Signals = &StandardSignals{
		Prompt:       resolution.InputTokenLimit(),
		Completion:   resolution.OutputTokenLimit(),
		CacheWrite1h: resolution.InputTokenLimit() / 2,
		WebSearch:    3,
		ActualSpeed:  "fast",
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms) < 0 {
		t.Fatalf("hold must cover stacked Anthropic final cost: hold=%s final=%s holdMeters=%#v finalMeters=%#v", state.Hold.MaxUSDAtoms, state.FinalCostUSDAtoms, state.Hold.Meters, state.FinalMeters)
	}
	finalCache := findMeterEstimate(state.FinalMeters, billing.MeterCacheWrite1hInputTokens)
	if finalCache == nil {
		t.Fatalf("expected 1h cache-write final meter, got %#v", state.FinalMeters)
	}
	finalSearch := findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls)
	if finalSearch == nil || finalSearch.Quantity != "2" || finalSearch.HoldRequired {
		t.Fatalf("expected final Anthropic web-search meter capped to two calls, got %#v in %#v", finalSearch, state.FinalMeters)
	}
	pricing := requestLogPricingBag(state)
	assertPricingBagEntry(t, pricing, billing.MeterCacheWrite1hInputTokens, billing.RatePerMillionTokens, finalCache.Quantity, finalCache.AmountUSDAtoms)
	assertPricingBagEntry(t, pricing, meterAnthropicWebSearchCalls, billing.RatePerThousandCalls, "2", finalSearch.AmountUSDAtoms)
	if actualWebSearchCalls(state) != 3 {
		t.Fatalf("expected telemetry to retain three observed calls while billing two, got %#v", state.Signals)
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
	assertMeterQuantity(t, state.FinalMeters, billing.MeterInputTokens, "400")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCachedInputTokens, "100")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCacheWrite5mInputTokens, "200")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCacheWrite1hInputTokens, "300")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterOutputTokens, "500")
}

func TestResponsesIngestionPreservesCacheWriteMeters(t *testing.T) {
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
	}
	resp := &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		Usage: &schemas.ResponsesResponseUsage{
			InputTokens:  1000,
			OutputTokens: 500,
			TotalTokens:  1500,
			InputTokensDetails: &schemas.ResponsesResponseInputTokens{
				CachedReadTokens:  100,
				CachedWriteTokens: 500,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 200,
					CachedWriteTokens1h: 300,
				},
			},
		},
	}}
	if err := (DefaultAdapter{}).IngestResponse(state, resp, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	if err := (DefaultAdapter{}).FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms != "2760" {
		t.Fatalf("expected cache-aware final price 2760, got %s", state.FinalCostUSDAtoms)
	}
	assertMeterQuantity(t, state.FinalMeters, billing.MeterInputTokens, "400")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCachedInputTokens, "100")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCacheWrite5mInputTokens, "200")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterCacheWrite1hInputTokens, "300")
	assertMeterQuantity(t, state.FinalMeters, billing.MeterOutputTokens, "500")
}

func findMeterEstimate(meters []catalog.MeterEstimate, key string) *catalog.MeterEstimate {
	for i := range meters {
		if meters[i].MeterKey == key {
			return &meters[i]
		}
	}
	return nil
}

func findMeterEstimateQuantity(meters []catalog.MeterEstimate, key string, quantity string) *catalog.MeterEstimate {
	for i := range meters {
		if meters[i].MeterKey == key && meters[i].Quantity == quantity {
			return &meters[i]
		}
	}
	return nil
}

func countMeterEstimates(meters []catalog.MeterEstimate, key string) int {
	count := 0
	for _, meter := range meters {
		if meter.MeterKey == key {
			count++
		}
	}
	return count
}

func assertMeterQuantity(t *testing.T, meters []catalog.MeterEstimate, key string, quantity string) {
	t.Helper()
	meter := findMeterEstimate(meters, key)
	if meter == nil {
		t.Fatalf("expected meter %s in %#v", key, meters)
	}
	if meter.Quantity != quantity {
		t.Fatalf("expected meter %s quantity %s, got %#v", key, quantity, meter)
	}
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
