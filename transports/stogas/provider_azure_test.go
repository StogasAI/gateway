package stogas

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestAzureGPT56CacheFieldsReachBothReviewedWireFormats(t *testing.T) {
	tests := []struct {
		body string
		path string
	}{
		{
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":64,"prompt_cache_key":"tenant-a","prompt_cache_retention":"24h"}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","max_output_tokens":64,"prompt_cache_key":"tenant-a","prompt_cache_retention":"24h"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			state := resolveAzureState(t, tc.path, tc.body)
			request, err := state.Resolution.ToBifrost(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			var wire any
			switch {
			case request.ChatRequest != nil:
				wire = openaiprovider.ToOpenAIChatRequest(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), request.ChatRequest)
			case request.ResponsesRequest != nil:
				wire = openaiprovider.ToOpenAIResponsesRequest(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), request.ResponsesRequest)
			default:
				t.Fatalf("unexpected Azure request: %#v", request)
			}
			encoded, err := sonic.Marshal(wire)
			if err != nil {
				t.Fatalf("marshal Azure wire request: %v", err)
			}
			var raw map[string]json.RawMessage
			if err := sonic.Unmarshal(encoded, &raw); err != nil {
				t.Fatalf("decode Azure wire request: %v", err)
			}
			if rawString(raw["prompt_cache_key"]) != "tenant-a" || rawString(raw["prompt_cache_retention"]) != "24h" {
				t.Fatalf("Azure cache fields missing from wire request: %s", encoded)
			}
			if rawString(raw["model"]) != "gpt-5.6-sol" {
				t.Fatalf("Azure wire model must be the customer deployment alias source, got %s", encoded)
			}
		})
	}
}

func TestAzureRejectsMalformedAndMaliciousCacheParameters(t *testing.T) {
	longKey := strings.Repeat("a", maxPromptCacheKeyBytes+1)
	tests := map[string]string{
		"empty key":            `"prompt_cache_key":""`,
		"line break key":       `"prompt_cache_key":"tenant\nother"`,
		"non-string key":       `"prompt_cache_key":1`,
		"oversized key":        `"prompt_cache_key":"` + longKey + `"`,
		"non-string retention": `"prompt_cache_retention":{"ttl":"24h"}`,
		"in-memory retention":  `"prompt_cache_retention":"in_memory"`,
		"other retention":      `"prompt_cache_retention":"30m"`,
		"explicit options":     `"prompt_cache_options":{"mode":"explicit","ttl":"30m"}`,
	}
	for name, field := range tests {
		t.Run(name, func(t *testing.T) {
			body := `{"model":"gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":64,` + field + `}`
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Body: []byte(body), Method: "POST", Path: "/v1/chat/completions"})
			if err != nil {
				return
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err == nil {
				t.Fatal("invalid Azure cache input was accepted")
			}
		})
	}

	breakpointBody := `{"model":"gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":[{"type":"text","text":"hi","prompt_cache_breakpoint":{"mode":"explicit"}}]}],"max_completion_tokens":64}`
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Body: []byte(breakpointBody), Method: "POST", Path: "/v1/chat/completions"})
	if err == nil {
		state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
		if err := state.Adapter.ValidateRequest(state); err == nil {
			t.Fatal("Azure explicit prompt cache breakpoint was accepted")
		}
	}
}

func TestAzureAllowsClientExecutedToolsAndRejectsRemoteMCP(t *testing.T) {
	valid := []struct {
		body string
		path string
	}{
		{
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]}`,
		},
	}
	for _, tc := range valid {
		t.Run("valid "+tc.path, func(t *testing.T) {
			resolveAzureState(t, tc.path, tc.body)
		})
	}

	invalid := []struct {
		body string
		path string
	}{
		{
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"custom","name":"shell","format":{"type":"text"}}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"web_search"}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"mcp","server_label":"docs","server_url":"https://example.com","require_approval":"never"}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"mcp","server_label":"calendar","connector_id":"connector_googlecalendar","require_approval":"never"}]}`,
		},
	}
	for _, tc := range invalid {
		t.Run("invalid "+tc.path+tc.body, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Body: []byte(tc.body), Method: "POST", Path: tc.path})
			if err != nil {
				return
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err == nil {
				t.Fatal("unsupported Azure tool was accepted")
			}
		})
	}
}

func TestAzureClaudeUsesAnthropicPolicyAndExactMessagesWireFormat(t *testing.T) {
	tests := []struct {
		path string
		body string
	}{
		{
			path: "/v1/chat/completions",
			body: `{"model":"azure-claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"1h"},"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":2}},{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"input_tokens","value":5000},"clear_tool_inputs":true,"exclude_tools":["preserve"],"keep":{"type":"tool_uses","value":3},"trigger":{"type":"tool_uses","value":4}},{"type":"compact_20260112","instructions":"keep summary","pause_after_compaction":true,"trigger":{"type":"input_tokens","value":50000}}]},"max_completion_tokens":64,"stop_sequences":["END"],"top_k":40}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"azure-claude-sonnet-4-6","input":"hi","cache_control":{"type":"ephemeral","ttl":"1h"},"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":2}},{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"input_tokens","value":5000},"clear_tool_inputs":true,"exclude_tools":["preserve"],"keep":{"type":"tool_uses","value":3},"trigger":{"type":"tool_uses","value":4}},{"type":"compact_20260112","instructions":"keep summary","pause_after_compaction":true,"trigger":{"type":"input_tokens","value":50000}}]},"max_output_tokens":64,"stop_sequences":["END"],"top_k":40}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			state := resolveAzureState(t, tc.path, tc.body)
			if !azureDeploymentUsesAnthropicWire(state) {
				t.Fatalf("Azure Claude deployment did not select Anthropic policy: %#v", state.Resolution.Deployment.Upstream)
			}

			bifrostContext := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			bifrostContext.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.RequestType)
			request, err := state.Resolution.ToBifrost(bifrostContext)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if err := PrepareProviderRequest(bifrostContext, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}

			var body []byte
			switch {
			case request.ChatRequest != nil:
				body = preparedProviderBody(t, bifrostContext, request.ChatRequest)
			case request.ResponsesRequest != nil:
				body = preparedProviderBody(t, bifrostContext, request.ResponsesRequest)
			default:
				t.Fatalf("unexpected Azure Claude request: %#v", request)
			}
			var wire map[string]any
			if err := sonic.Unmarshal(body, &wire); err != nil {
				t.Fatalf("decode Azure Claude wire request: %v", err)
			}
			if wire["model"] != "claude-sonnet-4-6" || wire["max_tokens"] != float64(64) || wire["top_k"] != float64(40) {
				t.Fatalf("Azure Claude wire fields were not preserved: %s", body)
			}
			stops, ok := wire["stop_sequences"].([]any)
			if !ok || len(stops) != 1 || stops[0] != "END" {
				t.Fatalf("Azure Claude stop_sequences were not preserved: %s", body)
			}
			cacheControl, ok := wire["cache_control"].(map[string]any)
			if !ok || cacheControl["type"] != "ephemeral" || cacheControl["ttl"] != "1h" {
				t.Fatalf("Azure Claude cache_control was not preserved: %s", body)
			}
			contextManagement, ok := wire["context_management"].(map[string]any)
			edits, editsOK := contextManagement["edits"].([]any)
			if !ok || !editsOK || len(edits) != 3 {
				t.Fatalf("Azure Claude context_management was not preserved: %s", body)
			}
			clearThinking, thinkingOK := edits[0].(map[string]any)
			thinkingKeep, keepOK := clearThinking["keep"].(map[string]any)
			clearTools, toolsOK := edits[1].(map[string]any)
			clearAtLeast, clearAtLeastOK := clearTools["clear_at_least"].(map[string]any)
			compact, compactOK := edits[2].(map[string]any)
			compactTrigger, compactTriggerOK := compact["trigger"].(map[string]any)
			if !thinkingOK || !keepOK || clearThinking["type"] != "clear_thinking_20251015" ||
				thinkingKeep["type"] != "thinking_turns" || thinkingKeep["value"] != float64(2) ||
				!toolsOK || !clearAtLeastOK || clearTools["type"] != "clear_tool_uses_20250919" ||
				clearAtLeast["type"] != "input_tokens" || clearAtLeast["value"] != float64(5000) ||
				!compactOK || !compactTriggerOK || compact["type"] != "compact_20260112" ||
				compact["pause_after_compaction"] != true || compactTrigger["value"] != float64(50000) {
				t.Fatalf("Azure Claude context_management changed on provider wire: %s", body)
			}
			if _, obsolete := clearTools["clear_at_last"]; obsolete {
				t.Fatalf("Azure Claude wire used obsolete clear_at_last: %s", body)
			}
			for _, field := range []string{"max_completion_tokens", "max_output_tokens", "prompt_cache_key", "service_tier", "store", "task_budget"} {
				if _, exists := wire[field]; exists {
					t.Fatalf("Azure Claude wire retained OpenAI-only field %q: %s", field, body)
				}
			}
		})
	}
}

func TestAzureClaudeRejectsOpenAIOnlyCacheAndMCPFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "prompt cache key",
			body: `{"model":"azure-claude-sonnet-4-6","input":"hi","prompt_cache_key":"tenant","max_output_tokens":64}`,
		},
		{
			name: "prompt cache options",
			body: `{"model":"azure-claude-sonnet-4-6","input":"hi","prompt_cache_options":{"mode":"explicit"},"max_output_tokens":64}`,
		},
		{
			name: "task budget",
			body: `{"model":"azure-claude-sonnet-4-6","input":"hi","task_budget":{"type":"tokens","total":20000},"max_output_tokens":64}`,
		},
		{
			name: "MCP connector",
			body: `{"model":"azure-claude-sonnet-4-6","input":"hi","tools":[{"type":"mcp","server_label":"calendar","connector_id":"connector_googlecalendar"}],"max_output_tokens":64}`,
		},
		{
			name: "MCP headers",
			body: `{"model":"azure-claude-sonnet-4-6","input":"hi","tools":[{"type":"mcp","server_label":"docs","server_url":"https://example.com","headers":{"authorization":"secret"}}],"max_output_tokens":64}`,
		},
		{
			name: "MCP approval",
			body: `{"model":"azure-claude-sonnet-4-6","input":"hi","tools":[{"type":"mcp","server_label":"docs","server_url":"https://example.com","require_approval":"never"}],"max_output_tokens":64}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Body: []byte(tc.body), Method: "POST", Path: "/v1/responses"})
			if err != nil {
				return
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err == nil {
				t.Fatal("Azure Claude accepted a field that the Anthropic wire translation cannot preserve")
			}
		})
	}
}

func TestAzureClaudeHoldCoversAnthropicCacheWriteAndToolOverhead(t *testing.T) {
	state := resolveAzureState(
		t,
		"/v1/chat/completions",
		`{"model":"azure-claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"1h"},"max_completion_tokens":64,"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`,
	)
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	cacheWrite := findMeterEstimate(state.Hold.Meters, billing.MeterCacheWrite1hInputTokens)
	if cacheWrite == nil {
		t.Fatalf("Azure Claude hold omitted the one-hour cache-write rate: %#v", state.Hold.Meters)
	}
	toolOverhead := anthropicToolSystemPromptHoldTokens(state.Resolution.Deployment.Upstream.Model, state.Resolution.ToolTypes())
	wantQuantity := state.Resolution.InputTokenLimit() + toolOverhead
	if cacheWrite.Quantity != strconv.Itoa(wantQuantity) {
		t.Fatalf("Azure Claude hold omitted tool-system overhead: got %s want %d", cacheWrite.Quantity, wantQuantity)
	}

	state.Signals = &StandardSignals{
		Prompt:       state.Resolution.InputTokenLimit(),
		Completion:   state.Resolution.OutputTokenLimit(),
		CacheWrite1h: state.Resolution.InputTokenLimit(),
	}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms) < 0 {
		t.Fatalf("Azure Claude hold does not cover cache-write execution: hold=%s final=%s", state.Hold.EstimatedUpstreamCostUSDAtoms, state.UpstreamCostUSDAtoms)
	}
}

func resolveAzureState(t *testing.T, path string, body string) *State {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Body: []byte(body), Method: "POST", Path: path})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Provider != schemas.Azure {
		t.Fatalf("provider = %q, want Azure", resolution.Provider)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatalf("SanitizeRequest returned error: %v", err)
	}
	return state
}
