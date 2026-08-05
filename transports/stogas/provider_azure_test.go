package stogas

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
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
			request, err := state.Resolution.ToBifrost(schemas.NewBifrostContext(nil, schemas.NoDeadline))
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			var wire any
			switch {
			case request.ChatRequest != nil:
				wire = openaiprovider.ToOpenAIChatRequest(schemas.NewBifrostContext(nil, schemas.NoDeadline), request.ChatRequest)
			case request.ResponsesRequest != nil:
				wire = openaiprovider.ToOpenAIResponsesRequest(schemas.NewBifrostContext(nil, schemas.NoDeadline), request.ResponsesRequest)
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

func TestAzureAllowsClientExecutedToolsAndApprovalFreeMCP(t *testing.T) {
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
		{
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"custom","name":"shell","format":{"type":"text"}}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"mcp","server_label":"docs","server_url":"https://example.com","headers":{"x-api-key":"secret"},"require_approval":"never"}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"mcp","server_label":"calendar","connector_id":"connector_googlecalendar","authorization":"secret","require_approval":"never"}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"mcp","server_label":"docs","server_url":"https://example.com","allowed_tools":null,"headers":{},"require_approval":"never"}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"mcp","server_label":"docs","server_url":"https://example.com","allowed_tools":{"read_only":false},"require_approval":"never"}]}`,
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
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"web_search"}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"mcp","server_label":"docs","server_url":"https://example.com","require_approval":"always"}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"mcp","server_label":"docs","server_url":"https://example.com","connector_id":"connector_googlecalendar","require_approval":"never"}]}`,
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
