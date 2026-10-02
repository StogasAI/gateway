package catalog

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestCatalogCapabilitiesFilterBeforeCredentialPreparation(t *testing.T) {
	for _, route := range []Route{RouteChat, RouteResponses} {
		for _, tc := range []struct {
			name, chat, responses string
			disable               func(*Capabilities)
		}{
			{"stream", `"stream":true`, `"stream":true`, func(c *Capabilities) { c.Streaming = false }},
			{"functions", `"tools":[{"type":"function","function":{"name":"test","parameters":{"type":"object"}}}]`, `"tools":[{"type":"function","name":"test","parameters":{"type":"object"}}]`, func(c *Capabilities) { c.FunctionCalling = false }},
			{"parallel calls", `"parallel_tool_calls":true`, `"parallel_tool_calls":true`, func(c *Capabilities) { c.ParallelFunctionCalling = false }},
			{"tool choice", `"tool_choice":"required"`, `"tool_choice":"required"`, func(c *Capabilities) { c.ToolChoice = false }},
			{"structured output", `"response_format":{"type":"json_schema","json_schema":{"name":"test","schema":{"type":"object"}}}`, `"text":{"format":{"type":"json_schema","name":"test","schema":{"type":"object"}}}`, func(c *Capabilities) { c.StructuredOutputs = false }},
			{"system message", `"messages":[{"role":"developer","content":"hello"}]`, `"instructions":"hello"`, func(c *Capabilities) { c.SystemMessages = false }},
			{"prompt caching", `"prompt_cache_key":"test"`, `"prompt_cache_key":"test"`, func(c *Capabilities) { c.ImplicitPromptCaching = false }},
			{"explicit prompt caching", `"prompt_cache_options":{"mode":"explicit"}`, `"prompt_cache_options":{"mode":"explicit"}`, func(c *Capabilities) { c.ExplicitPromptCaching = false }},
		} {
			for _, pinned := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/pinned=%t", route, tc.name, pinned), func(t *testing.T) {
					snap := loadTestCatalog(t)
					first := snap.graph.Deployments["openai-gpt-5.6-sol"]
					first.Capabilities.ExplicitPromptCaching = true
					second := snap.graph.Deployments["anthropic-claude-sonnet-4-6"]
					second.Capabilities = first.Capabilities
					tc.disable(&first.Capabilities)
					snap.graph.Deployments["openai-gpt-5.6-sol"] = first
					snap.graph.Deployments["anthropic-claude-sonnet-4-6"] = second
					config := policyConfig(1)
					config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6"}}
					fields := map[string]json.RawMessage{}
					extra, path := tc.chat, "/v1/chat/completions"
					fields["messages"] = json.RawMessage(`[{"role":"user","content":"hello"}]`)
					if route == RouteResponses {
						extra, path = tc.responses, "/v1/responses"
						delete(fields, "messages")
						fields["input"] = json.RawMessage(`"hello"`)
					}
					if err := json.Unmarshal([]byte("{"+extra+"}"), &fields); err != nil {
						t.Fatal(err)
					}
					if pinned {
						fields["model"] = json.RawMessage(`"openai-gpt-5.6-sol"`)
					}
					body, _ := json.Marshal(fields)
					checks := 0
					resolved, err := ResolveRequest(RequestInput{Body: body, Method: "POST", Path: path, Policy: config,
						CheckCandidate: func(provider schemas.ModelProvider, _ int, _ Deployment) error {
							checks++
							if provider != schemas.Anthropic {
								t.Fatal("prepared an incompatible credential")
							}
							return nil
						}})
					if pinned {
						if err == nil || PublicError(err).StatusCode != 400 || checks != 0 {
							t.Fatalf("incompatible pinned request was not rejected early: %v, %d", err, checks)
						}
					} else if err != nil || checks != 1 || resolved.Deployment.ID != "anthropic-claude-sonnet-4-6" {
						t.Fatalf("compatible deployment was not selected: %v, %d", err, checks)
					}
				})
			}
		}
	}
}

func TestNeutralControlsDoNotRequireCatalogCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		route      Route
	}{
		{"chat text", `{"stream":false,"parallel_tool_calls":false,"tool_choice":"none","functions":[],"tools":[],"response_format":{"type":"text"},"messages":[{"role":"user","content":"hello"}]}`, RouteChat},
		{"chat JSON mode", `{"response_format":{"type":"json_object"},"tool_choice":"auto","messages":[{"role":"assistant","content":"hello"}]}`, RouteChat},
		{"responses JSON mode", `{"text":{"format":{"type":"json_object"}},"input":"hello","instructions":"","tools":[],"tool_choice":"auto"}`, RouteResponses},
		{"responses text blocks", `{"text":{"format":{"type":"text"}},"input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}`, RouteResponses},
		{"null controls", `{"stream":null,"parallel_tool_calls":null,"tool_choice":null,"tools":null,"response_format":null,"prompt_cache_key":null,"prompt_cache_retention":null,"prompt_cache_options":null,"instructions":null}`, RouteResponses},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := DecodeRequestBody([]byte(tc.body), nil)
			if err != nil {
				t.Fatal(err)
			}
			required, err := requestCapabilities(raw, tc.route, Capabilities{})
			if err != nil || validateRequestCapabilities(required, Capabilities{}) != nil {
				t.Fatalf("neutral controls require unsupported capabilities: %+v, %v", required, err)
			}
		})
	}
}

func TestCapabilityProjectionSkipsOnlyUniversallySupportedFeatures(t *testing.T) {
	for _, route := range []Route{RouteChat, RouteResponses} {
		body := `{"stream":true,"parallel_tool_calls":true,"tool_choice":"required","tools":[{"type":"function"}],"response_format":{"type":"json_schema"},"text":{"format":{"type":"json_schema"}},"messages":[{"role":"system","content":"hello"}],"input":[{"role":"developer","content":"hello"}]}`
		raw, err := DecodeRequestBody([]byte(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		all := Capabilities{Streaming: true, ParallelFunctionCalling: true, ToolChoice: true, FunctionCalling: true, StructuredOutputs: true, SystemMessages: true}
		for _, shared := range []Capabilities{{}, all} {
			required, err := requestCapabilities(raw, route, shared)
			if err != nil || validateRequestCapabilities(required, all) != nil {
				t.Fatalf("supported request failed: %+v, %v", required, err)
			}
			if !shared.Streaming && (!required.Streaming || !required.ParallelFunctionCalling || !required.ToolChoice || !required.FunctionCalling || !required.StructuredOutputs || !required.SystemMessages) {
				t.Fatalf("projection omitted a requested feature: %+v", required)
			}
		}
	}
}
