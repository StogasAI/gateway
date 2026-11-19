package stogas

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	bifrost "github.com/maximhq/bifrost/core"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/catalog/catalogtest"
)

func TestAzureGPT56CacheFieldsReachBothReviewedWireFormats(t *testing.T) {
	tests := []struct {
		body string
		path string
	}{
		{
			path: "/v1/chat/completions",
			body: `{"model":"azure-gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":64,"prompt_cache_key":"tenant-a","prompt_cache_retention":"24h"}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"azure-gpt-5.6-sol","provider":"azure","input":"hi","max_output_tokens":64,"prompt_cache_key":"tenant-a","prompt_cache_retention":"24h"}`,
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
		"other retention":      `"prompt_cache_retention":"30m"`,
		"unpriced ttl":         `"prompt_cache_options":{"mode":"explicit","ttl":"1h"}`,
	}
	const request = `{"model":"azure-gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":64`
	// The request passes without the field, so each refusal is the field's.
	if err := validateResolvedChat(t, request+`}`); err != nil {
		t.Fatalf("the Azure request without a cache field was refused: %v", err)
	}
	for name, field := range tests {
		t.Run(name, func(t *testing.T) {
			if validateResolvedChat(t, request+`,`+field+`}`) == nil {
				t.Fatal("invalid Azure cache input was accepted")
			}
		})
	}

}

func TestAzureTakesOnlyClientExecutedTools(t *testing.T) {
	valid := []struct {
		body string
		path string
	}{
		{
			path: "/v1/chat/completions",
			body: `{"model":"azure-gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"azure-gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]}`,
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
			body: `{"model":"azure-gpt-5.6-sol","provider":"azure","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"custom","name":"shell","format":{"type":"text"}}]}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"azure-gpt-5.6-sol","provider":"azure","input":"hi","tools":[{"type":"web_search"}]}`,
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
			body: `{"model":"azure-claude-opus-4-8-anthropic-hosted","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"1h"},"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":2}},{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"input_tokens","value":5000},"clear_tool_inputs":true,"exclude_tools":["preserve"],"keep":{"type":"tool_uses","value":3},"trigger":{"type":"tool_uses","value":4}},{"type":"compact_20260112","instructions":"keep summary","pause_after_compaction":true,"trigger":{"type":"input_tokens","value":50000}}]},"max_completion_tokens":64,"stop_sequences":["END"],"top_k":40}`,
		},
		{
			path: "/v1/responses",
			body: `{"model":"azure-claude-opus-4-8-anthropic-hosted","input":"hi","cache_control":{"type":"ephemeral","ttl":"1h"},"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":{"type":"thinking_turns","value":2}},{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"input_tokens","value":5000},"clear_tool_inputs":true,"exclude_tools":["preserve"],"keep":{"type":"tool_uses","value":3},"trigger":{"type":"tool_uses","value":4}},{"type":"compact_20260112","instructions":"keep summary","pause_after_compaction":true,"trigger":{"type":"input_tokens","value":50000}}]},"max_output_tokens":64,"stop_sequences":["END"],"top_k":40}`,
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
			if wire["model"] != "claude-opus-4-8" || wire["max_tokens"] != float64(64) || wire["top_k"] != float64(40) {
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

// Foundry enforces a JSON schema itself on both Claude hostings, so Azure Claude gets
// output_config.format as Anthropic does. A synthetic tool would leave the schema unenforced,
// go unforced with thinking on, and take over tool_choice from the client's own tools.
func TestAzureClaudeSendsStructuredOutputsNatively(t *testing.T) {
	const schema = `{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}`
	const parameters = `{"type":"object","properties":{"q":{"type":"string"}},"required":["q"],"additionalProperties":false}`
	for _, model := range []string{"azure-claude-opus-4-8", "azure-claude-opus-4-8-anthropic-hosted"} {
		for path, body := range map[string]string{
			"/v1/chat/completions": `{"model":"` + model + `","messages":[{"role":"user","content":"hi"}],"tool_choice":"auto",` +
				`"tools":[{"type":"function","function":{"name":"lookup","parameters":` + parameters + `,"strict":true}}],` +
				`"response_format":{"type":"json_schema","json_schema":{"name":"place","strict":true,"schema":` + schema + `}}}`,
			"/v1/responses": `{"model":"` + model + `","input":"hi","tool_choice":"auto",` +
				`"tools":[{"type":"function","name":"lookup","parameters":` + parameters + `,"strict":true}],` +
				`"text":{"format":{"type":"json_schema","name":"place","strict":true,"schema":` + schema + `}}}`,
		} {
			t.Run(model+path, func(t *testing.T) {
				state := resolveAzureState(t, path, body)
				ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.RequestType)
				request, err := state.Resolution.ToBifrost(ctx)
				if err != nil {
					t.Fatalf("ToBifrost returned error: %v", err)
				}
				if err := PrepareProviderRequest(ctx, state, request); err != nil {
					t.Fatalf("PrepareProviderRequest returned error: %v", err)
				}
				var wire []byte
				if request.ChatRequest != nil {
					wire = preparedProviderBody(t, ctx, request.ChatRequest)
				} else {
					wire = preparedProviderBody(t, ctx, request.ResponsesRequest)
				}
				var decoded struct {
					OutputConfig struct {
						Format struct {
							Type   string          `json:"type"`
							Schema json.RawMessage `json:"schema"`
						} `json:"format"`
					} `json:"output_config"`
					ToolChoice map[string]any `json:"tool_choice"`
					Tools      []struct {
						Name   string `json:"name"`
						Strict bool   `json:"strict"`
					} `json:"tools"`
				}
				if err := sonic.Unmarshal(wire, &decoded); err != nil {
					t.Fatalf("decode Azure Claude wire request: %v", err)
				}
				if decoded.OutputConfig.Format.Type != "json_schema" || !strings.Contains(string(decoded.OutputConfig.Format.Schema), `"city"`) {
					t.Fatalf("output_config.format missing: %s", wire)
				}
				if strings.Contains(string(wire), "bf_so_") || len(decoded.Tools) != 1 || decoded.Tools[0].Name != "lookup" || !decoded.Tools[0].Strict {
					t.Fatalf("tools are not the client's strict tool alone: %s", wire)
				}
				if decoded.ToolChoice["type"] != "auto" {
					t.Fatalf("tool_choice = %v, want the client's auto: %s", decoded.ToolChoice, wire)
				}
			})
		}
	}
}

// Customers name their Azure deployments, so core must take the wire format from the catalog model.
func TestAzureClaudeWithCustomDeploymentNameUsesAnthropicEndpoint(t *testing.T) {
	const deploymentName = "sonnet-prod"
	var path, model string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		path, model = r.URL.Path, body.Model
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	t.Cleanup(server.Close)

	state := resolveAzureState(t, "/v1/chat/completions", `{"model":"azure-claude-opus-4-8-anthropic-hosted","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":64}`)
	if err := state.Resolution.SetWireModel(deploymentName); err != nil {
		t.Fatal(err)
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.RequestType)
	request, err := state.Resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatalf("PrepareProviderRequest returned error: %v", err)
	}
	client, err := bifrost.Init(t.Context(), schemas.BifrostConfig{
		Account: &account{
			keys: map[schemas.ModelProvider]schemas.Key{schemas.Azure: {
				ID: "test", Name: "test", Value: *schemas.NewSecretVar("test-key"),
				Models: schemas.WhiteList{deploymentName}, Weight: 1, Enabled: schemas.Ptr(true),
				AzureKeyConfig: &schemas.AzureKeyConfig{Endpoint: *schemas.NewSecretVar(server.URL)},
			}},
			providerConfigs: map[schemas.ModelProvider]schemas.ProviderConfig{schemas.Azure: newProviderConfig(server.URL, true, false)},
		},
		InitialPoolSize: 1,
		Logger:          bifrost.NewDefaultLogger(schemas.LogLevelError),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Shutdown)
	if _, bifrostErr := client.ChatCompletionRequest(ctx, request.ChatRequest); bifrostErr != nil {
		t.Fatalf("Azure Claude request failed: %v", bifrostErr.Error)
	}
	if path != "/anthropic/v1/messages" || model != deploymentName {
		t.Fatalf("Azure Claude request went to %s for model %q", path, model)
	}
}

func TestAzureClaudeRejectsPromptCacheOptions(t *testing.T) {
	// The request passes without the field, so the refusal is the field's.
	if err := validateResolvedResponses(t, `{"model":"azure-claude-opus-4-8-anthropic-hosted","input":"hi","max_output_tokens":64}`); err != nil {
		t.Fatalf("the Azure Claude request without the field was refused: %v", err)
	}
	if validateResolvedResponses(t, `{"model":"azure-claude-opus-4-8-anthropic-hosted","input":"hi","prompt_cache_options":{"mode":"explicit"},"max_output_tokens":64}`) == nil {
		t.Fatal("Azure Claude accepted prompt_cache_options, which the Anthropic wire translation cannot preserve")
	}
}

func TestAzureClaudeHoldCoversAnthropicCacheWriteAndToolOverhead(t *testing.T) {
	state := resolveAzureState(
		t,
		"/v1/chat/completions",
		`{"model":"azure-claude-opus-4-8-anthropic-hosted","messages":[{"role":"user","content":"hi"}],"cache_control":{"type":"ephemeral","ttl":"1h"},"max_completion_tokens":64,"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`,
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
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD) < 0 {
		t.Fatalf("Azure Claude hold does not cover cache-write execution: hold=%s final=%s", state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD)
	}
}

// Claude on Azure runs Anthropic's web search, which Foundry bills per call, so Azure counts and
// prices the calls as Anthropic's API does.
func TestAzureClaudeBillsWebSearchCallsAsAnthropicDoes(t *testing.T) {
	state := resolveAzureState(t, "/v1/responses", `{"model":"azure-claude-opus-4-8-anthropic-hosted","input":"Search the news.","tools":[{"type":"web_search_20250305","name":"web_search"}],"max_tool_calls":3,"max_output_tokens":64}`)
	if err := state.Adapter.EstimateHold(state); err != nil {
		t.Fatalf("EstimateHold returned error: %v", err)
	}
	response := validUnaryResponsesProviderResponse("resp_1")
	response.Output = []schemas.ResponsesMessage{
		providerWebSearchOutputItem("ws_1", "https://example.com/a"),
		providerWebSearchOutputItem("ws_2", "https://example.com/b"),
	}
	state.Signals = &StandardSignals{Prompt: 10, Completion: 10}
	if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: response}, nil); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if meter := findMeterEstimate(state.FinalMeters, meterAnthropicWebSearchCalls); meter == nil || meter.Quantity != "2" {
		t.Fatalf("web search calls were not billed: %#v", state.FinalMeters)
	}
	if compareMoneyStrings(state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD) < 0 {
		t.Fatalf("hold %s does not cover the cost %s", state.Hold.EstimatedUpstreamCostUSD, state.UpstreamCostUSD)
	}
}

// TestAzureOtherFormatsSendWhatAzureTook prepares a client's request in OpenAI's own fields, with
// the customer's own credential, for each recorded Azure model format. Azure OpenAI models would
// receive user, safety_identifier and store from it, but the body must equal the request that Azure
// took in the recording (capture azure/other-model-formats-request-fields).
func TestAzureOtherFormatsSendWhatAzureTook(t *testing.T) {
	recorded := providerCapture(t, "azure/other-model-formats-request-fields")
	for deployment, model := range map[string]string{
		"azure-grok-4.7":           "grok-4.7",
		"azure-kimi-k3.1-pro":      "kimi-k3.1-pro",
		"azure-mistral-large-2512": "mistral-large-3",
		"azure-mistral-large-4":    "mistral-large-4",
	} {
		t.Run(model, func(t *testing.T) {
			took := exchange(t, recorded, model+" max_tokens and a system message")
			body := azureCustomerChatBody(t, `{"model":"`+deployment+`","messages":[{"role":"developer","content":"Answer in one word."},{"role":"user","content":"Say OK."}],"max_completion_tokens":400,"user":"user-1","safety_identifier":"user-hash","store":false}`)
			if sent, accepted := withoutModel(t, body), withoutModel(t, took.Request.Body); sent != accepted {
				t.Fatalf("sent %s, Azure took %s", sent, accepted)
			}
		})
	}
}

// TestAzureMistralRequestsLeaveOutWhatAzureRefused sends each request that Azure refused for a
// Mistral model as a client's request, with the customer's own credential. The gateway leaves the
// refused field out of the body, or refuses a request that names a message other than a tool
// result, whose name the model would otherwise not see.
func TestAzureMistralRequestsLeaveOutWhatAzureRefused(t *testing.T) {
	recorded := providerCapture(t, "azure/other-model-formats-request-fields")
	for deployment, model := range map[string]string{"azure-mistral-large-2512": "mistral-large-3", "azure-mistral-large-4": "mistral-large-4"} {
		names := []string{"safety_identifier", "store", "user", "name", "developer message", "assistant reasoning_content", "assistant reasoning"}
		if model == "mistral-large-3" {
			names = append(names, "max_completion_tokens")
		}
		for _, name := range names {
			t.Run(model+" "+name, func(t *testing.T) {
				refused := exchange(t, recorded, model+" "+name)
				if refused.Response.Status < 400 || len(refusedChatFields(t, refused.Request.Body)) == 0 {
					t.Fatalf("the recording shows no refused field: %d %s", refused.Response.Status, refused.Request.Body)
				}
				request := map[string]json.RawMessage{}
				if err := json.Unmarshal(refused.Request.Body, &request); err != nil {
					t.Fatal(err)
				}
				request["model"], _ = json.Marshal(deployment)
				client, _ := json.Marshal(request)
				if name == "name" {
					resolution, err := catalog.ResolveRequest(catalog.RequestInput{Body: client, Method: http.MethodPost, Path: "/v1/chat/completions"})
					if err != nil {
						t.Fatal(err)
					}
					state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
					if err := state.Adapter.ValidateRequest(state); err == nil || !strings.Contains(err.Error(), "messages[0].name") {
						t.Fatalf("ValidateRequest = %v, want a refusal of the message's name", err)
					}
					return
				}
				if fields := refusedChatFields(t, azureCustomerChatBody(t, string(client))); len(fields) > 0 {
					t.Fatalf("the body keeps %v", fields)
				}
			})
		}
	}
}

// TestAzureOtherFormatsHoldWhatTheyGenerate replays the recorded replies of Azure's reasoning
// models of other formats to an output limit of 12 (capture azure/other-model-formats-output-limits).
// Grok reasons past either limit field, so its hold is the deployment's output limit, while Kimi and
// Mistral stay within the limit, so theirs is the client's. Billing counts every generated token.
func TestAzureOtherFormatsHoldWhatTheyGenerate(t *testing.T) {
	for name, reply := range providerCapture(t, "azure/other-model-formats-output-limits") {
		t.Run(name, func(t *testing.T) {
			response := &schemas.BifrostChatResponse{}
			if err := sonic.Unmarshal(reply.Response.Body, response); err != nil {
				t.Fatal(err)
			}
			usage := response.Usage
			generated := usage.TotalTokens - usage.PromptTokens
			request := map[string]json.RawMessage{}
			var model string
			if err := json.Unmarshal(reply.Request.Body, &request); err != nil || json.Unmarshal(request["model"], &model) != nil {
				t.Fatalf("decode request: %v", err)
			}
			request["model"], _ = json.Marshal("azure-" + model)
			body, _ := json.Marshal(request)
			state := resolveAzureState(t, "/v1/chat/completions", string(body))
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatal(err)
			}
			want := 12
			if strings.HasPrefix(model, "grok") {
				want = state.Resolution.Deployment.MaxOutputTokens
			}
			held := findMeterEstimate(state.Hold.Meters, billing.MeterOutputTokens)
			if held == nil || held.Quantity != strconv.Itoa(want) || want < generated {
				t.Fatalf("output hold = %#v, want %d tokens, at least the %d generated", held, want, generated)
			}
			if err := ingestReportedUsage(state, usage); err != nil {
				t.Fatal(err)
			}
			if got := state.Signals.CompletionTokens(); got != generated {
				t.Fatalf("completion tokens = %d billed, want the %d generated", got, generated)
			}
		})
	}
}

// azureOtherFormatDeployments names the catalog deployment of each model that the recordings of
// Azure's other model formats call by its Azure deployment name.
var azureOtherFormatDeployments = map[string]string{
	"grok-4.6":           "azure-grok-4.6",
	"grok-4.7":           "azure-grok-4.7",
	"kimi-k3.1-pro":      "azure-kimi-k3.1-pro",
	"mistral-large-3":    "azure-mistral-large-2512",
	"mistral-large-4":    "azure-mistral-large-4",
	"mistral-medium-3-5": "azure-mistral-medium-3-5",
}

// resolveRecordedAzureRequest resolves a recorded request to Azure as a client's request for the
// catalog deployment of its model.
func resolveRecordedAzureRequest(t *testing.T, recorded providerExchange) (*catalog.ResolvedRequest, error) {
	t.Helper()
	request := map[string]json.RawMessage{}
	var model string
	if err := json.Unmarshal(recorded.Request.Body, &request); err != nil || json.Unmarshal(request["model"], &model) != nil {
		t.Fatalf("decode request: %v", err)
	}
	deployment, ok := azureOtherFormatDeployments[model]
	if !ok {
		t.Fatalf("no catalog deployment for %q", model)
	}
	request["model"], _ = json.Marshal(deployment)
	body, _ := json.Marshal(request)
	return catalog.ResolveRequest(catalog.RequestInput{Method: http.MethodPost, Path: "/v1/chat/completions", Body: body})
}

// TestAzureOtherFormatsStateWhatAzureTook compares the sampling fields that the catalog states for
// each Azure deployment of another model format with what Azure took in the recording (capture
// azure/other-model-formats-sampling). The gateway forwards sampling fields unchanged and leaves
// their refusal to the provider, so the catalog's statement is what policies and clients rely on.
// Mistral Medium 3.5 states no reasoning, because Azure returns its reasoning at effort high in a
// shape that Chat Completions does not have, so the gateway takes only effort none.
func TestAzureOtherFormatsStateWhatAzureTook(t *testing.T) {
	catalogtest.UseFallback(t)
	var deployments map[string]struct {
		Routes map[string]struct {
			Sampling catalog.Sampling `json:"sampling"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(activeCatalogRecords(t, "deployments"), &deployments); err != nil {
		t.Fatal(err)
	}
	stated := map[string]func(catalog.Sampling) bool{
		"presence_penalty":  func(s catalog.Sampling) bool { return s.PresencePenalty },
		"frequency_penalty": func(s catalog.Sampling) bool { return s.FrequencyPenalty },
		"logit_bias":        func(s catalog.Sampling) bool { return s.LogitBias },
		"seed":              func(s catalog.Sampling) bool { return s.Seed },
		"temperature":       func(s catalog.Sampling) bool { return s.Temperature },
		"top_p":             func(s catalog.Sampling) bool { return s.TopP },
	}
	for name, recorded := range providerCapture(t, "azure/other-model-formats-sampling") {
		t.Run(name, func(t *testing.T) {
			model, field, _ := strings.Cut(name, " ")
			took := recorded.Response.Status == http.StatusOK
			if effort, ok := strings.CutPrefix(field, "reasoning_effort "); ok {
				if _, err := resolveRecordedAzureRequest(t, recorded); (err == nil) != (effort == "none") {
					t.Fatalf("resolve error = %v, Azure answered %d", err, recorded.Response.Status)
				}
				return
			}
			route, ok := deployments[azureOtherFormatDeployments[model]].Routes["azure-chat-completions"]
			if !ok {
				t.Fatalf("the catalog has no Chat Completions route for %s", model)
			}
			if got := stated[field](route.Sampling); got != took {
				t.Fatalf("the catalog states %s as %t, and Azure took it: %t", field, got, took)
			}
		})
	}
}

// TestAzureOtherFormatsSendOnlyEffortsThatAzureTook sends each recorded request with
// reasoning_effort as a client's request for its deployment (capture
// azure/other-model-formats-efforts). The gateway refuses none exactly where Azure refused it, and
// sends every other effort as one that Azure took.
func TestAzureOtherFormatsSendOnlyEffortsThatAzureTook(t *testing.T) {
	catalogtest.UseFallback(t)
	recorded := providerCapture(t, "azure/other-model-formats-efforts")
	for name, exchange := range recorded {
		t.Run(name, func(t *testing.T) {
			model, effort, _ := strings.Cut(name, " reasoning_effort ")
			if _, err := resolveRecordedAzureRequest(t, exchange); err != nil {
				if effort != "none" || exchange.Response.Status == http.StatusOK {
					t.Fatalf("resolve error = %v, Azure answered %d", err, exchange.Response.Status)
				}
				return
			}
			request := map[string]json.RawMessage{}
			if err := json.Unmarshal(exchange.Request.Body, &request); err != nil {
				t.Fatal(err)
			}
			request["model"], _ = json.Marshal(azureOtherFormatDeployments[model])
			body, _ := json.Marshal(request)
			var sent struct {
				ReasoningEffort string `json:"reasoning_effort"`
			}
			if err := json.Unmarshal(azureCustomerChatBody(t, string(body)), &sent); err != nil {
				t.Fatal(err)
			}
			if took := recorded[model+" reasoning_effort "+sent.ReasoningEffort]; took.Response.Status != http.StatusOK {
				t.Fatalf("sent reasoning_effort %q, which Azure answered with %d", sent.ReasoningEffort, took.Response.Status)
			}
		})
	}
}

// TestAzureOtherFormatsForceToolsOnlyWhereAzureDoes resolves each recorded request with tool_choice
// for its deployment (capture azure/other-model-formats-tool-choice). Only Grok called the tool
// that every forced choice asked for, so only Grok's deployment takes a forced choice.
func TestAzureOtherFormatsForceToolsOnlyWhereAzureDoes(t *testing.T) {
	catalogtest.UseFallback(t)
	for name, recorded := range providerCapture(t, "azure/other-model-formats-tool-choice") {
		t.Run(name, func(t *testing.T) {
			_, err := resolveRecordedAzureRequest(t, recorded)
			refuse := !strings.HasSuffix(name, " auto") && !strings.HasPrefix(name, "grok-")
			if (err != nil) != refuse {
				t.Fatalf("resolve error = %v, want refused %t", err, refuse)
			}
		})
	}
}

// azureCustomerChatBody prepares a client's Chat Completions request with the customer's own
// credential and returns the body that the provider receives.
func azureCustomerChatBody(t *testing.T, body string) []byte {
	t.Helper()
	_, customer := customerOpenAICredential(t)
	state := resolveAzureState(t, "/v1/chat/completions", body)
	state.PreparedCredential = customer
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.RequestType)
	request, err := state.Resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatal(err)
	}
	return preparedProviderBody(t, ctx, request.ChatRequest)
}

// withoutModel returns a body as canonical JSON without its model field, which names a deployment.
func withoutModel(t *testing.T, body []byte) string {
	t.Helper()
	fields := map[string]any{}
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "model")
	canonical, _ := json.Marshal(fields)
	return string(canonical)
}

// refusedChatFields lists the parts of a Chat Completions body that Azure refused for Mistral's
// models.
func refusedChatFields(t *testing.T, body []byte) []string {
	t.Helper()
	var request struct {
		Fields   map[string]json.RawMessage
		Messages []map[string]json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &request.Fields); err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, field := range []string{"safety_identifier", "store", "user", "max_completion_tokens"} {
		if _, ok := request.Fields[field]; ok {
			found = append(found, field)
		}
	}
	for _, message := range request.Messages {
		var role string
		_ = json.Unmarshal(message["role"], &role)
		if role == "developer" {
			found = append(found, "developer message")
		}
		for _, field := range []string{"name", "reasoning_content", "reasoning"} {
			if _, ok := message[field]; ok && role != "tool" {
				found = append(found, role+" "+field)
			}
		}
	}
	return found
}

// MiniMax M3 on Azure only turns reasoning on and off. The OpenAI format carries reasoning only as
// reasoning_effort, so reasoning off is the effort "none", and reasoning on leaves the model's
// default.
func TestAzureBinaryReasoningReachesTheOpenAIWire(t *testing.T) {
	for _, test := range []struct {
		reasoning string
		want      string
	}{
		{`"reasoning":{"enabled":false}`, "none"},
		{`"reasoning":{"effort":"none"}`, "none"},
		{`"reasoning_effort":"none"`, "none"},
		{`"reasoning":{"enabled":true}`, ""},
		{`"reasoning":{"effort":"high"}`, ""},
		{`"max_completion_tokens":64`, ""},
	} {
		t.Run(test.reasoning, func(t *testing.T) {
			state := resolveAzureState(t, "/v1/chat/completions",
				`{"model":"azure-minimax-m3-fireworks-hosted-us","messages":[{"role":"user","content":"hi"}],`+test.reasoning+`}`)
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.RequestType)
			request, err := state.Resolution.ToBifrost(ctx)
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			body := preparedProviderBody(t, ctx, request.ChatRequest)
			var wire map[string]json.RawMessage
			if err := sonic.Unmarshal(body, &wire); err != nil {
				t.Fatalf("decode Azure wire request: %v", err)
			}
			effort, sent := wire["reasoning_effort"]
			if rawString(effort) != test.want || sent != (test.want != "") {
				t.Fatalf("Azure received reasoning_effort %s, want %q: %s", effort, test.want, body)
			}
			for _, field := range []string{"reasoning", "thinking", "chat_template_kwargs"} {
				if _, exists := wire[field]; exists {
					t.Fatalf("Azure received %s: %s", field, body)
				}
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
