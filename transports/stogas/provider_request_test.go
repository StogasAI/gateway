package stogas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestPreparedProviderRequestPreservesDecodedPrompt(t *testing.T) {
	for index, encoded := range []string{
		`"  \u0061\u00e9\ud83d\ude42\n<>&\\\/\"  "`,
		`"e\u0301\u2028\u2029\t\r\n"`,
		`" \u3000\u2000x` + strings.Repeat(" ", 1<<20) + `"`,
	} {
		var want string
		if err := json.Unmarshal([]byte(encoded), &want); err != nil {
			t.Fatal(err)
		}
		for _, route := range []string{"chat/completions", "responses"} {
			t.Run(fmt.Sprintf("%s/%d", route, index), func(t *testing.T) {
				input, outputField, limitField := `"input":`+encoded, "input", "max_output_tokens"
				if route == "chat/completions" {
					input, outputField = `"messages":[{"role":"user","content":`+encoded+`}]`, "messages"
					limitField = "max_completion_tokens"
				}
				resolved, err := catalog.ResolveRequest(catalog.RequestInput{
					Method: "POST", Path: "/v1/" + route,
					Body: []byte(fmt.Sprintf(`{"model":"openai/gpt-5.5",%q:16,%s}`, limitField, input)),
				})
				if err != nil {
					t.Fatal(err)
				}
				state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
				if err := state.Adapter.ValidateRequest(state); err != nil {
					t.Fatal(err)
				}
				ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
				request, err := resolved.ToBifrost(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := PrepareProviderRequest(ctx, state, request); err != nil {
					t.Fatal(err)
				}
				var body []byte
				if request.ChatRequest != nil {
					body = preparedProviderBody(t, ctx, request.ChatRequest)
				} else {
					body = preparedProviderBody(t, ctx, request.ResponsesRequest)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(body, &fields); err != nil {
					t.Fatal(err)
				}
				var conversation []struct{ Content json.RawMessage }
				if err := json.Unmarshal(fields[outputField], &conversation); err != nil || len(conversation) != 1 {
					t.Fatalf("unexpected prepared conversation: %v", err)
				}
				content := conversation[0].Content
				var got string
				if err := json.Unmarshal(content, &got); err != nil {
					var blocks []struct{ Text string }
					if err := json.Unmarshal(content, &blocks); err != nil || len(blocks) != 1 {
						t.Fatalf("unexpected prepared content: %v", err)
					}
					got = blocks[0].Text
				}
				if got != want || resolved.StructuredPIIRedactionSummary() != nil {
					t.Fatalf("prompt changed: got %q, want %q", got, want)
				}
			})
		}
	}
}

func TestPreparedAnthropicThinkingDisplayPreservesCallerChoice(t *testing.T) {
	for _, route := range []string{"chat/completions", "responses"} {
		for _, display := range []string{"", "omitted", "summarized"} {
			t.Run(route+"/"+display, func(t *testing.T) {
				fields := `"messages":[{"role":"user","content":"hello"}],"reasoning_effort":"high"`
				if route == "responses" {
					fields = `"input":"hello","reasoning":{"effort":"high"}`
					if display != "" {
						summary := "auto"
						if display == "omitted" {
							summary = "none"
						}
						fields = fmt.Sprintf(`"input":"hello","reasoning":{"effort":"high","summary":%q}`, summary)
					}
				} else if display != "" {
					fields += fmt.Sprintf(`,"reasoning_display":%q`, display)
				}
				resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + route,
					Body: []byte(`{"model":"anthropic-claude-opus-4-7",` + fields + `}`)})
				if err != nil {
					t.Fatal(err)
				}
				state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
				if err := state.Adapter.ValidateRequest(state); err != nil {
					t.Fatal(err)
				}
				ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
				request, err := resolved.ToBifrost(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := PrepareProviderRequest(ctx, state, request); err != nil {
					t.Fatal(err)
				}
				var body []byte
				if request.ChatRequest != nil {
					body = preparedProviderBody(t, ctx, request.ChatRequest)
				} else {
					body = preparedProviderBody(t, ctx, request.ResponsesRequest)
				}
				var wire struct{ Thinking map[string]any }
				if err := json.Unmarshal(body, &wire); err != nil {
					t.Fatal(err)
				}
				got, present := wire.Thinking["display"]
				if wire.Thinking["type"] != "adaptive" || display == "" && present || display != "" && got != display {
					t.Fatalf("public reasoning controls changed: %s", body)
				}
			})
		}
	}
}

func TestPrepareProviderRequestSendsEndUserIDsOnlyToCustomerAccountsAndAppliesStorePolicy(t *testing.T) {
	_, customer := customerOpenAICredential(t)
	managed, err := (&billing.Service{}).PrepareCredential(&billing.KeyConfigSnapshot{
		Claims:         &billing.APIKeyClaims{OrganizationID: "org-test"},
		PolicySnapshot: billing.PolicySnapshot{Config: &policy.Config{}},
		Credentials:    map[string][]billing.CredentialSelection{"chutes": {{Mode: "managed"}}},
	}, "chutes", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	type endUserIDs struct{ user, safetyIdentifier, metadataUserID string }
	text := "hello"
	metadata := map[string]any{"private": "value"}
	// Preparation reads only whether the pair's credential is the customer's
	// own, so one credential of each kind serves every provider here.
	for _, tc := range []struct {
		name, model    string
		provider       schemas.ModelProvider
		customer       bool
		user, safety   string
		want           endUserIDs
		openAIWire     bool
		anthropicLimit bool
	}{
		{name: "openai managed", provider: schemas.OpenAI, model: "gpt-5.6-terra", user: "caller-user", safety: "caller-safety", openAIWire: true},
		{name: "openai customer", provider: schemas.OpenAI, model: "gpt-5.6-terra", customer: true, user: "caller-user", safety: "caller-safety", want: endUserIDs{user: "caller-user", safetyIdentifier: "caller-safety"}, openAIWire: true},
		{name: "azure gpt customer", provider: schemas.Azure, model: "gpt-5.6-terra", customer: true, user: "caller-user", safety: "caller-safety", want: endUserIDs{user: "caller-user", safetyIdentifier: "caller-safety"}, openAIWire: true},
		{name: "anthropic managed", provider: schemas.Anthropic, model: "claude-sonnet-4-6", user: "caller-user", safety: "caller-safety", anthropicLimit: true},
		{name: "anthropic customer", provider: schemas.Anthropic, model: "claude-sonnet-4-6", customer: true, user: "caller-user", safety: "caller-safety", want: endUserIDs{metadataUserID: "caller-safety"}, anthropicLimit: true},
		{name: "anthropic customer user only", provider: schemas.Anthropic, model: "claude-sonnet-4-6", customer: true, user: "caller-user", want: endUserIDs{metadataUserID: "caller-user"}, anthropicLimit: true},
		{name: "azure claude customer", provider: schemas.Azure, model: "claude-sonnet-4-6", customer: true, user: "caller-user", safety: "caller-safety", want: endUserIDs{metadataUserID: "caller-safety"}, anthropicLimit: true},
		{name: "chutes managed", provider: catalog.ProviderChutes, model: "deepseek-ai/DeepSeek-V3.2", user: "caller-user", safety: "caller-safety"},
		{name: "chutes customer", provider: catalog.ProviderChutes, model: "deepseek-ai/DeepSeek-V3.2", customer: true, user: "caller-user", safety: "caller-safety"},
	} {
		for _, requestType := range []schemas.RequestType{schemas.ChatCompletionRequest, schemas.ResponsesRequest} {
			if tc.provider == catalog.ProviderChutes && requestType == schemas.ResponsesRequest {
				continue
			}
			t.Run(tc.name+" "+string(requestType), func(t *testing.T) {
				var user, safety *string
				if tc.user != "" {
					user = &tc.user
				}
				if tc.safety != "" {
					safety = &tc.safety
				}
				request := &schemas.BifrostRequest{RequestType: requestType}
				if requestType == schemas.ChatCompletionRequest {
					request.ChatRequest = &schemas.BifrostChatRequest{
						Provider: tc.provider,
						Model:    tc.model,
						Input:    []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: &text}}},
						Params:   &schemas.ChatParameters{Metadata: &metadata, SafetyIdentifier: safety, Store: schemas.Ptr(true), User: user},
					}
				} else {
					role := schemas.ResponsesInputMessageRoleUser
					request.ResponsesRequest = &schemas.BifrostResponsesRequest{
						Provider: tc.provider,
						Model:    tc.model,
						Input:    []schemas.ResponsesMessage{{Role: &role, Content: &schemas.ResponsesMessageContent{ContentStr: &text}}},
						Params:   &schemas.ResponsesParameters{Metadata: &metadata, SafetyIdentifier: safety, Store: schemas.Ptr(true), User: user},
					}
				}
				ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, requestType)
				state := providerRequestTestState(tc.provider, tc.model, requestType, 128000)
				state.Resolution.Deployment.ModelID = tc.model
				state.PreparedCredential = managed
				if tc.customer {
					state.PreparedCredential = customer
				}

				if err := PrepareProviderRequest(ctx, state, request); err != nil {
					t.Fatalf("PrepareProviderRequest returned error: %v", err)
				}
				var body []byte
				if request.ChatRequest != nil {
					body = preparedProviderBody(t, ctx, request.ChatRequest)
				} else {
					body = preparedProviderBody(t, ctx, request.ResponsesRequest)
					if limit := request.ResponsesRequest.Params.MaxOutputTokens; tc.anthropicLimit && (limit == nil || *limit != 128000) {
						t.Fatalf("Anthropic max_output_tokens = %#v, want pinned limit 128000", limit)
					}
				}
				var wire struct {
					User             string            `json:"user"`
					SafetyIdentifier string            `json:"safety_identifier"`
					Metadata         map[string]string `json:"metadata"`
					Store            *bool             `json:"store"`
				}
				if err := json.Unmarshal(body, &wire); err != nil {
					t.Fatalf("decode prepared body: %v", err)
				}
				if got := (endUserIDs{wire.User, wire.SafetyIdentifier, wire.Metadata["user_id"]}); got != tc.want {
					t.Fatalf("end-user IDs = %+v, want %+v: %s", got, tc.want, body)
				}
				if _, private := wire.Metadata["private"]; private {
					t.Fatalf("client metadata reached the provider: %s", body)
				}
				if tc.openAIWire != (wire.Store != nil) || wire.Store != nil && *wire.Store {
					t.Fatalf("store = %#v, want false only on OpenAI wire: %s", wire.Store, body)
				}
			})
		}
	}
}

func TestCustomerRequestBodyEndUserIDsReachOpenAI(t *testing.T) {
	_, customer := customerOpenAICredential(t)
	// OpenAI accepted 4,096 characters in both fields on Oct 17, 2026.
	long := strings.Repeat("a", 4096)
	for _, tc := range []struct{ name, route, fields, user, safety string }{
		{"chat", "chat/completions", `"messages":[{"role":"user","content":"hi"}],"user":"user-1","safety_identifier":"hash-1"`, "user-1", "hash-1"},
		{"responses", "responses", `"input":"hi","user":"user-1","safety_identifier":"hash-1"`, "user-1", "hash-1"},
		{"empty values name no user", "chat/completions", `"messages":[{"role":"user","content":"hi"}],"user":"","safety_identifier":null`, "", ""},
		{"long chat values", "chat/completions", `"messages":[{"role":"user","content":"hi"}],"user":"` + long + `","safety_identifier":"` + long + `"`, long, long},
		{"long responses values", "responses", `"input":"hi","user":"` + long + `","safety_identifier":"` + long + `"`, long, long},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + tc.route, Body: []byte(`{"model":"openai/gpt-5.5",` + tc.fields + `}`)})
			if err != nil {
				t.Fatal(err)
			}
			state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
			state.PreparedCredential = customer
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatal(err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
			request, err := resolved.ToBifrost(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatal(err)
			}
			var body []byte
			if request.ChatRequest != nil {
				body = preparedProviderBody(t, ctx, request.ChatRequest)
			} else {
				body = preparedProviderBody(t, ctx, request.ResponsesRequest)
			}
			var wire map[string]any
			if err := json.Unmarshal(body, &wire); err != nil {
				t.Fatal(err)
			}
			for field, want := range map[string]string{"user": tc.user, "safety_identifier": tc.safety} {
				if got, present := wire[field]; want == "" && present || want != "" && got != want {
					t.Fatalf("%s = %#v, want %q: %s", field, got, want, body)
				}
			}
		})
	}
	for _, fields := range []string{`"user":123`, `"safety_identifier":{"id":"user-1"}`} {
		if _, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(`{"model":"openai/gpt-5.5","messages":[{"role":"user","content":"hi"}],` + fields + `}`)}); err == nil {
			t.Fatalf("%s was accepted", fields)
		}
	}
}

func TestPrepareProviderRequestRecordsSettingsWithoutContent(t *testing.T) {
	for _, tc := range []struct {
		name, route, body, want string
	}{
		{
			name:  "chat to Anthropic records the required output limit",
			route: "chat/completions",
			body: `{"model":"anthropic-claude-opus-4-7","messages":[{"role":"user","content":"secret prompt"}],
				"reasoning_effort":"high","task_budget":{"type":"tokens","total":20000},"stop":["secret-stop"],
				"tools":[{"type":"function","function":{"name":"secret_tool","parameters":{"type":"object"}}}],
				"tool_choice":"auto","metadata":{"secret":"value"},"user":"secret-user"}`,
			want: `{"max_output_tokens":%d,"reasoning_effort":"high","task_budget_tokens":20000,"tool_choice":"auto"}`,
		},
		{
			name:  "responses to OpenAI keeps only the format and tool choice types",
			route: "responses",
			body: `{"model":"openai/gpt-5.5","input":"secret prompt","instructions":"secret instructions","max_output_tokens":64,
				"reasoning":{"effort":"low","summary":"auto"},"include":["reasoning.encrypted_content"],"truncation":"auto",
				"text":{"verbosity":"low","format":{"type":"json_schema","name":"secret_schema","strict":true,
					"schema":{"type":"object","properties":{"secret":{"type":"string"}},"required":["secret"],"additionalProperties":false}}},
				"tools":[{"type":"function","name":"secret_tool","parameters":{"type":"object"}}],
				"tool_choice":{"type":"function","name":"secret_tool"},"parallel_tool_calls":false,
				"prompt_cache_key":"secret-cache-key","metadata":{"secret":"value"}}`,
			want: `{"max_output_tokens":64,"reasoning_effort":"low","reasoning_summary":"auto","verbosity":"low",
				"response_format":"json_schema","include":["reasoning.encrypted_content"],"tool_choice":"function",
				"parallel_tool_calls":false,"truncation":"auto"}`,
		},
		{
			name:  "responses to Anthropic reads extra parameters",
			route: "responses",
			body: `{"model":"anthropic-claude-opus-4-7","input":"secret prompt","max_output_tokens":256,"top_k":5,
				"task_budget":{"type":"tokens","total":30000}}`,
			want: `{"max_output_tokens":256,"task_budget_tokens":30000,"top_k":5}`,
		},
		{
			name:  "chat to Chutes reads the fields the gateway sends to Chutes",
			route: "chat/completions",
			body: `{"model":"chutes/qwen3-32b","messages":[{"role":"user","content":"secret prompt"}],"max_tokens":64,
				"reasoning":{"enabled":false},"temperature":0.2,"frequency_penalty":0.5,"repetition_penalty":1.1,"seed":7}`,
			want: `{"max_output_tokens":64,"reasoning_enabled":false,"temperature":0.2,"frequency_penalty":0.5,"repetition_penalty":1.1,"seed":7}`,
		},
		{
			name:  "chat to Chutes leaves out integers that would round in the log",
			route: "chat/completions",
			body: `{"model":"chutes/qwen3-32b","messages":[{"role":"user","content":"secret prompt"}],"max_tokens":64,
				"seed":9007199254740993,"top_k":-9007199254740992,"temperature":0.2}`,
			want: `{"max_output_tokens":64,"temperature":0.2}`,
		},
		{
			name:  "responses to OpenAI leaves out long text",
			route: "responses",
			body: `{"model":"openai/gpt-5.5","input":"secret prompt","max_output_tokens":64,
				"reasoning":{"effort":"low","summary":"` + strings.Repeat("x", 65) + `"}}`,
			want: `{"max_output_tokens":64,"reasoning_effort":"low"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/" + tc.route, Body: []byte(tc.body)})
			if err != nil {
				t.Fatal(err)
			}
			state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.SanitizeRequest(state); err != nil {
				t.Fatal(err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
			request, err := resolved.ToBifrost(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(state.RequestSettings)
			if err != nil {
				t.Fatal(err)
			}
			var got, want map[string]any
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(strings.Replace(tc.want, "%d", fmt.Sprint(resolvedOutputLimit(resolved)), 1)), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("request settings = %s, want %s", encoded, tc.want)
			}
		})
	}
}

func TestPreparedProviderBodySurvivesCredentialInstallationAndDispatchBuilder(t *testing.T) {
	text := "hello"
	request := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.OpenAI,
			Model:    "gpt-5.6-terra",
			Input: []schemas.ChatMessage{{
				Role:    schemas.ChatMessageRoleUser,
				Content: &schemas.ChatMessageContent{ContentStr: &text},
			}},
		},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, request.RequestType)
	state := providerRequestTestState(schemas.OpenAI, request.ChatRequest.Model, request.RequestType, 128000)
	state.Authorization = &billing.Authorization{
		UpstreamByok:       "0198f4cc-6c25-7000-8000-000000000001",
		UpstreamByokSecret: "sk-upstream-secret",
	}

	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatalf("PrepareProviderRequest returned error: %v", err)
	}
	prepared := append([]byte(nil), preparedProviderBody(t, ctx, request.ChatRequest)...)
	if err := applyUpstreamCredentials(ctx, state, nil); err != nil {
		t.Fatalf("ApplyUpstreamCredentials returned error: %v", err)
	}
	dispatched, bifrostErr := prepareChatProviderBody(ctx, request.ChatRequest, false)
	if bifrostErr != nil {
		t.Fatalf("dispatch builder returned error: %v", bifrostErr)
	}
	if !bytes.Equal(dispatched, prepared) {
		t.Fatalf("provider body changed after authorization: got %q want %q", dispatched, prepared)
	}
}

func TestPrepareProviderRequestAppliesPinnedAnthropicLimitBeforeSerialization(t *testing.T) {
	const model = "stogas-prepared-body-max-output-test"
	wrongLimit := 7
	schemas.SetCapabilityResolver(func(_ schemas.ModelProvider, candidate string) *schemas.ModelCapabilities {
		if candidate == model {
			return &schemas.ModelCapabilities{MaxOutputTokens: &wrongLimit}
		}
		return nil
	})
	t.Cleanup(func() { schemas.SetCapabilityResolver(nil) })
	text := "hello"
	request := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.Anthropic,
			Model:    model,
			Input: []schemas.ChatMessage{{
				Role:    schemas.ChatMessageRoleUser,
				Content: &schemas.ChatMessageContent{ContentStr: &text},
			}},
			Params: &schemas.ChatParameters{},
		},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, request.RequestType)
	state := providerRequestTestState(schemas.Anthropic, model, request.RequestType, 12345)

	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatalf("PrepareProviderRequest returned error: %v", err)
	}
	if request.ChatRequest.Params.MaxCompletionTokens == nil || *request.ChatRequest.Params.MaxCompletionTokens != 12345 {
		t.Fatalf("typed max_completion_tokens = %#v, want pinned limit 12345", request.ChatRequest.Params.MaxCompletionTokens)
	}
	var payload map[string]any
	if err := json.Unmarshal(preparedProviderBody(t, ctx, request.ChatRequest), &payload); err != nil {
		t.Fatalf("decode prepared body: %v", err)
	}
	if payload["max_tokens"] != float64(12345) {
		t.Fatalf("max_tokens = %#v, want 12345", payload["max_tokens"])
	}
}

func TestPrepareProviderRequestUsesNativeAnthropicBodiesForAzureClaude(t *testing.T) {
	text := "hello"
	for _, requestType := range []schemas.RequestType{schemas.ChatCompletionRequest, schemas.ResponsesRequest} {
		t.Run(string(requestType), func(t *testing.T) {
			request := &schemas.BifrostRequest{RequestType: requestType}
			if requestType == schemas.ChatCompletionRequest {
				request.ChatRequest = &schemas.BifrostChatRequest{
					Provider: schemas.Azure,
					Model:    "claude-sonnet-4-6",
					Input: []schemas.ChatMessage{{
						Role:    schemas.ChatMessageRoleUser,
						Content: &schemas.ChatMessageContent{ContentStr: &text},
					}},
					Params: &schemas.ChatParameters{Store: schemas.Ptr(true)},
				}
			} else {
				role := schemas.ResponsesInputMessageRoleUser
				request.ResponsesRequest = &schemas.BifrostResponsesRequest{
					Provider: schemas.Azure,
					Model:    "claude-sonnet-4-6",
					Input: []schemas.ResponsesMessage{{
						Role:    &role,
						Content: &schemas.ResponsesMessageContent{ContentStr: &text},
					}},
					Params: &schemas.ResponsesParameters{Store: schemas.Ptr(true)},
				}
			}

			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, requestType)
			state := providerRequestTestState(schemas.Azure, "claude-sonnet-4-6", requestType, 128000)
			state.Resolution.Deployment.ModelID = "claude-sonnet-4-6"

			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			var body []byte
			if request.ChatRequest != nil {
				if request.ChatRequest.Params.Store != nil || request.ChatRequest.Params.MaxCompletionTokens == nil || *request.ChatRequest.Params.MaxCompletionTokens != 128000 {
					t.Fatalf("unexpected sanitized Azure Claude chat params: %#v", request.ChatRequest.Params)
				}
				body = preparedProviderBody(t, ctx, request.ChatRequest)
			} else {
				if request.ResponsesRequest.Params.Store != nil || request.ResponsesRequest.Params.MaxOutputTokens == nil || *request.ResponsesRequest.Params.MaxOutputTokens != 128000 {
					t.Fatalf("unexpected sanitized Azure Claude Responses params: %#v", request.ResponsesRequest.Params)
				}
				body = preparedProviderBody(t, ctx, request.ResponsesRequest)
			}
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode prepared Azure Claude body: %v", err)
			}
			if payload["model"] != "claude-sonnet-4-6" || payload["max_tokens"] != float64(128000) {
				t.Fatalf("Azure Claude did not use the native Messages body: %s", body)
			}
			for _, invalid := range []string{"max_completion_tokens", "max_output_tokens", "store"} {
				if _, exists := payload[invalid]; exists {
					t.Fatalf("Azure Claude body retained OpenAI field %s: %s", invalid, body)
				}
			}
		})
	}
}

// The customer names the Azure deployment, so the wire model need not mention Claude.
func TestPrepareProviderRequestSendsBasicWebToolsToAzureHostedClaude(t *testing.T) {
	const deploymentName = "opus-prod"
	text := "hello"
	role := schemas.ResponsesInputMessageRoleUser
	request := &schemas.BifrostRequest{
		RequestType: schemas.ResponsesRequest,
		ResponsesRequest: &schemas.BifrostResponsesRequest{
			Provider: schemas.Azure,
			Model:    deploymentName,
			Input: []schemas.ResponsesMessage{{
				Role:    &role,
				Content: &schemas.ResponsesMessageContent{ContentStr: &text},
			}},
			Params: &schemas.ResponsesParameters{Tools: []schemas.ResponsesTool{
				{Type: schemas.ResponsesToolTypeWebSearch, ResponsesToolWebSearch: &schemas.ResponsesToolWebSearch{}},
				{Type: schemas.ResponsesToolTypeWebFetch, ResponsesToolWebFetch: &schemas.ResponsesToolWebFetch{}},
			}},
		},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, request.RequestType)
	state := providerRequestTestState(schemas.Azure, deploymentName, request.RequestType, 128000)
	state.Resolution.Deployment.ModelID = "claude-opus-5"
	state.Resolution.Deployment.Upstream.Hosting = "azure"

	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatalf("PrepareProviderRequest returned error: %v", err)
	}
	if !schemas.IsAnthropicModelFamily(ctx, deploymentName) {
		t.Fatal("core does not send the Anthropic wire format to the Claude deployment")
	}
	var payload struct {
		Model string `json:"model"`
		Tools []struct {
			Type string `json:"type"`
		} `json:"tools"`
	}
	body := preparedProviderBody(t, ctx, request.ResponsesRequest)
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode prepared Azure Claude body: %v", err)
	}
	if payload.Model != deploymentName || len(payload.Tools) != 2 || payload.Tools[0].Type != "web_search_20250305" || payload.Tools[1].Type != "web_fetch_20250910" {
		t.Fatalf("Azure hosted Claude did not receive the basic web tools: %s", body)
	}
}

func TestPrepareProviderRequestSendsBasicAnthropicWebToolVersions(t *testing.T) {
	text := "hello"
	role := schemas.ResponsesInputMessageRoleUser
	for _, provider := range []schemas.ModelProvider{schemas.Anthropic, schemas.Azure} {
		for _, model := range []string{"claude-sonnet-4-6", "claude-opus-5"} {
			t.Run(string(provider)+"/"+model, func(t *testing.T) {
				request := &schemas.BifrostRequest{
					RequestType: schemas.ResponsesRequest,
					ResponsesRequest: &schemas.BifrostResponsesRequest{
						Provider: provider,
						Model:    model,
						Input: []schemas.ResponsesMessage{{
							Role:    &role,
							Content: &schemas.ResponsesMessageContent{ContentStr: &text},
						}},
						Params: &schemas.ResponsesParameters{Tools: []schemas.ResponsesTool{
							{Type: schemas.ResponsesToolTypeWebSearch, ResponsesToolWebSearch: &schemas.ResponsesToolWebSearch{}},
							{Type: schemas.ResponsesToolTypeWebFetch, ResponsesToolWebFetch: &schemas.ResponsesToolWebFetch{}},
						}},
					},
				}
				ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, request.RequestType)
				state := providerRequestTestState(provider, model, request.RequestType, 32000)
				state.Resolution.Deployment.ModelID = model

				if err := PrepareProviderRequest(ctx, state, request); err != nil {
					t.Fatalf("PrepareProviderRequest returned error: %v", err)
				}
				var payload struct {
					Tools []struct {
						Type string `json:"type"`
					} `json:"tools"`
				}
				body := preparedProviderBody(t, ctx, request.ResponsesRequest)
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("decode prepared body: %v", err)
				}
				types := make([]string, 0, len(payload.Tools))
				for _, tool := range payload.Tools {
					types = append(types, tool.Type)
				}
				if strings.Join(types, ",") != "web_search_20250305,web_fetch_20250910" {
					t.Fatalf("tool types = %v, want the basic web tool versions: %s", types, body)
				}
			})
		}
	}
}

// OpenAI enforces blocked_domains, alone or beside allowed_domains, so the
// provider must receive both lists as the client sent them, and the choice to
// search only cached pages.
func TestPrepareProviderRequestSendsOpenAIWebSearchDomainFilters(t *testing.T) {
	for _, item := range []struct{ filters, cached string }{
		{filters: `{"blocked_domains":["example.com"]}`},
		{filters: `{"allowed_domains":["wikipedia.org","britannica.com"],"blocked_domains":["en.wikipedia.org"]}`},
		{filters: `{"allowed_domains":["wikipedia.org"]}`, cached: `false`},
		{filters: `{"blocked_domains":["example.com"]}`, cached: `true`},
	} {
		filters := item.filters
		tool := `{"type":"web_search","filters":` + filters
		if item.cached != "" {
			tool += `,"external_web_access":` + item.cached
		}
		t.Run(tool, func(t *testing.T) {
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST", Path: "/v1/responses",
				Body: []byte(`{"model":"openai/gpt-5.5","input":"hi","max_output_tokens":16,"tools":[` + tool + `}]}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatal(err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
			request, err := resolved.ToBifrost(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Tools []struct {
					Filters           json.RawMessage `json:"filters"`
					ExternalWebAccess json.RawMessage `json:"external_web_access"`
				} `json:"tools"`
			}
			body := preparedProviderBody(t, ctx, request.ResponsesRequest)
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode prepared body: %v", err)
			}
			if len(payload.Tools) != 1 || string(payload.Tools[0].Filters) != filters ||
				string(payload.Tools[0].ExternalWebAccess) != item.cached {
				t.Fatalf("prepared body lost the tool settings %s: %s", tool, body)
			}
		})
	}
}

func TestOpenAIAccessProgramsReachOnlyOpenAI(t *testing.T) {
	for _, item := range []struct {
		name, model, programs, want, err string
	}{
		{name: "OpenAI selection", model: "openai/gpt-5.5", programs: `{"cyber":"daybreak_red"}`, want: `{"cyber":"daybreak_red"}`},
		{name: "OpenAI standard", model: "openai/gpt-5.5", programs: `{"cyber":"standard"}`, want: `{"cyber":"standard"}`},
		{name: "OpenAI empty selection is omission", model: "openai/gpt-5.5", programs: `{}`},
		{name: "OpenAI null program is omission", model: "openai/gpt-5.5", programs: `{"cyber":null}`},
		{name: "Claude without a selection", model: "anthropic-claude-opus-4-8", programs: `{}`},
		{name: "Claude refuses a selection", model: "anthropic-claude-opus-4-8", programs: `{"cyber":"standard"}`, err: "access_programs is supported only on OpenAI deployments"},
		{name: "Azure OpenAI refuses a selection", model: "azure-gpt-5.6-sol", programs: `{"cyber":"standard"}`, err: "access_programs is supported only on OpenAI deployments"},
		{name: "unknown program", model: "openai/gpt-5.5", programs: `{"cyber":"daybreak_green"}`, err: "access_programs.cyber must be standard, daybreak_blue or daybreak_red"},
		{name: "unknown member", model: "openai/gpt-5.5", programs: `{"bio":"standard"}`, err: "access_programs.bio is not supported"},
		{name: "not an object", model: "openai/gpt-5.5", programs: `"standard"`, err: "access_programs must be an object"},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolved, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST", Path: "/v1/responses",
				Body: []byte(`{"model":"` + item.model + `","input":"hi","max_output_tokens":16,"access_programs":` + item.programs + `}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
			err = state.Adapter.ValidateRequest(state)
			if item.err != "" {
				if err == nil || err.Error() != item.err || catalog.PublicError(err).StatusCode != 400 {
					t.Fatalf("expected %q, got %v", item.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
			request, err := resolved.ToBifrost(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatal(err)
			}
			var payload map[string]json.RawMessage
			body := preparedProviderBody(t, ctx, request.ResponsesRequest)
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode prepared body: %v", err)
			}
			if got := string(payload["access_programs"]); got != item.want {
				t.Fatalf("access_programs = %q, want %q: %s", got, item.want, body)
			}
		})
	}
}

// Codex sends client_metadata on every Responses request. It is accepted and
// never sent to a provider.
func TestClientMetadataNeverReachesProvider(t *testing.T) {
	resolved, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST", Path: "/v1/responses",
		Body: []byte(`{"model":"openai/gpt-5.5","input":"hi","max_output_tokens":16,"client_metadata":{"x-codex-installation-id":"must-not-leave","traceparent":null}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resolved.RawBody()["client_metadata"]; ok {
		t.Fatal("client_metadata stayed in the request body")
	}
	state := NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatal(err)
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolved.RequestType)
	request, err := resolved.ToBifrost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatal(err)
	}
	if body := preparedProviderBody(t, ctx, request.ResponsesRequest); strings.Contains(string(body), "must-not-leave") || strings.Contains(string(body), "client_metadata") {
		t.Fatalf("client metadata reached the provider: %s", body)
	}
}

func TestPrepareProviderRequestUsesPinnedCatalogTranslationContext(t *testing.T) {
	const wireModel = "opaque-upstream-deployment"
	wrongLimit := 100000
	schemas.SetCapabilityResolver(func(_ schemas.ModelProvider, candidate string) *schemas.ModelCapabilities {
		if candidate == wireModel {
			return &schemas.ModelCapabilities{MaxOutputTokens: &wrongLimit}
		}
		return nil
	})
	t.Cleanup(func() { schemas.SetCapabilityResolver(nil) })

	text := "hello"
	request := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.OpenAI,
			Model:    wireModel,
			Input: []schemas.ChatMessage{{
				Role:    schemas.ChatMessageRoleUser,
				Content: &schemas.ChatMessageContent{ContentStr: &text},
			}},
			Params: &schemas.ChatParameters{Reasoning: &schemas.ChatReasoning{MaxTokens: schemas.Ptr(5000)}},
		},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, request.RequestType)
	state := &State{
		Pair: Pair{
			Resolution: &catalog.ResolvedRequest{
				Provider:    schemas.OpenAI,
				Model:       wireModel,
				RequestType: request.RequestType,
				Deployment: catalog.Deployment{
					ModelID:         "gpt-5.6-terra",
					MaxOutputTokens: 10000,
				},
			},
		},
	}

	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatalf("PrepareProviderRequest returned error: %v", err)
	}
	info, ok := schemas.GetRequestModelInfo(ctx, schemas.OpenAI, wireModel)
	if !ok || info.CanonicalModel != "gpt-5.6-terra" || info.MaxOutputTokens != 10000 {
		t.Fatalf("request model info = %#v ok=%v", info, ok)
	}
	var payload map[string]any
	if err := json.Unmarshal(preparedProviderBody(t, ctx, request.ChatRequest), &payload); err != nil {
		t.Fatalf("decode prepared body: %v", err)
	}
	if payload["model"] != wireModel || payload["reasoning_effort"] != "medium" {
		t.Fatalf("prepared request did not use pinned catalog context: %s", preparedProviderBody(t, ctx, request.ChatRequest))
	}
}

func TestPrepareProviderRequestRejectsIdentityMismatchWithoutArmingDispatch(t *testing.T) {
	text := "hello"
	request := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.OpenAI,
			Model:    "gpt-5-nano",
			Input: []schemas.ChatMessage{{
				Role:    schemas.ChatMessageRoleUser,
				Content: &schemas.ChatMessageContent{ContentStr: &text},
			}},
		},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, request.RequestType)
	ctx.SetValue(schemas.BifrostContextKeyPreparedRequestBody, "stale")
	state := providerRequestTestState(schemas.Azure, "gpt-5-nano", request.RequestType, 128000)

	if err := PrepareProviderRequest(ctx, state, request); err == nil {
		t.Fatal("provider mismatch was accepted")
	}
	if armed := ctx.Value(schemas.BifrostContextKeyPreparedRequestBody); armed != nil {
		t.Fatal("failed preparation armed provider dispatch")
	}
	if len(request.ChatRequest.RawRequestBody) != 0 {
		t.Fatal("failed preparation retained a provider body")
	}
}

func TestPrepareProviderRequestRequiresTrustedRequestType(t *testing.T) {
	text := "hello"
	request := &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Provider: schemas.OpenAI,
			Model:    "gpt-5.6-terra",
			Input: []schemas.ChatMessage{{
				Role:    schemas.ChatMessageRoleUser,
				Content: &schemas.ChatMessageContent{ContentStr: &text},
			}},
		},
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	state := providerRequestTestState(schemas.OpenAI, request.ChatRequest.Model, request.RequestType, 128000)

	if err := PrepareProviderRequest(ctx, state, request); err == nil {
		t.Fatal("missing trusted request type was accepted")
	}
	if armed := ctx.Value(schemas.BifrostContextKeyPreparedRequestBody); armed != nil {
		t.Fatal("failed preparation armed provider dispatch")
	}
}

func preparedProviderBody(t *testing.T, ctx *schemas.BifrostContext, request providerutils.RequestBodyGetter) []byte {
	t.Helper()
	body, ok := providerutils.CheckAndGetPreparedRequestBody(ctx, request)
	if !ok {
		t.Fatal("prepared provider body is not installed for the request identity")
	}
	return body
}

func providerRequestTestState(provider schemas.ModelProvider, model string, requestType schemas.RequestType, maxOutputTokens int) *State {
	return &State{
		Pair: Pair{
			Resolution: &catalog.ResolvedRequest{
				Provider:    provider,
				Model:       model,
				RequestType: requestType,
				Deployment:  catalog.Deployment{MaxOutputTokens: maxOutputTokens},
			},
		},
	}
}

func providerRequestTestModel(provider schemas.ModelProvider) string {
	if provider == schemas.Anthropic {
		return "claude-sonnet-4-6"
	}
	if provider == catalog.ProviderChutes {
		return "deepseek-ai/DeepSeek-V3.2"
	}
	return "gpt-5.6-terra"
}
