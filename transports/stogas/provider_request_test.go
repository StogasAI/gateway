package stogas

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestPrepareProviderRequestRemovesClientIdentityAndAppliesStorePolicy(t *testing.T) {
	text := "hello"
	metadata := map[string]any{"private": "value"}
	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Azure, schemas.Anthropic, catalog.ProviderChutes} {
		t.Run(string(provider)+" chat", func(t *testing.T) {
			model := providerRequestTestModel(provider)
			request := &schemas.BifrostRequest{
				RequestType: schemas.ChatCompletionRequest,
				ChatRequest: &schemas.BifrostChatRequest{
					Provider: provider,
					Model:    model,
					Input: []schemas.ChatMessage{{
						Role:    schemas.ChatMessageRoleUser,
						Content: &schemas.ChatMessageContent{ContentStr: &text},
					}},
					Params: &schemas.ChatParameters{
						Metadata:         &metadata,
						SafetyIdentifier: schemas.Ptr("caller-safety"),
						Store:            schemas.Ptr(true),
						User:             schemas.Ptr("caller-user"),
					},
				},
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, request.RequestType)
			state := providerRequestTestState(provider, model, request.RequestType, 128000)

			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			assertSanitizedProviderParams(t, provider, request.ChatRequest.Params, nil)
			assertSanitizedProviderBody(t, provider, preparedProviderBody(t, ctx, request.ChatRequest))
		})

		if provider == catalog.ProviderChutes {
			continue
		}
		t.Run(string(provider)+" responses", func(t *testing.T) {
			model := providerRequestTestModel(provider)
			role := schemas.ResponsesInputMessageRoleUser
			request := &schemas.BifrostRequest{
				RequestType: schemas.ResponsesRequest,
				ResponsesRequest: &schemas.BifrostResponsesRequest{
					Provider: provider,
					Model:    model,
					Input: []schemas.ResponsesMessage{{
						Role:    &role,
						Content: &schemas.ResponsesMessageContent{ContentStr: &text},
					}},
					Params: &schemas.ResponsesParameters{
						Metadata:         &metadata,
						SafetyIdentifier: schemas.Ptr("caller-safety"),
						Store:            schemas.Ptr(true),
						User:             schemas.Ptr("caller-user"),
					},
				},
			}
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, request.RequestType)
			state := providerRequestTestState(provider, model, request.RequestType, 128000)

			if err := PrepareProviderRequest(ctx, state, request); err != nil {
				t.Fatalf("PrepareProviderRequest returned error: %v", err)
			}
			if provider == schemas.Anthropic && (request.ResponsesRequest.Params.MaxOutputTokens == nil || *request.ResponsesRequest.Params.MaxOutputTokens != 128000) {
				t.Fatalf("Anthropic max_output_tokens = %#v, want pinned limit 128000", request.ResponsesRequest.Params.MaxOutputTokens)
			}
			assertSanitizedProviderParams(t, provider, nil, request.ResponsesRequest.Params)
			assertSanitizedProviderBody(t, provider, preparedProviderBody(t, ctx, request.ResponsesRequest))
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
	if err := ApplyUpstreamCredentials(ctx, state); err != nil {
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
	providerutils.SetModelParams(model, providerutils.ModelParams{MaxOutputTokens: &wrongLimit})
	defer providerutils.DeleteModelParams(model)
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

func TestPrepareProviderRequestUsesPinnedCatalogTranslationContext(t *testing.T) {
	const wireModel = "opaque-upstream-deployment"
	wrongLimit := 100000
	providerutils.SetModelParams(wireModel, providerutils.ModelParams{MaxOutputTokens: &wrongLimit})
	defer providerutils.DeleteModelParams(wireModel)

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
	state := &State{Resolution: &catalog.ResolvedRequest{
		Provider:    schemas.OpenAI,
		Model:       wireModel,
		RequestType: request.RequestType,
		Deployment: catalog.Deployment{
			ModelID:         "gpt-5.6-terra",
			MaxOutputTokens: 10000,
		},
	}}

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
	return &State{Resolution: &catalog.ResolvedRequest{
		Provider:    provider,
		Model:       model,
		RequestType: requestType,
		Deployment:  catalog.Deployment{MaxOutputTokens: maxOutputTokens},
	}}
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

func assertSanitizedProviderParams(t *testing.T, provider schemas.ModelProvider, chat *schemas.ChatParameters, responses *schemas.ResponsesParameters) {
	t.Helper()
	var metadata *map[string]any
	var safetyIdentifier, user *string
	var store *bool
	if chat != nil {
		metadata, safetyIdentifier, store, user = chat.Metadata, chat.SafetyIdentifier, chat.Store, chat.User
	} else {
		metadata, safetyIdentifier, store, user = responses.Metadata, responses.SafetyIdentifier, responses.Store, responses.User
	}
	if metadata != nil || safetyIdentifier != nil || user != nil {
		t.Fatalf("provider fields were not sanitized: metadata=%#v safety=%#v user=%#v", metadata, safetyIdentifier, user)
	}
	if provider == schemas.OpenAI || provider == schemas.Azure {
		if store == nil || *store {
			t.Fatalf("%s store policy = %#v, want false", provider, store)
		}
	} else if store != nil {
		t.Fatalf("provider %s retained store: %#v", provider, store)
	}
}

func assertSanitizedProviderBody(t *testing.T, provider schemas.ModelProvider, body []byte) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode prepared body: %v", err)
	}
	for _, field := range []string{"metadata", "safety_identifier", "user"} {
		if _, ok := payload[field]; ok {
			t.Fatalf("prepared body retained %s: %s", field, body)
		}
	}
	store, hasStore := payload["store"]
	if provider == schemas.OpenAI || provider == schemas.Azure {
		if !hasStore || store != false {
			t.Fatalf("%s prepared body store = %#v present=%v", provider, store, hasStore)
		}
	} else if hasStore {
		t.Fatalf("provider %s prepared body retained store: %s", provider, body)
	}
	if len(body) == 0 || bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		t.Fatal("prepared provider body is empty")
	}
}
