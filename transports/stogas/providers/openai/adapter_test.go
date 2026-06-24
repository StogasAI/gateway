package openai

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/transports/stogas/providers"
)

func TestValidateToolsAllowsOnlyExplicitNoExtraBillingTools(t *testing.T) {
	for _, item := range []struct {
		name  string
		route Route
		body  string
	}{
		{"chat function", RouteChat, `{"tools":[{"type":"function","function":{"name":"lookup"}}]}`},
		{"chat local shell alias", RouteChat, `{"tools":[{"type":"local_shell"}]}`},
		{"chat apply patch", RouteChat, `{"tools":[{"type":"apply_patch"}]}`},
		{"responses local shell", RouteResponses, `{"tools":[{"type":"shell","environment":{"type":"local"}}]}`},
		{"responses web search", RouteResponses, `{"tools":[{"type":"web_search"}]}`},
		{"responses versioned web search", RouteResponses, `{"tools":[{"type":"web_search_2026_01_01"}]}`},
		{"responses preview web search", RouteResponses, `{"tools":[{"type":"web_search_preview_2026_01_01"}]}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := ValidateRequest(toolProfileRequest(t, item.route, item.body)); err != nil {
				t.Fatalf("expected tool request to pass: %v", err)
			}
		})
	}
}

func TestValidateToolsRejectsOpenAINativeToolsAndBadShapes(t *testing.T) {
	for _, item := range []struct {
		name string
		body string
		err  error
	}{
		{"missing type", `{"tools":[{"function":{"name":"lookup"}}]}`, providers.ErrInvalidProviderToolSpec},
		{"chat web search", `{"tools":[{"type":"web_search"}]}`, providers.ErrUnsupportedTool},
		{"chat preview web search", `{"tools":[{"type":"web_search_preview_2026_01_01"}]}`, providers.ErrUnsupportedTool},
		{"file search", `{"tools":[{"type":"file_search"}]}`, providers.ErrUnsupportedTool},
		{"versioned file search", `{"tools":[{"type":"file_search_2026_01_01"}]}`, providers.ErrUnsupportedTool},
		{"code interpreter", `{"tools":[{"type":"code_interpreter"}]}`, providers.ErrUnsupportedTool},
		{"versioned code interpreter", `{"tools":[{"type":"code_interpreter-2026-01-01"}]}`, providers.ErrUnsupportedTool},
		{"image generation", `{"tools":[{"type":"image_generation"}]}`, providers.ErrUnsupportedTool},
		{"computer use hyphen", `{"tools":[{"type":"computer-use-preview"}]}`, providers.ErrUnsupportedTool},
		{"computer use underscore", `{"tools":[{"type":"computer_use_preview"}]}`, providers.ErrUnsupportedTool},
		{"remote mcp", `{"tools":[{"type":"mcp","server_label":"docs"}]}`, providers.ErrUnsupportedTool},
		{"shell missing environment", `{"tools":[{"type":"shell"}]}`, providers.ErrProviderContainers},
		{"shell container auto", `{"tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`, providers.ErrProviderContainers},
		{"shell container reference", `{"tools":[{"type":"shell","environment":{"type":"container_reference","container_id":"cntr_123"}}]}`, providers.ErrProviderContainers},
		{"shell local extra key", `{"tools":[{"type":"shell","environment":{"type":"local"},"max_uses":2}]}`, providers.ErrUnsupportedTool},
		{"shell local environment extra key", `{"tools":[{"type":"shell","environment":{"type":"local","container_id":"cntr_123"}}]}`, providers.ErrUnsupportedTool},
	} {
		t.Run(item.name, func(t *testing.T) {
			err := ValidateRequest(toolProfileRequest(t, RouteChat, item.body))
			if !errors.Is(err, item.err) {
				t.Fatalf("expected %v, got %v", item.err, err)
			}
		})
	}

	if err := ValidateRequest(PolicyRequest{Route: RouteChat, ToolsParseFailed: true}); !errors.Is(err, providers.ErrInvalidProviderToolSpec) {
		t.Fatalf("expected malformed tools to fail closed, got %v", err)
	}
}

func TestValidateRequestRejectsOpenAIOutputCapsBelowMinimum(t *testing.T) {
	err := ValidateRequest(PolicyRequest{Route: RouteChat, OutputTokenLimit: 15})
	if !errors.Is(err, providers.ErrOutputTokenLimitTooLow) {
		t.Fatalf("expected output limit minimum rejection, got %v", err)
	}
}

func TestValidateRequestRejectsUnsupportedInputShapes(t *testing.T) {
	for _, item := range []struct {
		name  string
		route Route
		body  string
	}{
		{"chat file", RouteChat, `{"messages":[{"role":"user","content":[{"type":"file","file":{"file_data":"abc"}}]}]}`},
		{"chat image", RouteChat, `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/image.png"}}]}]}`},
		{"chat audio", RouteChat, `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"abc","format":"mp3"}}]}]}`},
		{"responses file id", RouteResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}]}`},
		{"responses image", RouteResponses, `{"input":[{"type":"input_image","image_url":"https://example.com/image.png"}]}`},
		{"responses audio", RouteResponses, `{"input":[{"type":"input_audio","input_audio":{"data":"abc","format":"mp3"}}]}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			err := ValidateRequest(rawProfileRequest(t, item.route, item.body))
			if !errors.Is(err, providers.ErrUnsupportedInput) {
				t.Fatalf("expected unsupported input rejection, got %v", err)
			}
		})
	}
}

func TestValidateRequestAllowsTextAndInlineResponseFiles(t *testing.T) {
	for _, item := range []struct {
		name  string
		route Route
		body  string
	}{
		{"chat text", RouteChat, `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`},
		{"responses text", RouteResponses, `{"input":[{"type":"input_text","text":"summarize"}]}`},
		{"responses inline file", RouteResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]}]}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := ValidateRequest(rawProfileRequest(t, item.route, item.body)); err != nil {
				t.Fatalf("expected request to pass: %v", err)
			}
		})
	}
}

func TestValidateRequestAllowsWebSearchOptionsOnlyForChatSearchModels(t *testing.T) {
	err := ValidateRequest(PolicyRequest{
		Route:               RouteChat,
		HasWebSearchOptions: true,
		Deployment:          Deployment{Model: "gpt-5.5"},
	})
	if !errors.Is(err, providers.ErrUnsupportedParameter) {
		t.Fatalf("expected normal chat model web_search_options rejection, got %v", err)
	}

	err = ValidateRequest(PolicyRequest{
		Route:               RouteChat,
		HasWebSearchOptions: true,
		Deployment:          Deployment{Model: "gpt-5-search-api"},
	})
	if err != nil {
		t.Fatalf("expected search model web_search_options to pass, got %v", err)
	}
}

func TestWebSearchPricingRules(t *testing.T) {
	if got := webSearchFixedContentTokens("gpt-4o-mini", []string{"web_search"}); got != 8000 {
		t.Fatalf("expected fixed non-preview content tokens, got %d", got)
	}
	if got := webSearchFixedContentTokens("gpt-4.1-mini-2026-01-01", []string{"web_search_2026_01_01"}); got != 8000 {
		t.Fatalf("expected fixed versioned non-preview content tokens, got %d", got)
	}
	if got := webSearchFixedContentTokens("gpt-4o-mini-search-preview", []string{"web_search"}); got != 0 {
		t.Fatalf("search-preview chat model must not use fixed Responses token block, got %d", got)
	}
	if got := webSearchFixedContentTokens("gpt-4o-mini", []string{"web_search_preview"}); got != 0 {
		t.Fatalf("preview tool must not use fixed non-preview token block, got %d", got)
	}

	reasoningPreview := PolicyRequest{
		Route: RouteResponses,
		Deployment: Deployment{
			Model:              "gpt-5.5",
			ReasoningSupported: true,
		},
		ToolTypes: []string{"web_search_preview"},
	}
	if !webSearchContentTokensBilledAtModelRates(reasoningPreview) {
		t.Fatalf("reasoning-model web_search_preview content tokens should be billed at model rates")
	}
	nonReasoningPreview := reasoningPreview
	nonReasoningPreview.Deployment.Model = "gpt-4o-mini"
	nonReasoningPreview.Deployment.ReasoningSupported = false
	if webSearchContentTokensBilledAtModelRates(nonReasoningPreview) {
		t.Fatalf("non-reasoning web_search_preview content tokens should be free")
	}

	ambiguousSearch := PolicyRequest{
		Route: RouteResponses,
		Deployment: Deployment{Pricing: providers.Pricing{
			MeterOpenAIResponsesWebSearchCalls:        {providers.RatePerThousandCalls: "100"},
			MeterOpenAIResponsesWebSearchPreviewCalls: {providers.RatePerThousandCalls: "250"},
		}},
		ToolTypes: []string{"web_search", "web_search_preview_2026_01_01"},
	}
	if got := responsesSearchMeter(ambiguousSearch); got != MeterOpenAIResponsesWebSearchPreviewCalls {
		t.Fatalf("expected ambiguous Responses web search tools to choose costlier meter, got %q", got)
	}
}

func TestChatSearchModelPricingRules(t *testing.T) {
	for _, item := range []struct {
		model string
		meter string
	}{
		{"gpt-5-search-api", MeterOpenAIChatCompletionSearchModelCalls},
		{"gpt-5-search-api-2025-10-14", MeterOpenAIChatCompletionSearchModelCalls},
		{"gpt-4o-search-preview", MeterOpenAIChatCompletionSearchPreviewModelCalls},
		{"gpt-4o-mini-search-preview-2025-03-11", MeterOpenAIChatCompletionSearchPreviewModelCalls},
		{"gpt-5-search-api-preview", ""},
	} {
		ctx := PolicyRequest{Deployment: Deployment{Model: item.model}}
		got, _ := chatSearchMeter(ctx)
		if got != item.meter {
			t.Fatalf("expected %s to use meter %q, got %q", item.model, item.meter, got)
		}
	}

	pricing := providers.Pricing{
		MeterOpenAIChatCompletionSearchPreviewModelCalls: {
			RatePerThousandSearchContextLowCalls:    "25000000000000000000",
			RatePerThousandSearchContextMediumCalls: "27000000000000000000",
			RatePerThousandSearchContextHighCalls:   "30000000000000000000",
		},
	}
	if got := searchContextRateKey(pricing, MeterOpenAIChatCompletionSearchPreviewModelCalls, "low"); got != RatePerThousandSearchContextLowCalls {
		t.Fatalf("expected low-context rate key, got %q", got)
	}
	if got := searchContextRateKey(pricing, MeterOpenAIChatCompletionSearchPreviewModelCalls, "unexpected"); got != RatePerThousandSearchContextHighCalls {
		t.Fatalf("expected fallback to highest known context rate key, got %q", got)
	}
}

func toolProfileRequest(t *testing.T, route Route, body string) PolicyRequest {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := sonic.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("invalid test JSON: %v", err)
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw["tools"], &tools); err != nil {
		t.Fatalf("invalid tools JSON: %v", err)
	}
	toolTypes := make([]string, 0, len(tools))
	for _, tool := range tools {
		toolType := rawStringField(tool, "type")
		if toolType != "" {
			toolTypes = append(toolTypes, toolType)
		}
	}
	return PolicyRequest{Route: route, RawTools: tools, ToolTypes: toolTypes}
}

func rawProfileRequest(t *testing.T, route Route, body string) PolicyRequest {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := sonic.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("invalid test JSON: %v", err)
	}
	return PolicyRequest{Route: route, RawBody: raw}
}
