package openai

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/transports/stogas/providers"
)

func TestValidateToolsAllowsOnlyExplicitNoExtraBillingTools(t *testing.T) {
	adapter := Adapter{}
	for _, item := range []struct {
		name  string
		route providers.Route
		body  string
	}{
		{"chat function", providers.RouteChat, `{"tools":[{"type":"function","function":{"name":"lookup"}}]}`},
		{"chat local shell alias", providers.RouteChat, `{"tools":[{"type":"local_shell"}]}`},
		{"chat apply patch", providers.RouteChat, `{"tools":[{"type":"apply_patch"}]}`},
		{"responses local shell", providers.RouteResponses, `{"tools":[{"type":"shell","environment":{"type":"local"}}]}`},
		{"responses web search", providers.RouteResponses, `{"tools":[{"type":"web_search"}]}`},
		{"responses versioned web search", providers.RouteResponses, `{"tools":[{"type":"web_search_2026_01_01"}]}`},
		{"responses preview web search", providers.RouteResponses, `{"tools":[{"type":"web_search_preview_2026_01_01"}]}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := adapter.ValidateRequest(toolContext(t, item.route, item.body)); err != nil {
				t.Fatalf("expected tool request to pass: %v", err)
			}
		})
	}
}

func TestValidateToolsRejectsOpenAINativeToolsAndBadShapes(t *testing.T) {
	adapter := Adapter{}
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
			err := adapter.ValidateRequest(toolContext(t, providers.RouteChat, item.body))
			if !errors.Is(err, item.err) {
				t.Fatalf("expected %v, got %v", item.err, err)
			}
		})
	}

	if err := adapter.ValidateRequest(providers.RequestContext{ToolsParseFailed: true}); !errors.Is(err, providers.ErrInvalidProviderToolSpec) {
		t.Fatalf("expected malformed tools to fail closed, got %v", err)
	}
}

func TestValidateRequestRejectsOpenAIOutputCapsBelowMinimum(t *testing.T) {
	err := Adapter{}.ValidateRequest(providers.RequestContext{Route: providers.RouteChat, OutputTokenLimit: 15})
	if !errors.Is(err, providers.ErrOutputTokenLimitTooLow) {
		t.Fatalf("expected output limit minimum rejection, got %v", err)
	}
}

func TestValidateRequestRejectsUnsupportedInputShapes(t *testing.T) {
	adapter := Adapter{}
	for _, item := range []struct {
		name  string
		route providers.Route
		body  string
	}{
		{"chat file", providers.RouteChat, `{"messages":[{"role":"user","content":[{"type":"file","file":{"file_data":"abc"}}]}]}`},
		{"chat image", providers.RouteChat, `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/image.png"}}]}]}`},
		{"chat audio", providers.RouteChat, `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"abc","format":"mp3"}}]}]}`},
		{"responses file id", providers.RouteResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}]}`},
		{"responses image", providers.RouteResponses, `{"input":[{"type":"input_image","image_url":"https://example.com/image.png"}]}`},
		{"responses audio", providers.RouteResponses, `{"input":[{"type":"input_audio","input_audio":{"data":"abc","format":"mp3"}}]}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			err := adapter.ValidateRequest(rawRequestContext(t, item.route, item.body))
			if !errors.Is(err, providers.ErrUnsupportedInput) {
				t.Fatalf("expected unsupported input rejection, got %v", err)
			}
		})
	}
}

func TestValidateRequestAllowsTextAndInlineResponseFiles(t *testing.T) {
	adapter := Adapter{}
	for _, item := range []struct {
		name  string
		route providers.Route
		body  string
	}{
		{"chat text", providers.RouteChat, `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`},
		{"responses text", providers.RouteResponses, `{"input":[{"type":"input_text","text":"summarize"}]}`},
		{"responses inline file", providers.RouteResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]}]}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := adapter.ValidateRequest(rawRequestContext(t, item.route, item.body)); err != nil {
				t.Fatalf("expected request to pass: %v", err)
			}
		})
	}
}

func TestValidateRequestAllowsWebSearchOptionsOnlyForChatSearchModels(t *testing.T) {
	adapter := Adapter{}
	err := adapter.ValidateRequest(providers.RequestContext{
		Route:               providers.RouteChat,
		HasWebSearchOptions: true,
		Deployment:          providers.Deployment{Model: "gpt-5.5"},
	})
	if !errors.Is(err, providers.ErrUnsupportedParameter) {
		t.Fatalf("expected normal chat model web_search_options rejection, got %v", err)
	}

	err = adapter.ValidateRequest(providers.RequestContext{
		Route:               providers.RouteChat,
		HasWebSearchOptions: true,
		Deployment:          providers.Deployment{Model: "gpt-5-search-api"},
	})
	if err != nil {
		t.Fatalf("expected search model web_search_options to pass, got %v", err)
	}

	err = adapter.ValidateRequest(providers.RequestContext{
		Route:               providers.RouteResponses,
		HasWebSearchOptions: true,
	})
	if !errors.Is(err, providers.ErrUnsupportedParameter) {
		t.Fatalf("expected Responses web_search_options rejection, got %v", err)
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

	reasoningPreview := providers.RequestContext{
		Route: providers.RouteResponses,
		Deployment: providers.Deployment{
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

	ambiguousSearch := providers.RequestContext{
		Route: providers.RouteResponses,
		Deployment: providers.Deployment{Pricing: providers.Pricing{
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
		ctx := providers.RequestContext{Deployment: providers.Deployment{Model: item.model}}
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

func toolContext(t *testing.T, route providers.Route, body string) providers.RequestContext {
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
	return providers.RequestContext{Route: route, RawTools: tools, ToolTypes: toolTypes}
}

func rawRequestContext(t *testing.T, route providers.Route, body string) providers.RequestContext {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := sonic.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("invalid test JSON: %v", err)
	}
	return providers.RequestContext{Route: route, RawBody: raw}
}
