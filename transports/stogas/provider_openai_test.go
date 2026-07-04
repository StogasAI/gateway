package stogas

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestValidateToolsAllowsOnlyExplicitPricedOrCustomerOwnedTools(t *testing.T) {
	for _, item := range []struct {
		name  string
		route openAIAdapterRoute
		body  string
	}{
		{"chat function", openAIAdapterRouteChat, `{"tools":[{"type":"function","function":{"name":"lookup"}}]}`},
		{"chat custom", openAIAdapterRouteChat, `{"tools":[{"type":"custom","name":"lookup"}]}`},
		{"responses function", openAIAdapterRouteResponses, `{"tools":[{"type":"function","name":"lookup"}]}`},
		{"responses custom", openAIAdapterRouteResponses, `{"tools":[{"type":"custom","name":"lookup"}]}`},
		{"responses mcp", openAIAdapterRouteResponses, `{"tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"require_approval":"never"}]}`},
		{"responses mcp filter", openAIAdapterRouteResponses, `{"tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","server_description":"Docs search","allowed_tools":{"read_only":true,"tool_names":["search"]},"require_approval":"never"}]}`},
		{"responses web search", openAIAdapterRouteResponses, `{"tools":[{"type":"web_search"}]}`},
		{"responses compact versioned web search", openAIAdapterRouteResponses, `{"tools":[{"type":"web_search_20260209"}]}`},
		{"responses versioned web search", openAIAdapterRouteResponses, `{"tools":[{"type":"web_search_2026_01_01"}]}`},
		{"responses future web search alias", openAIAdapterRouteResponses, `{"tools":[{"type":"web_search_latest"}]}`},
		{"responses compact preview web search", openAIAdapterRouteResponses, `{"tools":[{"type":"web_search_preview_20250311"}]}`},
		{"responses preview web search", openAIAdapterRouteResponses, `{"tools":[{"type":"web_search_preview_2026_01_01"}]}`},
		{"responses future preview web search alias", openAIAdapterRouteResponses, `{"tools":[{"type":"web_search_preview_latest"}]}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := validateOpenAIGuardrails(toolAdapterContext(t, item.route, item.body)); err != nil {
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
		{"missing type", `{"tools":[{"function":{"name":"lookup"}}]}`, errOpenAIInvalidProviderToolSpec},
		{"chat local shell alias", `{"tools":[{"type":"local_shell"}]}`, errOpenAIUnsupportedTool},
		{"chat apply patch", `{"tools":[{"type":"apply_patch"}]}`, errOpenAIUnsupportedTool},
		{"chat shell local", `{"tools":[{"type":"shell","environment":{"type":"local"}}]}`, errOpenAIUnsupportedTool},
		{"chat web search", `{"tools":[{"type":"web_search"}]}`, errOpenAIUnsupportedTool},
		{"chat preview web search", `{"tools":[{"type":"web_search_preview_2026_01_01"}]}`, errOpenAIUnsupportedTool},
		{"file search", `{"tools":[{"type":"file_search"}]}`, errOpenAIUnsupportedTool},
		{"versioned file search", `{"tools":[{"type":"file_search_2026_01_01"}]}`, errOpenAIUnsupportedTool},
		{"code interpreter", `{"tools":[{"type":"code_interpreter"}]}`, errOpenAIUnsupportedTool},
		{"versioned code interpreter", `{"tools":[{"type":"code_interpreter-2026-01-01"}]}`, errOpenAIUnsupportedTool},
		{"image generation", `{"tools":[{"type":"image_generation"}]}`, errOpenAIUnsupportedTool},
		{"computer use hyphen", `{"tools":[{"type":"computer-use-preview"}]}`, errOpenAIUnsupportedTool},
		{"computer use underscore", `{"tools":[{"type":"computer_use_preview"}]}`, errOpenAIUnsupportedTool},
		{"remote mcp", `{"tools":[{"type":"mcp","server_label":"docs"}]}`, errOpenAIUnsupportedTool},
		{"shell missing environment", `{"tools":[{"type":"shell"}]}`, errOpenAIUnsupportedTool},
		{"shell container auto", `{"tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`, errOpenAIUnsupportedTool},
		{"shell container reference", `{"tools":[{"type":"shell","environment":{"type":"container_reference","container_id":"cntr_123"}}]}`, errOpenAIUnsupportedTool},
		{"shell local extra key", `{"tools":[{"type":"shell","environment":{"type":"local"},"max_uses":2}]}`, errOpenAIUnsupportedTool},
		{"shell local environment extra key", `{"tools":[{"type":"shell","environment":{"type":"local","container_id":"cntr_123"}}]}`, errOpenAIUnsupportedTool},
	} {
		t.Run(item.name, func(t *testing.T) {
			err := validateOpenAIGuardrails(toolAdapterContext(t, openAIAdapterRouteChat, item.body))
			if !errors.Is(err, item.err) {
				t.Fatalf("expected %v, got %v", item.err, err)
			}
		})
	}

	if err := validateOpenAIGuardrails(openAIAdapterContext{Route: openAIAdapterRouteChat, OutputTokenLimit: 16, ToolsParseFailed: true}); !errors.Is(err, errOpenAIInvalidProviderToolSpec) {
		t.Fatalf("expected malformed tools to fail closed, got %v", err)
	}
}

func TestValidateResponsesMCPToolsRejectUnsafeOrUnboundedShapes(t *testing.T) {
	for _, item := range []struct {
		name string
		body string
		err  error
	}{
		{
			name: "missing allowed tools",
			body: `{"tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","require_approval":"never"}]}`,
			err:  errOpenAIInvalidProviderToolSpec,
		},
		{
			name: "empty filter",
			body: `{"tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":{"read_only":false},"require_approval":"never"}]}`,
			err:  errOpenAIInvalidProviderToolSpec,
		},
		{
			name: "arbitrary headers",
			body: `{"tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"headers":{"x-api-key":"secret"},"require_approval":"never"}]}`,
			err:  errOpenAIUnsupportedTool,
		},
		{
			name: "approval workflow object",
			body: `{"tools":[{"type":"mcp","server_label":"remote","server_url":"https://example.com/mcp","allowed_tools":["search"],"require_approval":{"never":{"tool_names":["search"]}}}]}`,
			err:  errOpenAIUnsupportedTool,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			err := validateOpenAIGuardrails(toolAdapterContext(t, openAIAdapterRouteResponses, item.body))
			if !errors.Is(err, item.err) {
				t.Fatalf("expected %v, got %v", item.err, err)
			}
		})
	}
}

func TestValidateResponsesToolsRejectsContainerShellTools(t *testing.T) {
	for _, item := range []struct {
		body string
		err  error
	}{
		{`{"tools":[{"type":"local_shell"}]}`, errOpenAIUnsupportedTool},
		{`{"tools":[{"type":"apply_patch"}]}`, errOpenAIUnsupportedTool},
		{`{"tools":[{"type":"shell"}]}`, errOpenAIUnsupportedTool},
		{`{"tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`, errOpenAIUnsupportedTool},
		{`{"tools":[{"type":"shell","environment":{"type":"container_reference","container_id":"cntr_123"}}]}`, errOpenAIUnsupportedTool},
		{`{"tools":[{"type":"shell","environment":{"type":"local"}}]}`, errOpenAIUnsupportedTool},
		{`{"tools":[{"type":"shell","environment":{"type":"local","container_id":"cntr_123"}}]}`, errOpenAIUnsupportedTool},
		{`{"tools":[{"type":"shell","environment":{"type":"local"},"max_uses":2}]}`, errOpenAIUnsupportedTool},
	} {
		err := validateOpenAIGuardrails(toolAdapterContext(t, openAIAdapterRouteResponses, item.body))
		if !errors.Is(err, item.err) {
			t.Fatalf("expected Responses shell tool rejection %v for %s, got %v", item.err, item.body, err)
		}
	}
}

func TestOpenAIGuardrailRejectsUnnormalizedOutputCapsBelowMinimum(t *testing.T) {
	err := validateOpenAIGuardrails(openAIAdapterContext{Route: openAIAdapterRouteChat, OutputTokenLimit: 15})
	if !errors.Is(err, errOpenAIOutputTokenLimitTooLow) {
		t.Fatalf("expected output limit minimum rejection, got %v", err)
	}
}

func TestOpenAIAdapterNormalizesOutputCapsBelowProviderMinimum(t *testing.T) {
	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat max_completion_tokens",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":15}`,
		},
		{
			name: "chat max_tokens alias",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"max_tokens":15}`,
		},
		{
			name: "responses max_output_tokens",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","max_output_tokens":15}`,
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
			if resolution.OutputTokenLimit() != 15 {
				t.Fatalf("expected catalog to preserve parsed output limit 15 before adapter validation, got %d", resolution.OutputTokenLimit())
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatalf("ValidateRequest returned error: %v", err)
			}
			if resolution.OutputTokenLimit() != 16 {
				t.Fatalf("expected OpenAI adapter to normalize output limit to 16, got %d", resolution.OutputTokenLimit())
			}
			req, err := resolution.ToBifrost(&schemas.BifrostContext{})
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			switch {
			case req.ChatRequest != nil:
				if req.ChatRequest.Params == nil || req.ChatRequest.Params.MaxCompletionTokens == nil || *req.ChatRequest.Params.MaxCompletionTokens != 16 {
					t.Fatalf("expected normalized chat max_completion_tokens, got %#v", req.ChatRequest.Params)
				}
			case req.ResponsesRequest != nil:
				if req.ResponsesRequest.Params == nil || req.ResponsesRequest.Params.MaxOutputTokens == nil || *req.ResponsesRequest.Params.MaxOutputTokens != 16 {
					t.Fatalf("expected normalized responses max_output_tokens, got %#v", req.ResponsesRequest.Params)
				}
			default:
				t.Fatalf("expected Bifrost chat or responses request, got %#v", req)
			}
			if err := state.Adapter.EstimateHold(state); err != nil {
				t.Fatalf("EstimateHold returned error: %v", err)
			}
			if state.Hold.MaxUSDAtoms == "" || state.Hold.MaxUSDAtoms == "0" {
				t.Fatalf("expected normalized output limit to contribute to hold, got %#v", state.Hold)
			}
		})
	}
}

func TestOpenAIAdapterRejectsZeroOutputCaps(t *testing.T) {
	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat max_completion_tokens",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[],"max_completion_tokens":0}`,
		},
		{
			name: "responses max_output_tokens",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","max_output_tokens":0}`,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error before adapter validation: %v", err)
			}
			if resolution.OutputTokenLimit() != 0 {
				t.Fatalf("expected catalog to preserve zero output cap, got %d", resolution.OutputTokenLimit())
			}
			state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
			if err := state.Adapter.ValidateRequest(state); !errors.Is(err, catalog.ErrParameterTooLarge) {
				t.Fatalf("expected OpenAI adapter to reject zero output cap, got %v", err)
			}
		})
	}
}

func TestValidateRequestRejectsUnsupportedInputShapes(t *testing.T) {
	for _, item := range []struct {
		name  string
		route openAIAdapterRoute
		body  string
	}{
		{"chat file", openAIAdapterRouteChat, `{"messages":[{"role":"user","content":[{"type":"file","file":{"file_data":"abc"}}]}]}`},
		{"chat image", openAIAdapterRouteChat, `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/image.png"}}]}]}`},
		{"chat audio", openAIAdapterRouteChat, `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"abc","format":"mp3"}}]}]}`},
		{"responses file id", openAIAdapterRouteResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}]}`},
		{"responses file url", openAIAdapterRouteResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_url":"https://example.com/file.pdf"}]}]}`},
		{"responses inline file", openAIAdapterRouteResponses, `{"input":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]}]}`},
		{"responses image", openAIAdapterRouteResponses, `{"input":[{"type":"input_image","image_url":"https://example.com/image.png"}]}`},
		{"responses audio", openAIAdapterRouteResponses, `{"input":[{"type":"input_audio","input_audio":{"data":"abc","format":"mp3"}}]}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			err := validateOpenAIGuardrails(rawAdapterContext(t, item.route, item.body))
			if !errors.Is(err, errOpenAIUnsupportedInput) {
				t.Fatalf("expected unsupported input rejection, got %v", err)
			}
		})
	}
}

func TestValidateRequestAllowsTextResponsesInput(t *testing.T) {
	for _, item := range []struct {
		name  string
		route openAIAdapterRoute
		body  string
	}{
		{"chat text", openAIAdapterRouteChat, `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`},
		{"responses text", openAIAdapterRouteResponses, `{"input":[{"type":"input_text","text":"summarize"}]}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := validateOpenAIGuardrails(rawAdapterContext(t, item.route, item.body)); err != nil {
				t.Fatalf("expected request to pass: %v", err)
			}
		})
	}
}

func TestValidateRequestAllowsWebSearchOptionsOnlyForChatSearchModels(t *testing.T) {
	err := validateOpenAIGuardrails(openAIAdapterContext{
		Route:               openAIAdapterRouteChat,
		OutputTokenLimit:    16,
		HasWebSearchOptions: true,
		Deployment:          openAIAdapterDeployment{Model: "gpt-5.5"},
	})
	if !errors.Is(err, errOpenAIUnsupportedParameter) {
		t.Fatalf("expected normal chat model web_search_options rejection, got %v", err)
	}

	err = validateOpenAIGuardrails(openAIAdapterContext{
		Route:               openAIAdapterRouteChat,
		OutputTokenLimit:    16,
		HasWebSearchOptions: true,
		Deployment:          openAIAdapterDeployment{Model: "gpt-5-search-api"},
	})
	if err != nil {
		t.Fatalf("expected search model web_search_options to pass, got %v", err)
	}
}

func TestValidateOpenAIChatWebSearchOptionsPreservesTypedShape(t *testing.T) {
	if err := validateResolvedChat(t, `{
		"model":"gpt-4o-search-preview",
		"messages":[],
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
	}`); err != nil {
		t.Fatalf("expected typed web_search_options to pass: %v", err)
	}

	for _, item := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown option",
			body: `{"model":"gpt-4o-search-preview","messages":[],"web_search_options":{"future_option":true},"max_completion_tokens":100}`,
			want: "web_search_options.future_option is not supported",
		},
		{
			name: "unknown location field",
			body: `{"model":"gpt-4o-search-preview","messages":[],"web_search_options":{"user_location":{"type":"approximate","future_field":true}},"max_completion_tokens":100}`,
			want: "web_search_options.user_location.future_field is not supported",
		},
		{
			name: "unknown approximate field",
			body: `{"model":"gpt-4o-search-preview","messages":[],"web_search_options":{"user_location":{"type":"approximate","approximate":{"postal_code":"94107"}}},"max_completion_tokens":100}`,
			want: "web_search_options.user_location.approximate.postal_code is not supported",
		},
		{
			name: "unpriced search context size",
			body: `{"model":"gpt-4o-search-preview","messages":[],"web_search_options":{"search_context_size":"future"},"max_completion_tokens":100}`,
			want: "web_search_options.search_context_size must be low, medium, or high",
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			err := validateResolvedChat(t, item.body)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("expected %q error, got %v", item.want, err)
			}
		})
	}
}

func TestWebSearchPricingRules(t *testing.T) {
	if got := webSearchFixedContentTokens("gpt-4o-mini", []string{"web_search"}); got != 8000 {
		t.Fatalf("expected fixed non-preview content tokens, got %d", got)
	}
	if got := webSearchFixedContentTokens("gpt-4.1-mini-2026-01-01", []string{"web_search"}); got != 8000 {
		t.Fatalf("expected fixed versioned non-preview content tokens, got %d", got)
	}
	if got := webSearchFixedContentTokens("gpt-4o-mini-search-preview", []string{"web_search"}); got != 0 {
		t.Fatalf("search-preview chat model must not use fixed Responses token block, got %d", got)
	}
	if got := webSearchFixedContentTokens("gpt-4.1-mini-search-preview-2026-01-01", []string{"web_search"}); got != 0 {
		t.Fatalf("search-preview gpt-4.1-mini slug must not use fixed Responses token block, got %d", got)
	}
	if got := webSearchFixedContentTokens("gpt-4o-mini", []string{"web_search_preview"}); got != 0 {
		t.Fatalf("preview tool must not use fixed non-preview token block, got %d", got)
	}

	reasoningPreview := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{
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
	if got := responsesSearchMeter(reasoningPreview); got != MeterOpenAIResponsesWebSearchPreviewCalls {
		t.Fatalf("reasoning preview search should use reasoning preview meter, got %q", got)
	}
	if got := responsesSearchMeter(nonReasoningPreview); got != MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls {
		t.Fatalf("non-reasoning preview search should use non-reasoning preview meter, got %q", got)
	}

	ambiguousSearch := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{Pricing: billing.Pricing{
			MeterOpenAIResponsesWebSearchCalls:                    {billing.RatePerThousandCalls: "100"},
			MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls: {billing.RatePerThousandCalls: "250"},
		}},
		ToolTypes: []string{"web_search", "web_search_preview"},
	}
	if got := responsesSearchMeter(ambiguousSearch); got != MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls {
		t.Fatalf("expected ambiguous Responses web search tools to choose costlier meter, got %q", got)
	}

	ambiguousSearchWithExpensiveFixedTokens := ambiguousSearch
	ambiguousSearchWithExpensiveFixedTokens.Deployment.Model = "gpt-4o-mini"
	ambiguousSearchWithExpensiveFixedTokens.Deployment.Pricing[billing.MeterInputTokens] = map[string]string{billing.RatePerMillionTokens: "10000000000000000000000000"}
	if got := responsesSearchMeter(ambiguousSearchWithExpensiveFixedTokens); got != MeterOpenAIResponsesWebSearchCalls {
		t.Fatalf("expected fixed 8000 content tokens to make non-preview web_search costlier, got %q", got)
	}

	allowedNonPreviewSearch := ambiguousSearch
	allowedNonPreviewSearch.RawBody = rawJSON(t, `{"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search"}]}}`)
	if got := responsesSearchMeter(allowedNonPreviewSearch); got != MeterOpenAIResponsesWebSearchCalls {
		t.Fatalf("expected allowed_tools to narrow Responses search meter to non-preview, got %q", got)
	}
	allowedPreviewSearch := ambiguousSearch
	allowedPreviewSearch.RawBody = rawJSON(t, `{"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search_preview_2026_01_01"}]}}`)
	if got := responsesSearchMeter(allowedPreviewSearch); got != MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls {
		t.Fatalf("expected versioned allowed_tools preview selector to use preview meter, got %q", got)
	}
	selectedFunction := ambiguousSearch
	selectedFunction.RawBody = rawJSON(t, `{"tool_choice":{"type":"function","name":"lookup"}}`)
	if got := responsesSearchMeter(selectedFunction); got != "" {
		t.Fatalf("expected function tool_choice to remove hosted-search meter, got %q", got)
	}
}

func TestResponsesWebSearchHoldUsesMaxToolCalls(t *testing.T) {
	req := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{Pricing: billing.Pricing{
			MeterOpenAIResponsesWebSearchCalls: {billing.RatePerThousandCalls: "1000"},
		}},
		RawBody:   rawJSON(t, `{"max_tool_calls":4}`),
		ToolTypes: []string{"web_search"},
	}
	meters := openAIResponsesHostedToolHoldMeters(req, 0, 0)
	if len(meters) != 1 {
		t.Fatalf("expected one web search call meter, got %#v", meters)
	}
	if meters[0].MeterKey != MeterOpenAIResponsesWebSearchCalls || meters[0].Quantity != "4" || !meters[0].HoldRequired {
		t.Fatalf("expected max_tool_calls to scale hold meter, got %#v", meters[0])
	}
}

func TestResponsesPreviewSearchHoldDoesNotEmitNegativeRemainingContextMeter(t *testing.T) {
	req := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{
			Model:                 "gpt-5.5",
			ContextWindowTokens:   100,
			ReasoningSupported:    true,
			Pricing: billing.Pricing{
				billing.MeterInputTokens:                  {billing.RatePerMillionTokens: "1000000"},
				MeterOpenAIResponsesWebSearchPreviewCalls: {billing.RatePerThousandCalls: "1000"},
			},
		},
		RawBody:   rawJSON(t, `{"max_tool_calls":4}`),
		ToolTypes: []string{"web_search_preview"},
	}

	meters := openAIResponsesHostedToolHoldMeters(req, 20, 90)
	if len(meters) != 1 {
		t.Fatalf("expected only the web-search call meter when context is saturated, got %#v", meters)
	}
	if meters[0].MeterKey != MeterOpenAIResponsesWebSearchPreviewCalls || meters[0].Quantity != "4" || !meters[0].HoldRequired {
		t.Fatalf("expected preview call hold meter quantity 4, got %#v", meters[0])
	}
}

func TestResponsesPreviewSearchNonReasoningUses25DollarMeterWithoutContentTokens(t *testing.T) {
	req := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{
			Model:               "gpt-4.1",
			ContextWindowTokens: 200000,
			Pricing: billing.Pricing{
				billing.MeterInputTokens:                              {billing.RatePerMillionTokens: "1000000"},
				MeterOpenAIResponsesWebSearchPreviewCalls:             {billing.RatePerThousandCalls: "10000000000000000000"},
				MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls: {billing.RatePerThousandCalls: "25000000000000000000"},
			},
		},
		RawBody:              rawJSON(t, `{"max_tool_calls":2}`),
		ToolTypes:            []string{"web_search_preview"},
		ActualWebSearchCalls: 1,
	}

	holdMeters := openAIResponsesHostedToolHoldMeters(req, 16, 100)
	if len(holdMeters) != 1 {
		t.Fatalf("expected only non-reasoning preview call hold meter, got %#v", holdMeters)
	}
	if holdMeters[0].MeterKey != MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls || holdMeters[0].Quantity != "2" || holdMeters[0].RateKey != billing.RatePerThousandCalls {
		t.Fatalf("expected non-reasoning preview hold meter at per-call rate, got %#v", holdMeters[0])
	}

	finalMeters := openAIResponsesHostedToolFinalMeters(req)
	if len(finalMeters) != 1 {
		t.Fatalf("expected only non-reasoning preview call final meter, got %#v", finalMeters)
	}
	if finalMeters[0].MeterKey != MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls || finalMeters[0].Quantity != "1" || finalMeters[0].AmountUSDAtoms != "25000000000000000" {
		t.Fatalf("expected non-reasoning preview final meter at $25/1k calls, got %#v", finalMeters[0])
	}
}

func TestResponsesWebSearchHoldDefaultsOmittedMaxToolCallsToEffectiveCap(t *testing.T) {
	req := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{Pricing: billing.Pricing{
			MeterOpenAIResponsesWebSearchCalls: {billing.RatePerThousandCalls: "1000"},
		}},
		RawBody:   rawJSON(t, `{}`),
		ToolTypes: []string{"web_search"},
	}
	meters := openAIResponsesHostedToolHoldMeters(req, 0, 0)
	if len(meters) != 1 {
		t.Fatalf("expected one web search call meter, got %#v", meters)
	}
	if meters[0].MeterKey != MeterOpenAIResponsesWebSearchCalls || meters[0].Quantity != "50" || !meters[0].HoldRequired {
		t.Fatalf("expected omitted max_tool_calls to reserve effective cap 50, got %#v", meters[0])
	}
}

func TestResponsesWebSearchHoldSkipsCallMeterWhenToolChoiceNone(t *testing.T) {
	req := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{Pricing: billing.Pricing{
			MeterOpenAIResponsesWebSearchCalls: {billing.RatePerThousandCalls: "1000"},
		}},
		RawBody:   rawJSON(t, `{"tool_choice":"none"}`),
		ToolTypes: []string{"web_search"},
	}
	if meters := openAIResponsesHostedToolHoldMeters(req, 0, 0); len(meters) != 0 {
		t.Fatalf("expected no hosted-tool hold meters when tool_choice is none, got %#v", meters)
	}
}

func TestResponsesWebSearchSettlementUsesActualCalls(t *testing.T) {
	req := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{Pricing: billing.Pricing{
			MeterOpenAIResponsesWebSearchCalls: {billing.RatePerThousandCalls: "1000"},
		}},
		ToolTypes: []string{"web_search"},
	}
	if meters := openAIResponsesHostedToolFinalMeters(req); len(meters) != 0 {
		t.Fatalf("expected no web search settlement meter without observed calls, got %#v", meters)
	}

	req.ActualWebSearchCalls = 2
	meters := openAIResponsesHostedToolFinalMeters(req)
	if len(meters) != 1 {
		t.Fatalf("expected one web search settlement meter, got %#v", meters)
	}
	if meters[0].MeterKey != MeterOpenAIResponsesWebSearchCalls || meters[0].Quantity != "2" || meters[0].AmountUSDAtoms != "2" || meters[0].HoldRequired {
		t.Fatalf("expected settlement quantity 2 charged at call rate, got %#v", meters[0])
	}

	req.RawBody = rawJSON(t, `{"max_tool_calls":1}`)
	meters = openAIResponsesHostedToolFinalMeters(req)
	if len(meters) != 1 || meters[0].Quantity != "1" {
		t.Fatalf("expected settlement quantity to be capped by max_tool_calls, got %#v", meters)
	}
}

func TestResponsesAmbiguousWebSearchUsesOneCostlierTool(t *testing.T) {
	req := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{
			Model: "gpt-4o-mini",
			Pricing: billing.Pricing{
				billing.MeterInputTokens:                              {billing.RatePerMillionTokens: "1000000"},
				MeterOpenAIResponsesWebSearchCalls:                    {billing.RatePerThousandCalls: "10000000000000000000"},
				MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls: {billing.RatePerThousandCalls: "25000000000000000000"},
			},
		},
		ToolTypes: []string{"web_search", "web_search_preview"},
		RawBody:   rawJSON(t, `{"max_tool_calls":2}`),
	}
	if got := responsesSearchMeter(req); got != MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls {
		t.Fatalf("expected ambiguous tools to choose preview call meter, got %q", got)
	}
	holdMeters := openAIResponsesHostedToolHoldMeters(req, 0, 0)
	if len(holdMeters) != 1 {
		t.Fatalf("expected exactly one hold meter for costlier ambiguous tool, got %#v", holdMeters)
	}
	if holdMeters[0].MeterKey != MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls || holdMeters[0].Quantity != "2" {
		t.Fatalf("expected preview hold meter quantity 2, got %#v", holdMeters[0])
	}

	req.ActualWebSearchCalls = 1
	settlementMeters := openAIResponsesHostedToolFinalMeters(req)
	if len(settlementMeters) != 1 {
		t.Fatalf("expected exactly one settlement meter for costlier ambiguous tool, got %#v", settlementMeters)
	}
	if settlementMeters[0].MeterKey != MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls || settlementMeters[0].Quantity != "1" {
		t.Fatalf("expected preview settlement meter quantity 1, got %#v", settlementMeters[0])
	}

	req.RawBody = rawJSON(t, `{"max_tool_calls":2,"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search"}]}}`)
	req.ActualWebSearchCalls = 1
	holdMeters = openAIResponsesHostedToolHoldMeters(req, 0, 0)
	if len(holdMeters) != 2 {
		t.Fatalf("expected non-preview fixed content token meter plus call hold meter, got %#v", holdMeters)
	}
	if holdMeters[0].MeterKey != billing.MeterInputTokens || holdMeters[0].Quantity != "16000" {
		t.Fatalf("expected non-preview fixed content token hold for two calls, got %#v", holdMeters[0])
	}
	if holdMeters[1].MeterKey != MeterOpenAIResponsesWebSearchCalls || holdMeters[1].Quantity != "2" {
		t.Fatalf("expected allowed_tools to narrow hold meter to non-preview, got %#v", holdMeters[1])
	}
	settlementMeters = openAIResponsesHostedToolFinalMeters(req)
	if len(settlementMeters) != 2 {
		t.Fatalf("expected non-preview fixed content token meter plus call settlement meter, got %#v", settlementMeters)
	}
	if settlementMeters[0].MeterKey != billing.MeterInputTokens || settlementMeters[0].Quantity != "8000" {
		t.Fatalf("expected non-preview fixed content token settlement for one call, got %#v", settlementMeters[0])
	}
	if settlementMeters[1].MeterKey != MeterOpenAIResponsesWebSearchCalls || settlementMeters[1].Quantity != "1" {
		t.Fatalf("expected allowed_tools to narrow settlement meter to non-preview, got %#v", settlementMeters[1])
	}
}

func TestResponsesNonPreviewWebSearchAddsFixedContentTokensOnlyWhenSelected(t *testing.T) {
	req := openAIAdapterContext{
		Route: openAIAdapterRouteResponses,
		Deployment: openAIAdapterDeployment{
			Model: "gpt-4o-mini",
			Pricing: billing.Pricing{
				billing.MeterInputTokens:           {billing.RatePerMillionTokens: "1000000"},
				MeterOpenAIResponsesWebSearchCalls: {billing.RatePerThousandCalls: "10000000000000000000"},
			},
		},
		ToolTypes:            []string{"web_search"},
		ActualWebSearchCalls: 1,
	}
	meters := openAIResponsesHostedToolFinalMeters(req)
	if len(meters) != 2 {
		t.Fatalf("expected fixed content token meter plus call meter, got %#v", meters)
	}
	if meters[0].MeterKey != billing.MeterInputTokens || meters[0].Quantity != "8000" {
		t.Fatalf("expected fixed 8000 search content tokens, got %#v", meters[0])
	}
	if meters[1].MeterKey != MeterOpenAIResponsesWebSearchCalls || meters[1].Quantity != "1" {
		t.Fatalf("expected web_search call meter, got %#v", meters[1])
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
		ctx := openAIAdapterContext{Deployment: openAIAdapterDeployment{Model: item.model}}
		got, _ := chatSearchMeter(ctx)
		if got != item.meter {
			t.Fatalf("expected %s to use meter %q, got %q", item.model, item.meter, got)
		}
	}

	pricing := billing.Pricing{
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

func toolAdapterContext(t *testing.T, route openAIAdapterRoute, body string) openAIAdapterContext {
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
	return openAIAdapterContext{Route: route, OutputTokenLimit: 16, RawTools: tools, ToolTypes: toolTypes}
}

func rawAdapterContext(t *testing.T, route openAIAdapterRoute, body string) openAIAdapterContext {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := sonic.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("invalid test JSON: %v", err)
	}
	return openAIAdapterContext{Route: route, OutputTokenLimit: 16, RawBody: raw}
}

func rawJSON(t *testing.T, body string) map[string]json.RawMessage {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := sonic.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("invalid test JSON: %v", err)
	}
	return raw
}
