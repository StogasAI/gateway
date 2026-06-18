package catalog

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func hasMeter(meters []MeterEstimate, key string) bool {
	for _, meter := range meters {
		if meter.MeterKey == key {
			return true
		}
	}
	return false
}

func TestCompiledCatalogDrivesRouteDeploymentResolution(t *testing.T) {
	loadTestCatalog(t)

	nanoDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5-nano", RouteResponses)
	if !ok {
		t.Fatalf("expected gpt-5-nano to resolve")
	}
	if nanoDeployment.Model != "gpt-5-nano" {
		t.Fatalf("expected provider model gpt-5-nano, got %q", nanoDeployment.Model)
	}
	if !nanoDeployment.ReasoningSupported {
		t.Fatalf("expected gpt-5-nano reasoning support")
	}
	if nanoDeployment.ContextWindowTokens != 272000 || nanoDeployment.MaxOutputTokens != 128000 {
		t.Fatalf("expected gpt-5-nano limits, got context=%d output=%d", nanoDeployment.ContextWindowTokens, nanoDeployment.MaxOutputTokens)
	}
	if nanoDeployment.Pricing[meterInputTokens][ratePerMillionTokens] != "50000000000000000" {
		t.Fatalf("expected gpt-5-nano input pricing, got %#v", nanoDeployment.Pricing[meterInputTokens])
	}
	if nanoDeployment.Pricing[meterOpenAIResponsesWebSearchCalls][ratePerThousandCalls] != "10000000000000000000" {
		t.Fatalf("expected provider-level web search call pricing, got %#v", nanoDeployment.Pricing[meterOpenAIResponsesWebSearchCalls])
	}
	if nanoDeployment.Pricing[meterOpenAIResponsesWebSearchPreviewCalls][ratePerThousandCalls] != "10000000000000000000" {
		t.Fatalf("expected provider-level reasoning preview call pricing, got %#v", nanoDeployment.Pricing[meterOpenAIResponsesWebSearchPreviewCalls])
	}

	nanoFlexDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5-nano-flex-latest", RouteChat)
	if !ok {
		t.Fatalf("expected gpt-5-nano flex alias to resolve")
	}
	if nanoFlexDeployment.Model != "gpt-5-nano" {
		t.Fatalf("expected provider model gpt-5-nano, got %q", nanoFlexDeployment.Model)
	}
	if nanoFlexDeployment.ImpliedServiceTier == nil || *nanoFlexDeployment.ImpliedServiceTier != schemas.BifrostServiceTier("flex") {
		t.Fatalf("expected implied gpt-5-nano flex tier, got %#v", nanoFlexDeployment.ImpliedServiceTier)
	}
	if nanoFlexDeployment.Pricing[meterInputTokens][ratePerMillionTokens] != "25000000000000000" {
		t.Fatalf("expected gpt-5-nano flex input pricing, got %#v", nanoFlexDeployment.Pricing[meterInputTokens])
	}
	if nanoFlexDeployment.Pricing[meterOpenAIResponsesWebSearchCalls][ratePerThousandCalls] != "10000000000000000000" {
		t.Fatalf("expected provider-level web search pricing on flex deployment, got %#v", nanoFlexDeployment.Pricing[meterOpenAIResponsesWebSearchCalls])
	}

	nanoPriorityDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5-nano-priority-latest", RouteResponses)
	if !ok {
		t.Fatalf("expected gpt-5-nano priority alias to resolve")
	}
	if nanoPriorityDeployment.Model != "gpt-5-nano" {
		t.Fatalf("expected provider model gpt-5-nano, got %q", nanoPriorityDeployment.Model)
	}
	if nanoPriorityDeployment.ImpliedServiceTier == nil || *nanoPriorityDeployment.ImpliedServiceTier != schemas.BifrostServiceTier("priority") {
		t.Fatalf("expected implied gpt-5-nano priority tier, got %#v", nanoPriorityDeployment.ImpliedServiceTier)
	}
	if nanoPriorityDeployment.Pricing[meterInputTokens][ratePerMillionTokens] != "2500000000000000000" {
		t.Fatalf("expected gpt-5-nano priority input pricing, got %#v", nanoPriorityDeployment.Pricing[meterInputTokens])
	}
	if nanoPriorityDeployment.Pricing[meterOutputTokens][ratePerMillionTokens] != "400000000000000000" {
		t.Fatalf("expected gpt-5-nano priority output pricing, got %#v", nanoPriorityDeployment.Pricing[meterOutputTokens])
	}

	nanoSnapshotDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5-nano-2025-08-07", RouteResponses)
	if !ok {
		t.Fatalf("expected dated gpt-5-nano alias to resolve")
	}
	if nanoSnapshotDeployment.Model != "gpt-5-nano-2025-08-07" {
		t.Fatalf("expected dated gpt-5-nano provider model passthrough, got %q", nanoSnapshotDeployment.Model)
	}

	nanoFlexSnapshotDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5-nano-2025-08-07-flex", RouteResponses)
	if !ok {
		t.Fatalf("expected dated gpt-5-nano flex alias to resolve")
	}
	if nanoFlexSnapshotDeployment.Model != "gpt-5-nano" {
		t.Fatalf("expected dated flex alias to normalize to provider model gpt-5-nano, got %q", nanoFlexSnapshotDeployment.Model)
	}

	deployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5.5-latest", RouteResponses)
	if !ok {
		t.Fatalf("expected latest alias to resolve")
	}
	if deployment.Model != "gpt-5.5" {
		t.Fatalf("expected provider model gpt-5.5, got %q", deployment.Model)
	}
	if deployment.AllowedServiceTier == nil || *deployment.AllowedServiceTier != schemas.BifrostServiceTier("default") {
		t.Fatalf("expected default service tier policy, got %#v", deployment.AllowedServiceTier)
	}
	if deployment.ImpliedServiceTier != nil {
		t.Fatalf("default deployment should not imply service tier")
	}

	providerPrefixedDeployment, ok := DeploymentForRoute(schemas.OpenAI, "open-ai/gpt-5.5", RouteResponses)
	if !ok {
		t.Fatalf("expected provider-prefixed model alias to resolve")
	}
	if providerPrefixedDeployment.ID != "gpt-5.5" || providerPrefixedDeployment.Model != "gpt-5.5" {
		t.Fatalf("expected open-ai/gpt-5.5 to resolve default deployment, got %#v", providerPrefixedDeployment)
	}

	standardSnapshotDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5.5-2026-04-23-standard", RouteResponses)
	if !ok {
		t.Fatalf("expected dated gpt-5.5 standard alias to resolve")
	}
	if standardSnapshotDeployment.Model != "gpt-5.5" {
		t.Fatalf("expected dated standard alias to normalize to provider model gpt-5.5, got %q", standardSnapshotDeployment.Model)
	}

	providerPrefixedFlexDeployment, ok := DeploymentForRoute(schemas.OpenAI, "open-ai/gpt-5.5-flex", RouteResponses)
	if !ok {
		t.Fatalf("expected provider-prefixed flex alias to resolve")
	}
	if providerPrefixedFlexDeployment.ID != "gpt-5.5-flex" || providerPrefixedFlexDeployment.Model != "gpt-5.5" {
		t.Fatalf("expected open-ai/gpt-5.5-flex to resolve flex deployment, got %#v", providerPrefixedFlexDeployment)
	}

	authorProviderPrefixedDeployment, ok := DeploymentForRoute(schemas.OpenAI, "openai/open-ai/gpt-5.5", RouteResponses)
	if !ok {
		t.Fatalf("expected author/provider-prefixed model alias to resolve")
	}
	if authorProviderPrefixedDeployment.ID != "gpt-5.5" || authorProviderPrefixedDeployment.Model != "gpt-5.5" {
		t.Fatalf("expected openai/open-ai/gpt-5.5 to resolve default deployment, got %#v", authorProviderPrefixedDeployment)
	}

	authorProviderPrefixedFlexDeployment, ok := DeploymentForRoute(schemas.OpenAI, "open-ai/openai/gpt-5.5-flex", RouteResponses)
	if !ok {
		t.Fatalf("expected author/provider-prefixed flex alias to resolve")
	}
	if authorProviderPrefixedFlexDeployment.ID != "gpt-5.5-flex" || authorProviderPrefixedFlexDeployment.Model != "gpt-5.5" {
		t.Fatalf("expected open-ai/openai/gpt-5.5-flex to resolve flex deployment, got %#v", authorProviderPrefixedFlexDeployment)
	}

	searchSnapshotDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-4o-search-preview-2025-03-11", RouteChat)
	if !ok {
		t.Fatalf("expected dated gpt-4o search preview alias to resolve")
	}
	if searchSnapshotDeployment.Model != "gpt-4o-search-preview-2025-03-11" {
		t.Fatalf("expected dated provider model passthrough, got %q", searchSnapshotDeployment.Model)
	}

	miniSearchSnapshotDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-4o-mini-search-preview-2025-03-11", RouteChat)
	if !ok {
		t.Fatalf("expected dated gpt-4o mini search preview alias to resolve")
	}
	if miniSearchSnapshotDeployment.Model != "gpt-4o-mini-search-preview-2025-03-11" {
		t.Fatalf("expected dated provider model passthrough, got %q", miniSearchSnapshotDeployment.Model)
	}

	searchAPISnapshotDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5-search-api-2025-10-14", RouteChat)
	if !ok {
		t.Fatalf("expected dated gpt-5 search-api alias to resolve")
	}
	if searchAPISnapshotDeployment.Model != "gpt-5-search-api-2025-10-14" {
		t.Fatalf("expected dated gpt-5 search-api provider model passthrough, got %q", searchAPISnapshotDeployment.Model)
	}

	flexDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5.5-flex", RouteChat)
	if !ok {
		t.Fatalf("expected flex deployment to resolve")
	}
	if flexDeployment.Model != "gpt-5.5" {
		t.Fatalf("expected provider model gpt-5.5, got %q", flexDeployment.Model)
	}
	if flexDeployment.ImpliedServiceTier == nil || *flexDeployment.ImpliedServiceTier != schemas.BifrostServiceTier("flex") {
		t.Fatalf("expected implied flex tier, got %#v", flexDeployment.ImpliedServiceTier)
	}

	model := ""
	requestedTier := schemas.BifrostServiceTier("priority")
	requestedTierPtr := &requestedTier
	if applyResolvedDeployment(&model, &requestedTierPtr, flexDeployment, flexDeployment.ParameterPolicies) {
		t.Fatalf("expected conflicting explicit service tier to be rejected")
	}
}

func TestResolveChatRequestAppliesCatalogPolicy(t *testing.T) {
	loadTestCatalog(t)

	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5-flex","messages":[],"reasoning":{"effort":"minimal"},"unknown":true,"max_tokens":123}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Provider != schemas.OpenAI || resolution.Route != RouteChat {
		t.Fatalf("unexpected route/provider resolution: %#v", resolution)
	}
	if resolution.Model != "gpt-5.5" {
		t.Fatalf("expected provider model gpt-5.5, got %q", resolution.Model)
	}
	if resolution.Deployment.ID != "gpt-5.5-flex" || len(resolution.PolicyChain) != 4 {
		t.Fatalf("expected concrete catalog deployment chain, got %#v", resolution)
	}
	if resolution.Hold.MaxUSDAtoms != "3282500000000000" || resolution.Hold.ProductKey != "gpt-5.5-flex" {
		t.Fatalf("expected catalog hold estimate, got %#v", resolution.Hold)
	}
	if len(resolution.Hold.Meters) != 2 || resolution.Hold.Meters[0].MeterKey != "input_tokens" || resolution.Hold.Meters[1].MeterKey != "output_tokens" {
		t.Fatalf("expected input/output hold meters, got %#v", resolution.Hold.Meters)
	}
	if resolution.chat == nil || resolution.chat.ChatParameters.ServiceTier == nil || *resolution.chat.ChatParameters.ServiceTier != schemas.BifrostServiceTierFlex {
		t.Fatalf("expected implied flex service tier, got %#v", resolution.chat)
	}
	if resolution.chat.ChatParameters.MaxCompletionTokens == nil || *resolution.chat.ChatParameters.MaxCompletionTokens != 123 {
		t.Fatalf("expected max_tokens alias to populate max_completion_tokens, got %#v", resolution.chat.ChatParameters.MaxCompletionTokens)
	}
}

func TestSettlementCostUsesCatalogPricing(t *testing.T) {
	loadTestCatalog(t)

	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5-flex-latest","messages":[],"max_completion_tokens":1000}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	cost := SettlementCost(resolution, &schemas.BifrostLLMUsage{
		PromptTokens:     1000,
		CompletionTokens: 200,
		TotalTokens:      1200,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{
			CachedReadTokens: 100,
		},
	})
	if cost != "5275000000000000" {
		t.Fatalf("expected catalog settlement cost, got %s", cost)
	}

	reasoningCost := SettlementCost(resolution, &schemas.BifrostLLMUsage{
		PromptTokens:     1000,
		CompletionTokens: 200,
		TotalTokens:      1200,
		CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
			ReasoningTokens: 150,
		},
	})
	if reasoningCost != "5500000000000000" {
		t.Fatalf("expected reasoning tokens to be billed as output tokens, got %s", reasoningCost)
	}

	reasoningOnlyCost := SettlementCost(resolution, &schemas.BifrostLLMUsage{
		PromptTokens:     100,
		CompletionTokens: 16,
		TotalTokens:      116,
		CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
			TextTokens:      0,
			ReasoningTokens: 16,
		},
	})
	if reasoningOnlyCost != "490000000000000" {
		t.Fatalf("expected reasoning-only completion to bill input plus output tokens, got %s", reasoningOnlyCost)
	}
}

func TestOpenAIWebSearchFixedContentTokenRule(t *testing.T) {
	if got := openAIWebSearchFixedContentInputTokensForRequest("gpt-4o-mini", []string{"web_search"}); got != 8000 {
		t.Fatalf("expected fixed non-preview web search content tokens, got %d", got)
	}
	if got := openAIWebSearchFixedContentInputTokensForRequest("gpt-4.1-mini-2026-01-01", []string{"web_search_2026_01_01"}); got != 8000 {
		t.Fatalf("expected versioned non-preview web search content tokens, got %d", got)
	}
	if got := openAIWebSearchFixedContentInputTokensForRequest("gpt-4o-mini-search-preview", []string{"web_search"}); got != 0 {
		t.Fatalf("search preview model must not use fixed non-preview content tokens, got %d", got)
	}
	if got := openAIWebSearchFixedContentInputTokensForRequest("gpt-4o-mini", []string{"web_search_preview"}); got != 0 {
		t.Fatalf("preview web search tool must not use fixed non-preview content tokens, got %d", got)
	}
	if !openAIWebSearchContentTokensBilledAtModelRates(Deployment{ReasoningSupported: true, Model: "gpt-5.5"}, requestPricingContext{Route: RouteResponses, ToolTypes: []string{"web_search_preview"}}) {
		t.Fatalf("reasoning-model web_search_preview content tokens should be billed at model rates")
	}
	if openAIWebSearchContentTokensBilledAtModelRates(Deployment{ReasoningSupported: false, Model: "gpt-4o-mini"}, requestPricingContext{Route: RouteResponses, ToolTypes: []string{"web_search_preview"}}) {
		t.Fatalf("non-reasoning web_search_preview content tokens should be free")
	}
	if got := openAIResponsesWebSearchCallMeter(
		Deployment{Pricing: Pricing{
			meterOpenAIResponsesWebSearchCalls:        {ratePerThousandCalls: "100"},
			meterOpenAIResponsesWebSearchPreviewCalls: {ratePerThousandCalls: "250"},
		}},
		requestPricingContext{Route: RouteResponses, ToolTypes: []string{"web_search", "web_search_preview_2026_01_01"}},
	); got != meterOpenAIResponsesWebSearchPreviewCalls {
		t.Fatalf("expected ambiguous Responses web search tools to choose costlier meter, got %q", got)
	}
}

func TestChatSearchModelsUseCatalogWebSearchRules(t *testing.T) {
	loadTestCatalog(t)

	_, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"web_search_options":{"search_context_size":"low"}}`),
	})
	if err == nil {
		t.Fatalf("expected web_search_options to be rejected for gpt-5-nano")
	}

	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5","messages":[],"web_search_options":{"search_context_size":"low"}}`),
	})
	if err == nil {
		t.Fatalf("expected web_search_options to be rejected for non-search model")
	}

	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-search-preview","messages":[],"reasoning":{"effort":"minimal"}}`),
	})
	if err == nil {
		t.Fatalf("expected reasoning to be rejected for non-reasoning search model")
	}

	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-search-preview","messages":[],"web_search_options":{"search_context_size":"low"},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.Deployment.ID != "gpt-4o-search-preview" {
		t.Fatalf("expected search deployment, got %#v", resolution.Deployment)
	}
	if len(resolution.Hold.Meters) != 3 || resolution.Hold.Meters[2].MeterKey != "openai_chat_completion_search_preview_model_calls" {
		t.Fatalf("expected token meters plus guaranteed search call meter, got %#v", resolution.Hold.Meters)
	}
	if resolution.Hold.Meters[2].Quantity != "1" {
		t.Fatalf("expected one guaranteed search call, got %#v", resolution.Hold.Meters[2])
	}
	if resolution.Hold.Meters[2].RateKey != ratePerThousandSearchContextLowCalls {
		t.Fatalf("expected 4o search low-context meter, got %#v", resolution.Hold.Meters)
	}
	if resolution.Hold.Meters[2].AmountUSDAtoms != "30000000000000000" {
		t.Fatalf("expected 4o low-context query cost, got %#v", resolution.Hold.Meters[2])
	}

	searchDefaultResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-search-preview","messages":[],"web_search_options":{},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if len(searchDefaultResolution.Hold.Meters) != 3 || searchDefaultResolution.Hold.Meters[2].RateKey != ratePerThousandSearchContextMediumCalls {
		t.Fatalf("expected 4o search default medium-context meter, got %#v", searchDefaultResolution.Hold.Meters)
	}

	miniLowResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-mini-search-preview","messages":[],"web_search_options":{"search_context_size":"low"},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if len(miniLowResolution.Hold.Meters) != 3 || miniLowResolution.Hold.Meters[2].RateKey != ratePerThousandSearchContextLowCalls {
		t.Fatalf("expected mini search low-context meter, got %#v", miniLowResolution.Hold.Meters)
	}
	if miniLowResolution.Hold.Meters[2].AmountUSDAtoms != "25000000000000000" {
		t.Fatalf("expected mini low-context query cost, got %#v", miniLowResolution.Hold.Meters[2])
	}

	miniDefaultResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-mini-search-preview","messages":[],"web_search_options":{},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if len(miniDefaultResolution.Hold.Meters) != 3 || miniDefaultResolution.Hold.Meters[2].RateKey != ratePerThousandSearchContextMediumCalls {
		t.Fatalf("expected mini search default medium-context meter, got %#v", miniDefaultResolution.Hold.Meters)
	}
}

func TestToolBillingPolicyIsCatalogDriven(t *testing.T) {
	loadTestCatalog(t)

	allowedChatToolRequests := []string{
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"function","function":{"name":"local_lookup"}}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"local_shell"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"apply_patch"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"shell","environment":{"type":"local"}}]}`,
	}
	for _, body := range allowedChatToolRequests {
		if _, err := ResolveRequest(RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)}); err != nil {
			t.Fatalf("expected chat tool request to pass catalog policy: %s: %v", body, err)
		}
	}

	deniedChatToolRequests := []string{
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"shell","environment":{"type":"container_reference","container_id":"cntr_123"}}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"shell"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"shell","environment":{"type":"local"},"max_uses":2}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"file_search"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"file_search_2026_01_01"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"code_interpreter"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"image_generation"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"computer-use-preview"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"web_search"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"web_search_preview_2026_01_01"}]}`,
	}
	for _, body := range deniedChatToolRequests {
		if _, err := ResolveRequest(RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)}); err == nil {
			t.Fatalf("expected chat tool request to be denied by policy: %s", body)
		}
	}

	allowedResponsesToolRequests := []string{
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"web_search"}],"max_output_tokens":16}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"web_search_preview_2026_01_01"}],"max_output_tokens":16}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"web_search"},{"type":"web_search_preview"}],"max_output_tokens":16}`,
	}
	for _, body := range allowedResponsesToolRequests {
		resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
		if err != nil {
			t.Fatalf("expected responses web search tool request to pass catalog policy: %s: %v", body, err)
		}
		if !hasMeter(resolution.Hold.Meters, meterOpenAIResponsesWebSearchCalls) && !hasMeter(resolution.Hold.Meters, meterOpenAIResponsesWebSearchPreviewCalls) {
			t.Fatalf("expected responses web search call meter in hold: %s: %#v", body, resolution.Hold.Meters)
		}
		if !hasMeter(resolution.Hold.Meters, meterInputTokens) {
			t.Fatalf("expected input hold meter for request and billable search content risk: %s: %#v", body, resolution.Hold.Meters)
		}
		settlement := SettlementCost(resolution, &schemas.BifrostLLMUsage{PromptTokens: 100, CompletionTokens: 10, TotalTokens: 110})
		if settlement == "0" {
			t.Fatalf("expected responses web search settlement to include token and call meters")
		}
	}

	deniedResponsesToolRequests := []string{
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"shell","environment":{"type":"container_reference","container_id":"cntr_123"}}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"shell"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"shell","environment":{"type":"local"},"max_uses":2}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"file_search"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"file_search_2026_01_01"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"code_interpreter"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"code_interpreter-2026-01-01"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"image_generation"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"computer-use-preview"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"computer-use-preview-2026-01-01"}]}`,
	}
	for _, body := range deniedResponsesToolRequests {
		if _, err := ResolveRequest(RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)}); err == nil {
			t.Fatalf("expected responses tool request to be denied by policy: %s", body)
		}
	}
}

func TestMVPInputPolicyAllowsInlineFilesAndRejectsFileIDsAndMedia(t *testing.T) {
	loadTestCatalog(t)

	allowed := []string{
		`{"model":"gpt-5.5","input":"hi"}`,
		`{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_text","text":"summarize"}]}]}`,
		`{"model":"gpt-5.5","input":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="}]}`,
		`{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_file","file_data":"data:text/plain;base64,aGk="},{"type":"input_text","text":"summarize"}]}]}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`,
	}
	for _, body := range allowed {
		path := "/v1/responses"
		if strings.Contains(body, `"messages"`) {
			path = "/v1/chat/completions"
		}
		if _, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: []byte(body)}); err != nil {
			t.Fatalf("expected text-only request to pass catalog policy: %s: %v", body, err)
		}
	}

	denied := []string{
		`{"model":"gpt-5.5","input":[{"type":"input_file","file_id":"file_123"}]}`,
		`{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}]}`,
		`{"model":"gpt-5.5","input":[{"type":"input_image","image_url":"https://example.com/image.png"}]}`,
		`{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.com/image.png"}]}]}`,
		`{"model":"gpt-5.5","input":[{"type":"input_audio","input_audio":{"data":"abc","format":"mp3"}}]}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"file","file":{"file_data":"abc"}}]}]}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/image.png"}}]}]}`,
		`{"model":"gpt-5.5","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"abc","format":"mp3"}}]}]}`,
	}
	for _, body := range denied {
		path := "/v1/responses"
		if strings.Contains(body, `"messages"`) {
			path = "/v1/chat/completions"
		}
		if _, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: []byte(body)}); err == nil {
			t.Fatalf("expected file/media request to be denied by policy: %s", body)
		}
	}
}

func TestGPT5NanoSchemaPolicy(t *testing.T) {
	loadTestCatalog(t)

	flexResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano-flex-latest","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("expected gpt-5-nano flex chat request to resolve: %v", err)
	}
	if flexResolution.Deployment.ID != "gpt-5-nano-flex" || flexResolution.Model != "gpt-5-nano" {
		t.Fatalf("unexpected gpt-5-nano flex chat resolution: %#v", flexResolution)
	}
	if flexResolution.chat == nil || flexResolution.chat.ChatParameters.ServiceTier == nil || *flexResolution.chat.ChatParameters.ServiceTier != schemas.BifrostServiceTierFlex {
		t.Fatalf("expected implied gpt-5-nano flex service tier, got %#v", flexResolution.chat)
	}

	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano-flex-latest","messages":[{"role":"user","content":"hi"}],"service_tier":"priority","max_completion_tokens":16}`),
	})
	if err == nil {
		t.Fatalf("expected conflicting gpt-5-nano flex service tier to be rejected")
	}

	priorityResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano-priority-latest","input":"hi","max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("expected gpt-5-nano priority responses request to resolve: %v", err)
	}
	if priorityResolution.Deployment.ID != "gpt-5-nano-priority" || priorityResolution.Model != "gpt-5-nano" {
		t.Fatalf("unexpected gpt-5-nano priority responses resolution: %#v", priorityResolution)
	}
	if priorityResolution.responses == nil || priorityResolution.responses.ResponsesParameters.ServiceTier == nil || *priorityResolution.responses.ResponsesParameters.ServiceTier != schemas.BifrostServiceTierPriority {
		t.Fatalf("expected implied gpt-5-nano priority service tier, got %#v", priorityResolution.responses)
	}

	chatResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"reasoning":{"effort":"minimal"},"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("expected gpt-5-nano chat request to resolve: %v", err)
	}
	if chatResolution.Deployment.ID != "gpt-5-nano" || chatResolution.Model != "gpt-5-nano" {
		t.Fatalf("unexpected gpt-5-nano chat resolution: %#v", chatResolution)
	}
	if chatResolution.Hold.ProductKey != "gpt-5-nano" {
		t.Fatalf("expected gpt-5-nano hold product, got %#v", chatResolution.Hold)
	}

	responsesResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","reasoning":{"effort":"minimal"},"max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("expected gpt-5-nano responses request to resolve: %v", err)
	}
	if responsesResolution.Deployment.ID != "gpt-5-nano" || responsesResolution.Model != "gpt-5-nano" {
		t.Fatalf("unexpected gpt-5-nano responses resolution: %#v", responsesResolution)
	}

	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","max_output_tokens":128001}`),
	})
	if err != ErrParameterTooLarge {
		t.Fatalf("expected output cap rejection, got %v", err)
	}

	for _, item := range []RequestInput{
		{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":15}`),
		},
		{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"max_tokens":15}`),
		},
		{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"gpt-5-nano","input":"hi","max_output_tokens":15}`),
		},
	} {
		if _, err := ResolveRequest(item); err != ErrParameterTooLarge {
			t.Fatalf("expected OpenAI output minimum rejection for %s: %v", string(item.Body), err)
		}
	}
}

func TestResolveRequestRejectsFallbacks(t *testing.T) {
	loadTestCatalog(t)

	_, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5-latest","messages":[],"fallbacks":["gpt-5.5-flex"]}`),
	})
	if err != ErrFallbacksDisabled {
		t.Fatalf("expected fallback rejection, got %v", err)
	}
}

func TestCompiledCatalogFiltersRequestSurface(t *testing.T) {
	loadTestCatalog(t)

	if provider, ok := ProviderForRoute(RouteChat); !ok || provider != schemas.OpenAI {
		t.Fatalf("expected OpenAI provider for chat route, got %q ok=%v", provider, ok)
	}
	if path, ok := PathForRoute(RouteChat); !ok || path != "/v1/chat/completions" {
		t.Fatalf("expected chat path from catalog, got %q ok=%v", path, ok)
	}
	if route, ok := RouteForPath("/v1/responses"); !ok || route != RouteResponses {
		t.Fatalf("expected responses route from catalog path, got %q ok=%v", route, ok)
	}

	fields := KnownFields(RouteChat)
	if !fields["messages"] || !fields["max_tokens"] || fields["authorization"] {
		t.Fatalf("unexpected chat fields: messages=%v max_tokens=%v authorization=%v", fields["messages"], fields["max_tokens"], fields["authorization"])
	}
	if alias, ok := ParameterAliasFor(RouteChat, "max_tokens"); !ok || alias != "max_completion_tokens" {
		t.Fatalf("expected max_tokens alias from catalog, got %q ok=%v", alias, ok)
	}

	params := FilterExtraParams(schemas.OpenAI, "gpt-5.5", RouteChat, map[string]interface{}{
		"authorization": "client-key",
		"reasoning":     map[string]interface{}{"effort": "minimal"},
		"unknown":       true,
	})
	if len(params) != 1 || params["reasoning"] == nil {
		t.Fatalf("expected only catalog-approved request params, got %#v", params)
	}
	authHeaders := AuthHeaderNames(RouteChat)
	for _, expected := range []string{"authorization", "api-key", "x-api-key", "x-goog-api-key"} {
		if !containsString(authHeaders, expected) {
			t.Fatalf("expected auth header aliases to include %q, got %#v", expected, authHeaders)
		}
	}
	clientHeaders := ClientHeaderNames(RouteChat)
	for _, expected := range []string{"content-type", "x-stogas-return-extra-fields"} {
		if !containsString(clientHeaders, expected) {
			t.Fatalf("expected client headers to include %q, got %#v", expected, clientHeaders)
		}
	}
	if !AllowsResponseMetadataField("raw_request") || AllowsResponseMetadataField("secret") {
		t.Fatalf("unexpected response metadata field policy")
	}
	if AllowsUpstreamRequestHeader(schemas.OpenAI, "gpt-5.5", RouteChat, "authorization") {
		t.Fatalf("client authorization header must not be forwarded upstream")
	}
}

func loadTestCatalog(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile("../../../../catalog/compiled/catalog.json.gz")
	if err != nil {
		t.Fatalf("read compiled catalog fixture: %v", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("open compiled catalog fixture: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decompress compiled catalog fixture: %v", err)
	}
	snap, err := snapshotFromCatalogBytes(decoded)
	if err != nil {
		t.Fatalf("parse compiled catalog fixture: %v", err)
	}
	active.Store(snap)
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
