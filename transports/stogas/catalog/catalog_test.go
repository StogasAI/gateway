package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	openaiadapter "github.com/maximhq/bifrost/transports/stogas/providers/openai"
)

const (
	meterInputTokens     = billing.MeterInputTokens
	meterOutputTokens    = billing.MeterOutputTokens
	ratePerMillionTokens = billing.RatePerMillionTokens
	ratePerThousandCalls = billing.RatePerThousandCalls

	meterOpenAIResponsesWebSearchCalls        = openaiadapter.MeterOpenAIResponsesWebSearchCalls
	meterOpenAIResponsesWebSearchPreviewCalls = openaiadapter.MeterOpenAIResponsesWebSearchPreviewCalls
)

func resolveAndValidateProviderPolicy(input RequestInput) (*ResolvedRequest, error) {
	resolution, err := ResolveRequest(input)
	if err != nil {
		return nil, err
	}
	if err := ProviderPolicyError(openaiadapter.ValidateRequest(testOpenAIPolicyRequest(resolution.Route, resolution.Deployment, resolution.outputTokenLimit, resolution.pricing))); err != nil {
		return nil, err
	}
	return resolution, nil
}

func openAIWebSearchFixedContentInputTokensForRequest(model string, toolTypes []string) int {
	return openaiadapter.WebSearchFixedContentInputTokensForRequest(model, toolTypes)
}

func openAIWebSearchContentTokensBilledAtModelRates(deployment Deployment, pricing requestPricingContext) bool {
	return openaiadapter.WebSearchContentTokensBilledAtModelRates(testOpenAIPolicyRequest(pricing.Route, deployment, 0, pricing))
}

func openAIResponsesWebSearchCallMeter(deployment Deployment, pricing requestPricingContext) string {
	return openaiadapter.ResponsesWebSearchCallMeter(openaiadapter.PolicyRequest{
		Route: openaiadapter.Route(pricing.Route),
		Deployment: openaiadapter.Deployment{
			Model:               deployment.Model,
			ContextWindowTokens: deployment.ContextWindowTokens,
			Pricing:             deployment.Pricing,
			ReasoningSupported:  deployment.ReasoningSupported,
		},
		SearchContextSize: pricing.SearchContextSize,
		ToolTypes:         pricing.ToolTypes,
	})
}

func testOpenAIPolicyRequest(route Route, deployment Deployment, outputTokenLimit int, pricing requestPricingContext) openaiadapter.PolicyRequest {
	return openaiadapter.PolicyRequest{
		Route: openaiadapter.Route(route),
		Deployment: openaiadapter.Deployment{
			Model:               deployment.Model,
			ContextWindowTokens: deployment.ContextWindowTokens,
			Pricing:             deployment.Pricing,
			ReasoningSupported:  deployment.ReasoningSupported,
		},
		OutputTokenLimit:    outputTokenLimit,
		HasWebSearchOptions: pricing.HasWebSearchOptions,
		SearchContextSize:   pricing.SearchContextSize,
		ToolsParseFailed:    pricing.ToolsParseFailed,
		RawBody:             pricing.RawBody,
		ToolTypes:           pricing.ToolTypes,
		RawTools:            pricing.RawTools,
	}
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
	if nanoSnapshotDeployment.Model != "gpt-5-nano" {
		t.Fatalf("expected dated gpt-5-nano alias to use canonical provider model gpt-5-nano, got %q", nanoSnapshotDeployment.Model)
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
	if deployment.ServiceTier != "default" {
		t.Fatalf("expected default deployment service tier fact, got %q", deployment.ServiceTier)
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
	if searchSnapshotDeployment.Model != "gpt-4o-search-preview" {
		t.Fatalf("expected dated alias to use canonical provider model gpt-4o-search-preview, got %q", searchSnapshotDeployment.Model)
	}

	searchFlexDeployment, ok := DeploymentForRoute(schemas.OpenAI, "openai/gpt-4o-search-preview-flex", RouteChat)
	if !ok {
		t.Fatalf("expected gpt-4o search flex deployment to resolve")
	}
	if searchFlexDeployment.ID != "gpt-4o-search-preview-flex" || searchFlexDeployment.Model != "gpt-4o-search-preview" {
		t.Fatalf("unexpected gpt-4o search flex deployment %#v", searchFlexDeployment)
	}
	if searchFlexDeployment.ImpliedServiceTier == nil || *searchFlexDeployment.ImpliedServiceTier != schemas.BifrostServiceTier("flex") {
		t.Fatalf("expected gpt-4o search flex implied tier, got %#v", searchFlexDeployment.ImpliedServiceTier)
	}

	miniSearchSnapshotDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-4o-mini-search-preview-2025-03-11", RouteChat)
	if !ok {
		t.Fatalf("expected dated gpt-4o mini search preview alias to resolve")
	}
	if miniSearchSnapshotDeployment.Model != "gpt-4o-mini-search-preview" {
		t.Fatalf("expected dated alias to use canonical provider model gpt-4o-mini-search-preview, got %q", miniSearchSnapshotDeployment.Model)
	}

	searchAPISnapshotDeployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5-search-api-2025-10-14", RouteChat)
	if !ok {
		t.Fatalf("expected dated gpt-5 search-api alias to resolve")
	}
	if searchAPISnapshotDeployment.Model != "gpt-5-search-api" {
		t.Fatalf("expected dated alias to use canonical provider model gpt-5-search-api, got %q", searchAPISnapshotDeployment.Model)
	}

	searchAPIPriorityDeployment, ok := DeploymentForRoute(schemas.OpenAI, "open-ai/openai/gpt-5-search-api-priority", RouteChat)
	if !ok {
		t.Fatalf("expected gpt-5 search API priority deployment to resolve")
	}
	if searchAPIPriorityDeployment.ID != "gpt-5-search-api-priority" || searchAPIPriorityDeployment.Model != "gpt-5-search-api" {
		t.Fatalf("unexpected gpt-5 search API priority deployment %#v", searchAPIPriorityDeployment)
	}
	if searchAPIPriorityDeployment.ImpliedServiceTier == nil || *searchAPIPriorityDeployment.ImpliedServiceTier != schemas.BifrostServiceTier("priority") {
		t.Fatalf("expected gpt-5 search API priority implied tier, got %#v", searchAPIPriorityDeployment.ImpliedServiceTier)
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
	if applyResolvedDeployment(schemas.OpenAI, &model, &requestedTierPtr, flexDeployment) {
		t.Fatalf("expected conflicting explicit service tier to be rejected")
	}
}

func TestProviderForRouteModelUsesCatalogSlugIndexes(t *testing.T) {
	loadTestCatalog(t)

	for _, slug := range []string{"gpt-5.5", "openai/gpt-5.5", "openai/open-ai/gpt-5.5"} {
		provider, ok, err := ProviderForRouteModel(RouteChat, slug)
		if err != nil {
			t.Fatalf("%s: ProviderForRouteModel returned error: %v", slug, err)
		}
		if !ok || provider != schemas.OpenAI {
			t.Fatalf("%s: expected OpenAI provider, got %q ok=%v", slug, provider, ok)
		}
	}

	if _, ok, err := ProviderForRouteModel(RouteChat, "unknown-model"); err != nil || ok {
		t.Fatalf("expected unknown model to miss without error, ok=%v err=%v", ok, err)
	}
}

func TestAnthropicCatalogResolution(t *testing.T) {
	loadTestCatalog(t)

	for _, slug := range []string{"claude-opus-4-8", "anthropic/claude-opus-4-8", "anthropic/anthropic/claude-opus-latest"} {
		provider, ok, err := ProviderForRouteModel(RouteChat, slug)
		if err != nil {
			t.Fatalf("%s: ProviderForRouteModel returned error: %v", slug, err)
		}
		if !ok || provider != schemas.Anthropic {
			t.Fatalf("%s: expected Anthropic provider, got %q ok=%v", slug, provider, ok)
		}
		deployment, ok := DeploymentForRoute(schemas.Anthropic, slug, RouteChat)
		if !ok {
			t.Fatalf("%s: expected Anthropic deployment", slug)
		}
		if deployment.ID != "claude-opus-4-8" || deployment.Model != "claude-opus-4-8" {
			t.Fatalf("%s: unexpected deployment %#v", slug, deployment)
		}
		if deployment.ContextWindowTokens != 1000000 || deployment.MaxOutputTokens != 128000 {
			t.Fatalf("%s: unexpected limits context=%d output=%d", slug, deployment.ContextWindowTokens, deployment.MaxOutputTokens)
		}
	if deployment.Pricing[billing.MeterCacheWrite1hInputTokens][billing.RatePerMillionTokens] != "10000000000000000000" {
		t.Fatalf("%s: expected Anthropic 1h cache write pricing, got %#v", slug, deployment.Pricing)
	}
	if deployment.ServiceTier != "auto" || deployment.ImpliedServiceTier == nil || *deployment.ImpliedServiceTier != schemas.BifrostServiceTierAuto {
		t.Fatalf("%s: expected Anthropic auto deployment tier, got %q implied=%#v", slug, deployment.ServiceTier, deployment.ImpliedServiceTier)
	}
	}

	sonnet, ok := DeploymentForRoute(schemas.Anthropic, "claude-sonnet-latest", RouteChat)
	if !ok {
		t.Fatalf("expected Sonnet latest deployment")
	}
	if sonnet.ID != "claude-sonnet-4-6" || sonnet.MaxOutputTokens != 64000 {
		t.Fatalf("unexpected Sonnet deployment %#v", sonnet)
	}

	fast, ok := DeploymentForRoute(schemas.Anthropic, "claude-opus-4-8-fast", RouteChat)
	if !ok {
		t.Fatalf("expected Opus fast deployment")
	}
	if fast.ID != "claude-opus-4-8-fast" || fast.Model != "claude-opus-4-8" {
		t.Fatalf("unexpected Opus fast deployment %#v", fast)
	}
	if fast.Pricing[billing.MeterInputTokens][billing.RatePerMillionTokens] != "10000000000000000000" ||
		fast.Pricing[billing.MeterOutputTokens][billing.RatePerMillionTokens] != "50000000000000000000" {
		t.Fatalf("unexpected Opus fast pricing %#v", fast.Pricing)
	}
	if fast.ServiceTier != "auto" || fast.ImpliedServiceTier == nil || *fast.ImpliedServiceTier != schemas.BifrostServiceTierAuto {
		t.Fatalf("expected Opus fast auto deployment tier, got %q implied=%#v", fast.ServiceTier, fast.ImpliedServiceTier)
	}

	standard, ok := DeploymentForRoute(schemas.Anthropic, "anthropic/claude-opus-4-8-standard", RouteChat)
	if !ok {
		t.Fatalf("expected Opus standard-only deployment")
	}
	if standard.ID != "claude-opus-4-8-standard-only" || standard.ServiceTier != "standard_only" {
		t.Fatalf("unexpected Opus standard-only deployment %#v", standard)
	}
	if standard.ImpliedServiceTier == nil || *standard.ImpliedServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected Opus standard-only to imply Bifrost default, got %#v", standard.ImpliedServiceTier)
	}

	responsesProvider, ok, err := ProviderForRouteModel(RouteResponses, "anthropic/claude-sonnet-4-6")
	if err != nil {
		t.Fatalf("Responses ProviderForRouteModel returned error: %v", err)
	}
	if !ok || responsesProvider != schemas.Anthropic {
		t.Fatalf("expected Anthropic provider for Responses route, got %q ok=%v", responsesProvider, ok)
	}
	responsesDeployment, ok := DeploymentForRoute(schemas.Anthropic, "anthropic/claude-sonnet-4-6", RouteResponses)
	if !ok || responsesDeployment.ID != "claude-sonnet-4-6" {
		t.Fatalf("expected Anthropic Sonnet deployment for Responses route, got %#v ok=%v", responsesDeployment, ok)
	}
}

func TestResolveChatRequestAppliesCatalogPolicy(t *testing.T) {
	loadTestCatalog(t)

	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5-flex","messages":[],"reasoning":{"effort":"minimal"},"max_tokens":123}`),
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
	if resolution.chat == nil || resolution.chat.ChatParameters.ServiceTier == nil || *resolution.chat.ChatParameters.ServiceTier != schemas.BifrostServiceTierFlex {
		t.Fatalf("expected implied flex service tier, got %#v", resolution.chat)
	}
	if resolution.chat.ChatParameters.MaxCompletionTokens == nil || *resolution.chat.ChatParameters.MaxCompletionTokens != 123 {
		t.Fatalf("expected max_tokens alias to populate max_completion_tokens, got %#v", resolution.chat.ChatParameters.MaxCompletionTokens)
	}

	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5","messages":[],"unknown":true}`),
	})
	if err == nil {
		t.Fatalf("expected unknown request field rejection")
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

	_, err := resolveAndValidateProviderPolicy(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"web_search_options":{"search_context_size":"low"}}`),
	})
	if err == nil {
		t.Fatalf("expected web_search_options to be rejected for gpt-5-nano")
	}

	_, err = resolveAndValidateProviderPolicy(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.5","messages":[],"web_search_options":{"search_context_size":"low"}}`),
	})
	if err == nil {
		t.Fatalf("expected web_search_options to be rejected for non-search model")
	}

	_, err = resolveAndValidateProviderPolicy(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-search-preview","messages":[],"reasoning":{"effort":"minimal"}}`),
	})
	if err == nil {
		t.Fatalf("expected reasoning to be rejected for non-reasoning search model")
	}

	gpt5SearchResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-search-api","messages":[],"web_search_options":{"search_context_size":"high"},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("expected gpt-5 search API request to resolve: %v", err)
	}
	if gpt5SearchResolution.Deployment.ID != "gpt-5-search-api" {
		t.Fatalf("expected gpt-5 search API deployment, got %#v", gpt5SearchResolution.Deployment)
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

	searchDefaultResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-search-preview","messages":[],"web_search_options":{},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if searchDefaultResolution.Deployment.ID != "gpt-4o-search-preview" {
		t.Fatalf("expected 4o search default deployment, got %#v", searchDefaultResolution.Deployment)
	}

	miniLowResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-mini-search-preview","messages":[],"web_search_options":{"search_context_size":"low"},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if miniLowResolution.Deployment.ID != "gpt-4o-mini-search-preview" {
		t.Fatalf("expected mini search low-context deployment, got %#v", miniLowResolution.Deployment)
	}

	miniDefaultResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-4o-mini-search-preview","messages":[],"web_search_options":{},"max_completion_tokens":100}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if miniDefaultResolution.Deployment.ID != "gpt-4o-mini-search-preview" {
		t.Fatalf("expected mini search default deployment, got %#v", miniDefaultResolution.Deployment)
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
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"computer_use_preview"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"mcp","server_label":"docs"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"web_search"}]}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{"type":"web_search_preview_2026_01_01"}]}`,
		`{"model":"gpt-5-search-api","messages":[],"tools":[{"type":"web_search"}],"web_search_options":{}}`,
		`{"model":"gpt-4o-search-preview","messages":[],"tools":[{"type":"web_search_preview"}],"web_search_options":{}}`,
		`{"model":"gpt-5.5","messages":[],"tools":{"type":"web_search"}}`,
		`{"model":"gpt-5.5","messages":[],"tools":[{}]}`,
	}
	for _, body := range deniedChatToolRequests {
		if _, err := resolveAndValidateProviderPolicy(RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)}); err == nil {
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
		if !containsString(resolution.ToolTypes(), "web_search") && !containsString(resolution.ToolTypes(), "web_search_preview") && !containsString(resolution.ToolTypes(), "web_search_preview_2026_01_01") {
			t.Fatalf("expected responses web search tool facts: %s: %#v", body, resolution.ToolTypes())
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
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"computer_use_preview"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"computer-use-preview-2026-01-01"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"mcp","server_label":"docs"}]}`,
		`{"model":"gpt-5.5","input":"hi","tools":{"type":"web_search"}}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{}]}`,
	}
	for _, body := range deniedResponsesToolRequests {
		if _, err := resolveAndValidateProviderPolicy(RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)}); err == nil {
			t.Fatalf("expected responses tool request to be denied by policy: %s", body)
		}
	}

	_, err := resolveAndValidateProviderPolicy(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.5","input":"hi","web_search_options":{"search_context_size":"low"}}`),
	})
	if err == nil {
		t.Fatalf("expected Responses web_search_options to be rejected")
	}

	_, err = resolveAndValidateProviderPolicy(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.5","input":"hi","tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`),
	})
	if !errors.Is(err, ErrProviderContainersUnsupported) {
		t.Fatalf("expected hosted shell container rejection, got %v", err)
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
		`{"model":"gpt-5.5","input":{"type":"input_file","file_id":"file_123"}}`,
		`{"model":"gpt-5.5","input":{"role":"user","content":[{"type":"input_file","file_id":"file_123"}]}}`,
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
		if _, err := resolveAndValidateProviderPolicy(RequestInput{Method: "POST", Path: path, Body: []byte(body)}); err == nil {
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

	defaultResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"auto","max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("expected gpt-5-nano default request with auto service tier to resolve: %v", err)
	}
	if defaultResolution.Deployment.ID != "gpt-5-nano" || defaultResolution.chat == nil || defaultResolution.chat.ChatParameters.ServiceTier == nil || *defaultResolution.chat.ChatParameters.ServiceTier != schemas.BifrostServiceTierAuto {
		t.Fatalf("unexpected gpt-5-nano auto service tier resolution: %#v", defaultResolution)
	}

	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"priority","max_completion_tokens":16}`),
	})
	if err == nil {
		t.Fatalf("expected priority service tier to be rejected for default gpt-5-nano deployment")
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
		if _, err := resolveAndValidateProviderPolicy(item); err != ErrParameterTooLarge {
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

	if provider, ok := ProviderForRoute(RouteChat); ok || provider != "" {
		t.Fatalf("chat route has multiple providers and should not collapse to one provider, got %q ok=%v", provider, ok)
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
}

func loadTestCatalog(t *testing.T) {
	t.Helper()
	snap, err := snapshotFromCatalogBytes(embeddedCatalogJSON)
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
