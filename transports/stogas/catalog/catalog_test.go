package catalog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

const (
	meterInputTokens                         = billing.MeterInputTokens
	meterOutputTokens                        = billing.MeterOutputTokens
	meterOpenAIResponsesWebSearchCalls       = "openai_responses_web_search_calls"
	meterOpenAIResponsesWebSearchPreviewCalls = "openai_responses_web_search_preview_calls"
	meterOpenAIResponsesWebSearchPreviewNonReasoningCalls = "openai_responses_web_search_preview_non_reasoning_calls"
	ratePerMillionTokens                     = billing.RatePerMillionTokens
	ratePerThousandCalls                     = billing.RatePerThousandCalls
)

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
	if _, ok := nanoDeployment.Pricing[meterOpenAIResponsesWebSearchCalls]; ok {
		t.Fatalf("provider-level web search call pricing must not be duplicated onto deployment pricing: %#v", nanoDeployment.Pricing[meterOpenAIResponsesWebSearchCalls])
	}
	if _, ok := nanoDeployment.Pricing[meterOpenAIResponsesWebSearchPreviewCalls]; ok {
		t.Fatalf("provider-level web search preview pricing must not be duplicated onto deployment pricing: %#v", nanoDeployment.Pricing[meterOpenAIResponsesWebSearchPreviewCalls])
	}
	if _, ok := nanoDeployment.Pricing[meterOpenAIResponsesWebSearchPreviewNonReasoningCalls]; ok {
		t.Fatalf("provider-level non-reasoning web search preview pricing must not be duplicated onto deployment pricing: %#v", nanoDeployment.Pricing[meterOpenAIResponsesWebSearchPreviewNonReasoningCalls])
	}
	openAIPricing := ProviderPricing(schemas.OpenAI)
	if openAIPricing[meterOpenAIResponsesWebSearchCalls][ratePerThousandCalls] != "10000000000000000000" {
		t.Fatalf("expected provider-level web search call pricing, got %#v", openAIPricing[meterOpenAIResponsesWebSearchCalls])
	}
	if openAIPricing[meterOpenAIResponsesWebSearchPreviewCalls][ratePerThousandCalls] != "10000000000000000000" {
		t.Fatalf("expected provider-level reasoning preview call pricing, got %#v", openAIPricing[meterOpenAIResponsesWebSearchPreviewCalls])
	}
	if openAIPricing[meterOpenAIResponsesWebSearchPreviewNonReasoningCalls][ratePerThousandCalls] != "25000000000000000000" {
		t.Fatalf("expected provider-level non-reasoning preview call pricing, got %#v", openAIPricing[meterOpenAIResponsesWebSearchPreviewNonReasoningCalls])
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
	if _, ok := nanoFlexDeployment.Pricing[meterOpenAIResponsesWebSearchCalls]; ok {
		t.Fatalf("provider-level web search pricing must stay provider-owned, got deployment pricing %#v", nanoFlexDeployment.Pricing[meterOpenAIResponsesWebSearchCalls])
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

func TestAnthropicDeploymentsDeclareAllCachePricingMeters(t *testing.T) {
	loadTestCatalog(t)

	snap := active.Load()
	if snap == nil {
		t.Fatal("expected loaded catalog")
	}
	for deploymentID, deployment := range snap.graph.Deployments {
		if deployment.ProviderID != string(schemas.Anthropic) {
			continue
		}
		for _, meterKey := range []string{
			billing.MeterInputTokens,
			billing.MeterCachedInputTokens,
			billing.MeterCacheWrite5mInputTokens,
			billing.MeterCacheWrite1hInputTokens,
			billing.MeterOutputTokens,
		} {
			rates := deployment.Pricing[meterKey]
			if rates[billing.RatePerMillionTokens] == "" {
				t.Fatalf("%s missing %s.%s pricing: %#v", deploymentID, meterKey, billing.RatePerMillionTokens, deployment.Pricing)
			}
		}
	}
}

func TestOpenAILongContextDeploymentsDeclareLongContextRateKeys(t *testing.T) {
	loadTestCatalog(t)

	snap := active.Load()
	if snap == nil {
		t.Fatal("expected loaded catalog")
	}
	for deploymentID, deployment := range snap.graph.Deployments {
		contextWindowTokens := effectiveContextWindowTokens(deployment, snap.graph.Models[deployment.ModelID])
		if deployment.ProviderID != string(schemas.OpenAI) || contextWindowTokens <= billing.LongContextThresholdTokens {
			continue
		}
		for _, meterKey := range []string{
			billing.MeterInputTokens,
			billing.MeterCachedInputTokens,
			billing.MeterOutputTokens,
		} {
			rates := deployment.Pricing[meterKey]
			if rates[billing.RatePerMillionContextLTE272K] == "" || rates[billing.RatePerMillionContextGT272K] == "" {
				t.Fatalf("%s has context window %d and must declare %s short/long rates: %#v", deploymentID, contextWindowTokens, meterKey, rates)
			}
		}
	}

	nano, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5-nano", RouteResponses)
	if !ok {
		t.Fatal("expected gpt-5-nano deployment")
	}
	if nano.ContextWindowTokens != billing.LongContextThresholdTokens {
		t.Fatalf("expected gpt-5-nano to sit at the long-context threshold, got %d", nano.ContextWindowTokens)
	}
	if nano.Pricing[billing.MeterInputTokens][billing.RatePerMillionContextGT272K] != "" {
		t.Fatalf("gpt-5-nano cannot exceed %d context tokens and should not advertise gt-272k pricing: %#v", billing.LongContextThresholdTokens, nano.Pricing[billing.MeterInputTokens])
	}
}

func TestProviderPreferenceDisambiguatesCatalogSlugIndexes(t *testing.T) {
	previous := active.Load()
	defer active.Store(previous)
	active.Store(&snapshot{
		graph: compiledGraph{
				ProviderEndpoints: map[string]compiledProviderEndpoint{
					"anthropic-messages": {
						ID:              "anthropic-messages",
						ProviderID:      "anthropic",
						StogasEndpoints: []string{"stogas-chat-completions"},
				},
				"openai-chat-completions": {
					ID:              "openai-chat-completions",
					ProviderID:      "openai",
					StogasEndpoints: []string{"stogas-chat-completions"},
				},
				},
				Providers: map[string]compiledProvider{
					"anthropic": {ProviderSlugs: []string{"anthropic", "anthropic-api"}},
					"openai":   {ProviderSlugs: []string{"openai", "open-ai"}},
				},
			},
			providerEndpointRequestSlugs: map[string]string{
				"anthropic-messages:anthropic-lab/anthropic-api/shared-model": "anthropic-shared-model",
				"anthropic-messages:anthropic-lab/shared-model":               "anthropic-shared-model",
				"anthropic-messages:anthropic/anthropic/shared-model":         "anthropic-shared-model",
				"anthropic-messages:anthropic/shared-model":                   "anthropic-shared-model",
				"anthropic-messages:shared-model":                             "anthropic-shared-model",
				"openai-chat-completions:open-ai/openai/shared-model":          "openai-shared-model",
				"openai-chat-completions:open-ai/shared-model":                 "openai-shared-model",
				"openai-chat-completions:openai/open-ai/shared-model":          "openai-shared-model",
				"openai-chat-completions:openai/openai/shared-model":           "openai-shared-model",
				"openai-chat-completions:openai/shared-model":                  "openai-shared-model",
				"openai-chat-completions:shared-model":                         "openai-shared-model",
			},
		})

	if _, _, err := ProviderForRouteModelPreference(RouteChat, "shared-model", ""); !errors.Is(err, ErrModelAmbiguous) {
		t.Fatalf("expected ambiguous model without provider preference, got %v", err)
	}
	provider, ok, err := ProviderForRouteModelPreference(RouteChat, "open-ai/shared-model", "")
	if err != nil || !ok || provider != schemas.OpenAI {
		t.Fatalf("expected provider-prefixed slug to resolve openai, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelPreference(RouteChat, "openai/open-ai/shared-model", "")
	if err != nil || !ok || provider != schemas.OpenAI {
		t.Fatalf("expected author/provider-prefixed slug to resolve openai, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelPreference(RouteChat, "anthropic/shared-model", "")
	if err != nil || !ok || provider != schemas.Anthropic {
		t.Fatalf("expected provider-prefixed slug to resolve anthropic, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelPreference(RouteChat, "anthropic/anthropic/shared-model", "")
	if err != nil || !ok || provider != schemas.Anthropic {
		t.Fatalf("expected author/provider-prefixed slug to resolve anthropic, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelPreference(RouteChat, "anthropic-lab/shared-model", "")
	if err != nil || !ok || provider != schemas.Anthropic {
		t.Fatalf("expected author-prefixed slug to resolve anthropic, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelPreference(RouteChat, "anthropic-lab/anthropic-api/shared-model", "")
	if err != nil || !ok || provider != schemas.Anthropic {
		t.Fatalf("expected distinct author/provider-prefixed slug to resolve anthropic, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelPreference(RouteChat, "shared-model", "open-ai")
	if err != nil || !ok || provider != schemas.OpenAI {
		t.Fatalf("expected openai provider preference to resolve, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelPreference(RouteChat, "shared-model", "anthropic")
	if err != nil || !ok || provider != schemas.Anthropic {
		t.Fatalf("expected anthropic provider preference to resolve, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelRouting(RouteChat, "shared-model", ProviderRoutingPreference{Only: []string{"openai", "anthropic"}, Order: []string{"anthropic"}})
	if err != nil || !ok || provider != schemas.Anthropic {
		t.Fatalf("expected provider order preference to resolve anthropic, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelRouting(RouteChat, "shared-model", ProviderRoutingPreference{Order: []string{"anthropic"}})
	if err != nil || !ok || provider != schemas.Anthropic {
		t.Fatalf("expected order-only provider preference to resolve anthropic, provider=%q ok=%v err=%v", provider, ok, err)
	}
	provider, ok, err = ProviderForRouteModelRouting(RouteChat, "shared-model", ProviderRoutingPreference{Only: []string{"openai"}, Order: []string{"anthropic", "openai"}})
	if err != nil || !ok || provider != schemas.OpenAI {
		t.Fatalf("expected provider order to respect only filter, provider=%q ok=%v err=%v", provider, ok, err)
	}
	if _, _, err := ProviderForRouteModelRouting(RouteChat, "shared-model", ProviderRoutingPreference{Only: []string{"openai", "anthropic"}}); !errors.Is(err, ErrModelAmbiguous) {
		t.Fatalf("expected multi-provider only filter without order to stay ambiguous, got %v", err)
	}
	provider, ok, err = ProviderForRouteModelRouting(RouteChat, "shared-model", ProviderRoutingPreference{Only: []string{"openai"}})
	if err != nil || !ok || provider != schemas.OpenAI {
		t.Fatalf("expected single only filter to resolve openai, provider=%q ok=%v err=%v", provider, ok, err)
	}
	if _, _, err := ProviderForRouteModelPreference(RouteChat, "shared-model", "missing"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected unknown provider preference to be rejected, got %v", err)
	}
	if _, _, err := ProviderForRouteModelRouting(RouteChat, "shared-model", ProviderRoutingPreference{Only: []string{"missing"}}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected unknown provider in only filter to be rejected, got %v", err)
	}
	if _, _, err := ProviderForRouteModelRouting(RouteChat, "shared-model", ProviderRoutingPreference{Order: []string{"missing"}}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected unknown provider in order preference to be rejected, got %v", err)
	}
	if _, _, err := ProviderForRouteModelPreference(RouteChat, "missing-model", "openai"); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("expected unavailable model for preferred provider, got %v", err)
	}
}

func TestProviderPreferenceIsLocalRoutingHint(t *testing.T) {
	loadTestCatalog(t)

	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"claude-sonnet-4-6","provider":"anthropic","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("expected provider preference to resolve request: %v", err)
	}
	if resolution.Provider != schemas.Anthropic || resolution.Deployment.ID != "claude-sonnet-4-6" {
		t.Fatalf("unexpected provider preference resolution: %#v", resolution)
	}
	if resolution.Model != "claude-sonnet-4-6" {
		t.Fatalf("expected canonical upstream model slug, got %q", resolution.Model)
	}
	if _, ok := resolution.chat.ExtraParams["provider"]; ok {
		t.Fatalf("provider preference must not be forwarded as extra param: %#v", resolution.chat.ExtraParams)
	}
	if _, ok := resolution.chat.ExtraParams["rules"]; ok {
		t.Fatalf("rules preference must not be forwarded as extra param: %#v", resolution.chat.ExtraParams)
	}

	resolution, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"claude-sonnet-4-6","rules":{"only":["anthropic"],"order":["anthropic"]},"input":"hi","max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("expected rules object preference to resolve request: %v", err)
	}
	if resolution.Provider != schemas.Anthropic || resolution.Deployment.ID != "claude-sonnet-4-6" {
		t.Fatalf("unexpected rules object preference resolution: %#v", resolution)
	}
	if _, ok := resolution.responses.ExtraParams["provider"]; ok {
		t.Fatalf("provider object preference must not be forwarded as extra param: %#v", resolution.responses.ExtraParams)
	}
	if _, ok := resolution.responses.ExtraParams["rules"]; ok {
		t.Fatalf("rules object preference must not be forwarded as extra param: %#v", resolution.responses.ExtraParams)
	}

	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"claude-sonnet-4-6","provider":"openai","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("expected conflicting provider preference to reject request, got %v", err)
	}

	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"claude-sonnet-4-6","provider":42,"messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if err == nil || !strings.Contains(err.Error(), "provider must be a non-empty string or an object") {
		t.Fatalf("expected invalid provider preference shape to reject request, got %v", err)
	}
	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"claude-sonnet-4-6","provider":{"only":[]},"messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16}`),
	})
	if err == nil || !strings.Contains(err.Error(), "provider must be a non-empty string or an object") {
		t.Fatalf("expected empty provider preference list to reject request, got %v", err)
	}
	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"claude-sonnet-4-6","provider":"anthropic","rules":"anthropic","input":"hi","max_output_tokens":16}`),
	})
	if err == nil || !strings.Contains(err.Error(), "provider and rules cannot both be set") {
		t.Fatalf("expected duplicate routing preference aliases to reject request, got %v", err)
	}
	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"claude-sonnet-4-6","rules":{"only":[]},"input":"hi","max_output_tokens":16}`),
	})
	if err == nil || !strings.Contains(err.Error(), "rules must be a non-empty string or an object") {
		t.Fatalf("expected empty rules preference list to reject request, got %v", err)
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
		if deployment.ServiceTier != "standard" || deployment.ImpliedServiceTier == nil || *deployment.ImpliedServiceTier != schemas.BifrostServiceTierDefault {
			t.Fatalf("%s: expected Anthropic standard deployment tier, got %q implied=%#v", slug, deployment.ServiceTier, deployment.ImpliedServiceTier)
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
	if fast.ServiceTier != "standard" || fast.ImpliedServiceTier == nil || *fast.ImpliedServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected Opus fast standard deployment tier, got %q implied=%#v", fast.ServiceTier, fast.ImpliedServiceTier)
	}

	standardOnlyTier := schemas.BifrostServiceTier("standard_only")
	standard, ok := DeploymentForRouteServiceTier(schemas.Anthropic, "anthropic/claude-opus-4-8", RouteChat, &standardOnlyTier)
	if !ok {
		t.Fatalf("expected Opus standard deployment")
	}
	if standard.ID != "claude-opus-4-8" || standard.ServiceTier != "standard" {
		t.Fatalf("unexpected Opus standard deployment %#v", standard)
	}
	if standard.ImpliedServiceTier == nil || *standard.ImpliedServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected Opus standard to imply Bifrost default, got %#v", standard.ImpliedServiceTier)
	}

	us, ok := DeploymentForRoute(schemas.Anthropic, "anthropic/claude-opus-4-8-us", RouteChat)
	if !ok {
		t.Fatalf("expected Opus US deployment")
	}
	if us.ID != "claude-opus-4-8-us" || us.RegionID != "us" || us.Model != "claude-opus-4-8" {
		t.Fatalf("unexpected Opus US deployment %#v", us)
	}
	if us.Pricing[billing.MeterInputTokens][billing.RatePerMillionTokens] != "5500000000000000000" ||
		us.Pricing[billing.MeterOutputTokens][billing.RatePerMillionTokens] != "27500000000000000000" {
		t.Fatalf("expected US inference 1.1x pricing, got %#v", us.Pricing)
	}

	usFastStandard, ok := DeploymentForRoute(schemas.Anthropic, "anthropic/claude-opus-4-8-fast-us", RouteChat)
	if !ok {
		t.Fatalf("expected Opus fast US deployment")
	}
	if usFastStandard.ID != "claude-opus-4-8-fast-us" || usFastStandard.RegionID != "us" || usFastStandard.ServiceTier != "standard" {
		t.Fatalf("unexpected Opus fast US deployment %#v", usFastStandard)
	}
	if usFastStandard.Pricing[billing.MeterInputTokens][billing.RatePerMillionTokens] != "11000000000000000000" ||
		usFastStandard.Pricing[billing.MeterOutputTokens][billing.RatePerMillionTokens] != "55000000000000000000" {
		t.Fatalf("expected fast US inference pricing, got %#v", usFastStandard.Pricing)
	}

	usResponsesProvider, ok, err := ProviderForRouteModel(RouteResponses, "anthropic/claude-sonnet-4-6-us")
	if err != nil {
		t.Fatalf("Responses US ProviderForRouteModel returned error: %v", err)
	}
	if !ok || usResponsesProvider != schemas.Anthropic {
		t.Fatalf("expected Anthropic provider for US Responses route, got %q ok=%v", usResponsesProvider, ok)
	}
	usResponsesDeployment, ok := DeploymentForRoute(schemas.Anthropic, "anthropic/claude-sonnet-4-6-us", RouteResponses)
	if !ok || usResponsesDeployment.ID != "claude-sonnet-4-6-us" || usResponsesDeployment.RegionID != "us" {
		t.Fatalf("expected Anthropic Sonnet US deployment for Responses route, got %#v ok=%v", usResponsesDeployment, ok)
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

func TestAnthropicRequestedServiceTierNormalizesToStandardDeployment(t *testing.T) {
	loadTestCatalog(t)

	for _, item := range []struct {
		name           string
		body           string
		wantDeployment string
		wantTier       schemas.BifrostServiceTier
	}{
		{
			name:           "default requests standard only",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"default","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "auto requests standard deployment with auto capacity",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"auto","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8",
			wantTier:       schemas.BifrostServiceTierAuto,
		},
		{
			name:           "priority requests standard deployment with auto capacity",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"priority","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8",
			wantTier:       schemas.BifrostServiceTierAuto,
		},
		{
			name:           "flex requests standard only",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"flex","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "standard_only requests standard only",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"standard_only","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "fast standard only keeps fast deployment",
			body:           `{"model":"anthropic/claude-opus-4-8-fast","messages":[{"role":"user","content":"hi"}],"service_tier":"standard_only","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8-fast",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			if resolution.Deployment.ID != item.wantDeployment {
				t.Fatalf("expected deployment %q, got %#v", item.wantDeployment, resolution.Deployment)
			}
			if resolution.chat == nil || resolution.chat.ChatParameters.ServiceTier == nil || *resolution.chat.ChatParameters.ServiceTier != item.wantTier {
				t.Fatalf("expected normalized tier %q, got %#v", item.wantTier, resolution.chat)
			}
		})
	}

	responsesResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"standard_only","max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("Responses ResolveRequest returned error: %v", err)
	}
	if responsesResolution.Deployment.ID != "claude-sonnet-4-6" {
		t.Fatalf("expected Responses standard deployment, got %#v", responsesResolution.Deployment)
	}
	if responsesResolution.responses == nil ||
		responsesResolution.responses.ResponsesParameters.ServiceTier == nil ||
		*responsesResolution.responses.ResponsesParameters.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("expected Responses tier to normalize to Bifrost default, got %#v", responsesResolution.responses)
	}

	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat default_only",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"default_only","max_completion_tokens":16}`,
		},
		{
			name: "responses default_only",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"default_only","max_output_tokens":16}`,
		},
		{
			name: "chat scale",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"service_tier":"scale","max_completion_tokens":16}`,
		},
		{
			name: "responses provisioned",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","service_tier":"provisioned","max_output_tokens":16}`,
		},
	} {
		t.Run("rejects "+item.name, func(t *testing.T) {
			_, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err == nil {
				t.Fatalf("expected unsupported Anthropic service tier to be rejected")
			}
			var apiErr APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != 400 || apiErr.Type != ErrorTypeInvalidRequest {
				t.Fatalf("expected unsupported service tier error, got %#v", err)
			}
		})
	}
}

func TestAnthropicInferenceGeoSelectsRegionalDeployment(t *testing.T) {
	loadTestCatalog(t)

	for _, item := range []struct {
		name           string
		path           string
		body           string
		wantDeployment string
		wantRegion     string
		wantTier       schemas.BifrostServiceTier
	}{
		{
			name:           "chat auto us",
			path:           "/v1/chat/completions",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"inference_geo":"us","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8-us",
			wantRegion:     "us",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "chat auto global",
			path:           "/v1/chat/completions",
			body:           `{"model":"anthropic/claude-opus-4-8-us","messages":[{"role":"user","content":"hi"}],"inference_geo":"global","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8",
			wantRegion:     "multi-region",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "chat standard us",
			path:           "/v1/chat/completions",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"inference_geo":"us","service_tier":"standard_only","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8-us",
			wantRegion:     "us",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "responses auto us",
			path:           "/v1/responses",
			body:           `{"model":"anthropic/claude-sonnet-4-6","input":"hi","inference_geo":"us","max_output_tokens":16}`,
			wantDeployment: "claude-sonnet-4-6-us",
			wantRegion:     "us",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "responses auto global",
			path:           "/v1/responses",
			body:           `{"model":"anthropic/claude-sonnet-4-6-us","input":"hi","inference_geo":"global","max_output_tokens":16}`,
			wantDeployment: "claude-sonnet-4-6",
			wantRegion:     "multi-region",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "responses standard us",
			path:           "/v1/responses",
			body:           `{"model":"anthropic/claude-sonnet-4-6","input":"hi","inference_geo":"us","service_tier":"standard_only","max_output_tokens":16}`,
			wantDeployment: "claude-sonnet-4-6-us",
			wantRegion:     "us",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			if resolution.Deployment.ID != item.wantDeployment || resolution.Deployment.RegionID != item.wantRegion {
				t.Fatalf("expected deployment %q in region %q, got %#v", item.wantDeployment, item.wantRegion, resolution.Deployment)
			}
			switch item.path {
			case "/v1/chat/completions":
				if resolution.chat == nil || resolution.chat.ChatParameters.ServiceTier == nil || *resolution.chat.ChatParameters.ServiceTier != item.wantTier {
					t.Fatalf("expected normalized Chat tier %q, got %#v", item.wantTier, resolution.chat)
				}
			case "/v1/responses":
				if resolution.responses == nil || resolution.responses.ResponsesParameters.ServiceTier == nil || *resolution.responses.ResponsesParameters.ServiceTier != item.wantTier {
					t.Fatalf("expected normalized Responses tier %q, got %#v", item.wantTier, resolution.responses)
				}
			}
		})
	}
}

func TestAnthropicSpeedSelectsDeployment(t *testing.T) {
	loadTestCatalog(t)

	for _, item := range []struct {
		name           string
		path           string
		body           string
		wantDeployment string
		wantTier       schemas.BifrostServiceTier
	}{
		{
			name:           "chat fast",
			path:           "/v1/chat/completions",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"speed":"fast","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8-fast",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "chat fast standard only",
			path:           "/v1/chat/completions",
			body:           `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"speed":"fast","service_tier":"standard_only","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8-fast",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "chat standard overrides fast slug",
			path:           "/v1/chat/completions",
			body:           `{"model":"anthropic/claude-opus-4-8-fast","messages":[{"role":"user","content":"hi"}],"speed":"standard","max_completion_tokens":16}`,
			wantDeployment: "claude-opus-4-8",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "responses fast us",
			path:           "/v1/responses",
			body:           `{"model":"anthropic/claude-opus-4-8","input":"hi","speed":"fast","inference_geo":"us","max_output_tokens":16}`,
			wantDeployment: "claude-opus-4-8-fast-us",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
		{
			name:           "responses standard us overrides fast slug",
			path:           "/v1/responses",
			body:           `{"model":"anthropic/claude-opus-4-8-fast-us","input":"hi","speed":"standard","max_output_tokens":16}`,
			wantDeployment: "claude-opus-4-8-us",
			wantTier:       schemas.BifrostServiceTierDefault,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			if resolution.Deployment.ID != item.wantDeployment {
				t.Fatalf("expected deployment %q, got %#v", item.wantDeployment, resolution.Deployment)
			}
			switch item.path {
			case "/v1/chat/completions":
				if resolution.chat == nil || resolution.chat.ChatParameters.ServiceTier == nil || *resolution.chat.ChatParameters.ServiceTier != item.wantTier {
					t.Fatalf("expected normalized Chat tier %q, got %#v", item.wantTier, resolution.chat)
				}
			case "/v1/responses":
				if resolution.responses == nil || resolution.responses.ResponsesParameters.ServiceTier == nil || *resolution.responses.ResponsesParameters.ServiceTier != item.wantTier {
					t.Fatalf("expected normalized Responses tier %q, got %#v", item.wantTier, resolution.responses)
				}
			}
		})
	}
}

func TestInferenceGeoRejectsUnsupportedRequests(t *testing.T) {
	loadTestCatalog(t)

	for _, item := range []struct {
		name string
		path string
		body string
		want string
	}{
		{
			name: "openai",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"inference_geo":"us","max_completion_tokens":16}`,
			want: "only supported for Anthropic",
		},
		{
			name: "unsupported region",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"inference_geo":"eu","max_completion_tokens":16}`,
			want: "inference_geo is not supported",
		},
		{
			name: "bad shape",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","inference_geo":["us"],"max_output_tokens":16}`,
			want: "inference_geo must be a string",
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			_, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("expected %q rejection, got %v", item.want, err)
			}
		})
	}
}

func TestSpeedRejectsUnsupportedRequests(t *testing.T) {
	loadTestCatalog(t)

	for _, item := range []struct {
		name string
		path string
		body string
		want string
	}{
		{
			name: "openai",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}],"speed":"fast","max_completion_tokens":16}`,
			want: "only supported for Anthropic",
		},
		{
			name: "bad shape",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-opus-4-8","input":"hi","speed":true,"max_output_tokens":16}`,
			want: "speed must be a string",
		},
		{
			name: "bad value",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"speed":"turbo","max_completion_tokens":16}`,
			want: "speed is not supported",
		},
		{
			name: "unsupported model",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hi","speed":"fast","max_output_tokens":16}`,
			want: "Model is not available",
		},
		{
			name: "priority tier",
			path: "/v1/chat/completions",
			body: `{"model":"anthropic/claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"speed":"fast","service_tier":"priority","max_completion_tokens":16}`,
			want: "Anthropic priority service_tier is not supported with speed fast",
		},
		{
			name: "auto tier",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-opus-4-8","input":"hi","speed":"fast","service_tier":"auto","max_output_tokens":16}`,
			want: "Anthropic auto service_tier is not supported with speed fast",
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			_, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("expected %q rejection, got %v", item.want, err)
			}
		})
	}
}

func TestResolveChatRequestAppliesDeploymentResolution(t *testing.T) {
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
	if resolution.Deployment.ID != "gpt-5.5-flex" {
		t.Fatalf("expected concrete catalog deployment, got %#v", resolution.Deployment)
	}
	if resolution.chat == nil || resolution.chat.ChatParameters.ServiceTier == nil || *resolution.chat.ChatParameters.ServiceTier != schemas.BifrostServiceTierFlex {
		t.Fatalf("expected implied flex service tier, got %#v", resolution.chat)
	}
	if resolution.chat.ChatParameters.MaxCompletionTokens == nil || *resolution.chat.ChatParameters.MaxCompletionTokens != 123 {
		t.Fatalf("expected max_tokens alias to populate max_completion_tokens, got %#v", resolution.chat.ChatParameters.MaxCompletionTokens)
	}
	for _, item := range []struct {
		name string
		body string
	}{
		{
			name: "string stop",
			body: `{"model":"gpt-5.5","messages":[],"stop":"END"}`,
		},
		{
			name: "array stop",
			body: `{"model":"gpt-5.5","messages":[],"stop":["END"]}`,
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			req, err := resolution.ToBifrost(&schemas.BifrostContext{})
			if err != nil {
				t.Fatalf("ToBifrost returned error: %v", err)
			}
			if req.ChatRequest == nil || req.ChatRequest.Params == nil || len(req.ChatRequest.Params.Stop) != 1 || req.ChatRequest.Params.Stop[0] != "END" {
				t.Fatalf("expected stop sequence to normalize to Bifrost array, got %#v", req)
			}
		})
	}
	for _, item := range []struct {
		name string
		body string
	}{
		{
			name: "numeric stop",
			body: `{"model":"gpt-5.5","messages":[],"stop":123}`,
		},
		{
			name: "object stop",
			body: `{"model":"gpt-5.5","messages":[],"stop":{"value":"END"}}`,
		},
		{
			name: "mixed array stop",
			body: `{"model":"gpt-5.5","messages":[],"stop":["END",123]}`,
		},
	} {
		t.Run("rejects "+item.name, func(t *testing.T) {
			_, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(item.body),
			})
			var apiErr APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != 400 || apiErr.Message != "stop must be a string or array of strings" {
				t.Fatalf("expected explicit stop shape rejection, got %#v", err)
			}
		})
	}

	for _, input := range []RequestInput{
		{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(`{"model":"gpt-5.5","messages":[],"unknown":true}`),
		},
		{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"gpt-5.5","input":"hi","unknown":true}`),
		},
	} {
		_, err = ResolveRequest(input)
		var apiErr APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 400 || apiErr.Message != "unknown is not supported by Stogas API" {
			t.Fatalf("%s expected unknown request field rejection, got %#v", input.Path, err)
		}
	}
}

func TestChatSearchModelsUseCatalogWebSearchRules(t *testing.T) {
	loadTestCatalog(t)

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

func TestCatalogCapturesResponsesToolFacts(t *testing.T) {
	loadTestCatalog(t)

	requests := []string{
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"web_search"}],"max_tool_calls":1,"max_output_tokens":16}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"web_search_preview_2026_01_01"}],"max_tool_calls":1,"max_output_tokens":16}`,
		`{"model":"gpt-5.5","input":"hi","tools":[{"type":"web_search"},{"type":"web_search_preview"}],"max_tool_calls":1,"max_output_tokens":16}`,
	}
	for _, body := range requests {
		resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
		if err != nil {
			t.Fatalf("ResolveRequest returned error: %s: %v", body, err)
		}
		if !containsString(resolution.ToolTypes(), "web_search") && !containsString(resolution.ToolTypes(), "web_search_preview") {
			t.Fatalf("expected responses web search tool facts: %s: %#v", body, resolution.ToolTypes())
		}
	}
}

func TestGPT5NanoDeploymentServiceTierResolution(t *testing.T) {
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
	if defaultResolution.Deployment.ID != "gpt-5-nano" || defaultResolution.chat == nil || defaultResolution.chat.ChatParameters.ServiceTier == nil || *defaultResolution.chat.ChatParameters.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("unexpected gpt-5-nano auto service tier resolution: %#v", defaultResolution)
	}

	omittedTierResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("expected gpt-5-nano default request without service tier to resolve: %v", err)
	}
	if omittedTierResolution.Deployment.ID != "gpt-5-nano" ||
		omittedTierResolution.responses == nil ||
		omittedTierResolution.responses.ResponsesParameters.ServiceTier == nil ||
		*omittedTierResolution.responses.ResponsesParameters.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("unexpected gpt-5-nano omitted service tier resolution: %#v", omittedTierResolution)
	}

	defaultRequestResolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"default","max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("expected gpt-5-nano default request with default service tier to resolve: %v", err)
	}
	if defaultRequestResolution.Deployment.ID != "gpt-5-nano" || defaultRequestResolution.chat == nil || defaultRequestResolution.chat.ChatParameters.ServiceTier == nil || *defaultRequestResolution.chat.ChatParameters.ServiceTier != schemas.BifrostServiceTierDefault {
		t.Fatalf("unexpected gpt-5-nano default service tier resolution: %#v", defaultRequestResolution)
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
		Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"scale","max_completion_tokens":16}`),
	})
	if err == nil {
		t.Fatalf("expected OpenAI scale service tier to be rejected")
	}
	var apiErr APIError
	if !errors.As(err, &apiErr) || apiErr.Message != "OpenAI scale service_tier is not supported by Stogas" {
		t.Fatalf("expected explicit OpenAI scale rejection, got %#v", err)
	}

	_, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","service_tier":"scale","max_output_tokens":16}`),
	})
	if err == nil {
		t.Fatalf("expected OpenAI Responses scale service tier to be rejected")
	}
	if !errors.As(err, &apiErr) || apiErr.Message != "OpenAI scale service_tier is not supported by Stogas" {
		t.Fatalf("expected explicit OpenAI Responses scale rejection, got %#v", err)
	}

	for _, item := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat standard",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"standard","max_completion_tokens":16}`,
		},
		{
			name: "responses standard",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","service_tier":"standard","max_output_tokens":16}`,
		},
		{
			name: "chat provisioned",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"service_tier":"provisioned","max_completion_tokens":16}`,
		},
		{
			name: "responses provisioned",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"hi","service_tier":"provisioned","max_output_tokens":16}`,
		},
	} {
		_, err = ResolveRequest(RequestInput{
			Method: "POST",
			Path:   item.path,
			Body:   []byte(item.body),
		})
		if err == nil {
			t.Fatalf("expected OpenAI %s service tier to be rejected", item.name)
		}
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected OpenAI %s rejection, got %#v", item.name, err)
		}
		if strings.Contains(item.name, "standard") {
			if apiErr != ErrUnsupportedServiceTier {
				t.Fatalf("expected unsupported OpenAI %s service tier error, got %#v", item.name, err)
			}
			continue
		}
		if apiErr.Message != "OpenAI provisioned service_tier is not supported by Stogas" {
			t.Fatalf("expected explicit OpenAI %s provisioned rejection, got %#v", item.name, err)
		}
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

	for _, item := range []struct {
		name string
		input RequestInput
	}{
		{
			name: "chat max_completion_tokens",
			input: RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":15}`),
			},
		},
		{
			name: "chat max_tokens alias",
			input: RequestInput{
				Method: "POST",
				Path:   "/v1/chat/completions",
				Body:   []byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hi"}],"max_tokens":15}`),
			},
		},
		{
			name: "responses max_output_tokens",
			input: RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(`{"model":"gpt-5-nano","input":"hi","max_output_tokens":15}`),
			},
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := ResolveRequest(item.input)
			if err != nil {
				t.Fatalf("expected output limit below provider minimum to parse before adapter normalization, got %v", err)
			}
			if resolution.OutputTokenLimit() != 15 {
				t.Fatalf("expected catalog to preserve parsed output limit 15, got %d", resolution.OutputTokenLimit())
			}
			req, err := resolution.ToBifrost(&schemas.BifrostContext{})
			if err != nil {
				t.Fatalf("expected request to convert to Bifrost before adapter normalization: %v", err)
			}
			switch {
			case req.ChatRequest != nil:
				if req.ChatRequest.Params == nil || req.ChatRequest.Params.MaxCompletionTokens == nil || *req.ChatRequest.Params.MaxCompletionTokens != 15 {
					t.Fatalf("expected parsed chat max_completion_tokens, got %#v", req.ChatRequest.Params)
				}
			case req.ResponsesRequest != nil:
				if req.ResponsesRequest.Params == nil || req.ResponsesRequest.Params.MaxOutputTokens == nil || *req.ResponsesRequest.Params.MaxOutputTokens != 15 {
					t.Fatalf("expected parsed responses max_output_tokens, got %#v", req.ResponsesRequest.Params)
				}
			default:
				t.Fatalf("expected Bifrost chat or responses request, got %#v", req)
			}
		})
	}
}

func TestResolveRequestUsesSimpleCappedInputHoldEstimate(t *testing.T) {
	loadTestCatalog(t)

	for _, item := range []struct {
		name string
		path string
		body string
		want int
	}{
		{
			name: "openai ascii",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5-nano","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":16}`,
			want: roughInputTokenEstimate([]byte(`{"model":"gpt-5-nano","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":16}`), schemas.OpenAI),
		},
		{
			name: "anthropic multiplier",
			path: "/v1/responses",
			body: `{"model":"anthropic/claude-sonnet-4-6","input":"hello","max_output_tokens":16}`,
			want: roughInputTokenEstimate([]byte(`{"model":"anthropic/claude-sonnet-4-6","input":"hello","max_output_tokens":16}`), schemas.Anthropic),
		},
		{
			name: "unicode multiplier",
			path: "/v1/responses",
			body: `{"model":"gpt-5-nano","input":"こんにちは世界🌍","max_output_tokens":16}`,
			want: roughInputTokenEstimate([]byte(`{"model":"gpt-5-nano","input":"こんにちは世界🌍","max_output_tokens":16}`), schemas.OpenAI),
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolution, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   item.path,
				Body:   []byte(item.body),
			})
			if err != nil {
				t.Fatalf("ResolveRequest returned error: %v", err)
			}
			if resolution.InputTokenLimit() != item.want {
				t.Fatalf("expected input estimate %d, got %d", item.want, resolution.InputTokenLimit())
			}
		})
	}

	t.Run("caps estimate to deployment input cap", func(t *testing.T) {
		body := `{"model":"gpt-5-nano","input":"` + strings.Repeat("a", 1200000) + `","max_output_tokens":128000}`
		resolution, err := ResolveRequest(RequestInput{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(body),
		})
		if err != nil {
			t.Fatalf("ResolveRequest returned error: %v", err)
		}
		want := resolution.Deployment.ContextWindowTokens
		if resolution.InputTokenLimit() != want {
			t.Fatalf("expected capped input estimate %d, got %d", want, resolution.InputTokenLimit())
		}
	})
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
	if len(params) != 0 {
		t.Fatalf("expected OpenAI client extra params to be blocked, got %#v", params)
	}
	params = FilterExtraParams(schemas.Anthropic, "claude-sonnet-4-6", RouteResponses, map[string]interface{}{
		"cache_control":       map[string]interface{}{"type": "ephemeral"},
		"context_management":  map[string]interface{}{"edits": []interface{}{}},
		"reasoning.effort":    "low",
		"speed":               "fast",
		"task_budget":         map[string]interface{}{"type": "tokens", "total": float64(20000)},
		"top_k":               float64(40),
		"unknown":             true,
	})
	if len(params) != 3 || params["cache_control"] == nil || params["context_management"] == nil || params["task_budget"] == nil {
		t.Fatalf("expected only explicit Anthropic Responses extra params, got %#v", params)
	}
	for _, blocked := range []string{"reasoning.effort", "speed", "top_k", "unknown"} {
		if _, ok := params[blocked]; ok {
			t.Fatalf("client param %q must not pass through ExtraParams: %#v", blocked, params)
		}
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

func TestCompiledCatalogRequiresProviderUserIdentityPropagation(t *testing.T) {
	loadTestCatalog(t)

	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic} {
		if !ProviderUsesPseudoanonymousUserID(provider) {
			t.Fatalf("expected %s provider to require upstream pseudoanonymous user identity", provider)
		}
	}
}

func TestPublicCatalogDeploymentNodesOnlyExposeOwnAttributes(t *testing.T) {
	loadTestCatalog(t)

	encoded, ok := PublicCatalogJSON()
	if !ok {
		t.Fatalf("expected public catalog JSON")
	}

	var payload struct {
		Graph struct {
			Deployments map[string]map[string]json.RawMessage `json:"deployments"`
			Models      map[string]map[string]json.RawMessage `json:"models"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("decode public catalog JSON: %v", err)
	}

	deployment, ok := payload.Graph.Deployments["gpt-5-search-api"]
	if !ok {
		t.Fatalf("expected gpt-5-search-api deployment node")
	}
	for _, field := range []string{"contextWindowTokens", "maxOutputTokens"} {
		if _, ok := deployment[field]; ok {
			t.Fatalf("deployment node should not expose inherited %s", field)
		}
	}

	model, ok := payload.Graph.Models["gpt-5-search-api-2025-10-14"]
	if !ok {
		t.Fatalf("expected gpt-5-search-api-2025-10-14 model node")
	}
	for _, field := range []string{"contextWindowTokens", "maxOutputTokens", "releaseDate", "knowledgeCutoff"} {
		if _, ok := model[field]; !ok {
			t.Fatalf("model node should expose %s", field)
		}
	}
}

func TestResponsesPenaltyParametersResolveToTypedBifrostFields(t *testing.T) {
	loadTestCatalog(t)

	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5-nano","input":"hi","frequency_penalty":0.25,"presence_penalty":-0.5,"max_output_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("ResolveRequest returned error: %v", err)
	}
	if resolution.responses == nil {
		t.Fatal("expected parsed Responses request")
	}
	params := resolution.responses.ResponsesParameters
	if params.FrequencyPenalty == nil || *params.FrequencyPenalty != 0.25 {
		t.Fatalf("frequency_penalty was not preserved in parsed Responses parameters: %#v", params.FrequencyPenalty)
	}
	if params.PresencePenalty == nil || *params.PresencePenalty != -0.5 {
		t.Fatalf("presence_penalty was not preserved in parsed Responses parameters: %#v", params.PresencePenalty)
	}

	bifrostReq, err := resolution.ToBifrost(nil)
	if err != nil {
		t.Fatalf("ToBifrost returned error: %v", err)
	}
	if bifrostReq.ResponsesRequest == nil || bifrostReq.ResponsesRequest.Params == nil {
		t.Fatalf("expected Bifrost Responses request, got %#v", bifrostReq)
	}
	if bifrostReq.ResponsesRequest.Params.FrequencyPenalty == nil || *bifrostReq.ResponsesRequest.Params.FrequencyPenalty != 0.25 {
		t.Fatalf("frequency_penalty was not preserved in Bifrost request: %#v", bifrostReq.ResponsesRequest.Params)
	}
	if bifrostReq.ResponsesRequest.Params.PresencePenalty == nil || *bifrostReq.ResponsesRequest.Params.PresencePenalty != -0.5 {
		t.Fatalf("presence_penalty was not preserved in Bifrost request: %#v", bifrostReq.ResponsesRequest.Params)
	}
	if len(bifrostReq.ResponsesRequest.Params.ExtraParams) != 0 {
		t.Fatalf("penalty parameters must be typed, not ExtraParams: %#v", bifrostReq.ResponsesRequest.Params.ExtraParams)
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
