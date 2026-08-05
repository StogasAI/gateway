package catalog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestEmbeddedCatalogV5LoadsFiveNodeGraph(t *testing.T) {
	snap := loadTestCatalog(t)
	if snap.identity.Sequence != 0 || !strings.HasPrefix(snap.identity.Digest, "sha256:") {
		t.Fatalf("unexpected fallback identity: %#v", snap.identity)
	}
	if len(snap.graph.Authors) != 9 ||
		len(snap.graph.Models) < 10 ||
		len(snap.graph.Providers) != 4 ||
		len(snap.graph.Routes) != 6 ||
		len(snap.graph.Deployments) < 40 {
		t.Fatalf("unexpected v4 graph sizes: %#v", snap.graph)
	}
	if _, exists := snap.graph.Deployments["openai-gpt-4o-search-preview-2025-03-11"]; !exists {
		t.Fatal("historical search preview deployment must remain reproducible")
	}
}

func TestResolveRequestRejectsAmbiguousOrPathologicalJSON(t *testing.T) {
	tests := []RequestInput{
		{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(`{"model":"gpt-5.6-sol","model":"gpt-5.6-terra","messages":[{"role":"user","content":"hi"}]}`),
		},
		{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"gpt-5.6-sol","input":[{"role":"user","content":[{"type":"input_text","text":"a","text":"b"}]}]}`),
		},
		{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"gpt-5.6-sol","input":"hi"}{"model":"gpt-5.6-sol","input":"again"}`),
		},
	}
	for _, input := range tests {
		if _, err := ResolveRequest(input); !errors.Is(err, ErrInvalidJSON) {
			t.Fatalf("ResolveRequest error = %v, want invalid JSON for %s", err, input.Body)
		}
	}

	deepInput := strings.Repeat("[", maxRequestJSONDepth+2) + `"hi"` + strings.Repeat("]", maxRequestJSONDepth+2)
	if _, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.6-sol","input":` + deepInput + `}`),
	}); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("deeply nested request error = %v, want invalid JSON", err)
	}
}

func TestGPT56ProDeploymentsUseFixedResponsesModeWithoutChangingTheUpstreamModel(t *testing.T) {
	loadTestCatalog(t)
	for _, modelCase := range []struct {
		model     string
		selectors []string
	}{
		{model: "gpt-5.6-sol", selectors: []string{"gpt-5.6-pro", "gpt-5.6-sol-pro"}},
		{model: "gpt-5.6-terra", selectors: []string{"gpt-5.6-terra-pro"}},
		{model: "gpt-5.6-luna", selectors: []string{"gpt-5.6-luna-pro"}},
	} {
		for _, tierCase := range []struct {
			selectorSuffix   string
			serviceTier      string
			deploymentSuffix string
		}{
			{serviceTier: "default"},
			{selectorSuffix: "-flex", serviceTier: "flex", deploymentSuffix: "-flex"},
			{selectorSuffix: "-fast", serviceTier: "priority", deploymentSuffix: "-fast"},
		} {
			deploymentID := "openai-" + modelCase.model + "-pro" + tierCase.deploymentSuffix
			for _, baseSelector := range modelCase.selectors {
				selector := baseSelector + tierCase.selectorSuffix
				t.Run(selector, func(t *testing.T) {
					resolution, err := ResolveRequest(RequestInput{
						Method: "POST",
						Path:   "/v1/responses",
						Body:   []byte(`{"model":"` + selector + `","input":"hello"}`),
					})
					if err != nil {
						t.Fatalf("resolve Pro deployment: %v", err)
					}
					if resolution.Provider != schemas.OpenAI || resolution.Deployment.ID != deploymentID ||
						resolution.Deployment.Upstream.Model != modelCase.model ||
						resolution.Deployment.Upstream.ReasoningMode != "pro" ||
						resolution.Deployment.Upstream.ServiceTier != tierCase.serviceTier {
						t.Fatalf("unexpected Pro resolution: %#v", resolution.Deployment)
					}
					request, err := resolution.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
					if err != nil {
						t.Fatalf("build Pro request: %v", err)
					}
					if request.ResponsesRequest == nil || request.ResponsesRequest.Model != modelCase.model ||
						request.ResponsesRequest.Params.Reasoning == nil ||
						request.ResponsesRequest.Params.Reasoning.Mode == nil ||
						*request.ResponsesRequest.Params.Reasoning.Mode != "pro" {
						t.Fatalf("Pro mode did not reach the typed provider request: %#v", request.ResponsesRequest)
					}
					if actual, ok := DeploymentForActualExecution(schemas.OpenAI, RouteResponses, resolution.Deployment, nil, ""); !ok || actual.ID != deploymentID {
						t.Fatalf("actual execution lost Pro identity: %#v", actual)
					}
				})
			}
			if _, ok := DeploymentForRoute(schemas.OpenAI, deploymentID, RouteChat); ok {
				t.Fatalf("%s was exposed on Chat Completions", deploymentID)
			}
		}
	}

	standard, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"openai/gpt-5.6-sol","input":"hello"}`),
	})
	if err != nil {
		t.Fatalf("resolve standard GPT-5.6: %v", err)
	}
	if standard.Deployment.Upstream.ReasoningMode != "" {
		t.Fatalf("standard deployment unexpectedly enabled Pro mode: %#v", standard.Deployment)
	}
	flex, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.6-pro","input":"hello","service_tier":"flex"}`),
	})
	if err != nil || flex.Deployment.ID != "openai-gpt-5.6-sol-pro-flex" {
		t.Fatalf("service tier did not retarget within the Pro deployment family: resolution=%#v err=%v", flex, err)
	}
	for _, tier := range []string{"fast", "priority"} {
		fast, err := ResolveRequest(RequestInput{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"gpt-5.6-pro","input":"hello","service_tier":"` + tier + `"}`),
		})
		if err != nil || fast.Deployment.ID != "openai-gpt-5.6-sol-pro-fast" {
			t.Fatalf("%s tier did not retarget within the Pro deployment family: resolution=%#v err=%v", tier, fast, err)
		}
	}
	actualTier := schemas.BifrostServiceTierDefault
	actual, ok := DeploymentForActualExecution(schemas.OpenAI, RouteResponses, flex.Deployment, &actualTier, "")
	if !ok || actual.ID != "openai-gpt-5.6-sol-pro" {
		t.Fatalf("actual service tier did not preserve Pro mode while selecting settlement pricing: %#v", actual)
	}
	if _, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.6-pro-flex","input":"hello","service_tier":"default"}`),
	}); err == nil {
		t.Fatal("a conflicting service tier changed a pinned Pro Flex selector")
	}
	if _, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"openai-gpt-5.6-sol-pro","input":"hello","service_tier":"flex"}`),
	}); err == nil {
		t.Fatal("a conflicting service tier changed an exact Pro deployment selector")
	}
}

func TestCatalogResolvesStructuralQualificationWithoutGeneratedPermutations(t *testing.T) {
	loadTestCatalog(t)
	for _, requested := range []string{
		"gpt-5.5",
		"openai/gpt-5.5",
		"openai/openai/gpt-5.5",
		"open-ai/gpt-5.5",
		"open-ai/open-ai/gpt-5.5",
	} {
		provider, ok, err := ProviderForRouteModel(RouteResponses, requested)
		if err != nil || !ok || provider != schemas.OpenAI {
			t.Fatalf("%s: provider=%q ok=%v err=%v", requested, provider, ok, err)
		}
	}
	for _, requested := range []string{
		"anthropic/gpt-5.5",
		"anthropic/openai/gpt-5.5",
		"open_ai/gpt-5.5",
		"openai/openai/openai/gpt-5.5",
		"gpt-5.5-latest",
	} {
		if _, ok, err := ProviderForRouteModel(RouteResponses, requested); err != nil || ok {
			t.Fatalf("%s: expected a closed miss, ok=%v err=%v", requested, ok, err)
		}
	}
}

func TestSharedModelDefaultsToItsAuthorAndAllowsExplicitAzureRouting(t *testing.T) {
	loadTestCatalog(t)
	for _, route := range []Route{RouteChat, RouteResponses} {
		provider, ok, err := ProviderForRouteModel(route, "gpt-5.6-sol")
		if err != nil || !ok || provider != schemas.OpenAI {
			t.Fatalf("unqualified GPT-5.6 must default to OpenAI: provider=%q ok=%v err=%v", provider, ok, err)
		}
		provider, ok, err = ProviderForRouteModel(route, "azure/gpt-5.6-sol")
		if err != nil || !ok || provider != schemas.Azure {
			t.Fatalf("qualified GPT-5.6 must select Azure: provider=%q ok=%v err=%v", provider, ok, err)
		}
		provider, ok, err = ProviderForRouteModelPreference(route, "gpt-5.6-sol", "azure")
		if err != nil || !ok || provider != schemas.Azure {
			t.Fatalf("provider preference must select Azure: provider=%q ok=%v err=%v", provider, ok, err)
		}
	}
}

func TestDeploymentLifecycleCutoffsFailClosed(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	for name, deployment := range map[string]compiledDeployment{
		"active": {
			DeprecationDate: nil,
		},
		"future retirement": {
			DeprecationDate: stringPointer("2026-07-28"),
		},
	} {
		if !deploymentAvailableAt(deployment, now) {
			t.Fatalf("%s deployment was unavailable", name)
		}
	}
	for name, deployment := range map[string]compiledDeployment{
		"retired": {
			DeprecationDate: stringPointer("2026-07-23"),
		},
	} {
		if deploymentAvailableAt(deployment, now) {
			t.Fatalf("%s deployment remained available", name)
		}
	}
}

func TestDeploymentFactsSelectTierRegionAndSpeedExplicitly(t *testing.T) {
	loadTestCatalog(t)
	flex, ok := DeploymentForRoute(schemas.OpenAI, "openai-gpt-5.5-2026-04-23-flex", RouteResponses)
	if !ok || flex.Upstream.ServiceTier != "flex" ||
		flex.ImpliedServiceTier == nil ||
		*flex.ImpliedServiceTier != schemas.BifrostServiceTierFlex {
		t.Fatalf("unexpected flex deployment: %#v", flex)
	}
	requestedFlex := schemas.BifrostServiceTierFlex
	flex, ok = DeploymentForRouteServiceTier(
		schemas.OpenAI,
		"gpt-5.5",
		RouteResponses,
		&requestedFlex,
	)
	if !ok || flex.ID != "openai-gpt-5.5-2026-04-23-flex" {
		t.Fatalf("OpenAI service_tier did not select the concrete flex deployment: %#v", flex)
	}
	for _, requestedFastTier := range []schemas.BifrostServiceTier{
		schemas.BifrostServiceTier("fast"),
		schemas.BifrostServiceTierPriority,
	} {
		fast, fastOK := DeploymentForRouteServiceTier(
			schemas.OpenAI,
			"gpt-5.5",
			RouteResponses,
			&requestedFastTier,
		)
		if !fastOK ||
			fast.ID != "openai-gpt-5.5-2026-04-23-fast" ||
			fast.Upstream.ServiceTier != "priority" ||
			fast.ImpliedServiceTier == nil ||
			*fast.ImpliedServiceTier != schemas.BifrostServiceTierPriority {
			t.Fatalf("OpenAI %q service_tier did not select the Fast deployment: %#v", requestedFastTier, fast)
		}
		flex, ok = DeploymentForRouteServiceTier(
			schemas.OpenAI,
			"openai-gpt-5.5-2026-04-23-flex",
			RouteResponses,
			&requestedFastTier,
		)
		if ok {
			t.Fatalf("conflicting %q request tier accepted for exact flex deployment: %#v", requestedFastTier, flex)
		}
	}
	if retired, retiredOK := DeploymentForRoute(
		schemas.OpenAI,
		"openai-gpt-5.5-2026-04-23-priority",
		RouteResponses,
	); retiredOK {
		t.Fatalf("retired Priority deployment selector remained available: %#v", retired)
	}
	if _, ok = DeploymentForRouteServiceTier(
		schemas.OpenAI,
		"openai-gpt-5.5-2026-04-23",
		RouteResponses,
		&requestedFlex,
	); ok {
		t.Fatal("conflicting axes must not retarget an exact deployment selector")
	}
	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.5","input":"hello","service_tier":"fast"}`),
	})
	if err != nil {
		t.Fatalf("resolve Fast mode request: %v", err)
	}
	if resolution.Deployment.ID != "openai-gpt-5.5-2026-04-23-fast" ||
		resolution.responses == nil ||
		resolution.responses.ResponsesParameters.ServiceTier == nil ||
		*resolution.responses.ResponsesParameters.ServiceTier != schemas.BifrostServiceTierPriority {
		t.Fatalf("Fast mode was not normalized to Bifrost's priority wire value: %#v", resolution)
	}
	actualFast := schemas.BifrostServiceTier("fast")
	actual, actualOK := DeploymentForActualExecution(
		schemas.OpenAI,
		RouteResponses,
		resolution.Deployment,
		&actualFast,
		"",
	)
	if !actualOK || actual.ID != "openai-gpt-5.5-2026-04-23-fast" {
		t.Fatalf("returned fast tier did not settle against the Fast deployment: %#v", actual)
	}
	fastUS, ok := DeploymentForRoute(
		schemas.Anthropic,
		"anthropic-claude-opus-4-8-fast-us",
		RouteResponses,
	)
	if !ok ||
		fastUS.ID != "anthropic-claude-opus-4-8-fast-us" ||
		fastUS.Upstream.Speed != "fast" ||
		fastUS.Upstream.InferenceGeo != "us" ||
		len(fastUS.RouteIDs) != 1 ||
		fastUS.RouteIDs[0] != "anthropic-messages" {
		t.Fatalf("unexpected fast US deployment: %#v", fastUS)
	}
}

func TestReasoningAdmissionMapsCanonicalControlsWithoutInventingBinaryEfforts(t *testing.T) {
	loadTestCatalog(t)
	optional := Deployment{ReasoningAvailability: "optional", ReasoningEfforts: []string{"minimal", "low", "medium", "high"}}
	if got, err := normalizeReasoningEffort("high", optional); err != nil || got.Effort == nil || *got.Effort != "high" {
		t.Fatalf("accepted effort = %#v, err=%v", got, err)
	}
	if got, err := normalizeReasoningEffort("max", optional); err != nil || got.Effort == nil || *got.Effort != "high" {
		t.Fatalf("higher effort did not map down: %#v err=%v", got, err)
	}
	if got, err := normalizeReasoningEffort("none", optional); err != nil || got.Effort == nil || *got.Effort != "none" {
		t.Fatalf("optional reasoning was not disabled: %#v err=%v", got, err)
	}
	binary := Deployment{ReasoningAvailability: "optional"}
	if got, err := normalizeReasoningEffort("minimal", binary); err != nil || got.Enabled == nil || !*got.Enabled || got.Effort != nil {
		t.Fatalf("positive binary reasoning did not map to enabled: %#v err=%v", got, err)
	}
	if got, err := normalizeReasoningEffort("none", binary); err != nil || got.Enabled == nil || *got.Enabled || got.Effort != nil {
		t.Fatalf("binary reasoning did not map none to disabled: %#v err=%v", got, err)
	}
	twoLevels := Deployment{ReasoningAvailability: "optional", ReasoningEfforts: []string{"high", "max"}}
	if got, err := normalizeReasoningEffort("xhigh", twoLevels); err != nil || got.Effort == nil || *got.Effort != "max" {
		t.Fatalf("upward tie did not map to max: %#v err=%v", got, err)
	}
	requiredWithoutLevels := Deployment{ReasoningAvailability: "required"}
	if _, err := normalizeReasoningEffort("high", requiredWithoutLevels); err == nil {
		t.Fatal("effort was accepted for always-on reasoning without level control")
	}
	if _, err := normalizeReasoningEffort("none", Deployment{ReasoningAvailability: "required", ReasoningEfforts: []string{"low", "high"}}); err == nil {
		t.Fatal("required reasoning was disabled")
	}
	if _, err := normalizeReasoningEffort("ultra", optional); err == nil {
		t.Fatal("non-canonical effort was accepted")
	}
}

func TestResolvedRequestPinsCatalogIdentityAndFiveNodeChain(t *testing.T) {
	snap := loadTestCatalog(t)
	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.5","input":"hello","reasoning":{"effort":"high"}}`),
	})
	if err != nil {
		t.Fatalf("resolve request: %v", err)
	}
	if resolution.Deployment.snapshot != snap {
		t.Fatal("request did not pin the active catalog snapshot")
	}
	want := []string{
		"author:openai",
		"model:gpt-5.5-2026-04-23",
		"deployment:openai-gpt-5.5-2026-04-23",
		"route:openai-responses",
		"provider:openai",
	}
	if got := resolution.CatalogNodeIDs(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog chain = %#v, want %#v", got, want)
	}
	if identity := resolution.CatalogIdentity(); identity != snap.identity {
		t.Fatalf("catalog identity = %#v, want %#v", identity, snap.identity)
	}
}

func TestPublicCatalogDisclosesEffectiveModerationAndDataHandling(t *testing.T) {
	loadTestCatalog(t)
	payload, ok := PublicCatalogPayload()
	if !ok || payload.Schema != PublicCatalogVersion {
		t.Fatalf("public catalog unavailable: %#v", payload)
	}
	if !strings.HasPrefix(payload.RuntimeDigest, "sha256:") ||
		!strings.HasPrefix(payload.PublicDigest, "sha256:") ||
		payload.RuntimeDigest == payload.PublicDigest {
		t.Fatalf("public catalog identities are incomplete: %#v", payload)
	}
	rawDeployments := payload.Graph["deployments"]
	var deployments map[string]struct {
		DataHandling map[string]any `json:"dataHandling"`
		Moderated    bool           `json:"moderated"`
	}
	if err := json.Unmarshal(rawDeployments, &deployments); err != nil {
		t.Fatalf("decode public deployments: %v", err)
	}
	for id, deployment := range deployments {
		if deployment.Moderated != !strings.HasPrefix(id, "chutes-") {
			t.Fatalf("%s has incorrect effective moderation: %v", id, deployment.Moderated)
		}
		if deployment.DataHandling["processingRegions"] == nil || deployment.DataHandling["storageRegions"] == nil {
			t.Fatalf("%s data handling is incomplete: %#v", id, deployment.DataHandling)
		}
	}
}

func TestFlattenedPricingNeedsNoProviderOverlay(t *testing.T) {
	loadTestCatalog(t)
	deployment, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5.5", RouteResponses)
	if !ok {
		t.Fatal("gpt-5.5 deployment unavailable")
	}
	if ProviderPricing(schemas.OpenAI) != nil {
		t.Fatal("v4 pricing must be fully materialized on deployments")
	}
	if deployment.Pricing["openai_responses_web_search_calls"][billing.RatePerThousandCalls] == "" {
		t.Fatalf("route pricing was not materialized: %#v", deployment.Pricing)
	}
}

func TestChutesTEEPolicyIsMaterializedPerDeployment(t *testing.T) {
	loadTestCatalog(t)
	blocked, ok := DeploymentForRoute(
		ProviderChutes,
		"chutes-qwen3-32b",
		RouteChat,
	)
	if !ok || blocked.TEE == nil || blocked.TEE.ExternalNetworkEgress != "blocked" {
		t.Fatalf("unexpected blocked Chutes TEE policy: %#v", blocked.TEE)
	}
	allowed, ok := DeploymentForRoute(
		ProviderChutes,
		"chutes-nemotron-3-nano-omni-30b",
		RouteChat,
	)
	if !ok || allowed.TEE == nil || allowed.TEE.ExternalNetworkEgress != "allowed" {
		t.Fatalf("unexpected Nemotron Chutes TEE policy: %#v", allowed.TEE)
	}
}

func TestSnapshotValidationRejectsBrokenReferences(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["openai-gpt-5.5-2026-04-23"].(map[string]any)
	deployment["routeIds"] = []any{"missing-route"}
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "unknown route") {
		t.Fatalf("broken route reference was accepted: %v", err)
	}
}

func TestSnapshotValidationRejectsAzureDeploymentModelMaps(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["azure-gpt-5.6-sol"].(map[string]any)
	upstream := deployment["upstream"].(map[string]any)
	upstream["model"] = "customer-specific-deployment"
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "invalid Azure upstream selector") {
		t.Fatalf("Azure deployment model map was accepted: %v", err)
	}
}

func TestSnapshotValidationRejectsUnbillablePricingAndReasoning(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["openai-gpt-5.5-2026-04-23"].(map[string]any)
	pricing := deployment["pricing"].(map[string]any)
	delete(pricing, billing.MeterInputTokens)
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "missing required pricing meter") {
		t.Fatalf("catalog without input pricing was accepted: %v", err)
	}

	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph = runtime["graph"].(map[string]any)
	deployments = graph["deployments"].(map[string]any)
	deployment = deployments["openai-gpt-5.5-2026-04-23"].(map[string]any)
	deployment["reasoningEfforts"] = []any{"low", "future"}
	broken, err = json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "unsupported reasoning effort") {
		t.Fatalf("catalog with unknown reasoning effort was accepted: %v", err)
	}

	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph = runtime["graph"].(map[string]any)
	deployments = graph["deployments"].(map[string]any)
	deployment = deployments["openai-gpt-5.5-2026-04-23"].(map[string]any)
	deployment["reasoningEfforts"] = []any{"high", "low"}
	broken, err = json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "canonical order") {
		t.Fatalf("catalog with unordered reasoning efforts was accepted: %v", err)
	}
}

func TestSnapshotValidationRejectsInvalidChutesTEEPolicy(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["chutes-qwen3-32b"].(map[string]any)
	tee := deployment["tee"].(map[string]any)
	tee["externalNetworkEgress"] = "sometimes"
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "external network egress") {
		t.Fatalf("catalog with unknown Chutes egress policy was accepted: %v", err)
	}
}

func TestSnapshotValidationRejectsReasoningThatWeakensTheModel(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["chutes-qwen3-235b-a22b-thinking-2507"].(map[string]any)
	deployment["reasoningAvailability"] = "unsupported"
	deployment["reasoningEfforts"] = []any{}
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "weakens required model reasoning") {
		t.Fatalf("catalog that weakens required model reasoning was accepted: %v", err)
	}
}

func TestSnapshotValidationRejectsRoutesWithoutCompiledTransportContracts(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	routes := graph["routes"].(map[string]any)
	routes["openai-uncompiled"] = map[string]any{
		"interfaces": []any{"responses"},
		"providerId": "openai",
	}
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "not a compiled gateway transport contract") {
		t.Fatalf("uncompiled route was accepted: %v", err)
	}
}

func TestSnapshotValidationRejectsMismatchedPublicProjection(t *testing.T) {
	var public map[string]any
	if err := json.Unmarshal(embeddedPublicCatalogJSON, &public); err != nil {
		t.Fatal(err)
	}
	graph := public["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	delete(deployments, "openai-gpt-5.5-2026-04-23")
	broken, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromRelease(embeddedRuntimeCatalogJSON, broken, Identity{}); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched public projection was accepted: %v", err)
	}

}

func stringPointer(value string) *string {
	return &value
}

func TestCatalogErrorsRemainPubliclyStable(t *testing.T) {
	if !errors.Is(PublicError(ErrModelUnavailable), ErrModelUnavailable) {
		t.Fatal("catalog API errors must survive public normalization")
	}
	if got := PublicError(errors.New("secret")); got.Message != "Internal server error" {
		t.Fatalf("unexpected public error: %#v", got)
	}
}

func loadTestCatalog(t *testing.T) *snapshot {
	t.Helper()
	snap, err := loadSnapshot()
	if err != nil {
		t.Fatalf("parse embedded catalog: %v", err)
	}
	active.Store(snap)
	return snap
}
