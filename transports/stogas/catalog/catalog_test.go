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
	if len(snap.graph.Authors) != 2 ||
		len(snap.graph.Models) < 10 ||
		len(snap.graph.Providers) != 2 ||
		len(snap.graph.Routes) != 3 ||
		len(snap.graph.Deployments) < 30 {
		t.Fatalf("unexpected v4 graph sizes: %#v", snap.graph)
	}
	if _, exists := snap.graph.Deployments["openai-gpt-4o-search-preview-2025-03-11"]; !exists {
		t.Fatal("historical search preview deployment must remain reproducible")
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
	if !ok || flex.Upstream.FixedRequest.ServiceTier != "flex" ||
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
			fast.Upstream.FixedRequest.ServiceTier != "priority" ||
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
		fastUS.Upstream.FixedRequest.Speed != "fast" ||
		fastUS.Upstream.FixedRequest.InferenceGeo != "us" ||
		len(fastUS.RouteIDs) != 1 ||
		fastUS.RouteIDs[0] != "anthropic-messages" {
		t.Fatalf("unexpected fast US deployment: %#v", fastUS)
	}
}

func TestReasoningAdmissionIsExactBeforeBifrostConversion(t *testing.T) {
	loadTestCatalog(t)
	if got, err := normalizeReasoningEffort("high", []string{"minimal", "low", "medium", "high"}); err != nil || got != "high" {
		t.Fatalf("accepted effort = %q, err=%v", got, err)
	}
	if _, err := normalizeReasoningEffort("max", []string{"minimal", "low", "medium", "high"}); err == nil {
		t.Fatal("unsupported canonical effort must not pass through to Bifrost")
	}
	if _, err := normalizeReasoningEffort("none", []string{"low", "medium", "high"}); err == nil {
		t.Fatal("reasoning disablement must be declared by the deployment")
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
		if !deployment.Moderated {
			t.Fatalf("%s moderation fact is not explicit", id)
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
