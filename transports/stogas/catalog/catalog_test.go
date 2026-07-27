package catalog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestEmbeddedCatalogV3LoadsFiveNodeGraph(t *testing.T) {
	snap := loadTestCatalog(t)
	if snap.identity.Sequence != 0 || !strings.HasPrefix(snap.identity.Digest, "sha256:") {
		t.Fatalf("unexpected fallback identity: %#v", snap.identity)
	}
	if len(snap.graph.Authors) != 2 ||
		len(snap.graph.Models) != 7 ||
		len(snap.graph.Providers) != 2 ||
		len(snap.graph.Routes) != 3 ||
		len(snap.graph.Deployments) != 19 {
		t.Fatalf("unexpected v3 graph sizes: %#v", snap.graph)
	}
	if len(snap.aliases) != 36 {
		t.Fatalf("aliases = %d, want 36 explicit records", len(snap.aliases))
	}
}

func TestCatalogResolvesStructuralQualificationWithoutGeneratedPermutations(t *testing.T) {
	loadTestCatalog(t)
	for _, requested := range []string{
		"gpt-5.5",
		"open-ai/gpt-5.5",
		"openai/open-ai/gpt-5.5",
	} {
		provider, ok, err := ProviderForRouteModel(RouteResponses, requested)
		if err != nil || !ok || provider != schemas.OpenAI {
			t.Fatalf("%s: provider=%q ok=%v err=%v", requested, provider, ok, err)
		}
	}
	for _, requested := range []string{
		"anthropic/gpt-5.5",
		"anthropic/openai/gpt-5.5",
		"openai/openai/openai/gpt-5.5",
		"gpt-5.5-latest",
	} {
		if _, ok, err := ProviderForRouteModel(RouteResponses, requested); err != nil || ok {
			t.Fatalf("%s: expected a closed miss, ok=%v err=%v", requested, ok, err)
		}
	}
}

func TestDeploymentFactsSelectTierRegionAndSpeedExplicitly(t *testing.T) {
	loadTestCatalog(t)
	flex, ok := DeploymentForRoute(schemas.OpenAI, "gpt-5.5-flex", RouteResponses)
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
	if !ok || flex.ID != "gpt-5.5-flex" {
		t.Fatalf("OpenAI service_tier did not select the concrete flex deployment: %#v", flex)
	}
	requestedPriority := schemas.BifrostServiceTierPriority
	flex, ok = DeploymentForRouteServiceTier(
		schemas.OpenAI,
		"gpt-5.5-flex",
		RouteResponses,
		&requestedPriority,
	)
	if !ok || flex.ID != "gpt-5.5-flex" {
		t.Fatalf("explicit tier alias was retargeted by request service_tier: %#v", flex)
	}
	fastUS, ok := DeploymentForRouteServiceTierRegionSpeed(
		schemas.Anthropic,
		"claude-opus-4-8",
		RouteResponses,
		nil,
		"us",
		"fast",
	)
	if !ok ||
		fastUS.ID != "claude-opus-4-8-fast-us" ||
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
		"deployment:gpt-5.5",
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
		Moderation   struct {
			Input  string `json:"input"`
			Output string `json:"output"`
		} `json:"moderation"`
	}
	if err := json.Unmarshal(rawDeployments, &deployments); err != nil {
		t.Fatalf("decode public deployments: %v", err)
	}
	for id, deployment := range deployments {
		if deployment.Moderation.Input != "provider" || deployment.Moderation.Output != "provider" {
			t.Fatalf("%s moderation actor is not explicit: %#v", id, deployment.Moderation)
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
		t.Fatal("v3 pricing must be fully materialized on deployments")
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
	deployment := deployments["gpt-5.5"].(map[string]any)
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
	delete(deployments, "gpt-5.5")
	broken, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromRelease(embeddedRuntimeCatalogJSON, broken, Identity{}); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched public projection was accepted: %v", err)
	}
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
