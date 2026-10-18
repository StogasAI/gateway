package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func snapshotFromCatalogBytes(data []byte) (*snapshot, error) {
	return snapshotFromRelease(data, nil, Identity{})
}

func testDeploymentForRoute(provider schemas.ModelProvider, model string, route Route) (Deployment, bool) {
	return activeState().deploymentForRoute(provider, model, route, variant{})
}

func TestClientHeaderCatalogOmitsRemovedProviderSecrets(t *testing.T) {
	for _, header := range []string{
		"stogas-metadata",
	} {
		if !strings.Contains(allClientHeadersValue, header) {
			t.Fatalf("client header catalog omitted %q", header)
		}
	}
	for _, legacy := range []string{
		"stogas-receipt",
		"x-stogas-upstream-anthropic-api-key",
		"x-stogas-upstream-chutes-api-key",
		"x-stogas-upstream-openai-api-key",
		"x-stogas-upstream-api-key",
		"x-stogas-upstream-provider",
	} {
		if strings.Contains(allClientHeadersValue, legacy) {
			t.Fatalf("client header catalog retained legacy header %q", legacy)
		}
	}
}

func TestEmbeddedCatalogLoadsCompleteGraph(t *testing.T) {
	snap := loadTestCatalog(t)
	if snap.identity.Sequence != 0 || !strings.HasPrefix(snap.identity.Digest, "sha256:") {
		t.Fatalf("unexpected fallback identity: %#v", snap.identity)
	}
	if len(snap.graph.Authors) != 10 ||
		len(snap.graph.Models) != 42 ||
		len(snap.graph.Providers) != 4 ||
		len(snap.graph.Routes) != 7 ||
		len(snap.graph.Deployments) != 212 {
		t.Fatalf("unexpected catalog graph sizes: authors=%d models=%d providers=%d routes=%d deployments=%d",
			len(snap.graph.Authors),
			len(snap.graph.Models),
			len(snap.graph.Providers),
			len(snap.graph.Routes),
			len(snap.graph.Deployments),
		)
	}
	if _, exists := snap.graph.Deployments["openai-gpt-4o-search-preview-2025-03-11"]; exists {
		t.Fatal("retired search preview deployment must not remain in the current catalog")
	}
	euDeployment := snap.graph.Deployments["azure-gpt-5.6-sol-eu"]
	for routeID, route := range euDeployment.Routes {
		if handling := route.DataHandling; handling.ProcessingLocation != "europe" || handling.StorageLocation != "europe" {
			t.Fatalf("Azure EU Data Zone route %s has invalid boundaries: %#v", routeID, handling)
		}
	}
}

func TestSnapshotValidationAllowsPublicModelsWithoutExecutableDeployments(t *testing.T) {
	snap, err := snapshotFromRelease(embeddedRuntimeCatalogJSON, embeddedPublicCatalogJSON, Identity{})
	if err != nil {
		t.Fatalf("public informational models were rejected: %v", err)
	}

	var public map[string]any
	if err := json.Unmarshal(embeddedPublicCatalogJSON, &public); err != nil {
		t.Fatal(err)
	}
	models := public["graph"].(map[string]any)["models"].(map[string]any)
	delete(models, "gpt-5.6-sol")
	missingRuntimeModel, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromRelease(embeddedRuntimeCatalogJSON, missingRuntimeModel, Identity{}); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("public catalog missing a runtime model was accepted: %v", err)
	}

	if len(snap.graph.Models) != 42 {
		t.Fatalf("runtime catalog unexpectedly contains informational-only models: %d", len(snap.graph.Models))
	}
}

func TestSnapshotValidationKeepsProviderTargetsStructural(t *testing.T) {
	for _, deploymentID := range []string{
		"azure-gpt-5.6-sol-fast",
		"azure-gpt-5.6-sol-instant",
		"azure-gpt-5.6-sol-pro",
		"openai-gpt-5.6-sol-pro",
	} {
		t.Run(deploymentID, func(t *testing.T) {
			var runtime map[string]any
			if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
				t.Fatal(err)
			}
			deployment := runtime["graph"].(map[string]any)["deployments"].(map[string]any)[deploymentID].(map[string]any)
			deployment["upstream"].(map[string]any)["model"] = "future-openai-model"
			data, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(data); err != nil {
				t.Fatalf("structurally valid Azure target was coupled to a model allowlist: %v", err)
			}
		})
	}
}

func TestSnapshotValidationRejectsContradictoryZeroDataRetention(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(map[string]any)
	}{
		{name: "stored content", apply: func(handling map[string]any) { handling["storageLocation"] = "unknown" }},
		{name: "positive retention", apply: func(handling map[string]any) { handling["retentionDays"] = 1 }},
		{name: "unknown retention", apply: func(handling map[string]any) { handling["retentionDays"] = nil }},
		{name: "training use", apply: func(handling map[string]any) { handling["trainingUse"] = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var runtime map[string]any
			if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
				t.Fatal(err)
			}
			deployment := runtime["graph"].(map[string]any)["deployments"].(map[string]any)["chutes-qwen3-32b"].(map[string]any)
			route := deployment["routes"].(map[string]any)["chutes-chat-completions"].(map[string]any)
			test.apply(route["dataHandling"].(map[string]any))
			data, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(data); err == nil ||
				!strings.Contains(err.Error(), "contradictory zero data retention") {
				t.Fatalf("contradictory zero-retention artifact was accepted: %v", err)
			}
		})
	}
}

func TestSnapshotValidationAllowsUncachedPricingOnlyWhenCachingIsUnavailable(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	deployments := runtime["graph"].(map[string]any)["deployments"].(map[string]any)
	uncached := deployments["azure-gpt-oss-120b"].(map[string]any)["routes"].(map[string]any)["azure-chat-completions"].(map[string]any)
	if _, present := uncached["pricing"].(map[string]any)[billing.MeterCachedInputTokens]; present {
		t.Fatal("test fixture unexpectedly has a cached-input price")
	}
	if _, err := snapshotFromCatalogBytes(embeddedRuntimeCatalogJSON); err != nil {
		t.Fatalf("uncached deployment was rejected: %v", err)
	}

	cached := deployments["azure-gpt-5.6-sol"].(map[string]any)["routes"].(map[string]any)["azure-responses"].(map[string]any)
	delete(cached["pricing"].(map[string]any), billing.MeterCachedInputTokens)
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "missing required pricing meter cached_input_tokens") {
		t.Fatalf("cache-capable deployment without a cache rate was accepted: %v", err)
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
	for _, model := range []string{"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"} {
		for _, tierCase := range []struct {
			suffix      string
			serviceTier string
		}{
			{serviceTier: TierStandard},
			{suffix: "-flex", serviceTier: TierFlex},
			{suffix: "-fast", serviceTier: TierFast},
		} {
			deploymentID := "openai-" + model + "-pro" + tierCase.suffix
			t.Run(deploymentID, func(t *testing.T) {
				resolution, err := ResolveRequest(RequestInput{
					Method: "POST",
					Path:   "/v1/responses",
					Body:   []byte(`{"model":"` + deploymentID + `","input":"hello"}`),
				})
				if err != nil {
					t.Fatalf("resolve Pro deployment: %v", err)
				}
				if resolution.Provider != schemas.OpenAI || resolution.Deployment.ID != deploymentID ||
					resolution.Deployment.Upstream.Model != model ||
					resolution.Deployment.Upstream.ReasoningMode != "pro" ||
					resolution.Deployment.Upstream.ServiceTier != tierCase.serviceTier {
					t.Fatalf("unexpected Pro resolution: %#v", resolution.Deployment)
				}
				request, err := resolution.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
				if err != nil {
					t.Fatalf("build Pro request: %v", err)
				}
				if request.ResponsesRequest == nil || request.ResponsesRequest.Model != model ||
					request.ResponsesRequest.Params.Reasoning == nil ||
					request.ResponsesRequest.Params.Reasoning.Mode == nil ||
					*request.ResponsesRequest.Params.Reasoning.Mode != "pro" {
					t.Fatalf("Pro mode did not reach the typed provider request: %#v", request.ResponsesRequest)
				}
				if _, ok := testDeploymentForRoute(schemas.OpenAI, deploymentID, RouteChat); ok {
					t.Fatalf("%s was exposed on Chat Completions", deploymentID)
				}
			})
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
	flex, ok := testDeploymentForRoute(schemas.OpenAI, "openai-gpt-5.6-sol-pro-flex", RouteResponses)
	if !ok {
		t.Fatal("GPT-5.6 Sol Pro Flex is missing")
	}
	actual, ok := StandardTierDeployment(schemas.OpenAI, RouteResponses, flex)
	if !ok || actual.ID != "openai-gpt-5.6-sol-pro" {
		t.Fatalf("Standard tier lookup did not preserve Pro mode: %#v", actual)
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
	snap := active.Load()
	if snap == nil {
		t.Fatal("catalog is not loaded")
	}
	for _, requested := range []string{
		"openai/gpt-5.5-2026-04-23",
		"openai/openai/gpt-5.5-2026-04-23",
		"open-ai/gpt-5.5-2026-04-23",
		"open-ai/open-ai/gpt-5.5-2026-04-23",
	} {
		providers := snap.routeModelProviders(RouteResponses, requested, nil, nil)
		if len(providers) != 1 || providers[0] != schemas.OpenAI {
			t.Fatalf("%s: providers=%v", requested, providers)
		}
	}
	for _, requested := range []string{
		"anthropic/gpt-5.5-2026-04-23",
		"anthropic/openai/gpt-5.5-2026-04-23",
		"open_ai/gpt-5.5-2026-04-23",
		"openai/openai/openai/gpt-5.5-2026-04-23",
		"gpt-5.5-latest",
	} {
		if providers := snap.routeModelProviders(RouteResponses, requested, nil, nil); len(providers) != 0 {
			t.Fatalf("%s: expected a closed miss, providers=%v", requested, providers)
		}
	}
	for _, requested := range []string{
		"claude-haiku-4-5",
		"claude-haiku-4.5",
		"anthropic/claude-haiku-4.5",
	} {
		deployment, ok := testDeploymentForRoute(schemas.Anthropic, requested, RouteChat)
		if !ok || deployment.ID != "anthropic-claude-haiku-4-5-20251001" ||
			deployment.Upstream.Model != "claude-haiku-4-5-20251001" {
			t.Fatalf("%s did not resolve through the simple model node: %#v", requested, deployment)
		}
	}
	if _, ok := testDeploymentForRoute(
		schemas.Anthropic,
		"anthropic-claude-haiku-4.5-20251001",
		RouteChat,
	); ok {
		t.Fatal("an unlisted deployment alias was generated")
	}
	for _, rotated := range []struct {
		provider schemas.ModelProvider
		route    Route
		selector string
	}{
		{provider: schemas.Anthropic, route: RouteResponses, selector: "anthropic-claude-opus-4-8-us-fast"},
		{provider: schemas.OpenAI, route: RouteResponses, selector: "gpt-5.6-sol-fast-pro"},
	} {
		if _, ok := testDeploymentForRoute(rotated.provider, rotated.selector, rotated.route); ok {
			t.Fatalf("rotated deployment modifier alias %s was generated", rotated.selector)
		}
	}
}

func TestProviderRestrictionUsesTheDefaultOrder(t *testing.T) {
	loadTestCatalog(t)
	for _, route := range []Route{RouteChat, RouteResponses} {
		path := "/v1/responses"
		body := `{"model":"gpt-5.6-sol","input":"hello","provider":{"only":["azure"]}}`
		if route == RouteChat {
			path = "/v1/chat/completions"
			body = `{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"provider":{"only":["azure"]}}`
		}
		resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: []byte(body)})
		if err != nil || resolution.Deployment.ID != "azure-gpt-5.6-sol" {
			t.Fatalf("provider restriction skipped the cheapest region: resolution=%#v err=%v", resolution, err)
		}
	}
}

func TestResolveRequestSupportsModelProviderAndDeploymentSelectors(t *testing.T) {
	loadTestCatalog(t)
	tests := []struct {
		deployment string
		provider   schemas.ModelProvider
		selector   string
	}{
		{selector: "openai/gpt-5.6-sol", provider: schemas.OpenAI, deployment: "openai-gpt-5.6-sol"},
		{selector: "azure/azure-gpt-5.6-sol", provider: schemas.Azure, deployment: "azure-gpt-5.6-sol"},
		{selector: "openai-gpt-5.6-sol", provider: schemas.OpenAI, deployment: "openai-gpt-5.6-sol"},
	}
	for _, route := range []struct {
		body string
		path string
	}{
		{path: "/v1/chat/completions", body: `{"model":"%s","messages":[{"role":"user","content":"hello"}]}`},
		{path: "/v1/responses", body: `{"model":"%s","input":"hello"}`},
	} {
		for _, test := range tests {
			t.Run(route.path+"/"+test.selector, func(t *testing.T) {
				resolution, err := ResolveRequest(RequestInput{
					Method: "POST",
					Path:   route.path,
					Body:   []byte(fmt.Sprintf(route.body, test.selector)),
				})
				if err != nil {
					t.Fatal(err)
				}
				if resolution.Provider != test.provider || resolution.Deployment.ID != test.deployment {
					t.Fatalf("resolution = %s/%s, want %s/%s", resolution.Provider, resolution.Deployment.ID, test.provider, test.deployment)
				}
			})
		}
	}
}

func TestRequestCompatibilityPrecedesProviderPreference(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		body := `{"model":"gpt-5.5","input":"hello","service_tier":"flex"}`
		if path == "/v1/chat/completions" {
			body = `{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}],"service_tier":"flex"}`
		}
		resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: []byte(body)})
		if err != nil {
			t.Fatalf("%s Flex request: %v", path, err)
		}
		if resolution.Provider != schemas.OpenAI || resolution.Deployment.ID != "openai-gpt-5.5-2026-04-23-flex" {
			t.Fatalf("%s Flex resolution = %s/%s", path, resolution.Provider, resolution.Deployment.ID)
		}
	}

	ordered, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.5","input":"hello","service_tier":"flex","provider":{"order":["azure","openai"]}}`),
	})
	if err != nil || ordered.Provider != schemas.OpenAI {
		t.Fatalf("incompatible preferred provider was selected: resolution=%#v err=%v", ordered, err)
	}

	if _, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.5","input":"hello","service_tier":"flex","provider":{"only":["azure"]}}`),
	}); !errors.Is(err, ErrProviderSelection) {
		t.Fatalf("strict provider rule error = %v, want provider selection error", err)
	}
}

func TestUnusablePreferredProviderLeavesTheDefaultOrder(t *testing.T) {
	snap := loadTestCatalog(t)

	openAI := snap.graph.Deployments["openai-gpt-5.6-sol"]
	openAI.MaxOutputTokens = 1
	snap.graph.Deployments["openai-gpt-5.6-sol"] = openAI

	chutes := snap.graph.Deployments["chutes-deepseek-v3.2"]
	chutes.ModelID = "gpt-5.6-sol"
	chutes.Upstream.Model = "gpt-5.6-sol"
	snap.graph.Deployments["chutes-gpt-5.6-sol"] = chutes
	chutesRoute := snap.graph.Routes["chutes-chat-completions"]
	chutesRoute.DeploymentIDs = append(chutesRoute.DeploymentIDs, "chutes-gpt-5.6-sol")
	snap.graph.Routes["chutes-chat-completions"] = chutesRoute

	// OpenAI cannot serve two output tokens here. The copied Chutes price is
	// lower than every Azure price, so it leads unless Azure is ranked first.
	for providerRule, want := range map[string]string{
		``:                                 "chutes-gpt-5.6-sol",
		`,"provider":{"order":["openai"]}`: "chutes-gpt-5.6-sol",
		`,"provider":{"order":["openai","azure"]}`: "azure-gpt-5.6-sol",
	} {
		resolution, err := ResolveRequest(RequestInput{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":2` + providerRule + `}`),
		})
		if err != nil || resolution.Deployment.ID != want {
			t.Fatalf("%q: resolution=%v err=%v, want %s", providerRule, resolution, err, want)
		}
	}
}

func TestServiceTierSpellingsSelectOneTier(t *testing.T) {
	loadTestCatalog(t)
	// Claude runs in several regions, so the request must choose one.
	multiRegion := `"policy":{"routing":{"filter":"deployment.upstream.inferenceGeo == 'global'"}}`
	source, err := policy.CompileSource([]byte(`{"delegation":{"request":["routing.filter"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		fields     string
		deployment string
		wire       schemas.BifrostServiceTier
		err        error
	}{
		{fields: `"model":"openai/gpt-5.5"`, deployment: "openai-gpt-5.5-2026-04-23", wire: "default"},
		{fields: `"model":"openai/gpt-5.5","service_tier":"auto"`, deployment: "openai-gpt-5.5-2026-04-23", wire: "default"},
		{fields: `"model":"openai/gpt-5.5","service_tier":"standard"`, deployment: "openai-gpt-5.5-2026-04-23", wire: "default"},
		{fields: `"model":"openai/gpt-5.5","service_tier":"priority"`, deployment: "openai-gpt-5.5-2026-04-23-fast", wire: "fast"},
		{fields: `"model":"openai/gpt-5.5","service_tier":"flex"`, deployment: "openai-gpt-5.5-2026-04-23-flex", wire: "flex"},
		{fields: `"model":"azure/gpt-5.6-sol","service_tier":"fast"`, deployment: "azure-gpt-5.6-sol-fast", wire: "priority"},
		{fields: `"model":"azure/gpt-6-astra","service_tier":"flex"`, deployment: "azure-gpt-6-astra-flex", wire: "flex"},
		{fields: `"model":"openai/gpt-6-astra","service_tier":"ultrafast"`, deployment: "openai-gpt-6-astra-ultrafast", wire: "ultrafast"},
		{fields: `"model":"anthropic/claude-opus-4-8","service_tier":"fast",` + multiRegion, deployment: "anthropic-claude-opus-4-8-fast", wire: "default"},
		{fields: `"model":"anthropic/claude-opus-4-8","service_tier":"auto",` + multiRegion, deployment: "anthropic-claude-opus-4-8", wire: "default"},
		{fields: `"model":"azure/claude-fable-5-1","service_tier":"default"`, deployment: "azure-claude-fable-5-1-anthropic-hosted"},
		// Azure sells Claude Fast as its own model, so the request names no tier.
		{fields: `"model":"azure/claude-opus-5-5","service_tier":"fast"`, deployment: "azure-claude-opus-5-5-fast"},
		{fields: `"model":"openai/gpt-5.6-sol","service_tier":"ultrafast"`, err: ErrServiceTierUnavailable},
		{fields: `"model":"anthropic/claude-opus-4-8","service_tier":"flex"`, err: ErrServiceTierUnavailable},
		{fields: `"model":"openai-gpt-5.5-2026-04-23-flex","service_tier":"fast"`, err: ErrServiceTierUnavailable},
		{fields: `"model":"openai/gpt-5.5","service_tier":"scale"`, err: ErrUnsupportedServiceTier},
		{fields: `"model":"anthropic/claude-opus-4-8","service_tier":"standard_only"`, err: ErrUnsupportedServiceTier},
	} {
		resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(`{"input":"hello",` + test.fields + `}`), Policy: config})
		if test.err != nil {
			if !errors.Is(err, test.err) {
				t.Fatalf("%s error = %v, want %v", test.fields, err, test.err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("resolve %s: %v", test.fields, err)
		}
		wire := resolution.responses.ResponsesParameters.ServiceTier
		if resolution.Deployment.ID != test.deployment || (wire == nil) != (test.wire == "") || wire != nil && *wire != test.wire {
			t.Fatalf("%s selected %s with service_tier %v, want %s with %q", test.fields, resolution.Deployment.ID, wire, test.deployment, test.wire)
		}
	}
}

func TestReasoningModeSelectsDeployments(t *testing.T) {
	loadTestCatalog(t)
	allowing := func(deployments ...string) *policy.Config {
		config := policyConfig(2)
		config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: deployments}
		return config
	}
	for _, test := range []struct {
		fields     string
		config     *policy.Config
		deployment string
		effort     string
		err        error
	}{
		{fields: `"model":"openai/gpt-5.6-sol","reasoning":{"mode":"pro"}`, deployment: "openai-gpt-5.6-sol-pro"},
		{fields: `"model":"openai/gpt-5.6-sol","reasoning":{"mode":"standard","effort":"high"}`, deployment: "openai-gpt-5.6-sol", effort: "high"},
		{fields: `"model":"openai/gpt-5.6-sol","reasoning":{"mode":null}`, deployment: "openai-gpt-5.6-sol"},
		{fields: `"model":"openai/gpt-5.6-sol","reasoning":{"mode":"pro"},"service_tier":"flex"`, deployment: "openai-gpt-5.6-sol-pro-flex"},
		{fields: `"model":"azure/gpt-6-astra","reasoning":{"mode":"pro"}`, deployment: "azure-gpt-6-astra-pro"},
		{fields: `"model":"openai-gpt-5.6-sol-pro","reasoning":{"mode":"pro"}`, deployment: "openai-gpt-5.6-sol-pro"},
		// A group selects its newest model in the mode.
		{fields: `"model":"openai/gpt-6","reasoning":{"mode":"pro"}`, deployment: "openai-gpt-6.1-sol-pro"},
		{fields: `"model":"openai-gpt-5.6-sol-pro","reasoning":{"mode":"standard"}`, err: ErrReasoningModeUnavailable},
		{fields: `"model":"openai-gpt-5.6-sol","reasoning":{"mode":"pro"}`, err: ErrReasoningModeUnavailable},
		{fields: `"model":"openai/gpt-5.5","reasoning":{"mode":"pro"}`, err: ErrReasoningModeUnavailable},
		{fields: `"model":"claude","reasoning":{"mode":"pro"}`, err: ErrReasoningModeUnavailable},
		// The mode applies before the tier.
		{fields: `"model":"openai/gpt-5.5","reasoning":{"mode":"pro"},"service_tier":"ultrafast"`, err: ErrReasoningModeUnavailable},
		{fields: `"model":"openai/gpt-6-astra","reasoning":{"mode":"pro"},"service_tier":"ultrafast"`, err: ErrServiceTierUnavailable},
		{fields: `"model":"openai/gpt-5.6-sol","reasoning":{"mode":"turbo"}`, err: ErrUnsupportedReasoningMode},
		{fields: `"model":"openai/gpt-5.6-sol","reasoning":{"mode":1}`, err: ErrInvalidJSON},
		// A key that allows only some deployments names the field that its allowed nodes exclude.
		{fields: `"model":"openai/gpt-5.6-sol","reasoning":{"mode":"pro"},"service_tier":"flex"`, config: allowing("openai-gpt-5.6-sol-pro"), err: ErrServiceTierUnavailable},
		{fields: `"model":"openai/gpt-5.6-sol","reasoning":{"mode":"pro"},"service_tier":"flex"`, config: allowing("openai-gpt-5.6-sol-flex"), err: ErrReasoningModeUnavailable},
		{fields: `"model":"openai/gpt-5.6-sol","reasoning":{"mode":"standard"}`, config: allowing("openai-gpt-5.6-sol-pro"), err: ErrReasoningModeUnavailable},
		{fields: `"model":"openai/gpt-5.6-sol"`, config: allowing("openai-gpt-5.6-sol-pro"), err: ErrModelUnavailable},
	} {
		resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(`{"input":"hello",` + test.fields + `}`), Policy: test.config})
		if test.err != nil {
			if !errors.Is(err, test.err) {
				t.Fatalf("%s error = %v, want %v", test.fields, err, test.err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("resolve %s: %v", test.fields, err)
		}
		// The deployment owns the mode that reaches the provider.
		var mode, effort string
		if reasoning := resolution.responses.ResponsesParameters.Reasoning; reasoning != nil {
			mode, effort = ptrValue(reasoning.Mode), ptrValue(reasoning.Effort)
		}
		if resolution.Deployment.ID != test.deployment || mode != resolution.Deployment.Upstream.ReasoningMode || effort != test.effort {
			t.Fatalf("%s selected %s with mode %q and effort %q, want %s with effort %q", test.fields, resolution.Deployment.ID, mode, effort, test.deployment, test.effort)
		}
	}
	if _, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"openai/gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"reasoning":{"mode":"pro"}}`),
	}); err == nil || !strings.Contains(err.Error(), "reasoning.mode is not supported") {
		t.Fatalf("Chat Completions reasoning.mode error = %v", err)
	}
}

func ptrValue[T any](value *T) T {
	var zero T
	if value == nil {
		return zero
	}
	return *value
}

func TestAzureGPT56PriorityAndProAreIndependentDeploymentAxes(t *testing.T) {
	loadTestCatalog(t)
	for _, tier := range []string{"sol", "terra"} {
		model := "gpt-5.6-" + tier
		priorityID := "azure-" + model + "-fast"
		for _, serviceTier := range []string{"fast", "priority"} {
			resolution, err := ResolveRequest(RequestInput{
				Method: "POST",
				Path:   "/v1/responses",
				Body:   []byte(`{"model":"` + model + `","provider":"azure","input":"hello","service_tier":"` + serviceTier + `"}`),
			})
			if err != nil {
				t.Fatalf("resolve Azure %s %s request: %v", model, serviceTier, err)
			}
			if resolution.Deployment.ID != priorityID ||
				resolution.Deployment.Upstream.ServiceTier != TierFast ||
				resolution.Deployment.Upstream.ReasoningMode != "" {
				t.Fatalf("unexpected Azure Priority deployment: %#v", resolution.Deployment)
			}
			request, err := resolution.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
			if err != nil || request.ResponsesRequest == nil ||
				request.ResponsesRequest.Params.ServiceTier == nil ||
				*request.ResponsesRequest.Params.ServiceTier != schemas.BifrostServiceTierPriority {
				t.Fatalf("Azure Priority did not reach the provider request: request=%#v err=%v", request, err)
			}
		}

		proPriorityID := "azure-" + model + "-pro-fast"
		resolution, err := ResolveRequest(RequestInput{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"azure-` + model + `-pro-fast","input":"hello"}`),
		})
		if err != nil {
			t.Fatalf("resolve Azure Pro Priority deployment: %v", err)
		}
		if resolution.Deployment.ID != proPriorityID ||
			resolution.Deployment.Upstream.ReasoningMode != "pro" ||
			resolution.Deployment.Upstream.ServiceTier != TierFast {
			t.Fatalf("unexpected Azure Pro Priority deployment: %#v", resolution.Deployment)
		}
		request, err := resolution.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
		if err != nil || request.ResponsesRequest == nil ||
			request.ResponsesRequest.Params.Reasoning == nil ||
			request.ResponsesRequest.Params.Reasoning.Mode == nil ||
			*request.ResponsesRequest.Params.Reasoning.Mode != "pro" ||
			request.ResponsesRequest.Params.ServiceTier == nil ||
			*request.ResponsesRequest.Params.ServiceTier != schemas.BifrostServiceTierPriority {
			t.Fatalf("Azure Pro Priority axes did not reach the provider request: request=%#v err=%v", request, err)
		}

		actual, ok := StandardTierDeployment(schemas.Azure, RouteResponses, resolution.Deployment)
		if !ok || actual.ID != "azure-"+model+"-pro" ||
			actual.Upstream.Hosting != resolution.Deployment.Upstream.Hosting ||
			actual.Upstream.DeploymentType != resolution.Deployment.Upstream.DeploymentType {
			t.Fatalf("Azure Priority downgrade lost Pro, host, or deployment type: %#v", actual)
		}
	}

	for _, model := range []string{"azure-gpt-5.6-luna", "azure-gpt-5.6-luna-pro"} {
		if _, err := ResolveRequest(RequestInput{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"` + model + `","input":"hello","service_tier":"priority"}`),
		}); err == nil || !strings.Contains(err.Error(), "service_tier") {
			t.Fatalf("%s Priority error = %v, want a service_tier error", model, err)
		}
	}
}

func TestAzureClaudeUsesNativeRoute(t *testing.T) {
	loadTestCatalog(t)
	for _, input := range []RequestInput{
		{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(`{"model":"azure/claude-fable-5-1","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":8192}`),
		},
		{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"azure/claude-fable-5-1","input":"hello","max_output_tokens":8192}`),
		},
	} {
		resolution, err := ResolveRequest(input)
		if err != nil {
			t.Fatalf("resolve Azure Claude request: %v", err)
		}
		if resolution.Provider != schemas.Azure || resolution.Deployment.ID != "azure-claude-fable-5-1-anthropic-hosted" ||
			resolution.Deployment.RouteID != "azure-anthropic-messages" {
			t.Fatalf("unexpected Azure Claude resolution: %#v", resolution)
		}
	}
}

func TestGPT56ReasoningEffortsFollowTheSelectedRoute(t *testing.T) {
	loadTestCatalog(t)
	for _, test := range []struct {
		provider schemas.ModelProvider
		model    string
	}{
		{provider: schemas.OpenAI, model: "openai-gpt-5.6-sol"},
		{provider: schemas.Azure, model: "azure-gpt-5.6-sol"},
	} {
		chat, ok := testDeploymentForRoute(test.provider, test.model, RouteChat)
		if !ok || !sameStrings(chat.ReasoningEfforts, []string{"low", "medium", "high", "xhigh"}) {
			t.Fatalf("%s Chat reasoning efforts = %#v", test.model, chat.ReasoningEfforts)
		}
		responses, ok := testDeploymentForRoute(test.provider, test.model, RouteResponses)
		if !ok || !sameStrings(responses.ReasoningEfforts, []string{"low", "medium", "high", "xhigh", "max"}) {
			t.Fatalf("%s Responses reasoning efforts = %#v", test.model, responses.ReasoningEfforts)
		}
	}

	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"azure-gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"reasoning":{"effort":"max"}}`),
	})
	if err != nil {
		t.Fatalf("resolve Azure GPT-5.6 Chat request: %v", err)
	}
	effort, ok := resolution.ReasoningEffort()
	if !ok || effort != "xhigh" {
		t.Fatalf("Azure GPT-5.6 Chat max effort = %q, present=%v", effort, ok)
	}

	resolution, err = ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"azure-gpt-5.6-sol","input":"hello","reasoning":{"effort":"max"}}`),
	})
	if err != nil {
		t.Fatalf("resolve Azure GPT-5.6 Responses request: %v", err)
	}
	if resolution.responses == nil || resolution.responses.ResponsesParameters.Reasoning == nil ||
		resolution.responses.ResponsesParameters.Reasoning.Effort == nil ||
		*resolution.responses.ResponsesParameters.Reasoning.Effort != "max" {
		t.Fatalf("Azure GPT-5.6 Responses did not preserve max: %#v", resolution.responses)
	}
}

func TestDeploymentLifecycleCutoffsFailClosed(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	for name, deployment := range map[string]compiledDeployment{
		"active": {
			RetirementDate: nil,
		},
		"future retirement": {
			RetirementDate: stringPointer("2026-07-28"),
		},
	} {
		if !deploymentAvailableAt(deployment, now) {
			t.Fatalf("%s deployment was unavailable", name)
		}
	}
	for name, deployment := range map[string]compiledDeployment{
		"retired": {
			RetirementDate: stringPointer("2026-07-23"),
		},
	} {
		if deploymentAvailableAt(deployment, now) {
			t.Fatalf("%s deployment remained available", name)
		}
	}
}

func TestRetiredAnthropicOpus41IsNotRoutableOrListed(t *testing.T) {
	loadTestCatalog(t)
	for _, selector := range []string{
		"claude-opus-4-1",
		"claude-opus-4.1",
		"anthropic-claude-opus-4-1-20250805",
	} {
		if deployment, ok := testDeploymentForRoute(schemas.Anthropic, selector, RouteChat); ok {
			t.Fatalf("retired selector %q remained routable: %#v", selector, deployment)
		}
	}

	models, ok := PublicModelsPayload()
	if !ok {
		t.Fatal("public model list unavailable")
	}
	for _, model := range models.Data {
		if strings.Contains(model.ID, "claude-opus-4-1") || model.ID == "claude-opus-4.1" {
			t.Fatalf("retired Claude Opus 4.1 selector remained listed: %q", model.ID)
		}
	}
}

func TestRequestedTierMovesOnlyModelSelectors(t *testing.T) {
	loadTestCatalog(t)
	for tier, want := range map[string]string{TierFlex: "openai-gpt-5.5-2026-04-23-flex", TierFast: "openai-gpt-5.5-2026-04-23-fast"} {
		if deployment, ok := activeState().deploymentForRoute(schemas.OpenAI, "gpt-5.5-2026-04-23", RouteResponses, variant{tier: tier}); !ok || deployment.ID != want {
			t.Fatalf("%s request selected %#v, want %s", tier, deployment, want)
		}
	}
	for _, selector := range []string{"openai-gpt-5.5-2026-04-23", "openai-gpt-5.5-2026-04-23-fast"} {
		if deployment, ok := activeState().deploymentForRoute(schemas.OpenAI, selector, RouteResponses, variant{tier: TierFlex}); ok {
			t.Fatalf("a requested tier retargeted the exact selector %s to %s", selector, deployment.ID)
		}
	}
	fastUS, ok := testDeploymentForRoute(schemas.Anthropic, "anthropic-claude-opus-4-8-fast-us", RouteResponses)
	if !ok {
		t.Fatal("Claude Opus 4.8 Fast US is missing")
	}
	if standardUS, ok := StandardTierDeployment(schemas.Anthropic, RouteResponses, fastUS); !ok || standardUS.ID != "anthropic-claude-opus-4-8-us" {
		t.Fatalf("Standard sibling of %s = %#v, want anthropic-claude-opus-4-8-us", fastUS.ID, standardUS)
	}
	// Azure's Claude Fast model has its own name but is the same deployment at another tier.
	azureFastUS, ok := testDeploymentForRoute(schemas.Azure, "azure-claude-opus-5-5-fast-us", RouteResponses)
	if !ok {
		t.Fatal("Azure Claude Opus 5.5 Fast US is missing")
	}
	if standardUS, ok := StandardTierDeployment(schemas.Azure, RouteResponses, azureFastUS); !ok || standardUS.ID != "azure-claude-opus-5-5-us" {
		t.Fatalf("Standard sibling of %s = %#v, want azure-claude-opus-5-5-us", azureFastUS.ID, standardUS)
	}
}

func TestGroupsSelectTheirNewestModel(t *testing.T) {
	loadTestCatalog(t)
	openAI, anthropic := map[string][]int{"openai": {0}}, map[string][]int{"anthropic": {0}}
	for _, test := range []struct {
		body        string
		credentials map[string][]int
		policy      string
		deployment  string
		code        string
	}{
		{body: `{"model":"gpt-5.5","input":"hello"}`, credentials: openAI, deployment: "openai-gpt-5.5-2026-04-23"},
		{body: `{"model":"gpt-6","input":"hello"}`, credentials: openAI, deployment: "openai-gpt-6.1-sol"},
		{body: `{"model":"openai/gpt-6","input":"hello"}`, credentials: openAI, deployment: "openai-gpt-6.1-sol"},
		{body: `{"model":"gpt-6","input":"hello","service_tier":"flex"}`, credentials: openAI, deployment: "openai-gpt-6.1-sol-flex"},
		{body: `{"model":"anthropic/gpt-6","input":"hello"}`, code: ErrModelUnavailable.Code},
		// Every Claude Mythos deployment needs approval, which only an exact selector requests.
		{body: `{"model":"claude-mythos","input":"hello"}`, code: ErrModelUnavailable.Code},
		// GPT-5.6 Luna, Sol and Terra share the newest release date, so only a policy order
		// chooses among them.
		{body: `{"model":"gpt-5.6","input":"hello"}`, credentials: openAI, code: ErrModelAmbiguous.Code},
		{
			body:        `{"model":"gpt-5.6","input":"hello"}`,
			credentials: openAI,
			policy:      `{"routing":{"sort":[{"by":"blended_price(3, 1)","direction":"asc"}]}}`,
			deployment:  "openai-gpt-5.6-luna",
		},
		{
			body:        `{"model":"claude","input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"filter":"'claude-opus' in model.groupIds"}}`,
			deployment:  "anthropic-claude-opus-5-5",
		},
	} {
		var config *policy.Config
		if test.policy != "" {
			source, err := policy.CompileSource([]byte(test.policy))
			if err != nil {
				t.Fatal(err)
			}
			if config, err = policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}}); err != nil {
				t.Fatal(err)
			}
		}
		resolved, err := ResolveRequest(RequestInput{
			AvailableCredentials: test.credentials,
			Body:                 []byte(test.body),
			Method:               "POST",
			Path:                 "/v1/responses",
			Policy:               config,
		})
		if test.code != "" {
			if err == nil || PublicError(err).Code != test.code {
				t.Fatalf("%s: want %s, got %#v, %v", test.body, test.code, resolved, err)
			}
			continue
		}
		if err != nil || resolved.Deployment.ID != test.deployment {
			t.Fatalf("%s: want %s, got %#v, %v", test.body, test.deployment, resolved, err)
		}
	}

	models, ok := PublicModelsPayload()
	if !ok {
		t.Fatal("public model list unavailable")
	}
	listed := map[string]bool{}
	for _, model := range models.Data {
		listed[model.ID] = true
	}
	for selector, want := range map[string]bool{"gpt-5.5": true, "gpt-6": true, "gpt-5.6": false, "claude-mythos": false} {
		if listed[selector] != want {
			t.Fatalf("/v1/models lists %s: %t, want %t", selector, listed[selector], want)
		}
	}
}

func TestReasoningAdmissionMapsCanonicalControlsWithoutInventingBinaryEfforts(t *testing.T) {
	loadTestCatalog(t)
	optional := Deployment{Reasoning: "optional", ReasoningEfforts: []string{"minimal", "low", "medium", "high"}}
	if got, err := normalizeReasoningEffort("high", optional); err != nil || got.Effort == nil || *got.Effort != "high" {
		t.Fatalf("accepted effort = %#v, err=%v", got, err)
	}
	if got, err := normalizeReasoningEffort("max", optional); err != nil || got.Effort == nil || *got.Effort != "high" {
		t.Fatalf("higher effort did not map down: %#v err=%v", got, err)
	}
	if got, err := normalizeReasoningEffort("none", optional); err != nil || got.Effort == nil || *got.Effort != "none" {
		t.Fatalf("optional reasoning was not disabled: %#v err=%v", got, err)
	}
	binary := Deployment{Reasoning: "optional"}
	if got, err := normalizeReasoningEffort("minimal", binary); err != nil || got.Enabled == nil || !*got.Enabled || got.Effort != nil {
		t.Fatalf("positive binary reasoning did not map to enabled: %#v err=%v", got, err)
	}
	if got, err := normalizeReasoningEffort("none", binary); err != nil || got.Enabled == nil || *got.Enabled || got.Effort != nil {
		t.Fatalf("binary reasoning did not map none to disabled: %#v err=%v", got, err)
	}
	twoLevels := Deployment{Reasoning: "optional", ReasoningEfforts: []string{"high", "max"}}
	if got, err := normalizeReasoningEffort("xhigh", twoLevels); err != nil || got.Effort == nil || *got.Effort != "max" {
		t.Fatalf("upward tie did not map to max: %#v err=%v", got, err)
	}
	requiredWithoutLevels := Deployment{Reasoning: "required"}
	if _, err := normalizeReasoningEffort("high", requiredWithoutLevels); err == nil {
		t.Fatal("effort was accepted for always-on reasoning without level control")
	}
	if _, err := normalizeReasoningEffort("none", Deployment{Reasoning: "required", ReasoningEfforts: []string{"low", "high"}}); err == nil {
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
		Body:   []byte(`{"model":"openai/gpt-5.5","input":"hello","reasoning":{"effort":"high"}}`),
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
	if got := resolution.CatalogNodeIDsForDeployment(resolution.Deployment); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog chain = %#v, want %#v", got, want)
	}
	if identity := resolution.CatalogIdentity(); identity != snap.identity {
		t.Fatalf("catalog identity = %#v, want %#v", identity, snap.identity)
	}
	expectedHash := snap.graph.Deployments[resolution.Deployment.ID].Routes["openai-responses"].ChainHash
	if !validSHA256Digest(expectedHash) || resolution.Deployment.ChainHash != expectedHash {
		t.Fatalf("request selected the wrong historical chain: %s", resolution.Deployment.ChainHash)
	}
}

// The public catalog states each route's facts with its provider's facts applied, and each
// deployment's facts per route, so readers never combine nodes themselves.
func TestPublicCatalogResolvesRouteFacts(t *testing.T) {
	loadTestCatalog(t)
	payload, ok := PublicCatalogPayload()
	if !ok || payload.Schema != publicSchema {
		t.Fatalf("public catalog unavailable: %#v", payload)
	}
	if !strings.HasPrefix(payload.RuntimeDigest, "sha256:") ||
		!strings.HasPrefix(payload.PublicDigest, "sha256:") ||
		payload.RuntimeDigest == payload.PublicDigest {
		t.Fatalf("public catalog identities are incomplete: %#v", payload)
	}
	var graph struct {
		Providers   map[string]map[string]any `json:"providers"`
		Routes      map[string]map[string]any `json:"routes"`
		Deployments map[string]struct {
			DataHandling map[string]any `json:"dataHandling"`
			Routes       map[string]struct {
				DataHandling DataHandling `json:"dataHandling"`
			} `json:"routes"`
		} `json:"deployments"`
	}
	for key, target := range map[string]any{"providers": &graph.Providers, "routes": &graph.Routes, "deployments": &graph.Deployments} {
		if err := json.Unmarshal(payload.Graph[key], target); err != nil {
			t.Fatalf("decode public %s: %v", key, err)
		}
	}
	for id, provider := range graph.Providers {
		if _, ok := provider["dataHandling"]; ok {
			t.Fatalf("provider %s repeats facts that its routes state", id)
		}
	}
	var fields map[string]any
	encoded, _ := json.Marshal(DataHandling{})
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for id, route := range graph.Routes {
		handling, _ := route["dataHandling"].(map[string]any)
		for field := range fields {
			if _, ok := handling[field]; !ok {
				t.Fatalf("route %s data handling lacks %s", id, field)
			}
		}
	}
	for id, deployment := range graph.Deployments {
		if deployment.DataHandling != nil {
			t.Fatalf("deployment %s states data handling outside its routes", id)
		}
		for routeID, route := range deployment.Routes {
			if err := validateDeploymentDataHandling(id+" route "+routeID, route.DataHandling); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestPricingIsMaterializedOnDeployments(t *testing.T) {
	loadTestCatalog(t)
	deployment, ok := testDeploymentForRoute(schemas.OpenAI, "gpt-5.5-2026-04-23", RouteResponses)
	if !ok {
		t.Fatal("GPT-5.5 deployment unavailable")
	}
	if deployment.Pricing["openai_responses_web_search_calls"][billing.RatePerThousandCalls] == "" {
		t.Fatalf("route pricing was not materialized: %#v", deployment.Pricing)
	}
}

func TestChutesTEEStatusIsMaterializedPerDeployment(t *testing.T) {
	loadTestCatalog(t)
	standard, ok := testDeploymentForRoute(
		ProviderChutes,
		"chutes-qwen3-32b",
		RouteChat,
	)
	if !ok || !standard.DataHandling.TEE || standard.DataHandling.TEEVerified {
		t.Fatalf("unexpected Chutes TEE status: %#v", standard.DataHandling)
	}
	nemotron, ok := testDeploymentForRoute(
		ProviderChutes,
		"chutes-nemotron-3-nano-omni-30b",
		RouteChat,
	)
	if !ok || !nemotron.DataHandling.TEE || nemotron.DataHandling.TEEVerified {
		t.Fatalf("unexpected Nemotron Chutes TEE status: %#v", nemotron.DataHandling)
	}
}

func TestDeploymentDataHandlingIsMaterializedForTheSelectedRoute(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["azure-gpt-5.6-sol"].(map[string]any)
	routes := deployment["routes"].(map[string]any)
	routes["azure-chat-completions"].(map[string]any)["dataHandling"].(map[string]any)["storageLocation"] = "US"
	routes["azure-responses"].(map[string]any)["dataHandling"].(map[string]any)["storageLocation"] = "eu"
	data, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshotFromCatalogBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	chat, ok := snap.deploymentFromCompiled(
		"azure-gpt-5.6-sol",
		snap.graph.Routes["azure-chat-completions"],
	)
	if !ok || chat.DataHandling.StorageLocation != "US" {
		t.Fatalf("chat route handling = %#v", chat.DataHandling)
	}
	responses, ok := snap.deploymentFromCompiled(
		"azure-gpt-5.6-sol",
		snap.graph.Routes["azure-responses"],
	)
	if !ok || responses.DataHandling.StorageLocation != "eu" {
		t.Fatalf("responses route handling = %#v", responses.DataHandling)
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
	routes := deployment["routes"].(map[string]any)
	routes["missing-route"] = routes["openai-responses"]
	delete(routes, "openai-responses")
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "unknown route") {
		t.Fatalf("broken route reference was accepted: %v", err)
	}
}

func TestSnapshotValidationRequiresBoundedInputCeiling(t *testing.T) {
	for _, limit := range []any{nil, 0, -1, 1050001} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			var runtime map[string]any
			if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
				t.Fatal(err)
			}
			deployment := runtime["graph"].(map[string]any)["deployments"].(map[string]any)["openai-gpt-5.6-sol"].(map[string]any)
			if limit == nil {
				delete(deployment, "maxInputTokens")
			} else {
				deployment["maxInputTokens"] = limit
			}
			data, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(data); err == nil {
				t.Fatalf("accepted invalid input ceiling %v", limit)
			}
		})
	}
}

func TestSnapshotValidationRequiresEachResolvedChain(t *testing.T) {
	for _, hash := range []string{"", "invalid", "sha256:" + strings.Repeat("a", 63)} {
		var runtime compiledCatalog
		if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
			t.Fatal(err)
		}
		route := runtime.Graph.Deployments["openai-gpt-5.5-2026-04-23"].Routes["openai-responses"]
		route.ChainHash = hash
		runtime.Graph.Deployments["openai-gpt-5.5-2026-04-23"].Routes["openai-responses"] = route
		if err := validateCompiledGraph(runtime.Graph); err == nil {
			t.Fatalf("invalid historical chain was accepted: %q", hash)
		}
	}
}

func TestSnapshotValidationBoundsExplicitAliases(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	models := graph["models"].(map[string]any)
	model := models["claude-haiku-4-5"].(map[string]any)
	aliases := make([]any, maxAliasesPerNode+1)
	for index := range aliases {
		aliases[index] = fmt.Sprintf("bounded-alias-%d", index)
	}
	model["aliases"] = aliases
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "too many aliases") {
		t.Fatalf("catalog with an unbounded alias list was accepted: %v", err)
	}
}

func TestSnapshotValidationBindsThePublicCatalog(t *testing.T) {
	var public map[string]any
	if err := json.Unmarshal(embeddedPublicCatalogJSON, &public); err != nil {
		t.Fatal(err)
	}
	graph := public["graph"].(map[string]any)
	authors := graph["authors"].(map[string]any)
	author := authors["anthropic"].(map[string]any)
	author["name"] = "changed"
	changed, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromRelease(embeddedRuntimeCatalogJSON, changed, Identity{}); err == nil ||
		!strings.Contains(err.Error(), "public catalog digest does not match") {
		t.Fatalf("mismatched public catalog was accepted: %v", err)
	}
}

func TestSnapshotValidationRequiresThePublicDigestCommitment(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	runtime["publicDigest"] = "sha256:invalid"
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "public digest is invalid") {
		t.Fatalf("invalid public digest commitment was accepted: %v", err)
	}
}

func TestSnapshotValidationAllowsDistinctSignedAzureModelSelectors(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["azure-deepseek-v4-pro"].(map[string]any)
	upstream := deployment["upstream"].(map[string]any)
	upstream["model"] = "reviewed-provider-selector"
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err != nil {
		t.Fatalf("distinct signed Azure provider selector was rejected: %v", err)
	}
}

func TestSnapshotValidationPreservesExactUSDRates(t *testing.T) {
	for _, rate := range []string{"0", "0.001", "0.042", "0.000000000000000000000000000000000001", "1000000000000", "-1", "01", "0.010", "1e15", "1000000000000.000000000000000000000000000000000001"} {
		t.Run(rate, func(t *testing.T) {
			var runtime map[string]any
			if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
				t.Fatal(err)
			}
			deployment := runtime["graph"].(map[string]any)["deployments"].(map[string]any)["openai-gpt-5.5-2026-04-23"].(map[string]any)
			route := deployment["routes"].(map[string]any)["openai-responses"].(map[string]any)
			route["pricing"].(map[string]any)[billing.MeterOutputTokens] = map[string]any{billing.RatePerMillionTokens: rate}
			data, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := snapshotFromCatalogBytes(data)
			switch rate {
			case "-1", "01", "0.010", "1e15", "1000000000000.000000000000000000000000000000000001":
				if err == nil {
					t.Fatal("invalid monetary rate was accepted")
				}
			default:
				if err != nil {
					t.Fatalf("valid monetary rate rejected: %v", err)
				}
				if got := loaded.graph.Deployments["openai-gpt-5.5-2026-04-23"].Routes["openai-responses"].Pricing[billing.MeterOutputTokens][billing.RatePerMillionTokens]; got != rate {
					t.Fatalf("rate changed: got %s, want %s", got, rate)
				}
			}
		})
	}
}

func TestSnapshotValidationRejectsUnbillablePricingAndReasoning(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(route map[string]any)
		want  string
	}{
		{
			name:  "missing input price",
			apply: func(route map[string]any) { delete(route["pricing"].(map[string]any), billing.MeterInputTokens) },
			want:  "missing required pricing meter",
		},
		{
			name:  "unknown effort",
			apply: func(route map[string]any) { route["reasoningEfforts"] = []any{"low", "future"} },
			want:  "unsupported reasoning effort",
		},
		{
			name:  "unordered efforts",
			apply: func(route map[string]any) { route["reasoningEfforts"] = []any{"high", "low"} },
			want:  "canonical order",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var runtime map[string]any
			if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
				t.Fatal(err)
			}
			deployment := runtime["graph"].(map[string]any)["deployments"].(map[string]any)["openai-gpt-5.5-2026-04-23"].(map[string]any)
			test.apply(deployment["routes"].(map[string]any)["openai-responses"].(map[string]any))
			broken, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(broken); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("catalog was accepted or failed for another reason: %v", err)
			}
		})
	}
}

func TestSnapshotValidationRejectsVerifiedTEEWithoutTEEProcessing(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["chutes-qwen3-32b"].(map[string]any)
	dataHandling := deployment["routes"].(map[string]any)["chutes-chat-completions"].(map[string]any)["dataHandling"].(map[string]any)
	dataHandling["tee"] = false
	dataHandling["teeVerified"] = true
	broken, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "verifies a TEE that is not enabled") {
		t.Fatalf("catalog with impossible TEE verification was accepted: %v", err)
	}
}

func TestSnapshotValidationRejectsReasoningThatWeakensTheModel(t *testing.T) {
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph := runtime["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["chutes-kimi-k3"].(map[string]any)
	deployment["reasoning"] = "unsupported"
	for _, route := range deployment["routes"].(map[string]any) {
		route.(map[string]any)["reasoningEfforts"] = []any{}
	}
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

// Policies check compared strings against the same vocabulary, so a catalog value outside it
// would be impossible to name in a policy.
func TestSnapshotRejectsValuesThatPoliciesCannotName(t *testing.T) {
	deployment := func(graph map[string]any) map[string]any {
		return graph["deployments"].(map[string]any)["azure-gpt-5.6-sol"].(map[string]any)
	}
	upstream := func(graph map[string]any) map[string]any { return deployment(graph)["upstream"].(map[string]any) }
	deploymentRoute := func(graph map[string]any) map[string]any {
		return deployment(graph)["routes"].(map[string]any)["azure-chat-completions"].(map[string]any)
	}
	for _, tc := range []struct {
		name  string
		apply func(graph map[string]any)
	}{
		{"hosting", func(g map[string]any) { upstream(g)["hosting"] = "Azure" }},
		{"deployment type", func(g map[string]any) { upstream(g)["deploymentType"] = "GlobalStandard" }},
		{"weight precision", func(g map[string]any) { deployment(g)["weightPrecision"] = "fp7" }},
		{"processing location", func(g map[string]any) {
			deploymentRoute(g)["dataHandling"].(map[string]any)["processingLocation"] = "EU"
		}},
		{"extension", func(g map[string]any) {
			g["routes"].(map[string]any)["azure-chat-completions"].(map[string]any)["documentFormats"] = map[string]any{
				"extensions": []any{"pdf"}, "mediaTypes": []any{"application/pdf"}}
		}},
		{"country", func(g map[string]any) {
			g["authors"].(map[string]any)["openai"].(map[string]any)["headquarteredCountry"] = "USA"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var runtime map[string]any
			if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
				t.Fatal(err)
			}
			tc.apply(runtime["graph"].(map[string]any))
			raw, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(raw); err == nil || !strings.Contains(err.Error(), "outside the policy vocabulary") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestSnapshotRejectsIncompleteOrAmbiguousFileFormats(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(map[string]any)
	}{
		{"missing formats", func(r map[string]any) { delete(r, "documentFormats") }},
		{"missing array", func(r map[string]any) { delete(r["documentFormats"].(map[string]any), "mediaTypes") }},
		{"wildcard MIME", func(r map[string]any) { r["documentFormats"].(map[string]any)["mediaTypes"] = []any{"text/*"} }},
		{"duplicate extension", func(r map[string]any) {
			r["documentFormats"].(map[string]any)["extensions"] = []any{".pdf", ".pdf"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var runtime map[string]any
			if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
				t.Fatal(err)
			}
			tc.apply(runtime["graph"].(map[string]any)["routes"].(map[string]any)["openai-responses"].(map[string]any))
			raw, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(raw); err == nil {
				t.Fatal("invalid document formats accepted")
			}
		})
	}
}
