package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func testDeploymentForRoute(provider schemas.ModelProvider, model string, route Route) (Deployment, bool) {
	return testDeploymentAt(provider, model, route, variant{})
}

// testDeploymentAt returns the provider's deployment that a model field selects at a variant: the
// one that it names, or else the one with the shortest ID, which carries no region or other
// suffix.
func testDeploymentAt(provider schemas.ModelProvider, model string, route Route, want variant) (Deployment, bool) {
	snap := activeState()
	selection, err := snap.parseModelSelection(model)
	if err != nil {
		return Deployment{}, false
	}
	var found Deployment
	for _, candidate := range snap.routingSelections(route, selection, want, nil, nil, time.Now()) {
		if candidate.provider == provider && (found.ID == "" || len(candidate.deployment.ID) < len(found.ID)) {
			found = candidate.deployment
		}
	}
	return found, found.ID != ""
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

// A gateway serves the fallback until it approves a release, so the fallback loads with every
// record that its root lists, but for models without a deployment.
func TestFallbackLoadsEveryRecordThatItsRootLists(t *testing.T) {
	root, _, err := Fallback()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := loadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.identity.Sequence != 0 || !strings.HasPrefix(snap.identity.Digest, "sha256:") {
		t.Fatalf("unexpected fallback identity: %#v", snap.identity)
	}
	var listed struct {
		Summaries map[string]map[string]json.RawMessage `json:"summaries"`
	}
	if err := json.Unmarshal(root, &listed); err != nil {
		t.Fatal(err)
	}
	deployed := map[string]json.RawMessage{}
	for _, deployment := range snap.graph.Deployments {
		deployed[deployment.ModelID] = listed.Summaries["models"][deployment.ModelID]
	}
	for kind, same := range map[string]bool{
		"authors":     sameIDs(snap.graph.Authors, listed.Summaries["authors"]),
		"models":      sameIDs(snap.graph.Models, deployed),
		"providers":   sameIDs(snap.graph.Providers, listed.Summaries["providers"]),
		"routes":      sameIDs(snap.graph.Routes, listed.Summaries["routes"]),
		"deployments": sameIDs(snap.graph.Deployments, listed.Summaries["deployments"]),
	} {
		if !same {
			t.Errorf("the fallback's graph holds other %s than its root lists", kind)
		}
	}
	if _, exists := snap.graph.Deployments["openai-gpt-4o-search-preview-2025-03-11"]; exists {
		t.Fatal("retired search preview deployment must not remain in the current catalog")
	}
}

func sameIDs[Record any](records map[string]Record, listed map[string]json.RawMessage) bool {
	if len(records) != len(listed) {
		return false
	}
	for id := range listed {
		if _, ok := records[id]; !ok {
			return false
		}
	}
	return true
}

func TestAzureEUDataZoneKeepsDataInEurope(t *testing.T) {
	snap := loadTestCatalog(t)
	euDeployment := snap.graph.Deployments["azure-gpt-5.6-sol-eu"]
	if len(euDeployment.Routes) == 0 {
		t.Fatal("the test catalog has no Azure EU Data Zone deployment")
	}
	for routeID, route := range euDeployment.Routes {
		if handling := route.DataHandling; handling.ProcessingLocation != "europe" || handling.StorageLocation != "europe" {
			t.Fatalf("Azure EU Data Zone route %s has invalid boundaries: %#v", routeID, handling)
		}
	}
}

func TestGraphLeavesOutModelsWithoutDeployments(t *testing.T) {
	root, _ := testFiles(t)
	var listed struct {
		Summaries struct {
			Models map[string]json.RawMessage `json:"models"`
		} `json:"summaries"`
	}
	if err := json.Unmarshal(root, &listed); err != nil {
		t.Fatal(err)
	}
	snap := loadTestCatalog(t)
	deployed := make(map[string]bool)
	for _, deployment := range snap.graph.Deployments {
		deployed[deployment.ModelID] = true
	}
	for id := range listed.Summaries.Models {
		if _, inGraph := snap.graph.Models[id]; inGraph != deployed[id] {
			t.Fatalf("model %s is in the graph: %t, has a deployment: %t", id, inGraph, deployed[id])
		}
	}
	if len(snap.graph.Models) == len(listed.Summaries.Models) {
		t.Fatal("the test catalog lists no model without a deployment, so this test checks nothing")
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
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			deployment := whole["graph"].(map[string]any)["deployments"].(map[string]any)[deploymentID].(map[string]any)
			deployment["upstream"].(map[string]any)["model"] = "future-openai-model"
			data, err := json.Marshal(whole)
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
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			deployment := whole["graph"].(map[string]any)["deployments"].(map[string]any)["chutes-qwen3.6-27b"].(map[string]any)
			route := deployment["routes"].(map[string]any)["chutes-chat-completions"].(map[string]any)
			test.apply(route["dataHandling"].(map[string]any))
			data, err := json.Marshal(whole)
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
	var whole map[string]any
	if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
		t.Fatal(err)
	}
	deployments := whole["graph"].(map[string]any)["deployments"].(map[string]any)
	uncached := deployments["azure-gpt-oss-120b"].(map[string]any)["routes"].(map[string]any)["azure-chat-completions"].(map[string]any)
	if _, present := uncached["pricing"].(map[string]any)[billing.MeterCachedInputTokens]; present {
		t.Fatal("test fixture unexpectedly has a cached-input price")
	}
	if _, err := snapshotFromCatalogBytes(testCatalogJSON); err != nil {
		t.Fatalf("uncached deployment was rejected: %v", err)
	}

	cached := deployments["azure-gpt-5.6-sol"].(map[string]any)["routes"].(map[string]any)["azure-responses"].(map[string]any)
	delete(cached["pricing"].(map[string]any), billing.MeterCachedInputTokens)
	broken, err := json.Marshal(whole)
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
		Body:   []byte(`{"model":"provider:openai gpt-5.6-sol","input":"hello"}`),
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

// The model field names what serves a request by a bare ID, OpenRouter's author/model form or
// typed terms, and matches IDs whatever their case, dots or underscores.
func TestModelFieldTerms(t *testing.T) {
	loadTestCatalog(t)
	snap := active.Load()
	providers := func(field string) []string {
		t.Helper()
		selection, err := snap.parseModelSelection(field)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		seen := map[string]bool{}
		for _, candidate := range snap.routingSelections(RouteResponses, selection, variant{}, nil, nil, time.Now()) {
			seen[string(candidate.provider)] = true
		}
		return slices.Sorted(maps.Keys(seen))
	}
	for field, want := range map[string][]string{
		"gpt-5.5-2026-04-23":                              {"azure", "openai"},
		"openai/gpt-5.5-2026-04-23":                       {"azure", "openai"},
		"Open_AI/GPT-5.5-2026-04-23":                      {"azure", "openai"},
		"provider:openai gpt-5.5-2026-04-23":              {"openai"},
		"gpt-5.5-2026-04-23 provider:open-ai":             {"openai"},
		"route:openai-responses model:gpt-5.5-2026-04-23": {"openai"},
		"deployment:openai-gpt-5.5-2026-04-23":            {"openai"},
		"provider:gcp claude-haiku-4.5":                   {},
		"author:anthropic provider:anthropic":             {"anthropic"},
	} {
		if got := providers(field); !slices.Equal(got, want) {
			t.Errorf("%s: providers %v, want %v", field, got, want)
		}
	}
	// A dot or an underscore matches a hyphen, so the dotted alias and the deployment ID with a
	// dot name the same nodes.
	for _, field := range []string{"claude-haiku-4-5", "claude-haiku-4.5", "anthropic/claude-haiku-4.5", "anthropic-claude-haiku-4.5-20251001"} {
		deployment, ok := testDeploymentForRoute(schemas.Anthropic, field, RouteChat)
		if !ok || deployment.ID != "anthropic-claude-haiku-4-5-20251001" || deployment.Upstream.Model != "claude-haiku-4-5-20251001" {
			t.Fatalf("%s did not select Claude Haiku 4.5: %#v", field, deployment)
		}
	}
	for field, want := range map[string]string{
		"anthropic/gpt-5.5-2026-04-23":                 "gpt-5.5-2026-04-23 is a model by openai, not by anthropic.",
		"openai/openai/gpt-5.5-2026-04-23":             `Write "openai/openai/gpt-5.5-2026-04-23" as author/model`,
		"chutes/glm-5.2":                               "chutes is not an author. To choose a provider, write provider:chutes glm-5.2.",
		"azure":                                        "azure is a provider. Write provider:azure",
		"gpt-5.5-latest":                               "The catalog has no model, group or deployment gpt-5.5-latest.",
		"vendor:openai":                                `Unknown term "vendor:openai"`,
		"provider:":                                    `Write "provider:" as kind:ID`,
		"provider:azure provider:openai":               "names more than one provider",
		"gpt-5.5-2026-04-23 claude-haiku-4-5":          "names more than one model, group or deployment",
		"model:claude":                                 "claude is a group. Write group:claude",
		"anthropic-claude-opus-4-8-us-fast":            "The catalog has no model, group or deployment",
		"author:openai author:anthropic gpt-5 a b c d": "at most 6 terms",
		strings.Repeat("a", maxModelFieldBytes+1):      "at most 1024 bytes",
	} {
		_, err := snap.parseModelSelection(field)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", field, err, want)
		}
	}
}

func TestProviderRestrictionKeepsThePolicyOrder(t *testing.T) {
	loadTestCatalog(t)
	for _, route := range []Route{RouteChat, RouteResponses} {
		path := "/v1/responses"
		body := `{"model":"gpt-5.6-sol","input":"hello","provider":{"only":["azure"]}}`
		if route == RouteChat {
			path = "/v1/chat/completions"
			body = `{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"provider":{"only":["azure"]}}`
		}
		resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: []byte(body), Policy: policyConfig(3)})
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
		{selector: "provider:openai gpt-5.6-sol", provider: schemas.OpenAI, deployment: "openai-gpt-5.6-sol"},
		{selector: "provider:azure azure-gpt-5.6-sol", provider: schemas.Azure, deployment: "azure-gpt-5.6-sol"},
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

func TestUnusablePreferredProviderLeavesThePolicyOrder(t *testing.T) {
	snap := loadTestCatalog(t)

	openAI := *snap.graph.Deployments["openai-gpt-5.6-sol"]
	openAI.MaxOutputTokens = 1
	snap.graph.Deployments["openai-gpt-5.6-sol"] = &openAI

	chutes := *snap.graph.Deployments["chutes-deepseek-v3.2"]
	chutes.ModelID = "gpt-5.6-sol"
	chutes.Upstream.Model = "gpt-5.6-sol"
	snap.graph.Deployments["chutes-gpt-5.6-sol"] = &chutes
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
			Policy: policyConfig(3),
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
	source, err := policy.CompileSource([]byte(`{"delegation":{"request":["routing.filter"]},"routing":{"sort":[{"by":"model.releaseDate","direction":"desc"},{"by":"blended_price(3, 1)"},{"by":"deployment.id"}]}}`))
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
		{fields: `"model":"provider:openai gpt-5.5"`, deployment: "openai-gpt-5.5-2026-04-23", wire: "default"},
		{fields: `"model":"provider:openai gpt-5.5","service_tier":"auto"`, deployment: "openai-gpt-5.5-2026-04-23", wire: "default"},
		{fields: `"model":"provider:openai gpt-5.5","service_tier":"standard"`, deployment: "openai-gpt-5.5-2026-04-23", wire: "default"},
		{fields: `"model":"provider:openai gpt-5.5","service_tier":"priority"`, deployment: "openai-gpt-5.5-2026-04-23-fast", wire: "fast"},
		{fields: `"model":"provider:openai gpt-5.5","service_tier":"flex"`, deployment: "openai-gpt-5.5-2026-04-23-flex", wire: "flex"},
		{fields: `"model":"provider:azure gpt-5.6-sol","service_tier":"fast"`, deployment: "azure-gpt-5.6-sol-fast", wire: "priority"},
		{fields: `"model":"provider:azure gpt-6-astra","service_tier":"flex"`, deployment: "azure-gpt-6-astra-flex", wire: "flex"},
		{fields: `"model":"provider:openai gpt-6-astra","service_tier":"ultrafast"`, deployment: "openai-gpt-6-astra-ultrafast", wire: "ultrafast"},
		{fields: `"model":"provider:anthropic claude-opus-5","service_tier":"fast",` + multiRegion, deployment: "anthropic-claude-opus-5-fast", wire: "default"},
		{fields: `"model":"provider:anthropic claude-opus-5","service_tier":"auto",` + multiRegion, deployment: "anthropic-claude-opus-5", wire: "default"},
		{fields: `"model":"provider:azure claude-fable-5-1","service_tier":"default"`, deployment: "azure-claude-fable-5-1-anthropic-hosted"},
		// Azure sells Claude Fast as its own model, so the request names no tier.
		{fields: `"model":"provider:azure claude-opus-5-5","service_tier":"fast"`, deployment: "azure-claude-opus-5-5-fast"},
		{fields: `"model":"provider:openai gpt-5.6-sol","service_tier":"ultrafast"`, err: ErrServiceTierUnavailable},
		{fields: `"model":"provider:anthropic claude-opus-4-8","service_tier":"flex"`, err: ErrServiceTierUnavailable},
		{fields: `"model":"openai-gpt-5.5-2026-04-23-flex","service_tier":"fast"`, err: ErrServiceTierUnavailable},
		{fields: `"model":"provider:openai gpt-5.5","service_tier":"scale"`, err: ErrUnsupportedServiceTier},
		{fields: `"model":"provider:anthropic claude-opus-4-8","service_tier":"standard_only"`, err: ErrUnsupportedServiceTier},
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
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":"pro"}`, deployment: "openai-gpt-5.6-sol-pro"},
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":"standard","effort":"high"}`, deployment: "openai-gpt-5.6-sol", effort: "high"},
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":null}`, deployment: "openai-gpt-5.6-sol"},
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":"pro"},"service_tier":"flex"`, deployment: "openai-gpt-5.6-sol-pro-flex"},
		{fields: `"model":"provider:azure gpt-6-astra","reasoning":{"mode":"pro"}`, deployment: "azure-gpt-6-astra-pro"},
		{fields: `"model":"openai-gpt-5.6-sol-pro","reasoning":{"mode":"pro"}`, deployment: "openai-gpt-5.6-sol-pro"},
		// A group selects its newest model in the mode.
		{fields: `"model":"provider:openai gpt-6","reasoning":{"mode":"pro"}`, deployment: "openai-gpt-6.1-sol-pro"},
		{fields: `"model":"openai-gpt-5.6-sol-pro","reasoning":{"mode":"standard"}`, err: ErrReasoningModeUnavailable},
		{fields: `"model":"openai-gpt-5.6-sol","reasoning":{"mode":"pro"}`, err: ErrReasoningModeUnavailable},
		{fields: `"model":"provider:openai gpt-5.5","reasoning":{"mode":"pro"}`, err: ErrReasoningModeUnavailable},
		{fields: `"model":"claude","reasoning":{"mode":"pro"}`, err: ErrReasoningModeUnavailable},
		// The mode applies before the tier.
		{fields: `"model":"provider:openai gpt-5.5","reasoning":{"mode":"pro"},"service_tier":"ultrafast"`, err: ErrReasoningModeUnavailable},
		{fields: `"model":"provider:openai gpt-6-astra","reasoning":{"mode":"pro"},"service_tier":"ultrafast"`, err: ErrServiceTierUnavailable},
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":"turbo"}`, err: ErrUnsupportedReasoningMode},
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":1}`, err: ErrInvalidJSON},
		// A key that allows only some deployments names the field that its allowed nodes exclude.
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":"pro"},"service_tier":"flex"`, config: allowing("openai-gpt-5.6-sol-pro"), err: ErrServiceTierUnavailable},
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":"pro"},"service_tier":"flex"`, config: allowing("openai-gpt-5.6-sol-flex"), err: ErrReasoningModeUnavailable},
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":"standard"}`, config: allowing("openai-gpt-5.6-sol-pro"), err: ErrReasoningModeUnavailable},
		{fields: `"model":"provider:openai gpt-5.6-sol"`, config: allowing("openai-gpt-5.6-sol-pro"), err: ErrModelUnavailable},
		// The key serves Pro only at Flex, so the tier that the request leaves to the model fails.
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":"pro"}`, config: allowing("openai-gpt-5.6-sol-pro-flex"), err: ErrModelUnavailable},
		{fields: `"model":"provider:openai gpt-5.6-sol","reasoning":{"mode":"pro"},"service_tier":"fast"`, config: allowing("openai-gpt-5.6-sol-pro-flex"), err: ErrServiceTierUnavailable},
		// A key that can use no Claude model gets no mode named.
		{fields: `"model":"claude","reasoning":{"mode":"pro"}`, config: allowing("openai-gpt-5.6-sol"), err: ErrModelUnavailable},
	} {
		config := test.config
		if config == nil {
			config = policyConfig(3)
		}
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
		Body:   []byte(`{"model":"provider:openai gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"reasoning":{"mode":"pro"}}`),
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
			Body:   []byte(`{"model":"provider:azure claude-fable-5-1","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":8192}`),
		},
		{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"provider:azure claude-fable-5-1","input":"hello","max_output_tokens":8192}`),
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
	for name, deployment := range map[string]*compiledDeployment{
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
	for name, deployment := range map[string]*compiledDeployment{
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
		if deployment, ok := testDeploymentAt(schemas.OpenAI, "gpt-5.5-2026-04-23", RouteResponses, variant{tier: tier}); !ok || deployment.ID != want {
			t.Fatalf("%s request selected %#v, want %s", tier, deployment, want)
		}
	}
	for _, selector := range []string{"openai-gpt-5.5-2026-04-23", "openai-gpt-5.5-2026-04-23-fast"} {
		if deployment, ok := testDeploymentAt(schemas.OpenAI, selector, RouteResponses, variant{tier: TierFlex}); ok {
			t.Fatalf("a requested tier retargeted the exact selector %s to %s", selector, deployment.ID)
		}
	}
	fastUS, ok := testDeploymentForRoute(schemas.Anthropic, "anthropic-claude-opus-5-fast-us", RouteResponses)
	if !ok {
		t.Fatal("Claude Opus 5 Fast US is missing")
	}
	if standardUS, ok := StandardTierDeployment(schemas.Anthropic, RouteResponses, fastUS); !ok || standardUS.ID != "anthropic-claude-opus-5-us" {
		t.Fatalf("Standard sibling of %s = %#v, want anthropic-claude-opus-5-us", fastUS.ID, standardUS)
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

// Only the policy decides which model of a group serves: no hidden rule picks
// the newest one. The test default sorts by release date, then price.
func TestGroupsFollowThePolicyOrder(t *testing.T) {
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
		{body: `{"model":"provider:openai gpt-6","input":"hello"}`, credentials: openAI, deployment: "openai-gpt-6.1-sol"},
		{body: `{"model":"gpt-6","input":"hello","service_tier":"flex"}`, credentials: openAI, deployment: "openai-gpt-6.1-sol-flex"},
		{body: `{"model":"provider:anthropic gpt-6","input":"hello"}`, code: ErrModelUnavailable.Code},
		// Every Claude Mythos deployment needs approval, which only an exact selector requests.
		{body: `{"model":"claude-mythos","input":"hello"}`, code: ErrModelUnavailable.Code},
		// Without a sort, the models of a group tie.
		{body: `{"model":"gpt-5.6","input":"hello"}`, credentials: openAI, policy: `{}`, code: ErrModelAmbiguous.Code},
		// GPT-5.6 Luna, Sol and Terra share a release date, so price decides.
		{body: `{"model":"gpt-5.6","input":"hello"}`, credentials: openAI, deployment: "openai-gpt-5.6-luna"},
		{
			body:        `{"model":"gpt-5.6","input":"hello"}`,
			credentials: openAI,
			policy:      `{"routing":{"sort":[{"by":"blended_price(3, 1)","direction":"asc"}]}}`,
			deployment:  "openai-gpt-5.6-luna",
		},
		// A price sort alone picks the cheapest Claude, whatever its age.
		{
			body:        `{"model":"claude","input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"sort":[{"by":"blended_price(3, 1)"},{"by":"deployment.id"}]}}`,
			deployment:  "anthropic-claude-haiku-5-5",
		},
		{
			body:        `{"model":"claude","input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"filter":"'claude-opus' in model.groupIds","sort":[{"by":"model.releaseDate","direction":"desc"},{"by":"blended_price(3, 1)"},{"by":"deployment.id"}]}}`,
			deployment:  "anthropic-claude-opus-5-5",
		},
	} {
		config := policyConfig(3)
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
	// Every group with a deployment that needs no approval is listed, even
	// one whose newest models share a release date: policies choose.
	for selector, want := range map[string]bool{"gpt-5.5": true, "gpt-6": true, "gpt-5.6": true, "claude-mythos": false} {
		if listed[selector] != want {
			t.Fatalf("/v1/models lists %s: %t, want %t", selector, listed[selector], want)
		}
	}
}

func TestReasoningAdmissionMapsCanonicalControlsWithoutInventingBinaryEfforts(t *testing.T) {
	loadTestCatalog(t)
	optional := Deployment{Reasoning: "optional", ReasoningEfforts: []string{"minimal", "low", "medium", "high"}}
	if got, err := normalizeReasoningEffort("high", optional, 64000); err != nil || got.Effort == nil || *got.Effort != "high" {
		t.Fatalf("accepted effort = %#v, err=%v", got, err)
	}
	if got, err := normalizeReasoningEffort("max", optional, 64000); err != nil || got.Effort == nil || *got.Effort != "high" {
		t.Fatalf("higher effort did not map down: %#v err=%v", got, err)
	}
	if got, err := normalizeReasoningEffort("none", optional, 64000); err != nil || got.Effort == nil || *got.Effort != "none" {
		t.Fatalf("optional reasoning was not disabled: %#v err=%v", got, err)
	}
	binary := Deployment{Reasoning: "optional"}
	if got, err := normalizeReasoningEffort("minimal", binary, 64000); err != nil || got.Enabled == nil || !*got.Enabled || got.Effort != nil {
		t.Fatalf("positive binary reasoning did not map to enabled: %#v err=%v", got, err)
	}
	if got, err := normalizeReasoningEffort("none", binary, 64000); err != nil || got.Enabled == nil || *got.Enabled || got.Effort != nil {
		t.Fatalf("binary reasoning did not map none to disabled: %#v err=%v", got, err)
	}
	twoLevels := Deployment{Reasoning: "optional", ReasoningEfforts: []string{"high", "max"}}
	if got, err := normalizeReasoningEffort("xhigh", twoLevels, 64000); err != nil || got.Effort == nil || *got.Effort != "max" {
		t.Fatalf("upward tie did not map to max: %#v err=%v", got, err)
	}
	requiredWithoutLevels := Deployment{Reasoning: "required"}
	if _, err := normalizeReasoningEffort("high", requiredWithoutLevels, 64000); err == nil {
		t.Fatal("effort was accepted for always-on reasoning without level control")
	}
	if _, err := normalizeReasoningEffort("none", Deployment{Reasoning: "required", ReasoningEfforts: []string{"low", "high"}}, 64000); err == nil {
		t.Fatal("required reasoning was disabled")
	}
	if _, err := normalizeReasoningEffort("ultra", optional, 64000); err == nil {
		t.Fatal("non-canonical effort was accepted")
	}
}

// A deployment that takes a budget but no levels gets each positive effort as its share of the output
// token limit above the minimum, so the effort reaches every provider as the same number.
func TestReasoningEffortSelectsABudgetWhereADeploymentHasNoLevels(t *testing.T) {
	budgeted := Deployment{Reasoning: "optional", ReasoningMaxTokens: &ReasoningMaxTokens{Minimum: 1024, Maximum: 63999}}
	for effort, want := range map[string]int{
		"minimal": 2598, "low": 10470, "medium": 27788, "high": 51404, "xhigh": 58961, "max": 63999,
	} {
		got, err := normalizeReasoningEffort(effort, budgeted, 64000)
		if err != nil || got.MaxTokens == nil || *got.MaxTokens != want || got.Effort != nil || got.Enabled != nil {
			t.Fatalf("%s = %#v, err=%v, want a budget of %d", effort, got, err, want)
		}
	}
	for _, test := range []struct {
		name       string
		effort     string
		deployment Deployment
		limit      int
		want       int
	}{
		{"a smaller output token limit", "high", budgeted, 4096, 3481},
		{"the deployment maximum", "max", Deployment{Reasoning: "optional", ReasoningMaxTokens: &ReasoningMaxTokens{Minimum: 1024, Maximum: 32000}}, 64000, 32000},
		{"one token above the minimum", "max", budgeted, 1025, 1024},
		{"an always-on deployment", "low", Deployment{Reasoning: "required", ReasoningMaxTokens: budgeted.ReasoningMaxTokens}, 64000, 10470},
	} {
		got, err := normalizeReasoningEffort(test.effort, test.deployment, test.limit)
		if err != nil || got.MaxTokens == nil || *got.MaxTokens != test.want {
			t.Fatalf("%s: %#v, err=%v, want a budget of %d", test.name, got, err, test.want)
		}
	}
	if _, err := normalizeReasoningEffort("low", budgeted, 1024); err == nil {
		t.Fatal("a budget was accepted that does not fit below the output token limit")
	}
	if got, err := normalizeReasoningEffort("none", budgeted, 64000); err != nil || got.Effort == nil || *got.Effort != "none" || got.Enabled != nil || got.MaxTokens != nil {
		t.Fatalf("none = %#v, err=%v, want the effort none", got, err)
	}
	if got, err := normalizeReasoningEnabled(true, budgeted, 64000); err != nil || got.MaxTokens == nil || *got.MaxTokens != 27788 {
		t.Fatalf("enabled = %#v, err=%v, want the medium budget", got, err)
	}

	effort := func(value string) *string { return &value }
	enabled := func(value bool) *bool { return &value }
	for _, test := range []struct {
		name      string
		reasoning schemas.ChatReasoning
		want      schemas.ChatReasoning
	}{
		{"an effort", schemas.ChatReasoning{Effort: effort("high")}, schemas.ChatReasoning{MaxTokens: schemas.Ptr(51404)}},
		{"reasoning on", schemas.ChatReasoning{Enabled: enabled(true)}, schemas.ChatReasoning{MaxTokens: schemas.Ptr(27788)}},
		{"reasoning on with an effort", schemas.ChatReasoning{Enabled: enabled(true), Effort: effort("low")}, schemas.ChatReasoning{MaxTokens: schemas.Ptr(10470)}},
		{"reasoning off", schemas.ChatReasoning{Enabled: enabled(false)}, schemas.ChatReasoning{Effort: effort("none")}},
		{"a manual budget", schemas.ChatReasoning{MaxTokens: schemas.Ptr(2048)}, schemas.ChatReasoning{MaxTokens: schemas.Ptr(2048)}},
	} {
		reasoning := test.reasoning
		if err := normalizeChatReasoning(&reasoning, budgeted, 64000); err != nil || !reflect.DeepEqual(reasoning, test.want) {
			t.Fatalf("chat with %s = %#v, err=%v, want %#v", test.name, reasoning, err, test.want)
		}
	}

	for _, test := range []struct {
		name      string
		reasoning schemas.ResponsesParametersReasoning
		want      schemas.ResponsesParametersReasoning
	}{
		{"an effort", schemas.ResponsesParametersReasoning{Effort: effort("low")}, schemas.ResponsesParametersReasoning{MaxTokens: schemas.Ptr(10470)}},
		{"reasoning off", schemas.ResponsesParametersReasoning{Effort: effort("none")}, schemas.ResponsesParametersReasoning{Effort: effort("none")}},
		{"a manual budget", schemas.ResponsesParametersReasoning{MaxTokens: schemas.Ptr(2048)}, schemas.ResponsesParametersReasoning{MaxTokens: schemas.Ptr(2048)}},
	} {
		reasoning := test.reasoning
		if err := normalizeResponsesReasoning(&reasoning, budgeted, 64000); err != nil || !reflect.DeepEqual(reasoning, test.want) {
			t.Fatalf("Responses with %s = %#v, err=%v, want %#v", test.name, reasoning, err, test.want)
		}
	}
	both := schemas.ResponsesParametersReasoning{Effort: effort("low"), MaxTokens: schemas.Ptr(2048)}
	if err := normalizeResponsesReasoning(&both, budgeted, 64000); err == nil {
		t.Fatal("Responses accepted an effort together with a manual budget")
	}
	binary := schemas.ResponsesParametersReasoning{Effort: effort("low")}
	if err := normalizeResponsesReasoning(&binary, Deployment{Reasoning: "optional"}, 64000); err == nil {
		t.Fatal("Responses accepted an effort for a deployment that only turns reasoning on and off")
	}
}

func TestResolvedRequestPinsCatalogIdentityAndFiveNodeChain(t *testing.T) {
	snap := loadTestCatalog(t)
	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"provider:openai gpt-5.5","input":"hello","reasoning":{"effort":"high"}}`),
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
func TestCatalogStatesDataHandlingOnRoutes(t *testing.T) {
	release := testCatalogRelease(t)
	for id, provider := range release.root["summaries"].(map[string]any)["providers"].(map[string]any) {
		if _, ok := provider.(map[string]any)["dataHandling"]; ok {
			t.Fatalf("provider %s repeats facts that its routes state", id)
		}
	}
	var fields map[string]any
	encoded, _ := json.Marshal(DataHandling{})
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, part := range release.parts {
		graph := part["graph"].(map[string]any)
		routes, _ := graph["routes"].(map[string]any)
		for id, route := range routes {
			handling, _ := route.(map[string]any)["dataHandling"].(map[string]any)
			for field := range fields {
				if _, ok := handling[field]; !ok {
					t.Fatalf("route %s data handling lacks %s", id, field)
				}
			}
		}
		deployments, _ := graph["deployments"].(map[string]any)
		for id, deployment := range deployments {
			if _, ok := deployment.(map[string]any)["dataHandling"]; ok {
				t.Fatalf("deployment %s states data handling outside its routes", id)
			}
			for routeID, route := range deployment.(map[string]any)["routes"].(map[string]any) {
				var handling DataHandling
				encoded, _ := json.Marshal(route.(map[string]any)["dataHandling"])
				if err := json.Unmarshal(encoded, &handling); err != nil {
					t.Fatal(err)
				}
				if err := validateDeploymentDataHandling(id+" route "+routeID, handling); err != nil {
					t.Fatal(err)
				}
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
		"chutes-qwen3.6-27b",
		RouteChat,
	)
	if !ok || !standard.DataHandling.TEE || standard.DataHandling.TEEVerified {
		t.Fatalf("unexpected Chutes TEE status: %#v", standard.DataHandling)
	}
}

func TestDeploymentDataHandlingIsMaterializedForTheSelectedRoute(t *testing.T) {
	var whole map[string]any
	if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
		t.Fatal(err)
	}
	graph := whole["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["azure-gpt-5.6-sol"].(map[string]any)
	routes := deployment["routes"].(map[string]any)
	routes["azure-chat-completions"].(map[string]any)["dataHandling"].(map[string]any)["storageLocation"] = "US"
	routes["azure-responses"].(map[string]any)["dataHandling"].(map[string]any)["storageLocation"] = "eu"
	data, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshotFromCatalogBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	chat, ok := snap.deploymentFromCompiledAt(
		"azure-gpt-5.6-sol",
		snap.graph.Routes["azure-chat-completions"],
		time.Now(),
	)
	if !ok || chat.DataHandling.StorageLocation != "US" {
		t.Fatalf("chat route handling = %#v", chat.DataHandling)
	}
	responses, ok := snap.deploymentFromCompiledAt(
		"azure-gpt-5.6-sol",
		snap.graph.Routes["azure-responses"],
		time.Now(),
	)
	if !ok || responses.DataHandling.StorageLocation != "eu" {
		t.Fatalf("responses route handling = %#v", responses.DataHandling)
	}
}

func TestSnapshotValidationRejectsBrokenReferences(t *testing.T) {
	var whole map[string]any
	if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
		t.Fatal(err)
	}
	graph := whole["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["openai-gpt-5.5-2026-04-23"].(map[string]any)
	routes := deployment["routes"].(map[string]any)
	routes["missing-route"] = routes["openai-responses"]
	delete(routes, "openai-responses")
	broken, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "unknown route") {
		t.Fatalf("broken route reference was accepted: %v", err)
	}
}

// Bedrock's geographies are its inference profiles: Claude Platform on AWS takes only Anthropic's
// global and us, and a profile's ID names its geography.
func TestSnapshotValidationKeepsBedrockGeographiesToTheirProfiles(t *testing.T) {
	for _, test := range []struct{ deployment, geo, model, want string }{
		{"aws-claude-haiku-5-5-eu", "fr", "fr.anthropic.claude-haiku-5-5", "invalid aws upstream selector"},
		{"aws-claude-fable-5-1-anthropic-hosted", "eu", "claude-fable-5-1", "invalid aws upstream selector"},
		{"aws-claude-haiku-5-5-eu", "eu", "us.anthropic.claude-haiku-5-5", "must name the eu inference profile"},
		{"aws-claude-haiku-5-5-ca", "jp", "ca.anthropic.claude-haiku-5-5", "must name the jp inference profile"},
	} {
		var whole map[string]any
		if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
			t.Fatal(err)
		}
		deployment := whole["graph"].(map[string]any)["deployments"].(map[string]any)[test.deployment].(map[string]any)
		upstream := deployment["upstream"].(map[string]any)
		upstream["inferenceGeo"], upstream["model"] = test.geo, test.model
		data, err := json.Marshal(whole)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := snapshotFromCatalogBytes(data); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s with %s and %s: got %v, want %q", test.deployment, test.geo, test.model, err, test.want)
		}
	}
}

func TestSnapshotValidationRequiresBoundedInputCeiling(t *testing.T) {
	for _, limit := range []any{nil, 0, -1, 1050001} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			deployment := whole["graph"].(map[string]any)["deployments"].(map[string]any)["openai-gpt-5.6-sol"].(map[string]any)
			if limit == nil {
				delete(deployment, "maxInputTokens")
			} else {
				deployment["maxInputTokens"] = limit
			}
			data, err := json.Marshal(whole)
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
		var whole compiledCatalog
		if err := decodeStrict(testCatalogJSON, &whole, sharedJSON[Pricing]()); err != nil {
			t.Fatal(err)
		}
		route := whole.Graph.Deployments["openai-gpt-5.5-2026-04-23"].Routes["openai-responses"]
		route.ChainHash = hash
		whole.Graph.Deployments["openai-gpt-5.5-2026-04-23"].Routes["openai-responses"] = route
		if err := validateCompiledGraph(whole.Graph); err == nil {
			t.Fatalf("invalid historical chain was accepted: %q", hash)
		}
	}
}

func TestSnapshotValidationBoundsExplicitAliases(t *testing.T) {
	var whole map[string]any
	if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
		t.Fatal(err)
	}
	graph := whole["graph"].(map[string]any)
	models := graph["models"].(map[string]any)
	model := models["claude-haiku-4-5"].(map[string]any)
	aliases := make([]any, maxAliasesPerNode+1)
	for index := range aliases {
		aliases[index] = fmt.Sprintf("bounded-alias-%d", index)
	}
	model["aliases"] = aliases
	broken, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "too many aliases") {
		t.Fatalf("catalog with an unbounded alias list was accepted: %v", err)
	}
}

// One spelling names one node: IDs and aliases that match under the model field's normalization
// must belong to the same node, while a model's own dot alias stays allowed.
func TestSnapshotValidationRefusesSelectorsThatCollideWhenNormalized(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(graph map[string]any)
		// The owners of the colliding spellings, which the error names in either order.
		owners []string
	}{
		{"a model alias spells another model", func(graph map[string]any) {
			graph["models"].(map[string]any)["claude-haiku-4-5"].(map[string]any)["aliases"] = []any{"claude-opus-4.8"}
		}, []string{"model:claude-haiku-4-5", "model:claude-opus-4-8"}},
		{"a group spells a deployment", func(graph map[string]any) {
			model := graph["models"].(map[string]any)["claude-haiku-4-5"].(map[string]any)
			model["groupIds"] = append(model["groupIds"].([]any), "OpenAI_GPT_5.6_Sol")
		}, []string{"group:OpenAI_GPT_5.6_Sol", "deployment:openai-gpt-5.6-sol"}},
		{"a provider alias spells another provider", func(graph map[string]any) {
			graph["providers"].(map[string]any)["openai"].(map[string]any)["aliases"] = []any{"Google_Cloud"}
		}, []string{"openai", "google-cloud"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			test.edit(whole["graph"].(map[string]any))
			broken, err := json.Marshal(whole)
			if err != nil {
				t.Fatal(err)
			}
			_, err = snapshotFromCatalogBytes(broken)
			if err == nil || !strings.Contains(err.Error(), "is shared by") ||
				!strings.Contains(err.Error(), test.owners[0]) || !strings.Contains(err.Error(), test.owners[1]) {
				t.Fatalf("got %v, want a selector shared by %v", err, test.owners)
			}
		})
	}
	var whole map[string]any
	if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
		t.Fatal(err)
	}
	whole["graph"].(map[string]any)["models"].(map[string]any)["claude-haiku-4-5"].(map[string]any)["aliases"] = []any{"claude-haiku-4.5"}
	own, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(own); err != nil {
		t.Fatalf("a model's own spellings were refused: %v", err)
	}
}

func TestSnapshotValidationAllowsDistinctSignedAzureModelSelectors(t *testing.T) {
	var whole map[string]any
	if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
		t.Fatal(err)
	}
	graph := whole["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["azure-deepseek-v4-pro"].(map[string]any)
	upstream := deployment["upstream"].(map[string]any)
	upstream["model"] = "reviewed-provider-selector"
	broken, err := json.Marshal(whole)
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
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			deployment := whole["graph"].(map[string]any)["deployments"].(map[string]any)["openai-gpt-5.5-2026-04-23"].(map[string]any)
			route := deployment["routes"].(map[string]any)["openai-responses"].(map[string]any)
			route["pricing"].(map[string]any)[billing.MeterOutputTokens] = map[string]any{billing.RatePerMillionTokens: rate}
			data, err := json.Marshal(whole)
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
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			deployment := whole["graph"].(map[string]any)["deployments"].(map[string]any)["openai-gpt-5.5-2026-04-23"].(map[string]any)
			test.apply(deployment["routes"].(map[string]any)["openai-responses"].(map[string]any))
			broken, err := json.Marshal(whole)
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
	var whole map[string]any
	if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
		t.Fatal(err)
	}
	graph := whole["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["chutes-qwen3.6-27b"].(map[string]any)
	dataHandling := deployment["routes"].(map[string]any)["chutes-chat-completions"].(map[string]any)["dataHandling"].(map[string]any)
	dataHandling["tee"] = false
	dataHandling["teeVerified"] = true
	broken, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "verifies a TEE that is not enabled") {
		t.Fatalf("catalog with impossible TEE verification was accepted: %v", err)
	}
}

func TestSnapshotValidationRejectsReasoningThatWeakensTheModel(t *testing.T) {
	var whole map[string]any
	if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
		t.Fatal(err)
	}
	graph := whole["graph"].(map[string]any)
	deployments := graph["deployments"].(map[string]any)
	deployment := deployments["chutes-kimi-k3"].(map[string]any)
	deployment["reasoning"] = "unsupported"
	for _, route := range deployment["routes"].(map[string]any) {
		route.(map[string]any)["reasoningEfforts"] = []any{}
	}
	broken, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "weakens required model reasoning") {
		t.Fatalf("catalog that weakens required model reasoning was accepted: %v", err)
	}
}

func TestSnapshotValidationRejectsRoutesWithoutCompiledTransportContracts(t *testing.T) {
	var whole map[string]any
	if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
		t.Fatal(err)
	}
	graph := whole["graph"].(map[string]any)
	routes := graph["routes"].(map[string]any)
	routes["openai-uncompiled"] = map[string]any{
		"interfaces": []any{"responses"},
		"providerId": "openai",
	}
	broken, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "not a compiled gateway transport contract") {
		t.Fatalf("uncompiled route was accepted: %v", err)
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
	snap := testSnapshot(t)
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
	const vocabulary = "outside the policy vocabulary"
	for _, tc := range []struct {
		name  string
		apply func(graph map[string]any)
		want  string
	}{
		{"hosting", func(g map[string]any) { upstream(g)["hosting"] = "Azure" }, vocabulary},
		{"deployment type", func(g map[string]any) { upstream(g)["deploymentType"] = "GlobalStandard" }, vocabulary},
		{"weight precision", func(g map[string]any) { deployment(g)["weightPrecision"] = "fp7" }, vocabulary},
		// Locations are the catalog's places, which name the European Union eu.
		{"processing location", func(g map[string]any) {
			deploymentRoute(g)["dataHandling"].(map[string]any)["processingLocation"] = "EU"
		}, "names a location that the catalog does not list"},
		{"extension", func(g map[string]any) {
			g["routes"].(map[string]any)["azure-chat-completions"].(map[string]any)["documentFormats"] = map[string]any{
				"extensions": []any{"pdf"}, "mediaTypes": []any{"application/pdf"}}
		}, vocabulary},
		{"country", func(g map[string]any) {
			g["authors"].(map[string]any)["openai"].(map[string]any)["headquarteredCountry"] = "USA"
		}, "not a country of the catalog"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			tc.apply(whole["graph"].(map[string]any))
			raw, err := json.Marshal(whole)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
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
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			tc.apply(whole["graph"].(map[string]any)["routes"].(map[string]any)["openai-responses"].(map[string]any))
			raw, err := json.Marshal(whole)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(raw); err == nil {
				t.Fatal("invalid document formats accepted")
			}
		})
	}
}
