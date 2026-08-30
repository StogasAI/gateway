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
)

func snapshotFromCatalogBytes(data []byte) (*snapshot, error) {
	return snapshotFromRelease(data, nil, Identity{})
}

func testDeploymentForRoute(provider schemas.ModelProvider, model string, route Route) (Deployment, bool) {
	return DeploymentForRouteServiceTier(provider, model, route, nil)
}

func TestClientHeaderCatalogPublishesBoundedPassThroughPool(t *testing.T) {
	for _, header := range []string{
		"x-stogas-upstream-anthropic-api-key",
		"x-stogas-upstream-chutes-api-key",
		"x-stogas-upstream-openai-api-key",
	} {
		if !strings.Contains(allClientHeadersValue, header) {
			t.Fatalf("client header catalog omitted %q", header)
		}
	}
	for _, legacy := range []string{
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
		len(snap.graph.Models) != 36 ||
		len(snap.graph.Providers) != 4 ||
		len(snap.graph.Routes) != 7 ||
		len(snap.graph.Deployments) != 114 {
		t.Fatalf("unexpected catalog graph sizes: authors=%d models=%d providers=%d routes=%d deployments=%d",
			len(snap.graph.Authors),
			len(snap.graph.Models),
			len(snap.graph.Providers),
			len(snap.graph.Routes),
			len(snap.graph.Deployments),
		)
	}
	if _, exists := snap.graph.Deployments["openai-gpt-4o-search-preview-2025-03-11"]; !exists {
		t.Fatal("historical search preview deployment must remain reproducible")
	}
	euDeployment := snap.graph.Deployments["azure-gpt-5.6-sol-eu"]
	for routeID, handling := range euDeployment.DataHandlingByRoute {
		if handling.ProcessingLocation != "europe" || handling.StorageLocation != "europe" {
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

	if len(snap.graph.Models) != 36 {
		t.Fatalf("runtime catalog unexpectedly contains informational-only models: %d", len(snap.graph.Models))
	}
}

func TestSnapshotValidationRejectsInvalidAzureFormatHostingAndInstantCombinations(t *testing.T) {
	mutate := func(t *testing.T, deploymentID string, apply func(map[string]any)) []byte {
		t.Helper()
		var runtime map[string]any
		if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
			t.Fatal(err)
		}
		deployment := runtime["graph"].(map[string]any)["deployments"].(map[string]any)[deploymentID].(map[string]any)
		apply(deployment["upstream"].(map[string]any))
		data, err := json.Marshal(runtime)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	for _, test := range []struct {
		name         string
		deploymentID string
		apply        func(map[string]any)
	}{
		{
			name:         "format hosting mismatch",
			deploymentID: "azure-gpt-5.6-sol",
			apply:        func(upstream map[string]any) { upstream["hosting"] = "nvidia" },
		},
		{
			name:         "instant non-default tier",
			deploymentID: "azure-gpt-5.6-sol-instant",
			apply:        func(upstream map[string]any) { upstream["serviceTier"] = "priority" },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := snapshotFromCatalogBytes(mutate(t, test.deploymentID, test.apply)); err == nil {
				t.Fatal("invalid Azure selector was accepted")
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
	uncached := deployments["azure-gpt-oss-120b"].(map[string]any)
	if _, present := uncached["pricing"].(map[string]any)[billing.MeterCachedInputTokens]; present {
		t.Fatal("test fixture unexpectedly has a cached-input price")
	}
	if _, err := snapshotFromCatalogBytes(embeddedRuntimeCatalogJSON); err != nil {
		t.Fatalf("uncached deployment was rejected: %v", err)
	}

	cached := deployments["azure-gpt-5.6-sol"].(map[string]any)
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
			if _, ok := testDeploymentForRoute(schemas.OpenAI, deploymentID, RouteChat); ok {
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
	snap := active.Load()
	if snap == nil {
		t.Fatal("catalog is not loaded")
	}
	for _, requested := range []string{
		"gpt-5.5",
		"openai/gpt-5.5",
		"openai/openai/gpt-5.5",
		"open-ai/gpt-5.5",
		"open-ai/open-ai/gpt-5.5",
	} {
		providers := snap.routeModelProviders(RouteResponses, requested, nil)
		if len(providers) != 1 || providers[0] != schemas.OpenAI {
			t.Fatalf("%s: providers=%v", requested, providers)
		}
	}
	for _, requested := range []string{
		"anthropic/gpt-5.5",
		"anthropic/openai/gpt-5.5",
		"open_ai/gpt-5.5",
		"openai/openai/openai/gpt-5.5",
		"gpt-5.5-latest",
	} {
		if providers := snap.routeModelProviders(RouteResponses, requested, nil); len(providers) != 0 {
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

func TestSharedModelDefaultsToItsAuthorAndAllowsExplicitAzureRouting(t *testing.T) {
	loadTestCatalog(t)
	for _, route := range []Route{RouteChat, RouteResponses} {
		path := "/v1/responses"
		body := `{"model":"gpt-5.6-sol","input":"hello","provider":{"only":["azure"]}}`
		if route == RouteChat {
			path = "/v1/chat/completions"
			body = `{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"provider":{"only":["azure"]}}`
		}
		resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: []byte(body)})
		if err != nil || resolution.Provider != schemas.Azure {
			t.Fatalf("provider preference must select Azure: resolution=%#v err=%v", resolution, err)
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
		{selector: "gpt-5.6-sol", provider: schemas.OpenAI, deployment: "openai-gpt-5.6-sol"},
		{selector: "azure/gpt-5.6-sol", provider: schemas.Azure, deployment: "azure-gpt-5.6-sol"},
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
		body := `{"model":"gpt-5.6-sol","input":"hello","service_tier":"flex"}`
		if path == "/v1/chat/completions" {
			body = `{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"service_tier":"flex"}`
		}
		resolution, err := ResolveRequest(RequestInput{Method: "POST", Path: path, Body: []byte(body)})
		if err != nil {
			t.Fatalf("%s Flex request: %v", path, err)
		}
		if resolution.Provider != schemas.OpenAI || resolution.Deployment.ID != "openai-gpt-5.6-sol-flex" {
			t.Fatalf("%s Flex resolution = %s/%s", path, resolution.Provider, resolution.Deployment.ID)
		}
	}

	ordered, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.6-sol","input":"hello","service_tier":"flex","provider":{"order":["azure","openai"]}}`),
	})
	if err != nil || ordered.Provider != schemas.OpenAI {
		t.Fatalf("incompatible preferred provider was selected: resolution=%#v err=%v", ordered, err)
	}

	if _, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.6-sol","input":"hello","service_tier":"flex","provider":{"only":["azure"]}}`),
	}); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("strict provider rule error = %v, want unavailable model", err)
	}
}

func TestFailedPreferredProviderDoesNotHideRemainingAmbiguity(t *testing.T) {
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

	for _, providerRule := range []string{"", `,"provider":{"order":["openai"]}`} {
		_, err := ResolveRequest(RequestInput{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":2` + providerRule + `}`),
		})
		if err == nil || !strings.Contains(err.Error(), "azure/gpt-5.6-sol") ||
			!strings.Contains(err.Error(), "chutes/gpt-5.6-sol") {
			t.Fatalf("failed preferred provider error = %v, want both remaining selectors", err)
		}
	}

	resolution, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":2,"provider":{"order":["openai","azure"]}}`),
	})
	if err != nil || resolution.Provider != schemas.Azure {
		t.Fatalf("next compatible ordered provider = %#v, err = %v", resolution, err)
	}
}

func TestUltrafastRequiresACatalogedPrice(t *testing.T) {
	loadTestCatalog(t)
	_, err := ResolveRequest(RequestInput{
		Method: "POST",
		Path:   "/v1/responses",
		Body:   []byte(`{"model":"gpt-5.6-sol","input":"hello","service_tier":"ultrafast"}`),
	})
	if err == nil || !strings.Contains(err.Error(), "service_tier") {
		t.Fatalf("uncataloged Ultrafast error = %v", err)
	}
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
				resolution.Deployment.Upstream.ServiceTier != "priority" ||
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
			t.Fatalf("resolve Azure Pro Priority alias: %v", err)
		}
		if resolution.Deployment.ID != proPriorityID ||
			resolution.Deployment.Upstream.ReasoningMode != "pro" ||
			resolution.Deployment.Upstream.ServiceTier != "priority" {
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

		actualTier := schemas.BifrostServiceTierDefault
		actual, ok := DeploymentForActualExecution(
			schemas.Azure,
			RouteResponses,
			resolution.Deployment,
			&actualTier,
			"",
		)
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

func TestAzureClaudeUsesNativeRouteAndManualReasoningBudget(t *testing.T) {
	loadTestCatalog(t)
	for _, input := range []RequestInput{
		{
			Method: "POST",
			Path:   "/v1/chat/completions",
			Body:   []byte(`{"model":"azure/claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":8192,"reasoning":{"max_tokens":4096}}`),
		},
		{
			Method: "POST",
			Path:   "/v1/responses",
			Body:   []byte(`{"model":"azure/claude-sonnet-4-6","input":"hello","max_output_tokens":8192,"reasoning":{"max_tokens":4096}}`),
		},
	} {
		resolution, err := ResolveRequest(input)
		if err != nil {
			t.Fatalf("resolve Azure Claude request: %v", err)
		}
		if resolution.Provider != schemas.Azure || resolution.Deployment.ID != "azure-claude-sonnet-4-6" ||
			len(resolution.Deployment.RouteIDs) != 1 || resolution.Deployment.RouteIDs[0] != "azure-anthropic-messages" ||
			resolution.Deployment.ReasoningMaxTokens == nil || resolution.Deployment.ReasoningMaxTokens.Minimum != 1024 ||
			resolution.Deployment.ReasoningMaxTokens.Maximum != 127999 {
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

func TestDeploymentFactsSelectTierRegionAndSpeedExplicitly(t *testing.T) {
	loadTestCatalog(t)
	flex, ok := testDeploymentForRoute(schemas.OpenAI, "openai-gpt-5.5-2026-04-23-flex", RouteResponses)
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
	if retired, retiredOK := testDeploymentForRoute(
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
	fastUS, ok := testDeploymentForRoute(
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

func TestPublicCatalogPreservesPolicyOwnership(t *testing.T) {
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
	var providers map[string]struct {
		DataHandling map[string]any            `json:"dataHandling"`
		Moderated    bool                      `json:"moderated"`
		Pricing      map[string]map[string]any `json:"pricing"`
	}
	if err := json.Unmarshal(payload.Graph["providers"], &providers); err != nil {
		t.Fatalf("decode public providers: %v", err)
	}
	for id, provider := range providers {
		_, hasTEE := provider.DataHandling["tee"]
		_, hasTEEVerification := provider.DataHandling["teeVerified"]
		if provider.DataHandling["processingLocation"] == nil ||
			provider.DataHandling["storageLocation"] == nil ||
			provider.DataHandling["endToEndEncrypted"] != nil || !hasTEE || !hasTEEVerification {
			t.Fatalf("%s provider data handling is incomplete: %#v", id, provider.DataHandling)
		}
	}
	if providers["anthropic"].Pricing[meterAnthropicWebSearchCalls][billing.RatePerThousandCalls] == nil {
		t.Fatalf("Anthropic provider-wide web-search pricing is absent: %#v", providers["anthropic"].Pricing)
	}
	var routes map[string]map[string]any
	if err := json.Unmarshal(payload.Graph["routes"], &routes); err != nil {
		t.Fatalf("decode public routes: %v", err)
	}
	if handling, ok := routes["anthropic-messages"]["dataHandling"].(map[string]any); !ok ||
		handling["endToEndEncrypted"] == nil ||
		handling["processingLocation"] != nil || handling["storageLocation"] != nil {
		t.Fatalf("Anthropic route transport handling is incomplete: %#v", handling)
	}
	if _, misplaced := routes["anthropic-messages"]["pricing"]; misplaced {
		t.Fatal("Anthropic route owns provider-wide pricing")
	}
	var deployments map[string]map[string]any
	if err := json.Unmarshal(payload.Graph["deployments"], &deployments); err != nil {
		t.Fatalf("decode public deployments: %v", err)
	}
	if _, duplicated := deployments["chutes-qwen3-32b"]["dataHandling"]; duplicated {
		t.Fatal("Chutes deployment duplicates provider data handling")
	}
	if _, duplicated := deployments["chutes-qwen3-32b"]["moderated"]; duplicated {
		t.Fatal("Chutes deployment duplicates provider moderation")
	}
}

func TestPricingIsMaterializedOnDeployments(t *testing.T) {
	loadTestCatalog(t)
	deployment, ok := testDeploymentForRoute(schemas.OpenAI, "gpt-5.5", RouteResponses)
	if !ok {
		t.Fatal("gpt-5.5 deployment unavailable")
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
	byRoute := deployment["dataHandlingByRoute"].(map[string]any)
	byRoute["azure-chat-completions"].(map[string]any)["storageLocation"] = "US"
	byRoute["azure-responses"].(map[string]any)["storageLocation"] = "eu"
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

	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	graph = runtime["graph"].(map[string]any)
	deployments = graph["deployments"].(map[string]any)
	deployment = deployments["openai-gpt-5.6-sol"].(map[string]any)
	deployment["routeOverrides"] = map[string]any{
		"openai-responses": map[string]any{
			"reasoningEfforts": []any{"low", "medium", "high", "xhigh", "max"},
		},
	}
	broken, err = json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromCatalogBytes(broken); err == nil ||
		!strings.Contains(err.Error(), "redundantly repeats") {
		t.Fatalf("catalog with redundant route reasoning efforts was accepted: %v", err)
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
	dataHandling := deployment["dataHandlingByRoute"].(map[string]any)["chutes-chat-completions"].(map[string]any)
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

func TestCanonicalDataLocationContainment(t *testing.T) {
	tests := map[string]struct {
		actual   string
		boundary string
		allowed  bool
	}{
		"exact country":            {actual: "US", boundary: "US", allowed: true},
		"country outside country":  {actual: "CA", boundary: "US", allowed: false},
		"EU country":               {actual: "SE", boundary: "eu", allowed: true},
		"non-EU European country":  {actual: "CH", boundary: "eu", allowed: false},
		"European country":         {actual: "CH", boundary: "europe", allowed: true},
		"EU within Europe":         {actual: "eu", boundary: "europe", allowed: true},
		"APAC country":             {actual: "JP", boundary: "apac", allowed: true},
		"country outside APAC":     {actual: "US", boundary: "apac", allowed: false},
		"global boundary":          {actual: "US", boundary: "global", allowed: true},
		"unknown boundary":         {actual: "unknown", boundary: "unknown", allowed: true},
		"unknown actual is not EU": {actual: "unknown", boundary: "eu", allowed: false},
		"invalid country":          {actual: "ZZ", boundary: "global", allowed: false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := DataLocationWithin(test.actual, test.boundary); got != test.allowed {
				t.Fatalf("DataLocationWithin(%q, %q) = %v, want %v", test.actual, test.boundary, got, test.allowed)
			}
		})
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
