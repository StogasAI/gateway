package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestRequestPoliciesAreConsumedForChatAndResponses(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			source, err := policy.CompileSource([]byte(`{"delegation":{"request":["routing.filter"]},"routing":{"fallbacks":{"maxPreDispatchCandidates":2}}}`))
			if err != nil {
				t.Fatal(err)
			}
			config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
			if err != nil {
				t.Fatal(err)
			}
			content := `"messages":[{"role":"user","content":"hello"}]`
			if path == "/v1/responses" {
				content = `"input":"hello"`
			}
			body := []byte(`{"model":"gpt-5.6-sol",` + content + `,"policy":{"routing":{"filter": "deployment.id == \"azure-gpt-5.6-sol\""}}}`)
			resolved, err := ResolveRequest(RequestInput{Body: body, Method: "POST", Path: path, Policy: config})
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range []*ResolvedRequest{resolved} {
				if candidate.Provider != schemas.Azure {
					t.Fatal("request filter was not applied")
				}
				if _, found := candidate.RawBody()["policy"]; found {
					t.Fatal("request policy reached the provider body")
				}
				upstream, err := candidate.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(upstream)
				if err != nil || bytes.Contains(raw, []byte("provider.id")) {
					t.Fatalf("request policy reached upstream: %v", err)
				}
			}
			config.RequestPermission = 0
			if _, err := ResolveRequest(RequestInput{Body: body, Method: "POST", Path: path, Policy: config}); err == nil {
				t.Fatal("denied request policy was accepted")
			}
			if err := json.Unmarshal([]byte(`["routing.filter"]`), &config.RequestPermission); err != nil {
				t.Fatal(err)
			}
			for _, invalid := range []string{
				`{"version":1,"version":1,"routing":{"filter": "has(provider.id)"}}`,
				`{"routing":{"filter": "request.model == \"�\""}}`,
			} {
				body := []byte(`{"model":"gpt-5.6-sol",` + content + `,"policy":` + invalid + `}`)
				if _, err := ResolveRequest(RequestInput{Body: body, Method: "POST", Path: path, Policy: config}); err == nil {
					t.Fatal("malformed raw policy was accepted")
				}
			}
		})
	}
}

func policyChatBody(extra string) []byte {
	return []byte(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]` + extra + `}`)
}

func policyConfig(maxCandidates int) *policy.Config {
	return &policy.Config{
		CompilerVersion: policy.CompilerVersion,
		Routing: policy.Routing{
			MaxPreDispatchCandidates: maxCandidates,
		},
		Schema: "stogas.key-config.compiled.v1",
	}
}

func resolvePolicyChat(t *testing.T, config *policy.Config, extra string) (*ResolvedRequest, error) {
	t.Helper()
	return ResolveRequest(RequestInput{
		Body:   policyChatBody(extra),
		Method: "POST",
		Path:   "/v1/chat/completions",
		Policy: config,
	})
}

func TestRoutingFallbacksRequireExplicitAllowanceAndFollowCandidateOrder(t *testing.T) {
	loadTestCatalog(t)
	unavailable := errors.New("local credential unavailable")
	for _, test := range []struct {
		name        string
		config      *policy.Config
		extra       string
		want        []schemas.ModelProvider
		failFirst   bool
		wantFailure bool
		ambiguous   bool
	}{
		{"no implicit provider order", nil, "", nil, false, false, true},
		{"explicit order without fallback", nil, `,"provider":{"order":["openai","azure"]}`, []schemas.ModelProvider{schemas.OpenAI}, false, false, false},
		{"default never falls back", nil, `,"provider":{"order":["openai","azure"]}`, []schemas.ModelProvider{schemas.OpenAI}, true, true, false},
		{"one candidate never falls back", policyConfig(1), `,"provider":{"order":["openai","azure"]}`, []schemas.ModelProvider{schemas.OpenAI}, true, true, false},
		{"allowance does not define order", policyConfig(2), "", nil, false, false, true},
		{"explicit fallback", policyConfig(2), `,"provider":{"order":["openai","azure"]}`, []schemas.ModelProvider{schemas.OpenAI, schemas.Azure}, true, false, false},
		{"client order", policyConfig(2), `,"provider":{"order":["azure","openai"]}`, []schemas.ModelProvider{schemas.Azure, schemas.OpenAI}, true, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var attempts []schemas.ModelProvider
			resolved, err := ResolveRequest(RequestInput{
				Body: policyChatBody(test.extra), Method: "POST", Path: "/v1/chat/completions", Policy: test.config,
				DeploymentEligible: func(_ schemas.ModelProvider, _ int, deployment Deployment) bool {
					return deployment.ID == "openai-gpt-5.6-sol" || deployment.ID == "azure-gpt-5.6-sol"
				},
				CheckCandidate: func(provider schemas.ModelProvider, _ int, _ Deployment) error {
					attempts = append(attempts, provider)
					if test.failFirst && len(attempts) == 1 {
						return unavailable
					}
					return nil
				},
			})
			if !reflect.DeepEqual(attempts, test.want) {
				t.Fatalf("attempts=%v want=%v", attempts, test.want)
			}
			if test.ambiguous {
				if PublicError(err).Code != "model_ambiguous" || resolved != nil {
					t.Fatalf("ambiguity=%v result=%v", err, resolved)
				}
			} else if test.wantFailure {
				if !errors.Is(err, unavailable) || resolved != nil {
					t.Fatalf("failure=%v result=%v", err, resolved)
				}
			} else if err != nil || resolved == nil || resolved.Provider != test.want[len(test.want)-1] {
				t.Fatalf("resolution=%v error=%v", resolved, err)
			}
		})
	}
}

func TestRoutingPolicyIntersectsClientAndEveryCatalogNodeRestriction(t *testing.T) {
	loadTestCatalog(t)
	base, err := ResolveRequest(RequestInput{
		Body:                 policyChatBody(""),
		AvailableCredentials: map[string][]int{"openai": {0}},
		Method:               "POST",
		Path:                 "/v1/chat/completions",
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := candidatePolicyIDs(base)
	if ids.author == "" || ids.model == "" || ids.deployment == "" || ids.route == "" || ids.provider == "" {
		t.Fatalf("incomplete policy chain: %#v", ids)
	}

	tests := []struct {
		name    string
		allowed func(string) *policy.AllowedCatalogNodes
		actual  func(policyIDs) string
		value   string
	}{
		{name: "author", value: ids.author, actual: func(ids policyIDs) string { return ids.author }, allowed: func(value string) *policy.AllowedCatalogNodes {
			return &policy.AllowedCatalogNodes{Authors: []string{value}}
		}},
		{name: "model", value: ids.model, actual: func(ids policyIDs) string { return ids.model }, allowed: func(value string) *policy.AllowedCatalogNodes {
			return &policy.AllowedCatalogNodes{Models: []string{value}}
		}},
		{name: "deployment", value: ids.deployment, actual: func(ids policyIDs) string { return ids.deployment }, allowed: func(value string) *policy.AllowedCatalogNodes {
			return &policy.AllowedCatalogNodes{Deployments: []string{value}}
		}},
		{name: "route", value: ids.route, actual: func(ids policyIDs) string { return ids.route }, allowed: func(value string) *policy.AllowedCatalogNodes {
			return &policy.AllowedCatalogNodes{Routes: []string{value}}
		}},
		{name: "provider", value: ids.provider, actual: func(ids policyIDs) string { return ids.provider }, allowed: func(value string) *policy.AllowedCatalogNodes {
			return &policy.AllowedCatalogNodes{Providers: []string{value}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := policyConfig(2)
			config.Routing.Query = mustRouting(t, "", []policy.Sort{{By: "deployment.id", Direction: "asc"}})
			config.Routing.AllowedCatalogNodes = test.allowed(test.value)
			resolved, err := resolvePolicyChat(t, config, "")
			if err != nil {
				t.Fatal(err)
			}
			if resolved == nil {
				t.Fatalf("matching restriction resolved %#v", resolved)
			}
			for _, candidate := range []*ResolvedRequest{resolved} {
				if actual := test.actual(candidatePolicyIDs(candidate)); actual != test.value {
					t.Fatalf("matching restriction retained %q, want %q", actual, test.value)
				}
			}

			config.Routing.AllowedCatalogNodes = test.allowed("not-a-real-node")
			if _, err := resolvePolicyChat(t, config, ""); !errors.Is(err, ErrModelUnavailable) {
				t.Fatalf("mismatched restriction error = %v, want ErrModelUnavailable", err)
			}
		})
	}

	config := policyConfig(2)
	config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Providers: []string{"openai"}}
	if _, err := resolvePolicyChat(t, config, `,"provider":"azure"`); !errors.Is(err, ErrProviderSelection) {
		t.Fatalf("client/policy intersection error = %v, want ErrProviderSelection", err)
	}
}

func TestAllowedCatalogNodesPrecedeServiceTierCompatibility(t *testing.T) {
	loadTestCatalog(t)
	config := policyConfig(2)
	config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Providers: []string{"azure"}}
	if _, err := resolvePolicyChat(t, config, `,"service_tier":"flex"`); !errors.Is(err, ErrUnsupportedServiceTier) {
		t.Fatalf("Azure-only Flex error = %v, want ErrUnsupportedServiceTier", err)
	}
	if _, err := resolvePolicyChat(t, config, `,"service_tier":"unknown"`); !errors.Is(err, ErrUnsupportedServiceTier) {
		t.Fatalf("unknown tier error = %v, want ErrUnsupportedServiceTier", err)
	}

	config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"openai-gpt-5.6-sol"}}
	if _, err := resolvePolicyChat(t, config, `,"service_tier":"flex"`); !errors.Is(err, ErrServiceTierUnavailable) {
		t.Fatalf("default-only deployment Flex error = %v, want ErrServiceTierUnavailable", err)
	}
	config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"openai-gpt-5.6-sol-flex"}}
	resolved, err := resolvePolicyChat(t, config, `,"service_tier":"flex"`)
	if err != nil || resolved == nil || resolved.Deployment.ID != "openai-gpt-5.6-sol-flex" {
		t.Fatalf("Flex-only deployment resolution = %#v, err = %v", resolved, err)
	}

	config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Providers: []string{"not-a-real-provider"}}
	if _, err := resolvePolicyChat(t, config, `,"service_tier":"flex"`); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("fully denied policy error = %v, want ErrModelUnavailable", err)
	}
}

func TestRoutingQueryFiltersAndDeterministicallySortsCandidates(t *testing.T) {
	loadTestCatalog(t)
	stable := policy.Sort{Direction: "asc", By: "deployment.id"}
	filter := policyConfig(2)
	filter.Routing.Query = mustRouting(t, `deployment.id == 'azure-gpt-5.6-sol'`, nil)
	resolved, err := resolvePolicyChat(t, filter, "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil || resolved.Provider != schemas.Azure {
		t.Fatalf("filtered candidates = %#v", resolved)
	}

	preserveClientOrder := policyConfig(2)
	preserveClientOrder.Routing.Query = mustRouting(t, `deployment.id in ['azure-gpt-5.6-sol', 'openai-gpt-5.6-sol']`, nil)
	resolved, err = resolvePolicyChat(t, preserveClientOrder, `,"provider":{"order":["azure","openai"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil || resolved.Provider != schemas.Azure {
		t.Fatalf("filter-only policy changed client order: %#v", resolved)
	}

	sorted := policyConfig(2)
	sorted.Routing.Query = mustRouting(t, "", []policy.Sort{{Direction: "desc", By: "provider.id"}, stable})
	resolved, err = resolvePolicyChat(t, sorted, `,"provider":{"order":["azure","openai"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil || resolved.Provider != schemas.OpenAI {
		t.Fatalf("policy-sorted candidates = %#v", resolved)
	}

	missing := policyConfig(2)
	missing.Routing.Query = mustRouting(t, `deployment.upstream.chuteId != 'none'`, []policy.Sort{stable})
	if _, err := resolvePolicyChat(t, missing, ""); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("missing-value comparison error = %v, want ErrModelUnavailable", err)
	}
}

func TestRoutingPolicyCanSelectACompatibleDeploymentVariant(t *testing.T) {
	loadTestCatalog(t)
	config := policyConfig(1)
	config.Routing.Query = mustRouting(t, `deployment.id == 'azure-gpt-5.6-sol-us'`, nil)
	resolved, err := resolvePolicyChat(t, config, "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil || resolved.Deployment.ID != "azure-gpt-5.6-sol-us" {
		t.Fatalf("selected deployment variant = %#v", resolved)
	}

	config.Routing.Query = mustRouting(t, `deployment.id == 'azure-gpt-5.6-sol-fast'`, nil)
	if _, err := resolvePolicyChat(t, config, ""); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("default tier selected a priority deployment: %v", err)
	}
	priority, err := resolvePolicyChat(t, config, `,"service_tier":"priority"`)
	if err != nil {
		t.Fatal(err)
	}
	if priority == nil || priority.Deployment.ID != "azure-gpt-5.6-sol-fast" {
		t.Fatalf("priority deployment variant = %#v", priority)
	}

	pinned, err := ResolveRequest(RequestInput{
		Body:   []byte(`{"model":"azure-gpt-5.6-sol-us","messages":[{"role":"user","content":"hello"}]}`),
		Method: "POST",
		Path:   "/v1/chat/completions",
		Policy: policyConfig(3),
	})
	if err != nil {
		t.Fatal(err)
	}
	if pinned == nil || pinned.Deployment.ID != "azure-gpt-5.6-sol-us" {
		t.Fatalf("pinned deployment expanded to %#v", pinned)
	}
}

func TestResolvedPolicyValuesExposeTypedRegisteredCatalogAndRequestData(t *testing.T) {
	loadTestCatalog(t)
	resolution, err := ResolveRequest(RequestInput{
		Body:                 policyChatBody(`,"max_completion_tokens":4096`),
		AvailableCredentials: map[string][]int{"openai": {0}},
		Method:               "POST",
		Path:                 "/v1/chat/completions",
	})
	if err != nil {
		t.Fatal(err)
	}
	values, ok := newResolvedPolicyValues(resolution)
	if !ok {
		t.Fatal("newResolvedPolicyValues() rejected a catalog-backed resolution")
	}

	tests := []struct {
		path      string
		fieldType string
		value     string
	}{
		{path: "author.id", fieldType: "string", value: "openai"},
		{path: "author.name", fieldType: "string", value: "OpenAI"},
		{path: "model.id", fieldType: "string", value: "gpt-5.6-sol"},
		{path: "model.name", fieldType: "string", value: "GPT-5.6 Sol"},
		{path: "deployment.id", fieldType: "string", value: "openai-gpt-5.6-sol"},
		{path: "provider.id", fieldType: "string", value: "openai"},
		{path: "provider.name", fieldType: "string", value: "OpenAI"},
		{path: "route.id", fieldType: "string", value: "openai-chat-completions"},
		{path: "route.providerId", fieldType: "string", value: "openai"},
		{path: "request.model", fieldType: "string", value: "gpt-5.6-sol"},
		{path: "request.route", fieldType: "string", value: "chat-completions"},
		{path: "deployment.capabilities.streaming", fieldType: "boolean", value: "true"},
	}
	for _, test := range tests {
		value, exists := values.PolicyValue(test.path)
		if !exists || value.Type != test.fieldType {
			t.Errorf("PolicyValue(%q) = %#v, %t", test.path, value, exists)
			continue
		}
		var actual string
		switch value.Type {
		case "string":
			actual = value.String
		case "integer":
			actual = value.Integer.String()
		case "boolean":
			actual = strconv.FormatBool(value.Boolean)
		}
		if test.fieldType == "boolean" {
			if value.Boolean != (test.value == "true") {
				t.Errorf("PolicyValue(%q).Boolean = %t", test.path, value.Boolean)
			}
		} else if actual != test.value {
			t.Errorf("PolicyValue(%q) = %q, want %q", test.path, actual, test.value)
		}
	}

	aliases, exists := values.PolicyValue("model.aliases")
	if !exists || aliases.Type != "string_list" || len(aliases.Strings) == 0 {
		t.Fatalf("model aliases = %#v, %t", aliases, exists)
	}
	price, exists := values.PolicyValue("deployment.pricing.input_tokens.per_mill_context_lte_272k")
	if !exists || price.Type != "decimal" || price.Decimal == nil || price.Decimal.Sign() <= 0 {
		t.Fatalf("input price = %#v, %t", price, exists)
	}
	blendedQuery, err := policy.CompileRouting(`blended_price(3, 1, "per_mill_context_lte_272k") > decimal("0") && !has(deployment.pricing.input_tokens.per_mill_tokens)`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if matches, err := blendedQuery.Matches(values); err != nil || !matches {
		t.Fatal("blended price did not read the resolved deployment's explicit tier")
	}
	for _, path := range []string{"request.estimatedInputTokens", "request.maximumOutputTokens"} {
		if _, exists := values.PolicyValue(path); exists {
			t.Fatalf("post-selection fact is available to routing: %s", path)
		}
	}
	precisionResolution, err := ResolveRequest(RequestInput{
		Body:   []byte(`{"model":"chutes-glm-5.2","messages":[{"role":"user","content":"hello"}]}`),
		Method: "POST",
		Path:   "/v1/chat/completions",
	})
	if err != nil {
		t.Fatal(err)
	}
	precisionValues, ok := newResolvedPolicyValues(precisionResolution)
	if !ok {
		t.Fatal("newResolvedPolicyValues() rejected a precision-tagged deployment")
	}
	precision, exists := precisionValues.PolicyValue("deployment.weightPrecision")
	if !exists || precision.Type != "string" || precision.String != "nvfp4" {
		t.Fatalf("deployment precision = %#v, %t", precision, exists)
	}
	for _, path := range []string{"", "provider.__proto__", "deployment.pricing.unknown.per_mill_tokens"} {
		if value, exists := values.PolicyValue(path); exists {
			t.Errorf("unknown PolicyValue(%q) = %#v", path, value)
		}
	}
}

func TestOmittedModelUsesRestrictedAndSortedCandidates(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			content := `"messages":[{"role":"user","content":"hello"}]`
			if path == "/v1/responses" {
				content = `"input":"hello"`
			}
			resolve := func(config *policy.Config, extra string) (*ResolvedRequest, error) {
				return ResolveRequest(RequestInput{Body: []byte(`{` + content + extra + `}`), Method: "POST", Path: path, Policy: config})
			}
			config := policyConfig(3)
			config.RequestPermission = 0
			config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Providers: []string{"openai"}}
			config.Routing.Query = mustRouting(t, "", []policy.Sort{{Direction: "desc", By: "deployment.id"}})
			candidates, err := resolve(config, "")
			if err != nil {
				t.Fatal(err)
			}
			if candidates.Provider != schemas.OpenAI || candidates.Deployment.ModelID == "" {
				t.Fatalf("unauthorized or unresolved selection: %#v", candidates.Deployment)
			}
			upstream, err := candidates.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
			if err != nil || upstream == nil {
				t.Fatalf("selected request cannot be sent upstream: %v", err)
			}
			selected := candidates.Deployment.ID
			config.Routing.Query = nil
			config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{selected}}
			single, err := resolve(config, "")
			if err != nil || single == nil || single.Deployment.ID != selected {
				t.Fatalf("single permitted deployment was not selected: %v", err)
			}
			for _, invalid := range []string{`null`, `""`, `" "`, `42`} {
				if _, err := resolve(config, `,"model":`+invalid); err == nil {
					t.Fatalf("invalid explicit model %s accepted", invalid)
				}
			}
			if _, err := resolve(config, `,"model":"missing-deployment"`); err == nil {
				t.Fatal("explicit selector was ignored")
			}
			config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{}}
			if _, err := resolve(config, ""); !errors.Is(err, ErrModelUnavailable) {
				t.Fatalf("empty allowed set: %v", err)
			}
			config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Providers: []string{"openai"}}
			if _, err := resolve(config, ""); err == nil {
				t.Fatal("multiple models without sorting were selected arbitrarily")
			}
		})
	}
}

func mustRouting(t *testing.T, filter string, order []policy.Sort) *policy.Query {
	t.Helper()
	query, err := policy.CompileRouting(filter, order)
	if err != nil {
		t.Fatal(err)
	}
	return query
}
