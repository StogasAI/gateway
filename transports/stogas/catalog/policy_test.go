package catalog

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

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

func resolvePolicyChat(t *testing.T, config *policy.Config, extra string) ([]*ResolvedRequest, error) {
	t.Helper()
	return ResolveRequests(RequestInput{
		Body:   policyChatBody(extra),
		Method: "POST",
		Path:   "/v1/chat/completions",
		Policy: config,
	})
}

func TestRoutingPolicyExpandsOnlyBoundedPreDispatchCandidates(t *testing.T) {
	loadTestCatalog(t)

	withoutPolicy, err := ResolveRequest(RequestInput{
		Body:   policyChatBody(""),
		Method: "POST",
		Path:   "/v1/chat/completions",
	})
	if err != nil {
		t.Fatal(err)
	}
	if withoutPolicy.Provider != schemas.OpenAI {
		t.Fatalf("native provider = %q, want openai", withoutPolicy.Provider)
	}

	two, err := resolvePolicyChat(t, policyConfig(2), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(two) != 2 || two[0].Provider != schemas.OpenAI || two[1].Provider != schemas.Azure {
		t.Fatalf("default candidates = %#v", providerIDs(two))
	}

	one, err := resolvePolicyChat(t, policyConfig(1), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].Provider != schemas.OpenAI {
		t.Fatalf("bounded candidates = %#v", providerIDs(one))
	}

	ordered, err := resolvePolicyChat(t, policyConfig(2), `,"provider":{"order":["azure","openai"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 2 || ordered[0].Provider != schemas.Azure || ordered[1].Provider != schemas.OpenAI {
		t.Fatalf("client-ordered candidates = %#v", providerIDs(ordered))
	}
}

func TestRoutingPolicyIntersectsClientAndEveryCatalogNodeRestriction(t *testing.T) {
	loadTestCatalog(t)
	base, err := ResolveRequest(RequestInput{
		Body:   policyChatBody(""),
		Method: "POST",
		Path:   "/v1/chat/completions",
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
			config.Routing.AllowedCatalogNodes = test.allowed(test.value)
			resolved, err := resolvePolicyChat(t, config, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(resolved) == 0 {
				t.Fatalf("matching restriction resolved %#v", providerIDs(resolved))
			}
			for _, candidate := range resolved {
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
	if _, err := resolvePolicyChat(t, config, `,"provider":"azure"`); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("client/policy intersection error = %v, want ErrModelUnavailable", err)
	}
}

func TestRoutingQueryFiltersAndDeterministicallySortsCandidates(t *testing.T) {
	loadTestCatalog(t)
	stable := policy.Sort{Direction: "asc", Path: "deployment.id", Type: "string"}
	providerLiteral := func(value string) json.RawMessage {
		return json.RawMessage(`{"type":"string","value":"` + value + `"}`)
	}

	filter := policyConfig(2)
	filter.Routing.Query = &policy.Query{
		Where: &policy.Expression{
			Kind:     "compare",
			Left:     &policy.Field{Path: "provider.id", Type: "string"},
			Operator: "==",
			Right:    providerLiteral("azure"),
		},
	}
	resolved, err := resolvePolicyChat(t, filter, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[0].Provider != schemas.Azure || resolved[1].Provider != schemas.Azure || resolved[0].Deployment.ID == resolved[1].Deployment.ID {
		t.Fatalf("filtered candidates = %#v", providerIDs(resolved))
	}

	preserveClientOrder := policyConfig(2)
	preserveClientOrder.Routing.Query = &policy.Query{
		Where: &policy.Expression{
			Kind: "exists",
			Path: "deployment.id",
		},
	}
	resolved, err = resolvePolicyChat(t, preserveClientOrder, `,"provider":{"order":["azure","openai"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[0].Provider != schemas.Azure || resolved[1].Provider != schemas.OpenAI {
		t.Fatalf("filter-only policy changed client order: %#v", providerIDs(resolved))
	}

	sorted := policyConfig(2)
	sorted.Routing.Query = &policy.Query{OrderBy: []policy.Sort{
		{Direction: "desc", Path: "provider.id", Type: "string"},
		stable,
	}}
	resolved, err = resolvePolicyChat(t, sorted, `,"provider":{"order":["azure","openai"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[0].Provider != schemas.OpenAI || resolved[1].Provider != schemas.Azure {
		t.Fatalf("policy-sorted candidates = %#v", providerIDs(resolved))
	}

	missing := policyConfig(2)
	missing.Routing.Query = &policy.Query{
		OrderBy: []policy.Sort{stable},
		Where: &policy.Expression{
			Kind:     "compare",
			Left:     &policy.Field{Path: "deployment.data.upstream.chuteId", Type: "string"},
			Operator: "!=",
			Right:    providerLiteral("none"),
		},
	}
	if _, err := resolvePolicyChat(t, missing, ""); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("missing-value comparison error = %v, want ErrModelUnavailable", err)
	}
}

func TestRoutingPolicyCanSelectACompatibleDeploymentVariant(t *testing.T) {
	loadTestCatalog(t)
	config := policyConfig(1)
	config.Routing.Query = &policy.Query{Where: &policy.Expression{
		Kind:     "compare",
		Left:     &policy.Field{Path: "deployment.id", Type: "string"},
		Operator: "==",
		Right:    json.RawMessage(`{"type":"string","value":"azure-gpt-5.6-sol-us"}`),
	}}
	resolved, err := resolvePolicyChat(t, config, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].Deployment.ID != "azure-gpt-5.6-sol-us" {
		t.Fatalf("selected deployment variant = %#v", providerIDs(resolved))
	}

	config.Routing.Query.Where.Right = json.RawMessage(
		`{"type":"string","value":"azure-gpt-5.6-sol-fast"}`,
	)
	if _, err := resolvePolicyChat(t, config, ""); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("default tier selected a priority deployment: %v", err)
	}
	priority, err := resolvePolicyChat(t, config, `,"service_tier":"priority"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(priority) != 1 || priority[0].Deployment.ID != "azure-gpt-5.6-sol-fast" {
		t.Fatalf("priority deployment variant = %#v", providerIDs(priority))
	}

	pinned, err := ResolveRequests(RequestInput{
		Body:   []byte(`{"model":"azure-gpt-5.6-sol-us","messages":[{"role":"user","content":"hello"}]}`),
		Method: "POST",
		Path:   "/v1/chat/completions",
		Policy: policyConfig(3),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned) != 1 || pinned[0].Deployment.ID != "azure-gpt-5.6-sol-us" {
		t.Fatalf("pinned deployment expanded to %#v", providerIDs(pinned))
	}
}

func TestResolvedPolicyValuesExposeTypedRegisteredCatalogAndRequestData(t *testing.T) {
	loadTestCatalog(t)
	resolution, err := ResolveRequest(RequestInput{
		Body:   policyChatBody(`,"max_completion_tokens":4096`),
		Method: "POST",
		Path:   "/v1/chat/completions",
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
		{path: "model.id", fieldType: "string", value: "gpt-5.6-sol"},
		{path: "provider.id", fieldType: "string", value: "openai"},
		{path: "request.model", fieldType: "string", value: "gpt-5.6-sol"},
		{path: "request.route", fieldType: "string", value: "chat-completions"},
		{path: "request.maximumOutputTokens", fieldType: "integer", value: "4096"},
		{path: "deployment.data.capabilities.streaming", fieldType: "boolean", value: "true"},
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

	aliases, exists := values.PolicyValue("model.data.aliases")
	if !exists || aliases.Type != "string_list" || len(aliases.Strings) == 0 {
		t.Fatalf("model aliases = %#v, %t", aliases, exists)
	}
	price, exists := values.PolicyValue("deployment.data.pricing.input_tokens.per_mill_context_lte_272k")
	if !exists || price.Type != "integer" || price.Integer == nil || price.Integer.Sign() <= 0 {
		t.Fatalf("input price = %#v, %t", price, exists)
	}
	estimatedInput, exists := values.PolicyValue("request.estimatedInputTokens")
	if !exists || estimatedInput.Type != "integer" || estimatedInput.Integer == nil || estimatedInput.Integer.Sign() <= 0 {
		t.Fatalf("estimated input tokens = %#v, %t", estimatedInput, exists)
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
	precision, exists := precisionValues.PolicyValue("deployment.data.weightPrecision")
	if !exists || precision.Type != "string" || precision.String != "nvfp4" {
		t.Fatalf("deployment precision = %#v, %t", precision, exists)
	}
	for _, path := range []string{"", "provider.__proto__", "deployment.data.pricing.unknown.per_mill_tokens"} {
		if value, exists := values.PolicyValue(path); exists {
			t.Errorf("unknown PolicyValue(%q) = %#v", path, value)
		}
	}
}

func providerIDs(resolved []*ResolvedRequest) []schemas.ModelProvider {
	providers := make([]schemas.ModelProvider, 0, len(resolved))
	for _, candidate := range resolved {
		providers = append(providers, candidate.Provider)
	}
	return providers
}
