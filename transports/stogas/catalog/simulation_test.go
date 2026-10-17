package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestRoutingSimulationNamesWhatRemovedEachCandidate(t *testing.T) {
	loadTestCatalog(t)
	compose := func(documents ...string) *policy.Config {
		t.Helper()
		sources := make([]policy.ScopedSource, len(documents))
		for index, document := range documents {
			source, err := policy.CompileSource([]byte(document))
			if err != nil {
				t.Fatal(err)
			}
			sources[index] = policy.ScopedSource{Scope: []policy.Scope{policy.OrganizationScope, policy.KeyScope}[index], Value: source}
		}
		config, err := policy.ComposeSources(sources)
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	week := `[{"days":["mon","tue","wed","thu","fri","sat","sun"],"start":"00:00","end":"24:00","timeZone":"UTC"}]`
	shared := compose(`{"routing":{"filter":"provider.id == 'azure'"}}`)
	expired := APIError{StatusCode: 403, Type: ErrorTypeInvalidRequest, Code: "credential_expired", Message: "credential expired"}
	for _, test := range []struct {
		name               string
		route              Route
		model, tier        string
		credentials        map[string][]int
		base               *policy.Config
		credential         func(index int) (RequestPolicy, error)
		eligible           func(index int, deployment string) bool
		pairs, tried       int
		removed, ambiguous []string
		code               string
	}{
		{name: "every pair beyond the fallbacks", model: "gpt-5.6-sol", credentials: map[string][]int{"azure": {0}, "openai": {0}}, pairs: 6, tried: 3},
		{name: "another interface", route: RouteResponses, model: "gpt-oss-120b", credentials: map[string][]int{"azure": {0}},
			removed: []string{"interface azure"}, code: "model_unavailable"},
		{name: "a missing credential outranks another interface", model: "gpt-5.6-sol", credentials: map[string][]int{"openai": {0}},
			removed: []string{"no_credential azure"}, pairs: 1, tried: 1},
		{name: "exact deployment without a credential", model: "azure-gpt-5.6-sol-us", credentials: map[string][]int{"openai": {0}},
			removed: []string{"no_credential azure"}, code: "model_unavailable"},
		{name: "service tier", model: "gpt-5.6-luna", tier: "fast", credentials: map[string][]int{"azure": {0}, "openai": {0}},
			removed: []string{"service_tier azure"}, pairs: 1, tried: 1},
		{name: "approval and ambiguity", route: RouteResponses, model: "gpt-5.6", credentials: map[string][]int{"openai": {0}},
			removed: []string{"approval openai/openai-gpt-5.6-cyber", "no_credential azure"}, code: "model_ambiguous",
			ambiguous: []string{"gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra"}},
		{name: "older models of a group", model: "gpt-6", credentials: map[string][]int{"openai": {0}},
			removed: []string{"no_credential azure", "older_model openai/openai-gpt-6-astra", "older_model openai/openai-gpt-6-luna", "older_model openai/openai-gpt-6-sol"}, pairs: 1, tried: 1},
		{name: "allowed nodes of the key", model: "gpt-5.6-sol", credentials: map[string][]int{"azure": {0}, "openai": {0}},
			base: compose(`{}`, `{"routing":{"allowedCatalogNodes":{"deployments":["azure-gpt-5.6-sol-eu"]}}}`),
			removed: []string{
				"allowed_nodes azure/azure-gpt-5.6-sol @1", "allowed_nodes azure/azure-gpt-5.6-sol-apac @1", "allowed_nodes azure/azure-gpt-5.6-sol-instant @1",
				"allowed_nodes azure/azure-gpt-5.6-sol-us @1", "allowed_nodes openai/openai-gpt-5.6-sol @1",
			}, pairs: 1, tried: 1},
		{name: "credential targets", model: "gpt-5.6-sol", credentials: map[string][]int{"azure": {0, 1}},
			eligible: func(index int, deployment string) bool { return index == 1 || deployment == "azure-gpt-5.6-sol-us" },
			removed: []string{
				"credential_target azure/azure-gpt-5.6-sol#0", "credential_target azure/azure-gpt-5.6-sol-apac#0",
				"credential_target azure/azure-gpt-5.6-sol-eu#0", "credential_target azure/azure-gpt-5.6-sol-instant#0", "no_credential openai",
			}, pairs: 6, tried: 3},
		{name: "unusable credential", model: "openai-gpt-5.6-sol", credentials: map[string][]int{"openai": {0, 1}},
			credential: func(index int) (RequestPolicy, error) {
				if index == 0 {
					return RequestPolicy{}, expired
				}
				return RequestPolicy{Config: policyConfig(3)}, nil
			},
			removed: []string{"credential openai/openai-gpt-5.6-sol#0 credential_expired"}, pairs: 1, tried: 1},
		{name: "undecided condition", model: "gpt-5.6-sol", credentials: map[string][]int{"azure": {0}, "openai": {0}},
			base:    compose(`{"rules":{"typed":{"when":"deployment.upstream.deploymentType != ''","input":{"asciiOnly":true}}}}`),
			removed: []string{"condition openai/openai-gpt-5.6-sol#0 @0typed deployment.upstream.deploymentType != ''"}, pairs: 5, tried: 3},
		// A deny period comes before the filters that would also remove a pair.
		{name: "deny period of a rule", model: "gpt-5.6-sol", credentials: map[string][]int{"azure": {0}, "openai": {0}},
			base: compose(`{"routing":{"filter":"provider.id == 'openai'"}}`, `{"rules":{"closed":{"when":"provider.id == 'azure'","access":{"deny":`+week+`}}}}`),
			removed: []string{
				"deny azure/azure-gpt-5.6-sol#0 @1closed", "deny azure/azure-gpt-5.6-sol-apac#0 @1closed", "deny azure/azure-gpt-5.6-sol-eu#0 @1closed",
				"deny azure/azure-gpt-5.6-sol-instant#0 @1closed", "deny azure/azure-gpt-5.6-sol-us#0 @1closed",
			}, pairs: 1, tried: 1},
		{name: "deny period of the key", model: "openai-gpt-5.6-sol", credentials: map[string][]int{"openai": {0}},
			base:    compose(`{}`, `{"access":{"deny":`+week+`}}`),
			removed: []string{"deny openai/openai-gpt-5.6-sol#0 @1"}, code: "schedule_denied"},
		{name: "false and undecided filters", model: "gpt-5.6-sol", credentials: map[string][]int{"azure": {0}, "openai": {0}},
			base: compose(`{"routing":{"filter":"deployment.upstream.deploymentType == 'global_standard'"}}`),
			removed: []string{
				"filter azure/azure-gpt-5.6-sol-apac#0 @0 deployment.upstream.deploymentType == 'global_standard'",
				"filter azure/azure-gpt-5.6-sol-eu#0 @0 deployment.upstream.deploymentType == 'global_standard'",
				"filter azure/azure-gpt-5.6-sol-instant#0 @0 deployment.upstream.deploymentType == 'global_standard'",
				"filter azure/azure-gpt-5.6-sol-us#0 @0 deployment.upstream.deploymentType == 'global_standard'",
				"filter openai/openai-gpt-5.6-sol#0 @0 deployment.upstream.deploymentType == 'global_standard' unknown",
			}, pairs: 1, tried: 1},
		{name: "credentials beyond one policy's pairs", model: "openai-gpt-5.6-sol", credentials: map[string][]int{"openai": {0, 1, 2, 3}},
			removed: []string{"pair_limit openai/openai-gpt-5.6-sol#3"}, pairs: 3, tried: 3},
		{name: "credentials beyond a deployment's pairs", model: "openai-gpt-5.6-sol", credentials: map[string][]int{"openai": {0, 1, 2, 3, 4}},
			credential: func(int) (RequestPolicy, error) { return RequestPolicy{Config: policyConfig(3)}, nil },
			removed:    []string{"pair_limit openai/openai-gpt-5.6-sol#3", "pair_limit openai/openai-gpt-5.6-sol#4"}, pairs: 3, tried: 3},
		{name: "credentials share their policy's removal", model: "openai-gpt-5.6-sol", credentials: map[string][]int{"openai": {0, 1}},
			credential: func(int) (RequestPolicy, error) { return RequestPolicy{Config: shared}, nil },
			removed: []string{
				"filter openai/openai-gpt-5.6-sol#0 @0 provider.id == 'azure'",
				"filter openai/openai-gpt-5.6-sol#1 @0 provider.id == 'azure'",
			}, code: "model_unavailable"},
		{name: "any model", credentials: map[string][]int{"openai": {0}},
			removed: []string{"no_credential anthropic", "no_credential azure", "no_credential chutes"}, code: "model_ambiguous"},
	} {
		t.Run(test.name, func(t *testing.T) {
			route := RouteChat
			if test.route != "" {
				route = test.route
			}
			input := RequestInput{Policy: test.base, AvailableCredentials: test.credentials}
			if input.Policy == nil {
				input.Policy = policyConfig(3)
			}
			if test.credential != nil {
				input.CredentialPolicy = func(_ schemas.ModelProvider, index int) (RequestPolicy, error) { return test.credential(index) }
			}
			if test.eligible != nil {
				input.DeploymentEligible = func(_ schemas.ModelProvider, index int, deployment Deployment) bool {
					return test.eligible(index, deployment.ID)
				}
			}
			simulation := SimulateRouting(input, route, test.model, test.tier)
			got := describeRemovals(simulation.Removed)
			if !reflect.DeepEqual(got, test.removed) && (len(got) > 0 || len(test.removed) > 0) {
				t.Errorf("removed:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(test.removed, "\n"))
			}
			if code := PublicError(simulation.Err).Code; simulation.Err != nil && code != test.code || simulation.Err == nil && test.code != "" {
				t.Fatalf("error %v, want %s", simulation.Err, test.code)
			}
			if test.ambiguous != nil && !reflect.DeepEqual(simulation.Ambiguous, test.ambiguous) || test.code == "model_ambiguous" && len(simulation.Ambiguous) < 2 {
				t.Errorf("ambiguous models %v", simulation.Ambiguous)
			}
			if len(simulation.Pairs) != test.pairs || simulation.Tried != test.tried {
				t.Errorf("pairs %v, tried %d", describePairs(simulation.Pairs), simulation.Tried)
			}
			// A request tries the simulated pairs in order, or fails as simulated.
			attempts, err := requestAttempts(input, route, test.model, test.tier)
			if simulation.Err != nil {
				if PublicError(err).Code != test.code || len(attempts) != 0 {
					t.Fatalf("request attempts %v, error %v", attempts, err)
				}
				return
			}
			if want := describePairs(simulation.Pairs)[:simulation.Tried]; !reflect.DeepEqual(attempts, want) {
				t.Fatalf("request attempts %v, simulated %v", attempts, want)
			}
		})
	}
}

func TestRoutingSimulationLocatesOrderAndFallbacks(t *testing.T) {
	loadTestCatalog(t)
	org, err := policy.CompileSource([]byte(`{"routing":{"fallbacks":1},"rules":{"newest":{"mode":"default","routing":{"sort":[{"by":"deployment.id","direction":"desc"}]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: org}})
	if err != nil {
		t.Fatal(err)
	}
	input := RequestInput{Policy: config, AvailableCredentials: map[string][]int{"azure": {0}}}
	simulation := SimulateRouting(input, RouteChat, "gpt-5.6-sol", "")
	if simulation.Err != nil || simulation.Tried != 2 || simulation.Fallbacks != 1 ||
		simulation.Order == nil || *simulation.Order != (policy.Origin{Rule: "newest"}) ||
		simulation.FallbacksOrigin == nil || *simulation.FallbacksOrigin != (policy.Origin{}) {
		t.Fatalf("simulation %+v", simulation)
	}
	want := []string{"azure-gpt-5.6-sol-us#0", "azure-gpt-5.6-sol-instant#0", "azure-gpt-5.6-sol-eu#0", "azure-gpt-5.6-sol-apac#0", "azure-gpt-5.6-sol#0"}
	if got := describePairs(simulation.Pairs); !reflect.DeepEqual(got, want) {
		t.Fatalf("pairs %v", got)
	}
	attempts, _ := requestAttempts(input, RouteChat, "gpt-5.6-sol", "")
	if !reflect.DeepEqual(attempts, want[:2]) {
		t.Fatalf("request attempts %v", attempts)
	}
	if simulation := SimulateRouting(RequestInput{Policy: policyConfig(3), AvailableCredentials: input.AvailableCredentials}, RouteChat, "gpt-5.6-sol", ""); simulation.Order != nil || simulation.FallbacksOrigin != nil {
		t.Fatalf("default settings have origins: %+v", simulation)
	}
}

func TestRoutingSimulationBoundsItsRemovals(t *testing.T) {
	loadTestCatalog(t)
	source, err := policy.CompileSource([]byte(`{"routing":{"filter":"provider.id == 'none'"}}`))
	if err != nil {
		t.Fatal(err)
	}
	config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
	if err != nil {
		t.Fatal(err)
	}
	indexes := make([]int, 40)
	for index := range indexes {
		indexes[index] = index
	}
	credentials := map[string][]int{"anthropic": indexes, "azure": indexes, "chutes": indexes, "openai": indexes}
	simulation := SimulateRouting(RequestInput{Policy: config, AvailableCredentials: credentials}, RouteChat, "", "")
	if len(simulation.Removed) != maxRemovedCandidates || simulation.Truncated == 0 || PublicError(simulation.Err).Code != "model_unavailable" {
		t.Fatalf("removed %d, truncated %d, error %v", len(simulation.Removed), simulation.Truncated, simulation.Err)
	}
}

func describeRemovals(removed []RemovedCandidate) []string {
	var described []string
	for _, entry := range removed {
		text := entry.Reason + " " + string(entry.Provider)
		if entry.Deployment != "" {
			text += "/" + entry.Deployment
		}
		if entry.Credential != nil {
			text += fmt.Sprintf("#%d", *entry.Credential)
		}
		if entry.Origin != nil {
			text += fmt.Sprintf(" @%d%s", entry.Origin.Source, entry.Origin.Rule)
		}
		for _, detail := range []string{entry.Expression, map[bool]string{true: "unknown"}[entry.Unknown], entry.Code} {
			if detail != "" {
				text += " " + detail
			}
		}
		described = append(described, text)
	}
	slices.Sort(described)
	return described
}

func describePairs(pairs []SimulatedPair) []string {
	described := make([]string, len(pairs))
	for index, pair := range pairs {
		described[index] = fmt.Sprintf("%s#%d", pair.Deployment.ID, pair.Credential)
	}
	return described
}

// requestAttempts sends a text request with the simulation's inputs, fails
// every pair it tries, and returns the pairs in order.
func requestAttempts(input RequestInput, route Route, model, tier string) ([]string, error) {
	body := map[string]any{"messages": []map[string]string{{"role": "user", "content": "hello"}}}
	input.Path = "/v1/chat/completions"
	if route == RouteResponses {
		body, input.Path = map[string]any{"input": "hello"}, "/v1/responses"
	}
	if model != "" {
		body["model"] = model
	}
	if tier != "" {
		body["service_tier"] = tier
	}
	input.Body, _ = json.Marshal(body)
	input.Method = "POST"
	var attempts []string
	input.CheckCandidate = func(_ schemas.ModelProvider, index int, deployment Deployment) error {
		attempts = append(attempts, fmt.Sprintf("%s#%d", deployment.ID, index))
		return errors.New("unusable credential")
	}
	_, err := ResolveRequest(input)
	return attempts, err
}
