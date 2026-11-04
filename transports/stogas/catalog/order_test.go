package catalog

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestRoutingOrderPutsListedDeploymentsFirstWithinThePairSlots(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, limit := range []int{1, 2, 3} {
			config := policyConfig(limit)
			config.Routing.Query = orderedQuery(t, "", "openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6")
			body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
			if path == "/v1/responses" {
				body = []byte(`{"input":"hello"}`)
			}
			var checked []credentialCandidate
			resolved, err := ResolveRequest(RequestInput{
				Body: body, Method: "POST", Path: path, Policy: config,
				AvailableCredentials: map[string][]int{"openai": {4, 2}, "anthropic": {3}},
				CheckCandidate: func(provider schemas.ModelProvider, index int, _ Deployment) error {
					checked = append(checked, credentialCandidate{provider, index})
					if provider == schemas.OpenAI {
						return errors.New("credential unavailable")
					}
					return nil
				},
			})
			want := []credentialCandidate{{schemas.OpenAI, 4}, {schemas.OpenAI, 2}, {schemas.Anthropic, 3}}
			if !reflect.DeepEqual(checked, want[:limit]) || (err == nil) != (limit == 3) {
				t.Fatalf("%s limit=%d: checked=%v error=%v", path, limit, checked, err)
			}
			if resolved != nil && (resolved.Deployment.ID != "anthropic-claude-sonnet-4-6" || resolved.CredentialIndex != 3) {
				t.Fatalf("order is wrong: %+v", resolved)
			}
			if resolved != nil {
				if next, _ := resolved.NextPair(nil); next != nil {
					t.Fatalf("the last pair left a slot: %+v", next)
				}
			}
		}
	}
}

// The plan hands each pair that it refuses to the caller in plan order, and
// when it refuses every pair it keeps the error that the caller prefers.
func TestPlanHandsOverEachRefusedPairAndKeepsThePreferredError(t *testing.T) {
	loadTestCatalog(t)
	config := policyConfig(2)
	config.Routing.Query = orderedQuery(t, "", "openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6")
	refusals := map[schemas.ModelProvider]error{schemas.OpenAI: errors.New("openai"), schemas.Anthropic: errors.New("anthropic")}
	for _, prefersLater := range []bool{false, true} {
		var skipped []error
		_, err := ResolveRequest(RequestInput{
			Body: []byte(`{"input":"hello"}`), Method: "POST", Path: "/v1/responses", Policy: config,
			AvailableCredentials: map[string][]int{"openai": {0}, "anthropic": {0}},
			CheckCandidate: func(provider schemas.ModelProvider, _ int, _ Deployment) error {
				return refusals[provider]
			},
			PairSkipped: func(err error) { skipped = append(skipped, err) },
			Prefers:     func(error, error) bool { return prefersLater },
		})
		want := refusals[schemas.OpenAI]
		if prefersLater {
			want = refusals[schemas.Anthropic]
		}
		if !reflect.DeepEqual(skipped, []error{refusals[schemas.OpenAI], refusals[schemas.Anthropic]}) || err != want {
			t.Fatalf("prefers later %v: skipped=%v error=%v", prefersLater, skipped, err)
		}
	}
}

// A pair that waits is passed over only while another remains, and uses its
// place; the request's last pair gets its call whatever it waits.
func TestPlanPassesOverAWaitingPairWhileAnotherRemains(t *testing.T) {
	loadTestCatalog(t)
	waiting := errors.New("waiting")
	for _, test := range []struct {
		pairs   int
		waits   []schemas.ModelProvider
		checked []schemas.ModelProvider // the pairs that reach preparation, in order
		skipped int
	}{
		{2, []schemas.ModelProvider{schemas.OpenAI}, []schemas.ModelProvider{schemas.Anthropic}, 1},
		{1, []schemas.ModelProvider{schemas.OpenAI}, []schemas.ModelProvider{schemas.OpenAI}, 0},
		{2, []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic}, []schemas.ModelProvider{schemas.Anthropic}, 1},
		{2, []schemas.ModelProvider{schemas.Anthropic}, []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic}, 0},
	} {
		config := policyConfig(test.pairs)
		config.Routing.Query = orderedQuery(t, "", "openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6")
		var checked []schemas.ModelProvider
		var skipped []error
		resolved, err := ResolveRequest(RequestInput{
			Body: []byte(`{"input":"hello"}`), Method: "POST", Path: "/v1/responses", Policy: config,
			AvailableCredentials: map[string][]int{"openai": {0}, "anthropic": {0}},
			PairWaits: func(provider schemas.ModelProvider, _ int, _ Deployment) error {
				if slices.Contains(test.waits, provider) {
					return waiting
				}
				return nil
			},
			CheckCandidate: func(provider schemas.ModelProvider, _ int, _ Deployment) error {
				checked = append(checked, provider)
				return nil
			},
			PairSkipped: func(err error) { skipped = append(skipped, err) },
		})
		for next := resolved; err == nil && next != nil; {
			next, err = next.NextPair(nil)
		}
		if !errors.Is(err, ErrModelUnavailable) && !errors.Is(err, waiting) || !reflect.DeepEqual(checked, test.checked) || len(skipped) != test.skipped {
			t.Fatalf("%d pairs waiting %v: checked=%v skipped=%v error=%v", test.pairs, test.waits, checked, skipped, err)
		}
	}
}

func TestRoutingOrderNeverWidensCatalogAuthorizationOrPinnedSelectors(t *testing.T) {
	loadTestCatalog(t)
	for _, model := range []string{"", "gpt-5.6-sol", "provider:openai gpt-5.6-sol", "openai-gpt-5.6-sol"} {
		config := policyConfig(3)
		config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Providers: []string{"anthropic"}}
		config.Routing.Query = orderedQuery(t, "", "openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6")
		body := map[string]any{"input": "hello"}
		if model != "" {
			body["model"] = model
		}
		raw, _ := json.Marshal(body)
		checks := 0
		resolved, err := ResolveRequest(RequestInput{Body: raw, Method: "POST", Path: "/v1/responses", Policy: config,
			CheckCandidate: func(provider schemas.ModelProvider, _ int, _ Deployment) error {
				checks++
				if provider != schemas.Anthropic {
					t.Fatal("blocked provider reached credential preparation")
				}
				return nil
			},
		})
		if model == "" {
			if err != nil || resolved.Deployment.ID != "anthropic-claude-sonnet-4-6" || checks != 1 {
				t.Fatalf("eligible listed deployment was not first: resolved=%v error=%v", resolved, err)
			}
		} else if err == nil || resolved != nil || checks != 0 {
			t.Fatalf("%s widened a selector: checks=%d error=%v", model, checks, err)
		}
	}
}

func TestRandomSortTriesEachDeploymentOnceAndStopsOnTerminalCredentialErrors(t *testing.T) {
	loadTestCatalog(t)
	for _, terminal := range []bool{false, true} {
		config := policyConfig(3)
		config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6", "azure-gpt-5.6-sol"}}
		config.Routing.Query = mustRouting(t, "", []policy.Sort{{By: "random()"}})
		seen := map[string]bool{}
		_, err := ResolveRequest(RequestInput{Body: []byte(`{"input":"hello"}`), Method: "POST", Path: "/v1/responses", Policy: config,
			CheckCandidate: func(_ schemas.ModelProvider, _ int, deployment Deployment) error {
				if seen[deployment.ID] {
					t.Fatal("random order returned to a deployment before trying the others")
				}
				seen[deployment.ID] = true
				if terminal {
					return customerkey.ErrEnvelope
				}
				return errors.New("credential unavailable")
			},
		})
		want := 3
		if terminal {
			want = 1
		}
		if err == nil || len(seen) != want || terminal && !errors.Is(err, customerkey.ErrEnvelope) {
			t.Fatalf("wrong random attempt boundary: seen=%v error=%v", seen, err)
		}
	}
}

// Weights decide which deployment comes first, in proportion. Credentials of
// one deployment stay together whatever the draw.
func TestWeightedRandomSortSplitsFirstAttemptsByWeight(t *testing.T) {
	loadTestCatalog(t)
	config := policyConfig(3)
	config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"openai-gpt-5.6-sol", "azure-gpt-5.6-sol"}}
	config.Routing.Query = mustRouting(t, "", []policy.Sort{{By: `random(provider.id == "openai" ? 3 : 1)`}})
	const runs = 4000
	first := map[string]int{}
	for range runs {
		var checked []string
		_, err := ResolveRequest(RequestInput{Body: []byte(`{"model":"gpt-5.6-sol","input":"hello"}`), Method: "POST", Path: "/v1/responses", Policy: config,
			AvailableCredentials: map[string][]int{"openai": {0, 1}, "azure": {0}},
			CheckCandidate: func(_ schemas.ModelProvider, _ int, deployment Deployment) error {
				checked = append(checked, deployment.ID)
				return errors.New("credential unavailable")
			},
		})
		if err == nil || len(checked) != 3 {
			t.Fatalf("checked=%v error=%v", checked, err)
		}
		if checked[0] == "openai-gpt-5.6-sol" && checked[1] != checked[0] || checked[0] == "azure-gpt-5.6-sol" && checked[1] != "openai-gpt-5.6-sol" {
			t.Fatalf("credentials of one deployment were split: %v", checked)
		}
		first[checked[0]]++
	}
	// Expect 3000 of 4000; the band is about six standard deviations.
	if got := first["openai-gpt-5.6-sol"]; got < 2830 || got > 3170 {
		t.Fatalf("weight 3 of 4 came first %d of %d times", got, runs)
	}
}

// Only policy criteria order candidates. A tie that reaches the tried pairs
// fails the request and names the tied models or deployments.
func TestPolicyCriteriaDecideEveryTriedTie(t *testing.T) {
	loadTestCatalog(t)
	anthropic := map[string][]int{"anthropic": {0}}
	tiebreak := `{"by":"blended_price(3, 1)"},{"by":"deployment.id"}`
	for _, test := range []struct {
		name, body, policy, deployment, code string
		credentials                          map[string][]int
	}{
		{
			name:        "latest model from an author",
			body:        `{"input":"hello"}`,
			credentials: map[string][]int{"openai": {0}},
			policy:      `{"routing":{"filter":"author.id == 'openai'","sort":[{"by":"model.releaseDate","direction":"desc"},` + tiebreak + `]}}`,
			deployment:  "openai-gpt-6.1-sol",
		},
		{
			// GPT-6 Luna and Sol share a release date behind GPT-6.1 Sol, so the
			// first fallback is a tie.
			name:        "a tie among fallbacks fails",
			body:        `{"input":"hello"}`,
			credentials: map[string][]int{"openai": {0}},
			policy:      `{"routing":{"filter":"author.id == 'openai'","sort":[{"by":"model.releaseDate","direction":"desc"}]}}`,
			code:        ErrModelAmbiguous.Code,
		},
		{
			name:        "a tie beyond the fallbacks changes nothing",
			body:        `{"input":"hello"}`,
			credentials: map[string][]int{"openai": {0}},
			policy:      `{"routing":{"fallbacks":0,"filter":"author.id == 'openai'","sort":[{"by":"model.releaseDate","direction":"desc"}]}}`,
			deployment:  "openai-gpt-6.1-sol",
		},
		{
			name:        "cheapest model in a group",
			body:        `{"input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"filter":"'claude' in model.groupIds","sort":[{"by":"blended_price(3, 1)"}]}}`,
			deployment:  "anthropic-claude-haiku-5-5",
		},
		{
			// Claude Sonnet 5 and 5.5 cost the same.
			name:        "equal prices tie",
			body:        `{"input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"filter":"'claude-sonnet' in model.groupIds","sort":[{"by":"blended_price(3, 1)"}]}}`,
			code:        ErrModelAmbiguous.Code,
		},
		{
			name:        "a later criterion breaks a price tie",
			body:        `{"input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"filter":"'claude-sonnet' in model.groupIds","sort":[{"by":"blended_price(3, 1)"},{"by":"model.releaseDate","direction":"desc"},{"by":"deployment.id"}]}}`,
			deployment:  "anthropic-claude-sonnet-5-5",
		},
		{
			name:        "a group follows the sort to its oldest model",
			body:        `{"model":"claude-sonnet","input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"sort":[{"by":"model.releaseDate"},` + tiebreak + `]}}`,
			deployment:  "anthropic-claude-sonnet-4-6",
		},
		{
			name:        "an order lists a model the request did not name",
			body:        `{"input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"order":["anthropic-claude-opus-4-8"],"sort":[` + tiebreak + `]}}`,
			deployment:  "anthropic-claude-opus-4-8",
		},
		{
			name:        "an order picks any model of a group",
			body:        `{"model":"claude-opus","input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"sort":[{"deployments":["anthropic-claude-opus-4-8"]},` + tiebreak + `]}}`,
			deployment:  "anthropic-claude-opus-4-8",
		},
		{
			name:        "the order outranks the sort",
			body:        `{"input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"order":["anthropic-claude-opus-5-5-us"],"sort":[{"by":"blended_price(3, 1)"}]}}`,
			deployment:  "anthropic-claude-opus-5-5-us",
		},
		{
			name:        "several models without a sort",
			body:        `{"input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"filter":"'claude-sonnet' in model.groupIds"}}`,
			code:        ErrModelAmbiguous.Code,
		},
		{
			// Claude Sonnet 4.6 runs worldwide and in the US.
			name:        "deployments of one model tie",
			body:        `{"model":"claude-sonnet-4-6","input":"hello"}`,
			credentials: anthropic,
			policy:      `{"routing":{"sort":[{"by":"model.releaseDate"}]}}`,
			code:        ErrDeploymentAmbiguous.Code,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, err := policy.CompileSource([]byte(test.policy))
			if err != nil {
				t.Fatal(err)
			}
			config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
			if err != nil {
				t.Fatal(err)
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
					t.Fatalf("want %s, got %#v, %v", test.code, resolved, err)
				}
				return
			}
			if err != nil || resolved.Deployment.ID != test.deployment {
				t.Fatalf("want %s, got %#v, %v", test.deployment, resolved, err)
			}
		})
	}
}
