package catalog

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func BenchmarkRoutingCredentialAlternatives(b *testing.B) {
	snap, err := loadSnapshot()
	if err != nil {
		b.Fatal(err)
	}
	previous := active.Swap(snap)
	b.Cleanup(func() { active.Store(previous) })
	base, err := ResolveRequest(RequestInput{Body: []byte(`{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":"hi"}]}`), Method: "POST", Path: "/v1/chat/completions"})
	if err != nil {
		b.Fatal(err)
	}
	for _, deployments := range []int{1, 64} {
		selections := make([]routingSelection, deployments)
		for index := range selections {
			deployment := base.Deployment
			deployment.ID = fmt.Sprintf("benchmark-%03d", index)
			snap.graph.Deployments[deployment.ID] = snap.graph.Deployments[base.Deployment.ID]
			selections[index] = routingSelection{provider: schemas.OpenAI, deployment: deployment}
		}
		for _, count := range []int{1, 64, 1000} {
			b.Run(fmt.Sprintf("deployments_%d/credentials_%d", deployments, count), func(b *testing.B) {
				indexes := make([]int, count)
				for index := range indexes {
					indexes[index] = index
				}
				config := policyConfig(1)
				b.ReportAllocs()
				for b.Loop() {
					variants := &requestVariants{base: RequestPolicy{Config: config}, selections: selections}
					input := RequestInput{now: time.Now(), policyBudget: policy.NewCELBudget(), Policy: config, AvailableCredentials: map[string][]int{"openai": indexes}}
					_, _, err := selectRequestCandidate(input, RouteChat, base.RequestedModel, ProviderRoutingPreference{}, variants)
					if deployments == 1 && err != nil || deployments > 1 && PublicError(err).Code != "model_ambiguous" {
						b.Fatalf("unexpected routing result: %v", err)
					}
				}
			})
		}
	}
}

func BenchmarkRoutingDistinctCredentialPolicies(b *testing.B) {
	snap, err := loadSnapshot()
	if err != nil {
		b.Fatal(err)
	}
	previous := active.Swap(snap)
	b.Cleanup(func() { active.Store(previous) })
	base, err := ResolveRequest(RequestInput{Body: []byte(`{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":"hi"}]}`), Method: "POST", Path: "/v1/chat/completions"})
	if err != nil {
		b.Fatal(err)
	}
	empty, err := policy.CompileSource([]byte(`{}`))
	if err != nil {
		b.Fatal(err)
	}
	configs := make([]*policy.Config, 1000)
	indexes := make([]int, len(configs))
	for index := range configs {
		indexes[index] = index
		source, err := policy.CompileSource([]byte(fmt.Sprintf(`{"limits":{"spend":{"lifetimeUsd":"%d"}},"routing":{"filter":"true"}}`, index+1)))
		if err != nil {
			b.Fatal(err)
		}
		configs[index], err = policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: empty}, {Scope: policy.CredentialScope, Value: source}, {Scope: policy.KeyScope, Value: empty}})
		if err != nil {
			b.Fatal(err)
		}
	}
	selections := make([]routingSelection, 64)
	for index := range selections {
		deployment := base.Deployment
		deployment.ID = fmt.Sprintf("benchmark-distinct-%03d", index)
		snap.graph.Deployments[deployment.ID] = snap.graph.Deployments[base.Deployment.ID]
		selections[index] = routingSelection{provider: schemas.OpenAI, deployment: deployment}
	}
	b.ReportAllocs()
	for b.Loop() {
		variants := &requestVariants{selections: selections, load: func(_ schemas.ModelProvider, index int) (RequestPolicy, error) {
			return RequestPolicy{Config: configs[index]}, nil
		}}
		input := RequestInput{now: time.Now(), policyBudget: policy.NewCELBudget(), AvailableCredentials: map[string][]int{"openai": indexes}}
		if _, _, err := selectRequestCandidate(input, RouteChat, base.RequestedModel, ProviderRoutingPreference{}, variants); PublicError(err).Code != "model_ambiguous" {
			b.Fatalf("unexpected routing result: %v", err)
		}
	}
}

// A normal one-blend filter and ordering, including production catalog lookup.
// The larger benchmark below intentionally repeats many distinct predicates.
func BenchmarkRoutingSingleBlend(b *testing.B) {
	snap, err := loadSnapshot()
	if err != nil {
		b.Fatal(err)
	}
	previous := active.Swap(snap)
	b.Cleanup(func() { active.Store(previous) })
	base, err := ResolveRequest(RequestInput{AvailableCredentials: map[string][]int{"openai": {0}}, Body: policyChatBody(""), Method: "POST", Path: "/v1/chat/completions"})
	if err != nil {
		b.Fatal(err)
	}
	source, err := policy.CompileSource([]byte(`{"routing":{"filter": "blended_price(1, 3, 'per_mill_tokens') < decimal(\"100\")", "sort": [{"by":"blended_price(1, 3, 'per_mill_tokens')","direction":"asc"}]}}`))
	if err != nil {
		b.Fatal(err)
	}
	empty, err := policy.CompileSource([]byte(`{}`))
	if err != nil {
		b.Fatal(err)
	}
	config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: empty}, {Scope: policy.KeyScope, Value: source}})
	if err != nil {
		b.Fatal(err)
	}
	for _, count := range []int{1, 64} {
		b.Run(fmt.Sprintf("candidates_%d", count), func(b *testing.B) {
			candidates := make([]*ResolvedRequest, count)
			for i := range candidates {
				candidate := *base
				candidate.Deployment.ID = fmt.Sprintf("single-blend-%03d", i)
				snap.graph.Deployments[candidate.Deployment.ID] = snap.graph.Deployments[base.Deployment.ID]
				candidate.Deployment.Pricing = Pricing{"input_tokens": {"per_mill_tokens": "1.25"}, "output_tokens": {"per_mill_tokens": fmt.Sprintf("%d.50", i+2)}}
				candidates[i] = &candidate
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				budget := policy.NewCELBudget()
				for _, candidate := range candidates {
					candidate.policyBudget = budget
				}
				resolved, err := finalizeRoutingCandidates(append([]*ResolvedRequest{}, candidates...), config, ProviderRoutingPreference{})
				if err != nil || len(resolved) != len(candidates) {
					b.Fatalf("routing result: %d candidates, %v", len(resolved), err)
				}
			}
		})
	}
}

// Includes the production catalog field resolver, exact price parsing, query
// intersection, and filter/sort value reuse. Candidate construction, source
// compilation and tokenization are outside the measured routing pass.
func BenchmarkRoutingBlendedPrices(b *testing.B) {
	snap, err := loadSnapshot()
	if err != nil {
		b.Fatal(err)
	}
	previous := active.Swap(snap)
	b.Cleanup(func() { active.Store(previous) })
	base, err := ResolveRequest(RequestInput{AvailableCredentials: map[string][]int{"openai": {0}}, Body: policyChatBody(""), Method: "POST", Path: "/v1/chat/completions"})
	if err != nil {
		b.Fatal(err)
	}
	for _, prices := range []string{"equal", "unequal", "large"} {
		for _, unique := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/unique_weights_%t", prices, unique), func(b *testing.B) {
				sources := make([]policy.ScopedSource, 3)
				for scope := range sources {
					predicates := make([]string, 40)
					for i := range predicates {
						weight := 9007199254740991
						if unique {
							weight -= scope*len(predicates) + i
						}
						predicates[i] = fmt.Sprintf("blended_price(%d, 9007199254740990, 'per_mill_tokens') < decimal('1000000000000')", weight)
					}
					filter := strings.Join(predicates, " && ")
					raw, err := json.Marshal(map[string]any{"routing": map[string]any{"filter": filter, "sort": []policy.Sort{{By: "blended_price(1, 3, 'per_mill_tokens')", Direction: "asc"}}, "maxAttempts": 3}})
					if err != nil {
						b.Fatal(err)
					}
					sources[scope].Scope = []policy.Scope{policy.OrganizationScope, policy.GrantScope, policy.KeyScope}[scope]
					sources[scope].Value, err = policy.CompileSource(raw)
					if err != nil {
						b.Fatal(err)
					}
				}
				config, err := policy.ComposeSources(sources)
				if err != nil {
					b.Fatal(err)
				}
				candidates := make([]*ResolvedRequest, 64)
				for i := range candidates {
					candidate := *base
					candidate.Deployment.ID = fmt.Sprintf("multiple-blends-%03d", i)
					snap.graph.Deployments[candidate.Deployment.ID] = snap.graph.Deployments[base.Deployment.ID]
					input := "1.000000000000000000000000000000000001"
					output := input
					if prices == "unequal" {
						output = fmt.Sprintf("%d.000000000000000000000000000000000007", i+2)
					} else if prices == "large" {
						input = "999999999997.999999999999999999999999999999999997"
						output = "999999999999.999999999999999999999999999999999991"
					}
					candidate.Deployment.Pricing = Pricing{"input_tokens": {"per_mill_tokens": input}, "output_tokens": {"per_mill_tokens": output}}
					candidates[i] = &candidate
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					budget := policy.NewCELBudget()
					for _, candidate := range candidates {
						candidate.policyBudget = budget
					}
					resolved, err := finalizeRoutingCandidates(append([]*ResolvedRequest{}, candidates...), config, ProviderRoutingPreference{})
					if err != nil || len(resolved) != len(candidates) {
						b.Fatalf("routing result: %d candidates, %v", len(resolved), err)
					}
				}
			})
		}
	}
}
