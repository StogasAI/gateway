package catalog

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestOrderedTargetsShareCredentialAndProviderAttemptBudget(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, limit := range []int{1, 2, 3} {
			config := policyConfig(limit)
			config.Routing.Selection = &policy.Selection{Mode: "ordered", Targets: []string{"openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6"}}
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
			if resolved != nil && (resolved.Deployment.ID != "anthropic-claude-sonnet-4-6" || resolved.CredentialIndex != 3 || resolved.ProviderAttemptLimit() != 1) {
				t.Fatalf("remaining provider allowance or selection is wrong: %+v", resolved)
			}
		}
	}
}

func TestTargetSelectionNeverWidensCatalogAuthorizationOrPinnedSelectors(t *testing.T) {
	loadTestCatalog(t)
	for _, mode := range []string{"ordered", "random"} {
		for _, model := range []string{"", "gpt-5.6-sol", "openai/gpt-5.6-sol", "openai-gpt-5.6-sol"} {
			config := policyConfig(3)
			config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Providers: []string{"anthropic"}}
			config.Routing.Selection = &policy.Selection{Mode: mode, Targets: []string{"openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6"}}
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
				if err != nil || resolved.Deployment.ID != "anthropic-claude-sonnet-4-6" || checks != 1 || resolved.ProviderAttemptLimit() != 3 {
					t.Fatalf("eligible target was not selected: resolved=%v error=%v", resolved, err)
				}
			} else if err == nil || resolved != nil || checks != 0 {
				t.Fatalf("%s/%s widened a selector: checks=%d error=%v", mode, model, checks, err)
			}
		}
	}
}

func TestRandomTargetsDoNotRepeatDeploymentsOrIgnoreTerminalCredentialErrors(t *testing.T) {
	loadTestCatalog(t)
	for _, terminal := range []bool{false, true} {
		config := policyConfig(3)
		config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6", "azure-gpt-5.6-sol"}}
		config.Routing.Selection = &policy.Selection{Mode: "random"}
		seen := map[string]bool{}
		_, err := ResolveRequest(RequestInput{Body: []byte(`{"input":"hello"}`), Method: "POST", Path: "/v1/responses", Policy: config,
			CheckCandidate: func(_ schemas.ModelProvider, _ int, deployment Deployment) error {
				if seen[deployment.ID] {
					t.Fatal("random fallback retried a deployment")
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

func TestEveryCredentialParticipatesInSelectionAgreement(t *testing.T) {
	loadTestCatalog(t)
	checked := 0
	_, err := ResolveRequest(RequestInput{
		Body: []byte(`{"model":"openai-gpt-5.6-sol","input":"hello"}`), Method: "POST", Path: "/v1/responses",
		AvailableCredentials: map[string][]int{"openai": {0, 1, 2, 3}},
		CredentialPolicy: func(_ schemas.ModelProvider, index int) (RequestPolicy, error) {
			config := policyConfig(3)
			config.Routing.Selection = &policy.Selection{Mode: "random"}
			if index == 3 {
				config.Routing.Selection = &policy.Selection{Mode: "ordered", Targets: []string{"openai-gpt-5.6-sol"}}
			}
			return RequestPolicy{Config: config}, nil
		},
		CheckCandidate: func(schemas.ModelProvider, int, Deployment) error { checked++; return nil },
	})
	if err == nil || PublicError(err).Code != "invalid_request" || checked != 0 {
		t.Fatalf("an unreachable conflicting credential was ignored: checks=%d error=%v", checked, err)
	}
}
