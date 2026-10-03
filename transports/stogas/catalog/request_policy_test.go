package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestCredentialEligibilityPrecedesPoliciesAndAmbiguity(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, test := range []struct {
			name, model, extra, deployment, code string
			providers                            map[string][]int
			azureTarget                          string
			filter                               string
		}{
			{name: "one configured provider", model: "gpt-5.6-sol", providers: map[string][]int{"openai": {0}}, deployment: "openai-gpt-5.6-sol"},
			{name: "Azure target narrows region", model: "gpt-5.6-sol", providers: map[string][]int{"azure": {0}}, azureTarget: "azure-gpt-5.6-sol-us", deployment: "azure-gpt-5.6-sol-us"},
			{name: "unconfigured exact deployment", model: "openai-gpt-5.6-sol", providers: map[string][]int{"azure": {0}}, code: "model_unavailable"},
			{name: "no configured credentials", model: "gpt-5.6-sol", providers: map[string][]int{}, code: "model_unavailable"},
			{name: "no model and no credentials", providers: map[string][]int{}, code: "model_unavailable"},
			{name: "two configured providers", model: "gpt-5.6-sol", providers: map[string][]int{"azure": {0}, "openai": {0}}, code: "model_ambiguous"},
			{name: "provider still has regions", model: "azure/gpt-5.6-sol", providers: map[string][]int{"azure": {0}}, code: "model_ambiguous"},
			{name: "strict provider unavailable", model: "gpt-5.6-sol", providers: map[string][]int{"azure": {0}}, extra: `,"provider":"openai"`, code: "provider_not_allowed"},
			{name: "exact selection retains policy", model: "openai-gpt-5.6-sol", providers: map[string][]int{"openai": {0}}, filter: `provider.id == 'azure'`, code: "model_unavailable"},
			{name: "policy narrows one region", model: "gpt-5.6-sol", providers: map[string][]int{"azure": {0}}, filter: `deployment.id == 'azure-gpt-5.6-sol-eu'`, deployment: "azure-gpt-5.6-sol-eu"},
			{name: "policy cannot restore missing provider", model: "gpt-5.6-sol", providers: map[string][]int{"azure": {0}}, filter: `provider.id == 'openai'`, code: "model_unavailable"},
			{name: "exact selection retains credential targets", model: "azure-gpt-5.6-sol-us", providers: map[string][]int{"azure": {0}}, azureTarget: "azure-gpt-5.6-sol", code: "model_unavailable"},
			{name: "provider order chooses unique first group", model: "gpt-5.6-sol", providers: map[string][]int{"azure": {0}, "openai": {0}}, extra: `,"provider":{"order":["openai","azure"]}`, deployment: "openai-gpt-5.6-sol"},
			{name: "missing first provider is ineligible", model: "gpt-5.6-sol", providers: map[string][]int{"azure": {0}}, azureTarget: "azure-gpt-5.6-sol", extra: `,"provider":{"order":["openai","azure"]}`, deployment: "azure-gpt-5.6-sol"},
		} {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				content := `"messages":[{"role":"user","content":"hello"}]`
				if path == "/v1/responses" {
					content = `"input":"hello"`
				}
				model := ""
				if test.model != "" {
					model = `"model":"` + test.model + `",`
				}
				config := policyConfig(1)
				if test.filter != "" {
					config.Routing.Query = mustRouting(t, test.filter, nil)
				}
				checks, transforms := 0, 0
				resolved, err := ResolveRequest(RequestInput{
					Body: []byte(`{` + model + content + test.extra + `}`), Method: "POST", Path: path,
					Policy: config, AvailableCredentials: test.providers,
					DeploymentEligible: func(provider schemas.ModelProvider, _ int, deployment Deployment) bool {
						return test.azureTarget == "" || provider != schemas.Azure || deployment.ID == test.azureTarget
					},
					CredentialPolicy: func(provider schemas.ModelProvider, _ int) (RequestPolicy, error) {
						if len(test.providers[string(provider)]) == 0 {
							t.Fatal("loaded policy for an unconfigured provider")
						}
						return RequestPolicy{Config: config, LoadRedactionPolicy: func() (*redaction.Policy, error) {
							transforms++
							return redaction.CompilePolicy(redaction.Options{})
						}}, nil
					},
					CheckCandidate: func(_ schemas.ModelProvider, _ int, _ Deployment) error { checks++; return nil },
				})
				if test.code != "" {
					if PublicError(err).Code != test.code || resolved != nil || checks != 0 || transforms != 0 {
						t.Fatalf("error=%v checks=%d transforms=%d", err, checks, transforms)
					}
				} else if err != nil || resolved == nil || resolved.Deployment.ID != test.deployment || checks != 1 || transforms != 1 {
					t.Fatalf("result=%v error=%v checks=%d transforms=%d", resolved, err, checks, transforms)
				}
			})
		}
	}
}

func TestReasoningCompatibilityFiltersBeforeCredentialPreparationAndRedaction(t *testing.T) {
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, test := range []struct {
			name, model, reasoning string
			wantDeployment         string
		}{
			{name: "manual budget resolves deployment ambiguity", reasoning: `"reasoning":{"max_tokens":2048}`, wantDeployment: "anthropic-claude-sonnet-4-6"},
			{name: "pinned incompatible model is not replaced", model: "openai-gpt-5.6-sol", reasoning: `"reasoning":{"max_tokens":2048}`},
			{name: "below catalog minimum", model: "anthropic-claude-sonnet-4-6", reasoning: `"reasoning":{"max_tokens":512}`},
			{name: "reasoning consumes entire output limit", model: "anthropic-claude-sonnet-4-6", reasoning: `"reasoning":{"max_tokens":4096}`},
			{name: "effort conflicts with manual budget", reasoning: `"reasoning":{"effort":"high","max_tokens":2048}`},
		} {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				loadTestCatalog(t)
				config := policyConfig(1)
				config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"openai-gpt-5.6-sol", "anthropic-claude-sonnet-4-6"}}
				content := `"messages":[{"role":"user","content":"private@example.com"}],"max_completion_tokens":4096`
				if path == "/v1/responses" {
					content = `"input":"private@example.com","max_output_tokens":4096`
				}
				if test.model != "" {
					content += `,"model":"` + test.model + `"`
				}
				checks, transforms := 0, 0
				resolved, err := ResolveRequest(RequestInput{
					Body: []byte(`{` + content + `,` + test.reasoning + `}`), Method: "POST", Path: path,
					Policy: config, AvailableCredentials: map[string][]int{"openai": {0}, "anthropic": {0}},
					CheckCandidate: func(schemas.ModelProvider, int, Deployment) error { checks++; return nil },
					LoadRedactionPolicy: func() (*redaction.Policy, error) {
						transforms++
						return redaction.CompilePolicy(redaction.Options{})
					},
				})
				if test.wantDeployment == "" {
					if err == nil || resolved != nil || PublicError(err).StatusCode != 400 || checks != 0 || transforms != 0 {
						t.Fatalf("incompatible request reached preparation: resolved=%v err=%v checks=%d transforms=%d", resolved, err, checks, transforms)
					}
					return
				}
				if err != nil || resolved == nil || resolved.Deployment.ID != test.wantDeployment || checks != 1 || transforms != 1 {
					t.Fatalf("compatible deployment was not selected first: resolved=%v err=%v checks=%d transforms=%d", resolved, err, checks, transforms)
				}
			})
		}
	}
}

func TestReasoningAliasesUseTheSameEarlyCatalogConstraints(t *testing.T) {
	loadTestCatalog(t)
	for _, input := range []RequestInput{
		{Path: "/v1/chat/completions", Body: []byte(`{"model":"anthropic-claude-sonnet-4-6","messages":[],"reasoning_max_tokens":512}`)},
		{Path: "/v1/chat/completions", Body: []byte(`{"model":"openai-gpt-5.6-sol","messages":[],"reasoning_effort":"invalid"}`)},
		{Path: "/v1/responses", Body: []byte(`{"model":"openai-gpt-5.6-sol","input":"hello","reasoning.effort":"invalid"}`)},
	} {
		input.Method = "POST"
		input.CheckCandidate = func(schemas.ModelProvider, int, Deployment) error {
			t.Fatal("incompatible reasoning alias reached credential preparation")
			return nil
		}
		if _, err := ResolveRequest(input); err == nil || PublicError(err).StatusCode != 400 {
			t.Fatalf("incompatible alias was accepted: %s, %v", input.Path, err)
		}
	}
}

func TestConditionalPolicyRedactsOnlyTheSelectedBranch(t *testing.T) {
	loadTestCatalog(t)
	source, err := policy.CompileSource([]byte(`{"rules":{"openai":{"when":"provider.id == 'openai'","plugins":{"stogasRedaction":{"literals":[{"values":["OPENAI_PRIVATE"]}]}}},"other":{"when":"provider.id == 'anthropic'","plugins":{"stogasRedaction":{"literals":[{"values":["OTHER_PRIVATE"]}]}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		body := map[string]any{"model": "openai-gpt-5.6-sol"}
		if path == "/v1/responses" {
			body["input"] = "OPENAI_PRIVATE and OTHER_PRIVATE"
		} else {
			body["messages"] = []map[string]string{{"role": "user", "content": "OPENAI_PRIVATE and OTHER_PRIVATE"}}
		}
		raw, _ := json.Marshal(body)
		resolved, err := ResolveRequest(RequestInput{Body: raw, Method: "POST", Path: path, Policy: config})
		if err != nil {
			t.Fatal(err)
		}
		text, _ := json.Marshal(resolved.RawBody())
		if strings.Contains(string(text), "OPENAI_PRIVATE") || !strings.Contains(string(text), "OTHER_PRIVATE") || resolved.StructuredPIIRedactionSummary().ItemsRedacted != 1 {
			t.Fatalf("wrong branch on %s: %s, %+v", path, text, resolved.StructuredPIIRedactionSummary())
		}
	}
}

func TestFallbackCannotChooseAnAmbiguousBackup(t *testing.T) {
	loadTestCatalog(t)
	checks := 0
	_, err := ResolveRequest(RequestInput{
		Body: policyChatBody(`,"provider":{"order":["openai","azure"]}`), Method: "POST", Path: "/v1/chat/completions", Policy: policyConfig(2),
		CheckCandidate: func(provider schemas.ModelProvider, _ int, _ Deployment) error {
			checks++
			if provider != schemas.OpenAI {
				t.Fatal("attempted an ambiguous backup")
			}
			return errors.New("credential could not be decrypted")
		},
	})
	if checks != 1 || PublicError(err).Code != "model_ambiguous" {
		t.Fatalf("checks=%d error=%v", checks, err)
	}
}

func TestOnlyTheSelectedCredentialTransformsInput(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, fallback := range []bool{false, true} {
			t.Run(path+map[bool]string{false: "/first", true: "/fallback"}[fallback], func(t *testing.T) {
				raw := map[string]any{"model": "gpt-5.6-sol", "provider": map[string]any{"only": []string{"openai", "azure"}, "order": []string{"openai", "azure"}}}
				if path == "/v1/responses" {
					raw["input"] = "OPENAI_PRIVATE and AZURE_PRIVATE"
				} else {
					raw["messages"] = []map[string]string{{"role": "user", "content": "OPENAI_PRIVATE and AZURE_PRIVATE"}}
				}
				body, _ := json.Marshal(raw)
				loads := 0
				resolved, err := ResolveRequest(RequestInput{Body: body, Method: "POST", Path: path, Policy: policyConfig(2),
					DeploymentEligible: func(_ schemas.ModelProvider, _ int, deployment Deployment) bool {
						return deployment.ID == "openai-gpt-5.6-sol" || deployment.ID == "azure-gpt-5.6-sol"
					},
					CheckCandidate: func(provider schemas.ModelProvider, _ int, _ Deployment) error {
						if loads != 0 {
							t.Fatal("redaction ran before credential selection finished")
						}
						if fallback && provider == schemas.OpenAI {
							return errors.New("credential unavailable")
						}
						return nil
					},
					CredentialPolicy: func(provider schemas.ModelProvider, _ int) (RequestPolicy, error) {
						literal := "OPENAI_PRIVATE"
						if provider == schemas.Azure {
							literal = "AZURE_PRIVATE"
						}
						return RequestPolicy{Config: policyConfig(2), LoadRedactionPolicy: func() (*redaction.Policy, error) {
							loads++
							return redaction.CompilePolicy(redaction.Options{Literals: []redaction.Literal{{Text: literal}}})
						}}, nil
					},
				})
				if err != nil || resolved == nil || loads != 1 {
					t.Fatalf("loads=%d error=%v", loads, err)
				}
				removed, retained := "OPENAI_PRIVATE", "AZURE_PRIVATE"
				if fallback {
					removed, retained = retained, removed
				}
				encoded, _ := json.Marshal(resolved.RawBody())
				if strings.Contains(string(encoded), removed) || !strings.Contains(string(encoded), retained) {
					t.Fatal("wrong selected dictionary")
				}
				if _, known := resolved.EstimatedInputTokens(); !known {
					t.Fatal("missing selected estimate")
				}
				upstream, err := resolved.ToBifrost(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))
				wire, _ := json.Marshal(upstream)
				if err != nil || strings.Contains(string(wire), removed) || !strings.Contains(string(wire), retained) {
					t.Fatal("conversion lost the selected transformation")
				}
			})
		}
	}
}

func TestCredentialFilteringRunsBeforeItsDictionaryAndCannotWeakenTheKey(t *testing.T) {
	loadTestCatalog(t)
	base := policyConfig(2)
	base.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Providers: []string{"openai", "azure"}}
	loads := 0
	resolved, err := ResolveRequest(RequestInput{Body: policyChatBody(""), Method: "POST", Path: "/v1/chat/completions", Policy: base, CredentialPolicy: func(provider schemas.ModelProvider, _ int) (RequestPolicy, error) {
		config := policyConfig(2)
		config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Deployments: []string{"azure-gpt-5.6-sol"}}
		if provider == schemas.OpenAI {
			config.Routing.AllowedCatalogNodes = &policy.AllowedCatalogNodes{Models: []string{}}
		}
		return RequestPolicy{Config: config, LoadRedactionPolicy: func() (*redaction.Policy, error) {
			if provider == schemas.OpenAI {
				t.Fatal("compiled a dictionary for an excluded candidate")
			}
			loads++
			return redaction.CompilePolicy(redaction.Options{})
		}}, nil
	}})
	if err != nil || resolved == nil || loads != 1 {
		t.Fatalf("resolution=%v loads=%d error=%v", resolved, loads, err)
	}
	for _, candidate := range []*ResolvedRequest{resolved} {
		if candidate.Provider != schemas.Azure {
			t.Fatal("credential restriction was not enforced")
		}
	}
}

func TestRequestPolicyCompilesOnceAndCombinesRedactionBeforeScanning(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			org, err := policy.CompileSource([]byte(`{"routing":{"fallbacks":{"maxPreDispatchCandidates":2}},"plugins":{"stogasRedaction":{"literals":[{"values":["SAVED_PRIVATE"]}]}}}`))
			if err != nil {
				t.Fatal(err)
			}
			key, err := policy.CompileSource([]byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			credential, err := policy.CompileSource([]byte(`{"delegation":{"request":["plugins","input"]}}`))
			if err != nil {
				t.Fatal(err)
			}
			base, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: org}, {Scope: policy.KeyScope, Value: key}})
			if err != nil {
				t.Fatal(err)
			}
			selected, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: org}, {Scope: policy.CredentialScope, Value: credential}, {Scope: policy.KeyScope, Value: key}})
			if err != nil {
				t.Fatal(err)
			}
			matcher, err := policy.CompileRedaction(base)
			if err != nil {
				t.Fatal(err)
			}
			original, _ := json.Marshal(selected)
			raw := map[string]any{"model": "gpt-5.6-sol", "provider": map[string]any{"only": []string{"openai", "azure"}, "order": []string{"openai", "azure"}}, "policy": map[string]any{"input": map[string]any{"asciiOnly": true}, "plugins": map[string]any{"stogasRedaction": map[string]any{"literals": []any{map[string]any{"values": []string{"REQUEST_PRIVATE"}}}}}}}
			if path == "/v1/responses" {
				raw["input"] = "SAVED_PRIVATE REQUEST_PRIVATE"
			} else {
				raw["messages"] = []map[string]string{{"role": "user", "content": "SAVED_PRIVATE REQUEST_PRIVATE"}}
			}
			body, _ := json.Marshal(raw)
			compilations, loads := 0, 0
			resolved, err := ResolveRequest(RequestInput{Body: body, Method: "POST", Path: path, Policy: base,
				CompileRequestPolicy: func(raw []byte) (*policy.Request, error) { compilations++; return policy.CompileRequest(raw, "", nil) },
				CredentialPolicy: func(provider schemas.ModelProvider, _ int) (RequestPolicy, error) {
					return RequestPolicy{Config: selected, LoadRedactionPolicy: func() (*redaction.Policy, error) { loads++; return matcher, nil }}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if resolved == nil || compilations != 1 || loads != 1 {
				t.Fatalf("duplicate work: compilations=%d loads=%d", compilations, loads)
			}
			for _, candidate := range []*ResolvedRequest{resolved} {
				encoded, _ := json.Marshal(candidate.RawBody())
				if strings.Contains(string(encoded), "SAVED_PRIVATE") || strings.Contains(string(encoded), "REQUEST_PRIVATE") || strings.Contains(string(encoded), `"policy"`) {
					t.Fatalf("unredacted text or policy reached upstream: %s", encoded)
				}
				if _, known := candidate.EstimatedInputTokens(); !known {
					t.Fatal("request redaction lost token estimation")
				}
			}
			after, _ := json.Marshal(selected)
			if string(original) != string(after) {
				t.Fatal("request changed saved policy")
			}
			delete(raw, "policy")
			body, _ = json.Marshal(raw)
			next, err := ResolveRequest(RequestInput{Body: body, Method: "POST", Path: path, Policy: base, RedactionPolicy: matcher})
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(next.RawBody())
			if !strings.Contains(string(encoded), "REQUEST_PRIVATE") || strings.Contains(string(encoded), "SAVED_PRIVATE") {
				t.Fatal("request plugin leaked into a subsequent request")
			}
		})
	}
}

func TestOrderedCredentialsChooseWithinOneDeployment(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, test := range []struct {
			name                      string
			indexes                   []int
			limit                     int
			firstFails, firstFiltered bool
			want                      int
			attempts                  int
			failed                    bool
		}{
			{name: "preference order", indexes: []int{0, 1}, limit: 1, want: 0, attempts: 1},
			{name: "missing root already excluded", indexes: []int{1}, limit: 1, want: 1, attempts: 1},
			{name: "credential policy excludes first", indexes: []int{0, 1}, limit: 1, firstFiltered: true, want: 1, attempts: 1},
			{name: "failure cannot fall back by default", indexes: []int{0, 1}, limit: 1, firstFails: true, attempts: 1, failed: true},
			{name: "explicit preparation fallback", indexes: []int{0, 1}, limit: 2, firstFails: true, want: 1, attempts: 2},
		} {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				body := `{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]}`
				if path == "/v1/responses" {
					body = `{"model":"openai-gpt-5.6-sol","input":"hello"}`
				}
				attempts, transforms := []int{}, []int{}
				failure := errors.New("unusable selected credential")
				resolved, err := ResolveRequest(RequestInput{
					Body: []byte(body), Method: "POST", Path: path,
					Policy:               policyConfig(test.limit),
					AvailableCredentials: map[string][]int{"openai": test.indexes},
					CredentialPolicy: func(_ schemas.ModelProvider, index int) (RequestPolicy, error) {
						config := policyConfig(test.limit)
						if index == 0 && test.firstFiltered {
							config.Routing.Query = mustRouting(t, "false", nil)
						}
						return RequestPolicy{Config: config, LoadRedactionPolicy: func() (*redaction.Policy, error) {
							transforms = append(transforms, index)
							return redaction.CompilePolicy(redaction.Options{})
						}}, nil
					},
					CheckCandidate: func(_ schemas.ModelProvider, index int, _ Deployment) error {
						attempts = append(attempts, index)
						if index == 0 && test.firstFails {
							return failure
						}
						return nil
					},
				})
				if len(attempts) != test.attempts {
					t.Fatalf("attempts=%v, want %d", attempts, test.attempts)
				}
				if test.failed {
					if !errors.Is(err, failure) || resolved != nil || len(transforms) != 0 {
						t.Fatalf("failed choice transformed or rerouted: %v %v", err, transforms)
					}
				} else if err != nil || resolved.CredentialIndex != test.want || len(transforms) != 1 || transforms[0] != test.want {
					t.Fatalf("selection=%v error=%v transforms=%v", resolved, err, transforms)
				}
			})
		}
	}
}

func TestCredentialOrderCannotChooseBetweenDeployments(t *testing.T) {
	loadTestCatalog(t)
	checks := 0
	_, err := ResolveRequest(RequestInput{
		Body:   []byte(`{"model":"azure/gpt-5.6-sol","messages":[{"role":"user","content":"hello"}],"provider":{"order":["azure"]}}`),
		Method: "POST", Path: "/v1/chat/completions", Policy: policyConfig(2),
		AvailableCredentials: map[string][]int{"azure": {0, 1}},
		CheckCandidate:       func(schemas.ModelProvider, int, Deployment) error { checks++; return nil },
	})
	if PublicError(err).Code != "model_ambiguous" || checks != 0 {
		t.Fatalf("error=%v checks=%d", err, checks)
	}
}

func TestCredentialCompilationBudgetCannotSelectAnotherCandidate(t *testing.T) {
	loadTestCatalog(t)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			body := []byte(`{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]}`)
			if path == "/v1/responses" {
				body = []byte(`{"model":"openai-gpt-5.6-sol","input":"hello"}`)
			}
			loads, checks := 0, 0
			_, err := ResolveRequest(RequestInput{
				Body: body, Method: "POST", Path: path,
				AvailableCredentials: map[string][]int{"openai": {0, 1, 2}},
				CredentialPolicy: func(_ schemas.ModelProvider, index int) (RequestPolicy, error) {
					loads++
					if index == 1 {
						return RequestPolicy{}, policy.ErrSourceBudget
					}
					return RequestPolicy{Config: policyConfig(3)}, nil
				},
				CheckCandidate: func(schemas.ModelProvider, int, Deployment) error { checks++; return nil },
			})
			if PublicError(err).Code != "policy_work_limit_exceeded" || loads != 2 || checks != 0 {
				t.Fatalf("error=%v loads=%d checks=%d", err, loads, checks)
			}
		})
	}
}

func TestRequestCompositionBudgetCannotSkipAnEarlierCredential(t *testing.T) {
	loadTestCatalog(t)
	makeSource := func(identity string, rules, terms int, request bool) []byte {
		definitions := make(map[string]any, rules)
		for index := range rules {
			conditions := make([]string, terms)
			for term := range conditions {
				conditions[term] = fmt.Sprintf("provider.id != 'blocked-%s-%d-%d'", identity, index, term)
			}
			definitions[fmt.Sprintf("rule_%d", index)] = map[string]any{
				"when": strings.Join(conditions, " && "), "input": map[string]bool{"asciiOnly": true},
			}
		}
		document := map[string]any{"rules": definitions}
		if !request {
			document["delegation"] = map[string]bool{"request": true}
		}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	organization, err := policy.CompileSource(makeSource("org", 3, 250, false))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := policy.CompileSource(makeSource("credential", 3, 250, false))
	if err != nil {
		t.Fatal(err)
	}
	large, err := policy.ComposeSources([]policy.ScopedSource{
		{Scope: policy.OrganizationScope, Value: organization},
		{Scope: policy.CredentialScope, Value: credential},
	})
	if err != nil {
		t.Fatal(err)
	}
	small, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: organization}})
	if err != nil {
		t.Fatal(err)
	}
	request := json.RawMessage(makeSource("request", 1, 150, true))
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			document := map[string]any{"model": "openai-gpt-5.6-sol", "policy": request}
			if path == "/v1/responses" {
				document["input"] = "hello"
			} else {
				document["messages"] = []map[string]string{{"role": "user", "content": "hello"}}
			}
			body, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			loads, checks := 0, 0
			_, err = ResolveRequest(RequestInput{
				Body: body, Method: "POST", Path: path,
				AvailableCredentials: map[string][]int{"openai": {0, 1}},
				CredentialPolicy: func(_ schemas.ModelProvider, index int) (RequestPolicy, error) {
					loads++
					config := large
					if index == 1 {
						config = small
					}
					return RequestPolicy{Config: config}, nil
				},
				CheckCandidate: func(schemas.ModelProvider, int, Deployment) error { checks++; return nil },
			})
			if PublicError(err).Code != "policy_work_limit_exceeded" || loads != 1 || checks != 0 {
				t.Fatalf("error=%v loads=%d checks=%d", err, loads, checks)
			}
		})
	}
}

func TestSharedPolicyGroupsPreserveInterleavedCredentialPreference(t *testing.T) {
	loadTestCatalog(t)
	for _, sorted := range []bool{false, true} {
		for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
			t.Run(fmt.Sprintf("sort_%t/%s", sorted, path), func(t *testing.T) {
				first := policyConfig(3)
				if sorted {
					first.Routing.Query = mustRouting(t, "", []policy.Sort{{By: "deployment.id", Direction: "asc"}})
				}
				other := *first
				other.Input = &policy.Input{ASCIIOnly: true}
				configs := []*policy.Config{first, &other, first}
				body := []byte(`{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]}`)
				if path == "/v1/responses" {
					body = []byte(`{"model":"openai-gpt-5.6-sol","input":"hello"}`)
				}
				var attempts, transformed []int
				resolved, err := ResolveRequest(RequestInput{Body: body, Method: "POST", Path: path, AvailableCredentials: map[string][]int{"openai": {0, 1, 2}},
					CredentialPolicy: func(_ schemas.ModelProvider, index int) (RequestPolicy, error) {
						return RequestPolicy{Config: configs[index], LoadRedactionPolicy: func() (*redaction.Policy, error) {
							transformed = append(transformed, index)
							return redaction.CompilePolicy(redaction.Options{})
						}}, nil
					},
					CheckCandidate: func(_ schemas.ModelProvider, index int, _ Deployment) error {
						attempts = append(attempts, index)
						if index < 2 {
							return errors.New("unusable credential")
						}
						return nil
					},
				})
				if err != nil || resolved.CredentialIndex != 2 || !reflect.DeepEqual(attempts, []int{0, 1, 2}) || !reflect.DeepEqual(transformed, []int{2}) {
					t.Fatalf("selection=%v attempts=%v transformations=%v error=%v", resolved, attempts, transformed, err)
				}
				if resolved.policy != nil || resolved.PreDispatchCandidateLimit() != 3 {
					t.Fatal("inference retained the full policy graph or lost its decision")
				}
			})
		}
	}
}

func TestUnreachableCredentialStillParticipatesInRoutingOrderAgreement(t *testing.T) {
	loadTestCatalog(t)
	for _, filtered := range []bool{false, true} {
		checks := 0
		_, err := ResolveRequest(RequestInput{
			Body: []byte(`{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]}`), Method: "POST", Path: "/v1/chat/completions",
			AvailableCredentials: map[string][]int{"openai": {0, 1, 2, 3}},
			CredentialPolicy: func(_ schemas.ModelProvider, index int) (RequestPolicy, error) {
				config := policyConfig(3)
				filter, direction := "true", "asc"
				if index == 3 {
					direction = "desc"
					if filtered {
						filter = "false"
					}
				}
				config.Routing.Query = mustRouting(t, filter, []policy.Sort{{By: "deployment.id", Direction: direction}})
				return RequestPolicy{Config: config}, nil
			},
			CheckCandidate: func(schemas.ModelProvider, int, Deployment) error { checks++; return nil },
		})
		if filtered && (err != nil || checks != 1) || !filtered && (PublicError(err).Code != "invalid_request" || checks != 0) {
			t.Fatalf("filtered=%t checks=%d error=%v", filtered, checks, err)
		}
	}
}

func TestInvalidEncryptedCandidateCannotFallBack(t *testing.T) {
	loadTestCatalog(t)
	for _, phase := range []string{"policy", "credential", "redaction"} {
		for _, failure := range []error{customerkey.ErrKey, customerkey.ErrEnvelope} {
			t.Run(phase+"/"+failure.Error(), func(t *testing.T) {
				prepared, redacted := []int{}, []int{}
				public := APIError{Code: "invalid_encrypted_content", StatusCode: 400, Type: ErrorTypeInvalidRequest, Message: "Invalid encrypted content"}
				failure = errors.Join(failure, public)
				resolved, err := ResolveRequest(RequestInput{
					Body:   []byte(`{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":"private"}]}`),
					Method: "POST", Path: "/v1/chat/completions", Policy: policyConfig(2),
					AvailableCredentials: map[string][]int{"openai": {0, 1}},
					CredentialPolicy: func(_ schemas.ModelProvider, index int) (RequestPolicy, error) {
						if phase == "policy" && index == 0 {
							return RequestPolicy{}, failure
						}
						return RequestPolicy{Config: policyConfig(2), LoadRedactionPolicy: func() (*redaction.Policy, error) {
							redacted = append(redacted, index)
							if phase == "redaction" && index == 0 {
								return nil, failure
							}
							return redaction.CompilePolicy(redaction.Options{})
						}}, nil
					},
					CheckCandidate: func(_ schemas.ModelProvider, index int, _ Deployment) error {
						prepared = append(prepared, index)
						if phase == "credential" && index == 0 {
							return failure
						}
						return nil
					},
				})
				if resolved != nil || !errors.Is(err, failure) || PublicError(err).Code != public.Code {
					t.Fatalf("cryptographic error did not terminate with its public error: result=%v error=%v", resolved, err)
				}
				for _, indexes := range [][]int{prepared, redacted} {
					for _, index := range indexes {
						if index != 0 {
							t.Fatal("tried a fallback after invalid encrypted content")
						}
					}
				}
			})
		}
	}
}
