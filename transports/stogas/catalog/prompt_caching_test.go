package catalog

import (
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestResolvedRequestKeepsPromptCaching(t *testing.T) {
	for _, test := range []struct {
		name, model, provider, policy, want string
	}{
		{"a deployment that caches only marked prompts", "anthropic-claude-opus-4-8", "anthropic", `{"plugins":{"promptCaching":"1h"}}`, "1h"},
		{"no setting", "anthropic-claude-opus-4-8", "anthropic", `{}`, ""},
		{"off", "anthropic-claude-opus-4-8", "anthropic", `{"plugins":{"promptCaching":"off"}}`, ""},
		{"a deployment that caches on its own", "openai-gpt-5.6-sol", "openai", `{"plugins":{"promptCaching":"5m"}}`, ""},
		// A rule decides for each candidate, so one provider's deployments can get their own setting.
		{"a rule for the provider", "anthropic-claude-fable-5-1", "anthropic", `{"rules":{"claude":{"when":"provider.id == 'anthropic'","plugins":{"promptCaching":"1h"}}}}`, "1h"},
		{"a rule for another provider", "aws-claude-fable-5-1", "aws", `{"rules":{"claude":{"when":"provider.id == 'anthropic'","plugins":{"promptCaching":"1h"}}}}`, ""},
		{"a rule beside a default", "anthropic-claude-fable-5-1", "anthropic", `{"rules":{"default_caching":{"mode":"default","plugins":{"promptCaching":"5m"}},"claude":{"when":"provider.id == 'anthropic'","plugins":{"promptCaching":"1h"}}}}`, "1h"},
		{"a default where the rule does not match", "aws-claude-fable-5-1", "aws", `{"rules":{"default_caching":{"mode":"default","plugins":{"promptCaching":"5m"}},"claude":{"when":"provider.id == 'anthropic'","plugins":{"promptCaching":"1h"}}}}`, "5m"},
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
				AvailableCredentials: map[string][]int{test.provider: {0}},
				Body:                 []byte(`{"model":"` + test.model + `","input":"hello"}`),
				Method:               "POST",
				Path:                 "/v1/responses",
				Policy:               config,
			})
			if err != nil || resolved.Deployment.ID != test.model {
				t.Fatalf("resolved %#v, %v", resolved, err)
			}
			if got := resolved.PromptCaching(); got != test.want {
				t.Fatalf("prompt caching = %q, want %q", got, test.want)
			}
		})
	}
}
