package catalog

import (
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// A request that keeps or reads state in its provider account routes only to OpenAI's own API,
// only through a customer's credential, and, when it reads what one account holds, only where one
// credential can serve it. Its data handling and its policy fields say what the provider keeps.
func TestRoutingSendsProviderStateOnlyThroughCustomerAccounts(t *testing.T) {
	// Stogas serves this deployment with its own account too, so its credentials reach it.
	loadTestCatalog(t).graph.Deployments["openai-gpt-5.6-sol"].StogasManaged = true
	customer := func(schemas.ModelProvider, int) string { return CredentialStored }
	for _, tc := range []struct {
		name, body, policy string
		credentials        map[string][]int
		kind               func(schemas.ModelProvider, int) string
		// zeroRetention gives the first OpenAI credential an account with zero data retention.
		zeroRetention bool
		want          ProviderState
		wantErr       string
	}{
		{name: "a stored reply", body: `"store":true`, want: ProviderState{Fields: []string{"store"}, Store: true, Keeps: true}},
		{name: "a stored reply on an account with zero data retention", body: `"store":true`, zeroRetention: true,
			want: ProviderState{Fields: []string{"store"}, Store: true, Keeps: true}},
		// A continuation stores its reply, as OpenAI's default does, unless the client says not to.
		{name: "a continued reply", body: `"previous_response_id":"resp_1"`,
			want: ProviderState{Fields: []string{"store", "previous_response_id"}, Store: true, Keeps: true, Held: "previous_response_id"}},
		{name: "a continued reply that stores nothing", body: `"previous_response_id":"resp_1","store":false`,
			want: ProviderState{Fields: []string{"previous_response_id"}, Held: "previous_response_id"}},
		// A conversation keeps each turn, whatever store says.
		{name: "a conversation", body: `"conversation":{"id":"conv_1"},"store":false`,
			want: ProviderState{Fields: []string{"conversation"}, Keeps: true, Held: "conversation"}},
		{name: "null and empty continuations", body: `"previous_response_id":"","conversation":null,"store":null`},
		{name: "Stogas credentials", body: `"store":true`, kind: func(schemas.ModelProvider, int) string { return CredentialManaged },
			wantErr: "store needs your own provider credential, because Stogas's provider accounts keep nothing for a request. Omit store or set it to false."},
		{name: "two customer credentials", body: `"previous_response_id":"resp_1"`, credentials: map[string][]int{"openai": {0, 1}},
			wantErr: "previous_response_id names content that one provider account holds, and this request can use 2 credentials; use a key with one credential for this model"},
		{name: "two customer credentials for a stored reply", body: `"store":true`, credentials: map[string][]int{"openai": {0, 1}},
			want: ProviderState{Fields: []string{"store"}, Store: true, Keeps: true}},
		{name: "a policy that checks input", body: `"conversation":"conv_1"`, policy: `{"input":{"asciiOnly":true}}`,
			wantErr: "conversation names content that your provider account holds, which input.asciiOnly cannot check. Send the whole conversation in input."},
		{name: "a policy that refuses stored content", body: `"store":true`, policy: `{"routing":{"filter":"!request.store"}}`,
			wantErr: ErrModelUnavailable.Message},
		{name: "a policy that refuses held input", body: `"previous_response_id":"resp_1","store":false`, policy: `{"routing":{"filter":"!request.storedInput"}}`,
			wantErr: ErrModelUnavailable.Message},
		{name: "a policy that lets a reply be stored", body: `"store":true`, policy: `{"routing":{"filter":"request.store && !request.storedInput"}}`,
			want: ProviderState{Fields: []string{"store"}, Store: true, Keeps: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := policyConfig(1)
			if tc.policy != "" {
				config = composedPolicy(t, tc.policy)
			}
			credentials, kind := tc.credentials, tc.kind
			if credentials == nil {
				credentials = map[string][]int{"openai": {0}}
			}
			if kind == nil {
				kind = customer
			}
			resolved, err := ResolveRequest(RequestInput{
				Body:   []byte(`{"model":"openai-gpt-5.6-sol","input":"hi",` + tc.body + `}`),
				Method: "POST", Path: "/v1/responses", Policy: config, AvailableCredentials: credentials, CredentialKind: kind,
				CredentialOptions: func(_ schemas.ModelProvider, index int) []HeldOption {
					if tc.zeroRetention && index == 0 {
						return []HeldOption{{ID: "zero-data-retention"}}
					}
					return nil
				},
			})
			if tc.wantErr != "" {
				if public := PublicError(err); public.StatusCode != 400 || !strings.Contains(public.Message, tc.wantErr) {
					t.Fatalf("want %q: %+v", tc.wantErr, public)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			state := resolved.ProviderState()
			if !slices.Equal(state.Fields, tc.want.Fields) || state.Store != tc.want.Store || state.Keeps != tc.want.Keeps || state.Held != tc.want.Held {
				t.Fatalf("provider state %+v, want %+v", state, tc.want)
			}
			// What the provider keeps stays as long as the provider decides, whatever the account.
			if handling := resolved.EffectiveDataHandling(); state.Keeps &&
				(handling.RetentionDays != nil || handling.ZeroDataRetention || handling.StorageLocation == "none") {
				t.Fatalf("data handling %+v of a request that keeps its content", handling)
			}
			// The gateway never sees held content, so the hold covers the whole input.
			if full := resolved.InputTokenLimit() == resolved.Deployment.MaxInputTokens; full != (state.Held != "") {
				t.Fatalf("input hold %d of %d, held content %q", resolved.InputTokenLimit(), resolved.Deployment.MaxInputTokens, state.Held)
			}
		})
	}
}

// Provider state needs OpenAI's own API, which neither another provider nor the translation of
// another interface carries.
func TestRoutingRefusesProviderStateWhereNoDeploymentKeepsIt(t *testing.T) {
	loadTestCatalog(t)
	for _, tc := range []struct{ name, path, body, want string }{
		{"Claude", "/v1/responses", `{"model":"anthropic-claude-sonnet-5-5","input":"hi","previous_response_id":"resp_1"}`,
			"previous_response_id needs one of OpenAI's models on OpenAI or Azure, which keep it in your provider account. Send the whole conversation in input."},
		{"Chutes", "/v1/chat/completions", `{"model":"chutes-glm-5.2","messages":[{"role":"user","content":"hi"}],"store":true}`,
			"store needs one of OpenAI's models on OpenAI or Azure, which keep it in your provider account. Omit store or set it to false."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveRequest(RequestInput{Body: []byte(tc.body), Method: "POST", Path: tc.path, Policy: policyConfig(1)})
			public := PublicError(err)
			if public.StatusCode != 400 || public.Code != ProviderStateUnsupported || public.Message != tc.want {
				t.Fatalf("want %q: %+v", tc.want, public)
			}
		})
	}
}
