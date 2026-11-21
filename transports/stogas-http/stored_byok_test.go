package stogashttp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// A request to use a sealed secret holds only the fields of its use, as one JSON object. Control
// sends no other, so anything else is a mistake that the gateway refuses before it opens a secret.
func TestStoredByokRequestsTakeOnlyTheirFields(t *testing.T) {
	const (
		account      = `"azureAccountId":"/subscriptions/00000000-0000-4000-8000-000000000003/resourcegroups/stogas/providers/microsoft.cognitiveservices/accounts/stogas-east"`
		subscription = `"subscriptionIds":["00000000-0000-4000-8000-000000000003"]`
	)
	grant := &billing.StoredByokGrant{
		OrganizationID: "0196f0f4-0000-7000-8000-000000000001", ByokID: "0196f0f4-0000-7000-8000-000000000002",
		Provider: "azure", Scope: billing.StoredByokProbe,
	}
	for _, test := range []struct {
		name, path, body string
		valid            bool
	}{
		{"a probe", storedByokProbePath, `{"secret":"v1.a.b"}`, true},
		{"an Azure probe", storedByokProbePath, `{"secret":"v1.a.b",` + account + `}`, true},
		{"an account listing", storedAzureAccountsPath, `{"secret":"v1.a.b",` + subscription + "}\n", true},
		{"an unknown field", storedByokProbePath, `{"secret":"v1.a.b","provider":"openai"}`, false},
		{"a check's start in a probe", storedByokProbePath, `{"secret":"v1.a.b","startedAt":"2026-11-03T12:00:00.123Z"}`, false},
		{"a listing's field in a probe", storedByokProbePath, `{"secret":"v1.a.b",` + subscription + `}`, false},
		{"a probe's field in a listing", storedAzureAccountsPath, `{"secret":"v1.a.b",` + subscription + `,` + account + `}`, false},
		{"a second value", storedByokProbePath, `{"secret":"v1.a.b"} {}`, false},
		{"trailing text", storedByokProbePath, `{"secret":"v1.a.b"}x`, false},
		{"an array", storedByokProbePath, `[{"secret":"v1.a.b"}]`, false},
		{"no body", storedByokProbePath, ``, false},
		{"a query", storedByokProbePath + "?debug=1", `{"secret":"v1.a.b"}`, false},
		{"over 16 KiB", storedByokProbePath, `{"secret":"` + strings.Repeat("a", storedByokMaxBody) + `"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestRequest(t)
			ctx.request.Method = http.MethodPost
			testRequestURI(ctx, test.path)
			testRequestBody(ctx, test.body)
			ctx.credential = &apiCredential{Stored: grant}
			server := &Server{}
			switch path, _, _ := strings.Cut(test.path, "?"); path {
			case storedByokProbePath:
				server.probeStoredByok(ctx)
			default:
				server.listStoredAzureAccounts(ctx)
			}
			// Without a runtime, a request that parses stops where it needs the gateway's keys.
			response := testResponse(ctx)
			want, code := http.StatusBadRequest, `"invalid_request"`
			if test.valid {
				want, code = http.StatusServiceUnavailable, `"gateway_unavailable"`
			}
			if response.Code != want || !strings.Contains(response.Body.String(), code) {
				t.Fatalf("status %d: %s", response.Code, response.Body.String())
			}
		})
	}
}
