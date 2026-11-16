package stogashttp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// A stored credential's request holds only the fields of its use, as one JSON object. Control
// sends no other, so anything else is a mistake that the gateway refuses before it opens a secret.
func TestStoredByokRequestsTakeOnlyTheirFields(t *testing.T) {
	const (
		account      = `"azureAccountId":"/subscriptions/00000000-0000-4000-8000-000000000003/resourcegroups/stogas/providers/microsoft.cognitiveservices/accounts/stogas-east"`
		subscription = `"subscriptionIds":["00000000-0000-4000-8000-000000000003"]`
	)
	grant := &billing.StoredByokGrant{
		OrganizationID: "0196f0f4-0000-7000-8000-000000000001", ByokID: "0196f0f4-0000-7000-8000-000000000002",
		Provider: "azure", Scope: billing.StoredByokCheck,
	}
	for _, test := range []struct {
		name, path, body string
		valid            bool
	}{
		{"a check", storedByokCheckPath, `{"secret":"v1.a.b"}`, true},
		{"an Azure check", storedByokCheckPath, `{"secret":"v1.a.b",` + account + `,"startedAt":"2026-11-03T12:00:00.123Z"}`, true},
		{"an account listing", storedAzureAccountsPath, `{"secret":"v1.a.b",` + subscription + "}\n", true},
		{"an unknown field", storedByokCheckPath, `{"secret":"v1.a.b","provider":"openai"}`, false},
		{"a listing's field in a check", storedByokCheckPath, `{"secret":"v1.a.b",` + subscription + `}`, false},
		{"a check's field in a listing", storedAzureAccountsPath, `{"secret":"v1.a.b",` + subscription + `,` + account + `}`, false},
		{"a second value", storedByokCheckPath, `{"secret":"v1.a.b"} {}`, false},
		{"trailing text", storedByokCheckPath, `{"secret":"v1.a.b"}x`, false},
		{"an array", storedByokCheckPath, `[{"secret":"v1.a.b"}]`, false},
		{"a start that is not a time", storedByokCheckPath, `{"secret":"v1.a.b","startedAt":"yesterday"}`, false},
		{"a query", storedByokCheckPath + "?debug=1", `{"secret":"v1.a.b"}`, false},
		{"over 16 KiB", storedByokCheckPath, `{"secret":"` + strings.Repeat("a", storedByokMaxBody) + `"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := newTestRequest(t)
			ctx.request.Method = http.MethodPost
			testRequestURI(ctx, test.path)
			testRequestBody(ctx, test.body)
			ctx.credential = &apiCredential{Stored: grant}
			server := &Server{}
			if strings.HasPrefix(test.path, storedByokCheckPath) {
				server.checkStoredByok(ctx)
			} else {
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
