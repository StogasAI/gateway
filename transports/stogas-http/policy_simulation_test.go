package stogashttp

import (
	"net/http"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestPolicySimulationTakesToolTypesAlone(t *testing.T) {
	for _, test := range []struct {
		name, body string
		valid      bool
	}{
		{"types and an allowed_tools choice", `{"interface":"responses","tools":["function","web_search_20250305"],"toolChoice":{"type":"allowed_tools","tools":[{"type":"function"}]}}`, true},
		{"a mode", `{"interface":"responses","tools":["mcp"],"toolChoice":"none"}`, true},
		{"Chat Completions", `{"interface":"chat_completions","tools":["web_search"]}`, false},
		{"an empty type", `{"interface":"responses","tools":[""]}`, false},
		{"a tool definition", `{"interface":"responses","tools":[{"type":"web_search"}]}`, false},
		{"a function name", `{"interface":"responses","toolChoice":{"type":"function","name":"lookup"}}`, false},
		{"tools outside allowed_tools", `{"interface":"responses","toolChoice":{"type":"auto","tools":[]}}`, false},
		{"null", `{"interface":"responses","toolChoice":null}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{memory: newRequestMemoryAdmission()}
			ctx := newTestRequest(t)
			ctx.memory.release()
			ctx.request.Method = http.MethodPost
			testRequestURI(ctx, policySimulationPath)
			testRequestBody(ctx, test.body)
			ctx.memory, _ = server.memory.acquire(cap(ctx.body))
			t.Cleanup(ctx.memory.release)
			ctx.credential = &apiCredential{Dashboard: &billing.DashboardCredential{}}
			server.simulatePolicy(ctx)
			// Without a runtime, a valid simulation stops when it needs the key's configuration.
			if rejected := testResponse(ctx).Code == http.StatusBadRequest; rejected == test.valid {
				t.Fatalf("status %d: %s", testResponse(ctx).Code, testResponse(ctx).Body.String())
			}
		})
	}
}
