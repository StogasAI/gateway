package catalog

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestRequestFactsListToolsAndSystemMessages(t *testing.T) {
	const responsesTools = `[{"type":"function","name":"lookup","parameters":{}},{"type":"custom","name":"run_sql"},{"type":"web_search"}]`
	const chatTools = `[{"type":"function","function":{"name":"lookup","parameters":{}}},{"type":"function","function":{"name":"lookup"}}]`
	for _, test := range []struct {
		name   string
		route  Route
		body   string
		client []string
		system bool
	}{
		{name: "every tool", route: RouteResponses, body: `{"tools":` + responsesTools + `}`, client: []string{"lookup", "run_sql"}},
		{name: "no callable tool", route: RouteResponses, body: `{"tools":` + responsesTools + `,"tool_choice":"none"}`},
		{name: "namespace tools by their own names", route: RouteResponses,
			body: `{"tools":[{"type":"function","name":"lookup"},{"type":"namespace","name":"functions","description":"","tools":[{"type":"function","name":"exec"}]},` +
				`{"type":"namespace","name":"crm","description":"CRM tools.","tools":[{"type":"function","name":"find"},{"type":"custom","name":"note"}]}]}`,
			client: []string{"exec", "find", "lookup", "note"}},
		// A search that the client runs can load tools that the request does not declare.
		{name: "tools that a tool search loaded", route: RouteResponses,
			body: `{"tools":[{"type":"function","name":"lookup"}],"input":[{"type":"tool_search_output","call_id":"call_1","execution":"client","tools":[` +
				`{"type":"namespace","name":"crm","description":"CRM tools.","tools":[{"type":"function","name":"find"},{"type":"custom","name":"note"}]},{"type":"function","name":"run_shell"}]}]}`,
			client: []string{"find", "lookup", "note", "run_shell"}},
		{name: "a loaded tool whose item type JSON escapes", route: RouteResponses,
			body:   `{"input":[{"type":"tool_search\u005foutput","tools":[{"type":"function","name":"run_shell"}]}]}`,
			client: []string{"run_shell"}},
		{name: "a forced function counts every function", route: RouteResponses,
			body: `{"tools":` + responsesTools + `,"tool_choice":{"type":"function","name":"lookup"}}`, client: []string{"lookup"}},
		{name: "shell and apply_patch by their types", route: RouteResponses,
			body:   `{"tools":[{"type":"function","name":"lookup"},{"type":"shell","environment":{"type":"local"}},{"type":"apply_patch"}]}`,
			client: []string{"apply_patch", "lookup", "shell"}},
		{name: "a forced shell leaves the other types out", route: RouteResponses,
			body:   `{"tools":[{"type":"function","name":"lookup"},{"type":"shell"},{"type":"apply_patch"}],"tool_choice":{"type":"shell"}}`,
			client: []string{"shell"}},
		{name: "allowed tools count every function", route: RouteResponses,
			body: `{"tools":[{"type":"function","name":"lookup"},{"type":"function","name":"find"},{"type":"custom","name":"note"}],` +
				`"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"function","name":"lookup"}]}}`,
			client: []string{"find", "lookup"}},
		{name: "instructions", route: RouteResponses, body: `{"instructions":"Answer briefly.","input":"hi"}`, system: true},
		{name: "empty instructions", route: RouteResponses, body: `{"instructions":"","input":"hi"}`},
		{name: "a developer message", route: RouteResponses, body: `{"input":[{"role":"developer","content":"Be brief."},{"role":"user","content":"hi"}]}`,
			system: true},
		{name: "a user message", route: RouteResponses, body: `{"input":[{"role":"user","content":"hi"}]}`},
		{name: "Chat functions, once each", route: RouteChat, body: `{"tools":` + chatTools + `,"messages":[{"role":"system","content":"x"}]}`,
			client: []string{"lookup"}, system: true},
		{name: "Chat with tool_choice none", route: RouteChat, body: `{"tools":` + chatTools + `,"tool_choice":"none"}`},
		{name: "legacy Chat functions", route: RouteChat, body: `{"functions":[{"name":"old"}],"messages":[{"role":"user","content":"x"}]}`,
			client: []string{"old"}},
		{name: "legacy Chat functions turned off", route: RouteChat, body: `{"functions":[{"name":"old"}],"function_call":"none"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(test.body), &raw); err != nil {
				t.Fatal(err)
			}
			facts := readRequestTools(test.route, raw).facts
			// Policies read an empty list, never a missing one.
			if facts.clientTools == nil || !slices.Equal(facts.clientTools, append([]string{}, test.client...)) {
				t.Fatalf("client tools %q, want %q", facts.clientTools, test.client)
			}
			if got := facts.systemMessages(); got != test.system {
				t.Fatalf("system messages %v, want %v", got, test.system)
			}
		})
	}
}

func TestPoliciesReadRequestToolsAndMessages(t *testing.T) {
	loadTestCatalog(t)
	compile := func(filter string) *policy.Config {
		t.Helper()
		document, _ := json.Marshal(map[string]any{"routing": map[string]any{"filter": filter}})
		source, err := policy.CompileSource(document)
		if err != nil {
			t.Fatal(err)
		}
		config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	noShell := compile(`!('run_shell' in request.clientTools)`)
	noClientTools := compile(`size(request.clientTools) == 0`)
	noSystem := compile(`!request.systemMessages`)
	anthropic := map[string][]int{"anthropic": {0}}
	const deployment = "anthropic-claude-fable-5-1"
	for _, test := range []struct {
		name   string
		config *policy.Config
		body   string
		want   string
	}{
		{name: "a denied function", config: noShell,
			body: `{"model":"` + deployment + `","input":"hi","tools":[{"type":"function","name":"run_shell","parameters":{}}]}`, want: "model_unavailable"},
		{name: "another function", config: noShell,
			body: `{"model":"` + deployment + `","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{}}]}`, want: deployment},
		{name: "a denied function the model cannot call", config: noClientTools,
			body: `{"model":"` + deployment + `","input":"hi","tools":[{"type":"function","name":"run_shell","parameters":{}}],"tool_choice":"none"}`,
			want: deployment},
		{name: "instructions", config: noSystem, body: `{"model":"` + deployment + `","input":"hi","instructions":"Be brief."}`, want: "model_unavailable"},
		{name: "a system message", config: noSystem,
			body: `{"model":"` + deployment + `","input":[{"role":"system","content":"Be brief."},{"role":"user","content":"hi"}]}`, want: "model_unavailable"},
		{name: "user messages alone", config: noSystem, body: `{"model":"` + deployment + `","input":[{"role":"user","content":"hi"}]}`, want: deployment},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := ResolveRequest(RequestInput{Body: []byte(test.body), Method: "POST", Path: "/v1/responses",
				Policy: test.config, AvailableCredentials: anthropic})
			got := ""
			if err != nil {
				got = PublicError(err).Code
			} else {
				got = resolved.Deployment.ID
			}
			if got != test.want {
				t.Fatalf("got %s (%v), want %s", got, err, test.want)
			}
		})
	}

	// A simulation names no tool, and sends no system message.
	simulation := SimulateRouting(RequestInput{AvailableCredentials: anthropic, Policy: compile(`size(request.clientTools) == 0 && !request.systemMessages`)},
		RouteResponses, deployment, "", "", []string{"function"}, nil)
	if simulation.Err != nil || len(simulation.Pairs) == 0 {
		t.Fatalf("simulation %v with %d pairs", simulation.Err, len(simulation.Pairs))
	}
}

// Policies that compare these fields with a string that they can never hold fail at save.
func TestRequestToolFieldsRefuseImpossibleValues(t *testing.T) {
	for _, filter := range []string{
		`'mcp' in request.hostedTools`,
		`request.hostedTools.exists(tool, tool == 'code_interpreter')`,
	} {
		document, _ := json.Marshal(map[string]any{"routing": map[string]any{"filter": filter}})
		if _, err := policy.CompileSource(document); err == nil {
			t.Fatalf("%s compiled", filter)
		}
	}
	for _, filter := range []string{
		`request.hostedTools.all(tool, tool == 'web_search')`,
		`request.clientTools.all(name, name.matches('^(get|list)_'))`,
		`request.systemMessages`,
	} {
		document, _ := json.Marshal(map[string]any{"routing": map[string]any{"filter": filter}})
		if _, err := policy.CompileSource(document); err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
	}
}
