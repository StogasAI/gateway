package catalog

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestRequestFactsListToolsServersAndSystemMessages(t *testing.T) {
	const responsesTools = `[{"type":"function","name":"lookup","parameters":{}},{"type":"custom","name":"run_sql"},{"type":"web_search"},` +
		`{"type":"mcp","server_label":"docs","server_url":"https://MCP.Example.com.:8443/sse?key=secret","allowed_tools":["search","fetch"]},` +
		`{"type":"mcp","server_label":"drive","connector_id":"Connector_GoogleDrive","allowed_tools":{"read_only":true}},` +
		`{"type":"mcp","server_label":"bücher","server_url":"https://bücher.example/mcp","allowed_tools":{"tool_names":["find"],"read_only":true}},` +
		`{"type":"mcp","server_label":"local","tunnel_id":"tun_1","allowed_tools":[]},` +
		`{"type":"mcp","server_label":"broken","server_url":"not a url"},` +
		`{"type":"mcp","server_label":"both","server_url":"https://allowed.example/mcp","tunnel_id":"TUN_2","allowed_tools":["read"]}]`
	const chatTools = `[{"type":"function","function":{"name":"lookup","parameters":{}}},{"type":"function","function":{"name":"lookup"}}]`
	// An ID carries its field's prefix, so a URL whose host spells a connector's ID stays a host.
	servers := []string{"", "allowed.example", "connector:connector_googledrive", "mcp.example.com", "tunnel:tun_1", "tunnel:tun_2", "xn--bcher-kva.example"}
	serverTools := []string{"/*", "allowed.example/read", "connector:connector_googledrive/*", "mcp.example.com/fetch", "mcp.example.com/search",
		"tunnel:tun_1/*", "tunnel:tun_2/read", "xn--bcher-kva.example/find"}
	for _, test := range []struct {
		name                               string
		route                              Route
		body                               string
		client, servers, tools, unattended []string
		system                             bool
	}{
		{name: "every tool", route: RouteResponses, body: `{"tools":` + responsesTools + `}`,
			client: []string{"lookup", "run_sql"}, servers: servers, tools: serverTools},
		// The provider can connect to a listed server whatever tool_choice says.
		{name: "no callable tool", route: RouteResponses, body: `{"tools":` + responsesTools + `,"tool_choice":"none"}`, servers: servers, tools: serverTools},
		{name: "a URL that spells a connector", route: RouteResponses,
			body:    `{"tools":[{"type":"mcp","server_label":"a","server_url":"https://connector_gmail/mcp"},{"type":"mcp","server_label":"b","server_url":"https://[connector:gmail]/mcp"}]}`,
			servers: []string{"", "connector_gmail"}, tools: []string{"/*", "connector_gmail/*"}},
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
		{name: "functions named as hosted tools stay client tools", route: RouteResponses,
			body:   `{"tools":[{"type":"function","name":"web_search","parameters":{}},{"type":"custom","name":"web_fetch"}]}`,
			client: []string{"web_fetch", "web_search"}},
		{name: "a forced function counts every function", route: RouteResponses,
			body: `{"tools":` + responsesTools + `,"tool_choice":{"type":"function","name":"lookup"}}`, client: []string{"lookup"}, servers: servers, tools: serverTools},
		{name: "shell and apply_patch by their types", route: RouteResponses,
			body:   `{"tools":[{"type":"function","name":"lookup"},{"type":"shell","environment":{"type":"local"}},{"type":"apply_patch"}]}`,
			client: []string{"apply_patch", "lookup", "shell"}},
		{name: "a forced shell leaves the other types out", route: RouteResponses,
			body:   `{"tools":[{"type":"function","name":"lookup"},{"type":"shell"},{"type":"apply_patch"}],"tool_choice":{"type":"shell"}}`,
			client: []string{"shell"}},
		{name: "allowed MCP tools count every server", route: RouteResponses,
			body: `{"tools":[{"type":"function","name":"lookup"},{"type":"mcp","server_label":"a","server_url":"https://a.example/mcp"},` +
				`{"type":"mcp","server_label":"b","server_url":"https://b.example/mcp"}],` +
				`"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"mcp","server_label":"a"}]}}`,
			servers: []string{"a.example", "b.example"}, tools: []string{"a.example/*", "b.example/*"}},
		// A server counts when require_approval frees any of its calls, whatever tool_choice says.
		{name: "servers that run calls without approval", route: RouteResponses,
			body: `{"tool_choice":"none","tools":[{"type":"mcp","server_label":"a","server_url":"https://a.example/mcp","require_approval":"never"},` +
				`{"type":"mcp","server_label":"b","connector_id":"connector_gmail","require_approval":{"never":{"read_only":true}}},` +
				`{"type":"mcp","server_label":"c","server_url":"https://c.example/mcp","require_approval":{"always":{"tool_names":["delete"]}}},` +
				`{"type":"mcp","server_label":"d","server_url":"https://d.example/mcp","require_approval":"always"},` +
				`{"type":"mcp","server_label":"e","server_url":"https://e.example/mcp"}]}`,
			servers:    []string{"a.example", "c.example", "connector:connector_gmail", "d.example", "e.example"},
			tools:      []string{"a.example/*", "c.example/*", "connector:connector_gmail/*", "d.example/*", "e.example/*"},
			unattended: []string{"a.example", "connector:connector_gmail"}},
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
			for _, list := range []struct {
				name      string
				got, want []string
			}{{"client tools", facts.clientTools, test.client}, {"MCP servers", facts.mcpServers, test.servers}, {"MCP tools", facts.mcpTools, test.tools},
				{"MCP servers without approval", facts.mcpUnattended, test.unattended}} {
				// Policies read an empty list, never a missing one.
				if list.got == nil || !slices.Equal(list.got, append([]string{}, list.want...)) {
					t.Fatalf("%s %q, want %q", list.name, list.got, list.want)
				}
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

	// A simulation names no tool or server, and sends no system message.
	simulation := SimulateRouting(RequestInput{AvailableCredentials: anthropic, Policy: compile(`size(request.clientTools) == 0 && !request.systemMessages`)},
		RouteResponses, deployment, "", "", []string{"function"}, nil)
	if simulation.Err != nil || len(simulation.Pairs) == 0 {
		t.Fatalf("simulation %v with %d pairs", simulation.Err, len(simulation.Pairs))
	}
}

// Policies that compare these fields with a string that they can never hold fail at save.
func TestRequestToolFieldsRefuseImpossibleValues(t *testing.T) {
	for _, filter := range []string{
		`'MCP.example.com' in request.mcpServers`,
		`'https://mcp.example.com' in request.mcpServers`,
		`'mcp.example.com' in request.mcpTools`,
		`request.mcpTools.exists(tool, tool == 'search')`,
	} {
		document, _ := json.Marshal(map[string]any{"routing": map[string]any{"filter": filter}})
		if _, err := policy.CompileSource(document); err == nil {
			t.Fatalf("%s compiled", filter)
		}
	}
	for _, filter := range []string{
		`request.mcpServers.all(server, server == 'mcp.example.com' || server.endsWith('.example.com'))`,
		`!request.mcpTools.exists(tool, tool.endsWith('/*') || tool == 'mcp.example.com/delete_repo')`,
		`request.clientTools.all(name, name.matches('^(get|list)_'))`,
		`request.systemMessages`,
	} {
		document, _ := json.Marshal(map[string]any{"routing": map[string]any{"filter": filter}})
		if _, err := policy.CompileSource(document); err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
	}
}
