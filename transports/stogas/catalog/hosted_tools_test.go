package catalog

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestRequestHostedToolsFollowToolChoice(t *testing.T) {
	const tools = `[{"type":"function","name":"lookup","parameters":{}},{"type":"web_search_20250305"},{"type":"web_fetch"},{"type":"mcp","server_label":"docs","server_url":"https://example.com"}]`
	all := []HostedTool{HostedToolWebSearch, HostedToolWebFetch, HostedToolMCP}
	for _, test := range []struct {
		name            string
		route           Route
		body            string
		listed, enabled []HostedTool
	}{
		{name: "every listed tool", route: RouteResponses, body: `{"tools":` + tools + `}`, listed: all, enabled: all},
		{name: "auto", route: RouteResponses, body: `{"tools":` + tools + `,"tool_choice":"auto"}`, listed: all, enabled: all},
		{name: "required", route: RouteResponses, body: `{"tools":` + tools + `,"tool_choice":"required"}`, listed: all, enabled: all},
		{name: "none", route: RouteResponses, body: `{"tools":` + tools + `,"tool_choice":"none"}`, listed: all},
		{name: "a forced function", route: RouteResponses, body: `{"tools":` + tools + `,"tool_choice":{"type":"function","name":"lookup"}}`, listed: all},
		{name: "a forced tool", route: RouteResponses, body: `{"tools":` + tools + `,"tool_choice":{"type":"web_fetch"}}`, listed: all,
			enabled: []HostedTool{HostedToolWebFetch}},
		{name: "allowed tools", route: RouteResponses,
			body:   `{"tools":` + tools + `,"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"mcp","server_label":"docs"},{"type":"web_search"}]}}`,
			listed: all, enabled: []HostedTool{HostedToolWebSearch, HostedToolMCP}},
		{name: "a preview search, once", route: RouteResponses, body: `{"tools":[{"type":"web_search_preview"},{"type":"web_search"}]}`,
			listed: []HostedTool{HostedToolWebSearch}, enabled: []HostedTool{HostedToolWebSearch}},
		{name: "function tools alone", route: RouteResponses, body: `{"tools":[{"type":"function","name":"lookup","parameters":{}}]}`},
		{name: "tools that do not parse", route: RouteResponses, body: `{"tools":{"type":"web_search"}}`},
		{name: "Chat Completions", route: RouteChat, body: `{"tools":` + tools + `}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(test.body), &raw); err != nil {
				t.Fatal(err)
			}
			use := requestHostedTools(test.route, raw)
			if !slices.Equal(use.listed, test.listed) || !slices.Equal(use.enabled, test.enabled) {
				t.Fatalf("listed %v and enabled %v, want %v and %v", use.listed, use.enabled, test.listed, test.enabled)
			}
		})
	}
}

func TestEffectiveDataHandlingOnlyWorsens(t *testing.T) {
	loadTestCatalog(t)
	places := activeState().places
	days := func(value int) *int { return &value }
	yes, no := true, false
	deployment := Deployment{
		DataHandling: DataHandling{ProcessingLocation: "US", StorageLocation: "none", RetentionDays: days(0),
			ZeroDataRetention: true, EndToEndEncrypted: true, TEE: true, TEEVerified: true},
		Locations: places,
		HostedTools: map[HostedTool]HostedToolOffer{
			HostedToolWebSearch: {DataHandling: HostedToolDataHandling{ProcessingLocation: "DE", RetentionDays: RetentionEffect{Set: true, Days: days(30)}}},
			HostedToolWebFetch: {DataHandling: HostedToolDataHandling{ProcessingLocation: "unknown", StorageLocation: "unknown",
				RetentionDays: RetentionEffect{Set: true}, ZeroDataRetention: &no}},
			HostedToolMCP: {DataHandling: HostedToolDataHandling{TrainingUse: &yes, EndToEndEncrypted: &no, TEE: &no, TEEVerified: &no}},
		},
	}
	if got := deployment.EffectiveDataHandling(nil); !reflect.DeepEqual(got, deployment.DataHandling) {
		t.Fatalf("no tools changed data handling: %+v", got)
	}
	search := deployment.EffectiveDataHandling([]HostedTool{HostedToolWebSearch})
	if search.ProcessingLocation != "world" || search.StorageLocation != "none" || search.RetentionDays == nil || *search.RetentionDays != 30 ||
		!search.ZeroDataRetention || !search.TEEVerified {
		t.Fatalf("web search: %+v", search)
	}
	fetch := deployment.EffectiveDataHandling([]HostedTool{HostedToolWebSearch, HostedToolWebFetch})
	if fetch.ProcessingLocation != "unknown" || fetch.StorageLocation != "unknown" || fetch.RetentionDays != nil || fetch.ZeroDataRetention {
		t.Fatalf("web fetch: %+v", fetch)
	}
	mcp := deployment.EffectiveDataHandling([]HostedTool{HostedToolMCP})
	if mcp.ProcessingLocation != "US" || !mcp.TrainingUse || mcp.EndToEndEncrypted || mcp.TEE || mcp.TEEVerified || !mcp.ZeroDataRetention {
		t.Fatalf("mcp: %+v", mcp)
	}
	if *deployment.DataHandling.RetentionDays != 0 {
		t.Fatal("the join changed the deployment's own retention")
	}
	offered := deployment
	delete(offered.HostedTools, HostedToolWebFetch)
	if got := offered.EffectiveDataHandling([]HostedTool{HostedToolWebFetch}); !reflect.DeepEqual(got, deployment.DataHandling) {
		t.Fatalf("a tool that the deployment does not run changed data handling: %+v", got)
	}
}

func TestRoutingKeepsDeploymentsThatRunListedHostedTools(t *testing.T) {
	loadTestCatalog(t)
	aws := map[string][]int{"aws": {0}}
	simulation := SimulateRouting(RequestInput{AvailableCredentials: aws}, RouteResponses, "claude-fable-5-1", "", "",
		[]string{"function", "web_fetch_20260309"}, nil)
	if simulation.Err != nil {
		t.Fatal(simulation.Err)
	}
	var served []string
	for _, pair := range simulation.Pairs {
		served = append(served, pair.Deployment.ID)
	}
	if !slices.Equal(served, []string{"aws-claude-fable-5-1-anthropic-hosted"}) {
		t.Fatalf("pairs %v", served)
	}
	var removed []string
	for _, entry := range simulation.Removed {
		if entry.Reason == RemovedHostedTool && slices.Equal(entry.Tools, []string{"web_fetch"}) {
			removed = append(removed, entry.Deployment)
		}
	}
	slices.Sort(removed)
	if !slices.Equal(removed, []string{"aws-claude-fable-5-1", "aws-claude-fable-5-1-us"}) {
		t.Fatalf("removed %v from %+v", removed, simulation.Removed)
	}

	// Bedrock runs no hosted tool, and a request that lists them says which, even when
	// tool_choice lets the model call none, since the deployment refuses their declarations.
	simulation = SimulateRouting(RequestInput{AvailableCredentials: aws}, RouteResponses, "aws-claude-fable-5-1", "", "",
		[]string{"web_fetch", "web_search"}, json.RawMessage(`"none"`))
	var apiErr APIError
	if !errors.As(simulation.Err, &apiErr) || apiErr.Code != "unsupported_tool" || apiErr.Param != "tools" ||
		apiErr.Message != "No deployment for this request runs all of web_search, web_fetch. Remove a tool or choose another model." {
		t.Fatalf("error %#v", simulation.Err)
	}

	// Chat Completions takes no hosted tool, so its routing reads none.
	if simulation := SimulateRouting(RequestInput{AvailableCredentials: aws}, RouteChat, "aws-claude-fable-5-1", "", "", nil, nil); simulation.Err != nil {
		t.Fatal(simulation.Err)
	}
}

func TestPoliciesReadHostedToolDataHandling(t *testing.T) {
	loadTestCatalog(t)
	compile := func(document string) *policy.Config {
		t.Helper()
		source, err := policy.CompileSource([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	usOnly := compile(`{"routing":{"filter":"deployment.dataHandling.processingLocation == 'US'"}}`)
	noFetch := compile(`{"routing":{"filter":"!('web_fetch' in request.hostedTools)"}}`)
	anthropic := map[string][]int{"anthropic": {0}}
	for _, test := range []struct {
		name   string
		config *policy.Config
		body   string
		want   string
	}{
		{name: "inference alone", config: usOnly, body: `{"model":"claude-fable-5-1","input":"hi"}`, want: "anthropic-claude-fable-5-1-us"},
		{name: "a search that may run anywhere", config: usOnly,
			body: `{"model":"claude-fable-5-1","input":"hi","tools":[{"type":"web_search"}]}`, want: "model_unavailable"},
		{name: "a search the model cannot call", config: usOnly,
			body: `{"model":"claude-fable-5-1","input":"hi","tools":[{"type":"web_search"}],"tool_choice":"none"}`, want: "anthropic-claude-fable-5-1-us"},
		{name: "a tool the policy denies", config: noFetch,
			body: `{"model":"anthropic-claude-fable-5-1","input":"hi","tools":[{"type":"web_fetch"}]}`, want: "model_unavailable"},
		{name: "another tool", config: noFetch,
			body: `{"model":"anthropic-claude-fable-5-1","input":"hi","tools":[{"type":"web_search"}]}`, want: "anthropic-claude-fable-5-1"},
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
}

func TestCredentialsThatReachOnlyRuledOutDeploymentsGetTheRequestNamed(t *testing.T) {
	loadTestCatalog(t)
	aws := map[string][]int{"aws": {0}}
	bedrock := func(_ schemas.ModelProvider, _ int, _ Route, deployment Deployment) bool {
		return !strings.HasSuffix(deployment.ID, "-anthropic-hosted")
	}
	nothing := func(schemas.ModelProvider, int, Route, Deployment) bool { return false }
	for _, test := range []struct {
		name     string
		eligible func(schemas.ModelProvider, int, Route, Deployment) bool
		want     string
	}{
		{"a credential that reaches only Bedrock", bedrock,
			"No deployment that your credentials reach runs web_fetch. Remove the tool or check each credential's Region, hostings and Azure deployments."},
		{"a credential that reaches no deployment of the model", nothing, ErrByokTargetUnavailable.Message},
	} {
		t.Run(test.name, func(t *testing.T) {
			simulation := SimulateRouting(RequestInput{AvailableCredentials: aws, DeploymentEligible: test.eligible},
				RouteResponses, "claude-fable-5-1", "", "", []string{"web_fetch"}, nil)
			if simulation.Err == nil || PublicError(simulation.Err).Message != test.want {
				t.Fatalf("error %v, want %q", simulation.Err, test.want)
			}
		})
	}

	// A parameter that rules out the only deployment that a credential reaches is named too.
	limit := APIError{Code: "parameter_limit_exceeded", Message: "limit"}
	variants := &requestVariants{ruledOut: []ruledOut{
		{routingSelection{provider: ProviderAWS, deployment: Deployment{ID: "unreached"}}, errors.New("unreached")},
		{routingSelection{provider: ProviderAWS, deployment: Deployment{ID: "reached"}}, limit},
	}}
	input := RequestInput{AvailableCredentials: map[string][]int{"aws": {0, 1}},
		DeploymentEligible: func(_ schemas.ModelProvider, index int, _ Route, deployment Deployment) bool {
			return deployment.ID == "reached" && index == 1
		}}
	if err := variants.ruledOutError(input, RouteResponses); !reflect.DeepEqual(err, error(limit)) {
		t.Fatalf("error %v", err)
	}
	input.AvailableCredentials["aws"] = []int{0}
	if err := variants.ruledOutError(input, RouteResponses); err != nil {
		t.Fatalf("a credential that reaches no ruled-out deployment got %v", err)
	}
}

func TestSnapshotValidationRejectsHostedToolsThatTheRouteCannotRun(t *testing.T) {
	tools := func(route map[string]any) map[string]any { return route["hostedTools"].(map[string]any) }
	effect := func(route map[string]any, tool string) map[string]any {
		return tools(route)[tool].(map[string]any)["dataHandling"].(map[string]any)
	}
	pricing := func(route map[string]any) map[string]any { return route["pricing"].(map[string]any) }
	for _, test := range []struct {
		name, deployment, route string
		apply                   func(route map[string]any)
		want                    string
	}{
		{"an unknown tool", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) {
				tools(route)["code_interpreter"] = map[string]any{"dataHandling": map[string]any{}}
			},
			"offers unknown hosted tool"},
		{"zero data retention that the deployment lacks", "anthropic-claude-fable-5-1", "anthropic-messages",
			func(route map[string]any) { effect(route, "web_fetch")["zeroDataRetention"] = true }, "would improve the deployment's"},
		{"no training use", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) { effect(route, "mcp")["trainingUse"] = false }, "would improve the deployment's"},
		{"negative retention", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) { effect(route, "mcp")["retentionDays"] = -1 }, "would improve the deployment's"},
		{"a location that the catalog does not list", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) { effect(route, "mcp")["processingLocation"] = "atlantis" },
			"data handling in a location that the catalog does not list"},
		{"web search without its price", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) { delete(pricing(route), "openai_responses_web_search_preview_calls") },
			"prices openai_responses_web_search_preview_calls only with web search"},
		{"a search price without web search", "anthropic-claude-fable-5-1", "anthropic-messages",
			func(route map[string]any) { delete(tools(route), "web_search") }, "prices anthropic_web_search_calls only with web search"},
		{"another wire's search price", "anthropic-claude-fable-5-1", "anthropic-messages",
			func(route map[string]any) {
				pricing(route)["openai_responses_web_search_calls"] = pricing(route)["anthropic_web_search_calls"]
			}, "which its wire does not charge"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			deployment := whole["graph"].(map[string]any)["deployments"].(map[string]any)[test.deployment].(map[string]any)
			test.apply(deployment["routes"].(map[string]any)[test.route].(map[string]any))
			broken, err := json.Marshal(whole)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(broken); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("catalog was accepted or failed for another reason: %v", err)
			}
		})
	}
}

func TestSimulationsReadHostedToolsAsRequestsDo(t *testing.T) {
	loadTestCatalog(t)
	source, err := policy.CompileSource([]byte(`{"routing":{"filter":"deployment.dataHandling.processingLocation == 'US'"}}`))
	if err != nil {
		t.Fatal(err)
	}
	usOnly, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
	if err != nil {
		t.Fatal(err)
	}
	input := RequestInput{Policy: usOnly, AvailableCredentials: map[string][]int{"anthropic": {0}}}
	for _, test := range []struct {
		name       string
		tools      []string
		toolChoice string
		want       string
	}{
		{"a search the model may call", []string{"function", "web_search_20250305"}, "", "model_unavailable"},
		{"a search that tool_choice leaves out", []string{"function", "web_search_20250305"},
			`{"type":"allowed_tools","mode":"auto","tools":[{"type":"function"}]}`, "anthropic-claude-fable-5-1-us"},
		{"function tools alone", []string{"function"}, `"required"`, "anthropic-claude-fable-5-1-us"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var choice json.RawMessage
			if test.toolChoice != "" {
				choice = json.RawMessage(test.toolChoice)
			}
			simulation := SimulateRouting(input, RouteResponses, "claude-fable-5-1", "", "", test.tools, choice)
			got := ""
			if simulation.Err != nil {
				got = PublicError(simulation.Err).Code
			} else {
				got = simulation.Pairs[0].Deployment.ID
			}
			if got != test.want {
				t.Fatalf("got %s (%v), want %s", got, simulation.Err, test.want)
			}
		})
	}
}
