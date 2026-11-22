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
	const tools = `[{"type":"function","name":"lookup","parameters":{}},{"type":"web_search_20250305"},{"type":"web_fetch"}]`
	all := []HostedTool{HostedToolWebSearch, HostedToolWebFetch}
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
			body:   `{"tools":` + tools + `,"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"function","name":"lookup"},{"type":"web_search"}]}}`,
			listed: all, enabled: []HostedTool{HostedToolWebSearch}},
		{name: "a preview search, once", route: RouteResponses, body: `{"tools":[{"type":"web_search_preview"},{"type":"web_search"}]}`,
			listed: []HostedTool{HostedToolWebSearch}, enabled: []HostedTool{HostedToolWebSearch}},
		{name: "function tools alone", route: RouteResponses, body: `{"tools":[{"type":"function","name":"lookup","parameters":{}}]}`},
		// A name states nothing: only a tool's type makes it hosted.
		{name: "client tools named as hosted tools", route: RouteResponses,
			body: `{"tools":[{"type":"function","name":"web_search","parameters":{}},{"type":"custom","name":"web_fetch"},` +
				`{"type":"namespace","name":"web","description":"","tools":[{"type":"function","name":"web_search_preview"}]}]}`},
		{name: "a forced function named as a hosted tool", route: RouteResponses,
			body:   `{"tools":[{"type":"function","name":"web_search","parameters":{}},{"type":"web_search"}],"tool_choice":{"type":"function","name":"web_search"}}`,
			listed: []HostedTool{HostedToolWebSearch}},
		{name: "tools that do not parse", route: RouteResponses, body: `{"tools":{"type":"web_search"}}`},
		{name: "Chat Completions", route: RouteChat, body: `{"tools":` + tools + `}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(test.body), &raw); err != nil {
				t.Fatal(err)
			}
			use := readRequestTools(test.route, raw).hosted
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
		DataHandling: DataHandling{ProcessingLocation: "US", StorageLocation: "none", RetentionDays: days(0), TrainingUse: &no,
			ZeroDataRetention: true, EndToEndEncrypted: true, TEE: true, TEEVerified: true, SharedWith: []string{"openai"},
			Certifications: []string{"soc2-type2", "iso-27001", "hipaa-eligible"}},
		Locations: places,
		HostedTools: map[HostedTool]HostedToolOffer{
			HostedToolWebSearch: {DataHandling: HostedToolDataHandling{ProcessingLocation: "DE", RetentionDays: Stated[int]{Set: true, Value: days(30)}}},
			HostedToolWebFetch: {DataHandling: HostedToolDataHandling{ProcessingLocation: "unknown", StorageLocation: "unknown",
				RetentionDays: Stated[int]{Set: true}, ZeroDataRetention: &no, TrainingUse: Stated[bool]{Set: true, Value: &yes}, EndToEndEncrypted: &no, TEE: &no, TEEVerified: &no,
				SharedWith: []string{"anthropic", "openai", "unknown"}, Certifications: []string{"soc2-type2", "iso-27001", "fedramp-high"}}},
			HostedToolMCP: {DataHandling: HostedToolDataHandling{TrainingUse: Stated[bool]{Set: true}}},
		},
	}
	if got := deployment.EffectiveDataHandling(nil, nil, false, false); !reflect.DeepEqual(got, deployment.DataHandling) {
		t.Fatalf("no tools changed data handling: %+v", got)
	}
	search := deployment.EffectiveDataHandling(nil, []HostedTool{HostedToolWebSearch}, false, false)
	// A tool that keeps content ends zero data retention although its record does not say so.
	if search.ProcessingLocation != "world" || search.StorageLocation != "none" || search.RetentionDays == nil || *search.RetentionDays != 30 ||
		search.ZeroDataRetention || !search.TEEVerified || !search.EndToEndEncrypted {
		t.Fatalf("web search: %+v", search)
	}
	// A tool that leaves the TEE ends the encryption and the verification that rest on it.
	outside := deployment
	outside.HostedTools = map[HostedTool]HostedToolOffer{HostedToolWebSearch: {DataHandling: HostedToolDataHandling{TEE: &no}}}
	if got := outside.EffectiveDataHandling(nil, []HostedTool{HostedToolWebSearch}, false, false); got.TEE || got.TEEVerified || got.EndToEndEncrypted ||
		!got.ZeroDataRetention {
		t.Fatalf("a tool outside the TEE: %+v", got)
	}
	fetch := deployment.EffectiveDataHandling(nil, []HostedTool{HostedToolWebSearch, HostedToolWebFetch}, false, false)
	if fetch.ProcessingLocation != "unknown" || fetch.StorageLocation != "unknown" || fetch.RetentionDays != nil || fetch.ZeroDataRetention ||
		fetch.TrainingUse == nil || !*fetch.TrainingUse || fetch.EndToEndEncrypted || fetch.TEE || fetch.TEEVerified ||
		!slices.Equal(fetch.SharedWith, []string{"anthropic", "openai", "unknown"}) || !slices.Equal(search.SharedWith, []string{"openai"}) {
		t.Fatalf("web fetch: %+v", fetch)
	}
	// A request keeps the certifications that cover each tool that it lists, and a tool's list adds
	// none: no list keeps them all, and an empty one keeps none.
	if !slices.Equal(fetch.Certifications, []string{"soc2-type2", "iso-27001"}) ||
		!slices.Equal(search.Certifications, deployment.DataHandling.Certifications) || len(deployment.DataHandling.Certifications) != 3 {
		t.Fatalf("certifications: web fetch %v, web search %v, deployment %v", fetch.Certifications, search.Certifications, deployment.DataHandling.Certifications)
	}
	uncovered := deployment
	uncovered.HostedTools = map[HostedTool]HostedToolOffer{HostedToolWebSearch: {DataHandling: HostedToolDataHandling{Certifications: []string{}}}}
	if got := uncovered.EffectiveDataHandling(nil, []HostedTool{HostedToolWebSearch}, false, false); len(got.Certifications) != 0 {
		t.Fatalf("a tool that no certification covers kept %v", got.Certifications)
	}
	// Unknown training use replaces false and ends zero data retention, and never replaces true.
	if got := deployment.EffectiveDataHandling(nil, []HostedTool{HostedToolMCP}, false, false); got.TrainingUse != nil || got.ZeroDataRetention {
		t.Fatalf("a tool whose training use is unknown: %+v", got)
	}
	if got := deployment.EffectiveDataHandling(nil, []HostedTool{HostedToolWebFetch, HostedToolMCP}, false, false); got.TrainingUse == nil || !*got.TrainingUse {
		t.Fatalf("unknown training use replaced true: %+v", got)
	}
	if *deployment.DataHandling.RetentionDays != 0 || deployment.DataHandling.TrainingUse == nil {
		t.Fatal("the join changed the deployment's own facts")
	}
	offered := deployment
	delete(offered.HostedTools, HostedToolWebFetch)
	if got := offered.EffectiveDataHandling(nil, []HostedTool{HostedToolWebFetch}, false, false); !reflect.DeepEqual(got, deployment.DataHandling) {
		t.Fatalf("a tool that the deployment does not run changed data handling: %+v", got)
	}
}

func TestRoutingKeepsDeploymentsThatRunListedHostedTools(t *testing.T) {
	loadTestCatalog(t)
	aws := map[string][]int{"aws": {0}}
	simulation := SimulateRouting(RequestInput{AvailableCredentials: aws}, RouteResponses, "claude-fable-5-1", "", "",
		[]string{"function", "web_fetch_20250910"}, nil)
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
	pricing := func(route map[string]any, tool string) map[string]any {
		return tools(route)[tool].(map[string]any)["pricing"].(map[string]any)
	}
	for _, test := range []struct {
		name, deployment, route string
		apply                   func(route map[string]any)
		want                    string
	}{
		{"an unknown tool", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) {
				tools(route)["local_shell"] = map[string]any{"dataHandling": map[string]any{}}
			},
			"offers unknown hosted tool"},
		{"image generation on Claude's wire", "anthropic-claude-fable-5-1", "anthropic-messages",
			func(route map[string]any) {
				tools(route)["image_generation"] = map[string]any{"dataHandling": map[string]any{}}
			},
			"offers image generation on Claude's wire, which has none"},
		{"a price on image generation", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) {
				tools(route)["image_generation"] = map[string]any{"dataHandling": map[string]any{},
					"pricing": map[string]any{"openai_responses_file_search_calls": map[string]any{"per_1k_calls": "2.5"}}}
			}, "prices image_generation on a meter that it does not bill"},
		{"zero data retention that the deployment lacks", "anthropic-claude-fable-5-1", "anthropic-messages",
			func(route map[string]any) { effect(route, "web_fetch")["zeroDataRetention"] = true }, "would improve the deployment's"},
		{"no training use", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) { effect(route, "web_search")["trainingUse"] = false }, "would improve the deployment's"},
		{"negative retention", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) { effect(route, "web_search")["retentionDays"] = -1 }, "would improve the deployment's"},
		{"a location that the catalog does not list", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) { effect(route, "web_search")["processingLocation"] = "atlantis" },
			"data handling in a location that the catalog does not list"},
		{"web search without its price", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) {
				delete(pricing(route, "web_search"), "openai_responses_web_search_preview_calls")
			},
			"offers web_search without a price for openai_responses_web_search_preview_calls"},
		{"file search without its price", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) {
				delete(pricing(route, "file_search"), "openai_responses_file_search_calls")
			},
			"offers file_search without a price for openai_responses_file_search_calls"},
		{"a web search price on file search", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) {
				pricing(route, "file_search")["openai_responses_web_search_calls"] = pricing(route, "web_search")["openai_responses_web_search_calls"]
			}, "prices file_search on a meter that it does not bill"},
		{"file search on Claude's wire", "anthropic-claude-fable-5-1", "anthropic-messages",
			func(route map[string]any) {
				tools(route)["file_search"] = map[string]any{"dataHandling": map[string]any{},
					"pricing": map[string]any{"openai_responses_file_search_calls": map[string]any{"per_1k_calls": "2.5"}}}
			}, "offers file search on Claude's wire, which has none"},
		{"code interpreter on Claude's wire", "anthropic-claude-fable-5-1", "anthropic-messages",
			func(route map[string]any) {
				tools(route)["code_interpreter"] = map[string]any{"dataHandling": map[string]any{}}
			},
			"offers code_interpreter on Claude's wire, which the gateway does not run"},
		{"a price on code interpreter", "openai-gpt-5.5-2026-04-23", "openai-responses",
			func(route map[string]any) {
				tools(route)["code_interpreter"] = map[string]any{"dataHandling": map[string]any{},
					"pricing": map[string]any{"openai_responses_file_search_calls": map[string]any{"per_1k_calls": "2.5"}}}
			}, "prices code_interpreter on a meter that it does not bill"},
		{"a search price on another tool", "anthropic-claude-fable-5-1", "anthropic-messages",
			func(route map[string]any) {
				pricing(route, "web_fetch")["anthropic_web_search_calls"] = pricing(route, "web_search")["anthropic_web_search_calls"]
			}, "prices web_fetch on a meter that it does not bill"},
		{"another wire's search price", "anthropic-claude-fable-5-1", "anthropic-messages",
			func(route map[string]any) {
				pricing(route, "web_search")["openai_responses_web_search_calls"] = pricing(route, "web_search")["anthropic_web_search_calls"]
			}, "prices web_search on a meter that it does not bill"},
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

// A hosted tool's call priced on the deployment would bill on a route that runs no such tool.
func TestSnapshotValidationRejectsCallPricesOutsideHostedTools(t *testing.T) {
	for deployment, meter := range map[string]string{
		"anthropic-claude-fable-5-1": "anthropic_web_search_calls",
		"openai-gpt-5.5-2026-04-23":  "openai_responses_file_search_calls",
	} {
		t.Run(meter, func(t *testing.T) {
			var whole map[string]any
			if err := json.Unmarshal(testCatalogJSON, &whole); err != nil {
				t.Fatal(err)
			}
			record := whole["graph"].(map[string]any)["deployments"].(map[string]any)[deployment].(map[string]any)
			record["pricing"].(map[string]any)[meter] = map[string]any{"per_1k_calls": "10"}
			broken, err := json.Marshal(whole)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snapshotFromCatalogBytes(broken); err == nil ||
				!strings.Contains(err.Error(), "prices "+meter+", which only a hosted tool on its wire charges") {
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
