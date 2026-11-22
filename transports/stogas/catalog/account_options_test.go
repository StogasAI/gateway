package catalog

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestAccountOptionsSetFactsBeforeToolsJoin(t *testing.T) {
	loadTestCatalog(t)
	days := func(value int) *int { return &value }
	yes, no := true, false
	zeroRetention := AccountOption{ID: "zero-data-retention", Routes: []string{"responses"},
		DataHandling: AccountOptionDataHandling{StorageLocation: "none", RetentionDays: days(0), ZeroDataRetention: &yes}}
	agreement := AccountOption{ID: "business-associate-agreement", Routes: []string{"responses"}, Grants: []string{"hipaa"}}
	deployment := Deployment{
		DataHandling: DataHandling{ProcessingLocation: "US", StorageLocation: "US", RetentionDays: days(30), TrainingUse: &no,
			Certifications: []string{"soc2-type2", "hipaa-eligible"}},
		Locations:      activeState().places,
		AccountOptions: []AccountOption{zeroRetention, agreement},
		HostedTools: map[HostedTool]HostedToolOffer{
			HostedToolWebSearch: {DataHandling: HostedToolDataHandling{RetentionDays: Stated[int]{Set: true, Value: days(30)}}},
			HostedToolWebFetch:  {DataHandling: HostedToolDataHandling{Certifications: []string{"soc2-type2"}}},
		},
	}
	held := []HeldOption{{ID: "business-associate-agreement", Declared: true}, {ID: "zero-data-retention"}, {ID: "another-provider-option"}}
	if got := deployment.AppliedOptions(held); !slices.Equal(got, []HeldOption{held[1], held[0]}) {
		t.Fatalf("applied options %v, want the deployment's two in the provider's order", got)
	}
	// Two options of one group are two values of one setting, which no account has.
	retention := "data-retention"
	grouped := deployment
	grouped.AccountOptions = []AccountOption{zeroRetention, {ID: "modified-abuse-monitoring", Group: &retention, Routes: []string{"responses"},
		DataHandling: AccountOptionDataHandling{TrainingUse: &no}}, agreement}
	grouped.AccountOptions[0].Group = &retention
	both := append(slices.Clone(held), HeldOption{ID: "modified-abuse-monitoring", Declared: true})
	if got := grouped.AppliedOptions(both); !slices.Equal(got, []HeldOption{held[0]}) {
		t.Fatalf("applied options %v, want neither option of the group that the credential states twice", got)
	}
	if got := grouped.AppliedOptions(held); !slices.Equal(got, []HeldOption{held[1], held[0]}) {
		t.Fatalf("applied options %v, want the one stated option of the group", got)
	}
	alone := deployment.EffectiveDataHandling(held, nil, false, false)
	if alone.StorageLocation != "none" || *alone.RetentionDays != 0 || !alone.ZeroDataRetention ||
		!slices.Equal(alone.Certifications, []string{"soc2-type2", "hipaa-eligible", "hipaa"}) {
		t.Fatalf("held options: %+v", alone)
	}
	// A tool joins after the options, so an option never hides what a tool keeps.
	search := deployment.EffectiveDataHandling(held, []HostedTool{HostedToolWebSearch}, false, false)
	if *search.RetentionDays != 30 || search.ZeroDataRetention || !slices.Contains(search.Certifications, "hipaa") {
		t.Fatalf("held options with web search: %+v", search)
	}
	// A tool that the agreement leaves out removes the entry that the grant needs.
	if fetch := deployment.EffectiveDataHandling(held, []HostedTool{HostedToolWebFetch}, false, false); !slices.Equal(fetch.Certifications, []string{"soc2-type2"}) {
		t.Fatalf("held options with web fetch: %v", fetch.Certifications)
	}
	if got := deployment.EffectiveDataHandling(nil, nil, false, false); got.ZeroDataRetention || *got.RetentionDays != 30 || len(got.Certifications) != 2 {
		t.Fatalf("no options changed the facts: %+v", got)
	}
	if *deployment.DataHandling.RetentionDays != 30 || len(deployment.DataHandling.Certifications) != 2 {
		t.Fatal("the options changed the deployment's own facts")
	}
}

func TestRouteRecordsListOnlyOptionsThatMayReachThem(t *testing.T) {
	days := func(value int) *int { return &value }
	yes, no := true, false
	provider := compiledProvider{AccountOptions: []AccountOption{
		{ID: "zero-data-retention", Routes: []string{"messages"},
			DataHandling: AccountOptionDataHandling{StorageLocation: "none", RetentionDays: days(0), ZeroDataRetention: &yes}},
		{ID: "business-associate-agreement", Routes: []string{"messages", "batch"}, Grants: []string{"hipaa"}},
	}}
	record := func(options ...string) compiledDeploymentRoute {
		return compiledDeploymentRoute{AccountOptions: options,
			DataHandling: DataHandling{StorageLocation: "US", RetentionDays: days(30), TrainingUse: &no, Certifications: []string{}}}
	}
	unknownTraining := record("zero-data-retention")
	unknownTraining.DataHandling.TrainingUse = nil
	for _, test := range []struct {
		name   string
		route  string
		record compiledDeploymentRoute
		model  compiledModel
		valid  bool
	}{
		{name: "both options", route: "messages", record: record("zero-data-retention", "business-associate-agreement"), valid: true},
		{name: "no option", route: "messages", record: record(), valid: true},
		{name: "another provider's option", route: "messages", record: record("modified-abuse-monitoring")},
		{name: "out of the provider's order", route: "messages", record: record("business-associate-agreement", "zero-data-retention")},
		{name: "an option listed twice", route: "messages", record: record("zero-data-retention", "zero-data-retention")},
		{name: "a route that the option does not cover", route: "batch", record: record("zero-data-retention")},
		// The model's developer requires 30 days wherever it runs, so no account reaches zero.
		{name: "under the model's minimum retention", route: "messages", record: record("zero-data-retention"),
			model: compiledModel{MinimumRetentionDays: days(30)}},
		{name: "zero data retention with unknown training use", route: "messages", record: unknownTraining},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateReachingOptions("record", test.route, test.record, provider, test.model)
			if (err == nil) != test.valid {
				t.Fatalf("valid %t, want %t: %v", err == nil, test.valid, err)
			}
		})
	}
}

func TestRoutingAndPoliciesReadEachCredentialsAccountOptions(t *testing.T) {
	loadTestCatalog(t)
	compile := func(filter string) *policy.Config {
		t.Helper()
		document, _ := json.Marshal(map[string]any{"routing": map[string]string{"filter": filter}})
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
	// Three credentials of one provider: the provider reported the first one's option, the second
	// holds none, and the third's owner declared two that together end zero data retention.
	held := map[string][][]HeldOption{
		"openai": {
			{{ID: "zero-data-retention"}},
			nil,
			{{ID: "data-sharing", Declared: true}, {ID: "zero-data-retention", Declared: true}},
		},
		"anthropic": {{{ID: "business-associate-agreement", Declared: true}}, nil},
	}
	input := func(config *policy.Config) RequestInput {
		return RequestInput{Policy: config, AvailableCredentials: map[string][]int{"openai": {0, 1, 2}, "anthropic": {0, 1}},
			CredentialOptions: func(provider schemas.ModelProvider, index int) []HeldOption { return held[string(provider)][index] }}
	}
	for _, test := range []struct {
		name, filter, model string
		tools               []string
		want                []int
	}{
		{name: "no requirement", filter: "true", model: "openai-gpt-5.6-sol", want: []int{0, 1, 2}},
		{name: "the facts that an option sets", filter: "deployment.dataHandling.zeroDataRetention && deployment.dataHandling.retentionDays == 0",
			model: "openai-gpt-5.6-sol", want: []int{0}},
		{name: "an option that makes a fact worse", filter: "deployment.dataHandling.trainingUse == false", model: "openai-gpt-5.6-sol", want: []int{0, 1}},
		{name: "a held option", filter: "'zero-data-retention' in credential.accountOptions", model: "openai-gpt-5.6-sol", want: []int{0, 2}},
		{name: "an option that the provider reported",
			filter: "'zero-data-retention' in credential.accountOptions && !('zero-data-retention' in credential.declaredAccountOptions)",
			model:  "openai-gpt-5.6-sol", want: []int{0}},
		{name: "a granted certification", filter: "'hipaa' in deployment.dataHandling.certifications", model: "anthropic-claude-sonnet-5-5", want: []int{0}},
		// Anthropic's agreement leaves web fetch out, so a request that can call it loses the grant.
		{name: "a grant that a tool blocks", filter: "'hipaa' in deployment.dataHandling.certifications", model: "anthropic-claude-sonnet-5-5",
			tools: []string{"web_fetch"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			simulation := SimulateRouting(input(compile(test.filter)), RouteResponses, test.model, "", "", test.tools, nil)
			var got []int
			for _, pair := range simulation.Pairs {
				got = append(got, pair.Credential)
			}
			slices.Sort(got)
			if !slices.Equal(got, test.want) {
				t.Fatalf("credentials %v (%v), want %v", got, simulation.Err, test.want)
			}
		})
	}

	// The pair that a request takes carries its credential's options to the log and the policies.
	request := input(compile("deployment.dataHandling.zeroDataRetention"))
	request.Body, request.Method, request.Path = []byte(`{"model":"openai-gpt-5.6-sol","input":"hi"}`), "POST", "/v1/responses"
	resolved, err := ResolveRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.CredentialIndex != 0 || !slices.Equal(resolved.AccountOptions(), held["openai"][0]) || !resolved.EffectiveDataHandling().ZeroDataRetention ||
		resolved.Deployment.DataHandling.ZeroDataRetention {
		t.Fatalf("credential %d with options %v and facts %+v", resolved.CredentialIndex, resolved.AccountOptions(), resolved.EffectiveDataHandling())
	}
}
