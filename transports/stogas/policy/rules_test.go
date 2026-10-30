package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestCELCompilationBudgetSharesRepeatedExpressionsAndBoundsDistinctWork(t *testing.T) {
	conditions := make([]string, 250)
	for i := range conditions {
		conditions[i] = fmt.Sprintf(`model.id != "model-%d"`, i)
	}
	condition := strings.Join(conditions, " && ")
	makeSource := func(count, identity int, repeated bool) []byte {
		rules := make(map[string]any)
		for i := range count {
			when := condition
			if !repeated {
				when += fmt.Sprintf(` && provider.id != "blocked-%d-%d"`, identity, i)
			}
			rules[fmt.Sprintf("rule_%d", i)] = map[string]any{"when": when, "input": map[string]bool{"asciiOnly": true}}
		}
		raw, _ := json.Marshal(map[string]any{"rules": rules})
		return raw
	}
	shared, err := CompileSource(makeSource(30, 0, true))
	if err != nil {
		t.Fatal(err)
	}
	if shared.Rules[0].When != shared.Rules[29].When || shared.ExpressionBytes() != shared.Rules[0].When.bytes {
		t.Fatal("repeated expressions were rebuilt or their retained memory was counted repeatedly")
	}
	oversized := makeSource(8, 0, false)
	if _, err := CompileSource(oversized); err == nil || !strings.Contains(err.Error(), "CEL compilation limit") {
		t.Fatalf("source work limit was bypassed: %v", err)
	}
	if _, err := InspectSource(oversized); err == nil || !strings.Contains(err.Error(), "CEL compilation limit") {
		t.Fatalf("inspection did not enforce the source work limit: %v", err)
	}
	inspector := NewInspector(nil, false)
	var sources []ScopedSource
	for i, scope := range []Scope{OrganizationScope, RoleScope, KeyScope} {
		raw := makeSource(3, i, false)
		source, err := CompileSource(raw)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, ScopedSource{Scope: scope, Value: source})
		err = inspector.Add(InspectionSource{Scope: scope, Config: raw})
		if i < 2 && err != nil || i == 2 && (err == nil || !strings.Contains(err.Error(), "CEL compilation limit")) {
			t.Fatalf("source %d: wrong aggregate work result: %v", i, err)
		}
	}
	if _, err := ComposeSources(sources); err == nil || !strings.Contains(err.Error(), "CEL compilation limit") {
		t.Fatalf("runtime did not enforce aggregate compilation work: %v", err)
	}
	var candidateBudget SourceBudget
	for index, entry := range sources {
		err := candidateBudget.AddSource(entry.Value)
		if index < 2 && err != nil || index == 2 && !errors.Is(err, ErrSourceBudget) {
			t.Fatalf("candidate %d: compilation budget = %v", index, err)
		}
		if index == 0 {
			for range 1000 {
				if err := candidateBudget.AddSource(entry.Value); err != nil {
					t.Fatalf("a shared source consumed more compilation work: %v", err)
				}
			}
		}
	}
	// Reusing a sort program must not make a non-boolean condition valid.
	if _, err := CompileSource([]byte(`{"routing":{"sort":[{"by":"1","direction":"asc"}]},"rules":{"invalid":{"when":"1","input":{"asciiOnly":true}}}}`)); err == nil {
		t.Fatal("shared compilation bypassed the required condition type")
	}
}

func TestRuleFragmentsPreserveCanonicalIdentityAndStrictFields(t *testing.T) {
	// Includes alternate number spellings, HTML characters, Unicode property
	// names with different UTF-8/UTF-16 ordering, and a literal line separator.
	settings := `{"limits":{"custom":{"\ue000":1e+0,"\ud83d\ude00":-0}},"plugins":{"redaction":{"literals":[{"values":["<>&\u2028é"]}]}},"routing":{"filter":"true"}}`
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(settings), &fields); err != nil {
		t.Fatal(err)
	}
	expectedRaw, _ := json.Marshal(fields)
	expected, err := jsoncanonicalizer.Transform(expectedRaw)
	if err != nil {
		t.Fatal(err)
	}
	expected = append(expected, '\n')
	parent, err := ParseSourceDocument([]byte(`{"rules":{"selected":` + settings + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	fragment := parent.rules["selected"].source
	digest := sha256.Sum256(expected)
	if !bytes.Equal(fragment.CanonicalJSON(), expected) || fragment.Digest() != hex.EncodeToString(digest[:]) {
		t.Fatal("rule fragment changed canonical bytes or identity")
	}
	for _, raw := range []string{
		`{"rules":{"selected":{"Input":{"asciiOnly":true}}}}`,
		`{"rules":{"selected":{"input":{"ASCIIOnly":true}}}}`,
		`{"rules":{"selected":{"input":{"asciiOnly":null}}}}`,
		`{"rules":{"selected":{"plugins":{"redaction":{"email_address":null}}}}}`,
		`{"rules":{"selected":{"limits":{"lifetime":{"usd":null}}}}}`,
		`{"rules":{"selected":{"rules":{"nested":{"input":{"asciiOnly":true}}}}}}`,
		`{"rules":null}`,
		`{"rules":{}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid fields: %s", raw)
		}
	}
}

type ruleValues map[string]Value

func (v ruleValues) PolicyValue(path string) (Value, bool) { value, ok := v[path]; return value, ok }
func (v ruleValues) PolicyTokenPrice(meter string, _ int64) (Value, bool) {
	return v.PolicyValue("deployment.pricing." + meter + ".per_mill_tokens")
}

type budgetRuleValues struct {
	ruleValues
	budget *CELBudget
}

func (v budgetRuleValues) PolicyCELBudget() *CELBudget { return v.budget }

func TestConstantRulesConsumeTheSharedRequestBudget(t *testing.T) {
	for _, condition := range []string{"", `"when":"true",`} {
		source := ruleSource(t, `{"rules":{"first":{`+condition+`"input":{"asciiOnly":true}},"second":{`+condition+`"input":{"asciiOnly":true}}}}`)
		config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: source}})
		if err != nil {
			t.Fatal(err)
		}
		values := budgetRuleValues{budget: &CELBudget{remaining: 1}}
		if _, err := config.Activate(values); !errors.Is(err, ErrPolicyWorkLimit) {
			t.Fatalf("constant rules escaped the shared work limit: %v", err)
		}
		values.budget = &CELBudget{remaining: 2}
		if _, err := config.Activate(values); err != nil || values.budget.remaining != 0 {
			t.Fatalf("exact rule allowance was not honored: %v", err)
		}
	}
}

func ruleSource(t *testing.T, raw string) *Source {
	t.Helper()
	source, err := CompileSource([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestRulesDefaultsAndRequirementsAreOrderIndependent(t *testing.T) {
	org := ruleSource(t, `{"delegation":{"request":true},"rules":{"baseline":{"mode":"default","input":{"asciiOnly":true},"plugins":{"redaction":{"email_address":true}},"routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}}}`)
	role := ruleSource(t, `{"rules":{"chat":{"when":"request.interface == 'chat_completions'","input":{"asciiOnly":false},"plugins":{"redaction":{"credit_card_number":true}}}}}`)
	other := ruleSource(t, `{"routing":{"filter":"provider.id != 'blocked'"}}`)
	for _, sources := range [][]ScopedSource{
		{{Scope: OrganizationScope, Value: org}, {Scope: RoleScope, Value: role}, {Scope: RoleScope, Value: other}},
		{{Scope: OrganizationScope, Value: org}, {Scope: RoleScope, Value: other}, {Scope: RoleScope, Value: role}},
	} {
		combined, err := ComposeSources(sources)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"chat_completions", "responses"} {
			active, err := combined.Activate(ruleValues{"request.interface": {Type: "string", String: name}})
			if err != nil {
				t.Fatal(err)
			}
			if active.Input != nil && active.Input.ASCIIOnly != (name == "responses") {
				t.Fatalf("wrong input requirement for %s", name)
			}
			if name == "responses" && active.Input == nil {
				t.Fatal("default input requirement disappeared")
			}
			preset := "email_address"
			if name == "chat_completions" {
				preset = "credit_card_number"
			}
			if len(active.PluginSources) != 1 || active.PluginSources[0].Redaction.Presets[0] != preset || active.Routing.Query.OrderBy[0].By != "provider.id" {
				t.Fatalf("wrong settings for %s: %+v", name, active)
			}
			if len(active.Routing.Query.Filters) != 1 {
				t.Fatal("required filter was lost while replacing defaults")
			}
		}
		if org.Config.Input != nil || org.Config.Plugins != nil || role.Config.Input != nil {
			t.Fatal("activation mutated a cached source")
		}
	}
}

func TestRulesRequestOverridesOnlyDefaults(t *testing.T) {
	org := ruleSource(t, `{"delegation":{"request":["routing.sort"]},"routing":{"filter":"provider.id == 'openai'"},"rules":{"default_sort":{"mode":"default","routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}}}`)
	base, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := CompileRequest([]byte(`{"routing":{"sort":[{"by":"deployment.id","direction":"desc"}]}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := ApplyRequest(base, request)
	if err != nil {
		t.Fatal(err)
	}
	active, err := combined.Activate(ruleValues{"provider.id": {Type: "string", String: "openai"}})
	if err != nil || active.Routing.Query.OrderBy[0].By != "deployment.id" || len(active.Routing.Query.Filters) != 1 {
		t.Fatalf("request composition failed: %+v, %v", active, err)
	}
	preferred, err := CompileRequest([]byte(`{"rules":{"d":{"mode":"default","routing":{"sort":[{"by":"model.id"}]}}}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if combined, err = ApplyRequest(base, preferred); err != nil || combined.Routing.Query.OrderBy[0].By != "model.id" {
		t.Fatalf("request default did not replace the saved default: %+v, %v", combined, err)
	}
	strict := ruleSource(t, `{"delegation":{"request":["routing.sort"]},"routing":{"sort":[{"by":"provider.id"}]}}`)
	required, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: strict}})
	if err != nil {
		t.Fatal(err)
	}
	if combined, err = ApplyRequest(required, preferred); err != nil || combined.Routing.Query.OrderBy[0].By != "provider.id" {
		t.Fatalf("request default replaced a saved requirement: %+v, %v", combined, err)
	}
	denied, err := CompileRequest([]byte(`{"rules":{"nested":{"routing":{"filter":"true"}}}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRequest(base, denied); !errors.Is(err, ErrRequestPolicyDenied) {
		t.Fatalf("nested rule bypassed section permission: %v", err)
	}
}

func TestTimeoutRulesComposeIndependentlyWithoutMutatingSavedPolicies(t *testing.T) {
	org := ruleSource(t, `{"delegation":{"request":["timeouts.outputIdleSeconds"]},"timeouts":{"totalSeconds":900},"rules":{"baseline":{"mode":"default","timeouts":{"outputIdleSeconds":90}},"openai":{"when":"provider.id == 'openai'","timeouts":{"outputIdleSeconds":60}}}}`)
	key := ruleSource(t, `{"timeouts":{"totalSeconds":1200}}`)
	base, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: key}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := CompileRequest([]byte(`{"timeouts":{"outputIdleSeconds":180}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := ApplyRequest(base, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []*Config{combined, base, combined} {
		for _, provider := range []string{"openai", "anthropic"} {
			active, err := config.Activate(ruleValues{"provider.id": {Type: "string", String: provider}})
			if err != nil {
				t.Fatal(err)
			}
			wantTotal, wantIdle := 900*time.Second, 180*time.Second
			if config == base {
				wantIdle = 90 * time.Second
			}
			if provider == "openai" {
				wantIdle = 60 * time.Second
			}
			if active.Timeouts.Total() != wantTotal || active.Timeouts.OutputIdle() != wantIdle {
				t.Fatalf("%s timeouts = %+v, want %s/%s", provider, active.Timeouts, wantTotal, wantIdle)
			}
		}
	}
	for _, raw := range []string{`{"timeouts":{"totalSeconds":300}}`, `{"rules":{"bypass":{"timeouts":{"totalSeconds":300}}}}`} {
		denied, err := CompileRequest([]byte(raw), "org", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyRequest(base, denied); !errors.Is(err, ErrRequestPolicyDenied) {
			t.Fatalf("request bypassed timeout field delegation: %v", err)
		}
	}
}

func TestRulesExplicitEmptySettingsReplaceDefaultsWithoutWeakeningRequirements(t *testing.T) {
	settings := `"access":{"deny":[{"days":["mon"],"start":"09:00","end":"17:00","timeZone":"UTC"}]},"input":{"asciiOnly":true},"plugins":{"redaction":{"email_address":true}},"routing":{"allowedCatalogNodes":{"providers":["openai"]},"filter":"provider.id == 'openai'","sort":[{"by":"provider.id","direction":"asc"}],"retries":1,"fallbacks":0}`
	org := ruleSource(t, `{"rules":{"baseline":{"mode":"default",`+settings+`}}}`)
	empty := ruleSource(t, `{"access":{"deny":[]},"input":{"asciiOnly":false},"plugins":{"redaction":{}},"routing":{"allowedCatalogNodes":{},"filter":"true","sort":[],"retries":3,"fallbacks":2}}`)
	required := ruleSource(t, `{`+settings+`}`)
	for _, withRequired := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			// The grant's required sort is broader than the key's empty one.
			sources := []ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: empty}}
			if withRequired {
				sources = append(sources, ScopedSource{Scope: GrantScope, Value: required})
				if reverse {
					sources[1], sources[2] = sources[2], sources[1]
				}
			}
			combined, err := ComposeSources(sources)
			if err != nil {
				t.Fatal(err)
			}
			active, err := combined.Activate(ruleValues{"provider.id": {Type: "string", String: "openai"}})
			if err != nil {
				t.Fatal(err)
			}
			if (active.Input != nil && active.Input.ASCIIOnly) != withRequired || (len(active.Access.Deny) > 0) != withRequired || (len(active.Routing.Query.OrderBy) > 0) != withRequired {
				t.Fatalf("required=%v: wrong active restrictions: %+v", withRequired, active)
			}
			// The smallest required value applies; the default rule's never does.
			if want := map[bool][2]int{false: {3, 2}, true: {1, 0}}[withRequired]; active.Routing.Retries != want[0] || active.Routing.Fallbacks != want[1] {
				t.Fatalf("required=%v: retries=%d fallbacks=%d, want %v", withRequired, active.Routing.Retries, active.Routing.Fallbacks, want)
			}
			if (len(active.Routing.AllowedCatalogNodes.Providers) > 0) != withRequired {
				t.Fatal("wrong catalog restriction")
			}
			hasPreset := false
			for _, plugins := range active.PluginSources {
				hasPreset = hasPreset || len(plugins.Redaction.Presets) > 0
			}
			if hasPreset != withRequired {
				t.Fatal("wrong redaction requirement")
			}
			matches, err := active.Routing.Query.Matches(ruleValues{"provider.id": {Type: "string", String: "anthropic"}})
			if err != nil || matches == withRequired {
				t.Fatalf("filter requirement changed: matches=%v error=%v", matches, err)
			}
		}
	}
}

// One ordering applies to a request: the required one from the broadest scope,
// or else the default one from the closest scope.
func TestOneRoutingOrderingApplies(t *testing.T) {
	required := func(by string) string { return `{"routing":{"sort":[{"by":"` + by + `"}]}}` }
	preferred := func(by string) string {
		return `{"rules":{"d":{"mode":"default","routing":{"sort":[{"by":"` + by + `"}]}}}}`
	}
	scopes := []Scope{OrganizationScope, FolderScope, GrantScope, KeyScope}
	for _, test := range []struct {
		name      string
		sources   [4]string
		sortBy    string
		from      Scope
		isDefault bool
	}{
		{"broadest required", [4]string{required("provider.id"), required("model.id"), "", required("deployment.id")}, "provider.id", OrganizationScope, false},
		{"required before closer defaults", [4]string{preferred("provider.id"), required("model.id"), preferred("route.id"), preferred("deployment.id")}, "model.id", FolderScope, false},
		{"closest default", [4]string{preferred("provider.id"), "", preferred("route.id"), `{}`}, "route.id", GrantScope, true},
		{"explicit empty requirement", [4]string{preferred("provider.id"), "", "", `{"routing":{"sort":[]}}`}, "", KeyScope, false},
		{"none", [4]string{`{}`, "", "", `{}`}, "", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var sources []ScopedSource
			for i, raw := range test.sources {
				if raw != "" {
					sources = append(sources, ScopedSource{Scope: scopes[i], Value: ruleSource(t, raw)})
				}
			}
			combined, err := ComposeSources(sources)
			if err != nil {
				t.Fatal(err)
			}
			active, err := combined.Activate(ruleValues{})
			if err != nil {
				t.Fatal(err)
			}
			for _, config := range []*Config{combined, active} {
				sortBy := ""
				if config.Routing.Query != nil && len(config.Routing.Query.OrderBy) > 0 {
					sortBy = config.Routing.Query.OrderBy[0].By
				}
				if sortBy != test.sortBy || config.orderScope != test.from || config.orderDefault != test.isDefault {
					t.Fatalf("ordering = %q from %s (default %v)", sortBy, config.orderScope, config.orderDefault)
				}
			}
		})
	}
	// routing.order and routing.sort form one ordering from one policy.
	org := ruleSource(t, `{"routing":{"order":["deployment-b"],"sort":[{"by":"provider.id"}]}}`)
	key := ruleSource(t, `{"routing":{"order":["deployment-a"]}}`)
	combined, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: key}})
	if err != nil || !slices.Equal(combined.Routing.Order, []string{"deployment-b"}) || len(combined.Routing.Query.OrderBy) != 1 {
		t.Fatalf("ordering mixed policies: %+v, %v", combined, err)
	}
}

func TestRuleOrderingsAreUnconditionalDefaults(t *testing.T) {
	sort := `"sort":[{"by":"provider.id","direction":"asc"}]`
	for _, raw := range []string{
		`{"rules":{"r":{"routing":{` + sort + `}}}}`,
		`{"rules":{"r":{"mode":"required","routing":{"order":["deployment-a"]}}}}`,
		`{"rules":{"r":{"when":"request.interface == 'chat_completions'","mode":"default","routing":{` + sort + `}}}}`,
		`{"rules":{"r":{"when":"provider.id == 'openai'","mode":"default","routing":{"sort":[]}}}}`,
		`{"rules":{"r":{"when":"[1].exists(deployment, deployment == 1)","routing":{"sort":[{"by":"random()"}]}}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), "only with mode default and no when") {
			t.Fatalf("conditional or required rule ordering accepted: %s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"routing":{` + sort + `},"rules":{"r":{"mode":"default","routing":{"order":["deployment-a"]}}}}`,
		`{"rules":{"a":{"mode":"default","routing":{` + sort + `}},"b":{"mode":"default","routing":{"order":["deployment-a"]}}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), "once per policy") {
			t.Fatalf("second ordering accepted: %s: %v", raw, err)
		}
	}
	source := ruleSource(t, `{"rules":{"r":{"mode":"default","routing":{"filter":"provider.id != 'x'","order":["deployment-a"],`+sort+`}}}}`)
	if source.defaultOrdering == nil || len(source.defaultOrdering.sorts) != 1 || source.Rules[0].Value.orders() || len(source.Rules[0].Value.Config.Routing.Query.Filters) != 1 {
		t.Fatalf("default ordering did not move to its policy: %+v", source)
	}
}

// A routing simulation names the policy, and the rule, behind each decision.
func TestOriginsLocateTheDecidingPolicyAndRule(t *testing.T) {
	org := ruleSource(t, `{"routing":{"allowedCatalogNodes":{"providers":["openai","anthropic"]},"filter":"provider.id != 'blocked'","fallbacks":2},"rules":{"order":{"mode":"default","routing":{"sort":[{"by":"provider.id"}]}}}}`)
	folder := ruleSource(t, `{"access":{"deny":[{"days":["mon"],"start":"09:00","end":"17:00","timeZone":"UTC"}]},"routing":{"fallbacks":1},"rules":{"loose":{"mode":"default","routing":{"filter":"provider.id == 'never'"}}}}`)
	key := ruleSource(t, `{"rules":{"chat":{"when":"request.interface == 'chat_completions'","access":{"deny":[{"days":["tue"],"start":"00:00","end":"23:59","timeZone":"UTC"}]},"routing":{"allowedCatalogNodes":{"deployments":["openai-a"]},"filter":"deployment.id != 'openai-b'"}}}}`)
	base, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: FolderScope, Value: folder}, {Scope: KeyScope, Value: key}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = base.Activate(ruleValues{})
	var unknown *UnknownConditionError
	if !errors.As(err, &unknown) || !errors.Is(err, ErrUnknownCondition) || unknown.Origin != (Origin{Source: 2, Rule: "chat"}) || unknown.Condition != "request.interface == 'chat_completions'" {
		t.Fatalf("undecided condition = %#v", err)
	}
	active, err := base.Activate(ruleValues{"request.interface": {Type: "string", String: "chat_completions"}})
	if err != nil {
		t.Fatal(err)
	}
	located := func(origin Origin, found bool) string {
		return fmt.Sprintf("%d%s %v", origin.Source, origin.Rule, found)
	}
	monday, tuesday := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC), time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		got, want string
	}{
		// The folder's default filter yields to the organization's required one.
		{"first filter", located(active.FilterOrigin(0)), "0 true"},
		{"rule filter", located(active.FilterOrigin(1)), "2chat true"},
		{"no filter", located(active.FilterOrigin(2)), "0 false"},
		{"policy deny", located(active.DenyOrigin(monday)), "1 true"},
		{"rule deny", located(active.DenyOrigin(tuesday)), "2chat true"},
		{"inactive rule deny", located(base.DenyOrigin(tuesday)), "0 false"},
		{"policy nodes", located(active.NodesOrigin("openai", "gpt", "chutes-gpt", "chutes", "chutes")), "0 true"},
		{"rule nodes", located(active.NodesOrigin("openai", "gpt", "openai-b", "openai", "openai")), "2chat true"},
		{"allowed nodes", located(active.NodesOrigin("openai", "gpt", "openai-a", "openai", "openai")), "0 false"},
		{"smallest fallbacks", located(active.FallbacksOrigin()), "1 true"},
		{"default order", located(active.OrderOrigin()), "0order true"},
	} {
		if test.got != test.want {
			t.Errorf("%s: origin %s, want %s", test.name, test.got, test.want)
		}
	}
	if len(active.Routing.Query.Filters) != 2 || active.Routing.Fallbacks != 1 {
		t.Fatalf("composition changed: %+v", active.Routing)
	}
	required, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, `{}`)}, {Scope: KeyScope, Value: ruleSource(t, `{"routing":{"order":["a"]}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := located(required.OrderOrigin()); got != "1 true" {
		t.Fatalf("required order origin %s", got)
	}
	if got := located(required.FallbacksOrigin()); got != "0 false" {
		t.Fatalf("default fallbacks origin %s", got)
	}
	query := active.Routing.Query
	for _, test := range []struct {
		values ruleValues
		index  int
		known  bool
	}{
		{ruleValues{"provider.id": {Type: "string", String: "openai"}, "deployment.id": {Type: "string", String: "openai-a"}}, -1, true},
		{ruleValues{"provider.id": {Type: "string", String: "blocked"}}, 0, true},
		{ruleValues{"provider.id": {Type: "string", String: "openai"}}, 1, false},
		{ruleValues{"provider.id": {Type: "string", String: "openai"}, "deployment.id": {Type: "string", String: "openai-b"}}, 1, true},
	} {
		index, known, err := query.FirstFailure(test.values)
		if err != nil || index != test.index || known != test.known {
			t.Fatalf("first failure for %v = %d known %v: %v", test.values, index, known, err)
		}
	}
}

func TestFallbacksAndTotalTimeoutCannotDependOnTheCandidate(t *testing.T) {
	for _, raw := range []string{
		`{"rules":{"r":{"when":"provider.id == 'chutes'","routing":{"fallbacks":0}}}}`,
		`{"rules":{"r":{"when":"request.interface == 'chat_completions' && author.id == 'openai'","routing":{"fallbacks":1}}}}`,
		`{"rules":{"r":{"when":"blended_price(3, 1) < decimal('5')","routing":{"fallbacks":1}}}}`,
		`{"rules":{"r":{"when":"'claude-opus' in model.groupIds","timeouts":{"totalSeconds":60}}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), "author, model, deployment, route or provider fields") {
			t.Fatalf("candidate-dependent fallbacks or total timeout accepted: %s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"rules":{"r":{"when":"request.interface == 'chat_completions'","routing":{"fallbacks":0},"timeouts":{"totalSeconds":60}}}}`,
		`{"rules":{"r":{"when":"provider.id == 'openai'","routing":{"filter":"deployment.id != 'x'","allowedCatalogNodes":{"providers":["openai"]},"retries":2},"timeouts":{"outputIdleSeconds":60}}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err != nil {
			t.Fatalf("stable setting rejected: %s: %v", raw, err)
		}
	}
}

// Orderings come from one chain: organization, folder, grant, key and request.
// A credential policy applies to only some candidates, and role and member
// policies apply beside the chain.
func TestOnlyTheOrderingChainSetsOrderings(t *testing.T) {
	org := ruleSource(t, `{}`)
	for _, raw := range []string{
		`{"routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}`,
		`{"routing":{"sort":[]}}`,
		`{"routing":{"order":["deployment-a"]}}`,
		`{"rules":{"r":{"mode":"default","routing":{"sort":[{"by":"random()"}]}}}}`,
	} {
		for _, scope := range []Scope{CredentialScope, RoleScope, MemberScope} {
			if _, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: scope, Value: ruleSource(t, raw)}}); err == nil || !strings.Contains(err.Error(), string(scope)+" policies cannot") {
				t.Fatalf("%s ordering accepted: %s: %v", scope, raw, err)
			}
		}
		for _, scope := range []Scope{FolderScope, GrantScope, KeyScope} {
			if _, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: scope, Value: ruleSource(t, raw)}}); err != nil {
				t.Fatalf("%s ordering rejected: %s: %v", scope, raw, err)
			}
		}
	}
	for _, raw := range []string{
		`{"routing":{"fallbacks":1}}`,
		`{"timeouts":{"totalSeconds":60}}`,
		`{"rules":{"r":{"when":"request.interface == 'chat_completions'","timeouts":{"totalSeconds":60}}}}`,
	} {
		if _, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: CredentialScope, Value: ruleSource(t, raw)}}); err == nil || !strings.Contains(err.Error(), "credential policies cannot") {
			t.Fatalf("credential request-wide setting accepted: %s: %v", raw, err)
		}
	}
	allowed := ruleSource(t, `{"routing":{"filter":"provider.id == 'openai'","retries":2},"timeouts":{"outputIdleSeconds":60},"rules":{"r":{"when":"provider.id == 'openai'","routing":{"allowedCatalogNodes":{"providers":["openai"]}}}}}`)
	if _, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: CredentialScope, Value: allowed}}); err != nil {
		t.Fatalf("credential restriction rejected: %v", err)
	}
}

func TestRuleConditionsAreTypedAndNeverTreatUnknownAsFalse(t *testing.T) {
	for _, condition := range []string{"request.estimatedInputTokens > 2", "estimated_cost('base') > decimal('1')", "provider.id"} {
		_, err := CompileSource([]byte(`{"rules":{"restricted":{"when":` + quoted(condition) + `,"input":{"asciiOnly":true}}}}`))
		if err == nil {
			t.Fatalf("invalid condition accepted: %s", condition)
		}
	}
	source := ruleSource(t, `{"rules":{"restricted":{"when":"deployment.weightPrecision == 'fp8'","input":{"asciiOnly":true}}}}`)
	config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: source}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Activate(ruleValues{}); !errors.Is(err, ErrUnknownCondition) {
		t.Fatalf("unknown condition silently omitted a restriction: %v", err)
	}
}

func TestRuleCounterIdentityIgnoresFormatting(t *testing.T) {
	first := ruleSource(t, `{"rules":{"paid":{"when":"provider.id=='openai'","limits":{"spend":{"usd":"10"}}}}}`)
	formatted := ruleSource(t, `{"rules":{"paid":{"when":"( provider.id == \"openai\" )","limits":{"spend":{"usd":"20"}}}}}`)
	different := ruleSource(t, `{"rules":{"paid":{"when":"provider.id=='anthropic'","limits":{"spend":{"usd":"20"}}}}}`)
	if first.Rules[0].ConditionDigest() != formatted.Rules[0].ConditionDigest() || first.Rules[0].ConditionDigest() == different.Rules[0].ConditionDigest() {
		t.Fatal("counter condition identity changed incorrectly")
	}
	config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: first}})
	if err != nil {
		t.Fatal(err)
	}
	active, err := config.Activate(ruleValues{"provider.id": {Type: "string", String: "openai"}})
	if err != nil || len(active.ActiveRules) != 1 || active.ActiveRules[0] != (RuleMatch{Source: 0, Name: "paid"}) {
		t.Fatalf("counter selection: %+v, %v", active, err)
	}
}

func TestRuleShapeRejectsNestedAuthorityAndReplaceableBudgets(t *testing.T) {
	for _, body := range []string{
		`{"mode":"default","limits":{"total":{"tokens":1}}}`,
		`{"when":"true"}`, `{"mode":null,"input":{"asciiOnly":true}}`,
		`{"delegation":{"request":true}}`, `{"rules":{"again":{"input":{"asciiOnly":true}}}}`,
		`{"when":"true","encryption":{"keys":{}}}`, `{"version":1,"input":{"asciiOnly":true}}`,
	} {
		if _, err := CompileSource([]byte(`{"rules":{"test":` + body + `}}`)); err == nil {
			t.Fatalf("invalid rule accepted: %s", body)
		}
	}
}

func quoted(value string) string { return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"` }
