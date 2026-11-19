package policy

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
	// The node limit bounds each policy. Policies near it combine, since a
	// chain has no total that another policy's edit could pass.
	inspector := NewInspector(nil, false)
	var sources []ScopedSource
	for i, scope := range []Scope{OrganizationScope, RoleScope, RoleScope, KeyScope} {
		raw := makeSource(3, i, false)
		source, err := CompileSource(raw)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, ScopedSource{Scope: scope, Value: source})
		if err := inspector.Add(InspectionSource{Scope: scope, ID: fmt.Sprint(i), Config: raw}); err != nil {
			t.Fatalf("source %d did not join the combined view: %v", i, err)
		}
	}
	if _, err := ComposeSources(sources); err != nil {
		t.Fatalf("policies within their own limits did not combine: %v", err)
	}
	if _, err := inspector.Finish(); err != nil {
		t.Fatalf("policies within their own limits have no combined view: %v", err)
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
	// The identity excludes the document file's trailing newline.
	digest := sha512.Sum512(expected)
	expected = append(expected, '\n')
	parent, err := ParseSourceDocument([]byte(`{"rules":{"selected":` + settings + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	fragment := parent.rules["selected"].source
	if !bytes.Equal(fragment.CanonicalJSON(), expected) || fragment.Digest() != hex.EncodeToString(digest[:]) {
		t.Fatal("rule fragment changed canonical bytes or identity")
	}
	for _, raw := range []string{
		`{"rules":{"selected":{"Input":{"asciiOnly":true}}}}`,
		`{"rules":{"selected":{"input":{"ASCIIOnly":true}}}}`,
		`{"rules":{"selected":{"input":{"asciiOnly":null}}}}`,
		`{"rules":{"selected":{"plugins":{"redaction":{"presets":null}}}}}`,
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

func TestEachPolicyHasItsOwnExpressionBudget(t *testing.T) {
	for _, condition := range []string{"", `"when":"true",`} {
		raw := `{"rules":{"first":{` + condition + `"input":{"asciiOnly":true}},"second":{` + condition + `"input":{"asciiOnly":true}}}}`
		parent, child := ruleSource(t, raw), ruleSource(t, strings.Replace(raw, "first", "other", 1))
		config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: parent}, {Scope: KeyScope, Value: child}})
		if err != nil {
			t.Fatal(err)
		}
		// The key's policy has one unit left for its two rules. The
		// organization's own allowance does not help it.
		values := budgetRuleValues{budget: NewCELBudget()}
		values.budget.spent[child.work] = MaxPolicyCELCost - 1
		_, err = config.Activate(values)
		if origin, scope, ok := config.WorkLimitOrigin(err); !errors.Is(err, ErrPolicyWorkLimit) || !ok || origin.Source != 1 || scope != KeyScope {
			t.Fatalf("the key policy's rules escaped its work limit or the error names another policy: %v %v %s", err, origin, scope)
		}
		// A policy that used its allowance up leaves the other's untouched.
		values.budget = NewCELBudget()
		values.budget.spent[parent.work] = MaxPolicyCELCost - 2
		if _, err := config.Activate(values); err != nil || values.budget.spent[parent.work] != MaxPolicyCELCost || values.budget.spent[child.work] != 2 {
			t.Fatalf("exact allowance of each policy was not honored: %v %v", err, values.budget.spent)
		}
	}
}

// A key can use thousands of credentials with policies of their own, and each
// is another policy in the request. Together they stop at what one chain may
// cost, and the refusal names no single policy.
func TestPoliciesOfManyCredentialsShareTheRequestTotal(t *testing.T) {
	budget := NewCELBudget()
	activate := func(credential int) (*Config, *Source, error) {
		source := ruleSource(t, fmt.Sprintf(`{"rules":{"rule_%d":{"when":"true","input":{"asciiOnly":true}}}}`, credential))
		config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, `{}`)}, {Scope: CredentialScope, Value: source}, {Scope: KeyScope, Value: ruleSource(t, `{}`)}})
		if err != nil {
			t.Fatal(err)
		}
		// Each policy has one unit left of its own allowance.
		budget.spent[source.work], budget.total = MaxPolicyCELCost-1, budget.total+MaxPolicyCELCost-1
		_, err = config.Activate(budgetRuleValues{budget: budget})
		return config, source, err
	}
	for credential := range 37 {
		if _, _, err := activate(credential); err != nil {
			t.Fatalf("credential policy %d failed within its own allowance and the total: %v", credential, err)
		}
	}
	budget.total -= MaxPolicyCELCost - 1
	config, source, err := activate(37)
	if _, _, named := config.WorkLimitOrigin(err); !errors.Is(err, ErrPolicyWorkLimit) || named || budget.spent[source.work] != MaxPolicyCELCost-1 {
		t.Fatalf("the request total let another policy run or the error names one policy: %v", err)
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
	org := ruleSource(t, `{"delegation":{"requests":true},"rules":{"baseline":{"mode":"default","input":{"asciiOnly":true},"plugins":{"redaction":{"presets":["email_address"]}},"routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}}}`)
	role := ruleSource(t, `{"rules":{"chat":{"when":"request.interface == 'chat_completions'","input":{"asciiOnly":false},"plugins":{"redaction":{"presets":["credit_card_number"]}}}}}`)
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
	org := ruleSource(t, `{"delegation":{"requests":["routing.sort"]},"routing":{"filter":"provider.id == 'openai'"},"rules":{"default_sort":{"mode":"default","routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}}}`)
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
	strict := ruleSource(t, `{"delegation":{"requests":["routing.sort"]},"routing":{"sort":[{"by":"provider.id"}]}}`)
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
	org := ruleSource(t, `{"delegation":{"requests":["timeouts.outputIdleSeconds"]},"timeouts":{"totalSeconds":900},"rules":{"baseline":{"mode":"default","timeouts":{"outputIdleSeconds":90}},"openai":{"when":"provider.id == 'openai'","timeouts":{"outputIdleSeconds":60}}}}`)
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
	settings := `"access":{"schedule":{"deny":[{"days":["mon"],"start":"09:00","end":"17:00","timeZone":"UTC"}]}},"input":{"asciiOnly":true,"mediaTypes":{"allow":["image/png"]}},"plugins":{"classification":["language"],"redaction":{"presets":["email_address"]},"promptCaching":"1h"},"routing":{"providers":{"allow":["openai"]},"filter":"provider.id == 'openai'","sort":[{"by":"provider.id","direction":"asc"}],"retries":1,"fallbacks":0}`
	org := ruleSource(t, `{"rules":{"baseline":{"mode":"default",`+settings+`}}}`)
	empty := ruleSource(t, `{"access":{"schedule":{"deny":[]}},"input":{"asciiOnly":false,"mediaTypes":{"deny":[]}},"plugins":{"classification":[],"redaction":{},"promptCaching":"off"},"routing":{"providers":{"deny":[]},"filter":"true","sort":[],"retries":3,"fallbacks":2}}`)
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
			// Orderings stack, so the default sort applies beside an empty one.
			if (active.Input != nil && active.Input.ASCIIOnly) != withRequired || (len(active.Access.denyPeriods()) > 0) != withRequired || len(active.Routing.Query.OrderBy) != 1 {
				t.Fatalf("required=%v: wrong active restrictions: %+v", withRequired, active)
			}
			// The smallest required value applies; the default rule's never does.
			if want := map[bool][2]int{false: {3, 2}, true: {1, 0}}[withRequired]; active.Routing.Retries != want[0] || active.Routing.Fallbacks != want[1] {
				t.Fatalf("required=%v: retries=%d fallbacks=%d, want %v", withRequired, active.Routing.Retries, active.Routing.Fallbacks, want)
			}
			if (active.Routing.Providers != nil && len(active.Routing.Providers.Allow) > 0) != withRequired {
				t.Fatal("wrong catalog restriction")
			}
			if (active.MediaTypes() != nil && len(active.MediaTypes().Allow) > 0) != withRequired || (active.PromptCaching() == PromptCaching1h) != withRequired {
				t.Fatalf("required=%v: media types %+v, prompt caching %s", withRequired, active.MediaTypes(), active.PromptCaching())
			}
			if (len(active.Classification()) > 0) != withRequired {
				t.Fatalf("required=%v: classifiers %q", withRequired, active.Classification())
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

// Every ordering applies. Required criteria run from the broadest scope to
// the closest, then default criteria from the closest scope to the broadest,
// so each later criterion orders the ties of the ones before it.
func TestRoutingOrderingsStack(t *testing.T) {
	required := func(by string) string { return `{"routing":{"sort":[{"by":"` + by + `"}]}}` }
	preferred := func(by string) string {
		return `{"rules":{"d":{"mode":"default","routing":{"sort":[{"by":"` + by + `"}]}}}}`
	}
	both := func(want, prefer string) string {
		return `{"routing":{"sort":[{"by":"` + want + `"}]},"rules":{"d":{"mode":"default","routing":{"sort":[{"by":"` + prefer + `"}]}}}}`
	}
	scopes := []Scope{OrganizationScope, FolderScope, GrantScope, KeyScope}
	for _, test := range []struct {
		name     string
		sources  [4]string
		sortBy   []string
		origins  []Origin
		required int
	}{
		{"requirements broadest first", [4]string{required("provider.id"), required("model.id"), "", required("deployment.id")},
			[]string{"provider.id", "model.id", "deployment.id"}, []Origin{{0, ""}, {1, ""}, {2, ""}}, 3},
		{"requirements then defaults closest first", [4]string{preferred("provider.id"), required("model.id"), preferred("route.id"), preferred("deployment.id")},
			[]string{"model.id", "deployment.id", "route.id", "provider.id"}, []Origin{{1, ""}, {3, "d"}, {2, "d"}, {0, "d"}}, 1},
		{"defaults only", [4]string{preferred("provider.id"), "", preferred("route.id"), `{}`},
			[]string{"route.id", "provider.id"}, []Origin{{1, "d"}, {0, "d"}}, 0},
		{"one policy requires and prefers", [4]string{both("provider.id", "random()"), "", "", required("model.id")},
			[]string{"provider.id", "model.id", "random()"}, []Origin{{0, ""}, {1, ""}, {0, "d"}}, 2},
		{"an equal criterion is left out", [4]string{preferred("provider.id"), required("provider.id"), "", preferred("model.id")},
			[]string{"provider.id", "model.id"}, []Origin{{1, ""}, {2, "d"}}, 1},
		{"an empty requirement adds nothing", [4]string{preferred("provider.id"), "", "", `{"routing":{"sort":[]}}`},
			[]string{"provider.id"}, []Origin{{0, "d"}}, 0},
		{"none", [4]string{`{}`, "", "", `{}`}, nil, nil, 0},
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
				var sortBy []string
				if config.Routing.Query != nil {
					for _, criterion := range config.Routing.Query.OrderBy {
						sortBy = append(sortBy, criterion.By)
					}
				}
				if !slices.Equal(sortBy, test.sortBy) || !slices.Equal(config.SortOrigins(), test.origins) || config.RequiredSorts() != test.required {
					t.Fatalf("sort %q from %v, %d required", sortBy, config.SortOrigins(), config.RequiredSorts())
				}
			}
		})
	}
	org := ruleSource(t, `{"routing":{"sort":[{"deployments":["deployment-b"]},{"by":"provider.id"}]}}`)
	key := ruleSource(t, `{"routing":{"sort":[{"deployments":["deployment-a"]}]}}`)
	combined, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: key}})
	if err != nil {
		t.Fatal(err)
	}
	sorts := combined.Routing.Query.OrderBy
	if len(sorts) != 3 || !slices.Equal(sorts[0].Deployments, []string{"deployment-b"}) || sorts[1].By != "provider.id" || !slices.Equal(sorts[2].Deployments, []string{"deployment-a"}) {
		t.Fatalf("ordering mixed policies: %+v", sorts)
	}
}

func TestRuleOrderingsAreUnconditionalDefaults(t *testing.T) {
	sort := `"sort":[{"by":"provider.id","direction":"asc"}]`
	for _, raw := range []string{
		`{"rules":{"r":{"routing":{` + sort + `}}}}`,
		`{"rules":{"r":{"mode":"required","routing":{"sort":[{"deployments":["deployment-a"]}]}}}}`,
		`{"rules":{"r":{"when":"request.interface == 'chat_completions'","mode":"default","routing":{` + sort + `}}}}`,
		`{"rules":{"r":{"when":"provider.id == 'openai'","mode":"default","routing":{"sort":[]}}}}`,
		`{"rules":{"r":{"when":"[1].exists(deployment, deployment == 1)","routing":{"sort":[{"by":"random()"}]}}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), "only with mode default and no when") {
			t.Fatalf("conditional or required rule ordering accepted: %s: %v", raw, err)
		}
	}
	// A policy may require one ordering and prefer another, but it prefers
	// at most one.
	if _, err := CompileSource([]byte(`{"routing":{` + sort + `},"rules":{"r":{"mode":"default","routing":{"sort":[{"deployments":["deployment-a"]}]}}}}`)); err != nil {
		t.Fatalf("required and default ordering rejected: %v", err)
	}
	raw := `{"rules":{"a":{"mode":"default","routing":{` + sort + `}},"b":{"mode":"default","routing":{"sort":[{"deployments":["deployment-a"]}]}}}}`
	if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), "in one rule with mode default") {
		t.Fatalf("second default ordering accepted: %s: %v", raw, err)
	}
	source := ruleSource(t, `{"rules":{"r":{"mode":"default","routing":{"filter":"provider.id != 'x'","sort":[{"deployments":["deployment-a"]},{"by":"provider.id","direction":"asc"}]}}}}`)
	if source.defaultOrdering == nil || len(source.defaultOrdering.sorts) != 2 || source.Rules[0].Value.orders() || len(source.Rules[0].Value.Config.Routing.Query.Filters) != 1 {
		t.Fatalf("default ordering did not move to its policy: %+v", source)
	}
}

// A routing simulation names the policy, and the rule, behind each decision.
func TestOriginsLocateTheDecidingPolicyAndRule(t *testing.T) {
	org := ruleSource(t, `{"routing":{"providers":{"allow":["openai","anthropic"]},"filter":"provider.id != 'blocked'","fallbacks":2},"rules":{"order":{"mode":"default","routing":{"sort":[{"by":"provider.id"}]}}}}`)
	folder := ruleSource(t, `{"access":{"schedule":{"deny":[{"days":["mon"],"start":"09:00","end":"17:00","timeZone":"UTC"}]}},"routing":{"deployments":{"deny":["openai-c"]},"fallbacks":1},"rules":{"loose":{"mode":"default","routing":{"filter":"provider.id == 'never'"}}}}`)
	key := ruleSource(t, `{"rules":{"chat":{"when":"request.interface == 'chat_completions'","access":{"schedule":{"deny":[{"days":["tue"],"start":"00:00","end":"23:59","timeZone":"UTC"}]}},"routing":{"deployments":{"allow":["openai-a"]},"filter":"deployment.id != 'openai-b'"}}}}`)
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
		{"policy allow list", located(active.ListsOrigin("openai", "gpt", "chutes-gpt", "chutes", "chutes")), "0 true"},
		{"policy deny list", located(active.ListsOrigin("openai", "gpt", "openai-c", "openai", "openai")), "1 true"},
		{"rule lists", located(active.ListsOrigin("openai", "gpt", "openai-b", "openai", "openai")), "2chat true"},
		{"admitted", located(active.ListsOrigin("openai", "gpt", "openai-a", "openai", "openai")), "0 false"},
		{"smallest fallbacks", located(active.FallbacksOrigin()), "1 true"},
	} {
		if test.got != test.want {
			t.Errorf("%s: origin %s, want %s", test.name, test.got, test.want)
		}
	}
	if len(active.Routing.Query.Filters) != 2 || active.Routing.Fallbacks != 1 {
		t.Fatalf("composition changed: %+v", active.Routing)
	}
	required, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, `{}`)}, {Scope: KeyScope, Value: ruleSource(t, `{"routing":{"sort":[{"deployments":["a"]}]}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := required.SortOrigins(); !slices.Equal(got, []Origin{{Source: 1}}) || required.RequiredSorts() != 1 {
		t.Fatalf("required order origins %v", got)
	}
	if got := active.SortOrigins(); !slices.Equal(got, []Origin{{Source: 0, Rule: "order"}}) || active.RequiredSorts() != 0 {
		t.Fatalf("default order origins %v", got)
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

// A routing simulation shows, for each deployment that a request tries, which settings of the
// matched default rules a requirement replaces there, and which requirement does.
func TestReplacedDefaultsNameTheRequirementOnEachDeployment(t *testing.T) {
	fixture, _ := loadWebcryptoFixture(t)
	envelope, err := json.Marshal(fixture.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	org := ruleSource(t, `{"plugins":{"textExtraction":{"text":"always"}},"rules":{`+
		`"base":{"mode":"default","input":{"asciiOnly":true},"plugins":{"textExtraction":{"text":"off"},"redaction":{"presets":["email_address"]}},"routing":{"retries":2,"sort":[{"by":"provider.id"}]}},`+
		`"strict_openai":{"when":"provider.id == 'openai'","plugins":{"redaction":{"presets":["credit_card_number"]}}}}}`)
	role := ruleSource(t, `{"rules":{`+
		`"openai_too":{"when":"provider.id == 'openai'","plugins":{"redaction":{"presets":["phone_number"]}}},`+
		`"private":{"mode":"default","when":"provider.id != 'openai'","plugins":{"redaction":{"encrypted":`+string(envelope)+`}}},`+
		`"never":{"mode":"default","when":"provider.id == 'none'","timeouts":{"outputIdleSeconds":5}}}}`)
	key := ruleSource(t, `{"routing":{"retries":0,"sort":[{"by":"provider.id","direction":"desc"}]},"rules":{`+
		`"chutes_redaction":{"when":"provider.id == 'chutes'","plugins":{"redaction":{}}}}}`)
	combined, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: RoleScope, Value: role}, {Scope: KeyScope, Value: key}})
	if err != nil {
		t.Fatal(err)
	}
	// Before activation no rule has matched, so nothing is replaced yet.
	if got := combined.ReplacedDefaults(); got != nil {
		t.Fatalf("replaced before activation: %+v", got)
	}
	textExtraction := ReplacedDefault{Setting: "plugins.textExtraction.text", Default: Origin{Source: 0, Rule: "base"}, By: Origin{Source: 0}}
	retries := ReplacedDefault{Setting: "routing.retries", Default: Origin{Source: 0, Rule: "base"}, By: Origin{Source: 2}}
	for provider, want := range map[string][]ReplacedDefault{
		// Two required rules replace the default redaction; the first in the chain is named. The
		// unmatched default sets nothing, and orderings and input, which no requirement sets, stay.
		"openai": {
			{Setting: "plugins.redaction", Default: Origin{Source: 0, Rule: "base"}, By: Origin{Source: 0, Rule: "strict_openai"}, Others: 1},
			textExtraction, retries,
		},
		// No requirement sets redaction, so both default redactions apply, the encrypted one too.
		"anthropic": {textExtraction, retries},
		// An empty redaction replaces each default redaction, encrypted or not.
		"chutes": {
			{Setting: "plugins.redaction", Default: Origin{Source: 0, Rule: "base"}, By: Origin{Source: 2, Rule: "chutes_redaction"}},
			textExtraction, retries,
			{Setting: "plugins.redaction", Default: Origin{Source: 1, Rule: "private"}, By: Origin{Source: 2, Rule: "chutes_redaction"}},
		},
	} {
		active, err := combined.Activate(ruleValues{"provider.id": {Type: "string", String: provider}})
		if err != nil {
			t.Fatal(err)
		}
		if got := active.ReplacedDefaults(); !slices.Equal(got, want) {
			t.Errorf("%s: replaced %+v, want %+v", provider, got, want)
		}
		// What the list names is what composition dropped.
		replaced := slices.ContainsFunc(active.ReplacedDefaults(), func(r ReplacedDefault) bool { return r.Default.Rule == "private" })
		if opaque := len(active.ActiveEncryptedPlugins) > 0; provider != "openai" && opaque == replaced {
			t.Errorf("%s: encrypted default applies %v, listed as replaced %v", provider, opaque, replaced)
		}
	}
}

// Each kind of setting that a default can lose to a requirement has one name, so a new kind
// cannot go unlisted.
func TestEveryReplaceableKindHasOneName(t *testing.T) {
	var kinds Permission
	var names []string
	for _, setting := range replaceableSettings {
		if kinds&setting.kind != 0 {
			t.Fatalf("%s repeats a kind", setting.name)
		}
		kinds |= setting.kind
		names = append(names, setting.name)
	}
	if want := requestPermissions &^ permissionSort &^ permissionEncryptedPlugins; kinds != want {
		t.Fatalf("named kinds %b, want %b", kinds, want)
	}
	if want := []string{
		"access.countries", "access.networks", "access.schedule", "access.transports", "input.asciiOnly", "input.mediaTypes",
		"plugins.classification", "plugins.export", "plugins.promptCaching", "plugins.redaction", "plugins.textExtraction.office",
		"plugins.textExtraction.pdf", "plugins.textExtraction.text", "routing.authors", "routing.deployments", "routing.fallbacks", "routing.filter",
		"routing.missingEncryptionKeys", "routing.models", "routing.providers", "routing.retries", "routing.routes",
		"timeouts.outputIdleSeconds", "timeouts.totalSeconds",
	}; !slices.Equal(names, want) {
		t.Fatalf("names %q", names)
	}
}

func TestFallbacksAndTotalTimeoutCannotDependOnTheCandidate(t *testing.T) {
	for _, raw := range []string{
		`{"rules":{"r":{"when":"provider.id == 'chutes'","routing":{"fallbacks":0}}}}`,
		`{"rules":{"r":{"when":"request.interface == 'chat_completions' && author.id == 'openai'","routing":{"fallbacks":1}}}}`,
		`{"rules":{"r":{"when":"blendedPrice(3, 1) < decimal('5')","routing":{"fallbacks":1}}}}`,
		`{"rules":{"r":{"when":"'claude-opus' in model.groupIds","timeouts":{"totalSeconds":60}}}}`,
		`{"rules":{"r":{"when":"credential.kind == 'managed'","routing":{"fallbacks":0}}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), "author, model, deployment, route, provider or credential fields") {
			t.Fatalf("candidate-dependent fallbacks or total timeout accepted: %s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"rules":{"r":{"when":"request.interface == 'chat_completions'","routing":{"fallbacks":0},"timeouts":{"totalSeconds":60}}}}`,
		`{"rules":{"r":{"when":"provider.id == 'openai'","routing":{"filter":"deployment.id != 'x'","providers":{"allow":["openai"]},"retries":2},"timeouts":{"outputIdleSeconds":60}}}}`,
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
		`{"routing":{"sort":[{"deployments":["deployment-a"]}]}}`,
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
	allowed := ruleSource(t, `{"routing":{"filter":"provider.id == 'openai'","retries":2},"timeouts":{"outputIdleSeconds":60},"rules":{"r":{"when":"provider.id == 'openai'","routing":{"providers":{"allow":["openai"]}}}}}`)
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
		`{"delegation":{"requests":true}}`, `{"rules":{"again":{"input":{"asciiOnly":true}}}}`,
		`{"version":1,"input":{"asciiOnly":true}}`,
	} {
		if _, err := CompileSource([]byte(`{"rules":{"test":` + body + `}}`)); err == nil {
			t.Fatalf("invalid rule accepted: %s", body)
		}
	}
}

func quoted(value string) string { return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"` }

const (
	excludedFolder = "018f6f3d-0000-7000-8000-00000000000f"
	excludedGrant  = "018f6f3d-0000-7000-8000-000000000001"
	excludedMember = "018f6f3d-0000-7000-8000-000000000002"
	excludedKey    = "018f6f3d-0000-7000-8000-000000000003"
	otherKey       = "018f6f3d-0000-7000-8000-000000000004"
)

func TestRulesSkipTheKeysThatTheyExclude(t *testing.T) {
	org := ruleSource(t, `{"rules":{
		"ascii":{"exclude":{"keys":["`+excludedKey+`"],"grants":["`+excludedGrant+`"]},"input":{"asciiOnly":true},"limits":{"daily":{"requests":5}}},
		"members":{"exclude":{"members":["`+excludedMember+`"]},"when":"request.interface == 'chat_completions'","timeouts":{"outputIdleSeconds":30}},
		"always":{"routing":{"retries":0}}}}`)
	folder := ruleSource(t, `{"rules":{"fallback":{"mode":"default","input":{"asciiOnly":false}},"folder":{"exclude":{"keys":["`+excludedKey+`"],"grants":["`+excludedGrant+`"],"members":["`+excludedMember+`"]},"routing":{"fallbacks":0}}}}`)
	key := ruleSource(t, `{}`)
	chain := func(grant, member, id string) []ScopedSource {
		return []ScopedSource{{Scope: OrganizationScope, ID: "org", Value: org}, {Scope: FolderScope, ID: excludedFolder, Value: folder},
			{Scope: GrantScope, ID: grant, Value: key}, {Scope: MemberScope, ID: member, Value: key}, {Scope: KeyScope, ID: id, Value: key}}
	}
	values := ruleValues{"request.interface": {Type: "string", String: "chat_completions"}}
	for _, test := range []struct {
		name           string
		sources        []ScopedSource
		ascii          bool
		idle, limits   int
		fallbacks      int
		skippedInChain int
	}{
		{"no listed resource", chain(otherKey, otherKey, otherKey), true, 30, 1, 0, 0},
		{"listed key", chain(otherKey, otherKey, excludedKey), false, 30, 0, DefaultFallbacks, 2},
		{"listed grant", chain(excludedGrant, otherKey, otherKey), false, 30, 0, DefaultFallbacks, 2},
		{"listed member", chain(otherKey, excludedMember, otherKey), true, 0, 1, DefaultFallbacks, 2},
		// An ID matches only the kind that lists it.
		{"key ID as a member", chain(otherKey, excludedKey, otherKey), true, 30, 1, 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			composed, err := ComposeSources(test.sources)
			if err != nil {
				t.Fatal(err)
			}
			active, err := composed.Activate(values)
			if err != nil {
				t.Fatal(err)
			}
			idle := 0
			if active.Timeouts != nil && active.Timeouts.OutputIdleSeconds != nil {
				idle = *active.Timeouts.OutputIdleSeconds
			}
			// A skipped requirement leaves the folder's default in place, and its limit counts nothing.
			if ascii := active.Input != nil && active.Input.ASCIIOnly; ascii != test.ascii || idle != test.idle || len(active.ActiveRules) != test.limits ||
				active.Routing.Fallbacks != test.fallbacks || active.Routing.Retries != 0 {
				t.Fatalf("ascii=%v idle=%d limits=%v fallbacks=%d retries=%d", ascii, idle, active.ActiveRules, active.Routing.Fallbacks, active.Routing.Retries)
			}
			skipped := 0
			for i, entry := range composed.sources {
				skipped += len(test.sources[i].Value.Rules) - len(entry.Value.Rules)
			}
			if skipped != test.skippedInChain || (skipped > 0) != (composed.copiedBytes > 0) {
				t.Fatalf("skipped=%d copied=%d", skipped, composed.copiedBytes)
			}
			if len(org.Rules) != 3 || len(folder.Rules) != 2 {
				t.Fatal("composition changed a shared source")
			}
			// Keys share composed settings by this name, so it separates the chains that skip rules.
			if same := ChainDigest(test.sources) == ChainDigest(chain(otherKey, otherKey, otherKey)); same != (skipped == 0) {
				t.Fatalf("chain digest equal=%v with %d skipped rules", same, skipped)
			}
			// A request policy keeps the saved chain's skipped rules out.
			request, err := CompileRequest([]byte(`{"routing":{"retries":0}}`), "org", nil)
			if err != nil {
				t.Fatal(err)
			}
			composed.RequestPermission = RequestPermission(requestPermissions)
			applied, err := ApplyRequest(composed, request)
			if err != nil {
				t.Fatal(err)
			}
			if active, err = applied.Activate(values); err != nil || (active.Input != nil && active.Input.ASCIIOnly) != test.ascii {
				t.Fatalf("request policy changed the skipped rules: %v", err)
			}
		})
	}
	// Chains that name no resources skip nothing and keep the digest of their content alone.
	bare := []ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: key}}
	raw, _ := json.Marshal([][]string{{"organization", org.Digest}, {"key", key.Digest}})
	sum := sha256.Sum256(raw)
	if composed, err := ComposeSources(bare); err != nil || len(composed.sources[0].Value.Rules) != 3 || ChainDigest(bare) != hex.EncodeToString(sum[:]) {
		t.Fatalf("a chain without resource IDs skipped a rule or changed its digest: %v", err)
	}
}

func TestExclusionsNameOnlyResourcesUnderTheirPolicy(t *testing.T) {
	rule := func(exclude string) string {
		return `{"rules":{"r":{"exclude":` + exclude + `,"input":{"asciiOnly":true}}}}`
	}
	for _, exclude := range []string{
		`{}`, `[]`, `["` + excludedKey + `"]`, `null`, `{"keys":[]}`, `{"keys":null}`, `{"keys":"` + excludedKey + `"}`,
		`{"roles":["` + excludedKey + `"]}`, `{"credentials":["` + excludedKey + `"]}`, `{"Keys":["` + excludedKey + `"]}`,
		`{"keys":["key"]}`, `{"keys":["` + strings.ToUpper(excludedKey) + `"]}`, `{"keys":["` + excludedKey + `","` + excludedKey + `"]}`,
	} {
		if _, err := CompileSource([]byte(rule(exclude))); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("exclude %s compiled: %v", exclude, err)
		}
	}
	// Every default ordering of a chain applies, so none can leave a key out.
	if _, err := CompileSource([]byte(`{"rules":{"r":{"mode":"default","exclude":{"keys":["` + excludedKey + `"]},"routing":{"sort":[{"by":"provider.id"}]}}}}`)); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("a default ordering took exclusions: %v", err)
	}
	kinds := map[Scope][]string{OrganizationScope: {"folders", "grants", "members", "keys"}, FolderScope: {"grants", "members", "keys"}, GrantScope: {"members", "keys"}}
	empty := ruleSource(t, `{}`)
	for _, scope := range []Scope{OrganizationScope, FolderScope, GrantScope, RoleScope, MemberScope, CredentialScope, KeyScope} {
		for kind := range exclusionKinds {
			source := ruleSource(t, rule(`{"`+kind+`":["`+excludedKey+`"]}`))
			sources := []ScopedSource{{Scope: OrganizationScope, Value: empty}, {Scope: scope, Value: source}, {Scope: KeyScope, Value: empty}}
			if scope == OrganizationScope || scope == KeyScope {
				sources = []ScopedSource{{Scope: OrganizationScope, Value: empty}, {Scope: KeyScope, Value: empty}}
				sources[map[Scope]int{OrganizationScope: 0, KeyScope: 1}[scope]].Value = source
			}
			_, err := ComposeSources(sources)
			if allowed := slices.Contains(kinds[scope], kind); allowed != (err == nil) || err != nil && !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("%s policy excluding %s: allowed=%v err=%v", scope, kind, allowed, err)
			}
		}
	}
	// A key cannot leave itself out of its own rule, and a request cannot leave its key out.
	own := ruleSource(t, rule(`{"keys":["`+excludedKey+`"]}`))
	if _, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: empty}, {Scope: KeyScope, ID: excludedKey, Value: own}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("a key policy excluded its own key: %v", err)
	}
	parent, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, `{"delegation":{"requests":true}}`)}, {Scope: KeyScope, ID: excludedKey, Value: empty}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := CompileRequest([]byte(rule(`{"keys":["`+excludedKey+`"]}`)), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRequest(parent, request); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("a request policy took exclusions: %v", err)
	}
}

func TestInspectionMarksSkippedRulesWithoutTheirLists(t *testing.T) {
	org := `{"rules":{"ascii":{"exclude":{"keys":["` + excludedKey + `","` + otherKey + `"]},"input":{"asciiOnly":true}},"kept":{"plugins":{"promptCaching":"off"}}}}`
	folder := `{"rules":{"fallback":{"mode":"default","input":{"asciiOnly":false}}}}`
	inspect := func(key string) []any {
		inspection, err := InspectSources([]InspectionSource{{Scope: OrganizationScope, ID: "org", Config: json.RawMessage(org)},
			{Scope: FolderScope, ID: excludedFolder, Config: json.RawMessage(folder)}, {Scope: KeyScope, ID: key, Config: json.RawMessage(`{}`)}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(inspection.Effective["rules"])
		var rules []any
		if err := json.Unmarshal(raw, &rules); err != nil {
			t.Fatal(err)
		}
		return rules
	}
	skipped, applied := inspect(excludedKey), inspect("018f6f3d-0000-7000-8000-000000000009")
	want := map[string]any{"scope": "key", "id": excludedKey}
	ascii, fallback := skipped[0].(map[string]any), skipped[2].(map[string]any)
	if !reflect.DeepEqual(ascii["skipped"], want) || ascii["config"].(map[string]any)["exclude"] != nil || fallback["replaced"] != nil || skipped[1].(map[string]any)["skipped"] != nil {
		t.Fatalf("skipped rule: %v, default: %v", ascii, fallback)
	}
	ascii, fallback = applied[0].(map[string]any), applied[2].(map[string]any)
	if ascii["skipped"] != nil || ascii["config"].(map[string]any)["exclude"] != nil || fallback["replaced"] == nil {
		t.Fatalf("applied rule: %v, default: %v", ascii, fallback)
	}
}

// A kept rule's exclusions decide which keys its settings apply to, so a
// policy that can no longer set a section cannot change them either.
func TestChangingExclusionsNeedsTheRuleSectionsPermission(t *testing.T) {
	folder := func(exclude string) string {
		return `{"rules":{"ascii":{"exclude":{"keys":[` + exclude + `]},"input":{"asciiOnly":true}}}}`
	}
	inspect := func(delegation, proposal, previous string) error {
		_, err := InspectSources([]InspectionSource{
			{Scope: OrganizationScope, ID: "org", Config: json.RawMessage(`{"delegation":{"folders":` + delegation + `}}`)},
			{Scope: FolderScope, ID: excludedFolder, Config: json.RawMessage(proposal)},
			{Scope: KeyScope, Config: json.RawMessage(`{}`)},
		}, &InspectionEdit{Scope: FolderScope, ID: excludedFolder, Previous: json.RawMessage(previous)})
		return err
	}
	one, two := `"`+excludedKey+`"`, `"`+excludedKey+`","`+otherKey+`"`
	if err := inspect(`["limits"]`, folder(one), folder(one)); err != nil {
		t.Fatalf("an unchanged kept rule failed: %v", err)
	}
	for _, change := range [][2]string{{one, two}, {two, one}} {
		if err := inspect(`["limits"]`, folder(change[1]), folder(change[0])); !errors.Is(err, ErrPolicyEditForbidden) {
			t.Fatalf("exclusions of a kept rule changed from %s to %s: %v", change[0], change[1], err)
		}
		if err := inspect(`["input"]`, folder(change[1]), folder(change[0])); err != nil {
			t.Fatalf("a permitted section's exclusions could not change: %v", err)
		}
	}
}
