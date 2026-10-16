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
	settings := `{"limits":{"custom":{"\ue000":1e+0,"\ud83d\ude00":-0}},"plugins":{"stogasRedaction":{"literals":[{"values":["<>&\u2028é"]}]}},"routing":{"filter":"true"}}`
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
		`{"rules":{"selected":{"plugins":{"stogasRedaction":{"email_address":null}}}}}`,
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
		config, err := ComposeSources([]ScopedSource{{OrganizationScope, source}})
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
	org := ruleSource(t, `{"delegation":{"request":true},"rules":{"baseline":{"mode":"default","input":{"asciiOnly":true},"plugins":{"stogasRedaction":{"email_address":true}},"routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}}}`)
	role := ruleSource(t, `{"rules":{"chat":{"when":"request.route == 'chat'","input":{"asciiOnly":false},"plugins":{"stogasRedaction":{"credit_card_number":true}},"routing":{"sort":[{"by":"deployment.id","direction":"desc"}]}}}}`)
	other := ruleSource(t, `{"routing":{"filter":"provider.id != 'blocked'"}}`)
	for _, sources := range [][]ScopedSource{
		{{OrganizationScope, org}, {RoleScope, role}, {RoleScope, other}},
		{{OrganizationScope, org}, {RoleScope, other}, {RoleScope, role}},
	} {
		combined, err := ComposeSources(sources)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range []string{"chat", "responses"} {
			active, err := combined.Activate(ruleValues{"request.route": {Type: "string", String: route}})
			if err != nil {
				t.Fatal(err)
			}
			if active.Input != nil && active.Input.ASCIIOnly != (route == "responses") {
				t.Fatalf("wrong input requirement for %s", route)
			}
			if route == "responses" && active.Input == nil {
				t.Fatal("default input requirement disappeared")
			}
			preset, sortBy := "email_address", "provider.id"
			if route == "chat" {
				preset, sortBy = "credit_card_number", "deployment.id"
			}
			if len(active.PluginSources) != 1 || active.PluginSources[0].StogasRedaction.Presets[0] != preset || active.Routing.Query.OrderBy[0].By != sortBy {
				t.Fatalf("wrong settings for %s: %+v", route, active)
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
	base, err := ComposeSources([]ScopedSource{{OrganizationScope, org}})
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
	denied, err := CompileRequest([]byte(`{"rules":{"nested":{"routing":{"filter":"true"}}}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRequest(base, denied); !errors.Is(err, ErrRequestPolicyDenied) {
		t.Fatalf("nested rule bypassed section permission: %v", err)
	}
}

func TestTimeoutRulesComposeIndependentlyWithoutMutatingSavedPolicies(t *testing.T) {
	org := ruleSource(t, `{"delegation":{"request":["timeouts.outputIdleSeconds"]},"timeouts":{"totalSeconds":900},"rules":{"baseline":{"mode":"default","timeouts":{"outputIdleSeconds":90}},"openai":{"when":"provider.id == 'openai'","timeouts":{"totalSeconds":600}}}}`)
	key := ruleSource(t, `{"timeouts":{"totalSeconds":1200}}`)
	base, err := ComposeSources([]ScopedSource{{OrganizationScope, org}, {KeyScope, key}})
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
			if provider == "openai" {
				wantTotal = 600 * time.Second
			}
			if config == base {
				wantIdle = 90 * time.Second
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
	settings := `"access":{"deny":[{"days":["mon"],"start":"09:00","end":"17:00","timeZone":"UTC"}]},"input":{"asciiOnly":true},"plugins":{"stogasRedaction":{"email_address":true}},"routing":{"allowedCatalogNodes":{"providers":["openai"]},"filter":"provider.id == 'openai'","sort":[{"by":"provider.id","direction":"asc"}],"retries":1,"fallbacks":0}`
	org := ruleSource(t, `{"rules":{"baseline":{"mode":"default",`+settings+`}}}`)
	empty := ruleSource(t, `{"access":{"deny":[]},"input":{"asciiOnly":false},"plugins":{"stogasRedaction":{}},"routing":{"allowedCatalogNodes":{},"filter":"true","sort":[],"retries":3,"fallbacks":2}}`)
	required := ruleSource(t, `{`+settings+`}`)
	for _, withRequired := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			sources := []ScopedSource{{OrganizationScope, org}, {RoleScope, empty}}
			if withRequired {
				sources = append(sources, ScopedSource{RoleScope, required})
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
				hasPreset = hasPreset || len(plugins.StogasRedaction.Presets) > 0
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

func TestRulesRequiredSortsMustAgree(t *testing.T) {
	org := ruleSource(t, `{"routing":{"sort":[{"by":" provider.id ","direction":"asc"}]}}`)
	same := ruleSource(t, `{"routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}`)
	if _, err := ComposeSources([]ScopedSource{{OrganizationScope, org}, {RoleScope, same}}); err != nil {
		t.Fatalf("equivalent sorts conflict: %v", err)
	}
	conflict := ruleSource(t, `{"routing":{"sort":[{"by":"provider.id","direction":"desc"}]}}`)
	for _, values := range [][]ScopedSource{
		{{OrganizationScope, org}, {RoleScope, conflict}, {RoleScope, same}},
		{{OrganizationScope, org}, {RoleScope, same}, {RoleScope, conflict}},
	} {
		if _, err := ComposeSources(values); err == nil {
			t.Fatal("conflicting required sorts were accepted")
		}
	}
}

// routing.order and routing.sort form one ordering. Another policy may repeat
// it but not add to it, and a required ordering replaces a default one.
func TestPoliciesThatSetAnOrderingMustSetTheSameOne(t *testing.T) {
	ordered := `"order":["deployment-b","deployment-a"]`
	sorted := `"sort":[{"by":"provider.id"}]`
	org := ruleSource(t, `{"routing":{`+ordered+`,`+sorted+`}}`)
	for _, raw := range []string{
		`{"routing":{` + ordered + `,"sort":[{"by":"provider.id","direction":"asc"}]}}`,
		`{"routing":{"filter":"provider.id != 'x'"}}`,
		`{"rules":{"r":{"mode":"default","routing":{"order":["deployment-a"]}}}}`,
	} {
		combined, err := ComposeSources([]ScopedSource{{OrganizationScope, org}, {KeyScope, ruleSource(t, raw)}})
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if combined, err = combined.Activate(ruleValues{}); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if !slices.Equal(combined.Routing.Order, []string{"deployment-b", "deployment-a"}) || len(combined.Routing.Query.OrderBy) != 1 {
			t.Fatalf("%s: ordering = %v %+v", raw, combined.Routing.Order, combined.Routing.Query)
		}
	}
	for _, raw := range []string{
		`{"routing":{"order":["deployment-a","deployment-b"],` + sorted + `}}`,
		`{"routing":{` + ordered + `}}`,
		`{"routing":{` + sorted + `}}`,
		`{"routing":{` + ordered + `,"sort":[{"by":"provider.id"},{"by":"random()"}]}}`,
		`{"rules":{"r":{"routing":{"order":["deployment-c"]}}}}`,
	} {
		combined, err := ComposeSources([]ScopedSource{{OrganizationScope, org}, {KeyScope, ruleSource(t, raw)}})
		if err == nil {
			_, err = combined.Activate(ruleValues{})
		}
		if err == nil || !strings.Contains(err.Error(), "different routing orders") {
			t.Fatalf("%s: conflicting ordering accepted: %v", raw, err)
		}
	}
}

func TestRoutingOrderCannotDependOnTheCandidate(t *testing.T) {
	sort := `"sort":[{"by":"provider.id","direction":"asc"}]`
	for _, raw := range []string{
		`{"rules":{"r":{"when":"provider.id == 'openai'","routing":{` + sort + `}}}}`,
		`{"rules":{"r":{"when":"has(deployment.weightPrecision)","routing":{"order":["deployment-a"]}}}}`,
		`{"rules":{"r":{"when":"author.id == 'openai'","routing":{"sort":[{"by":"random()"}]}}}}`,
		`{"rules":{"r":{"when":"blended_price(3, 1) < decimal('5')","mode":"default","routing":{` + sort + `}}}}`,
		`{"rules":{"r":{"when":"request.route == 'chat' && author.id == 'openai'","routing":{"sort":[]}}}}`,
		`{"rules":{"r":{"when":"model.id.startsWith('gpt') || route.id == 'chat'","routing":{` + sort + `}}}}`,
		`{"rules":{"r":{"when":"provider.id == 'chutes'","routing":{"fallbacks":0}}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), "author, model, deployment, route or provider fields") {
			t.Fatalf("candidate-dependent order accepted: %s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"rules":{"r":{"when":"request.route == 'chat'","routing":{` + sort + `}}}}`,
		`{"rules":{"r":{"when":"[1].exists(deployment, deployment == 1)","routing":{"sort":[{"by":"random()"}]}}}}`,
		`{"rules":{"r":{"when":"request.route == 'chat'","routing":{"order":["deployment-a"]}}}}`,
		`{"rules":{"r":{"when":"provider.id == 'openai'","routing":{"filter":"deployment.id != 'x'","allowedCatalogNodes":{"providers":["openai"]},"retries":2}}}}`,
		`{"rules":{"r":{"when":"request.route == 'chat'","routing":{"fallbacks":0}}}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err != nil {
			t.Fatalf("stable order rejected: %s: %v", raw, err)
		}
	}
	// A credential policy applies only to that credential's candidates.
	org := ruleSource(t, `{}`)
	for _, raw := range []string{
		`{"routing":{` + sort + `}}`,
		`{"routing":{"sort":[]}}`,
		`{"routing":{"order":["deployment-a"]}}`,
		`{"rules":{"r":{"routing":{` + sort + `}}}}`,
		`{"rules":{"r":{"when":"request.route == 'chat'","mode":"default","routing":{"sort":[{"by":"random()"}]}}}}`,
		`{"routing":{"fallbacks":1}}`,
	} {
		if _, err := ComposeSources([]ScopedSource{{OrganizationScope, org}, {CredentialScope, ruleSource(t, raw)}}); err == nil || !strings.Contains(err.Error(), "credential policies cannot") {
			t.Fatalf("credential order accepted: %s: %v", raw, err)
		}
		if _, err := ComposeSources([]ScopedSource{{OrganizationScope, org}, {KeyScope, ruleSource(t, raw)}}); err != nil {
			t.Fatalf("key order rejected: %s: %v", raw, err)
		}
	}
	allowed := ruleSource(t, `{"routing":{"filter":"provider.id == 'openai'","retries":2},"rules":{"r":{"when":"provider.id == 'openai'","routing":{"allowedCatalogNodes":{"providers":["openai"]}}}}}`)
	if _, err := ComposeSources([]ScopedSource{{OrganizationScope, org}, {CredentialScope, allowed}}); err != nil {
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
	config, err := ComposeSources([]ScopedSource{{OrganizationScope, source}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Activate(ruleValues{}); !errors.Is(err, ErrUnknownCondition) {
		t.Fatalf("unknown condition silently omitted a restriction: %v", err)
	}
}

func TestRuleCounterIdentityIgnoresFormatting(t *testing.T) {
	first := ruleSource(t, `{"rules":{"paid":{"when":"provider.id=='openai'","limits":{"spend":{"lifetimeUsd":"10"}}}}}`)
	formatted := ruleSource(t, `{"rules":{"paid":{"when":"( provider.id == \"openai\" )","limits":{"spend":{"lifetimeUsd":"20"}}}}}`)
	different := ruleSource(t, `{"rules":{"paid":{"when":"provider.id=='anthropic'","limits":{"spend":{"lifetimeUsd":"20"}}}}}`)
	if first.Rules[0].ConditionDigest() != formatted.Rules[0].ConditionDigest() || first.Rules[0].ConditionDigest() == different.Rules[0].ConditionDigest() {
		t.Fatal("counter condition identity changed incorrectly")
	}
	config, err := ComposeSources([]ScopedSource{{OrganizationScope, first}})
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
		`{"mode":"default","limits":{"lifetimeTokens":1}}`,
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
