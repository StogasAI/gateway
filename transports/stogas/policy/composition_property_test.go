package policy

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

// The scalar settings that compose by minimum. Fallbacks and the total wait
// cover the whole request; retries and the idle wait belong to each pair.
type scalarUnit struct {
	section, field string
	choices        []int
	requestWide    bool
}

var scalarUnits = []scalarUnit{
	{"routing", "retries", []int{0, 1, 2, 3}, false},
	{"routing", "fallbacks", []int{0, 1, 2}, true},
	{"timeouts", "totalSeconds", []int{1, 30, 600, 3600}, true},
	{"timeouts", "outputIdleSeconds", []int{1, 15, 300, 3600}, false},
}

// A policy part: a source's top level, which is required, or one of its rules.
type scalarPart struct {
	values  map[int]int // unit index to value
	dflt    bool
	when    string
	matches func(provider, iface string) bool
}

var partConditions = []struct {
	when    string
	matches func(provider, iface string) bool
}{
	{"", func(string, string) bool { return true }},
	// Reads the candidate, so only per-pair settings may follow it.
	{"provider.id == 'openai'", func(provider, _ string) bool { return provider == "openai" }},
	{"request.interface == 'chat_completions'", func(_, iface string) bool { return iface == "chat_completions" }},
}

func randomPart(rng *rand.Rand, rule bool) scalarPart {
	part := scalarPart{values: map[int]int{}, matches: partConditions[0].matches}
	if rule {
		condition := partConditions[rng.IntN(len(partConditions))]
		part.when, part.matches, part.dflt = condition.when, condition.matches, rng.IntN(2) == 0
	}
	allowed := []int{}
	for index, unit := range scalarUnits {
		if unit.requestWide && strings.HasPrefix(part.when, "provider.") {
			continue
		}
		allowed = append(allowed, index)
		if rng.IntN(3) == 0 {
			part.values[index] = unit.choices[rng.IntN(len(unit.choices))]
		}
	}
	// A rule sets at least one setting.
	if rule && len(part.values) == 0 {
		index := allowed[rng.IntN(len(allowed))]
		part.values[index] = scalarUnits[index].choices[rng.IntN(len(scalarUnits[index].choices))]
	}
	return part
}

func (p scalarPart) fields() map[string]any {
	out := map[string]any{}
	for index, value := range p.values {
		unit := scalarUnits[index]
		section, _ := out[unit.section].(map[string]any)
		if section == nil {
			section = map[string]any{}
			out[unit.section] = section
		}
		section[unit.field] = value
	}
	return out
}

func scalarSourceJSON(t *testing.T, top scalarPart, rules []scalarPart, organization bool) []byte {
	t.Helper()
	doc := top.fields()
	if organization {
		doc["delegation"] = map[string]any{"request": true}
	}
	if len(rules) > 0 {
		named := map[string]any{}
		for index, rule := range rules {
			body := rule.fields()
			if rule.when != "" {
				body["when"] = rule.when
			}
			if rule.dflt {
				body["mode"] = "default"
			}
			named[fmt.Sprintf("r%d", index)] = body
		}
		doc["rules"] = named
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The documented composition: requirements intersect, so the smallest
// required value applies; defaults apply only to a unit that no matched part
// requires, the smallest of them; with neither, the built-in value.
func referenceScalar(parts []scalarPart, unit int, provider, iface string) (int, bool) {
	required, preferred := []int{}, []int{}
	for _, part := range parts {
		value, ok := part.values[unit]
		if !ok || !part.matches(provider, iface) {
			continue
		}
		if part.dflt {
			preferred = append(preferred, value)
		} else {
			required = append(required, value)
		}
	}
	if len(required) > 0 {
		return slices.Min(required), true
	}
	if len(preferred) > 0 {
		return slices.Min(preferred), true
	}
	return 0, false
}

func activeScalar(t *testing.T, config *Config, unit int) (int, bool) {
	t.Helper()
	switch scalarUnits[unit].field {
	case "retries":
		return config.Routing.Retries, true
	case "fallbacks":
		return config.Routing.Fallbacks, true
	case "totalSeconds":
		if config.Timeouts == nil || config.Timeouts.TotalSeconds == nil {
			return int(config.Timeouts.Total() / time.Second), false
		}
		return *config.Timeouts.TotalSeconds, true
	default:
		if config.Timeouts == nil || config.Timeouts.OutputIdleSeconds == nil {
			return int(config.Timeouts.OutputIdle() / time.Second), false
		}
		return *config.Timeouts.OutputIdleSeconds, true
	}
}

// Every chain of saved policies, with required and default values, plain and
// conditional rules and a request policy, composes as the reference model
// says, whatever order the non-organization sources arrive in.
func TestScalarCompositionMatchesTheReferenceModelInEveryOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(9, 31))
	builtIn := map[string]int{"retries": 0, "fallbacks": DefaultFallbacks, "totalSeconds": int(MaxRequestTimeout / time.Second), "outputIdleSeconds": int(DefaultOutputIdleTimeout / time.Second)}
	scopes := []Scope{FolderScope, GrantScope, RoleScope, RoleScope, MemberScope, KeyScope}
	for trial := range 3000 {
		var parts []scalarPart
		var sources []ScopedSource
		for index, scope := range append([]Scope{OrganizationScope}, scopes...) {
			if index > 0 && rng.IntN(3) == 0 {
				continue
			}
			top := randomPart(rng, false)
			rules := make([]scalarPart, rng.IntN(3))
			for i := range rules {
				rules[i] = randomPart(rng, true)
			}
			raw := scalarSourceJSON(t, top, rules, index == 0)
			source, err := CompileSource(raw)
			if err != nil {
				t.Fatalf("trial %d: %s: %v", trial, raw, err)
			}
			parts = append(append(parts, top), rules...)
			sources = append(sources, ScopedSource{Scope: scope, Value: source})
		}
		var request *Request
		if rng.IntN(2) == 0 {
			top := randomPart(rng, false)
			rules := make([]scalarPart, rng.IntN(2))
			for i := range rules {
				rules[i] = randomPart(rng, true)
			}
			raw := scalarSourceJSON(t, top, rules, false)
			compiled, err := CompileRequest(raw, "org", nil)
			if err != nil {
				t.Fatalf("trial %d: request %s: %v", trial, raw, err)
			}
			request, parts = compiled, append(append(parts, top), rules...)
		}
		shuffled := append([]ScopedSource{sources[0]}, sources[1:]...)
		rng.Shuffle(len(shuffled)-1, func(i, j int) { shuffled[i+1], shuffled[j+1] = shuffled[j+1], shuffled[i+1] })
		var configs []*Config
		for _, chain := range [][]ScopedSource{sources, shuffled} {
			config, err := ComposeSources(chain)
			if err == nil && request != nil {
				config, err = ApplyRequest(config, request)
			}
			if err != nil {
				t.Fatalf("trial %d: compose: %v", trial, err)
			}
			configs = append(configs, config)
		}
		for _, provider := range []string{"openai", "anthropic"} {
			for _, iface := range []string{"chat_completions", "responses"} {
				values := ruleValues{"provider.id": {Type: "string", String: provider}, "request.interface": {Type: "string", String: iface}}
				for order, config := range configs {
					active, err := config.Activate(values)
					if err != nil {
						t.Fatalf("trial %d: activate: %v", trial, err)
					}
					for unit := range scalarUnits {
						want, set := referenceScalar(parts, unit, provider, iface)
						if !set {
							want = builtIn[scalarUnits[unit].field]
						}
						if got, _ := activeScalar(t, active, unit); got != want {
							t.Fatalf("trial %d, order %d, %s/%s: %s = %d, want %d", trial, order, provider, iface, scalarUnits[unit].field, got, want)
						}
					}
				}
			}
		}
	}
}

// Every policy setting states whom it covers and how two values combine. A new
// section fails here until it joins this table, and the table must agree with
// what composition enforces.
func TestEverySettingDeclaresItsScopeAndCombination(t *testing.T) {
	type declared struct {
		// "candidate" settings may follow a rule that reads the candidate;
		// "request" settings cover every candidate; "saved" ones only saved
		// policies may set.
		scope   string
		combine string
	}
	settings := map[string]declared{
		"access":                      {"candidate", "union of deny periods"},
		"input":                       {"candidate", "any true requires ASCII"},
		"limits":                      {"saved", "every limit applies"},
		"plugins.redaction":           {"candidate", "union of presets and expressions"},
		"plugins.encrypted":           {"candidate", "every section applies"},
		"plugins.textExtraction":      {"candidate", "any true extracts"},
		"plugins.export":              {"candidate", "union of destinations"},
		"routing.filter":              {"candidate", "every filter must match"},
		"routing.allowedCatalogNodes": {"candidate", "intersection"},
		"routing.retries":             {"candidate", "minimum"},
		"timeouts.outputIdleSeconds":  {"candidate", "minimum"},
		"routing.order":               {"request", "one ordering: broadest required, else closest default"},
		"routing.sort":                {"request", "one ordering: broadest required, else closest default"},
		"routing.fallbacks":           {"request", "minimum"},
		"timeouts.totalSeconds":       {"request", "minimum"},
		"delegation":                  {"saved", "permissions intersect"},
		"encryption":                  {"saved", "organization only"},
	}
	var covered, requestWide, savedOnly Permission
	for section, setting := range settings {
		bit, ok := permissionSections[section]
		if !ok || bit == 0 || bit&(bit-1) != 0 {
			t.Fatalf("%s is not one policy setting", section)
		}
		if covered&bit != 0 {
			t.Fatalf("%s is declared twice", section)
		}
		covered |= bit
		switch setting.scope {
		case "request":
			requestWide |= bit
		case "saved":
			savedOnly |= bit
		case "candidate":
		default:
			t.Fatalf("%s has no scope", section)
		}
		if setting.combine == "" {
			t.Fatalf("%s has no combination", section)
		}
	}
	if covered != allPermissions {
		t.Fatalf("settings without a declaration: %b", allPermissions&^covered)
	}
	if requestWide != requestWidePermissions {
		t.Fatalf("request-wide settings %b differ from what composition enforces, %b", requestWide, requestWidePermissions)
	}
	if savedOnly != allPermissions&^requestPermissions {
		t.Fatalf("saved-only settings %b differ from what requests may not set, %b", savedOnly, allPermissions&^requestPermissions)
	}
}
