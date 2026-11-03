package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
)

func sameJSON(left, right any) bool {
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	l, leftErr := jsoncanonicalizer.Transform(l)
	r, rightErr := jsoncanonicalizer.Transform(r)
	return leftErr == nil && rightErr == nil && bytes.Equal(l, r)
}

func TestInspectionMatchesExecutionCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/source-policies.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []struct {
		Name     string
		Sources  [3]json.RawMessage
		Digest   string
		Compiled json.RawMessage
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, row := range corpus {
		t.Run(row.Name, func(t *testing.T) {
			var entries []InspectionSource
			for i, source := range row.Sources {
				if string(source) != "null" {
					entries = append(entries, InspectionSource{Scope: []Scope{OrganizationScope, GrantScope, KeyScope}[i], Config: source})
				}
			}
			result, err := InspectSources(entries, nil)
			if err != nil {
				t.Fatal(err)
			}
			var want any
			err = json.Unmarshal(row.Compiled, &want)
			if err != nil {
				t.Fatal(err)
			}
			if !sameJSON(result.Compiled, want) || result.Digest != row.Digest {
				t.Fatalf("inspection differs from the execution fixture: %#v", result)
			}
		})
	}
}

func TestInspectionAtSavedResourceScopes(t *testing.T) {
	root := InspectionSource{Scope: OrganizationScope, ID: "org", Config: json.RawMessage(`{"input":{"asciiOnly":true}}`)}
	for _, scope := range []Scope{OrganizationScope, FolderScope, GrantScope, RoleScope, MemberScope, CredentialScope} {
		t.Run(string(scope), func(t *testing.T) {
			entries := []InspectionSource{root}
			if scope != OrganizationScope {
				entries = append(entries, InspectionSource{Scope: scope, ID: "resource", Config: json.RawMessage(`{"limits":{"total":{"tokens":50}}}`)})
			}
			result, err := InspectSources(entries, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.Compiled.Input == nil || !result.Compiled.Input.ASCIIOnly {
				t.Fatal("lost the organization requirement")
			}
			if scope != OrganizationScope {
				limits := result.Effective["limits"].([]map[string]any)
				if len(limits) != 1 || !reflect.DeepEqual(limits[0]["policy"], map[string]any{"scope": scope, "id": "resource"}) {
					t.Fatalf("lost counter identity: %v", limits)
				}
			}
		})
	}
	for _, entries := range [][]InspectionSource{nil, {{Scope: MemberScope, Config: root.Config}}} {
		if _, err := InspectSources(entries, nil); err == nil {
			t.Fatal("accepted sources without an organization")
		}
	}
}

func TestInspectionPreservesOpaqueSourcesWithoutChargingTheirEncodingToCompiledSize(t *testing.T) {
	envelope := customerkey.Envelope{
		Version: 1, KeyID: strings.Repeat("a", 64),
		Salt:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		Blob:  base64.RawURLEncoding.EncodeToString(make([]byte, MaxSourceBytes-1024)),
	}
	encoded, _ := json.Marshal(map[string]any{"plugins": map[string]any{"redaction": map[string]any{"encrypted": envelope}}})
	entries := []InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(`{"encryption":{"keys":{"default":"` + envelope.KeyID + `"}},"plugins":{"redaction":{"email_address":true}}}`)},
		{Scope: RoleScope, ID: "first", Config: encoded},
		{Scope: RoleScope, ID: "second", Config: encoded},
		{Scope: KeyScope, Config: json.RawMessage(`{}`)},
	}
	before, _ := json.Marshal(entries)
	result, err := InspectSources(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	opaque := result.Effective["uncheckedPlugins"].([]map[string]any)
	if len(opaque) != 2 || opaque[0]["policy"].(map[string]any)["id"] != "first" || opaque[1]["policy"].(map[string]any)["id"] != "second" {
		t.Fatalf("opaque identities changed: %v", opaque)
	}
	for _, item := range opaque {
		if item["plugin"] != "redaction" || !reflect.DeepEqual(item["encrypted"], envelope) {
			t.Fatal("inspection changed an encrypted envelope or lost its plugin")
		}
	}
	if !reflect.DeepEqual(result.Compiled.Plugins.Redaction.Presets, []string{"email_address"}) {
		t.Fatal("opaque plugins displaced readable requirements")
	}
	after, _ := json.Marshal(entries)
	if string(before) != string(after) {
		t.Fatal("inspection mutated stored input")
	}
	preview, _ := json.Marshal(result.Effective)
	if len(preview) <= MaxCompiledBytes {
		t.Fatal("fixture does not exercise the separate opaque-byte allowance")
	}
}

func TestEncryptedSectionsShareTheCombinedByteBudget(t *testing.T) {
	for _, conditional := range []bool{false, true} {
		t.Run(fmt.Sprintf("conditional=%v", conditional), func(t *testing.T) {
			inspector := NewInspector(nil, true)
			var sources []ScopedSource
			for index := 0; index < 3; index++ {
				envelope := customerkey.Envelope{Version: 1, KeyID: strings.Repeat("a", 64),
					Salt: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
					Blob: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index)}, 250_000))}
				plugins := map[string]any{"export": map[string]any{"encrypted": envelope}}
				doc := map[string]any{}
				if conditional {
					doc["rules"] = map[string]any{"selected": map[string]any{"plugins": plugins}}
				} else {
					doc["plugins"] = plugins
				}
				scope := RoleScope
				if index == 0 {
					scope = OrganizationScope
					doc["encryption"] = map[string]any{"keys": map[string]string{"test": envelope.KeyID}}
				}
				raw, _ := json.Marshal(doc)
				document, err := ParseSourceDocument(raw)
				if err != nil {
					t.Fatal(err)
				}
				source, err := document.compile(nil, &celCompiler{prepare: true})
				if err != nil {
					t.Fatal(err)
				}
				sources = append(sources, ScopedSource{Scope: scope, Value: source})
				err = inspector.Add(InspectionSource{Scope: scope, Config: raw})
				if index < 2 && err != nil || index == 2 && (err == nil || !strings.Contains(err.Error(), "size limit")) {
					t.Fatalf("source %d: wrong size result: %v", index, err)
				}
				_, err = ComposeSources(sources)
				if index < 2 && err != nil || index == 2 && (err == nil || !strings.Contains(err.Error(), "size limit")) {
					t.Fatalf("runtime source %d: wrong size result: %v", index, err)
				}
			}
			if len(inspector.entries) != 2 {
				t.Fatal("oversized ciphertext collection was retained")
			}
		})
	}
}

func TestOpenedSourceKeepsTheSavedCiphertextBudget(t *testing.T) {
	fixture, key := loadWebcryptoFixture(t)
	raw, _ := json.Marshal(map[string]any{"plugins": map[string]any{"textExtraction": true, "redaction": map[string]any{"encrypted": fixture.Envelope}}})
	document, err := ParseSourceDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := document.Open(fixture.OrganizationID, customerkey.Keys{"test": key})
	if err != nil {
		t.Fatal(err)
	}
	plugins := opened.Config.Plugins
	if !reflect.DeepEqual(opened.size, document.size) || plugins == nil || plugins.Redaction == nil || plugins.TextExtraction == nil || !*plugins.TextExtraction {
		t.Fatal("opening changed the saved budget or lost a readable or decrypted plugin")
	}
}

func TestInspectionUsesExecutionPatternValidationAndTypedEditErrors(t *testing.T) {
	for _, expression := range []string{`^`, `(?=foo)`, `(a)\1`} {
		raw, _ := json.Marshal(map[string]any{"plugins": map[string]any{"redaction": map[string]any{"customPattern": expression}}})
		if _, err := InspectSource(raw); err == nil {
			t.Errorf("accepted an unsafe or unsupported expression %q", expression)
		}
	}
	entries := []InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(`{"delegation":{"keys":false}}`)},
		{Scope: KeyScope, ID: "key", Config: json.RawMessage(`{"input":{"asciiOnly":true}}`)},
	}
	_, err := InspectSources(entries, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: json.RawMessage(`{}`)})
	if !errors.Is(err, ErrPolicyEditForbidden) {
		t.Fatalf("blocked child edit must keep its typed error: %v", err)
	}
	previous := entries[1].Config
	entries[1].Config = json.RawMessage(`{}`)
	if _, err := InspectSources(entries, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: previous}); err != nil {
		t.Fatalf("a parent denial must still allow clearing a policy: %v", err)
	}
}

func TestInspectionSharesEqualPluginSectionsAcrossDifferentSources(t *testing.T) {
	inspector := NewInspector(nil, false)
	for _, entry := range []InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(`{"plugins":{"redaction":{"literals":[{"values":["alice"]}]}},"routing":{"filter": "provider.id != \"first\""}}`)},
		{Scope: KeyScope, Config: json.RawMessage(`{"plugins":{"redaction":{"literals":[{"values":["alice"]}]}},"routing":{"filter": "provider.id != \"second\""}}`)},
	} {
		if err := inspector.Add(entry); err != nil {
			t.Fatal(err)
		}
	}
	if inspector.sources[0].Value.Config.Plugins != inspector.sources[1].Value.Config.Plugins {
		t.Fatal("equal plugins must be compiled once within one inspection")
	}
	if inspector.sources[0].Value.Digest == inspector.sources[1].Value.Digest {
		t.Fatal("sharing a plugin changed source identity")
	}
	result, err := inspector.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Compiled.Routing.Query.Filters) != 2 || len(result.Compiled.Plugins.Redaction.Literals) != 1 {
		t.Fatal("sharing plugins lost a filter or repeated a literal")
	}
}

func TestInspectionRejectsRuleOverflowBeforeRetainingAnotherSource(t *testing.T) {
	rules := make(map[string]any)
	for i := range 30 {
		rules[fmt.Sprintf("rule_%d", i)] = map[string]any{"when": "model.id != '" + strings.Repeat("a", 7<<10) + "'", "input": map[string]bool{"asciiOnly": true}}
	}
	raw, _ := json.Marshal(map[string]any{"rules": rules})
	source, err := CompileSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	inspector := NewInspector(nil, true)
	for _, scope := range []Scope{OrganizationScope, RoleScope} {
		if err := inspector.Add(InspectionSource{Scope: scope, Config: raw}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := inspector.Finish(); err != nil {
		t.Fatalf("bounded combination was rejected: %v", err)
	}
	if err := inspector.Add(InspectionSource{Scope: KeyScope, Config: raw}); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized preview was retained: %v", err)
	}
	if len(inspector.sources) != 2 {
		t.Fatal("overflow retained another source")
	}
	if _, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: source}, {Scope: RoleScope, Value: source}, {Scope: KeyScope, Value: source}}); err == nil {
		t.Fatal("runtime accepted the same oversized rule combination")
	}
}

func BenchmarkInspectionSharedPolicies(b *testing.B) {
	values := make([]string, 1000)
	for i := range values {
		values[i] = strings.Repeat("x", 40) + string(rune('一'+i))
	}
	raw, _ := json.Marshal(map[string]any{"plugins": map[string]any{"redaction": map[string]any{"literals": []any{map[string]any{"values": values}}}}})
	entries := make([]InspectionSource, 36)
	for i := range entries {
		entries[i] = InspectionSource{Scope: RoleScope, Config: raw}
	}
	entries[0].Scope, entries[len(entries)-1].Scope = OrganizationScope, KeyScope
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := InspectSources(entries, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func TestInspectionBudgetsDistinctSettingsBeforeCompilation(t *testing.T) {
	inspector := NewInspector(nil, false)
	var sources []ScopedSource
	for index, scope := range []Scope{OrganizationScope, RoleScope, KeyScope} {
		ids := make([]string, 14_500)
		for j := range ids {
			ids[j] = fmt.Sprintf("model-%d-%05d", index, j)
		}
		raw, _ := json.Marshal(map[string]any{"routing": map[string]any{"allowedCatalogNodes": map[string]any{"models": ids}}})
		source, err := CompileSource(raw)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, ScopedSource{Scope: scope, Value: source})
		err = inspector.Add(InspectionSource{Scope: scope, Config: raw})
		if index < 2 && err != nil || index == 2 && (err == nil || !strings.Contains(err.Error(), "size limit")) {
			t.Fatalf("source %d: wrong size result: %v", index, err)
		}
	}
	if len(inspector.sources) != 2 {
		t.Fatal("oversized source collection was retained")
	}
	if _, err := inspector.Finish(); err != nil {
		t.Fatalf("bounded prefix cannot be composed: %v", err)
	}
	if _, err := ComposeSources(sources); err == nil {
		t.Fatal("runtime accepted the same oversized source collection")
	}
}

func TestInspectionSharesDictionaryBudgetAcrossDistinctSources(t *testing.T) {
	values := make([]string, 1000)
	for i := range values {
		values[i] = fmt.Sprintf("customer-%04d-%s", i, strings.Repeat("x", 40))
	}
	inspector := NewInspector(nil, false)
	for i := range 36 {
		scope := RoleScope
		if i == 0 {
			scope = OrganizationScope
		} else if i == 35 {
			scope = KeyScope
		}
		raw, _ := json.Marshal(map[string]any{"routing": map[string]any{"filter": fmt.Sprintf(`model.id != "blocked-%d"`, i)},
			"plugins": map[string]any{"redaction": map[string]any{"literals": []any{map[string]any{"values": values}}}}})
		if err := inspector.Add(InspectionSource{Scope: scope, Config: raw}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := inspector.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Compiled.PluginSources) != 1 || len(result.Compiled.Routing.Query.Filters) != 36 {
		t.Fatal("dictionary sharing removed an independent filter")
	}
}

func BenchmarkInspectionOpaqueRules(b *testing.B) {
	keyID := strings.Repeat("a", 64)
	entries := make([]InspectionSource, 36)
	for i := range entries {
		envelope := customerkey.Envelope{Version: 1, KeyID: keyID,
			Salt: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
			Blob: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(i)}, 14_000))}
		doc := map[string]any{"rules": map[string]any{"selected": map[string]any{"when": `provider.id == "openai"`, "plugins": map[string]any{"redaction": map[string]any{"encrypted": envelope}}}}}
		entries[i].Scope = RoleScope
		if i == 0 {
			entries[i].Scope = OrganizationScope
			doc["encryption"] = map[string]any{"keys": map[string]string{"test": keyID}}
		}
		entries[i].Config, _ = json.Marshal(doc)
	}
	entries[len(entries)-1].Scope = KeyScope
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		inspector := NewInspector(nil, true)
		for _, entry := range entries {
			if err := inspector.Add(entry); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := inspector.Finish(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestInspectionShowsWhichPolicySetsEachSortCriterion(t *testing.T) {
	required := func(by string) string { return `{"routing":{"sort":[{"by":"` + by + `"}]}}` }
	preferred := func(by string) string {
		return `{"rules":{"d":{"mode":"default","routing":{"sort":[{"by":"` + by + `"}]}}}}`
	}
	run := func(policy map[string]any, rule string, criteria int) map[string]any {
		value := map[string]any{"policy": policy, "criteria": criteria}
		if rule != "" {
			value["rule"] = rule
		}
		return value
	}
	org := run(map[string]any{"scope": OrganizationScope}, "", 1)
	key := run(map[string]any{"scope": KeyScope, "id": "key"}, "", 1)
	orgRule := run(map[string]any{"scope": OrganizationScope}, "d", 1)
	keyRule := run(map[string]any{"scope": KeyScope, "id": "key"}, "d", 1)
	for _, test := range []struct {
		org, key string
		sorts    []string
		from     []map[string]any
	}{
		// Requirements run broadest first, then defaults closest first.
		{required("provider.id"), required("model.id"), []string{"provider.id", "model.id"}, []map[string]any{org, key}},
		{required("provider.id"), preferred("model.id"), []string{"provider.id", "model.id"}, []map[string]any{org, keyRule}},
		{preferred("provider.id"), preferred("model.id"), []string{"model.id", "provider.id"}, []map[string]any{keyRule, orgRule}},
		{preferred("provider.id"), required("model.id"), []string{"model.id", "provider.id"}, []map[string]any{key, orgRule}},
		{preferred("provider.id"), `{}`, []string{"provider.id"}, []map[string]any{orgRule}},
		// A criterion equal to an earlier one cannot break its ties.
		{required("provider.id"), preferred("provider.id"), []string{"provider.id"}, []map[string]any{org}},
		// One run names the policy of consecutive criteria.
		{
			`{"routing":{"sort":[{"by":"provider.id"},{"by":"model.id"}]}}`, preferred("route.id"),
			[]string{"provider.id", "model.id", "route.id"},
			[]map[string]any{run(map[string]any{"scope": OrganizationScope}, "", 2), keyRule},
		},
		{`{}`, `{"routing":{"sort":[]}}`, nil, nil},
	} {
		inspection, err := InspectSources([]InspectionSource{
			{Scope: OrganizationScope, Config: json.RawMessage(test.org)},
			{Scope: KeyScope, ID: "key", Config: json.RawMessage(test.key)},
		}, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: json.RawMessage(test.key)})
		if err != nil {
			t.Fatal(err)
		}
		routing, _ := inspection.Effective["routing"].(map[string]any)
		sorts, _ := routing["sort"].([]Sort)
		var got []string
		for _, criterion := range sorts {
			got = append(got, criterion.By)
		}
		from, _ := routing["sortFrom"].([]map[string]any)
		if !slices.Equal(got, test.sorts) || !reflect.DeepEqual(from, test.from) || len(inspection.Notes) > 0 {
			t.Fatalf("%s + %s: sort %v from %v, notes %+v", test.org, test.key, got, from, inspection.Notes)
		}
	}
}

func TestInspectionShowsWhichRequirementsReplaceDefaults(t *testing.T) {
	org := `{"plugins":{"textExtraction":false},"timeouts":{"totalSeconds":900},"rules":{"openai":{"when":"provider.id == 'openai'","timeouts":{"outputIdleSeconds":60}}}}`
	key := `{"routing":{"retries":1},"rules":{"prefs":{"mode":"default","plugins":{"redaction":{"credit_card_number":true},"textExtraction":true},"timeouts":{"totalSeconds":60,"outputIdleSeconds":30},"routing":{"retries":2,"sort":[{"by":"provider.id"}]}}}}`
	inspection, err := InspectSources([]InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(org)},
		{Scope: KeyScope, ID: "key", Config: json.RawMessage(key)},
	}, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: json.RawMessage(key)})
	if err != nil {
		t.Fatal(err)
	}
	organization := map[string]any{"scope": OrganizationScope}
	own := map[string]any{"scope": KeyScope, "id": "key"}
	// A required plugin replaces the same plugin's default and no other: the
	// key's default redaction still applies. A condition limits the
	// replacement to the requests it matches, and the key's own requirement
	// replaces its own default. Nothing requires an ordering, so the default
	// sort applies.
	want := []map[string]any{
		{"setting": "plugins.textExtraction", "policy": organization},
		{"setting": "routing.retries", "policy": own},
		{"setting": "timeouts.outputIdleSeconds", "policy": organization, "rule": "openai", "conditional": true},
		{"setting": "timeouts.totalSeconds", "policy": organization},
	}
	rules, _ := inspection.Effective["rules"].([]map[string]any)
	if len(rules) != 2 || rules[0]["replaced"] != nil || !reflect.DeepEqual(rules[1]["replaced"], want) {
		t.Fatalf("replaced defaults: %+v", rules)
	}
	// The key hears about the organization's requirements, not its own.
	notes := []InspectionNote{
		{Kind: "replaced", Scope: OrganizationScope, Sections: []string{"plugins.textExtraction", "timeouts.totalSeconds"}},
		{Kind: "replaced", Scope: OrganizationScope, Sections: []string{"timeouts.outputIdleSeconds"}, Rules: []string{"openai"}},
	}
	if !reflect.DeepEqual(inspection.Notes, notes) {
		t.Fatalf("notes: %+v", inspection.Notes)
	}

	// A setting that one policy requires on every request is not repeated for
	// a rule that requires it on some.
	org = `{"timeouts":{"outputIdleSeconds":120},"rules":{"openai":{"when":"provider.id == 'openai'","timeouts":{"outputIdleSeconds":60}}}}`
	inspection, err = InspectSources([]InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(org)},
		{Scope: KeyScope, ID: "key", Config: json.RawMessage(key)},
	}, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: json.RawMessage(key)})
	if err != nil {
		t.Fatal(err)
	}
	notes = []InspectionNote{{Kind: "replaced", Scope: OrganizationScope, Sections: []string{"timeouts.outputIdleSeconds"}}}
	if !reflect.DeepEqual(inspection.Notes, notes) {
		t.Fatalf("notes: %+v", inspection.Notes)
	}

	// Every ordering applies, so no requirement replaces a default one.
	preferred := `{"rules":{"d":{"mode":"default","routing":{"order":["openai"],"sort":[{"by":"provider.id"}]}}}}`
	for _, test := range []struct {
		org      string
		replaced [2]any
	}{
		{`{"routing":{"sort":[{"by":"model.id"}]}}`, [2]any{nil, nil}},
		{preferred, [2]any{nil, nil}},
	} {
		inspection, err = InspectSources([]InspectionSource{
			{Scope: OrganizationScope, Config: json.RawMessage(test.org)},
			{Scope: KeyScope, ID: "key", Config: json.RawMessage(preferred)},
		}, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: json.RawMessage(preferred)})
		if err != nil {
			t.Fatal(err)
		}
		rules, _ = inspection.Effective["rules"].([]map[string]any)
		key := rules[len(rules)-1]
		var org any
		if len(rules) == 2 {
			org = rules[0]["replaced"]
		}
		if (org == nil) != (test.replaced[0] == nil) || org != nil && !reflect.DeepEqual(org, test.replaced[0]) ||
			(key["replaced"] == nil) != (test.replaced[1] == nil) || key["replaced"] != nil && !reflect.DeepEqual(key["replaced"], test.replaced[1]) {
			t.Fatalf("%s: replaced %+v", test.org, rules)
		}
		for _, note := range inspection.Notes {
			if note.Kind == "replaced" {
				t.Fatalf("%s: ordering note %+v", test.org, note)
			}
		}
	}
}

func TestInspectionBoundsReplacedDefaults(t *testing.T) {
	// Each replaced setting names one requirement and counts the others, so
	// many rules cannot multiply the preview.
	var org, key strings.Builder
	org.WriteString(`{"rules":{`)
	key.WriteString(`{"timeouts":{"totalSeconds":600},"rules":{`)
	for i := range 300 {
		if i > 0 {
			org.WriteString(",")
			key.WriteString(",")
		}
		fmt.Fprintf(&org, `"r%03d":{"when":"model.id == 'm%d'","timeouts":{"outputIdleSeconds":60}}`, i, i)
		fmt.Fprintf(&key, `"d%03d":{"mode":"default","timeouts":{"outputIdleSeconds":30,"totalSeconds":900}}`, i)
	}
	org.WriteString(`},"plugins":{"textExtraction":false}}`)
	key.WriteString(`}}`)
	folder := `{"rules":{"strict":{"plugins":{"textExtraction":false}}}}`
	inspection, err := InspectSources([]InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(org.String())},
		{Scope: FolderScope, ID: "folder", Config: json.RawMessage(folder)},
		{Scope: KeyScope, ID: "key", Config: json.RawMessage(key.String())},
	}, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: json.RawMessage(key.String())})
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := inspection.Effective["rules"].([]map[string]any)
	if len(rules) != 601 {
		t.Fatalf("rules: %d", len(rules))
	}
	want := []map[string]any{
		{"setting": "timeouts.outputIdleSeconds", "policy": map[string]any{"scope": OrganizationScope}, "rule": "r000", "conditional": true, "others": 299},
		{"setting": "timeouts.totalSeconds", "policy": map[string]any{"scope": KeyScope, "id": "key"}},
	}
	for _, rule := range rules {
		if rule["policy"].(map[string]any)["scope"] == KeyScope && !reflect.DeepEqual(rule["replaced"], want) {
			t.Fatalf("%s: %+v", rule["name"], rule["replaced"])
		}
	}
	// The key's own requirement replaces its default total wait, so only the
	// organization's rules are named, at most ten of them.
	note := inspection.Notes
	if len(note) != 1 || note[0].RuleCount != 300 || len(note[0].Rules) != maxNoteRules || note[0].Rules[0] != "r000" ||
		!reflect.DeepEqual(note[0].Sections, []string{"timeouts.outputIdleSeconds"}) {
		t.Fatalf("notes: %+v", note)
	}

	// A required rule without a condition replaces a default on every
	// request, and the first requirement is named with how many others agree.
	key = strings.Builder{}
	key.WriteString(`{"rules":{"d":{"mode":"default","plugins":{"textExtraction":true}}}}`)
	inspection, err = InspectSources([]InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(`{"plugins":{"textExtraction":false}}`)},
		{Scope: FolderScope, ID: "folder", Config: json.RawMessage(folder)},
		{Scope: KeyScope, ID: "key", Config: json.RawMessage(key.String())},
	}, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: json.RawMessage(key.String())})
	if err != nil {
		t.Fatal(err)
	}
	rules, _ = inspection.Effective["rules"].([]map[string]any)
	want = []map[string]any{{"setting": "plugins.textExtraction", "policy": map[string]any{"scope": OrganizationScope}, "others": 1}}
	if !reflect.DeepEqual(rules[len(rules)-1]["replaced"], want) {
		t.Fatalf("replaced: %+v", rules[len(rules)-1]["replaced"])
	}
	notes := []InspectionNote{
		{Kind: "replaced", Scope: OrganizationScope, Sections: []string{"plugins.textExtraction"}},
		{Kind: "replaced", Scope: FolderScope, ID: "folder", Sections: []string{"plugins.textExtraction"}},
	}
	if !reflect.DeepEqual(inspection.Notes, notes) {
		t.Fatalf("notes: %+v", inspection.Notes)
	}
}

func TestInspectionNamesWhoSetsEachSetting(t *testing.T) {
	org := `{"routing":{"retries":1,"filter":"provider.id != 'x'","fallbacks":2},"timeouts":{"totalSeconds":900},"input":{"asciiOnly":true}}`
	key := `{"routing":{"retries":2,"filter":"model.id != 'y'","fallbacks":1},"timeouts":{"totalSeconds":60,"outputIdleSeconds":30}}`
	inspection, err := InspectSources([]InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(org)},
		{Scope: KeyScope, ID: "key", Config: json.RawMessage(key)},
	}, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: json.RawMessage(key)})
	if err != nil {
		t.Fatal(err)
	}
	organization := map[string]any{"scope": OrganizationScope}
	own := map[string]any{"scope": KeyScope, "id": "key"}
	// The smallest value names the policy that sets it, and filters combine
	// from both.
	want := []map[string]any{
		{"setting": "input", "policy": organization},
		{"setting": "routing.fallbacks", "policy": own},
		{"setting": "routing.filter", "policy": organization},
		{"setting": "routing.filter", "policy": own},
		{"setting": "routing.retries", "policy": organization},
		{"setting": "timeouts.outputIdleSeconds", "policy": own},
		{"setting": "timeouts.totalSeconds", "policy": own},
	}
	if !reflect.DeepEqual(inspection.Effective["setBy"], want) {
		t.Fatalf("setBy: %+v", inspection.Effective["setBy"])
	}
}

// The combined view's replaced defaults agree with request activation: a
// setting marked replaced on every request is replaced whatever the request,
// one marked conditional only when its rule matches, and an unmarked one
// never. One ordering applies, and every other default ordering is marked.
func TestReplacedDefaultsAgreeWithActivation(t *testing.T) {
	type setting struct{ section, field, value string }
	pool := []setting{
		{"input", "asciiOnly", "true"},
		{"timeouts", "totalSeconds", "600"},
		{"timeouts", "outputIdleSeconds", "60"},
		{"routing", "retries", "1"},
		{"routing", "filter", `"provider.id != 'x'"`},
		{"routing", "allowedCatalogNodes", `{"providers":["openai"]}`},
		{"plugins", "textExtraction", "false"},
		{"plugins", "redaction", `{"email_address":true}`},
	}
	const when = "request.interface == 'chat_completions'"
	scopes := []Scope{OrganizationScope, FolderScope, GrantScope, KeyScope}
	rng := rand.New(rand.NewPCG(7, 11))
	// How often each case was checked, so the generator keeps reaching them.
	seen := map[string]int{}
	settings := func(count int) map[string]map[string]json.RawMessage {
		out := map[string]map[string]json.RawMessage{}
		for range count {
			s := pool[rng.IntN(len(pool))]
			if out[s.section] == nil {
				out[s.section] = map[string]json.RawMessage{}
			}
			out[s.section][s.field] = json.RawMessage(s.value)
		}
		return out
	}
	object := func(parts map[string]map[string]json.RawMessage) map[string]any {
		out := map[string]any{}
		for section, fields := range parts {
			if section == "input" {
				out[section] = map[string]any{"asciiOnly": true}
				continue
			}
			out[section] = fields
		}
		return out
	}
	for trial := range 400 {
		var entries []InspectionSource
		var sources []ScopedSource
		for _, scope := range scopes {
			config := object(settings(rng.IntN(3)))
			ordered := false
			if rng.IntN(4) == 0 {
				routing, _ := config["routing"].(map[string]json.RawMessage)
				if routing == nil {
					routing = map[string]json.RawMessage{}
				}
				routing["sort"] = json.RawMessage(`[{"by":"provider.id"}]`)
				config["routing"], ordered = routing, true
			}
			rules := map[string]any{}
			for index := range rng.IntN(4) {
				rule := object(settings(1 + rng.IntN(2)))
				switch rng.IntN(3) {
				case 0:
					rule["mode"] = "default"
					if !ordered && rng.IntN(3) == 0 {
						routing, _ := rule["routing"].(map[string]json.RawMessage)
						if routing == nil {
							routing = map[string]json.RawMessage{}
						}
						routing["sort"] = json.RawMessage(`[{"by":"model.id"}]`)
						rule["routing"], ordered = routing, true
					} else if rng.IntN(2) == 0 {
						rule["when"] = when
					}
				case 1:
					rule["when"] = when
				}
				rules[fmt.Sprintf("r%d", index)] = rule
			}
			if len(rules) > 0 {
				config["rules"] = rules
			}
			raw, _ := json.Marshal(config)
			source, err := CompileSource(raw)
			if err != nil {
				t.Fatalf("trial %d %s: %v: %s", trial, scope, err, raw)
			}
			id := ""
			if scope != OrganizationScope {
				id = string(scope)
			}
			entries = append(entries, InspectionSource{Scope: scope, ID: id, Config: raw})
			sources = append(sources, ScopedSource{Scope: scope, Value: source})
		}
		inspection, err := InspectSources(entries, nil)
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		combined, err := ComposeSources(sources)
		if err != nil {
			t.Fatal(err)
		}
		active := map[bool]*Config{}
		for _, matched := range []bool{true, false} {
			iface := "responses"
			if matched {
				iface = "chat_completions"
			}
			active[matched], err = combined.Activate(ruleValues{"request.interface": {Type: "string", String: iface}})
			if err != nil {
				t.Fatal(err)
			}
		}
		rules, _ := inspection.Effective["rules"].([]map[string]any)
		for _, item := range rules {
			reference := item["policy"].(map[string]any)
			name := item["name"].(string)
			fields := map[string]json.RawMessage{}
			raw, _ := json.Marshal(item["config"])
			_ = json.Unmarshal(raw, &fields)
			var mode string
			_ = json.Unmarshal(fields["mode"], &mode)
			marked := map[string]map[string]any{}
			list, _ := item["replaced"].([]map[string]any)
			for _, entry := range list {
				marked[entry["setting"].(string)] = entry
			}
			if mode != "default" {
				if len(list) > 0 {
					t.Fatalf("trial %d: required rule %s marked %+v", trial, name, list)
				}
				continue
			}
			for _, setting := range ruleSettings(fields) {
				entry := marked[setting]
				kind := settingsMask(permissionSections[setting])
				for _, matched := range []bool{true, false} {
					var replaced bool
					if kind&orderingPermissions != 0 {
						// A default ordering is never replaced; it orders the
						// ties that the others leave, unless an earlier equal
						// criterion already applies.
						query := active[matched].Routing.Query
						replaced = query == nil || !slices.ContainsFunc(query.OrderBy, func(s Sort) bool { return s.By == "model.id" })
					} else {
						replaced = kind&active[matched].requiredSettings != 0
					}
					want := entry != nil && (entry["conditional"] == nil || matched)
					switch {
					case kind&orderingPermissions != 0:
						seen[fmt.Sprintf("ordering %v", want)]++
					case entry == nil:
						seen["kept"]++
					case entry["conditional"] != nil:
						seen["conditional"]++
					default:
						seen["always"]++
					}
					if replaced != want {
						t.Fatalf("trial %d: %s rule %s %s matched=%v: replaced %v, marked %+v\n%s", trial, reference["scope"], name, setting, matched, replaced, entry, entries)
					}
				}
			}
		}
	}
	for _, name := range []string{"kept", "always", "conditional", "ordering false"} {
		if seen[name] < 20 {
			t.Fatalf("checked %s %d times: %v", name, seen[name], seen)
		}
	}
	t.Logf("checked %v", seen)
}
