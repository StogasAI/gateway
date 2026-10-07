package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
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
				entries = append(entries, InspectionSource{Scope: scope, ID: "resource", Config: json.RawMessage(`{"limits":{"lifetimeTokens":50}}`)})
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
				if len(limits) != 1 || limits[0]["scope"] != scope || limits[0]["id"] != "resource" {
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
	encoded, _ := json.Marshal(map[string]any{"plugins": map[string]any{"encrypted": envelope}})
	entries := []InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(`{"encryption":{"keys":{"default":"` + envelope.KeyID + `"}},"plugins":{"stogasRedaction":{"email_address":true}}}`)},
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
	if len(opaque) != 2 || opaque[0]["id"] != "first" || opaque[1]["id"] != "second" {
		t.Fatalf("opaque identities changed: %v", opaque)
	}
	for _, item := range opaque {
		if !reflect.DeepEqual(item["encrypted"], &envelope) {
			t.Fatal("inspection changed an encrypted envelope")
		}
	}
	if !reflect.DeepEqual(result.Compiled.Plugins.StogasRedaction.Presets, []string{"email_address"}) {
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
				plugins := map[string]any{"encrypted": envelope}
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
				sources = append(sources, ScopedSource{scope, source})
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
	raw, err := os.ReadFile("../customerkey/testdata/webcrypto.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Root, OrganizationID string
		Envelope             customerkey.Envelope
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := customerkey.Parse(fixture.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Clear()
	raw, _ = json.Marshal(map[string]any{"plugins": map[string]any{"encrypted": fixture.Envelope}})
	document, err := ParseSourceDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := document.Open(fixture.OrganizationID, customerkey.Keys{"test": key})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened.size, document.size) || opened.Config.Plugins == nil {
		t.Fatal("opening changed the saved budget or lost the decrypted plugin")
	}
}

func TestInspectionUsesExecutionPatternValidationAndTypedEditErrors(t *testing.T) {
	for _, expression := range []string{`^`, `(?=foo)`, `(a)\1`} {
		raw, _ := json.Marshal(map[string]any{"plugins": map[string]any{"stogasRedaction": map[string]any{"customPattern": expression}}})
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
		{Scope: OrganizationScope, Config: json.RawMessage(`{"plugins":{"stogasRedaction":{"literals":[{"values":["alice"]}]}},"routing":{"filter": "provider.id != \"first\""}}`)},
		{Scope: KeyScope, Config: json.RawMessage(`{"plugins":{"stogasRedaction":{"literals":[{"values":["alice"]}]}},"routing":{"filter": "provider.id != \"second\""}}`)},
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
	if len(result.Compiled.Routing.Query.Filters) != 2 || len(result.Compiled.Plugins.StogasRedaction.Literals) != 1 {
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
	if _, err := ComposeSources([]ScopedSource{{OrganizationScope, source}, {RoleScope, source}, {KeyScope, source}}); err == nil {
		t.Fatal("runtime accepted the same oversized rule combination")
	}
}

func BenchmarkInspectionSharedPolicies(b *testing.B) {
	values := make([]string, 1000)
	for i := range values {
		values[i] = strings.Repeat("x", 40) + string(rune('一'+i))
	}
	raw, _ := json.Marshal(map[string]any{"plugins": map[string]any{"stogasRedaction": map[string]any{"literals": []any{map[string]any{"values": values}}}}})
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
			"plugins": map[string]any{"stogasRedaction": map[string]any{"literals": []any{map[string]any{"values": values}}}}})
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
		doc := map[string]any{"rules": map[string]any{"selected": map[string]any{"when": `provider.id == "openai"`, "plugins": map[string]any{"encrypted": envelope}}}}
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
