package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTextExtractionRequirementsAndDefaults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sources []string
		want    string
	}{
		{"omitted", []string{`{}`}, TextExtractionOff},
		{"the strongest requirement", []string{`{"plugins":{"textExtraction":"always"}}`, `{"plugins":{"textExtraction":"off"}}`}, TextExtractionAlways},
		{"auto over off", []string{`{"plugins":{"textExtraction":"off"}}`, `{"plugins":{"textExtraction":"auto"}}`}, TextExtractionAuto},
		{"always over auto", []string{`{"plugins":{"textExtraction":"auto"}}`, `{"plugins":{"textExtraction":"always"}}`}, TextExtractionAlways},
		{"default", []string{`{"rules":{"extract":{"mode":"default","plugins":{"textExtraction":"auto"}}}}`}, TextExtractionAuto},
		{"a requirement replaces the default", []string{`{"rules":{"extract":{"mode":"default","plugins":{"textExtraction":"always"}}}}`, `{"plugins":{"textExtraction":"off"}}`}, TextExtractionOff},
		{"another plugin's requirement", []string{`{"rules":{"extract":{"mode":"default","plugins":{"textExtraction":"always"}}}}`, `{"plugins":{"redaction":{}}}`}, TextExtractionAlways},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := []ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, `{}`)}}
			for _, raw := range tc.sources {
				sources = append(sources, ScopedSource{Scope: RoleScope, Value: ruleSource(t, raw)})
			}
			combined, err := ComposeSources(sources)
			if err != nil {
				t.Fatal(err)
			}
			active, err := combined.Activate(ruleValues{})
			if err != nil {
				t.Fatal(err)
			}
			if active.TextExtraction() != tc.want {
				t.Fatalf("extraction = %v, want %v", active.TextExtraction(), tc.want)
			}
			if _, err := CompileRedaction(active); err != nil {
				t.Fatal(err)
			}
			inspected, err := inspectionPlugins(active.PluginSources)
			if err != nil {
				t.Fatal(err)
			}
			if (&Config{Plugins: inspected}).TextExtraction() != tc.want {
				t.Fatal("inspection differs from execution")
			}
		})
	}
}

func TestTextExtractionTakesOnlyItsModes(t *testing.T) {
	for _, value := range []string{`true`, `false`, `"yes"`, `"Always"`, `""`, `null`} {
		if _, err := CompileSource([]byte(`{"plugins":{"textExtraction":` + value + `}}`)); err == nil {
			t.Errorf("accepted %s", value)
		}
	}
}

func TestTextExtractionRequiresItsOwnRequestPermission(t *testing.T) {
	request, err := CompileRequest([]byte(`{"plugins":{"textExtraction":"always"}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"plugins.redaction", "plugins.textExtraction", "plugins"} {
		source := ruleSource(t, `{"delegation":{"request":["`+section+`"]}}`)
		base, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: source}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = ApplyRequest(base, request)
		if section == "plugins.redaction" {
			if !errors.Is(err, ErrRequestPolicyDenied) {
				t.Fatalf("redaction permission granted extraction: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

// The strongest mode wins, so the combined policy names the first policy that sets it, not every
// policy that sets a mode.
func TestInspectionNamesThePolicyWhoseTextExtractionModeWins(t *testing.T) {
	result, err := InspectSources([]InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(`{"plugins":{"textExtraction":"auto"}}`)},
		{Scope: RoleScope, ID: "role", Config: json.RawMessage(`{"plugins":{"textExtraction":"always"}}`)},
		{Scope: KeyScope, ID: "key", Config: json.RawMessage(`{"plugins":{"textExtraction":"always"}}`)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var setBy []string
	entries, _ := result.Effective["setBy"].([]map[string]any)
	for _, entry := range entries {
		if entry["setting"] == "plugins.textExtraction" {
			setBy = append(setBy, fmt.Sprint(entry["policy"]))
		}
	}
	if len(setBy) != 1 || !strings.Contains(setBy[0], "role") {
		t.Fatalf("plugins.textExtraction set by %v", setBy)
	}
}

// Routing decides, before any plugin is opened, whether a pair's policy refuses an attachment that
// stays opaque, and the pair's preparation refuses it under the same name: the setting that reads
// all input text. An encrypted redaction counts whatever it holds, and an empty one reads nothing.
func TestInputCheckNamesTheSettingThatReadsAllInputText(t *testing.T) {
	fixture, _ := loadWebcryptoFixture(t)
	envelope, err := json.Marshal(fixture.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	keys := `"encryption":{"keys":{"test":"` + fixture.Envelope.KeyID + `"}},`
	encrypted := `"plugins":{"redaction":{"encrypted":` + string(envelope) + `}}`
	for _, tc := range []struct{ name, source, want string }{
		{"nothing", `{}`, ""},
		{"text extraction", `{"plugins":{"textExtraction":"always"}}`, ""},
		{"empty redaction", `{"plugins":{"redaction":{}}}`, ""},
		{"ASCII input", `{"input":{"asciiOnly":true}}`, "input.asciiOnly"},
		{"redaction", `{"plugins":{"redaction":{"email_address":true}}}`, "plugins.redaction"},
		{"encrypted redaction", `{` + keys + encrypted + `}`, "plugins.redaction"},
		{"encrypted redaction of a matched rule", `{` + keys + `"rules":{"private":{"when":"provider.id == 'openai'",` + encrypted + `}}}`, "plugins.redaction"},
		{"encrypted redaction of an unmatched rule", `{` + keys + `"rules":{"private":{"when":"provider.id == 'azure'",` + encrypted + `}}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The gateway compiles a source for routing without opening its ciphertext.
			document, err := ParseSourceDocument([]byte(tc.source))
			if err != nil {
				t.Fatal(err)
			}
			source, err := document.RoutingSource()
			if err != nil {
				t.Fatal(err)
			}
			combined, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: source}})
			if err != nil {
				t.Fatal(err)
			}
			active, err := combined.Activate(ruleValues{"provider.id": {Type: "string", String: "openai"}})
			if err != nil {
				t.Fatal(err)
			}
			if got := active.InputCheck(); got != tc.want {
				t.Fatalf("input check %q, want %q", got, tc.want)
			}
		})
	}
}
