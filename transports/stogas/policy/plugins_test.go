package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/inputfiles/filetype"
)

func TestTextExtractionRequirementsAndDefaults(t *testing.T) {
	const (
		docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
		xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
		off  = TextExtractionOff
		auto = TextExtractionAuto
		all  = TextExtractionAlways
	)
	// modes are the modes of a plain text file, a CSV file, a Word file and an Excel file.
	type modes [4]string
	files := [4]filetype.Type{{Family: filetype.Text, MediaType: "text/plain"}, {Family: filetype.Text, MediaType: "text/csv"}, {Family: filetype.Office, MediaType: docx}, {Family: filetype.Office, MediaType: xlsx}}
	of := func(extraction TextExtraction) (got modes) {
		for i, file := range files {
			got[i] = extraction.Mode(file)
		}
		return got
	}
	text := func(mode string) modes { return modes{mode, mode, off, off} }
	required := func(extraction string) string { return `{"plugins":{"textExtraction":` + extraction + `}}` }
	byDefault := func(extraction string) string {
		return `{"rules":{"extract":{"mode":"default","plugins":{"textExtraction":` + extraction + `}}}}`
	}
	for _, tc := range []struct {
		name    string
		sources []string
		want    modes
	}{
		// The gateway changes no file unless a policy says so.
		{"omitted", []string{`{}`}, text(off)},
		{"off where nothing is stronger", []string{`{}`, required(`{"text":"off"}`)}, text(off)},
		{"the strongest requirement", []string{required(`{"text":"always"}`), required(`{"text":"off"}`)}, text(all)},
		{"auto over off", []string{required(`{"text":"off"}`), required(`{"text":"auto"}`)}, text(auto)},
		{"always over auto", []string{required(`{"text":"auto"}`), required(`{"text":"always"}`)}, text(all)},
		{"default", []string{byDefault(`{"text":"auto"}`)}, text(auto)},
		{"a requirement replaces the default", []string{byDefault(`{"text":"always"}`), required(`{"text":"off"}`)}, text(off)},
		{"another plugin's requirement", []string{byDefault(`{"text":"always"}`), `{"plugins":{"redaction":{}}}`}, text(all)},
		// Each family combines on its own.
		{"families of two policies", []string{required(`{"text":"auto"}`), required(`{"office":"always"}`)}, modes{auto, auto, all, all}},
		{"the strongest of each family", []string{required(`{"text":"always","office":"auto"}`), required(`{"text":"auto","office":"off"}`)}, modes{all, all, auto, auto}},
		{"a requirement replaces the default of its family alone", []string{byDefault(`{"text":"auto","office":"auto"}`), required(`{"office":"off"}`)}, modes{auto, auto, off, off}},
		// A media type decides for its files in place of the family of the same policy, and never
		// weakens what another policy sets.
		{"a media type alone", []string{required(`{"text/csv":"auto","` + xlsx + `":"always"}`)}, modes{off, auto, off, all}},
		{"a media type above its family", []string{required(`{"text":"auto","text/csv":"always"}`)}, modes{auto, all, off, off}},
		{"a media type below its family", []string{required(`{"office":"always","` + xlsx + `":"off"}`)}, modes{off, off, all, off}},
		{"another policy's family over a media type", []string{required(`{"office":"always","` + xlsx + `":"off"}`), required(`{"office":"auto"}`)}, modes{off, off, all, auto}},
		{"another policy's media type over a family", []string{required(`{"text":"auto"}`), required(`{"text/csv":"always"}`)}, modes{auto, all, off, off}},
		{"off for a media type against another policy", []string{required(`{"text":"always"}`), required(`{"text/csv":"off"}`)}, text(all)},
		{"the strongest of a media type", []string{required(`{"text/csv":"auto"}`), required(`{"text/csv":"always"}`), required(`{"text/csv":"off"}`)}, modes{off, all, off, off}},
		// A media type is a setting of its family, so it replaces the family's defaults.
		{"a required media type replaces the default of its family", []string{byDefault(`{"text":"auto","office":"auto"}`), required(`{"text/csv":"always"}`)}, modes{off, all, auto, auto}},
		{"a required family replaces a default media type", []string{byDefault(`{"text/csv":"always","` + xlsx + `":"always"}`), required(`{"text":"auto"}`)}, modes{auto, auto, off, all}},
		{"a default media type beside a default family", []string{byDefault(`{"text":"auto"}`), byDefault(`{"text/csv":"always"}`)}, modes{auto, all, off, off}},
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
			if got := of(active.TextExtraction()); got != tc.want {
				t.Fatalf("extraction = %v, want %v", got, tc.want)
			}
			if _, err := CompileRedaction(active); err != nil {
				t.Fatal(err)
			}
			inspected, err := inspectionPlugins(active.PluginSources)
			if err != nil {
				t.Fatal(err)
			}
			if got := of((&Config{Plugins: inspected}).TextExtraction()); got != tc.want {
				t.Fatalf("inspection gives %v, and execution %v", got, tc.want)
			}
		})
	}
}

func TestTextExtractionTakesOnlyItsFilesAndModes(t *testing.T) {
	for _, value := range []string{
		`true`, `"auto"`, `null`, `{}`, `[]`, `{"text":"yes"}`, `{"text":"Always"}`, `{"text":""}`, `{"text":true}`, `{"text":null}`,
		`{"PDF":"auto"}`, `{"text":"auto","pdfs":"auto"}`, `{"Text":"auto"}`,
		// A media type must be one that a family holds, in full and in lowercase.
		`{"application/x-pdf":"auto"}`, `{"image/png":"auto"}`, `{"application/zip":"auto"}`, `{"application/msword":"auto"}`,
		`{"text/*":"auto"}`, `{"*/*":"auto"}`, `{"Text/CSV":"auto"}`, `{"text/csv; charset=utf-8":"auto"}`, `{"csv":"auto"}`, `{".csv":"auto"}`,
		`{"text/csv":"yes"}`, `{"text":"auto","text/csv":null}`,
	} {
		if _, err := CompileSource([]byte(`{"plugins":{"textExtraction":` + value + `}}`)); err == nil {
			t.Errorf("accepted %s", value)
		}
	}
	for _, value := range []string{
		`{"text":"auto"}`, `{"office":"off"}`, `{"pdf":"auto"}`, `{"pdf":"always","application/pdf":"off"}`, `{"text/csv":"always"}`, `{"text/x-python":"auto"}`, `{"application/json":"off"}`,
		`{"application/ld+json":"auto"}`, `{"image/svg+xml":"auto"}`, `{"application/vnd.oasis.opendocument.spreadsheet":"always"}`,
		`{"text":"auto","text/csv":"always","office":"off","application/vnd.ms-excel.sheet.macroenabled.12":"auto"}`,
	} {
		if _, err := CompileSource([]byte(`{"plugins":{"textExtraction":` + value + `}}`)); err != nil {
			t.Errorf("refused %s: %v", value, err)
		}
	}
}

func TestTextExtractionRequiresItsOwnRequestPermission(t *testing.T) {
	request, err := CompileRequest([]byte(`{"plugins":{"textExtraction":{"text":"always"}}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"plugins.redaction", "plugins.textExtraction", "plugins"} {
		source := ruleSource(t, `{"delegation":{"requests":["`+section+`"]}}`)
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
		{Scope: OrganizationScope, Config: json.RawMessage(`{"plugins":{"textExtraction":{"text":"auto"}}}`)},
		{Scope: RoleScope, ID: "role", Config: json.RawMessage(`{"plugins":{"textExtraction":{"text":"always"}}}`)},
		{Scope: KeyScope, ID: "key", Config: json.RawMessage(`{"plugins":{"textExtraction":{"text":"always"}}}`)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var setBy []string
	entries, _ := result.Effective["setBy"].([]map[string]any)
	for _, entry := range entries {
		if entry["setting"] == "plugins.textExtraction.text" {
			setBy = append(setBy, fmt.Sprint(entry["policy"]))
		}
	}
	if len(setBy) != 1 || !strings.Contains(setBy[0], "role") {
		t.Fatalf("plugins.textExtraction.text set by %v", setBy)
	}
}

// A media type takes its family's mode from a policy that sets no mode for the type, so the
// combined policy states the mode that its files get, and the family names each policy that
// gives one of its modes.
func TestInspectionCombinesMediaTypesWithTheirFamilies(t *testing.T) {
	const xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	result, err := InspectSources([]InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(`{"plugins":{"textExtraction":{"office":"always","` + xlsx + `":"off"}}}`)},
		{Scope: RoleScope, ID: "role", Config: json.RawMessage(`{"plugins":{"textExtraction":{"office":"auto"}}}`)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result.Effective)
	if err != nil {
		t.Fatal(err)
	}
	var effective struct {
		Plugins struct {
			TextExtraction map[string]string `json:"textExtraction"`
		} `json:"plugins"`
		SetBy []struct {
			Setting string
			Policy  struct{ Scope, ID string }
		} `json:"setBy"`
	}
	if err := json.Unmarshal(raw, &effective); err != nil {
		t.Fatal(err)
	}
	if got := effective.Plugins.TextExtraction; len(got) != 2 || got["office"] != "always" || got[xlsx] != "auto" {
		t.Fatalf("combined text extraction %v", got)
	}
	// The organization gives Word files their mode, and the role gives Excel files theirs.
	var setBy []string
	for _, entry := range effective.SetBy {
		setBy = append(setBy, entry.Setting+" "+string(entry.Policy.Scope)+entry.Policy.ID)
	}
	if want := []string{"plugins.textExtraction.office " + string(OrganizationScope), "plugins.textExtraction.office " + string(RoleScope) + "role"}; !slices.Equal(setBy, want) {
		t.Fatalf("set by %v, want %v", setBy, want)
	}
}

// A default's media types are part of its family's setting, so a requirement for the family, or
// for another of its media types, replaces them as one.
func TestInspectionNamesAReplacedMediaTypeByItsFamily(t *testing.T) {
	key := `{"rules":{"d":{"mode":"default","plugins":{"textExtraction":{"text":"auto","text/csv":"always","office":"auto"}}}}}`
	inspection, err := InspectSources([]InspectionSource{
		{Scope: OrganizationScope, Config: json.RawMessage(`{"plugins":{"textExtraction":{"application/json":"off"}}}`)},
		{Scope: KeyScope, ID: "key", Config: json.RawMessage(key)},
	}, &InspectionEdit{Scope: KeyScope, ID: "key", Previous: json.RawMessage(key)})
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := inspection.Effective["rules"].([]map[string]any)
	want := []map[string]any{{"setting": "plugins.textExtraction.text", "policy": map[string]any{"scope": OrganizationScope}}}
	if len(rules) != 1 || !reflect.DeepEqual(rules[0]["replaced"], want) {
		t.Fatalf("rules: %+v", rules)
	}
	if notes := []InspectionNote{{Kind: "replaced", Scope: OrganizationScope, Sections: []string{"plugins.textExtraction.text"}}}; !reflect.DeepEqual(inspection.Notes, notes) {
		t.Fatalf("notes: %+v", inspection.Notes)
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
	encrypted := `"plugins":{"redaction":{"encrypted":` + string(envelope) + `}}`
	for _, tc := range []struct{ name, source, want string }{
		{"nothing", `{}`, ""},
		{"text extraction", `{"plugins":{"textExtraction":{"text":"always"}}}`, ""},
		{"empty redaction", `{"plugins":{"redaction":{}}}`, ""},
		{"ASCII input", `{"input":{"asciiOnly":true}}`, "input.asciiOnly"},
		{"redaction", `{"plugins":{"redaction":{"presets":["email_address"]}}}`, "plugins.redaction"},
		{"encrypted redaction", `{` + encrypted + `}`, "plugins.redaction"},
		{"encrypted redaction of a matched rule", `{"rules":{"private":{"when":"provider.id == 'openai'",` + encrypted + `}}}`, "plugins.redaction"},
		{"encrypted redaction of an unmatched rule", `{"rules":{"private":{"when":"provider.id == 'azure'",` + encrypted + `}}}`, ""},
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
