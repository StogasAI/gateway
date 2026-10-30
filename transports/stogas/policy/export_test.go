package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestExportSourceContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/export-policies.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name   string
		Source json.RawMessage
		Valid  bool
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			_, err := CompileSource(row.Source)
			if (err == nil) != row.Valid {
				t.Fatalf("valid=%v error=%v", row.Valid, err)
			}
		})
	}
}

func TestExportCompositionRulesAndInspection(t *testing.T) {
	const dest = `{"url":"https://collector.example/v1/traces"}`
	const plugin = `{"export":{"destinations":[` + dest + `]}}`
	const withoutContent = `{"export":{"destinations":[{"url":"https://collector.example/v1/traces","content":false}]}}`
	for _, tc := range []struct {
		name, org, key, provider string
		want                     int
		withoutContent           bool
	}{
		{"required survives neutral", `{"plugins":` + plugin + `}`, `{"plugins":{"export":{"destinations":[]}}}`, "openai", 1, false},
		{"exact duplicate", `{"plugins":` + plugin + `}`, `{"plugins":` + plugin + `}`, "openai", 1, false},
		{"distinct auth", `{"plugins":` + plugin + `}`, `{"plugins":{"export":{"destinations":[{"url":"https://collector.example/v1/traces","headers":{"Authorization":"Bearer different"}}]}}}`, "openai", 2, false},
		{"without content", `{"plugins":` + withoutContent + `}`, `{}`, "openai", 1, true},
		{"one record per receiver, with content", `{"plugins":` + withoutContent + `}`, `{"plugins":` + plugin + `}`, "openai", 1, false},
		{"inherited content stays", `{"plugins":` + plugin + `}`, `{"plugins":` + withoutContent + `}`, "openai", 1, false},
		{"default", `{"rules":{"export":{"mode":"default","plugins":` + plugin + `}}}`, `{}`, "openai", 1, false},
		{"neutral replaces default", `{"rules":{"export":{"mode":"default","plugins":` + plugin + `}}}`, `{"plugins":{"export":{"destinations":[]}}}`, "openai", 0, false},
		{"conditional applies", `{"rules":{"export":{"when":"provider.id == 'openai'","plugins":` + plugin + `}}}`, `{}`, "openai", 1, false},
		{"conditional skips", `{"rules":{"export":{"when":"provider.id == 'openai'","plugins":` + plugin + `}}}`, `{}`, "anthropic", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, tc.org)}, {Scope: KeyScope, Value: ruleSource(t, tc.key)}})
			if err != nil {
				t.Fatal(err)
			}
			active, err := base.Activate(ruleValues{"provider.id": {Type: "string", String: tc.provider}})
			if err != nil {
				t.Fatal(err)
			}
			exports, err := active.ExportConfig()
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			if exports != nil {
				n = len(exports.Destinations)
				for _, d := range exports.Destinations {
					if d.SendsContent() == tc.withoutContent {
						t.Fatalf("destination %s sends content: %v", d.URL, d.SendsContent())
					}
				}
			}
			if n != tc.want {
				t.Fatalf("destinations=%d want=%d", n, tc.want)
			}
			inspected, err := inspectionPlugins(active.PluginSources)
			if err != nil {
				t.Fatal(err)
			}
			exported, err := (&Config{Plugins: inspected}).ExportConfig()
			if err != nil {
				t.Fatal(err)
			}
			n = 0
			if exported != nil {
				n = len(exported.Destinations)
			}
			if n != tc.want {
				t.Fatalf("inspection destinations=%d", n)
			}
		})
	}
	request, err := CompileRequest([]byte(`{"plugins":`+plugin+`}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"plugins.redaction", "plugins.export", "plugins"} {
		base, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, `{"delegation":{"request":["`+section+`"]}}`)}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = ApplyRequest(base, request)
		if section == "plugins.redaction" {
			if !errors.Is(err, ErrRequestPolicyDenied) {
				t.Fatalf("export permission bypass: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestExportAggregateDestinationBound(t *testing.T) {
	destinations := make([]map[string]string, 8)
	for i := range destinations {
		destinations[i] = map[string]string{"url": fmt.Sprintf("https://collector.example/%d", i)}
	}
	raw, _ := json.Marshal(map[string]any{"plugins": map[string]any{"export": map[string]any{"destinations": destinations}}})
	source := ruleSource(t, string(raw))
	child := ruleSource(t, `{"plugins":{"export":{"destinations":[{"url":"https://other.example/"}]}}}`)
	combined, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: source}, {Scope: KeyScope, Value: child}})
	if err == nil {
		_, err = combined.Activate(ruleValues{})
	}
	if err == nil {
		t.Fatal("accepted more than eight combined destinations")
	}
}
