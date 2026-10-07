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
	const plugin = `{"stogasExport":{"destinations":[` + dest + `]}}`
	for _, tc := range []struct {
		name, org, key, provider string
		want                     int
	}{
		{"required survives neutral", `{"plugins":` + plugin + `}`, `{"plugins":{"stogasExport":{"destinations":[]}}}`, "openai", 1},
		{"exact duplicate", `{"plugins":` + plugin + `}`, `{"plugins":` + plugin + `}`, "openai", 1},
		{"distinct auth", `{"plugins":` + plugin + `}`, `{"plugins":{"stogasExport":{"destinations":[{"url":"https://collector.example/v1/traces","headers":{"Authorization":"Bearer different"}}]}}}`, "openai", 2},
		{"default", `{"rules":{"export":{"mode":"default","plugins":` + plugin + `}}}`, `{}`, "openai", 1},
		{"neutral replaces default", `{"rules":{"export":{"mode":"default","plugins":` + plugin + `}}}`, `{"plugins":{"stogasExport":{"destinations":[]}}}`, "openai", 0},
		{"conditional applies", `{"rules":{"export":{"when":"provider.id == 'openai'","plugins":` + plugin + `}}}`, `{}`, "openai", 1},
		{"conditional skips", `{"rules":{"export":{"when":"provider.id == 'openai'","plugins":` + plugin + `}}}`, `{}`, "anthropic", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, err := ComposeSources([]ScopedSource{{OrganizationScope, ruleSource(t, tc.org)}, {KeyScope, ruleSource(t, tc.key)}})
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
	for _, section := range []string{"plugins.stogasRedaction", "plugins.stogasExport", "plugins"} {
		base, err := ComposeSources([]ScopedSource{{OrganizationScope, ruleSource(t, `{"delegation":{"request":["`+section+`"]}}`)}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = ApplyRequest(base, request)
		if section == "plugins.stogasRedaction" {
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
	raw, _ := json.Marshal(map[string]any{"plugins": map[string]any{"stogasExport": map[string]any{"destinations": destinations}}})
	source := ruleSource(t, string(raw))
	child := ruleSource(t, `{"plugins":{"stogasExport":{"destinations":[{"url":"https://other.example/"}]}}}`)
	combined, err := ComposeSources([]ScopedSource{{OrganizationScope, source}, {KeyScope, child}})
	if err == nil {
		_, err = combined.Activate(ruleValues{})
	}
	if err == nil {
		t.Fatal("accepted more than eight combined destinations")
	}
}
