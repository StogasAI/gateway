package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
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
					if (d.ContentReach() > 0) == tc.withoutContent {
						t.Fatalf("destination %s sends content: %v", d.URL, d.ContentReach() > 0)
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
			exported, err := (&Config{Plugins: inspected.flat()}).ExportConfig()
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
		base, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, `{"delegation":{"requests":["`+section+`"]}}`)}})
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

// Eight destinations bound one policy, counting its rules. The policies of a
// chain have no total, so a key adds its own to an organization's eight.
func TestExportDestinationsBoundEachPolicy(t *testing.T) {
	destinations := make([]map[string]string, 8)
	for i := range destinations {
		destinations[i] = map[string]string{"url": fmt.Sprintf("https://collector.example/%d", i)}
	}
	export := map[string]any{"export": map[string]any{"destinations": destinations}}
	raw, _ := json.Marshal(map[string]any{"plugins": export})
	source := ruleSource(t, string(raw))
	const other = `{"plugins":{"export":{"destinations":[{"url":"https://other.example/"}]}}}`
	combined, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: source}, {Scope: KeyScope, Value: ruleSource(t, other)}})
	if err == nil {
		combined, err = combined.Activate(ruleValues{})
	}
	if err != nil {
		t.Fatalf("policies within their own bounds did not combine: %v", err)
	}
	if exports, err := combined.ExportConfig(); err != nil || len(exports.Destinations) != 9 {
		t.Fatalf("combined destinations = %v, %v", exports, err)
	}
	// A rule can match with its policy's own plugins, so they count together.
	raw, _ = json.Marshal(map[string]any{"plugins": export, "rules": map[string]any{"more": json.RawMessage(other)}})
	var sections *SectionsError
	if _, err := CompileSource(raw); !errors.As(err, &sections) || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("a policy and its rule exported to nine destinations: %v", err)
	}
	// The same destination in a rule is one receiver.
	raw, _ = json.Marshal(map[string]any{"plugins": export, "rules": map[string]any{"same": map[string]any{"plugins": map[string]any{"export": map[string]any{"destinations": destinations[:1]}}}}})
	if _, err := CompileSource(raw); err != nil {
		t.Fatalf("a repeated destination counted twice: %v", err)
	}
}

// Only a gateway reads an encrypted plugin, so it counts what a request opens
// with the other plugins of the same policy, and names that policy.
func TestOpenedPluginsCountWithTheirOwnPolicy(t *testing.T) {
	export := func(prefix string, count int) *Plugins {
		config := &exportconfig.Config{}
		for i := range count {
			config.Destinations = append(config.Destinations, exportconfig.Destination{URL: fmt.Sprintf("https://%s-%d.example/", prefix, i)})
		}
		return &Plugins{Export: config}
	}
	destinations := make([]map[string]string, 8)
	for i := range destinations {
		destinations[i] = map[string]string{"url": fmt.Sprintf("https://collector.example/%d", i)}
	}
	raw, _ := json.Marshal(map[string]any{"plugins": map[string]any{"export": map[string]any{"destinations": destinations}}})
	config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, string(raw))}, {Scope: KeyScope, Value: ruleSource(t, `{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	// The key's policy opens eight destinations of its own beside the
	// organization's eight.
	config.ActiveEncryptedPlugins = []EncryptedPlugins{{policy: 1}}
	active, err := config.WithOpened([]*Plugins{export("key", 8)})
	if err != nil {
		t.Fatalf("each policy kept to its own destinations: %v", err)
	}
	if exports, err := active.ExportConfig(); err != nil || len(exports.Destinations) != 16 || len(config.PluginSources) != 1 {
		t.Fatalf("opened destinations were lost or changed the cached policy: %v %v", exports, err)
	}
	// One more destination in the organization's own encrypted rule passes
	// the organization's bound.
	config.ActiveEncryptedPlugins = []EncryptedPlugins{{policy: 0}}
	var sections *SectionsError
	if _, err := config.WithOpened([]*Plugins{export("organization", 1)}); !errors.As(err, &sections) || sections.Scope != OrganizationScope || sections.Origin.Source != 0 {
		t.Fatalf("a policy opened a ninth destination: %v", err)
	}
}

// Policies that name one receiver send it one record whenever any of them
// would, so a policy below can add records and never take one away. A request
// policy and a rule widen the sample the same way.
func TestExportSamplesWidenAcrossPolicies(t *testing.T) {
	destination := func(sample string) string {
		if sample != "" {
			sample = `,"sample":` + sample
		}
		return `{"plugins":{"export":{"destinations":[{"url":"https://collector.example/v1/traces"` + sample + `}]}}}`
	}
	for _, tc := range []struct{ name, org, key, request, want string }{
		{"failures, then a tenth of successes", destination(`{"failed":1,"rejected":1}`), destination(`{"success":0.1}`), "", `{"failed":1,"rejected":1,"success":0.1}`},
		{"the higher rate", destination(`0.1`), destination(`0.5`), "", `0.5`},
		{"a lower rate below changes nothing", destination(`0.5`), destination(`0.01`), "", `0.5`},
		{"a narrower list below changes nothing", destination(`0.5`), destination(`{"failed":0.25}`), "", `0.5`},
		{"every record wins over a sample", destination(``), destination(`0.01`), "", ``},
		{"a sample cannot narrow every record", destination(`{"failed":1}`), destination(``), "", ``},
		{"a request adds to its key's sample", destination(`{"failed":1}`), `{}`, destination(`{"success":0.25}`), `{"failed":1,"success":0.25}`},
		{"a request cannot narrow its key's sample", destination(`0.5`), `{}`, destination(`{"unknown":0.001}`), `0.5`},
		{"the outcomes fill up to every record", destination(`{"success":1,"failed":1}`), destination(`{"cancelled":1,"rejected":1,"unknown":1}`), "", ``},
		{"a rule widens", `{"rules":{"audit":{"when":"provider.id == 'openai'","plugins":{"export":{"destinations":[{"url":"https://collector.example/v1/traces","sample":{"failed":1}}]}}}}}`, destination(`{"success":0.1}`), "", `{"failed":1,"success":0.1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			org := tc.org
			if tc.request != "" {
				org = `{"delegation":{"requests":["plugins.export"]},` + org[1:]
			}
			base, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: ruleSource(t, org)}, {Scope: KeyScope, Value: ruleSource(t, tc.key)}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.request != "" {
				request, err := CompileRequest([]byte(tc.request), "org", nil)
				if err != nil {
					t.Fatal(err)
				}
				if base, err = ApplyRequest(base, request); err != nil {
					t.Fatal(err)
				}
			}
			active, err := base.Activate(ruleValues{"provider.id": {Type: "string", String: "openai"}})
			if err != nil {
				t.Fatal(err)
			}
			exports, err := active.ExportConfig()
			if err != nil {
				t.Fatal(err)
			}
			inspected, err := inspectionPlugins(active.PluginSources)
			if err != nil {
				t.Fatal(err)
			}
			want := `{"destinations":[{"url":"https://collector.example/v1/traces"}]}`
			if tc.want != "" {
				want = `{"destinations":[{"url":"https://collector.example/v1/traces","sample":` + tc.want + `}]}`
			}
			for name, config := range map[string]any{"effective": exports, "inspected": inspected.Export} {
				encoded, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				if string(encoded) != want {
					t.Fatalf("%s export = %s, want %s", name, encoded, want)
				}
			}
		})
	}
}
