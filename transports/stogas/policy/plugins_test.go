package policy

import (
	"errors"
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
