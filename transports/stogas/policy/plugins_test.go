package policy

import (
	"errors"
	"testing"
)

func TestTextExtractionRequirementsAndDefaults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sources []string
		want    bool
	}{
		{"omitted", []string{`{}`}, false},
		{"required", []string{`{"plugins":{"textExtraction":true}}`, `{"plugins":{"textExtraction":false}}`}, true},
		{"default", []string{`{"rules":{"extract":{"mode":"default","plugins":{"textExtraction":true}}}}`}, true},
		{"explicit neutral", []string{`{"rules":{"extract":{"mode":"default","plugins":{"textExtraction":true}}}}`, `{"plugins":{"textExtraction":false}}`}, false},
		{"shared plugin default unit", []string{`{"rules":{"extract":{"mode":"default","plugins":{"textExtraction":true}}}}`, `{"plugins":{"redaction":{}}}`}, false},
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
			if active.TextExtractionEnabled() != tc.want {
				t.Fatalf("extraction = %v, want %v", active.TextExtractionEnabled(), tc.want)
			}
			if _, err := CompileRedaction(active); err != nil {
				t.Fatal(err)
			}
			inspected, err := inspectionPlugins(active.PluginSources)
			if err != nil {
				t.Fatal(err)
			}
			if (&Config{Plugins: inspected}).TextExtractionEnabled() != tc.want {
				t.Fatal("inspection differs from execution")
			}
		})
	}
}

func TestTextExtractionRequiresItsOwnRequestPermission(t *testing.T) {
	request, err := CompileRequest([]byte(`{"plugins":{"textExtraction":true}}`), "org", nil)
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
