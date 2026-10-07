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
		{"required", []string{`{"plugins":{"stogasTextExtraction":true}}`, `{"plugins":{"stogasTextExtraction":false}}`}, true},
		{"default", []string{`{"rules":{"extract":{"mode":"default","plugins":{"stogasTextExtraction":true}}}}`}, true},
		{"explicit neutral", []string{`{"rules":{"extract":{"mode":"default","plugins":{"stogasTextExtraction":true}}}}`, `{"plugins":{"stogasTextExtraction":false}}`}, false},
		{"shared plugin default unit", []string{`{"rules":{"extract":{"mode":"default","plugins":{"stogasTextExtraction":true}}}}`, `{"plugins":{"stogasRedaction":{}}}`}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := []ScopedSource{{OrganizationScope, ruleSource(t, `{}`)}}
			for _, raw := range tc.sources {
				sources = append(sources, ScopedSource{RoleScope, ruleSource(t, raw)})
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
	request, err := CompileRequest([]byte(`{"plugins":{"stogasTextExtraction":true}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"plugins.stogasRedaction", "plugins.stogasTextExtraction", "plugins"} {
		source := ruleSource(t, `{"delegation":{"request":["`+section+`"]}}`)
		base, err := ComposeSources([]ScopedSource{{OrganizationScope, source}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = ApplyRequest(base, request)
		if section == "plugins.stogasRedaction" {
			if !errors.Is(err, ErrRequestPolicyDenied) {
				t.Fatalf("redaction permission granted extraction: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}
