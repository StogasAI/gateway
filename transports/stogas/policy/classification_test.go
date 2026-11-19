package policy

import (
	"slices"
	"testing"
)

func TestClassificationRequirementsAndDefaults(t *testing.T) {
	required := func(names string) string { return `{"plugins":{"classification":[` + names + `]}}` }
	byDefault := func(names string) string {
		return `{"rules":{"classify":{"mode":"default","plugins":{"classification":[` + names + `]}}}}`
	}
	for _, tc := range []struct {
		name    string
		sources []string
		want    []string
	}{
		{"omitted", []string{`{}`}, nil},
		{"default", []string{byDefault(`"language"`)}, []string{ClassifierLanguage}},
		{"an empty requirement replaces the default", []string{byDefault(`"language"`), required(``)}, []string{}},
		{"another plugin's requirement", []string{byDefault(`"language"`), `{"plugins":{"promptCaching":"off"}}`}, []string{ClassifierLanguage}},
		// Each policy adds its classifiers, so an empty list never removes another policy's requirement.
		{"requirements join", []string{required(`"language"`), required(`"hidden_characters"`), required(``)}, []string{ClassifierHiddenCharacters, ClassifierLanguage}},
		{"defaults join", []string{byDefault(`"hidden_characters"`), byDefault(`"language","hidden_characters"`)}, []string{ClassifierHiddenCharacters, ClassifierLanguage}},
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
			if got := active.Classification(); !slices.Equal(got, tc.want) || (got == nil) != (tc.want == nil) {
				t.Fatalf("classifiers = %#v, want %#v", got, tc.want)
			}
			inspected, err := inspectionPlugins(active.PluginSources)
			if err != nil {
				t.Fatal(err)
			}
			if got := (&Config{Plugins: inspected}).Classification(); !slices.Equal(got, tc.want) {
				t.Fatalf("inspection gives %q, and execution %q", got, tc.want)
			}
		})
	}
}

func TestClassificationTakesOnlyItsClassifiers(t *testing.T) {
	for _, value := range []string{`null`, `true`, `"language"`, `{}`, `["Language"]`, `["code"]`, `["language","language"]`, `[null]`, `[""]`} {
		if _, err := CompileSource([]byte(`{"plugins":{"classification":` + value + `}}`)); err == nil {
			t.Errorf("accepted %s", value)
		}
	}
	for _, value := range []string{`[]`, `["language"]`, `["hidden_characters","language"]`} {
		if _, err := CompileSource([]byte(`{"plugins":{"classification":` + value + `}}`)); err != nil {
			t.Errorf("refused %s: %v", value, err)
		}
	}
}
