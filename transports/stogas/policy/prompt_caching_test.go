package policy

import "testing"

func TestPromptCachingRequirementsAndDefaults(t *testing.T) {
	required := func(mode string) string { return `{"plugins":{"promptCaching":"` + mode + `"}}` }
	byDefault := func(mode string) string {
		return `{"rules":{"cache":{"mode":"default","plugins":{"promptCaching":"` + mode + `"}}}}`
	}
	for _, tc := range []struct {
		name    string
		sources []string
		want    string
	}{
		// The gateway changes no request unless a policy says so.
		{"omitted", []string{`{}`}, PromptCachingOff},
		{"default", []string{byDefault("5m")}, PromptCaching5m},
		{"a requirement replaces the default", []string{byDefault("5m"), required("off")}, PromptCachingOff},
		{"another plugin's requirement", []string{byDefault("1h"), `{"plugins":{"textExtraction":{"text":"auto"}}}`}, PromptCaching1h},
		// A longer lifetime wins, so off never weakens another policy's requirement.
		{"off against a requirement", []string{required("5m"), required("off")}, PromptCaching5m},
		{"an hour over five minutes", []string{required("1h"), required("5m")}, PromptCaching1h},
		{"the strongest default", []string{byDefault("5m"), byDefault("1h")}, PromptCaching1h},
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
			if got := active.PromptCaching(); got != tc.want {
				t.Fatalf("prompt caching = %q, want %q", got, tc.want)
			}
			inspected, err := inspectionPlugins(active.PluginSources)
			if err != nil {
				t.Fatal(err)
			}
			if got := (&Config{Plugins: inspected}).PromptCaching(); got != tc.want {
				t.Fatalf("inspection gives %q, and execution %q", got, tc.want)
			}
		})
	}
}

func TestPromptCachingTakesOnlyItsModes(t *testing.T) {
	for _, value := range []string{`true`, `null`, `""`, `"5M"`, `"10m"`, `"24h"`, `"auto"`, `{}`, `{"ttl":"5m"}`, `["5m"]`} {
		if _, err := CompileSource([]byte(`{"plugins":{"promptCaching":` + value + `}}`)); err == nil {
			t.Errorf("accepted %s", value)
		}
	}
	for _, mode := range []string{PromptCachingOff, PromptCaching5m, PromptCaching1h} {
		if _, err := CompileSource([]byte(`{"plugins":{"promptCaching":"` + mode + `"}}`)); err != nil {
			t.Errorf("refused %s: %v", mode, err)
		}
	}
}
