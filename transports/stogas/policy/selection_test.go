package policy

import (
	"errors"
	"testing"
)

func TestRoutingSelectionCompositionAndDefaults(t *testing.T) {
	for _, test := range []struct {
		name, organization, child, mode string
		wantSort, invalid               bool
	}{
		{"required selection replaces default sort", `{"rules":{"baseline":{"mode":"default","routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}}}`, `{"routing":{"selection":{"mode":"random"}}}`, "random", false, false},
		{"required sort replaces default selection", `{"rules":{"baseline":{"mode":"default","routing":{"selection":{"mode":"random"}}}}}`, `{"routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}`, "", true, false},
		{"explicit empty sort clears default selection", `{"rules":{"baseline":{"mode":"default","routing":{"selection":{"mode":"random"}}}}}`, `{"routing":{"sort":[]}}`, "", false, false},
		{"random target order is immaterial", `{"routing":{"selection":{"mode":"random","targets":["a","b"]}}}`, `{"routing":{"selection":{"mode":"random","targets":["b","a"]}}}`, "random", false, false},
		{"conflicting ordered targets reject", `{"routing":{"selection":{"mode":"ordered","targets":["a","b"]}}}`, `{"routing":{"selection":{"mode":"ordered","targets":["b","a"]}}}`, "", false, true},
		{"required sort and selection conflict", `{"routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}`, `{"routing":{"selection":{"mode":"random"}}}`, "", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := ComposeSources([]ScopedSource{{OrganizationScope, ruleSource(t, test.organization)}, {KeyScope, ruleSource(t, test.child)}})
			if err == nil {
				config, err = config.Activate(ruleValues{})
			}
			if test.invalid {
				if err == nil {
					t.Fatal("conflicting routing requirements were accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			mode := ""
			if config.Routing.Selection != nil {
				mode = config.Routing.Selection.Mode
			}
			if mode != test.mode || (config.Routing.Query != nil && len(config.Routing.Query.OrderBy) > 0) != test.wantSort {
				t.Fatalf("wrong active ordering: %+v", config.Routing)
			}
		})
	}
}

func TestRoutingSelectionPermissionAndAttemptMinimum(t *testing.T) {
	base, err := ComposeSources([]ScopedSource{{OrganizationScope, ruleSource(t, `{"delegation":{"request":["routing.selection","routing.maxAttempts"]},"routing":{"maxAttempts":2,"allowedCatalogNodes":{"providers":["openai"]}}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := CompileRequest([]byte(`{"routing":{"maxAttempts":3,"selection":{"mode":"random"}}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := ApplyRequest(base, request)
	if err != nil || combined.Routing.MaxAttempts != 2 || combined.Routing.Selection.Mode != "random" || len(combined.Routing.AllowedCatalogNodes.Providers) != 1 {
		t.Fatalf("request weakened inherited restrictions: %+v, %v", combined, err)
	}
	for _, raw := range []string{`{"routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}`, `{"rules":{"widen":{"routing":{"allowedCatalogNodes":{}}}}}`} {
		denied, err := CompileRequest([]byte(raw), "org", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyRequest(base, denied); !errors.Is(err, ErrRequestPolicyDenied) {
			t.Fatalf("selection permission granted unrelated authority: %v", err)
		}
	}
	if base.Routing.Selection != nil || base.Routing.MaxAttempts != 2 {
		t.Fatal("request mutated the cached parent")
	}
}
