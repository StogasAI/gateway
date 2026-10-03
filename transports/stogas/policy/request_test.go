package policy

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestSourceQueryCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/source-queries.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Filter string
		Sort   []Sort
		Valid  bool
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for i, item := range cases {
		_, err := CompileRouting(item.Filter, item.Sort)
		if (err == nil) != item.Valid {
			t.Fatalf("case %d: CompileRouting()=%v want valid=%v", i, err, item.Valid)
		}
	}
}

func requestParent(t *testing.T, raw string) *Config {
	t.Helper()
	config, err := ComposeSources([]ScopedSource{{OrganizationScope, ruleSource(t, raw)}})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestRequestPolicyIntersectionAndIsolation(t *testing.T) {
	parent := requestParent(t, `{"delegation":{"request":true},"routing":{"allowedCatalogNodes":{"providers":["openai"]},"filter":"deployment.capabilities.streaming == false"},"rules":{"baseline":{"mode":"default","routing":{"sort":[{"by":"provider.id","direction":"desc"}]}}}}`)
	before, _ := json.Marshal(parent)
	child, err := applyRequestJSON(parent, []byte(`{"routing":{"filter": "provider.id == \"anthropic\"", "sort": [{"by":"provider.id","direction":"asc"},{"by":"model.id","direction":"asc"}],"allowedCatalogNodes":{"providers":["anthropic"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if child.Routing.AllowedCatalogNodes.Allows("a", "m", "d", "r", "openai") || child.Routing.AllowedCatalogNodes.Allows("a", "m", "d", "r", "anthropic") {
		t.Fatal("empty intersection must deny every provider")
	}
	if len(child.Routing.Query.Filters) != 2 {
		t.Fatal("request must add an AND filter")
	}
	child, err = child.Activate(testValues{})
	if err != nil {
		t.Fatal(err)
	}
	if len(child.Routing.Query.OrderBy) != 2 || child.Routing.Query.OrderBy[0].Direction != "asc" {
		t.Fatal("child must replace the complete overridable ordering")
	}
	after, _ := json.Marshal(parent)
	if string(before) != string(after) {
		t.Fatal("request changed cached parent")
	}
	next, err := applyRequestJSON(parent, []byte(`{"routing":{"allowedCatalogNodes":{"models":["gpt"]}}}`))
	if err != nil || !next.Routing.AllowedCatalogNodes.Allows("a", "gpt", "d", "r", "openai") {
		t.Fatalf("request restriction leaked: %v", err)
	}
}

func TestRequestPolicyPermissionsAndClosedDocument(t *testing.T) {
	parent := requestParent(t, `{"delegation":{"request":true}}`)
	filter := []byte(`{"routing":{"filter": "has(provider.id)"}}`)
	for _, allowed := range []Permission{0, permissionFilter, permissionFilter | permissionSort} {
		parent.RequestPermission = RequestPermission(allowed)
		_, err := applyRequestJSON(parent, filter)
		if (err == nil) != (allowed&permissionFilter != 0) {
			t.Fatalf("filter permission %d: %v", allowed, err)
		}
		_, err = applyRequestJSON(parent, []byte(`{"routing":{"sort":[{"by":"provider.id","direction":"asc"}]}}`))
		if (err == nil) != (allowed&permissionSort != 0) {
			t.Fatalf("sort permission %d: %v", allowed, err)
		}
	}

	if _, err := applyRequestJSON(nil, filter); !errors.Is(err, ErrRequestPolicyDenied) {
		t.Fatalf("nil parent: %v", err)
	}
	parent.RequestPermission = RequestPermission(requestPermissions)
	for _, raw := range []string{
		`null`, `{"version":1}`, `{"version":2,"routing":{"filter": "has(provider.id)"}}`,
		`{"routing":{"filter":null}}`,
		`{"routing":{"filter":""}}`, `{"routing":{"allowedCatalogNodes":{"unknown":[]}}}`,
		`{"routing":{"allowedCatalogNodes":{"providers":null}}}`,
		`{"routing":{"allowedCatalogNodes":{"Providers":["openai"]}}}`,
		`{"Version":1,"routing":{"filter": "has(provider.id)"}}`,
		`{"routing":{"Query":"where exists(provider.id)"}}`,
		`{"routing":{"filter": "has(provider.id)"},"plugins":{}}`,
		`{"routing":{"filter": "has(provider.id)"},"limits":{}}`,
		`{"routing":{"query":{"where":null}}}`, string(filter) + ` {}`, strings.Repeat(" ", (16<<10)+1),
	} {
		if _, err := applyRequestJSON(parent, []byte(raw)); err == nil {
			t.Fatalf("accepted invalid request: %s", raw)
		}
	}
	if _, err := applyRequestJSON(parent, []byte(`{"routing":{"allowedCatalogNodes":{"providers":[]}}}`)); err != nil {
		t.Fatal(err)
	}
}

func TestRequiredSortingAllowsFiltersAndRejectsDifferentRequestSorts(t *testing.T) {
	parent := requestParent(t, `{"delegation":{"request":true},"routing":{"sort":[{"by":"provider.id","direction":"desc"}]}}`)
	before, _ := json.Marshal(parent)
	for _, sortBy := range []string{"model.id", "blended_price(3, 1, 'per_mill_tokens')"} {
		raw, _ := json.Marshal(map[string]any{"routing": map[string]any{"sort": []Sort{{By: sortBy, Direction: "desc"}}}})
		if _, err := applyRequestJSON(parent, raw); err == nil {
			t.Fatal("accepted conflicting required sort")
		}
	}
	child, err := applyRequestJSON(parent, []byte(`{"routing":{"filter":"provider.id == 'openai'","sort":[{"by":"provider.id","direction":"desc"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(child.Routing.Query.OrderBy) != 1 || child.Routing.Query.OrderBy[0].Direction != "desc" {
		t.Fatal("filter request changed required ordering")
	}
	after, _ := json.Marshal(parent)
	if string(before) != string(after) {
		t.Fatal("request mutated parent")
	}
}

func FuzzSourceQuery(f *testing.F) {
	for _, seed := range []string{"provider.id == 'openai'", "!has(provider.id)", "blended_price(0,0,'per_mill_tokens') < decimal('5')", "(", strings.Repeat("!", 64)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		query, err := CompileRouting(source, nil)
		if err == nil {
			_, _ = query.Matches(testValues{})
		}
	})
}

func applyRequestJSON(parent *Config, raw []byte) (*Config, error) {
	request, err := CompileRequest(raw, "", nil)
	if err != nil {
		return nil, err
	}
	return ApplyRequest(parent, request)
}
