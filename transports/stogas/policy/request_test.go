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
		Source   string
		Valid    bool
		Compiled json.RawMessage
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, item := range cases {
		t.Run(item.Source, func(t *testing.T) {
			query, err := CompileQuery(item.Source)
			valid := item.Valid || item.Compiled != nil
			if (err == nil) != valid {
				t.Fatalf("CompileQuery() = %v, want valid=%t", err, valid)
			}
			if item.Compiled != nil {
				var want Query
				if err := json.Unmarshal(item.Compiled, &want); err != nil {
					t.Fatal(err)
				}
				actual, _ := json.Marshal(query)
				expected, _ := json.Marshal(want)
				if string(actual) != string(expected) {
					t.Fatalf("query = %s, want %s", actual, expected)
				}
			}
		})
	}
}

func TestRequestPolicyIntersectionAndIsolation(t *testing.T) {
	parent := validCompiledConfig()
	parent.Routing.RequestPolicy = "filter_and_sort"
	parent.Routing.AllowedCatalogNodes = &AllowedCatalogNodes{Providers: []string{"openai"}}
	parent.Routing.Query, _ = CompileQuery("where deployment.data.capabilities.streaming == false order by provider.id desc")
	before, _ := json.Marshal(parent)
	child, err := ApplyRequest(&parent, []byte(`{"version":1,"routing":{"query":"where provider.id == 'anthropic' order by provider.id asc, model.id asc","allowedCatalogNodes":{"providers":["anthropic"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if child.Routing.AllowedCatalogNodes.Allows("a", "m", "d", "r", "openai") || child.Routing.AllowedCatalogNodes.Allows("a", "m", "d", "r", "anthropic") {
		t.Fatal("empty intersection must deny every provider")
	}
	if len(child.Routing.Query.Where.Operands) != 2 || child.Routing.Query.Where.Kind != "and" {
		t.Fatal("request must add an AND filter")
	}
	if len(child.Routing.Query.OrderBy) != 2 || child.Routing.Query.OrderBy[0].Direction != "desc" {
		t.Fatal("child must preserve parent ordering")
	}
	after, _ := json.Marshal(parent)
	if string(before) != string(after) {
		t.Fatal("request changed cached parent")
	}
	next, err := ApplyRequest(&parent, []byte(`{"version":1,"routing":{"allowedCatalogNodes":{"models":["gpt"]}}}`))
	if err != nil || !next.Routing.AllowedCatalogNodes.Allows("a", "gpt", "d", "r", "openai") {
		t.Fatalf("request restriction leaked: %v", err)
	}
}

func TestRequestPolicyPermissionsAndClosedDocument(t *testing.T) {
	parent := validCompiledConfig()
	filter := []byte(`{"version":1,"routing":{"query":"where exists(provider.id)"}}`)
	for _, mode := range []string{"", "deny", "filter", "filter_and_sort"} {
		parent.Routing.RequestPolicy = mode
		_, err := ApplyRequest(&parent, filter)
		if (err == nil) != (mode == "filter" || mode == "filter_and_sort") {
			t.Fatalf("mode %q: %v", mode, err)
		}
		_, err = ApplyRequest(&parent, []byte(`{"version":1,"routing":{"query":"order by provider.id"}}`))
		if (err == nil) != (mode == "filter_and_sort") {
			t.Fatalf("sort mode %q: %v", mode, err)
		}
	}
	if _, err := ApplyRequest(nil, filter); !errors.Is(err, ErrRequestPolicyDenied) {
		t.Fatalf("nil parent: %v", err)
	}
	parent.Routing.RequestPolicy = "filter_and_sort"
	for _, raw := range []string{
		`null`, `{}`, `{"version":2,"routing":{"query":"where exists(provider.id)"}}`,
		`{"version":1,"routing":{}}`, `{"version":1,"routing":{"query":null}}`,
		`{"version":1,"routing":{"query":""}}`, `{"version":1,"routing":{"allowedCatalogNodes":{}}}`,
		`{"version":1,"routing":{"allowedCatalogNodes":{"providers":null}}}`,
		`{"version":1,"routing":{"allowedCatalogNodes":{"Providers":["openai"]}}}`,
		`{"Version":1,"routing":{"query":"where exists(provider.id)"}}`,
		`{"version":1,"routing":{"Query":"where exists(provider.id)"}}`,
		`{"version":1,"routing":{"query":"where exists(provider.id)"},"plugins":{}}`,
		`{"version":1,"routing":{"query":"where exists(provider.id)"},"limits":{}}`,
		`{"version":1,"routing":{"query":{"where":null}}}`, string(filter) + ` {}`, strings.Repeat(" ", (16<<10)+1),
	} {
		if _, err := ApplyRequest(&parent, []byte(raw)); err == nil {
			t.Fatalf("accepted invalid request: %s", raw)
		}
	}
	if _, err := ApplyRequest(&parent, []byte(`{"version":1,"routing":{"allowedCatalogNodes":{"providers":[]}}}`)); err != nil {
		t.Fatal(err)
	}
}

func FuzzSourceQuery(f *testing.F) {
	for _, seed := range []string{"where provider.id == 'openai'", "where not exists(provider.id)", "order by deployment.id", "where (", strings.Repeat("not ", 64)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		query, err := CompileQuery(source)
		if err == nil {
			if err := query.validate(); err != nil {
				t.Fatalf("compiler emitted invalid query: %v", err)
			}
		}
	})
}
