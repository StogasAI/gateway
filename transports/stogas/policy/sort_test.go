package policy

import (
	"slices"
	"strings"
	"testing"
)

func sortCandidate(provider, model, deployment string) ruleValues {
	return ruleValues{
		"provider.id":   {Type: "string", String: provider},
		"model.id":      {Type: "string", String: model},
		"deployment.id": {Type: "string", String: deployment},
	}
}

// A list ranks candidates by position, with unlisted ones last; later criteria
// order the ties; ties that remain are reported.
func TestSortListsRankByPositionAndReportTies(t *testing.T) {
	query := ruleSource(t, `{"routing":{"sort":[{"providers":["b","a"]},{"by":"model.id"}]}}`).Config.Routing.Query
	candidates := []Values{
		sortCandidate("a", "m1", "d0"),
		sortCandidate("c", "m1", "d1"),
		sortCandidate("b", "m2", "d2"),
		sortCandidate("b", "m1", "d3"),
		sortCandidate("c", "m1", "d4"),
	}
	order, ties, err := query.Sort(candidates)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(order, []int{3, 2, 0, 1, 4}) || !slices.Equal(ties, []bool{false, false, false, false, true}) {
		t.Fatalf("order %v ties %v", order, ties)
	}
	// Without a sort every candidate ties the one before it.
	order, ties, err = (*Query)(nil).Sort(candidates[:3])
	if err != nil || !slices.Equal(order, []int{0, 1, 2}) || !slices.Equal(ties, []bool{false, true, true}) {
		t.Fatalf("unsorted order %v ties %v: %v", order, ties, err)
	}
	// random() orders every deployment; candidates of one deployment tie.
	query = ruleSource(t, `{"routing":{"sort":[{"by":"random()"}]}}`).Config.Routing.Query
	order, ties, err = query.Sort([]Values{sortCandidate("a", "m", "d0"), sortCandidate("a", "m", "d1"), sortCandidate("a", "m", "d0")})
	if err != nil {
		t.Fatal(err)
	}
	position := map[int]int{}
	for i, index := range order {
		position[index] = i
	}
	tied := 0
	for _, tie := range ties {
		if tie {
			tied++
		}
	}
	if gap := position[2] - position[0]; gap != 1 && gap != -1 || !ties[max(position[0], position[2])] || tied != 1 {
		t.Fatalf("random order %v ties %v", order, ties)
	}
}

func TestSortCriteriaTakeOneKind(t *testing.T) {
	for _, test := range []struct{ raw, err string }{
		{`{"routing":{"sort":[{}]}}`, "takes by or one list"},
		{`{"routing":{"sort":[{"direction":"asc"}]}}`, "takes by or one list"},
		{`{"routing":{"sort":[{"by":"","providers":["openai"]}]}}`, "takes by or one list"},
		{`{"routing":{"sort":[{"providers":["openai"],"models":["gpt"]}]}}`, "takes by or one list"},
		{`{"routing":{"sort":[{"providers":["openai"],"direction":"desc"}]}}`, "takes no direction"},
		{`{"routing":{"sort":[{"providers":[]}]}}`, "unique catalog IDs"},
		{`{"routing":{"sort":[{"providers":["openai","openai"]}]}}`, "unique catalog IDs"},
		{`{"routing":{"sort":[{"providers":["Open AI"]}]}}`, "unique catalog IDs"},
		{`{"routing":{"sort":[{"providers":["a"]},{"providers":["b"]}]}}`, "one providers list per policy"},
		{`{"routing":{"sort":[{"deployments":["d"]},{"deployments":["e"]}]}}`, "one deployments list per policy"},
		{`{"routing":{"sort":[{"groups":["claude"]}]}}`, "unknown field"},
		{`{"routing":{"sort":[{"by":"model.id"},{"by":"model.id","direction":"desc"}]}}`, "must be unique"},
		{`{"routing":{"sort":[{"deployments":["d"]},{"by":"model.id"},{"by":"provider.id"},{"by":"route.id"},{"by":"author.id"}]}}`, "no more than four"},
		{`{"routing":{"sort":[{"by":"random()"},{"providers":["a"]}]}}`, "must be the last"},
	} {
		if _, err := CompileSource([]byte(test.raw)); err == nil || !strings.Contains(err.Error(), test.err) {
			t.Errorf("%s: %v, want %q", test.raw, err, test.err)
		}
	}
	for _, raw := range []string{
		`{"routing":{"sort":[{"authors":["openai"]},{"models":["gpt-5.5"]},{"deployments":["openai-gpt-5.5"]},{"routes":["openai"]}]}}`,
		`{"routing":{"sort":[{"deployments":["d"]},{"providers":["openai"]},{"by":"blendedPrice(3, 1)"},{"by":"random()"}]}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

// Each kind of catalog ID takes allow and deny lists, which validate as access lists do and
// combine across policies: allowed IDs intersect and denied IDs join.
func TestRoutingListsValidateAndCombineByKind(t *testing.T) {
	for raw, message := range map[string]string{
		`{"routing":{"providers":{}}}`:                                      "routing.providers requires allow or deny",
		`{"routing":{"models":{"allow":[]}}}`:                               "routing.models.allow requires at least one model ID",
		`{"routing":{"routes":{"deny":["Azure"]}}}`:                         `routing.routes.deny has "Azure", which is not a catalog ID`,
		`{"routing":{"authors":{"allow":["openai","openai"]}}}`:             "routing.authors.allow lists openai twice",
		`{"routing":{"deployments":{"allow":["a","b"],"deny":["b","a"]}}}`:  "routing.deployments.deny holds every deployment ID that allow lists",
		`{"routing":{"providers":{"allow":["openai"],"except":["azure"]}}}`: "unknown field",
	} {
		if _, err := CompileSource([]byte(raw)); err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("%s: %v, want %q", raw, err, message)
		}
	}
	org := ruleSource(t, `{"routing":{"providers":{"allow":["openai","azure"],"deny":["chutes"]},"models":{"deny":["gpt-a"]}}}`)
	key := ruleSource(t, `{"routing":{"providers":{"allow":["azure","anthropic"]},"models":{"deny":["gpt-b"]}}}`)
	config, err := ComposeSources([]ScopedSource{{Scope: OrganizationScope, Value: org}, {Scope: KeyScope, Value: key}})
	if err != nil {
		t.Fatal(err)
	}
	if providers, models := config.Routing.Providers, config.Routing.Models; !slices.Equal(providers.Allow, []string{"azure"}) ||
		!slices.Equal(providers.Deny, []string{"chutes"}) || models.Allow != nil || !slices.Equal(models.Deny, []string{"gpt-a", "gpt-b"}) {
		t.Fatalf("combined lists %+v %+v", providers, models)
	}
	for _, test := range []struct {
		model, provider string
		admitted        bool
	}{{"gpt-c", "azure", true}, {"gpt-c", "openai", false}, {"gpt-b", "azure", false}, {"gpt-a", "azure", false}} {
		if config.Routing.Admits("author", test.model, "deployment", "route", test.provider) != test.admitted {
			t.Errorf("%s on %s admitted=%v", test.model, test.provider, !test.admitted)
		}
	}
}
