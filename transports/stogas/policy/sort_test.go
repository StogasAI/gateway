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
		{`{"routing":{"order":["d"],"sort":[{"deployments":["e"]}]}}`, "one deployments list per policy"},
		{`{"routing":{"sort":[{"groups":["claude"]}]}}`, "unknown field"},
		{`{"routing":{"sort":[{"by":"model.id"},{"by":"model.id","direction":"desc"}]}}`, "must be unique"},
		{`{"routing":{"order":["d"],"sort":[{"by":"model.id"},{"by":"provider.id"},{"by":"route.id"},{"by":"author.id"}]}}`, "no more than four"},
		{`{"routing":{"sort":[{"by":"random()"},{"providers":["a"]}]}}`, "must be the last"},
	} {
		if _, err := CompileSource([]byte(test.raw)); err == nil || !strings.Contains(err.Error(), test.err) {
			t.Errorf("%s: %v, want %q", test.raw, err, test.err)
		}
	}
	for _, raw := range []string{
		`{"routing":{"sort":[{"authors":["openai"]},{"models":["gpt-5.5"]},{"deployments":["openai-gpt-5.5"]},{"routes":["openai"]}]}}`,
		`{"routing":{"order":["d"],"sort":[{"providers":["openai"]},{"by":"blended_price(3, 1)"},{"by":"random()"}]}}`,
	} {
		if _, err := CompileSource([]byte(raw)); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}
