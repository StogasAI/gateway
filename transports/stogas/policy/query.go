package policy

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"time"
	"unsafe"

	"cel.dev/cel-go/common/types"
)

// Query shares each source's checked filter instead of compiling a new
// concatenation for every key. Sort expressions run once per candidate.
type Query struct {
	Filters []*CELExpression `json:"filters,omitempty"`
	OrderBy []Sort           `json:"orderBy"`
}

// Sort is one routing criterion: a CEL expression in By, which Direction
// orders asc by default, or one list of catalog node IDs, which ranks
// candidates by position. Missing values and unlisted candidates sort last. A
// random() criterion has no direction.
type Sort struct {
	By          string   `json:"by,omitempty"`
	Direction   string   `json:"direction,omitempty"`
	Authors     []string `json:"authors,omitempty"`
	Models      []string `json:"models,omitempty"`
	Deployments []string `json:"deployments,omitempty"`
	Routes      []string `json:"routes,omitempty"`
	Providers   []string `json:"providers,omitempty"`
	expression  *CELExpression
	// ranks maps each listed ID to its position.
	ranks map[string]int
}

// sortLists names each list a criterion can hold and the candidate field it
// ranks. Lists name the same nodes as routing.allowedCatalogNodes.
var sortLists = [...]struct {
	name, field string
	ids         func(*Sort) []string
}{
	{"authors", "author.id", func(s *Sort) []string { return s.Authors }},
	{"models", "model.id", func(s *Sort) []string { return s.Models }},
	{"deployments", "deployment.id", func(s *Sort) []string { return s.Deployments }},
	{"routes", "route.id", func(s *Sort) []string { return s.Routes }},
	{"providers", "provider.id", func(s *Sort) []string { return s.Providers }},
}

const sortKinds = "each routing.sort criterion takes by or one list of authors, models, deployments, routes or providers"

// UnmarshalJSON requires exactly one kind, so an empty by cannot sit beside
// a list unnoticed.
func (s *Sort) UnmarshalJSON(raw []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return err
	}
	type plain Sort
	var value plain
	if err := decodeStrict(raw, &value); err != nil {
		return err
	}
	kinds := 0
	for name := range members {
		if name != "direction" {
			kinds++
		}
	}
	if kinds != 1 {
		return configError(sortKinds)
	}
	*s = Sort(value)
	return nil
}

// list returns the criterion's list kind, ranked field and IDs, or empty
// values for an expression.
func (s *Sort) list() (name, field string, ids []string) {
	for _, kind := range sortLists {
		if ids := kind.ids(s); ids != nil {
			return kind.name, kind.field, ids
		}
	}
	return "", "", nil
}

// key identifies what a criterion compares. A later criterion with the key
// of an earlier one can never break its ties, whatever its direction: values
// that tie one way tie the other. Composition keeps the first.
func (s *Sort) key() string {
	if name, _, ids := s.list(); name != "" {
		return name + "\x00" + strings.Join(ids, "\x00")
	}
	by := strings.TrimSpace(s.By)
	if s.expression != nil && s.expression.normalized != "" {
		by = s.expression.normalized
	}
	return "by\x00" + by
}

// CompositionBytes estimates this configuration's own retained structures.
// Sources own their strings, programs and plugins; composition borrows them.
func (c *Config) CompositionBytes() int64 {
	if c == nil {
		return 0
	}
	total := int64(unsafe.Sizeof(*c)) + int64(cap(c.sources))*int64(unsafe.Sizeof(ScopedSource{}))
	total += int64(cap(c.PluginSources))*8 + int64(cap(c.ActiveEncryptedPlugins))*int64(unsafe.Sizeof(EncryptedPlugins{})) + int64(cap(c.RequiredEncryptionKeys))*16
	total += int64(cap(c.ActiveRules)) * int64(unsafe.Sizeof(RuleMatch{}))
	if c.Access != nil {
		total += int64(unsafe.Sizeof(*c.Access)) + int64(cap(c.Access.Deny))*int64(unsafe.Sizeof(DenyWindow{}))
	}
	if c.Routing.Query != nil {
		total += int64(unsafe.Sizeof(*c.Routing.Query)) + int64(cap(c.Routing.Query.Filters))*8
	}
	if nodes := c.Routing.AllowedCatalogNodes; nodes != nil {
		borrowed := false
		for _, entry := range c.sources {
			if entry.Value.Config.Routing.AllowedCatalogNodes == nodes {
				borrowed = true
				break
			}
		}
		if !borrowed {
			total += int64(unsafe.Sizeof(*nodes))
			for _, list := range [][]string{nodes.Authors, nodes.Deployments, nodes.Models, nodes.Providers, nodes.Routes} {
				total += int64(cap(list)) * 16
			}
		}
	}
	return total
}

func (e *CELExpression) MarshalJSON() ([]byte, error) { return json.Marshal(e.Source) }

// ProviderOrder ranks providers by their position in ids, as a request's
// provider.order lists them.
func ProviderOrder(ids []string) Sort {
	criterion := Sort{Providers: ids, ranks: make(map[string]int, len(ids))}
	for rank, id := range ids {
		if _, listed := criterion.ranks[id]; !listed {
			criterion.ranks[id] = rank
		}
	}
	return criterion
}

// WithSort returns a query that sorts by q's criteria with criterion placed at
// index at. It shares q's filters and leaves q unchanged.
func (q *Query) WithSort(at int, criterion Sort) *Query {
	out := &Query{}
	if q != nil {
		out.Filters = q.Filters
		out.OrderBy = slices.Insert(slices.Clone(q.OrderBy), min(at, len(q.OrderBy)), criterion)
	} else {
		out.OrderBy = []Sort{criterion}
	}
	return out
}

func CompileRouting(filter string, order []Sort) (*Query, error) {
	return compileRouting(filter, order, &celCompiler{prepare: true})
}

// A combined view uses stored, already validated expressions. It does not
// execute them and need not type-check every unchanged ancestor again.
func compileRouting(filter string, order []Sort, compiler *celCompiler) (*Query, error) {
	query := &Query{OrderBy: append([]Sort{}, order...)}
	if filter != "" {
		query.Filters = []*CELExpression{{Source: filter, kind: "boolean"}}
	}
	if err := query.validate(); err != nil {
		return nil, err
	}
	for i, filter := range query.Filters {
		expression, err := compiler.compile(filter.Source, true)
		if err != nil {
			return nil, err
		}
		query.Filters[i] = expression
	}
	for i := range query.OrderBy {
		criterion := &query.OrderBy[i]
		if _, _, ids := criterion.list(); ids != nil {
			criterion.ranks = make(map[string]int, len(ids))
			for rank, id := range ids {
				criterion.ranks[id] = rank
			}
			continue
		}
		expression, err := compiler.compile(criterion.By, false)
		if err != nil {
			return nil, err
		}
		// A key that is the same for every candidate would order nothing.
		// random() differs per deployment without reading a field.
		switch {
		case expression.random && i != len(query.OrderBy)-1:
			return nil, configError("random() must be the last sort criterion")
		case expression.random && criterion.Direction != "":
			return nil, configError("random() takes no sort direction")
		case !expression.random && compiler.prepare && !expression.candidate:
			return nil, configError("routing.sort expressions must read author, model, deployment, route or provider fields")
		case !expression.random && criterion.Direction == "":
			criterion.Direction = "asc"
		}
		criterion.expression = expression
	}
	return query, nil
}

// ExpressionBytes accounts for the checked programs retained by this source.
// Shared source references are charged once by the owning policy cache.
func (c *Config) ExpressionBytes() int64 {
	seen := map[*CELExpression]bool{}
	var total int64
	c.visitExpressions(func(expression *CELExpression) {
		if expression != nil && !seen[expression] {
			seen[expression] = true
			total += expression.bytes
		}
	})
	return total
}

func (c *Config) visitExpressions(add func(*CELExpression)) {
	if c == nil || c.Routing.Query == nil {
		return
	}
	for _, expression := range c.Routing.Query.Filters {
		add(expression)
	}
	for _, criterion := range c.Routing.Query.OrderBy {
		add(criterion.expression)
	}
}

func (q *Query) validate() error {
	if q == nil {
		return nil
	}
	if len(q.Filters) == 0 && len(q.OrderBy) == 0 {
		return configError("routing requires a filter or sort")
	}
	if len(q.OrderBy) > MaxSorts {
		return configError("use no more than four sort criteria, counting routing.order")
	}
	for _, filter := range q.Filters {
		if filter == nil || strings.TrimSpace(filter.Source) == "" || len(filter.Source) > MaxCELBytes {
			return configError("routing filter is invalid")
		}
	}
	seen := map[string]bool{}
	for i := range q.OrderBy {
		item := &q.OrderBy[i]
		name, _, ids := item.list()
		kinds := 0
		for _, kind := range sortLists {
			if kind.ids(item) != nil {
				kinds++
			}
		}
		if item.By != "" {
			kinds++
		}
		if kinds != 1 {
			return configError(sortKinds)
		}
		if name != "" {
			// Two lists of one kind rank the same field, so one list says
			// the same.
			if seen[name] {
				return configError("use one %s list per policy; list its IDs in order", name)
			}
			seen[name] = true
			if item.Direction != "" {
				return configError("a %s list takes no direction; list the IDs in the order to try", name)
			}
			if err := validateNodeIDs(ids); err != nil {
				return configError("routing.sort %s must list unique catalog IDs", name)
			}
			continue
		}
		if item.Direction != "" && item.Direction != "asc" && item.Direction != "desc" {
			return configError("sort direction must be asc or desc")
		}
		if strings.TrimSpace(item.By) == "" || len(item.By) > MaxCELBytes {
			return configError("routing sort expression size is invalid")
		}
		if seen["by\x00"+strings.TrimSpace(item.By)] {
			return configError("sort expressions must be unique")
		}
		seen["by\x00"+strings.TrimSpace(item.By)] = true
	}
	return nil
}

func (q *Query) Matches(values Values) (bool, error) {
	index, _, err := q.FirstFailure(values)
	return index < 0 && err == nil, err
}

// FirstFailure returns the index of the first filter that removes a candidate,
// or -1, and whether that filter read only available fields.
func (q *Query) FirstFailure(values Values) (index int, known bool, err error) {
	if q == nil {
		return -1, true, nil
	}
	for i, filter := range q.Filters {
		known, matches, _, err := filter.Evaluate(values, policyTime(values))
		if err != nil {
			return i, true, fmt.Errorf("routing filter evaluation failed: %w", err)
		}
		if !known || !matches {
			return i, known, nil
		}
	}
	return -1, true, nil
}

// Sort returns indexes in order and, for each position after the first,
// whether that candidate ties the one before it on every criterion. Missing
// values and unlisted IDs sort last in either direction, and tied candidates
// keep their input order. Evaluation errors reject the whole ordering.
//
// random(weight) draws one key per deployment, Exp(1) / weight, and sorts it
// ascending (Efraimidis and Spirakis). Each deployment then comes first with
// probability weight / total weight, and the rest follow as weighted sampling
// without replacement. A weight below 1 counts as missing. Each random()
// criterion draws on its own.
func (q *Query) Sort(candidates []Values) ([]int, []bool, error) {
	order := make([]int, len(candidates))
	for i := range order {
		order[i] = i
	}
	ties := make([]bool, len(candidates))
	if q == nil || len(q.OrderBy) == 0 {
		for i := 1; i < len(ties); i++ {
			ties[i] = true
		}
		return order, ties, nil
	}
	type item struct {
		value   Value
		number  float64
		present bool
	}
	type drawKey struct {
		criterion  int
		deployment string
	}
	keys := make([][]item, len(candidates))
	draws := map[drawKey]float64{}
	for i, candidate := range candidates {
		keys[i] = make([]item, len(q.OrderBy))
		for j := range q.OrderBy {
			criterion := &q.OrderBy[j]
			if criterion.ranks != nil {
				_, field, _ := criterion.list()
				id, present := candidate.PolicyValue(field)
				if rank, listed := criterion.ranks[id.String]; present && listed {
					keys[i][j] = item{number: float64(rank), present: true}
				}
				continue
			}
			if criterion.expression == nil {
				return nil, nil, configError("routing sort has not been compiled")
			}
			result, _, err := criterion.expression.evaluate(candidate, policyTime(candidate))
			if err != nil {
				return nil, nil, fmt.Errorf("routing sort evaluation failed: %w", err)
			}
			if types.IsUnknown(result) {
				continue
			}
			if criterion.expression.random {
				weight, ok := result.(types.Int)
				if !ok {
					return nil, nil, configError("routing sort returned an invalid value")
				}
				id, present := candidate.PolicyValue("deployment.id")
				if weight < 1 || !present {
					continue
				}
				key := drawKey{j, id.String}
				draw, drawn := draws[key]
				if !drawn {
					draw = rand.ExpFloat64()
					draws[key] = draw
				}
				keys[i][j] = item{number: draw / float64(weight), present: true}
				continue
			}
			value := Value{Type: criterion.expression.kind}
			switch result := result.(type) {
			case types.Bool:
				value.Boolean = bool(result)
			case types.Int:
				value.Integer = big.NewInt(int64(result))
			case types.String:
				value.String = string(result)
			case celDecimal:
				value.Decimal = result.Decimal
			default:
				return nil, nil, configError("routing sort returned an invalid value")
			}
			keys[i][j] = item{value: value, present: true}
		}
	}
	// compare orders two candidates: negative when a comes first.
	compare := func(a, b int) int {
		left, right := keys[a], keys[b]
		for i := range q.OrderBy {
			criterion := &q.OrderBy[i]
			if left[i].present != right[i].present {
				if left[i].present {
					return -1
				}
				return 1
			}
			if !left[i].present {
				continue
			}
			var comparison int
			if criterion.ranks != nil || criterion.expression.random {
				comparison = cmp.Compare(left[i].number, right[i].number)
			} else {
				comparison = compareValues(left[i].value, right[i].value)
			}
			if comparison == 0 {
				continue
			}
			if criterion.Direction == "desc" {
				return -comparison
			}
			return comparison
		}
		return 0
	}
	sort.SliceStable(order, func(a, b int) bool { return compare(order[a], order[b]) < 0 })
	for i := 1; i < len(order); i++ {
		ties[i] = compare(order[i-1], order[i]) == 0
	}
	return order, ties, nil
}

func policyTime(values Values) time.Time {
	if timed, ok := values.(interface{ PolicyTime() time.Time }); ok {
		return timed.PolicyTime()
	}
	return time.Time{}
}
