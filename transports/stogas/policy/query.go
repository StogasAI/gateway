package policy

import (
	"encoding/json"
	"fmt"
	"math/big"
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

type Sort struct {
	By         string `json:"by"`
	Direction  string `json:"direction"`
	expression *CELExpression
}

// CompositionBytes estimates this configuration's own retained structures.
// Sources own their strings, programs and plugins; composition borrows them.
func (c *Config) CompositionBytes() int64 {
	if c == nil {
		return 0
	}
	total := int64(unsafe.Sizeof(*c)) + int64(cap(c.sources))*int64(unsafe.Sizeof(ScopedSource{}))
	total += int64(cap(c.PluginSources)+cap(c.ActiveEncryptedPlugins))*8 + int64(cap(c.RequiredEncryptionKeys))*16
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
		expression, err := compiler.compile(query.OrderBy[i].By, false)
		if err != nil {
			return nil, err
		}
		query.OrderBy[i].expression = expression
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
		return configError("use no more than three sort expressions")
	}
	for _, filter := range q.Filters {
		if filter == nil || strings.TrimSpace(filter.Source) == "" || len(filter.Source) > MaxCELBytes {
			return configError("routing filter is invalid")
		}
	}
	seen := map[string]bool{}
	for i := range q.OrderBy {
		item := &q.OrderBy[i]
		if item.Direction != "asc" && item.Direction != "desc" {
			return configError("sort direction must be asc or desc")
		}
		if seen[strings.TrimSpace(item.By)] {
			return configError("sort expressions must be unique")
		}
		seen[strings.TrimSpace(item.By)] = true
		if strings.TrimSpace(item.By) == "" || len(item.By) > MaxCELBytes {
			return configError("routing sort expression size is invalid")
		}
	}
	return nil
}

func (q *Query) Matches(values Values) (bool, error) {
	if q == nil {
		return true, nil
	}
	for _, filter := range q.Filters {
		known, matches, _, err := filter.Evaluate(values, policyTime(values))
		if err != nil {
			return false, fmt.Errorf("routing filter evaluation failed: %w", err)
		}
		if !known || !matches {
			return false, nil
		}
	}
	return true, nil
}

func (q *Query) SameOrder(other *Query) bool {
	if q == nil || other == nil {
		return q == nil && other == nil
	}
	if len(q.OrderBy) != len(other.OrderBy) {
		return false
	}
	for i, order := range q.OrderBy {
		left, right := strings.TrimSpace(order.By), strings.TrimSpace(other.OrderBy[i].By)
		if order.expression != nil && other.OrderBy[i].expression != nil {
			left, right = order.expression.normalized, other.OrderBy[i].expression.normalized
		}
		if left != right || order.Direction != other.OrderBy[i].Direction {
			return false
		}
	}
	return true
}

// Sort returns indexes in order. Missing values sort last in either direction;
// deployment IDs break final ties. Evaluation errors reject the whole ordering.
func (q *Query) Sort(candidates []Values) ([]int, error) {
	order := make([]int, len(candidates))
	type item struct {
		value   Value
		present bool
	}
	keys := make([][]item, len(candidates))
	for i, candidate := range candidates {
		order[i] = i
		if q == nil || len(q.OrderBy) == 0 {
			continue
		}
		keys[i] = make([]item, len(q.OrderBy)+1)
		for j, criterion := range q.OrderBy {
			if criterion.expression == nil {
				return nil, configError("routing sort has not been compiled")
			}
			result, _, err := criterion.expression.evaluate(candidate, policyTime(candidate))
			if err != nil {
				return nil, fmt.Errorf("routing sort evaluation failed: %w", err)
			}
			if types.IsUnknown(result) {
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
				return nil, configError("routing sort returned an invalid value")
			}
			keys[i][j] = item{value: value, present: true}
		}
		id, present := candidate.PolicyValue("deployment.id")
		keys[i][len(q.OrderBy)] = item{value: id, present: present}
	}
	if q == nil || len(q.OrderBy) == 0 {
		return order, nil
	}
	sort.SliceStable(order, func(a, b int) bool {
		left, right := keys[order[a]], keys[order[b]]
		for i := range left {
			if left[i].present != right[i].present {
				return left[i].present
			}
			if !left[i].present {
				continue
			}
			comparison := compareValues(left[i].value, right[i].value)
			if comparison == 0 {
				continue
			}
			if i < len(q.OrderBy) && q.OrderBy[i].Direction == "desc" {
				return comparison > 0
			}
			return comparison < 0
		}
		return false
	})
	return order, nil
}

func policyTime(values Values) time.Time {
	if timed, ok := values.(interface{ PolicyTime() time.Time }); ok {
		return timed.PolicyTime()
	}
	return time.Time{}
}
