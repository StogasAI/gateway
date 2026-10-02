package policy

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/interpreter"
)

const (
	MaxCELBytes         = 16 << 10
	MaxCELCost          = 10_000
	MaxRequestCELCost   = 100_000
	MaxSourceCELNodes   = 4_096
	MaxCombinedCELNodes = 2 * MaxSourceCELNodes
)

var ErrPolicyWorkLimit = errors.New("policy evaluation exceeded the work limit")

// CELBudget belongs to one request, including its candidate filters and sorts.
// Programs have a separate per-expression stop, so one evaluation can exceed
// the remaining shared allowance only by that bounded amount.
type CELBudget struct{ remaining uint64 }

func NewCELBudget() *CELBudget { return &CELBudget{remaining: MaxRequestCELCost} }

// CELExpression is immutable and can be evaluated concurrently. Source remains
// the reviewable representation; programs live only in the gateway's cache.
type CELExpression struct {
	Source     string
	normalized string
	program    cel.Program
	kind       string
	bytes      int64
}

var celEnvironment = sync.OnceValues(newCELEnvironment)

type celCompiler struct {
	prepare     bool
	nodes       int
	expressions map[string]*CELExpression
}

func CompileCEL(source string) (*CELExpression, error) {
	return compileCEL(source, true)
}

func compileCEL(source string, condition bool) (*CELExpression, error) {
	return (&celCompiler{prepare: true}).compile(source, condition)
}

func (c *celCompiler) compile(source string, condition bool) (*CELExpression, error) {
	if len(source) == 0 || len(source) > MaxCELBytes {
		return nil, configError("CEL expression must contain 1–%d bytes", MaxCELBytes)
	}
	if expression := c.expressions[source]; expression != nil {
		if c.prepare && condition && expression.kind != "boolean" {
			return nil, configError("CEL condition must return a boolean")
		}
		return expression, nil
	}
	environment, err := celEnvironment()
	if err != nil {
		return nil, err
	}
	parsed, issues := environment.Parse(source)
	if issues.Err() != nil {
		return nil, configError("invalid CEL expression: %v", issues.Err())
	}
	nodes := 0
	ast.PostOrderVisit(parsed.NativeRep().Expr(), ast.NewExprVisitor(func(ast.Expr) { nodes++ }))
	if c.nodes+nodes > MaxSourceCELNodes {
		return nil, configError("source policy exceeds the %d-node CEL compilation limit", MaxSourceCELNodes)
	}
	c.nodes += nodes
	if c.expressions == nil {
		c.expressions = make(map[string]*CELExpression)
	}
	if !c.prepare {
		// Stored policies need their AST identity and size for preview, but
		// do not need checked execution programs rebuilt on every detail read.
		normalized, err := cel.AstToString(parsed)
		if err != nil {
			return nil, configError("cannot normalize CEL expression: %v", err)
		}
		expression := &CELExpression{Source: source, normalized: normalized}
		c.expressions[source] = expression
		return expression, nil
	}
	checked, issues := environment.Check(parsed)
	if issues.Err() != nil {
		return nil, configError("invalid CEL expression: %v", issues.Err())
	}
	if condition && !checked.OutputType().IsExactType(cel.BoolType) {
		return nil, configError("CEL condition must return a boolean")
	}
	kind := ""
	for name, valueType := range map[string]*cel.Type{"boolean": cel.BoolType, "integer": cel.IntType, "string": cel.StringType, "decimal": decimalCELType} {
		if checked.OutputType().IsExactType(valueType) {
			kind = name
		}
	}
	if kind == "" {
		return nil, configError("CEL sort expression must return a boolean, integer, string, or exact decimal")
	}
	var validationErr error
	ast.PostOrderVisit(checked.NativeRep().Expr(), ast.NewExprVisitor(func(expression ast.Expr) {
		if validationErr != nil {
			return
		}
		if expression.Kind() == ast.SelectKind {
			selection := expression.AsSelect()
			parent := checked.NativeRep().GetType(selection.Operand().ID())
			if parent.IsExactType(cel.DynType) {
				validationErr = configError("conditional settings require typed field access")
			}
		}
		if expression.Kind() != ast.CallKind {
			return
		}
		call := expression.AsCall()
		args := call.Args()
		switch call.FunctionName() {
		case "decimal":
			if len(args) != 1 || args[0].Kind() != ast.LiteralKind {
				validationErr = configError("decimal requires a quoted constant")
				return
			}
			text, ok := args[0].AsLiteral().(types.String)
			if _, valid := DecimalValue(string(text)); !ok || !valid {
				validationErr = configError("invalid exact decimal")
			}
		case "blended_price":
			const count = 3
			if len(args) < count {
				validationErr = configError("invalid price expression")
				return
			}
			for _, arg := range args[:count] {
				if arg.Kind() != ast.LiteralKind {
					validationErr = configError("price weights and rate must be constants")
					return
				}
			}
			rate, ok := args[count-1].AsLiteral().(types.String)
			if !ok || !tokenPricingRates[string(rate)] {
				validationErr = configError("unknown token pricing rate")
				return
			}
			a, aOK := args[0].AsLiteral().(types.Int)
			b, bOK := args[1].AsLiteral().(types.Int)
			if !aOK || !bOK || a < 0 || b < 0 || a > types.Int(maxPriceWeight) || b > types.Int(maxPriceWeight) || a+b == 0 {
				validationErr = configError("price weights must be nonnegative safe integers with a positive total")
			}
		}
	}))
	if validationErr != nil {
		return nil, validationErr
	}
	program, err := environment.Program(checked, cel.EvalOptions(cel.OptOptimize, cel.OptPartialEval), cel.CostLimit(MaxCELCost))
	if err != nil {
		return nil, configError("invalid CEL program: %v", err)
	}
	// Account for the retained checked program separately from the source text.
	// Each node may retain its checked type, attributes, and evaluation wrapper.
	normalized, err := cel.AstToString(checked)
	if err != nil {
		return nil, configError("cannot normalize CEL expression: %v", err)
	}
	expression := &CELExpression{Source: source, normalized: normalized, program: program, kind: kind, bytes: int64(nodes*384 + 512)}
	c.expressions[source] = expression
	return expression, nil
}

// Evaluate preserves CEL's unknown value during early catalog filtering. A
// complete evaluation must be true to permit a request; unknown never means yes.
func (e *CELExpression) Evaluate(values Values, now time.Time) (known, matches bool, cost uint64, err error) {
	result, cost, err := e.evaluate(values, now)
	if err != nil {
		return false, false, cost, err
	}
	if types.IsUnknown(result) {
		return false, false, cost, nil
	}
	matched, ok := result.(types.Bool)
	if !ok {
		return false, false, cost, configError("CEL condition did not return a boolean")
	}
	return true, bool(matched), cost, nil
}

func (e *CELExpression) evaluate(values Values, now time.Time) (ref.Val, uint64, error) {
	if e == nil || e.program == nil {
		return nil, 0, configError("expression has not been compiled")
	}
	var budget *CELBudget
	if bounded, ok := values.(interface{ PolicyCELBudget() *CELBudget }); ok {
		budget = bounded.PolicyCELBudget()
	}
	if budget != nil && budget.remaining == 0 {
		return nil, 0, ErrPolicyWorkLimit
	}
	result, details, err := e.program.Eval(celPolicyActivation{values: values, now: now})
	var cost uint64
	if details != nil && details.ActualCost() != nil {
		cost = *details.ActualCost()
	}
	// Constant expressions still consume one evaluation in the request budget.
	cost = max(cost, 1)
	if budget != nil {
		if cost > budget.remaining {
			budget.remaining = 0
			return nil, cost, ErrPolicyWorkLimit
		}
		budget.remaining -= cost
	}
	var cancelled interpreter.EvalCancelledError
	if errors.As(err, &cancelled) && cancelled.Cause == interpreter.CostLimitExceeded {
		return nil, cost, ErrPolicyWorkLimit
	}
	return result, cost, err
}

func newCELEnvironment() (*cel.Env, error) {
	provider := newCELFieldProvider()
	options := []cel.EnvOption{
		cel.CustomTypeProvider(provider),
		cel.EnableMacroCallTracking(),
		cel.ParserExpressionSizeLimit(MaxCELBytes),
		cel.ParserRecursionLimit(64),
		cel.ASTValidators(cel.ValidateComprehensionNestingLimit(2), cel.ValidateRegexProgramSizeLimit(4096)),
		cel.HomogeneousAggregateLiterals(),
		cel.Function("decimal", cel.Overload("policy_decimal_string", []*cel.Type{cel.StringType}, decimalCELType,
			cel.UnaryBinding(func(value ref.Val) ref.Val {
				decimal, ok := DecimalValue(string(value.(types.String)))
				if !ok {
					return types.NewErr("invalid exact decimal")
				}
				return celDecimal{decimal.Decimal}
			}))),
	}
	for _, name := range []string{"author", "model", "deployment", "route", "provider", "request"} {
		options = append(options, cel.Variable(name, cel.ObjectType(celNodeTypeName(name))))
	}
	for _, operator := range []string{operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals} {
		options = append(options, cel.Function(operator, cel.Overload("policy_decimal"+operator,
			[]*cel.Type{decimalCELType, decimalCELType}, cel.BoolType)))
	}
	deploymentType := cel.ObjectType(celNodeTypeName("deployment"))
	options = append(options,
		cel.Macros(cel.GlobalMacro("blended_price", 3, func(factory cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *cel.Error) {
			return factory.NewMemberCall("blended_price", factory.NewIdent("deployment"), args...), nil
		})),
		cel.Function("blended_price", cel.MemberOverload("policy_blended_price",
			[]*cel.Type{deploymentType, cel.IntType, cel.IntType, cel.StringType}, decimalCELType,
			cel.FunctionBinding(func(args ...ref.Val) ref.Val {
				a, b := int64(args[1].(types.Int)), int64(args[2].(types.Int))
				divisor := priceWeightGCD(a, b)
				if a < 0 || b < 0 || a > maxPriceWeight || b > maxPriceWeight || divisor == 0 {
					return types.NewErr("invalid price weights")
				}
				blend := &BlendedPrice{InputWeight: a / divisor, OutputWeight: b / divisor, Rate: string(args[3].(types.String))}
				value, ok := blendedPriceValue(blend, args[0].(*celPolicyNode).values)
				return celPolicyValue(value, ok, "blended_price")
			}))),
	)
	return cel.NewEnv(options...)
}

var decimalCELType = types.NewObjectType("stogas.policy.Decimal", traits.ComparerType)

type celDecimal struct{ *Decimal }

func (d celDecimal) Type() ref.Type { return decimalCELType }
func (d celDecimal) Value() any     { return d.Decimal }
func (d celDecimal) ConvertToNative(target reflect.Type) (any, error) {
	if target == reflect.TypeFor[*Decimal]() {
		return d.Decimal, nil
	}
	return nil, fmt.Errorf("exact decimal cannot convert to %v", target)
}
func (d celDecimal) ConvertToType(target ref.Type) ref.Val {
	if target == types.TypeType {
		return decimalCELType
	}
	if target == decimalCELType {
		return d
	}
	return types.NewErr("exact decimal cannot convert to %s", target.TypeName())
}
func (d celDecimal) Equal(other ref.Val) ref.Val {
	value, ok := other.(celDecimal)
	if !ok {
		return types.MaybeNoSuchOverloadErr(other)
	}
	return types.Bool(d.Cmp(value.Decimal) == 0)
}
func (d celDecimal) Compare(other ref.Val) ref.Val {
	value, ok := other.(celDecimal)
	if !ok {
		return types.MaybeNoSuchOverloadErr(other)
	}
	return types.Int(d.Cmp(value.Decimal))
}

type celFieldProvider struct {
	types.Provider
	fields map[string]map[string]*cel.Type
}

func newCELFieldProvider() *celFieldProvider {
	registry, _ := types.NewRegistry()
	provider := &celFieldProvider{Provider: registry, fields: map[string]map[string]*cel.Type{}}
	paths := FieldPaths()
	for meter := range tokenPricingMeters {
		for rate := range tokenPricingRates {
			paths = append(paths, "deployment.pricing."+meter+"."+rate)
		}
	}
	for _, path := range paths {
		kind, _ := FieldType(path)
		valueType := map[string]*cel.Type{"boolean": cel.BoolType, "integer": cel.IntType, "decimal": decimalCELType, "string": cel.StringType, "string_list": cel.ListType(cel.StringType), "timestamp": cel.TimestampType}[kind]
		parts := strings.Split(path, ".")
		for i := 1; i < len(parts); i++ {
			parent := celNodeTypeName(strings.Join(parts[:i], "."))
			if provider.fields[parent] == nil {
				provider.fields[parent] = map[string]*cel.Type{}
			}
			fieldType := valueType
			if i < len(parts)-1 {
				fieldType = cel.ObjectType(celNodeTypeName(strings.Join(parts[:i+1], ".")))
			}
			provider.fields[parent][parts[i]] = fieldType
		}
	}
	return provider
}

func celNodeTypeName(path string) string { return "stogas.policy." + path }
func (p *celFieldProvider) FindStructType(name string) (*types.Type, bool) {
	if _, ok := p.fields[name]; ok {
		return types.NewTypeTypeWithParam(cel.ObjectType(name)), true
	}
	return p.Provider.FindStructType(name)
}
func (p *celFieldProvider) FindStructFieldNames(name string) ([]string, bool) {
	fields, ok := p.fields[name]
	if !ok {
		return p.Provider.FindStructFieldNames(name)
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	return names, true
}
func (p *celFieldProvider) FindStructFieldType(name, field string) (*types.FieldType, bool) {
	fieldType, ok := p.fields[name][field]
	if !ok {
		return p.Provider.FindStructFieldType(name, field)
	}
	path := strings.TrimPrefix(name, "stogas.policy.") + "." + field
	_, nested := p.fields[fieldType.TypeName()]
	return &types.FieldType{Type: fieldType,
		IsSet: func(target any) bool {
			if nested || path == "request.time" {
				return true
			}
			_, ok := target.(*celPolicyNode).values.PolicyValue(path)
			return ok
		},
		GetFrom: func(target any) (any, error) {
			node := target.(*celPolicyNode)
			if nested {
				return &celPolicyNode{path: path, values: node.values, now: node.now}, nil
			}
			if path == "request.time" {
				return types.Timestamp{Time: node.now}, nil
			}
			value, exists := node.values.PolicyValue(path)
			return celPolicyValue(value, exists, path), nil
		},
	}, true
}

type celPolicyNode struct {
	path   string
	values Values
	now    time.Time
}

func (n *celPolicyNode) Type() ref.Type { return cel.ObjectType(celNodeTypeName(n.path)) }
func (n *celPolicyNode) Value() any     { return n }
func (n *celPolicyNode) ConvertToNative(target reflect.Type) (any, error) {
	if target == reflect.TypeFor[*celPolicyNode]() {
		return n, nil
	}
	return nil, fmt.Errorf("policy object cannot convert to %v", target)
}
func (n *celPolicyNode) ConvertToType(target ref.Type) ref.Val {
	if target == types.TypeType {
		return n.Type().(ref.Val)
	}
	return types.NewErr("policy object cannot convert to %s", target.TypeName())
}
func (n *celPolicyNode) Equal(other ref.Val) ref.Val { return types.MaybeNoSuchOverloadErr(other) }

type celPolicyActivation struct {
	values Values
	now    time.Time
}

func (a celPolicyActivation) Parent() interpreter.Activation { return nil }
func (a celPolicyActivation) ResolveName(name string) (any, bool) {
	switch name {
	case "author", "model", "deployment", "route", "provider", "request":
		return &celPolicyNode{path: name, values: a.values, now: a.now}, true
	}
	return nil, false
}

func celPolicyValue(value Value, exists bool, path string) ref.Val {
	if !exists {
		return types.NewUnknown(0, types.NewAttributeTrail(path))
	}
	switch value.Type {
	case "boolean":
		return types.Bool(value.Boolean)
	case "integer":
		if value.Integer != nil && value.Integer.IsInt64() {
			return types.Int(value.Integer.Int64())
		}
	case "decimal":
		if value.Decimal != nil {
			return celDecimal{value.Decimal}
		}
	case "string":
		return types.String(value.String)
	case "string_list":
		return types.NewStringList(types.DefaultTypeAdapter, value.Strings)
	}
	return types.NewErr("invalid policy value for %s", path)
}
