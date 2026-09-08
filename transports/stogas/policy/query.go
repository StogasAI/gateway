package policy

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxSourceQueryRunes  = 4096
	maxSourceExpressions = 64
	maxSourceDepth       = 12
	maxSourceSorts       = 4
)

type queryToken struct {
	kind, value string
	position    int
}
type queryParser struct {
	tokens []queryToken
	index  int
}

// CompileQuery accepts the same bounded source grammar as saved policies.
// It never accepts compiled instructions or arbitrary catalog field names.
func CompileQuery(source string) (*Query, error) {
	if !utf8.ValidString(source) || utf8.RuneCountInString(source) > MaxSourceQueryRunes {
		return nil, configError("routing query must use valid Unicode and at most %d characters", MaxSourceQueryRunes)
	}
	tokens, err := tokenizeQuery(source)
	if err != nil {
		return nil, err
	}
	p := queryParser{tokens: tokens}
	q := &Query{OrderBy: []Sort{}}
	if p.match("where") {
		q.Where, err = p.expression("or", 0)
		if err != nil {
			return nil, err
		}
	}
	if p.match("order") {
		if !p.match("by") {
			return nil, p.error("expected by after order")
		}
		for {
			if len(q.OrderBy) >= maxSourceSorts {
				return nil, p.error("use no more than four sort fields")
			}
			field, err := p.field()
			if err != nil {
				return nil, err
			}
			if field.Type == "string_list" {
				return nil, p.error("list fields cannot be sorted")
			}
			direction := "asc"
			if p.match("desc") {
				direction = "desc"
			} else {
				p.match("asc")
			}
			q.OrderBy = append(q.OrderBy, Sort{Path: field.Path, Type: field.Type, Direction: direction})
			if !p.match(",") {
				break
			}
		}
	}
	if p.index != len(p.tokens) {
		return nil, p.error("unexpected query token")
	}
	if err := q.validate(); err != nil {
		return nil, err
	}
	count, depth := sourceExpressionSize(q.Where)
	if count > maxSourceExpressions || depth > maxSourceDepth {
		return nil, p.error("routing query exceeds expression or nesting limits")
	}
	return q, nil
}

func tokenizeQuery(source string) ([]queryToken, error) {
	runes := []rune(source)
	tokens := make([]queryToken, 0)
	for i := 0; i < len(runes); {
		r := runes[i]
		if (unicode.IsSpace(r) && r != '\u0085') || r == '\ufeff' {
			i++
			continue
		}
		start := i
		if strings.ContainsRune("(),[]", r) {
			tokens = append(tokens, queryToken{kind: string(r), position: start})
			i++
			continue
		}
		if r == '\'' || r == '"' {
			quote := r
			i++
			var value strings.Builder
			closed := false
			for i < len(runes) {
				next := runes[i]
				i++
				if next == quote {
					closed = true
					break
				}
				if next == '\\' {
					if i >= len(runes) || (runes[i] != quote && runes[i] != '\\') {
						return nil, configError("only quotes and backslashes can be escaped at character %d", i)
					}
					next = runes[i]
					i++
				}
				if next <= 0x1f || (next >= 0x7f && next <= 0x9f) {
					return nil, configError("string contains a control character")
				}
				value.WriteRune(next)
			}
			if !closed {
				return nil, configError("close the string at character %d", start+1)
			}
			if value.Len() > 1024 {
				return nil, configError("string values must use at most 1024 bytes")
			}
			tokens = append(tokens, queryToken{kind: "string", value: value.String(), position: start})
			continue
		}
		if strings.ContainsRune("=!<>", r) {
			i++
			if i < len(runes) && runes[i] == '=' {
				i++
			}
			operator := string(runes[start:i])
			if operator == "=" || operator == "!" {
				return nil, configError("invalid comparison operator")
			}
			tokens = append(tokens, queryToken{kind: "operator", value: operator, position: start})
			continue
		}
		if r == '-' || (r >= '0' && r <= '9') {
			if r == '-' {
				i++
			}
			if i >= len(runes) || runes[i] < '0' || runes[i] > '9' {
				return nil, configError("expected an integer")
			}
			if runes[i] == '0' {
				i++
			} else {
				for i < len(runes) && runes[i] >= '0' && runes[i] <= '9' {
					i++
				}
			}
			tokens = append(tokens, queryToken{kind: "integer", value: string(runes[start:i]), position: start})
			continue
		}
		if queryIdentifierStart(r) {
			i++
			for i < len(runes) && (queryIdentifierStart(runes[i]) || runes[i] == '.' || (runes[i] >= '0' && runes[i] <= '9')) {
				i++
			}
			value := string(runes[start:i])
			kind := "identifier"
			switch strings.ToLower(value) {
			case "where", "order", "by", "asc", "desc", "and", "or", "not", "in", "contains", "exists":
				kind = strings.ToLower(value)
			case "true", "false":
				kind = "boolean"
				value = strings.ToLower(value)
			}
			tokens = append(tokens, queryToken{kind: kind, value: value, position: start})
			continue
		}
		return nil, configError("unexpected character at character %d", start+1)
	}
	return tokens, nil
}

func queryIdentifierStart(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func (p *queryParser) expression(kind string, depth int) (*Expression, error) {
	next := func() (*Expression, error) {
		if kind == "or" {
			return p.expression("and", depth)
		}
		return p.primary(depth)
	}
	left, err := next()
	if err != nil {
		return nil, err
	}
	for p.match(kind) {
		right, err := next()
		if err != nil {
			return nil, err
		}
		operands := []*Expression{left}
		if left.Kind == kind {
			operands = append([]*Expression{}, left.Operands...)
		}
		if right.Kind == kind {
			operands = append(operands, right.Operands...)
		} else {
			operands = append(operands, right)
		}
		left = &Expression{Kind: kind, Operands: operands}
	}
	return left, nil
}

func (p *queryParser) primary(depth int) (*Expression, error) {
	if depth > maxSourceDepth {
		return nil, p.error("routing query nesting exceeds the limit")
	}
	if p.match("not") {
		operand, err := p.primary(depth + 1)
		return &Expression{Kind: "not", Operand: operand}, err
	}
	if p.match("(") {
		value, err := p.expression("or", depth+1)
		if err != nil {
			return nil, err
		}
		if !p.match(")") {
			return nil, p.error("close the parenthesis")
		}
		return value, nil
	}
	if p.match("exists") {
		if !p.match("(") {
			return nil, p.error("expected ( after exists")
		}
		field, err := p.field()
		if err != nil {
			return nil, err
		}
		if !p.match(")") {
			return nil, p.error("close exists()")
		}
		return &Expression{Kind: "exists", Path: field.Path}, nil
	}
	field, err := p.field()
	if err != nil {
		return nil, err
	}
	operator := p.peek()
	if operator.kind != "operator" && operator.kind != "in" && operator.kind != "contains" {
		return nil, p.error("expected a comparison operator")
	}
	p.index++
	operatorValue := operator.value
	if operator.kind != "operator" {
		operatorValue = operator.kind
	}
	var right []byte
	if operatorValue == "in" {
		if !p.match("[") {
			return nil, p.error("expected a list after in")
		}
		values := make([]Literal, 0)
		for {
			if len(values) >= MaxListItems {
				return nil, p.error("routing list exceeds the limit")
			}
			value, err := p.literal(field.Type)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
			if !p.match(",") {
				break
			}
		}
		if !p.match("]") {
			return nil, p.error("close the list")
		}
		right, err = json.Marshal(values)
	} else {
		literalType := field.Type
		if literalType == "string_list" {
			literalType = "string"
		}
		value, literalErr := p.literal(literalType)
		if literalErr != nil {
			return nil, literalErr
		}
		right, err = json.Marshal(value)
	}
	if err != nil {
		return nil, err
	}
	return &Expression{Kind: "compare", Left: &field, Operator: operatorValue, Right: right}, nil
}

func (p *queryParser) literal(kind string) (Literal, error) {
	token := p.peek()
	if token.kind != kind {
		return Literal{}, p.error("expected a " + kind + " value")
	}
	p.index++
	var value any = token.value
	if kind == "integer" {
		number, ok := new(big.Int).SetString(token.value, 10)
		if !ok {
			return Literal{}, p.error("invalid integer")
		}
		value = number.String()
	} else if kind == "boolean" {
		value = token.value == "true"
	}
	raw, err := json.Marshal(value)
	return Literal{Type: kind, Value: raw}, err
}

func (p *queryParser) field() (Field, error) {
	token := p.peek()
	if token.kind != "identifier" {
		return Field{}, p.error("expected a catalog or request field")
	}
	p.index++
	kind, ok := FieldType(token.value)
	if !ok {
		return Field{}, p.error("unknown policy field: " + token.value)
	}
	return Field{Path: token.value, Type: kind}, nil
}

func (p *queryParser) peek() queryToken {
	if p.index >= len(p.tokens) {
		return queryToken{position: MaxSourceQueryRunes}
	}
	return p.tokens[p.index]
}
func (p *queryParser) match(kind string) bool {
	if p.peek().kind != kind {
		return false
	}
	p.index++
	return true
}
func (p *queryParser) error(message string) error {
	return fmt.Errorf("%w: %s at character %d", ErrInvalidConfig, message, p.peek().position+1)
}

func sourceExpressionSize(e *Expression) (int, int) {
	if e == nil {
		return 0, 0
	}
	count, depth := 1, 0
	children := e.Operands
	if e.Operand != nil {
		children = []*Expression{e.Operand}
	}
	for _, child := range children {
		n, d := sourceExpressionSize(child)
		count += n
		if d+1 > depth {
			depth = d + 1
		}
	}
	return count, depth
}
