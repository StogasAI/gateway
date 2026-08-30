package policy

import (
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func validCompiledConfig() Config {
	return Config{
		CompilerVersion: CompilerVersion,
		Routing: Routing{
			MaxPreDispatchCandidates: 1,
		},
		Schema: "stogas.key-config.compiled.v1",
	}
}

func parseCompiledConfig(t *testing.T, config Config) *Config {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return parsed
}

func stringLiteral(value string) json.RawMessage {
	raw, _ := json.Marshal(Literal{Type: "string", Value: mustRawJSON(value)})
	return raw
}

func integerLiteral(value string) json.RawMessage {
	raw, _ := json.Marshal(Literal{Type: "integer", Value: mustRawJSON(value)})
	return raw
}

func booleanLiteral(value bool) json.RawMessage {
	raw, _ := json.Marshal(Literal{Type: "boolean", Value: mustRawJSON(value)})
	return raw
}

func literalList(values ...Literal) json.RawMessage {
	raw, _ := json.Marshal(values)
	return raw
}

func mustRawJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestParseCompiledConfigIsStrictAndBounded(t *testing.T) {
	valid := validCompiledConfig()
	valid.Routing.AllowedCatalogNodes = &AllowedCatalogNodes{Providers: []string{"provider:openai"}}
	parsed := parseCompiledConfig(t, valid)
	if parsed.Schema != valid.Schema || parsed.CompilerVersion != CompilerVersion {
		t.Fatalf("unexpected parsed config: %#v", parsed)
	}

	validRaw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	invalid := map[string][]byte{
		"empty":                   nil,
		"null":                    []byte(`null`),
		"trailing JSON":           append(append([]byte(nil), validRaw...), []byte(` {}`)...),
		"unknown root field":      []byte(`{"schema":"stogas.key-config.compiled.v1","compilerVersion":1,"access":null,"plugins":null,"routing":{"allowedCatalogNodes":null,"maxPreDispatchCandidates":1,"query":null},"unknown":true}`),
		"unknown routing field":   []byte(`{"schema":"stogas.key-config.compiled.v1","compilerVersion":1,"access":null,"plugins":null,"routing":{"allowedCatalogNodes":null,"maxPreDispatchCandidates":1,"query":null,"unknown":true}}`),
		"unsupported schema":      []byte(`{"schema":"attacker.v1","compilerVersion":1,"access":null,"plugins":null,"routing":{"allowedCatalogNodes":null,"maxPreDispatchCandidates":1,"query":null}}`),
		"unsupported compiler":    []byte(`{"schema":"stogas.key-config.compiled.v1","compilerVersion":2,"access":null,"plugins":null,"routing":{"allowedCatalogNodes":null,"maxPreDispatchCandidates":1,"query":null}}`),
		"missing required fields": []byte(`{}`),
		"oversized":               []byte(strings.Repeat(" ", MaxCompiledBytes+1)),
	}
	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Parse() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestCompiledConfigValidationClosesEveryPolicyShape(t *testing.T) {
	tooManyIDs := make([]string, MaxAllowedCatalogNodes+1)
	for index := range tooManyIDs {
		tooManyIDs[index] = "provider-" + big.NewInt(int64(index)).String()
	}
	stableSort := Sort{Direction: "asc", Path: "deployment.id", Type: "string"}
	validCompare := &Expression{
		Kind:     "compare",
		Left:     &Field{Path: "provider.id", Type: "string"},
		Operator: "==",
		Right:    stringLiteral("openai"),
	}
	invalid := map[string]func(*Config){
		"zero candidates":        func(config *Config) { config.Routing.MaxPreDispatchCandidates = 0 },
		"too many candidates":    func(config *Config) { config.Routing.MaxPreDispatchCandidates = MaxPreDispatchCandidates + 1 },
		"empty node restriction": func(config *Config) { config.Routing.AllowedCatalogNodes = &AllowedCatalogNodes{} },
		"invalid node ID": func(config *Config) {
			config.Routing.AllowedCatalogNodes = &AllowedCatalogNodes{Providers: []string{"OpenAI"}}
		},
		"duplicate node ID": func(config *Config) {
			config.Routing.AllowedCatalogNodes = &AllowedCatalogNodes{Providers: []string{"openai", "openai"}}
		},
		"too many node IDs": func(config *Config) { config.Routing.AllowedCatalogNodes = &AllowedCatalogNodes{Providers: tooManyIDs} },
		"empty query":       func(config *Config) { config.Routing.Query = &Query{} },
		"missing stable sort": func(config *Config) {
			config.Routing.Query = &Query{OrderBy: []Sort{{Direction: "asc", Path: "provider.id", Type: "string"}}}
		},
		"stable sort is not final": func(config *Config) {
			config.Routing.Query = &Query{OrderBy: []Sort{
				stableSort,
				{Direction: "asc", Path: "provider.id", Type: "string"},
			}}
		},
		"stable sort is descending": func(config *Config) {
			config.Routing.Query = &Query{OrderBy: []Sort{{Direction: "desc", Path: "deployment.id", Type: "string"}}}
		},
		"unknown sort field": func(config *Config) {
			config.Routing.Query = &Query{OrderBy: []Sort{{Direction: "asc", Path: "provider.unknown", Type: "string"}, stableSort}}
		},
		"wrong sort type": func(config *Config) {
			config.Routing.Query = &Query{OrderBy: []Sort{{Direction: "asc", Path: "provider.id", Type: "integer"}, stableSort}}
		},
		"list sort": func(config *Config) {
			config.Routing.Query = &Query{OrderBy: []Sort{{Direction: "asc", Path: "provider.data.aliases", Type: "string_list"}, stableSort}}
		},
		"invalid sort direction": func(config *Config) {
			config.Routing.Query = &Query{OrderBy: []Sort{{Direction: "sideways", Path: "provider.id", Type: "string"}, stableSort}}
		},
		"duplicate sort": func(config *Config) { config.Routing.Query = &Query{OrderBy: []Sort{stableSort, stableSort}} },
		"too many sorts": func(config *Config) {
			config.Routing.Query = &Query{OrderBy: []Sort{
				{Direction: "asc", Path: "provider.id", Type: "string"},
				{Direction: "asc", Path: "model.id", Type: "string"},
				{Direction: "asc", Path: "route.id", Type: "string"},
				{Direction: "asc", Path: "author.id", Type: "string"},
				{Direction: "asc", Path: "request.model", Type: "string"},
				stableSort,
			}}
		},
		"noncanonical fifth sort": func(config *Config) {
			config.Routing.Query = &Query{OrderBy: []Sort{
				stableSort,
				{Direction: "asc", Path: "provider.id", Type: "string"},
				{Direction: "asc", Path: "model.id", Type: "string"},
				{Direction: "asc", Path: "route.id", Type: "string"},
				{Direction: "asc", Path: "author.id", Type: "string"},
			}}
		},
		"unknown expression": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "execute"}, OrderBy: []Sort{stableSort}}
		},
		"malformed exists": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "exists", Path: "provider.id", Operator: "=="}, OrderBy: []Sort{stableSort}}
		},
		"malformed not": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "not"}, OrderBy: []Sort{stableSort}}
		},
		"malformed logical": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "and", Operands: []*Expression{validCompare}}, OrderBy: []Sort{stableSort}}
		},
		"nil logical operand": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "or", Operands: []*Expression{validCompare, nil}}, OrderBy: []Sort{stableSort}}
		},
		"unknown comparison field": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "provider.unknown", Type: "string"}, Operator: "==", Right: stringLiteral("x")}, OrderBy: []Sort{stableSort}}
		},
		"wrong comparison type": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "provider.id", Type: "integer"}, Operator: "==", Right: integerLiteral("1")}, OrderBy: []Sort{stableSort}}
		},
		"invalid comparison operator": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "provider.id", Type: "string"}, Operator: "matches", Right: stringLiteral("x")}, OrderBy: []Sort{stableSort}}
		},
		"list comparison operator": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "provider.data.aliases", Type: "string_list"}, Operator: "==", Right: stringLiteral("x")}, OrderBy: []Sort{stableSort}}
		},
		"boolean ordering": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "deployment.data.capabilities.streaming", Type: "boolean"}, Operator: ">", Right: booleanLiteral(true)}, OrderBy: []Sort{stableSort}}
		},
		"integer contains": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "request.estimatedInputTokens", Type: "integer"}, Operator: "contains", Right: integerLiteral("1")}, OrderBy: []Sort{stableSort}}
		},
		"list in": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "provider.data.aliases", Type: "string_list"}, Operator: "in", Right: literalList(Literal{Type: "string", Value: mustRawJSON("x")})}, OrderBy: []Sort{stableSort}}
		},
		"empty in list": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "provider.id", Type: "string"}, Operator: "in", Right: literalList()}, OrderBy: []Sort{stableSort}}
		},
		"duplicate in list": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "provider.id", Type: "string"}, Operator: "in", Right: literalList(Literal{Type: "string", Value: mustRawJSON("x")}, Literal{Type: "string", Value: mustRawJSON("x")})}, OrderBy: []Sort{stableSort}}
		},
		"noncanonical integer": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "request.estimatedInputTokens", Type: "integer"}, Operator: "==", Right: integerLiteral("01")}, OrderBy: []Sort{stableSort}}
		},
		"wrong literal type": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "provider.id", Type: "string"}, Operator: "==", Right: integerLiteral("1")}, OrderBy: []Sort{stableSort}}
		},
		"oversized string literal": func(config *Config) {
			config.Routing.Query = &Query{Where: &Expression{Kind: "compare", Left: &Field{Path: "provider.id", Type: "string"}, Operator: "==", Right: stringLiteral(strings.Repeat("x", 1025))}, OrderBy: []Sort{stableSort}}
		},
		"empty deny windows": func(config *Config) { config.Access = &Access{} },
		"invalid deny day": func(config *Config) {
			config.Access = &Access{Deny: []DenyWindow{{Days: []string{"monday"}, Start: "00:00", End: "01:00", TimeZone: "UTC"}}}
		},
		"duplicate deny day": func(config *Config) {
			config.Access = &Access{Deny: []DenyWindow{{Days: []string{"mon", "mon"}, Start: "00:00", End: "01:00", TimeZone: "UTC"}}}
		},
		"overnight deny window": func(config *Config) {
			config.Access = &Access{Deny: []DenyWindow{{Days: []string{"mon"}, Start: "23:00", End: "01:00", TimeZone: "UTC"}}}
		},
		"unknown time zone": func(config *Config) {
			config.Access = &Access{Deny: []DenyWindow{{Days: []string{"mon"}, Start: "00:00", End: "01:00", TimeZone: "Mars/Base"}}}
		},
		"too many deny windows": func(config *Config) {
			config.Access = &Access{Deny: make([]DenyWindow, MaxDenyWindows+1)}
		},
		"empty plugins": func(config *Config) {
			config.Plugins = &Plugins{}
		},
		"empty PII plugin": func(config *Config) {
			config.Plugins = &Plugins{StogasPIIRedaction: &PIIRedaction{}}
		},
		"unknown PII pattern": func(config *Config) {
			config.Plugins = &Plugins{StogasPIIRedaction: &PIIRedaction{Patterns: []string{"unknown"}}}
		},
		"mandatory PII pattern cannot be configured again": func(config *Config) {
			config.Plugins = &Plugins{StogasPIIRedaction: &PIIRedaction{Patterns: []string{"email_address"}}}
		},
		"duplicate PII pattern": func(config *Config) {
			config.Plugins = &Plugins{StogasPIIRedaction: &PIIRedaction{Patterns: []string{"ip_address", "ip_address"}}}
		},
		"empty custom PII pattern": func(config *Config) {
			config.Plugins = &Plugins{StogasPIIRedaction: &PIIRedaction{CustomPatterns: []string{""}}}
		},
		"duplicate custom PII pattern": func(config *Config) {
			config.Plugins = &Plugins{StogasPIIRedaction: &PIIRedaction{CustomPatterns: []string{"x", "x"}}}
		},
		"oversized custom PII pattern": func(config *Config) {
			config.Plugins = &Plugins{StogasPIIRedaction: &PIIRedaction{CustomPatterns: []string{strings.Repeat("x", MaxCustomPatternBytes+1)}}}
		},
		"too many custom PII patterns": func(config *Config) {
			patterns := make([]string, MaxCustomPatterns+1)
			for index := range patterns {
				patterns[index] = "pattern-" + big.NewInt(int64(index)).String()
			}
			config.Plugins = &Plugins{StogasPIIRedaction: &PIIRedaction{CustomPatterns: patterns}}
		},
		"combined custom PII pattern bytes": func(config *Config) {
			patterns := make([]string, 9)
			for index := range patterns {
				patterns[index] = strings.Repeat("x", MaxCustomPatternBytes-1) + big.NewInt(int64(index)).String()
			}
			config.Plugins = &Plugins{StogasPIIRedaction: &PIIRedaction{CustomPatterns: patterns}}
		},
	}

	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			config := validCompiledConfig()
			mutate(&config)
			if err := config.validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("validate() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestCompiledConfigBoundsExpressionCountAndDepth(t *testing.T) {
	stableSort := []Sort{{Direction: "asc", Path: "deployment.id", Type: "string"}}
	leaf := func(index int) *Expression {
		return &Expression{
			Kind:     "compare",
			Left:     &Field{Path: "request.estimatedInputTokens", Type: "integer"},
			Operator: ">=",
			Right:    integerLiteral(big.NewInt(int64(index)).String()),
		}
	}
	for _, test := range []struct {
		name    string
		where   func() *Expression
		wantErr bool
	}{
		{
			name: "expression boundary",
			where: func() *Expression {
				operands := make([]*Expression, MaxExpressions-1)
				for index := range operands {
					operands[index] = leaf(index)
				}
				return &Expression{Kind: "and", Operands: operands}
			},
		},
		{
			name: "expression overflow",
			where: func() *Expression {
				operands := make([]*Expression, MaxExpressions)
				for index := range operands {
					operands[index] = leaf(index)
				}
				return &Expression{Kind: "and", Operands: operands}
			},
			wantErr: true,
		},
		{
			name: "depth boundary",
			where: func() *Expression {
				expression := leaf(0)
				for range MaxDepth {
					expression = &Expression{Kind: "not", Operand: expression}
				}
				return expression
			},
		},
		{
			name: "depth overflow",
			where: func() *Expression {
				expression := leaf(0)
				for range MaxDepth + 1 {
					expression = &Expression{Kind: "not", Operand: expression}
				}
				return expression
			},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validCompiledConfig()
			config.Routing.Query = &Query{OrderBy: stableSort, Where: test.where()}
			err := config.validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("validate() error = %v, wantErr = %t", err, test.wantErr)
			}
		})
	}
}

type testValues map[string]Value

func (v testValues) PolicyValue(path string) (Value, bool) {
	value, ok := v[path]
	return value, ok
}

func TestPolicyEvaluationUsesClosedTypesAndThreeValuedMissingData(t *testing.T) {
	values := testValues{
		"deployment.data.aliases":                {Type: "string_list", Strings: []string{"stable", "fast"}},
		"deployment.data.capabilities.streaming": {Type: "boolean", Boolean: true},
		"deployment.data.maxOutputTokens":        {Type: "integer", Integer: big.NewInt(128_000)},
		"provider.id":                            {Type: "string", String: "openai"},
	}
	compare := func(path, fieldType, operator string, right json.RawMessage) *Expression {
		return &Expression{Kind: "compare", Left: &Field{Path: path, Type: fieldType}, Operator: operator, Right: right}
	}
	missing := compare(
		"deployment.data.dataHandling.teeVerified",
		"string",
		"!=",
		stringLiteral("none"),
	)
	tests := []struct {
		name  string
		where *Expression
		want  bool
	}{
		{name: "string equality", where: compare("provider.id", "string", "==", stringLiteral("openai")), want: true},
		{name: "string substring", where: compare("provider.id", "string", "contains", stringLiteral("pen")), want: true},
		{name: "list exact membership", where: compare("deployment.data.aliases", "string_list", "contains", stringLiteral("fast")), want: true},
		{name: "integer ordering", where: compare("deployment.data.maxOutputTokens", "integer", ">", integerLiteral("127999")), want: true},
		{name: "boolean equality", where: compare("deployment.data.capabilities.streaming", "boolean", "==", booleanLiteral(true)), want: true},
		{name: "scalar in list", where: compare("provider.id", "string", "in", literalList(Literal{Type: "string", Value: mustRawJSON("azure")}, Literal{Type: "string", Value: mustRawJSON("openai")})), want: true},
		{name: "missing comparison is not true", where: missing},
		{name: "not missing remains unknown", where: &Expression{Kind: "not", Operand: missing}},
		{name: "exists missing", where: &Expression{Kind: "exists", Path: "deployment.data.dataHandling.teeVerified"}},
		{name: "exists present", where: &Expression{Kind: "exists", Path: "provider.id"}, want: true},
		{name: "true or missing", where: &Expression{Kind: "or", Operands: []*Expression{compare("provider.id", "string", "==", stringLiteral("openai")), missing}}, want: true},
		{name: "false and missing", where: &Expression{Kind: "and", Operands: []*Expression{compare("provider.id", "string", "==", stringLiteral("azure")), missing}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := &Query{Where: test.where}
			if got := query.Matches(values); got != test.want {
				t.Fatalf("Matches() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestPolicyOrderingIsStableAndAlwaysPlacesMissingValuesLast(t *testing.T) {
	query := &Query{OrderBy: []Sort{
		{Direction: "desc", Path: "deployment.data.maxOutputTokens", Type: "integer"},
		{Direction: "asc", Path: "deployment.id", Type: "string"},
	}}
	large := testValues{
		"deployment.data.maxOutputTokens": {Type: "integer", Integer: big.NewInt(128_000)},
		"deployment.id":                   {Type: "string", String: "b"},
	}
	small := testValues{
		"deployment.data.maxOutputTokens": {Type: "integer", Integer: big.NewInt(64_000)},
		"deployment.id":                   {Type: "string", String: "a"},
	}
	missing := testValues{"deployment.id": {Type: "string", String: "z"}}
	if !query.Less(large, small) || query.Less(small, large) {
		t.Fatal("descending integer sort is not antisymmetric")
	}
	if !query.Less(large, missing) || query.Less(missing, large) {
		t.Fatal("missing values did not sort last")
	}
	tiedA := testValues{
		"deployment.data.maxOutputTokens": {Type: "integer", Integer: big.NewInt(128_000)},
		"deployment.id":                   {Type: "string", String: "a"},
	}
	if !query.Less(tiedA, large) || query.Less(large, tiedA) {
		t.Fatal("stable deployment ID tie-break is not deterministic")
	}
}

func TestDenyWindowsAreTimeZoneAwareAndHalfOpen(t *testing.T) {
	config := validCompiledConfig()
	config.Access = &Access{Deny: []DenyWindow{{
		Days:     []string{"mon"},
		Start:    "09:00",
		End:      "10:00",
		TimeZone: "America/New_York",
	}}}
	parsed := parseCompiledConfig(t, config)
	for _, test := range []struct {
		at   string
		want bool
	}{
		{at: "2026-06-01T12:59:59Z"},
		{at: "2026-06-01T13:00:00Z", want: true},
		{at: "2026-06-01T13:59:59Z", want: true},
		{at: "2026-06-01T14:00:00Z"},
		{at: "2026-06-02T13:30:00Z"},
	} {
		at, err := time.Parse(time.RFC3339, test.at)
		if err != nil {
			t.Fatal(err)
		}
		if got := parsed.DeniedAt(at); got != test.want {
			t.Errorf("DeniedAt(%s) = %t, want %t", test.at, got, test.want)
		}
	}
	if (&Config{}).DeniedAt(time.Now()) {
		t.Fatal("config without access policy denied a request")
	}
}

func TestDenyWindowCanEndAtMidnight(t *testing.T) {
	config := validCompiledConfig()
	config.Access = &Access{Deny: []DenyWindow{{
		Days:     []string{"mon"},
		Start:    "20:00",
		End:      "24:00",
		TimeZone: "UTC",
	}}}
	parsed := parseCompiledConfig(t, config)
	for _, test := range []struct {
		at   string
		want bool
	}{
		{at: "2026-06-01T19:59:59Z"},
		{at: "2026-06-01T20:00:00Z", want: true},
		{at: "2026-06-01T23:59:59Z", want: true},
		{at: "2026-06-02T00:00:00Z"},
	} {
		at, err := time.Parse(time.RFC3339, test.at)
		if err != nil {
			t.Fatal(err)
		}
		if got := parsed.DeniedAt(at); got != test.want {
			t.Errorf("DeniedAt(%s) = %t, want %t", test.at, got, test.want)
		}
	}
}

func TestPolicyFieldRegistryIsClosed(t *testing.T) {
	paths := FieldPaths()
	if len(paths) != 68 {
		t.Fatalf("FieldPaths() count = %d, want 68", len(paths))
	}
	for _, path := range paths {
		if fieldType, ok := FieldType(path); !ok || fieldType == "" {
			t.Fatalf("registered field %q did not resolve", path)
		}
	}
	validDynamic := []string{
		"deployment.data.pricing.input_tokens.per_mill_tokens",
		"deployment.data.pricing.output_tokens.per_mill_context_gt_272k",
		"deployment.data.pricing.anthropic_web_search_calls.per_1k_calls",
		"deployment.data.pricing.openai_chat_completion_search_preview_model_calls.per_1k_search_context_high_calls",
	}
	for _, path := range validDynamic {
		if fieldType, ok := FieldType(path); !ok || fieldType != "integer" {
			t.Fatalf("dynamic field %q = %q, %t", path, fieldType, ok)
		}
	}
	for _, path := range []string{
		"pricing.input_tokens.per_mill_tokens",
		"deployment.data.pricing.input_tokens.per_1k_calls",
		"deployment.data.pricing.unknown.per_mill_tokens",
		"deployment.data.pricing.anthropic_web_search_calls.per_mill_tokens",
		"deployment.__proto__",
	} {
		if fieldType, ok := FieldType(path); ok || fieldType != "" {
			t.Fatalf("unregistered field %q resolved as %q", path, fieldType)
		}
	}
}

func FuzzParseCompiledConfigNeverPanics(f *testing.F) {
	valid, _ := json.Marshal(validCompiledConfig())
	for _, seed := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`null`),
		valid,
		[]byte(`{"schema":"stogas.key-config.compiled.v1","compilerVersion":1,"access":null,"plugins":null,"routing":{"allowedCatalogNodes":null,"maxPreDispatchCandidates":1,"query":{"where":{"kind":"not","operand":null},"orderBy":[]}}}`),
		{0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = Parse(raw)
	})
}
