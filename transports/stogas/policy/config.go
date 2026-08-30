package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
	_ "time/tzdata"
)

const (
	CompilerVersion               = 1
	MaxCompiledBytes              = 32 << 10
	MaxExpressions                = 64
	MaxDepth                      = 12
	MaxListItems                  = 32
	MaxSorts                      = 5 // Four configured sorts plus deployment.id.
	MaxAllowedCatalogNodes        = 64
	MaxDenyWindows                = 16
	MaxPreDispatchCandidates      = 3
	MaxCustomPatterns             = 16
	MaxCustomPatternBytes         = 512
	MaxCombinedCustomPatternBytes = 4096
)

var (
	ErrInvalidConfig = errors.New("invalid compiled API key configuration")
	nodeIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
)

type Config struct {
	Access          *Access  `json:"access"`
	CompilerVersion int      `json:"compilerVersion"`
	Plugins         *Plugins `json:"plugins"`
	Routing         Routing  `json:"routing"`
	Schema          string   `json:"schema"`
}

type Routing struct {
	AllowedCatalogNodes      *AllowedCatalogNodes `json:"allowedCatalogNodes"`
	MaxPreDispatchCandidates int                  `json:"maxPreDispatchCandidates"`
	Query                    *Query               `json:"query"`
}

type AllowedCatalogNodes struct {
	Authors     []string `json:"authors,omitempty"`
	Deployments []string `json:"deployments,omitempty"`
	Models      []string `json:"models,omitempty"`
	Providers   []string `json:"providers,omitempty"`
	Routes      []string `json:"routes,omitempty"`
}

type Query struct {
	OrderBy []Sort      `json:"orderBy"`
	Where   *Expression `json:"where"`
}

type Sort struct {
	Direction string `json:"direction"`
	Path      string `json:"path"`
	Type      string `json:"type"`
}

type Field struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type Literal struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type Expression struct {
	Kind     string          `json:"kind"`
	Left     *Field          `json:"left,omitempty"`
	Operand  *Expression     `json:"operand,omitempty"`
	Operands []*Expression   `json:"operands,omitempty"`
	Operator string          `json:"operator,omitempty"`
	Path     string          `json:"path,omitempty"`
	Right    json.RawMessage `json:"right,omitempty"`
}

type Access struct {
	Deny []DenyWindow `json:"deny"`
}

type DenyWindow struct {
	Days     []string `json:"days"`
	End      string   `json:"end"`
	Start    string   `json:"start"`
	TimeZone string   `json:"timeZone"`

	endMinute   int
	location    *time.Location
	startMinute int
	weekdays    map[time.Weekday]bool
}

type Plugins struct {
	StogasPIIRedaction *PIIRedaction `json:"stogasPiiRedaction,omitempty"`
}

type PIIRedaction struct {
	CustomPatterns []string `json:"customPatterns,omitempty"`
	Patterns       []string `json:"patterns,omitempty"`
}

func Parse(raw []byte) (*Config, error) {
	if len(raw) == 0 || len(raw) > MaxCompiledBytes {
		return nil, configError("compiled configuration size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, configError("decode compiled configuration: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, configError("compiled configuration has trailing JSON")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *Config) validate() error {
	if c == nil || c.Schema != "stogas.key-config.compiled.v1" || c.CompilerVersion != CompilerVersion {
		return configError("unsupported schema or compiler version")
	}
	if c.Routing.MaxPreDispatchCandidates < 1 || c.Routing.MaxPreDispatchCandidates > MaxPreDispatchCandidates {
		return configError("pre-dispatch candidate count is invalid")
	}
	if err := c.Routing.AllowedCatalogNodes.validate(); err != nil {
		return err
	}
	if err := c.Routing.Query.validate(); err != nil {
		return err
	}
	if err := c.Access.validate(); err != nil {
		return err
	}
	if err := c.Plugins.validate(); err != nil {
		return err
	}
	return nil
}

func (a *AllowedCatalogNodes) validate() error {
	if a == nil {
		return nil
	}
	lists := [][]string{a.Authors, a.Deployments, a.Models, a.Providers, a.Routes}
	total := 0
	for _, values := range lists {
		if len(values) == 0 {
			continue
		}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if !nodeIDPattern.MatchString(value) {
				return configError("allowed catalog node ID is invalid")
			}
			if _, exists := seen[value]; exists {
				return configError("allowed catalog node IDs are not unique")
			}
			seen[value] = struct{}{}
		}
		total += len(values)
	}
	if total == 0 || total > MaxAllowedCatalogNodes {
		return configError("allowed catalog node count is invalid")
	}
	return nil
}

func (q *Query) validate() error {
	if q == nil {
		return nil
	}
	if q.Where == nil && len(q.OrderBy) == 0 {
		return configError("routing query is empty")
	}
	if len(q.OrderBy) > MaxSorts {
		return configError("routing sort count exceeds the limit")
	}
	seenSort := map[string]bool{}
	for _, item := range q.OrderBy {
		fieldType, ok := FieldType(item.Path)
		if !ok || fieldType != item.Type || fieldType == "string_list" {
			return configError("routing sort field is invalid")
		}
		if item.Direction != "asc" && item.Direction != "desc" {
			return configError("routing sort direction is invalid")
		}
		if seenSort[item.Path] {
			return configError("routing sort fields are not unique")
		}
		seenSort[item.Path] = true
	}
	if len(q.OrderBy) > 0 {
		stableSort := q.OrderBy[len(q.OrderBy)-1]
		if stableSort.Path != "deployment.id" || stableSort.Direction != "asc" {
			return configError("routing query has a noncanonical stable sort")
		}
	}
	count := 0
	return validateExpression(q.Where, 0, &count)
}

func validateExpression(expression *Expression, depth int, count *int) error {
	if expression == nil {
		return nil
	}
	if depth > MaxDepth {
		return configError("routing expression nesting exceeds the limit")
	}
	*count++
	if *count > MaxExpressions {
		return configError("routing expression count exceeds the limit")
	}
	switch expression.Kind {
	case "exists":
		if expression.Path == "" || hasExpressionExtras(expression, "path") {
			return configError("exists expression is malformed")
		}
		if _, ok := FieldType(expression.Path); !ok {
			return configError("exists expression has an unknown field")
		}
	case "not":
		if expression.Operand == nil || hasExpressionExtras(expression, "operand") {
			return configError("not expression is malformed")
		}
		return validateExpression(expression.Operand, depth+1, count)
	case "and", "or":
		if len(expression.Operands) < 2 || hasExpressionExtras(expression, "operands") {
			return configError("logical expression is malformed")
		}
		for _, operand := range expression.Operands {
			if operand == nil {
				return configError("logical expression contains an empty operand")
			}
			if err := validateExpression(operand, depth+1, count); err != nil {
				return err
			}
		}
	case "compare":
		if expression.Left == nil || expression.Operator == "" || len(expression.Right) == 0 || hasExpressionExtras(expression, "compare") {
			return configError("comparison expression is malformed")
		}
		fieldType, ok := FieldType(expression.Left.Path)
		if !ok || fieldType != expression.Left.Type {
			return configError("comparison expression has an invalid field")
		}
		return validateComparison(expression, fieldType)
	default:
		return configError("routing expression kind is invalid")
	}
	return nil
}

func hasExpressionExtras(expression *Expression, expected string) bool {
	switch expected {
	case "path":
		return expression.Left != nil || expression.Operand != nil || len(expression.Operands) != 0 || expression.Operator != "" || len(expression.Right) != 0
	case "operand":
		return expression.Left != nil || len(expression.Operands) != 0 || expression.Operator != "" || expression.Path != "" || len(expression.Right) != 0
	case "operands":
		return expression.Left != nil || expression.Operand != nil || expression.Operator != "" || expression.Path != "" || len(expression.Right) != 0
	case "compare":
		return expression.Operand != nil || len(expression.Operands) != 0 || expression.Path != ""
	default:
		return true
	}
}

func validateComparison(expression *Expression, fieldType string) error {
	operator := expression.Operator
	if fieldType == "string_list" && operator != "contains" {
		return configError("list comparison operator is invalid")
	}
	if fieldType == "boolean" && operator != "==" && operator != "!=" {
		return configError("boolean comparison operator is invalid")
	}
	if operator == "contains" && fieldType != "string" && fieldType != "string_list" {
		return configError("contains field type is invalid")
	}
	if operator == "in" {
		if fieldType == "string_list" {
			return configError("in field type is invalid")
		}
		var literals []Literal
		if err := decodeStrict(expression.Right, &literals); err != nil || len(literals) == 0 || len(literals) > MaxListItems {
			return configError("comparison list is invalid")
		}
		seen := map[string]bool{}
		for _, literal := range literals {
			key, err := validateLiteral(literal, fieldType)
			if err != nil || seen[key] {
				return configError("comparison list value is invalid")
			}
			seen[key] = true
		}
		return nil
	}
	if operator != "==" && operator != "!=" && operator != "<" && operator != "<=" && operator != ">" && operator != ">=" && operator != "contains" {
		return configError("comparison operator is invalid")
	}
	var literal Literal
	if err := decodeStrict(expression.Right, &literal); err != nil {
		return configError("comparison value is invalid")
	}
	expected := fieldType
	if expected == "string_list" {
		expected = "string"
	}
	_, err := validateLiteral(literal, expected)
	return err
}

func validateLiteral(literal Literal, expected string) (string, error) {
	if literal.Type != expected {
		return "", configError("comparison value type is invalid")
	}
	switch expected {
	case "boolean":
		var value bool
		if err := decodeStrict(literal.Value, &value); err != nil {
			return "", configError("boolean comparison value is invalid")
		}
		return fmt.Sprintf("boolean:%t", value), nil
	case "integer":
		var value string
		if err := decodeStrict(literal.Value, &value); err != nil {
			return "", configError("integer comparison value is invalid")
		}
		integer, ok := new(big.Int).SetString(value, 10)
		if !ok || integer.String() != value {
			return "", configError("integer comparison value is not canonical")
		}
		return "integer:" + value, nil
	case "string":
		var value string
		if err := decodeStrict(literal.Value, &value); err != nil || len(value) > 1024 {
			return "", configError("string comparison value is invalid")
		}
		return "string:" + value, nil
	default:
		return "", configError("comparison value type is unknown")
	}
}

func (a *Access) validate() error {
	if a == nil {
		return nil
	}
	if len(a.Deny) == 0 || len(a.Deny) > MaxDenyWindows {
		return configError("deny window count is invalid")
	}
	for index := range a.Deny {
		window := &a.Deny[index]
		if err := window.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (w *DenyWindow) validate() error {
	if w == nil || len(w.Days) == 0 || len(w.Days) > 7 {
		return configError("deny window days are invalid")
	}
	start, ok := clockMinute(w.Start)
	if !ok {
		return configError("deny window start is invalid")
	}
	end, ok := clockEndMinute(w.End)
	if !ok || start >= end {
		return configError("deny window end is invalid")
	}
	location, err := time.LoadLocation(w.TimeZone)
	if err != nil || len(w.TimeZone) > 64 {
		return configError("deny window time zone is invalid")
	}
	weekdays := make(map[time.Weekday]bool, len(w.Days))
	for _, day := range w.Days {
		weekday, ok := policyWeekday(day)
		if !ok || weekdays[weekday] {
			return configError("deny window days are invalid")
		}
		weekdays[weekday] = true
	}
	w.startMinute = start
	w.endMinute = end
	w.location = location
	w.weekdays = weekdays
	return nil
}

func (p *Plugins) validate() error {
	if p == nil || p.StogasPIIRedaction == nil {
		if p == nil {
			return nil
		}
		return configError("PII redaction plugin is missing")
	}
	pii := p.StogasPIIRedaction
	if len(pii.Patterns)+len(pii.CustomPatterns) == 0 {
		return configError("PII redaction plugin is empty")
	}
	if len(pii.Patterns) > 1 || len(pii.CustomPatterns) > MaxCustomPatterns {
		return configError("PII redaction option count is invalid")
	}
	seen := map[string]bool{}
	for _, pattern := range pii.Patterns {
		if pattern != "ip_address" || seen[pattern] {
			return configError("PII redaction pattern is invalid")
		}
		seen[pattern] = true
	}
	totalBytes := 0
	seen = map[string]bool{}
	for _, pattern := range pii.CustomPatterns {
		if pattern == "" || len(pattern) > MaxCustomPatternBytes || seen[pattern] {
			return configError("custom PII pattern is invalid")
		}
		totalBytes += len(pattern)
		seen[pattern] = true
	}
	if totalBytes > MaxCombinedCustomPatternBytes {
		return configError("custom PII patterns exceed the byte limit")
	}
	return nil
}

func (c *Config) DeniedAt(now time.Time) bool {
	if c == nil || c.Access == nil {
		return false
	}
	for index := range c.Access.Deny {
		window := &c.Access.Deny[index]
		local := now.In(window.location)
		minute := local.Hour()*60 + local.Minute()
		if window.weekdays[local.Weekday()] && minute >= window.startMinute && minute < window.endMinute {
			return true
		}
	}
	return false
}

func (a *AllowedCatalogNodes) Allows(authorID, modelID, deploymentID, routeID, providerID string) bool {
	if a == nil {
		return true
	}
	return allowedNode(a.Authors, authorID) &&
		allowedNode(a.Models, modelID) &&
		allowedNode(a.Deployments, deploymentID) &&
		allowedNode(a.Routes, routeID) &&
		allowedNode(a.Providers, providerID)
}

func allowedNode(allowed []string, value string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == value {
			return true
		}
	}
	return false
}

type Value struct {
	Type    string
	Boolean bool
	Integer *big.Int
	String  string
	Strings []string
}

type Values interface {
	PolicyValue(path string) (Value, bool)
}

type truth uint8

const (
	truthUnknown truth = iota
	truthFalse
	truthTrue
)

func (q *Query) Matches(values Values) bool {
	if q == nil || q.Where == nil {
		return true
	}
	return evaluate(q.Where, values) == truthTrue
}

func evaluate(expression *Expression, values Values) truth {
	if expression == nil {
		return truthUnknown
	}
	switch expression.Kind {
	case "exists":
		_, ok := values.PolicyValue(expression.Path)
		if ok {
			return truthTrue
		}
		return truthFalse
	case "not":
		value := evaluate(expression.Operand, values)
		if value == truthTrue {
			return truthFalse
		}
		if value == truthFalse {
			return truthTrue
		}
		return truthUnknown
	case "and":
		result := truthTrue
		for _, operand := range expression.Operands {
			value := evaluate(operand, values)
			if value == truthFalse {
				return truthFalse
			}
			if value == truthUnknown {
				result = truthUnknown
			}
		}
		return result
	case "or":
		result := truthFalse
		for _, operand := range expression.Operands {
			value := evaluate(operand, values)
			if value == truthTrue {
				return truthTrue
			}
			if value == truthUnknown {
				result = truthUnknown
			}
		}
		return result
	case "compare":
		left, ok := values.PolicyValue(expression.Left.Path)
		if !ok || left.Type != expression.Left.Type {
			return truthUnknown
		}
		matched, ok := compareExpression(left, expression.Operator, expression.Right)
		if !ok {
			return truthUnknown
		}
		if matched {
			return truthTrue
		}
		return truthFalse
	default:
		return truthUnknown
	}
}

func compareExpression(left Value, operator string, raw json.RawMessage) (bool, bool) {
	if operator == "in" {
		var literals []Literal
		if err := decodeStrict(raw, &literals); err != nil {
			return false, false
		}
		for _, literal := range literals {
			matched, ok := compareLiteral(left, "==", literal)
			if !ok {
				return false, false
			}
			if matched {
				return true, true
			}
		}
		return false, true
	}
	var literal Literal
	if err := decodeStrict(raw, &literal); err != nil {
		return false, false
	}
	return compareLiteral(left, operator, literal)
}

func compareLiteral(left Value, operator string, literal Literal) (bool, bool) {
	switch left.Type {
	case "boolean":
		var right bool
		if literal.Type != "boolean" || decodeStrict(literal.Value, &right) != nil {
			return false, false
		}
		return applyComparison(boolCompare(left.Boolean, right), operator), true
	case "integer":
		var raw string
		if literal.Type != "integer" || decodeStrict(literal.Value, &raw) != nil || left.Integer == nil {
			return false, false
		}
		right, ok := new(big.Int).SetString(raw, 10)
		if !ok {
			return false, false
		}
		return applyComparison(left.Integer.Cmp(right), operator), true
	case "string":
		var right string
		if literal.Type != "string" || decodeStrict(literal.Value, &right) != nil {
			return false, false
		}
		if operator == "contains" {
			return strings.Contains(left.String, right), true
		}
		return applyComparison(strings.Compare(left.String, right), operator), true
	case "string_list":
		var right string
		if operator != "contains" || literal.Type != "string" || decodeStrict(literal.Value, &right) != nil {
			return false, false
		}
		for _, item := range left.Strings {
			if item == right {
				return true, true
			}
		}
		return false, true
	default:
		return false, false
	}
}

func (q *Query) Less(left, right Values) bool {
	if q == nil {
		return false
	}
	for _, order := range q.OrderBy {
		leftValue, leftOK := left.PolicyValue(order.Path)
		rightValue, rightOK := right.PolicyValue(order.Path)
		if !leftOK || !rightOK {
			if leftOK != rightOK {
				return leftOK // Missing values always sort last.
			}
			continue
		}
		comparison := compareValues(leftValue, rightValue)
		if comparison == 0 {
			continue
		}
		if order.Direction == "desc" {
			return comparison > 0
		}
		return comparison < 0
	}
	return false
}

func compareValues(left, right Value) int {
	if left.Type != right.Type {
		return 0
	}
	switch left.Type {
	case "boolean":
		return boolCompare(left.Boolean, right.Boolean)
	case "integer":
		if left.Integer == nil || right.Integer == nil {
			return 0
		}
		return left.Integer.Cmp(right.Integer)
	case "string":
		return strings.Compare(left.String, right.String)
	default:
		return 0
	}
}

func applyComparison(comparison int, operator string) bool {
	switch operator {
	case "==":
		return comparison == 0
	case "!=":
		return comparison != 0
	case "<":
		return comparison < 0
	case "<=":
		return comparison <= 0
	case ">":
		return comparison > 0
	case ">=":
		return comparison >= 0
	default:
		return false
	}
}

func boolCompare(left, right bool) int {
	if left == right {
		return 0
	}
	if !left {
		return -1
	}
	return 1
}

func clockMinute(value string) (int, bool) {
	parsed, err := time.Parse("15:04", value)
	if err != nil || parsed.Format("15:04") != value {
		return 0, false
	}
	return parsed.Hour()*60 + parsed.Minute(), true
}

func clockEndMinute(value string) (int, bool) {
	if value == "24:00" {
		return 24 * 60, true
	}
	return clockMinute(value)
}

func policyWeekday(value string) (time.Weekday, bool) {
	switch value {
	case "sun":
		return time.Sunday, true
	case "mon":
		return time.Monday, true
	case "tue":
		return time.Tuesday, true
	case "wed":
		return time.Wednesday, true
	case "thu":
		return time.Thursday, true
	case "fri":
		return time.Friday, true
	case "sat":
		return time.Saturday, true
	default:
		return 0, false
	}
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func configError(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, arguments...))
}

var exactFieldTypes = map[string]string{
	"author.data.aliases": "string_list", "author.data.name": "string", "author.id": "string",
	"deployment.data.aliases": "string_list", "deployment.data.contextWindowTokens": "integer",
	"deployment.data.dataHandling.endToEndEncrypted": "boolean", "deployment.data.dataHandling.processingLocation": "string",
	"deployment.data.dataHandling.retentionDays": "integer", "deployment.data.dataHandling.storageLocation": "string",
	"deployment.data.dataHandling.tee": "boolean", "deployment.data.dataHandling.teeVerified": "boolean",
	"deployment.data.dataHandling.trainingUse":       "boolean",
	"deployment.data.dataHandling.zeroDataRetention": "boolean", "deployment.data.deprecationDate": "string",
	"deployment.data.inputModalities": "string_list", "deployment.data.maxOutputTokens": "integer",
	"deployment.data.modelId": "string", "deployment.data.outputModalities": "string_list",
	"deployment.data.reasoning": "string", "deployment.data.reasoningEfforts": "string_list",
	"deployment.data.reasoningMaxTokens.maximum": "integer", "deployment.data.reasoningMaxTokens.minimum": "integer",
	"deployment.data.routeIds": "string_list", "deployment.data.upstream.chuteId": "string",
	"deployment.data.upstream.deploymentType": "string", "deployment.data.upstream.gpuCount": "integer",
	"deployment.data.upstream.hosting": "string", "deployment.data.upstream.inferenceGeo": "string",
	"deployment.data.upstream.model": "string", "deployment.data.upstream.modelFormat": "string",
	"deployment.data.upstream.modelVersion": "string", "deployment.data.upstream.reasoningMode": "string",
	"deployment.data.upstream.serviceTier": "string", "deployment.data.upstream.speed": "string",
	"deployment.data.weightPrecision": "string",
	"deployment.id":                   "string", "model.data.aliases": "string_list", "model.data.authorId": "string",
	"model.data.maxOutputTokens": "integer", "model.data.name": "string", "model.data.reasoning": "string",
	"model.data.reasoningEfforts": "string_list", "model.data.reasoningMaxTokens.maximum": "integer",
	"model.data.reasoningMaxTokens.minimum": "integer", "model.data.releaseDate": "string", "model.id": "string",
	"provider.data.aliases": "string_list", "provider.data.credentialModes": "string_list",
	"provider.data.name": "string", "provider.id": "string", "request.estimatedInputTokens": "integer",
	"request.maximumOutputTokens": "integer", "request.model": "string", "request.route": "string",
	"route.data.interfaces": "string_list", "route.data.providerId": "string", "route.id": "string",
}

func init() {
	for _, capability := range []string{
		"cancellation", "explicitPromptCaching", "functionCalling", "implicitPromptCaching",
		"parallelFunctionCalling", "pdfInput", "streaming", "structuredOutputs", "systemMessages",
		"toolChoice", "urlContext",
	} {
		exactFieldTypes["deployment.data.capabilities."+capability] = "boolean"
	}
}

var tokenPricingMeters = stringSet(
	"cache_write_1h_input_tokens", "cache_write_5m_input_tokens", "cache_write_input_tokens",
	"cached_input_tokens", "input_tokens", "output_tokens", "reasoning_tokens",
)

var callPricingMeters = stringSet(
	"anthropic_web_search_calls", "openai_chat_completion_search_model_calls",
	"openai_responses_web_search_calls", "openai_responses_web_search_preview_calls",
	"openai_responses_web_search_preview_non_reasoning_calls",
)

var tokenPricingRates = stringSet(
	"per_mill_context_gt_272k", "per_mill_context_lte_272k", "per_mill_tokens",
)

var searchContextPricingRates = stringSet(
	"per_1k_search_context_high_calls", "per_1k_search_context_low_calls",
	"per_1k_search_context_medium_calls",
)

func FieldType(path string) (string, bool) {
	if fieldType, ok := exactFieldTypes[path]; ok {
		return fieldType, true
	}
	parts := strings.Split(path, ".")
	if len(parts) != 5 || parts[0] != "deployment" || parts[1] != "data" || parts[2] != "pricing" {
		return "", false
	}
	meter, rate := parts[3], parts[4]
	if (tokenPricingMeters[meter] && tokenPricingRates[rate]) ||
		(callPricingMeters[meter] && rate == "per_1k_calls") ||
		(meter == "openai_chat_completion_search_preview_model_calls" && searchContextPricingRates[rate]) {
		return "integer", true
	}
	return "", false
}

func FieldPaths() []string {
	paths := make([]string, 0, len(exactFieldTypes))
	for path := range exactFieldTypes {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
