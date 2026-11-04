package stogas

import (
	"bytes"
	"encoding/json"
	"errors"
	"iter"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The checks compare what a completed response returned with what the request
// asked for: each client tool call against its tool's parameters, and JSON text
// against response_format or text.format. A request supplies the schemas, so
// every bound below keeps one request's checks to a small, fixed amount of work.
// A value past a bound is not checked, so it counts as neither valid nor invalid.
const (
	// maxCheckedValueBytes bounds one tool call's arguments or one output, and
	// maxCheckedSchemaBytes one schema.
	maxCheckedValueBytes  = 1 << 20
	maxCheckedSchemaBytes = 64 << 10
	// maxCheckedValueDepth and maxCheckedSchemaDepth bound JSON nesting.
	maxCheckedValueDepth  = 64
	maxCheckedSchemaDepth = 128
	// maxCheckedNumberBytes and maxCheckedNumberExponent bound number literals,
	// which the validator converts to exact rationals.
	maxCheckedNumberBytes    = 64
	maxCheckedNumberExponent = 400
	// maxCheckRecursion bounds the validator's call depth: the value's nesting
	// times the longest chain of subschemas that apply to one value.
	maxCheckRecursion = 4_096
	// checkBudgetSteps bounds the work of one request's checks. A step takes
	// about half a microsecond: one subschema evaluation, 64 bytes decoded or
	// compared, or half a schema byte compiled. Ordinary checks use a few
	// thousand steps; without the bound a schema can make validation exponential.
	checkBudgetSteps = 256_000
	// checkedSchemaURL names a request schema inside its compiler. Nothing loads it.
	checkedSchemaURL = "https://schema.stogas.invalid/request.json"
)

var (
	errCheckedSchemaURL   = errors.New("request schemas cannot load URLs")
	errCheckBudget        = errors.New("output check budget exhausted")
	errCheckValueMismatch = errors.New("value does not match const or enum")
)

// outputChecks counts the client tool calls and structured outputs that a
// completed response returned, and the ones that break the request's schema.
type outputChecks struct {
	toolCalls, invalidToolCalls int
	outputs, invalidOutputs     int
}

type checkResult uint8

const (
	checkSkipped checkResult = iota
	checkValid
	checkInvalid
)

func (c *outputChecks) addToolCall(result checkResult) {
	if result != checkSkipped {
		c.toolCalls++
		if result == checkInvalid {
			c.invalidToolCalls++
		}
	}
}

func (c *outputChecks) addOutput(result checkResult) {
	if result != checkSkipped {
		c.outputs++
		if result == checkInvalid {
			c.invalidOutputs++
		}
	}
}

// structuredOutput is the JSON text that a request asks for.
type structuredOutput struct {
	json   bool
	schema json.RawMessage
}

func readStructuredOutput(resolution *catalog.ResolvedRequest) structuredOutput {
	if resolution == nil {
		return structuredOutput{}
	}
	body := resolution.RawBody()
	var format map[string]json.RawMessage
	switch resolution.Route {
	case catalog.RouteChat:
		format, _ = rawObject(body["response_format"])
	case catalog.RouteResponses:
		text, _ := rawObject(body["text"])
		format, _ = rawObject(text["format"])
	}
	switch rawString(format["type"]) {
	case "json_object":
		return structuredOutput{json: true}
	case "json_schema":
		if resolution.Route == catalog.RouteChat {
			definition, _ := rawObject(format["json_schema"])
			return structuredOutput{json: true, schema: definition["schema"]}
		}
		return structuredOutput{json: true, schema: format["schema"]}
	}
	return structuredOutput{}
}

func (s *State) structuredOutput() structuredOutput {
	if s.outputFormat == nil {
		format := readStructuredOutput(s.Resolution)
		s.outputFormat = &format
	}
	return *s.outputFormat
}

// recordChatOutput keeps streamed content for the structured output check.
func (s *State) recordChatOutput(content string) {
	if s.chatOutputLong || !s.structuredOutput().json {
		return
	}
	if s.chatOutput == nil {
		s.chatOutput = &bytes.Buffer{}
	}
	if len(content) > maxCheckedValueBytes-s.chatOutput.Len() {
		s.chatOutput, s.chatOutputLong = nil, true
		return
	}
	_, _ = s.chatOutput.WriteString(content)
}

// checkOutputs checks a completed response. Like OpenRouter's tool call error
// rate, a call is invalid when its arguments are not a JSON object, name no
// declared tool, or break the tool's parameters schema. A tool without a schema
// that compiles gets only the JSON check. Outputs are checked when the model
// ends normally without calling a tool or refusing.
func (s *State) checkOutputs() outputChecks {
	var checks outputChecks
	if s == nil || s.Resolution == nil || s.Response == nil {
		return checks
	}
	checker := &outputChecker{resolution: s.Resolution, budget: checkBudgetSteps}
	// A bridged request's state holds the provider's Chat Completions reply.
	switch s.Resolution.WireRoute() {
	case catalog.RouteChat:
		s.checkChatOutputs(checker, &checks)
	case catalog.RouteResponses:
		s.checkResponsesOutputs(checker, &checks)
	}
	return checks
}

func (s *State) checkChatOutputs(checker *outputChecker, checks *outputChecks) {
	switch s.chatFinishReason {
	case string(schemas.BifrostFinishReasonToolCalls):
		for index := range len(s.chatToolCalls) {
			if call, ok := s.chatToolCalls[uint16(index)]; ok && call.arguments != nil {
				checks.addToolCall(checker.toolCall(call.name, call.arguments.Bytes()))
			}
		}
	case string(schemas.BifrostFinishReasonStop):
		format := s.structuredOutput()
		if !format.json {
			return
		}
		var text []byte
		if response := s.Response.ChatResponse; response != nil && len(response.Choices) == 1 &&
			response.Choices[0].ChatNonStreamResponseChoice != nil {
			content, refusal := chatMessageOutput(response.Choices[0].ChatNonStreamResponseChoice.Message)
			if refusal {
				return
			}
			text = []byte(content)
		} else {
			if s.chatRefusal || s.chatOutputLong {
				return
			}
			if s.chatOutput != nil {
				text = s.chatOutput.Bytes()
			}
		}
		checks.addOutput(checker.output(format, text))
	}
}

func chatMessageOutput(message *schemas.ChatMessage) (text string, refusal bool) {
	if message == nil {
		return "", false
	}
	if assistant := message.ChatAssistantMessage; assistant != nil && assistant.Refusal != nil && *assistant.Refusal != "" {
		return "", true
	}
	if message.Content == nil {
		return "", false
	}
	if message.Content.ContentStr != nil {
		return *message.Content.ContentStr, false
	}
	var builder strings.Builder
	for _, block := range message.Content.ContentBlocks {
		switch block.Type {
		case schemas.ChatContentBlockTypeRefusal:
			return "", true
		case schemas.ChatContentBlockTypeText:
			if block.Text != nil {
				_, _ = builder.WriteString(*block.Text)
			}
		}
	}
	return builder.String(), false
}

func (s *State) checkResponsesOutputs(checker *outputChecker, checks *outputChecks) {
	response := s.Response.ResponsesResponse
	if stream := s.Response.ResponsesStreamResponse; stream != nil && stream.Type == schemas.ResponsesStreamResponseTypeCompleted {
		response = stream.Response
	}
	// The turn must end normally. A stream's terminal event can omit the status,
	// which then means completed, but Anthropic's wire also omits it for a turn
	// that stops for another reason, such as pause_turn.
	if response == nil || response.Status != nil && *response.Status != schemas.ResponsesResponseStatusCompleted ||
		response.StopReason != nil && *response.StopReason != string(schemas.BifrostFinishReasonStop) &&
			*response.StopReason != string(schemas.BifrostFinishReasonToolCalls) {
		return
	}
	format := s.structuredOutput()
	var text bytes.Buffer
	toolCalls, refusal, long := false, false, false
	for index := range response.Output {
		item := &response.Output[index]
		if item.Type == nil {
			continue
		}
		switch *item.Type {
		case schemas.ResponsesMessageTypeFunctionCall:
			toolCalls = true
			if tool := item.ResponsesToolMessage; tool != nil && tool.Name != nil && tool.Arguments != nil {
				checks.addToolCall(checker.toolCall(*tool.Name, []byte(*tool.Arguments)))
			}
		case schemas.ResponsesMessageTypeCustomToolCall:
			toolCalls = true
		case schemas.ResponsesMessageTypeMessage:
			if !format.json || item.Content == nil {
				continue
			}
			for _, block := range item.Content.ContentBlocks {
				switch block.Type {
				case schemas.ResponsesOutputMessageContentTypeRefusal:
					refusal = true
				case schemas.ResponsesOutputMessageContentTypeText:
					if block.Text != nil && !long {
						if len(*block.Text) > maxCheckedValueBytes-text.Len() {
							long = true
						} else {
							_, _ = text.WriteString(*block.Text)
						}
					}
				}
			}
		}
	}
	if format.json && !toolCalls && !refusal && !long {
		checks.addOutput(checker.output(format, text.Bytes()))
	}
}

// outputChecker checks one request's response. It compiles each schema once
// and charges all of its work to one budget.
type outputChecker struct {
	resolution *catalog.ResolvedRequest
	parameters map[string]json.RawMessage
	compiled   map[string]*checkedSchema
	budget     int
	// step is what one subschema evaluation costs in the current validation.
	step int
}

// checkedSchema is a compiled request schema. A nil schema checks only that
// the value is JSON; skip means the schema is past a bound.
type checkedSchema struct {
	schema *jsonschema.Schema
	chain  int
	skip   bool
}

func (c *outputChecker) toolCall(name string, arguments []byte) checkResult {
	if c.parameters == nil {
		c.parameters = make(map[string]json.RawMessage)
		chat := c.resolution.Route == catalog.RouteChat
		for _, tool := range c.resolution.RawTools() {
			if rawString(tool["type"]) != "function" {
				continue
			}
			if !chat {
				c.parameters[rawString(tool["name"])] = tool["parameters"]
			} else if function, ok := rawObject(tool["function"]); ok {
				c.parameters[rawString(function["name"])] = function["parameters"]
			}
		}
	}
	parameters, declared := c.parameters[name]
	if !declared {
		return checkInvalid
	}
	value, depth, result := c.decode(arguments)
	if result != checkValid {
		return result
	}
	if _, object := value.(map[string]any); !object {
		return checkInvalid
	}
	if c.compiled == nil {
		c.compiled = make(map[string]*checkedSchema)
	}
	schema, ok := c.compiled[name]
	if !ok {
		schema = c.compile(parameters)
		c.compiled[name] = schema
	}
	return c.validate(schema, value, depth)
}

func (c *outputChecker) output(format structuredOutput, text []byte) checkResult {
	value, depth, result := c.decode(text)
	if result != checkValid {
		return result
	}
	if format.schema == nil {
		if _, object := value.(map[string]any); !object {
			return checkInvalid
		}
		return checkValid
	}
	return c.validate(c.compile(format.schema), value, depth)
}

func (c *outputChecker) spend(steps int) bool {
	c.budget -= steps
	return c.budget >= 0
}

func (c *outputChecker) decode(data []byte) (any, int, checkResult) {
	if len(data) > maxCheckedValueBytes || !c.spend(1+len(data)/64) {
		return nil, 0, checkSkipped
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, 0, checkInvalid
	}
	depth, ok := boundedJSON(value, maxCheckedValueDepth)
	if !ok {
		return nil, 0, checkSkipped
	}
	return value, depth, checkValid
}

func (c *outputChecker) compile(raw json.RawMessage) *checkedSchema {
	if !rawJSONValueSet(raw) {
		return &checkedSchema{}
	}
	if len(raw) > maxCheckedSchemaBytes || !c.spend(2*len(raw)) {
		return &checkedSchema{skip: true}
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return &checkedSchema{}
	}
	if _, ok := boundedJSON(document, maxCheckedSchemaDepth); !ok {
		return &checkedSchema{skip: true}
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(noSchemaLoader{})
	compiler.DefaultDraft(jsonschema.Draft2020)
	if compiler.AddResource(checkedSchemaURL, document) != nil {
		return &checkedSchema{}
	}
	schema, err := compiler.Compile(checkedSchemaURL)
	if err != nil {
		return &checkedSchema{}
	}
	nodes, ok := schemaNodes(schema)
	if !ok {
		return &checkedSchema{skip: true}
	}
	for _, node := range nodes {
		c.meter(node)
	}
	return &checkedSchema{schema: schema, chain: sameValueChain(nodes)}
}

func (c *outputChecker) validate(schema *checkedSchema, value any, depth int) checkResult {
	if schema.skip {
		return checkSkipped
	}
	if schema.schema == nil {
		return checkValid
	}
	if (depth+1)*(schema.chain+1) > maxCheckRecursion || c.budget <= 0 {
		return checkSkipped
	}
	// The validator's cycle check walks the chain of subschemas applied to the
	// value, and each error copies the value's location.
	c.step = 1 + schema.chain/16 + depth/8
	err := schema.schema.Validate(value)
	if c.budget < 0 {
		return checkSkipped
	}
	if err != nil {
		return checkInvalid
	}
	return checkValid
}

// noSchemaLoader refuses every URL, so a request schema can refer only to
// itself and to the JSON Schema drafts that the library embeds.
type noSchemaLoader struct{}

func (noSchemaLoader) Load(string) (any, error) {
	return nil, errCheckedSchemaURL
}

// meter makes a compiled subschema charge the budget before it validates a
// value. The validator calls a schema's format first, after the type check, so
// the charge covers the work the subschema does itself; the subschemas it
// applies charge for themselves. const and enum move into the same call, since
// the validator compares them before the format. The format keyword itself
// becomes an annotation, as JSON Schema 2020-12 makes it by default.
func (c *outputChecker) meter(node *jsonschema.Schema) {
	if node.Bool != nil {
		return
	}
	var values []any
	if node.Enum != nil {
		values = node.Enum.Values
	}
	constant := node.Const
	node.Enum, node.Const = nil, nil
	// The evaluation and each subschema it applies to the same value cost a step.
	calls := 1 + len(sameValueSchemas(node))
	compare := 0
	for _, value := range values {
		compare += jsonWeight(value)
	}
	if constant != nil {
		compare += jsonWeight(*constant)
	}
	// A property or item costs a step to visit, which also covers a subschema
	// that rejects it on type before charging; contains and the unevaluated
	// keywords visit it again.
	itemVisits := 1
	if node.Contains != nil {
		itemVisits++
	}
	if node.UnevaluatedItems != nil {
		itemVisits++
	}
	propertyVisits := 1 + len(node.PatternProperties)
	if node.PropertyNames != nil {
		propertyVisits++
	}
	if node.UnevaluatedProperties != nil {
		propertyVisits++
	}
	patternSource := 0
	for pattern := range node.PatternProperties {
		patternSource += len(pattern.String())
	}
	required := len(node.Required) + len(node.Dependencies) + len(node.DependentSchemas)
	for _, names := range node.DependentRequired {
		required += len(names)
	}
	required /= 8
	// Matching a regular expression can take time proportional to the text
	// times the expression.
	text := -1
	if node.Pattern != nil {
		text = len(node.Pattern.String())
	} else if node.MinLength != nil || node.MaxLength != nil {
		text = 0
	}
	numeric := node.Minimum != nil || node.Maximum != nil || node.ExclusiveMinimum != nil ||
		node.ExclusiveMaximum != nil || node.MultipleOf != nil
	unique := node.UniqueItems
	node.Format = &jsonschema.Format{Name: "stogas-check", Validate: func(value any) error {
		// Once the budget is spent, every evaluation fails at once, so the
		// validator unwinds quickly and the result is not used.
		if c.budget < 0 {
			return errCheckBudget
		}
		cost := c.step*calls + compare
		switch value := value.(type) {
		case string:
			if text >= 0 {
				cost += len(value) * (text + 1) / 64
			}
		case json.Number:
			if numeric {
				cost += 4
			}
		case []any:
			cost += len(value) * itemVisits * c.step
			if unique {
				cost += jsonWeight(value)
			}
		case map[string]any:
			cost += required
			for name := range value {
				cost += propertyVisits*c.step + len(name)*patternSource/64
			}
		}
		if !c.spend(cost) {
			return errCheckBudget
		}
		if constant != nil && !jsonEqual(value, *constant) ||
			values != nil && !slices.ContainsFunc(values, func(item any) bool { return jsonEqual(value, item) }) {
			return errCheckValueMismatch
		}
		return nil
	}}
}

// schemaNodes lists the subschemas that validation can reach. It refuses
// dynamic references: the validator resolves them while it runs, so their
// targets may not be reachable here to be metered.
func schemaNodes(root *jsonschema.Schema) ([]*jsonschema.Schema, bool) {
	seen := make(map[*jsonschema.Schema]bool)
	var nodes []*jsonschema.Schema
	pending := []*jsonschema.Schema{root}
	for len(pending) > 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[node] {
			continue
		}
		seen[node] = true
		if node.RecursiveRef != nil || node.DynamicRef != nil {
			return nil, false
		}
		nodes = append(nodes, node)
		pending = append(pending, sameValueSchemas(node)...)
		pending = append(pending, childSchemas(node)...)
	}
	return nodes, true
}

// sameValueSchemas lists the subschemas that a schema applies to its own value.
func sameValueSchemas(node *jsonschema.Schema) []*jsonschema.Schema {
	var out []*jsonschema.Schema
	for _, schema := range []*jsonschema.Schema{node.Ref, node.Not, node.If, node.Then, node.Else} {
		if schema != nil {
			out = append(out, schema)
		}
	}
	out = append(out, node.AllOf...)
	out = append(out, node.AnyOf...)
	out = append(out, node.OneOf...)
	for _, schema := range node.DependentSchemas {
		out = append(out, schema)
	}
	for _, dependency := range node.Dependencies {
		if schema, ok := dependency.(*jsonschema.Schema); ok {
			out = append(out, schema)
		}
	}
	return out
}

// childSchemas lists the subschemas that a schema applies to property names,
// property values and items.
func childSchemas(node *jsonschema.Schema) []*jsonschema.Schema {
	var out []*jsonschema.Schema
	for _, schema := range []*jsonschema.Schema{node.PropertyNames, node.UnevaluatedProperties, node.Contains,
		node.Items2020, node.UnevaluatedItems, node.ContentSchema} {
		if schema != nil {
			out = append(out, schema)
		}
	}
	for _, schema := range node.Properties {
		out = append(out, schema)
	}
	for _, schema := range node.PatternProperties {
		out = append(out, schema)
	}
	out = append(out, node.PrefixItems...)
	for _, value := range []any{node.AdditionalProperties, node.AdditionalItems, node.Items} {
		switch value := value.(type) {
		case *jsonschema.Schema:
			out = append(out, value)
		case []*jsonschema.Schema:
			out = append(out, value...)
		}
	}
	return out
}

// sameValueChain bounds how many subschemas the validator can nest on one
// value. Its cycle check stops a chain at the first repeated subschema, so a
// chain enters each strongly connected component once and uses at most all
// of its subschemas.
func sameValueChain(nodes []*jsonschema.Schema) int {
	index := make(map[*jsonschema.Schema]int, len(nodes))
	low := make(map[*jsonschema.Schema]int, len(nodes))
	component := make(map[*jsonschema.Schema]int, len(nodes))
	onStack := make(map[*jsonschema.Schema]bool)
	var stack []*jsonschema.Schema
	// longest holds each component's longest chain, in the order that Tarjan's
	// algorithm completes them: every component reachable from one comes first.
	var longest []int
	var connect func(*jsonschema.Schema)
	connect = func(node *jsonschema.Schema) {
		index[node], low[node] = len(index), len(index)
		stack = append(stack, node)
		onStack[node] = true
		for _, target := range sameValueSchemas(node) {
			if _, seen := index[target]; !seen {
				connect(target)
				low[node] = min(low[node], low[target])
			} else if onStack[target] {
				low[node] = min(low[node], index[target])
			}
		}
		if low[node] != index[node] {
			return
		}
		id := len(longest)
		var members []*jsonschema.Schema
		for {
			member := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[member] = false
			component[member] = id
			members = append(members, member)
			if member == node {
				break
			}
		}
		reach := 0
		for _, member := range members {
			for _, target := range sameValueSchemas(member) {
				if other, ok := component[target]; ok && other != id {
					reach = max(reach, longest[other])
				}
			}
		}
		longest = append(longest, len(members)+reach)
	}
	chain := 0
	for _, node := range nodes {
		if _, seen := index[node]; !seen {
			connect(node)
		}
	}
	for _, length := range longest {
		chain = max(chain, length)
	}
	return chain
}

// boundedJSON returns how deeply a decoded value nests, and whether it stays
// within maxDepth and the number bounds.
func boundedJSON(value any, maxDepth int) (int, bool) {
	switch value := value.(type) {
	case json.Number:
		return 0, boundedNumber(string(value))
	case map[string]any:
		return boundedItems(maps.Values(value), maxDepth)
	case []any:
		return boundedItems(slices.Values(value), maxDepth)
	default:
		return 0, true
	}
}

func boundedItems(items iter.Seq[any], maxDepth int) (int, bool) {
	if maxDepth == 0 {
		return 0, false
	}
	depth := 0
	for item := range items {
		itemDepth, ok := boundedJSON(item, maxDepth-1)
		if !ok {
			return 0, false
		}
		depth = max(depth, itemDepth)
	}
	return depth + 1, true
}

func boundedNumber(literal string) bool {
	if len(literal) > maxCheckedNumberBytes {
		return false
	}
	_, exponent, found := strings.Cut(strings.ToLower(literal), "e")
	if !found {
		return true
	}
	value, err := strconv.Atoi(exponent)
	return err == nil && value >= -maxCheckedNumberExponent && value <= maxCheckedNumberExponent
}

// jsonWeight estimates the steps to walk or compare a decoded value.
func jsonWeight(value any) int {
	switch value := value.(type) {
	case string:
		return 1 + len(value)/64
	case []any:
		weight := 1
		for _, item := range value {
			weight += jsonWeight(item)
		}
		return weight
	case map[string]any:
		weight := 1
		for name, item := range value {
			weight += 1 + len(name)/64 + jsonWeight(item)
		}
		return weight
	default:
		return 1
	}
}

// jsonEqual compares decoded JSON values as JSON Schema does: numbers by value.
func jsonEqual(left, right any) bool {
	switch left := left.(type) {
	case map[string]any:
		right, ok := right.(map[string]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for name, value := range left {
			other, ok := right[name]
			if !ok || !jsonEqual(value, other) {
				return false
			}
		}
		return true
	case []any:
		right, ok := right.([]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for index := range left {
			if !jsonEqual(left[index], right[index]) {
				return false
			}
		}
		return true
	case json.Number:
		right, ok := right.(json.Number)
		if !ok {
			return false
		}
		leftValue, leftOK := new(big.Rat).SetString(string(left))
		rightValue, rightOK := new(big.Rat).SetString(string(right))
		return leftOK && rightOK && leftValue.Cmp(rightValue) == 0
	case string, bool, nil:
		return left == right
	default:
		return false
	}
}
