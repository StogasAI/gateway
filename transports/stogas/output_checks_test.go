package stogas

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const checkedToolsRequest = `{"model":"openai/gpt-5.5","messages":[{"role":"user","content":"hi"}],"tools":[` +
	`{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"integer","minimum":1}},"required":["q"],"additionalProperties":false}}},` +
	`{"type":"function","function":{"name":"free"}}]}`

// checkMeters returns the four check meters, with "-" for an absent one.
func checkMeters(state *State) string {
	meters := metersForState(state)
	var values []string
	for _, key := range []string{billing.MeterCheckedClientToolCalls, billing.MeterInvalidClientToolCalls,
		billing.MeterCheckedStructuredOutputs, billing.MeterInvalidStructuredOutputs} {
		meter, ok := meters[key]
		switch {
		case !ok:
			values = append(values, "-")
		case meter.RateKey != nil || meter.RateUSD != nil || meter.USD != nil:
			values = append(values, "priced")
		default:
			values = append(values, meter.Quantity)
		}
	}
	return strings.Join(values, " ")
}

func chatToolCallResponse(calls ...[2]string) *schemas.BifrostChatResponse {
	response := validUnaryChatProviderResponse()
	response.Choices[0].FinishReason = schemas.Ptr("tool_calls")
	assistant := &schemas.ChatAssistantMessage{}
	for index, call := range calls {
		assistant.ToolCalls = append(assistant.ToolCalls, schemas.ChatAssistantMessageToolCall{
			Type: schemas.Ptr("function"),
			ID:   schemas.Ptr(fmt.Sprintf("call_%d", index)),
			Function: schemas.ChatAssistantMessageToolCallFunction{
				Name: schemas.Ptr(call[0]), Arguments: call[1],
			},
		})
	}
	response.Choices[0].ChatNonStreamResponseChoice.Message.ChatAssistantMessage = assistant
	return response
}

func ingestUnaryChat(t *testing.T, request string, response *schemas.BifrostChatResponse) *State {
	t.Helper()
	state := resolvedChatValidationState(t, request)
	state.RequestType = string(schemas.ChatCompletionRequest)
	if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ChatResponse: response}, nil); err != nil {
		t.Fatalf("provider response rejected: %v", err)
	}
	return state
}

func TestToolCallChecksFollowEachToolSchema(t *testing.T) {
	for _, tc := range []struct {
		name  string
		calls [][2]string
		want  string
	}{
		{"matches", [][2]string{{"lookup", `{"q":"a","limit":2}`}}, "1 0 - -"},
		{"missing required property", [][2]string{{"lookup", `{"limit":2}`}}, "1 1 - -"},
		{"wrong type", [][2]string{{"lookup", `{"q":3}`}}, "1 1 - -"},
		{"below minimum", [][2]string{{"lookup", `{"q":"a","limit":0}`}}, "1 1 - -"},
		{"integer written as a decimal", [][2]string{{"lookup", `{"q":"a","limit":2.0}`}}, "1 0 - -"},
		{"undeclared property", [][2]string{{"lookup", `{"q":"a","extra":true}`}}, "1 1 - -"},
		{"tool without a schema", [][2]string{{"free", `{"anything":[1,2]}`}}, "1 0 - -"},
		{"one bad call of two", [][2]string{{"lookup", `{"q":"a"}`}, {"lookup", `{}`}}, "2 1 - -"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := ingestUnaryChat(t, checkedToolsRequest, chatToolCallResponse(tc.calls...))
			if got := checkMeters(state); got != tc.want {
				t.Fatalf("checks = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("no calls", func(t *testing.T) {
		state := ingestUnaryChat(t, checkedToolsRequest, validUnaryChatProviderResponse())
		if got := checkMeters(state); got != "- - - -" {
			t.Fatalf("checks = %q for a reply without calls", got)
		}
	})
}

func TestToolCallChecksReadStreamedArgumentsOnceComplete(t *testing.T) {
	run := func(finish bool, fragments ...string) *State {
		state := resolvedChatValidationState(t, checkedToolsRequest)
		state.RequestType = string(schemas.ChatCompletionStreamRequest)
		role := string(schemas.ChatMessageRoleAssistant)
		for index, arguments := range fragments {
			chunk := validChatProviderChunk("chatcmpl_tool", false)
			call := schemas.ChatAssistantMessageToolCall{Function: schemas.ChatAssistantMessageToolCallFunction{Arguments: arguments}}
			chunk.Choices[0].ChatStreamResponseChoice.Delta.Role = nil
			if index == 0 {
				call.Type, call.ID, call.Function.Name = schemas.Ptr("function"), schemas.Ptr("call_1"), schemas.Ptr("lookup")
				chunk.Choices[0].ChatStreamResponseChoice.Delta.Role = &role
			}
			chunk.Choices[0].ChatStreamResponseChoice.Delta.ToolCalls = []schemas.ChatAssistantMessageToolCall{call}
			if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
				t.Fatal(err)
			}
		}
		if finish {
			chunk := validChatProviderChunk("chatcmpl_tool", true)
			chunk.Choices[0].FinishReason = schemas.Ptr("tool_calls")
			if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
				t.Fatal(err)
			}
		}
		return state
	}
	if got := checkMeters(run(true, `{"q":`, `"a"}`)); got != "1 0 - -" {
		t.Fatalf("valid fragments: %q", got)
	}
	if got := checkMeters(run(true, `{"q":`, `1}`)); got != "1 1 - -" {
		t.Fatalf("invalid fragments: %q", got)
	}
	if got := checkMeters(run(false, `{"q":`, `"a"}`)); got != "- - - -" {
		t.Fatalf("unfinished stream was checked: %q", got)
	}
}

func TestStructuredOutputChecksFollowTheResponseFormat(t *testing.T) {
	const schemaFormat = `"response_format":{"type":"json_schema","json_schema":{"name":"answer","strict":true,"schema":{"type":"object","properties":{"city":{"type":"string","enum":["Paris","Rome"]}},"required":["city"],"additionalProperties":false}}}`
	request := func(format string) string {
		return `{"model":"openai/gpt-5.5","messages":[{"role":"user","content":"hi"}],` + format + `}`
	}
	reply := func(finish string, content *string, refusal *string) *schemas.BifrostChatResponse {
		response := validUnaryChatProviderResponse()
		response.Choices[0].FinishReason = schemas.Ptr(finish)
		message := response.Choices[0].ChatNonStreamResponseChoice.Message
		if content != nil {
			message.Content = &schemas.ChatMessageContent{ContentStr: content}
		}
		if refusal != nil {
			message.ChatAssistantMessage = &schemas.ChatAssistantMessage{Refusal: refusal}
		}
		return response
	}
	for _, tc := range []struct {
		name, format, finish string
		content, refusal     *string
		want                 string
	}{
		{"matches", schemaFormat, "stop", schemas.Ptr(` {"city":"Paris"} `), nil, "- - 1 0"},
		{"value outside the enum", schemaFormat, "stop", schemas.Ptr(`{"city":"Lyon"}`), nil, "- - 1 1"},
		{"not JSON", schemaFormat, "stop", schemas.Ptr("Paris"), nil, "- - 1 1"},
		{"fenced JSON", schemaFormat, "stop", schemas.Ptr("```json\n{\"city\":\"Paris\"}\n```"), nil, "- - 1 1"},
		{"two JSON values", schemaFormat, "stop", schemas.Ptr(`{"city":"Paris"}{"city":"Rome"}`), nil, "- - 1 1"},
		{"empty", schemaFormat, "stop", nil, nil, "- - 1 1"},
		{"refusal", schemaFormat, "stop", nil, schemas.Ptr("I can't help with that."), "- - - -"},
		{"cut at the token limit", schemaFormat, "length", schemas.Ptr(`{"city":`), nil, "- - - -"},
		{"content filter", schemaFormat, "content_filter", schemas.Ptr(""), nil, "- - - -"},
		{"JSON mode object", `"response_format":{"type":"json_object"}`, "stop", schemas.Ptr(`{"any":1}`), nil, "- - 1 0"},
		{"JSON mode array", `"response_format":{"type":"json_object"}`, "stop", schemas.Ptr(`[1]`), nil, "- - 1 1"},
		{"text format", `"response_format":{"type":"text"}`, "stop", schemas.Ptr("Paris"), nil, "- - - -"},
		{"no format", `"temperature":1`, "stop", schemas.Ptr("Paris"), nil, "- - - -"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := ingestUnaryChat(t, request(tc.format), reply(tc.finish, tc.content, tc.refusal))
			if got := checkMeters(state); got != tc.want {
				t.Fatalf("checks = %q, want %q", got, tc.want)
			}
		})
	}

	stream := func(t *testing.T, parts []string, refusal string) string {
		t.Helper()
		state := resolvedChatValidationState(t, request(schemaFormat))
		state.RequestType = string(schemas.ChatCompletionStreamRequest)
		for index, part := range parts {
			chunk := validChatProviderChunk("chatcmpl_json", false)
			if index > 0 {
				chunk.Choices[0].ChatStreamResponseChoice.Delta.Role = nil
			}
			chunk.Choices[0].ChatStreamResponseChoice.Delta.Content = schemas.Ptr(part)
			if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
				t.Fatal(err)
			}
		}
		if refusal != "" {
			chunk := validChatProviderChunk("chatcmpl_json", false)
			chunk.Choices[0].ChatStreamResponseChoice.Delta.Role = nil
			chunk.Choices[0].ChatStreamResponseChoice.Delta.Refusal = schemas.Ptr(refusal)
			if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
				t.Fatal(err)
			}
		}
		if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: validChatProviderChunk("chatcmpl_json", true)}); err != nil {
			t.Fatal(err)
		}
		return checkMeters(state)
	}
	if got := stream(t, []string{`{"ci`, `ty":"Rome"}`}, ""); got != "- - 1 0" {
		t.Fatalf("streamed output: %q", got)
	}
	if got := stream(t, []string{`{"city":`, `"Oslo"}`}, ""); got != "- - 1 1" {
		t.Fatalf("streamed invalid output: %q", got)
	}
	if got := stream(t, []string{""}, "No."); got != "- - - -" {
		t.Fatalf("streamed refusal was checked: %q", got)
	}
	t.Run("streamed output past the size bound", func(t *testing.T) {
		state := resolvedChatValidationState(t, request(schemaFormat))
		state.recordChatOutput(`{"city":"`)
		state.recordChatOutput(strings.Repeat("a", maxCheckedValueBytes))
		if state.chatOutput != nil || !state.chatOutputLong {
			t.Fatal("content past the bound stayed buffered")
		}
	})
}

func responsesFunctionItem(id, name, arguments string) schemas.ResponsesMessage {
	item := providerFunctionOutputItem(id, "call_"+id, name)
	item.ResponsesToolMessage.Arguments = schemas.Ptr(arguments)
	return item
}

func responsesMessageItem(id string, blocks ...schemas.ResponsesMessageContentBlock) schemas.ResponsesMessage {
	itemType := schemas.ResponsesMessageTypeMessage
	role := schemas.ResponsesInputMessageRoleAssistant
	return schemas.ResponsesMessage{
		ID: schemas.Ptr(id), Type: &itemType, Status: schemas.Ptr("completed"), Role: &role,
		Content: &schemas.ResponsesMessageContent{ContentBlocks: blocks},
	}
}

func responsesText(text string) schemas.ResponsesMessageContentBlock {
	return schemas.ResponsesMessageContentBlock{Type: schemas.ResponsesOutputMessageContentTypeText, Text: schemas.Ptr(text)}
}

func TestResponsesChecksReadTheCompletedOutput(t *testing.T) {
	request := `{"model":"openai/gpt-5.5","input":"hi","tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}}],` +
		`"text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}}}}`
	refusal := schemas.ResponsesMessageContentBlock{
		Type:                                 schemas.ResponsesOutputMessageContentTypeRefusal,
		ResponsesOutputMessageContentRefusal: &schemas.ResponsesOutputMessageContentRefusal{Refusal: "No."},
	}
	for _, tc := range []struct {
		name   string
		status string
		output []schemas.ResponsesMessage
		want   string
	}{
		{"valid call", schemas.ResponsesResponseStatusCompleted, []schemas.ResponsesMessage{responsesFunctionItem("fc_1", "lookup", `{"q":"a"}`)}, "1 0 - -"},
		{"invalid call", schemas.ResponsesResponseStatusCompleted, []schemas.ResponsesMessage{responsesFunctionItem("fc_1", "lookup", `{"q":[]}`)}, "1 1 - -"},
		{"preamble and call", schemas.ResponsesResponseStatusCompleted, []schemas.ResponsesMessage{
			responsesMessageItem("msg_1", responsesText("Looking it up.")), responsesFunctionItem("fc_1", "lookup", `{"q":"a"}`),
		}, "1 0 - -"},
		{"valid output", schemas.ResponsesResponseStatusCompleted, []schemas.ResponsesMessage{responsesMessageItem("msg_1", responsesText(`{"n":`), responsesText(`4}`))}, "- - 1 0"},
		{"invalid output", schemas.ResponsesResponseStatusCompleted, []schemas.ResponsesMessage{responsesMessageItem("msg_1", responsesText(`{"n":"four"}`))}, "- - 1 1"},
		{"no message", schemas.ResponsesResponseStatusCompleted, nil, "- - 1 1"},
		{"refusal", schemas.ResponsesResponseStatusCompleted, []schemas.ResponsesMessage{responsesMessageItem("msg_1", refusal)}, "- - - -"},
		{"incomplete", schemas.ResponsesResponseStatusIncomplete, []schemas.ResponsesMessage{responsesMessageItem("msg_1", responsesText(`{"n":`))}, "- - - -"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := resolvedResponseValidationState(t, request)
			state.RequestType = string(schemas.ResponsesRequest)
			response := validUnaryResponsesProviderResponse("resp_1")
			response.Status = schemas.Ptr(tc.status)
			if tc.status == schemas.ResponsesResponseStatusIncomplete {
				response.IncompleteDetails = &schemas.ResponsesResponseIncompleteDetails{Reason: schemas.ResponsesResponseIncompleteReasonMaxOutputTokens}
			}
			response.Output = tc.output
			if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: response}, nil); err != nil {
				t.Fatalf("provider response rejected: %v", err)
			}
			if got := checkMeters(state); got != tc.want {
				t.Fatalf("checks = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("stream terminal event", func(t *testing.T) {
		state := resolvedResponseValidationState(t, request)
		state.RequestType = string(schemas.ResponsesStreamRequest)
		state.responsesStreamEnded = true
		terminal := validResponsesProviderEvent(schemas.ResponsesStreamResponseTypeCompleted, 4, "resp_1")
		terminal.Response.Output = []schemas.ResponsesMessage{responsesFunctionItem("fc_1", "lookup", `{}`)}
		state.Response = &schemas.BifrostResponse{ResponsesStreamResponse: terminal}
		if got := checkMeters(state); got != "1 1 - -" {
			t.Fatalf("checks = %q", got)
		}
		terminal.Response.Status = nil
		terminal.Response.StopReason = schemas.Ptr(string(schemas.BifrostFinishReasonToolCalls))
		if got := checkMeters(state); got != "1 1 - -" {
			t.Fatalf("checks without a status = %q", got)
		}
		// Anthropic's wire ends a paused turn with response.completed and no status.
		terminal.Response.StopReason = schemas.Ptr("pause_turn")
		if got := checkMeters(state); got != "- - - -" {
			t.Fatalf("paused turn checks = %q", got)
		}
		state.Response.ResponsesStreamResponse = validResponsesProviderEvent(schemas.ResponsesStreamResponseTypeIncomplete, 4, "resp_1")
		if got := checkMeters(state); got != "- - - -" {
			t.Fatalf("incomplete stream checks = %q", got)
		}
	})
}

func checkWith(t *testing.T, schema, value string) checkResult {
	t.Helper()
	checker := &outputChecker{resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}, budget: checkBudgetSteps}
	return checker.output(structuredOutput{json: true, schema: json.RawMessage(schema)}, []byte(value))
}

func TestStructuredChecksUseStandardSchemaSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, schema, value string
		want                checkResult
	}{
		{"numbers compare by value", `{"const":1}`, `1.0`, checkValid},
		{"objects compare deeply", `{"enum":[{"a":[1,{"b":null}]}]}`, `{"a":[1,{"b":null}]}`, checkValid},
		{"enum mismatch", `{"enum":["a","b"]}`, `"c"`, checkInvalid},
		{"const after a type mismatch", `{"type":"string","const":"a"}`, `1`, checkInvalid},
		{"format is an annotation", `{"type":"string","format":"email"}`, `"not an email"`, checkValid},
		{"local references", `{"$defs":{"n":{"type":"integer"}},"type":"array","items":{"$ref":"#/$defs/n"}}`, `[1,"x"]`, checkInvalid},
		{"recursive schema", `{"$defs":{"node":{"type":"object","properties":{"next":{"$ref":"#/$defs/node"}},"additionalProperties":false}},"$ref":"#/$defs/node"}`, `{"next":{"next":{"bad":1}}}`, checkInvalid},
		{"draft 7", `{"$schema":"http://json-schema.org/draft-07/schema#","definitions":{"n":{"type":"number"}},"properties":{"x":{"$ref":"#/definitions/n"}}}`, `{"x":"1"}`, checkInvalid},
		{"array schemas", `{"type":"array","prefixItems":[{"type":"string"}],"items":{"type":"integer"},"uniqueItems":true}`, `["a",1,1]`, checkInvalid},
		{"one of", `{"oneOf":[{"type":"integer"},{"minimum":0}]}`, `1`, checkInvalid},
		{"remote reference counts as no schema", `{"$ref":"https://example.com/schema.json"}`, `{"x":1}`, checkValid},
		{"file reference counts as no schema", `{"$ref":"file:///etc/passwd"}`, `{"x":1}`, checkValid},
		{"unsupported regular expression counts as no schema", `{"type":"string","pattern":"(?=a)"}`, `"b"`, checkValid},
		{"no schema still needs JSON", `{"$ref":"https://example.com/schema.json"}`, `{"x":`, checkInvalid},
		{"dynamic reference is not checked", `{"$dynamicAnchor":"n","items":{"$dynamicRef":"#n"}}`, `[1]`, checkSkipped},
		{"nesting past the bound", `{}`, strings.Repeat("[", maxCheckedValueDepth+1) + strings.Repeat("]", maxCheckedValueDepth+1), checkSkipped},
		{"nesting at the bound", `{}`, strings.Repeat("[", maxCheckedValueDepth) + strings.Repeat("]", maxCheckedValueDepth), checkValid},
		{"long number", `{}`, "1" + strings.Repeat("0", maxCheckedNumberBytes), checkSkipped},
		{"huge exponent", `{"type":"number"}`, `1e-1000000000`, checkSkipped},
		{"schema with a huge exponent", `{"multipleOf":1e-1000000000}`, `1`, checkSkipped},
		{"value past the size bound", `{}`, `"` + strings.Repeat("a", maxCheckedValueBytes) + `"`, checkSkipped},
		{"schema past the size bound", `{"description":"` + strings.Repeat("a", maxCheckedSchemaBytes) + `"}`, `1`, checkSkipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkWith(t, tc.schema, tc.value); got != tc.want {
				t.Fatalf("check = %d, want %d", got, tc.want)
			}
		})
	}
}

// Request schemas are untrusted. Each case would take minutes, or exhaust the
// stack, without the bounds; with them each must end quickly as not checked.
func TestStructuredChecksStayBoundedForHostileSchemas(t *testing.T) {
	// doubling applies each level's subschema twice, so a naive validator does
	// 2^40 evaluations. root decides how the document starts the chain.
	doubling := func(combinator, leaf, root string) string {
		var defs []string
		for level := range 40 {
			next := fmt.Sprintf(`{"$ref":"#/$defs/s%d"}`, level+1)
			defs = append(defs, fmt.Sprintf(`"s%d":{"%s":[%s,%s]}`, level, combinator, next, next))
		}
		defs = append(defs, `"s40":`+leaf)
		return `{"$defs":{` + strings.Join(defs, ",") + `},` + root + `}`
	}
	const start = `"$ref":"#/$defs/s0"`
	chain := func(length int) string {
		var defs []string
		for level := range length {
			defs = append(defs, fmt.Sprintf(`"c%d":{"$ref":"#/$defs/c%d"}`, level, level+1))
		}
		defs = append(defs, fmt.Sprintf(`"c%d":{"items":{"$ref":"#/$defs/c0"}}`, length))
		return `{"$defs":{` + strings.Join(defs, ",") + `},"$ref":"#/$defs/c0"}`
	}
	enum := make([]string, 1000)
	for index := range enum {
		enum[index] = fmt.Sprintf(`"value-%04d"`, index)
	}
	patterns := make([]string, 500)
	for index := range patterns {
		patterns[index] = fmt.Sprintf(`"^p%d(a|b)*$":{}`, index)
	}
	properties := make([]string, 5000)
	for index := range properties {
		properties[index] = fmt.Sprintf(`"k%d":0`, index)
	}
	for _, tc := range []struct {
		name, schema, value string
		want                checkResult
	}{
		{"all of doubles every level", doubling("allOf", "{}", start), `{}`, checkSkipped},
		{"any of with failing branches", doubling("anyOf", "false", start), `{}`, checkSkipped},
		{"negated any of", doubling("anyOf", "false", `"not":{"$ref":"#/$defs/s0"}`), `{}`, checkSkipped},
		{"long reference chain on a nested value", chain(2000), `[[[1]]]`, checkSkipped},
		{"short reference chain on a nested value", chain(100), `[[[1]]]`, checkValid},
		{"large pattern on a long string", `{"pattern":"` + strings.Repeat("(a|b)", 2000) + `x"}`, `"` + strings.Repeat("ab", 400_000) + `"`, checkSkipped},
		{"large enum on many items", `{"items":{"enum":[` + strings.Join(enum, ",") + `]}}`, `[` + strings.Repeat(`"value-0999",`, 20_000) + `"x"]`, checkSkipped},
		{"many pattern properties", `{"patternProperties":{` + strings.Join(patterns, ",") + `}}`, `{` + strings.Join(properties, ",") + `}`, checkSkipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Now()
			if got := checkWith(t, tc.schema, tc.value); got != tc.want {
				t.Fatalf("check = %d, want %d", got, tc.want)
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("check took %s", elapsed)
			}
		})
	}

	t.Run("one request shares the budget", func(t *testing.T) {
		checker := &outputChecker{resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}, budget: checkBudgetSteps}
		hostile := structuredOutput{json: true, schema: json.RawMessage(doubling("allOf", "{}", start))}
		if got := checker.output(hostile, []byte(`{}`)); got != checkSkipped {
			t.Fatalf("hostile check = %d", got)
		}
		if got := checker.output(structuredOutput{json: true, schema: json.RawMessage(`{"type":"object"}`)}, []byte(`{}`)); got != checkSkipped {
			t.Fatalf("check after the budget ran out = %d", got)
		}
	})

	t.Run("compiling charges the budget", func(t *testing.T) {
		checker := &outputChecker{resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}, budget: checkBudgetSteps}
		schema := json.RawMessage(`{"description":"` + strings.Repeat("a", maxCheckedSchemaBytes-100) + `"}`)
		for range checkBudgetSteps / (2 * maxCheckedSchemaBytes) {
			if compiled := checker.compile(schema); compiled.skip || compiled.schema == nil {
				t.Fatal("schema within the budget was not compiled")
			}
		}
		if !checker.compile(schema).skip {
			t.Fatal("schema past the budget was compiled")
		}
	})
}

func TestBoundedNumberLimitsExponents(t *testing.T) {
	for literal, want := range map[string]bool{
		"0": true, "-12.5": true, "1e400": true, "1E-400": true, "1e401": false, "1e-401": false,
		"1e99999999999999999999": false, strings.Repeat("9", maxCheckedNumberBytes): true,
		strings.Repeat("9", maxCheckedNumberBytes+1): false,
	} {
		if got := boundedNumber(literal); got != want {
			t.Errorf("boundedNumber(%q) = %v, want %v", literal, got, want)
		}
	}
}
