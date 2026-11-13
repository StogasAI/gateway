package stogas

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

// testAccount is the provider account that the credential of every test pair reaches.
const testAccount = "acct-test"

// boundReasoning is OpenAI's encrypted reasoning that the test account produced, as a reply returns
// it.
func boundReasoning(content string) string {
	return "openai:" + testAccount + ":" + content
}

// testPair is the state of a pair whose credential reaches the test account.
func testPair(resolution *catalog.ResolvedRequest) *State {
	resolution.SetAccountTag(testAccount)
	return NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
}

// providerBody passes a request on path through its checks and returns the body that its provider
// gets, with the context of the provider call.
func providerBody(t *testing.T, path, body string) (map[string]json.RawMessage, *schemas.BifrostContext, *State) {
	t.Helper()
	return providerBodyOf(t, catalog.RequestInput{Method: "POST", Path: path, Body: []byte(body)})
}

// providerBodyOf is providerBody for a request with other input, such as a redaction policy.
func providerBodyOf(t *testing.T, input catalog.RequestInput) (map[string]json.RawMessage, *schemas.BifrostContext, *State) {
	t.Helper()
	resolution, err := catalog.ResolveRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	state := testPair(resolution)
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatal(err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatal(err)
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.WireRequestType())
	request, err := resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatal(err)
	}
	var prepared []byte
	if request.ChatRequest != nil {
		prepared = preparedProviderBody(t, ctx, request.ChatRequest)
	} else {
		prepared = preparedProviderBody(t, ctx, request.ResponsesRequest)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(prepared, &fields); err != nil {
		t.Fatal(err)
	}
	return fields, ctx, state
}

// requestCheckError is the error of the checks of a request on path.
func requestCheckError(t *testing.T, path, body string) error {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: path, Body: []byte(body)})
	if err != nil {
		return err
	}
	state := testPair(resolution)
	return state.Adapter.ValidateRequest(state)
}

// claudeThinkingContent is the encrypted content of the reasoning item in which a Claude reply
// returns a thinking block.
func claudeThinkingContent(t *testing.T, thinking string) string {
	t.Helper()
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	anthropic.SetOpenAIReasoning(ctx, true)
	var message anthropic.AnthropicMessageResponse
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{"id":"msg_01","type":"message","role":"assistant","model":"claude-sonnet-4-6",`+
		`"content":[{"type":"thinking","thinking":%q,"signature":"sig-%s"},{"type":"text","text":"Hi."}],`+
		`"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`, thinking, thinking)), &message); err != nil {
		t.Fatal(err)
	}
	for _, item := range message.ToBifrostResponsesResponse(ctx).Output {
		if item.ResponsesReasoning != nil && item.ResponsesReasoning.EncryptedContent != nil {
			return *item.ResponsesReasoning.EncryptedContent
		}
	}
	t.Fatal("the reply has no encrypted reasoning")
	return ""
}

// assistantBlocks are the content blocks of the assistant turns of an Anthropic body, joined as
// Anthropic joins consecutive messages of one role.
func assistantBlocks(t *testing.T, body map[string]json.RawMessage) [][]map[string]json.RawMessage {
	t.Helper()
	var messages []struct {
		Role    string                       `json:"role"`
		Content []map[string]json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(body["messages"], &messages); err != nil {
		t.Fatal(err)
	}
	var turns [][]map[string]json.RawMessage
	for index, message := range messages {
		if message.Role != "assistant" {
			continue
		}
		if index > 0 && messages[index-1].Role == "assistant" {
			turns[len(turns)-1] = append(turns[len(turns)-1], message.Content...)
		} else {
			turns = append(turns, message.Content)
		}
	}
	return turns
}

// blockFields reads the named fields of each block, so that a comparison ignores the fields that
// core adds, such as cache controls.
func blockFields(blocks []map[string]json.RawMessage, names ...string) string {
	var fields []string
	for _, block := range blocks {
		var parts []string
		for _, name := range names {
			if value, ok := block[name]; ok {
				parts = append(parts, name+"="+string(value))
			}
		}
		fields = append(fields, strings.Join(parts, " "))
	}
	return strings.Join(fields, "\n")
}

const weatherTool = `"tools":[{"type":"function","name":"get_weather","description":"Look up the weather.",` +
	`"parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}]`

// A Claude turn with signed thinking, redacted thinking, text, an omitted progress update and a
// tool call, streamed as Anthropic streams it.
var claudeToolTurnStream = []string{
	`{"type":"message_start","message":{"id":"msg_01round","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":1}}}`,
	`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`,
	`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Look up "}}`,
	`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Paris."}}`,
	`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"EqQBsig"}}`,
	`{"type":"content_block_stop","index":0}`,
	`{"type":"content_block_start","index":1,"content_block":{"type":"redacted_thinking","data":"EmwKAhgB"}}`,
	`{"type":"content_block_stop","index":1}`,
	`{"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`,
	`{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"Checking."}}`,
	`{"type":"content_block_stop","index":2}`,
	`{"type":"content_block_start","index":3,"content_block":{"type":"thinking","thinking":"","signature":""}}`,
	`{"type":"content_block_delta","index":3,"delta":{"type":"thinking_delta","thinking":""}}`,
	`{"type":"content_block_delta","index":3,"delta":{"type":"signature_delta","signature":"EqQBupdate"}}`,
	`{"type":"content_block_stop","index":3}`,
	`{"type":"content_block_start","index":4,"content_block":{"type":"tool_use","id":"toolu_01","name":"get_weather","input":{}}}`,
	`{"type":"content_block_delta","index":4,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"Paris\"}"}}`,
	`{"type":"content_block_stop","index":4}`,
	`{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":40}}`,
	`{"type":"message_stop"}`,
}

// A Responses client, such as Codex, gets each of Claude's thinking blocks as one of OpenAI's
// reasoning items, which pass the gateway's checks of the reply. The next request sends the blocks
// that start the turn back to Anthropic exactly as Claude returned them, with the text and the tool
// call, and leaves out the progress update after the text, which Anthropic allows.
func TestClaudeReasoningRoundTripsThroughResponses(t *testing.T) {
	request := `{"model":"anthropic-claude-sonnet-4-6","reasoning":{"effort":"medium"},"include":["reasoning.encrypted_content"],` +
		`"max_output_tokens":2048,"stream":true,` + weatherTool + `,"input":[{"role":"user","content":"Weather in Paris?"}]}`
	body, ctx, state := providerBody(t, "/v1/responses", request)
	if _, ok := body["include"]; ok {
		t.Fatalf("include reached Anthropic: %s", body["include"])
	}
	streamState := anthropic.AcquireAnthropicResponsesStreamState()
	defer anthropic.ReleaseAnthropicResponsesStreamState(streamState)
	var output []schemas.ResponsesMessage
	sequence := 0
	for _, line := range claudeToolTurnStream {
		var event anthropic.AnthropicStreamEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		chunks, bifrostErr, _ := event.ToBifrostResponsesStream(ctx, sequence, streamState)
		if bifrostErr != nil {
			t.Fatalf("convert %s: %v", event.Type, bifrostErr.Error)
		}
		for _, chunk := range chunks {
			if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: chunk}); err != nil {
				t.Fatalf("ingest %s: %v", chunk.Type, err)
			}
			if chunk.Type == schemas.ResponsesStreamResponseTypeCompleted {
				output = chunk.Response.Output
			}
		}
		sequence += len(chunks)
	}
	if len(output) != 5 {
		t.Fatalf("output = %d items, want reasoning, reasoning, message, reasoning, function call", len(output))
	}
	items := make([]string, 0, len(output))
	for _, item := range output {
		encoded, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, string(encoded))
	}
	next := `{"model":"anthropic-claude-sonnet-4-6","reasoning":{"effort":"medium"},"include":["reasoning.encrypted_content"],"max_output_tokens":2048,` +
		weatherTool + `,"input":[{"role":"user","content":"Weather in Paris?"},` + strings.Join(items, ",") +
		`,{"type":"function_call_output","call_id":"toolu_01","output":"18 C and sunny"}]}`
	nextBody, _, _ := providerBody(t, "/v1/responses", next)
	turns := assistantBlocks(t, nextBody)
	got := blockFields(turns[0], "type", "thinking", "signature", "data", "text", "id", "name", "input")
	want := strings.Join([]string{
		`type="thinking" thinking="Look up Paris." signature="EqQBsig"`,
		`type="redacted_thinking" data="EmwKAhgB"`,
		`type="text" text="Checking."`,
		`type="tool_use" id="toolu_01" name="get_weather" input={"city":"Paris"}`,
	}, "\n")
	if len(turns) != 1 || got != want {
		t.Fatalf("assistant blocks =\n%s\nwant\n%s", got, want)
	}
}

// One input with Claude's, OpenAI's and plain reasoning: each deployment gets only the reasoning
// that it takes back. OpenAI-format deployments get only the encrypted reasoning of their own
// account, with the provider's own content, and never another account's or content that the gateway
// did not bind.
func TestResponsesDeploymentsGetOnlyReasoningTheyTakeBack(t *testing.T) {
	input := `"input":[{"role":"user","content":"hi"},` +
		`{"type":"reasoning","id":"rs_claude","summary":[{"type":"summary_text","text":"Plan."}],"encrypted_content":"` + claudeThinkingContent(t, "Plan.") + `"},` +
		`{"type":"reasoning","id":"rs_openai","summary":[],"encrypted_content":"` + boundReasoning("gAAAAopaque") + `"},` +
		`{"type":"reasoning","id":"rs_other","summary":[],"encrypted_content":"openai:acct-other:gAAAAother"},` +
		`{"type":"reasoning","id":"rs_unbound","summary":[],"encrypted_content":"gAAAAunbound"},` +
		`{"type":"reasoning","id":"rs_plain","summary":[],"content":[{"type":"reasoning_text","text":"Thinking."}]},` +
		`{"role":"assistant","content":[{"type":"output_text","text":"Hello."}]},{"role":"user","content":"again"}]`

	body, _, _ := providerBody(t, "/v1/responses", `{"model":"anthropic-claude-sonnet-4-6",`+input+`}`)
	if got := blockFields(assistantBlocks(t, body)[0], "type", "thinking", "signature", "text"); got != `type="thinking" thinking="Plan." signature="sig-Plan."`+"\n"+`type="text" text="Hello."` {
		t.Fatalf("Claude's assistant blocks =\n%s", got)
	}
	for _, model := range []string{"provider:openai gpt-5.5", "azure-gpt-5.6-sol"} {
		body, _, _ := providerBody(t, "/v1/responses", `{"model":"`+model+`",`+input+`}`)
		var items []map[string]json.RawMessage
		if err := json.Unmarshal(body["input"], &items); err != nil {
			t.Fatal(err)
		}
		var reasoning []string
		for _, item := range items {
			if string(item["type"]) == `"reasoning"` {
				reasoning = append(reasoning, string(item["id"])+"="+string(item["encrypted_content"]))
			}
		}
		if got := strings.Join(reasoning, ","); got != `"rs_openai"="gAAAAopaque"` || !strings.Contains(string(body["input"]), `"Hello."`) {
			t.Fatalf("%s input = %s", model, body["input"])
		}
	}
}

// One Chat Completions history with Claude's, OpenAI's and plain reasoning: each deployment gets
// only the reasoning that it takes back, and an assistant message that held only reasoning that a
// deployment cannot read goes, since providers refuse an empty one.
func TestChatDeploymentsGetOnlyReasoningTheyTakeBack(t *testing.T) {
	messages := `"messages":[{"role":"user","content":"hi"},` +
		`{"role":"assistant","content":"Hello.","reasoning":"Greet.","reasoning_details":[{"index":0,"type":"reasoning.text","text":"Greet.","signature":"sig"},{"index":1,"type":"reasoning.encrypted","data":"redacted"}]},` +
		`{"role":"user","content":"Go on."},` +
		`{"role":"assistant","content":"More.","reasoning_details":[{"index":0,"type":"reasoning.encrypted","id":"rs_1","data":"gAAAAopaque"},` +
		`{"index":1,"type":"reasoning.encrypted","data":"` + boundReasoning("gAAAAwithout-id") + `"}]},` +
		`{"role":"user","content":"And?"},` +
		`{"role":"assistant","reasoning":"Plain thought."},` +
		`{"role":"user","content":"Done?"}]`

	body, _, _ := providerBody(t, "/v1/chat/completions", `{"model":"anthropic-claude-sonnet-4-6",`+messages+`}`)
	turns := assistantBlocks(t, body)
	got := make([]string, 0, len(turns))
	for _, turn := range turns {
		got = append(got, blockFields(turn, "type", "thinking", "signature", "data", "text"))
	}
	want := []string{
		`type="thinking" thinking="Greet." signature="sig"` + "\n" + `type="redacted_thinking" data="redacted"` + "\n" + `type="text" text="Hello."`,
		`type="text" text="More."`,
	}
	if strings.Join(got, "\n--\n") != strings.Join(want, "\n--\n") {
		t.Fatalf("Claude's assistant turns =\n%s", strings.Join(got, "\n--\n"))
	}

	body, _, _ = providerBody(t, "/v1/chat/completions", `{"model":"chutes-glm-5.2",`+messages+`}`)
	var wire []map[string]json.RawMessage
	if err := json.Unmarshal(body["messages"], &wire); err != nil {
		t.Fatal(err)
	}
	var reasoning []string
	for _, message := range wire {
		if string(message["role"]) == `"assistant"` {
			reasoning = append(reasoning, string(message["reasoning_content"]))
		}
		if message["reasoning_details"] != nil || message["reasoning"] != nil {
			t.Fatalf("Chutes messages = %s", body["messages"])
		}
	}
	if strings.Join(reasoning, ",") != `,,"Plain thought."` {
		t.Fatalf("Chutes reasoning = %s", strings.Join(reasoning, ","))
	}
}

// Reasoning history passes the same checks on every deployment, so whether a request is valid
// never depends on the deployment that routing picks.
func TestReasoningHistoryChecksAreTheSameOnEveryDeployment(t *testing.T) {
	for _, test := range []struct{ name, path, fields, want string }{
		{"altered Claude block", "/v1/responses", `"input":[{"role":"user","content":"hi"},{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"claude:e30"},` +
			`{"role":"assistant","content":"Hello."},{"role":"user","content":"again"}]`, "input[1].encrypted_content must be sent back unchanged"},
		{"summary detail", "/v1/chat/completions", `"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hello.",` +
			`"reasoning_details":[{"index":0,"type":"reasoning.summary","summary":"Plan."}]},{"role":"user","content":"again"}]`, "reasoning_details[0].type must be reasoning.text or reasoning.encrypted"},
		{"empty signature", "/v1/chat/completions", `"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hello.",` +
			`"reasoning_details":[{"index":0,"type":"reasoning.text","text":"Plan.","signature":""}]},{"role":"user","content":"again"}]`, "signature"},
		{"altered account item", "/v1/responses", `"input":[{"role":"user","content":"hi"},{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"openai:acct-test"},` +
			`{"role":"assistant","content":"Hello."},{"role":"user","content":"again"}]`, "input[1].encrypted_content must be sent back unchanged"},
		{"altered account detail", "/v1/chat/completions", `"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hello.",` +
			`"reasoning_details":[{"index":0,"type":"reasoning.encrypted","id":"rs_1","data":"openai::gAAAA"}]},{"role":"user","content":"again"}]`, "reasoning_details[0].data must be sent back unchanged"},
	} {
		for _, model := range []string{"anthropic-claude-sonnet-4-6", "provider:openai gpt-5.5", "azure-gpt-5.6-sol", "chutes-glm-5.2"} {
			t.Run(test.name+"/"+model, func(t *testing.T) {
				err := requestCheckError(t, test.path, `{"model":"`+model+`",`+test.fields+`}`)
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error = %v, want %q", err, test.want)
				}
			})
		}
	}
}

// A reply to a Responses request that did not include reasoning.encrypted_content returns reasoning
// items with a summary at most, and a client that appends the reply's output to its input sends
// them back. They hold nothing to continue from, so every deployment takes the request and gets
// the rest of the input. Plain reasoning reaches Chutes without the summary beside it.
func TestReasoningItemsWithNothingToContinueFromAreLeftOut(t *testing.T) {
	input := `"input":[{"role":"user","content":"Weather in Paris?"},` +
		`{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"Look it up."}]},` +
		`{"id":"rs_2","type":"reasoning","summary":[],"encrypted_content":null},` +
		`{"id":"rs_3","type":"reasoning","summary":[{"type":"summary_text","text":"Shown."}],"content":[{"type":"reasoning_text","text":"Paris, then."}]},` +
		`{"type":"function_call","call_id":"call_1","name":"get_weather","arguments":"{\"city\":\"Paris\"}"},` +
		`{"type":"function_call_output","call_id":"call_1","output":"18 C and sunny"}]`
	for _, model := range []string{"anthropic-claude-sonnet-4-6", "provider:openai gpt-5.5", "azure-gpt-5.6-sol", "chutes-glm-5.2"} {
		body, _, _ := providerBody(t, "/v1/responses", `{"model":"`+model+`",`+weatherTool+`,`+input+`}`)
		history := string(body["input"]) + string(body["messages"])
		if !strings.Contains(history, "get_weather") || !strings.Contains(history, "18 C and sunny") {
			t.Fatalf("%s lost the tool call or its result: %s", model, history)
		}
		for _, gone := range []string{"Look it up.", "Shown.", "rs_1", "rs_2"} {
			if strings.Contains(history, gone) {
				t.Fatalf("%s got %q: %s", model, gone, history)
			}
		}
		if plain := strings.Contains(history, "Paris, then."); plain != (model == "chutes-glm-5.2") {
			t.Fatalf("%s plain reasoning sent = %v: %s", model, plain, history)
		}
	}
}

// An empty reasoning_details or annotations array holds nothing: a client's stream accumulator
// leaves the first for a reply without reasoning, and OpenAI's own replies carry the second.
func TestEmptyReplyArraysInChatHistoryAreAccepted(t *testing.T) {
	messages := `"messages":[{"role":"user","content":"hi"},` +
		`{"role":"assistant","content":"Hello.","refusal":null,"annotations":[],"reasoning_details":[]},` +
		`{"role":"user","content":"again"}]`
	for _, model := range []string{"anthropic-claude-sonnet-4-6", "provider:openai gpt-5.5", "azure-gpt-5.6-sol", "chutes-glm-5.2"} {
		body, _, _ := providerBody(t, "/v1/chat/completions", `{"model":"`+model+`",`+messages+`}`)
		history := string(body["input"]) + string(body["messages"])
		if !strings.Contains(history, "Hello.") || strings.Contains(history, "annotations") || strings.Contains(history, "reasoning_details") {
			t.Fatalf("%s history = %s", model, history)
		}
	}
	if err := requestCheckError(t, "/v1/chat/completions", `{"model":"chutes-glm-5.2","messages":[{"role":"user","content":"hi"},{"role":"assistant","reasoning_details":[]},{"role":"user","content":"again"}]}`); err == nil {
		t.Fatal("an assistant message with nothing in it was accepted")
	}
}

// TestChatReplyWithReasoningTextGoesBackUnchanged sends a reply's message back as a client that
// appends it to its history does. A reply carries reasoning text under both of its names,
// reasoning and reasoning_content, so a request takes both, and either alone.
func TestChatReplyWithReasoningTextGoesBackUnchanged(t *testing.T) {
	reply, err := sonic.Marshal(schemas.ChatMessage{
		Role:    schemas.ChatMessageRoleAssistant,
		Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("4")},
		ChatAssistantMessage: &schemas.ChatAssistantMessage{
			Reasoning:        schemas.Ptr("two and two"),
			ReasoningDetails: []schemas.ChatReasoningDetails{{Index: 0, Type: schemas.BifrostReasoningDetailsTypeText, Text: schemas.Ptr("two and two")}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(reply, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["reasoning"]) != `"two and two"` || string(fields["reasoning_content"]) != `"two and two"` {
		t.Fatalf("a reply carries reasoning under both names, got %s", reply)
	}
	conversation := func(assistant string) string {
		return `"messages":[{"role":"user","content":"2+2?"},` + assistant + `,{"role":"user","content":"again"}]`
	}
	for _, model := range []string{"anthropic-claude-sonnet-4-6", "provider:openai gpt-5.5", "azure-gpt-5.6-sol", "chutes-glm-5.2"} {
		for name, assistant := range map[string]string{
			"the reply":              string(reply),
			"reasoning_content only": `{"role":"assistant","content":"4","reasoning_content":"two and two"}`,
			"reasoning only":         `{"role":"assistant","content":"4","reasoning":"two and two"}`,
		} {
			if err := requestCheckError(t, "/v1/chat/completions", `{"model":"`+model+`",`+conversation(assistant)+`}`); err != nil {
				t.Errorf("%s, %s: %v", model, name, err)
			}
		}
		for name, assistant := range map[string]string{
			"names that disagree": `{"role":"assistant","content":"4","reasoning":"two and two","reasoning_content":"five"}`,
			"not a string":        `{"role":"assistant","content":"4","reasoning_content":["two and two"]}`,
		} {
			if err := requestCheckError(t, "/v1/chat/completions", `{"model":"`+model+`",`+conversation(assistant)+`}`); err == nil {
				t.Errorf("%s, %s: accepted", model, name)
			}
		}
	}

	// Chutes takes plain reasoning back, once, whichever name the client used.
	for _, assistant := range []string{string(reply), `{"role":"assistant","content":"4","reasoning_content":"two and two"}`} {
		body, _, _ := providerBody(t, "/v1/chat/completions", `{"model":"chutes-glm-5.2",`+conversation(assistant)+`}`)
		var wire []map[string]json.RawMessage
		if err := json.Unmarshal(body["messages"], &wire); err != nil {
			t.Fatal(err)
		}
		if string(wire[1]["reasoning_content"]) != `"two and two"` || wire[1]["reasoning"] != nil || wire[1]["reasoning_details"] != nil {
			t.Fatalf("Chutes assistant message = %s", body["messages"])
		}
	}
}

// recordedReasoningItem is the reasoning item of a recorded request's input, decoded.
func recordedReasoningItem(t *testing.T, body json.RawMessage) (item any, encrypted string) {
	t.Helper()
	var request struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	for _, raw := range request.Input {
		var fields struct {
			Type             string `json:"type"`
			EncryptedContent string `json:"encrypted_content"`
		}
		if json.Unmarshal(raw, &fields) == nil && fields.Type == "reasoning" {
			if err := json.Unmarshal(raw, &item); err != nil {
				t.Fatal(err)
			}
			return item, fields.EncryptedContent
		}
	}
	t.Fatalf("no reasoning item in %s", body)
	return nil, ""
}

// forGateway turns a recorded provider request into the request that a client of the gateway
// sends for it: the gateway's model, and encrypted reasoning as a reply of the test account
// returned it.
func forGateway(t *testing.T, body json.RawMessage, model, encrypted string) string {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	fields["model"], _ = json.Marshal(model)
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == "" {
		return string(out)
	}
	return strings.Replace(string(out), encrypted, boundReasoning(encrypted), 1)
}

// TestRecordedEncryptedReasoningGoesBackAsTheProviderTookIt replays exchanges recorded from OpenAI
// and Azure. The gateway returns the recorded reply's encrypted reasoning bound to its account, and
// sends a client's copy of it back as the very item that the provider took in the recording, from
// a Responses item and from a Chat Completions reasoning detail with or without its id.
func TestRecordedEncryptedReasoningGoesBackAsTheProviderTookIt(t *testing.T) {
	for _, test := range []struct{ capture, model string }{
		{"openai/encrypted-reasoning-replay", "provider:openai gpt-6-luna"},
		{"azure/encrypted-reasoning-replay", "azure-gpt-5.6-sol"},
	} {
		t.Run(test.capture, func(t *testing.T) {
			exchanges := providerCapture(t, test.capture)
			for _, name := range []string{"replay as returned", "replay without id", "replay as the gateway sends it", "replay as the gateway sends it without id"} {
				if status := exchange(t, exchanges, name).Response.Status; status != 200 {
					t.Fatalf("%s: the provider answered %d in the recording", name, status)
				}
			}
			for _, name := range []string{"replay changed content", "replay another id", "replay without summary"} {
				if status := exchange(t, exchanges, name).Response.Status; status != 400 {
					t.Fatalf("%s: the provider answered %d in the recording", name, status)
				}
			}

			mint := exchange(t, exchanges, "mint")
			resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(forGateway(t, mint.Request.Body, test.model, ""))})
			if err != nil {
				t.Fatal(err)
			}
			state := testPair(resolution)
			if err := state.Adapter.ValidateRequest(state); err != nil {
				t.Fatal(err)
			}
			reply := mint.responsesReply(t)
			if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ResponsesResponse: reply}, nil); err != nil {
				t.Fatalf("recorded reply refused: %v", err)
			}
			withID, encrypted := recordedReasoningItem(t, exchange(t, exchanges, "replay as the gateway sends it").Request.Body)
			withoutID, _ := recordedReasoningItem(t, exchange(t, exchanges, "replay as the gateway sends it without id").Request.Body)
			var id, callID string
			for _, item := range reply.Output {
				switch {
				case item.ResponsesReasoning != nil && item.ResponsesReasoning.EncryptedContent != nil:
					if got := *item.ResponsesReasoning.EncryptedContent; got != boundReasoning(encrypted) {
						t.Fatalf("the reply's reasoning is not bound to its account: %.40s", got)
					}
					id = *item.ID
				case item.ResponsesToolMessage != nil && item.ResponsesToolMessage.CallID != nil:
					callID = *item.ResponsesToolMessage.CallID
				}
			}
			if id == "" || callID == "" {
				t.Fatalf("the recorded reply needs reasoning and a call, got %d items", len(reply.Output))
			}

			sent := func(path, body string) any {
				t.Helper()
				fields, _, _ := providerBody(t, path, body)
				item, _ := recordedReasoningItem(t, json.RawMessage(`{"input":`+string(fields["input"])+`}`))
				return item
			}
			if got := sent("/v1/responses", forGateway(t, exchange(t, exchanges, "replay as returned").Request.Body, test.model, encrypted)); !reflect.DeepEqual(got, withID) {
				t.Fatalf("Responses item sent = %v, the provider took %v", got, withID)
			}
			chat := func(detailID string) string {
				return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"},{"role":"assistant","reasoning_details":[{"type":"reasoning.encrypted","index":0,"data":%q%s}],"tool_calls":[{"id":%q,"type":"function","function":{"name":"get_secret_number","arguments":"{}"}}]},{"role":"tool","tool_call_id":%q,"content":"41"}],"tools":[{"type":"function","function":{"name":"get_secret_number","parameters":{"type":"object","properties":{}}}}]}`,
					test.model, boundReasoning(encrypted), detailID, callID, callID)
			}
			if got := sent("/v1/chat/completions", chat(`,"id":"`+id+`"`)); !reflect.DeepEqual(got, withID) {
				t.Fatalf("Chat detail sent = %v, the provider took %v", got, withID)
			}
			if got := sent("/v1/chat/completions", chat("")); !reflect.DeepEqual(got, withoutID) {
				t.Fatalf("Chat detail without id sent = %v, the provider took %v", got, withoutID)
			}
		})
	}
}

// Redaction runs before the request's checks, which compare a message's reasoning text with its
// details and with its other name. A Claude reply that comes back unchanged keeps its signed
// thinking and passes, and reasoning without a signature reaches its provider redacted.
func TestRedactionScansOnlyReasoningHistoryWithoutASignature(t *testing.T) {
	policy, err := redaction.CompilePolicy(redaction.Options{Patterns: []redaction.Pattern{redaction.PatternEmailAddress}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(model, assistant string) catalog.RequestInput {
		return catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", RedactionPolicy: policy, Body: []byte(`{"model":"` + model + `","messages":[` +
			`{"role":"user","content":"Who owns the repository?"},` + assistant + `,{"role":"user","content":"Thanks."}]}`)}
	}

	body, _, _ := providerBodyOf(t, request("anthropic-claude-sonnet-5", `{"role":"assistant","content":"The owner.",`+
		`"reasoning":"Mail owner@corp.io.","reasoning_content":"Mail owner@corp.io.",`+
		`"reasoning_details":[{"index":0,"type":"reasoning.text","text":"Mail owner@corp.io.","signature":"sig"}]}`))
	if thinking := rawString(assistantBlocks(t, body)[0][0]["thinking"]); thinking != "Mail owner@corp.io." {
		t.Fatalf("signed thinking = %q", thinking)
	}

	body, _, _ = providerBodyOf(t, request("chutes-glm-5.2", `{"role":"assistant","content":"The owner.",`+
		`"reasoning":"Mail owner@corp.io.","reasoning_content":"Mail owner@corp.io.",`+
		`"reasoning_details":[{"index":0,"type":"reasoning.text","text":"Mail owner@corp.io."}]}`))
	if messages := string(body["messages"]); strings.Contains(messages, "owner@corp.io") || !strings.Contains(messages, "Mail <EMAIL_ADDRESS>.") {
		t.Fatalf("plain reasoning reached the provider as %s", messages)
	}
}
