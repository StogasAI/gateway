package stogas

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/bytedance/sonic"

	"github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/schemas"
)

// Anthropic opens thinking blocks with an empty signature and reports the stop
// reason after every block has closed, as its streaming documentation shows.
var anthropicTruncatedThinkingStream = []string{
	`{"type":"message_start","message":{"id":"msg_01thinking","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":1}}}`,
	`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`,
	`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"The user wants a greeting."}}`,
	`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"EqQBCgIYAhIM"}}`,
	`{"type":"content_block_stop","index":0}`,
	`{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
	`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hello"}}`,
	`{"type":"content_block_stop","index":1}`,
	`{"type":"message_delta","delta":{"stop_reason":"max_tokens","stop_sequence":null},"usage":{"output_tokens":24}}`,
	`{"type":"message_stop"}`,
}

func TestAnthropicThinkingResponsesStreamPassesValidation(t *testing.T) {
	_, ctx, state := providerBody(t, "/v1/responses", `{"model":"anthropic-claude-sonnet-4-6","input":"hi","reasoning":{"effort":"medium"},"max_output_tokens":2048,"stream":true}`)
	streamState := anthropic.AcquireAnthropicResponsesStreamState()
	defer anthropic.ReleaseAnthropicResponsesStreamState(streamState)

	sequence := 0
	var terminal schemas.ResponsesStreamResponseType
	for _, line := range anthropicTruncatedThinkingStream {
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
			terminal = chunk.Type
		}
		sequence += len(chunks)
	}
	if terminal != schemas.ResponsesStreamResponseTypeIncomplete {
		t.Fatalf("terminal event = %s, want response.incomplete", terminal)
	}
}

func TestAnthropicThinkingChatResponsePassesValidation(t *testing.T) {
	state := resolvedChatValidationState(t, `{"model":"anthropic-claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"medium"}`)
	var message anthropic.AnthropicMessageResponse
	if err := json.Unmarshal([]byte(`{"id":"msg_01thinking","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"thinking","thinking":"The user wants a greeting.","signature":"EqQBCgIYAhIM"},{"type":"text","text":"Hello"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":24}}`), &message); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := schemas.NewBifrostContextWithCancel(context.Background())
	defer cancel()
	response := message.ToBifrostChatResponse(ctx)
	response.BackfillParams(&schemas.BifrostChatRequest{Model: "claude-sonnet-4-6"})
	if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ChatResponse: response}, nil); err != nil {
		t.Fatal(err)
	}
	if reasoning := response.Choices[0].Message.Reasoning; reasoning == nil || *reasoning != "The user wants a greeting." {
		t.Fatalf("reasoning = %v, want the thinking text", reasoning)
	}
}

// Claude writes a progress update as a thinking block right before the tool call it introduces,
// so one can follow text or an earlier tool call. Display "updates" returns the reasoning as a
// signed block without text and the updates as readable blocks.
const claudeProgressUpdateBlocks = `{"type":"thinking","thinking":"","signature":"c2lnLXJlYXNvbg=="},` +
	`{"type":"thinking","thinking":"Found the config. ","signature":"c2lnLXVwZGF0ZTE="},` +
	`{"type":"tool_use","id":"toolu_01","name":"lookup","input":{"q":"a"}},` +
	`{"type":"thinking","thinking":"Reading the tests next.","signature":"c2lnLXVwZGF0ZTI="},` +
	`{"type":"tool_use","id":"toolu_02","name":"lookup","input":{"q":"b"}}`

const claudeProgressUpdateModel = `"model":"anthropic-claude-fable-5-1","reasoning":{"effort":"medium","display":"updates"}`

const claudeProgressUpdateTool = `"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"}}}}}]`

const claudeProgressUpdateText = "Found the config. Reading the tests next."

// What Claude must get back: the hidden reasoning with its empty text, the update after it, and
// both calls. The update between the calls is left out, which Anthropic allows.
const claudeProgressUpdateHistory = `type="thinking" thinking="" signature="c2lnLXJlYXNvbg=="` + "\n" +
	`type="thinking" thinking="Found the config. " signature="c2lnLXVwZGF0ZTE="` + "\n" +
	`type="tool_use" id="toolu_01"` + "\n" +
	`type="tool_use" id="toolu_02"`

// claudeHistoryAfter sends an assistant message back with the results of its two tool calls and
// returns the blocks that Claude gets for it.
func claudeHistoryAfter(t *testing.T, assistant string) string {
	t.Helper()
	body, _, _ := providerBody(t, "/v1/chat/completions", `{`+claudeProgressUpdateModel+`,`+claudeProgressUpdateTool+
		`,"messages":[{"role":"user","content":"hi"},`+assistant+
		`,{"role":"tool","tool_call_id":"toolu_01","content":"a"},{"role":"tool","tool_call_id":"toolu_02","content":"b"}]}`)
	return blockFields(assistantBlocks(t, body)[0], "type", "thinking", "signature", "id")
}

// A Chat reply keeps every progress update readable in its reasoning text, and its
// reasoning_details hold only the thinking that starts it, which is all that the client can send
// back in place. The client sends the reply back unchanged, and Claude gets that thinking.
func TestClaudeProgressUpdatesReachChatClients(t *testing.T) {
	request := `{` + claudeProgressUpdateModel + `,` + claudeProgressUpdateTool + `,"messages":[{"role":"user","content":"hi"}]`
	state := resolvedChatValidationState(t, request+`}`)
	var message anthropic.AnthropicMessageResponse
	if err := json.Unmarshal([]byte(`{"id":"msg_01updates","type":"message","role":"assistant","model":"claude-fable-5-1","content":[`+claudeProgressUpdateBlocks+
		`],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":60}}`), &message); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := schemas.NewBifrostContextWithCancel(context.Background())
	defer cancel()
	response := message.ToBifrostChatResponse(ctx)
	response.BackfillParams(&schemas.BifrostChatRequest{Model: "claude-fable-5-1"})
	if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ChatResponse: response}, nil); err != nil {
		t.Fatal(err)
	}
	reply := response.Choices[0].Message
	if reasoning := reply.Reasoning; reasoning == nil || *reasoning != claudeProgressUpdateText || len(reply.ToolCalls) != 2 {
		t.Fatalf("reply = %+v", reply.ChatAssistantMessage)
	}
	assistant, err := sonic.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	if got := claudeHistoryAfter(t, string(assistant)); got != claudeProgressUpdateHistory {
		t.Fatalf("Claude gets\n%s\nwant\n%s", got, claudeProgressUpdateHistory)
	}

	// A streaming client joins the deltas of each detail and call by index. The hidden reasoning
	// streams as a signature alone, so its detail has no text.
	streaming := resolvedChatValidationState(t, request+`,"stream":true}`)
	streamState := anthropic.NewAnthropicStreamState()
	type detail struct{ text, signature *string }
	var details []detail
	var calls []string
	streamed := ""
	for _, event := range anthropicStreamEvents(t, claudeProgressUpdateBlocks, "tool_use") {
		chunk, bifrostErr, _ := event.ToBifrostChatCompletionStream(ctx, "", streamState)
		if bifrostErr != nil {
			t.Fatalf("convert %s: %v", event.Type, bifrostErr.Error)
		}
		if chunk == nil {
			continue
		}
		// The provider's stream loop names the message on every chunk.
		chunk.ID, chunk.Model = "msg_01updates", "claude-fable-5-1"
		if err := streaming.Adapter.IngestChunk(streaming, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
			t.Fatalf("ingest %s: %v", event.Type, err)
		}
		delta := chunk.Choices[0].ChatStreamResponseChoice.Delta
		if delta == nil {
			continue
		}
		if delta.Reasoning != nil {
			streamed += *delta.Reasoning
		}
		for _, part := range delta.ReasoningDetails {
			for len(details) <= part.Index {
				details = append(details, detail{})
			}
			if part.Text != nil {
				text := *part.Text
				if details[part.Index].text != nil {
					text = *details[part.Index].text + text
				}
				details[part.Index].text = &text
			}
			if part.Signature != nil {
				details[part.Index].signature = part.Signature
			}
		}
		for _, call := range delta.ToolCalls {
			if call.ID != nil {
				calls = append(calls, `{"id":"`+*call.ID+`","type":"function","function":{"name":"lookup","arguments":"{}"}}`)
			}
		}
	}
	if streamed != claudeProgressUpdateText {
		t.Fatalf("streamed reasoning = %q", streamed)
	}
	parts := make([]string, len(details))
	for index, part := range details {
		parts[index] = `{"type":"reasoning.text","index":` + strconv.Itoa(index) + `,"signature":"` + *part.signature + `"`
		if part.text != nil {
			parts[index] += `,"text":"` + *part.text + `"`
		}
		parts[index] += `}`
	}
	assembled := `{"role":"assistant","reasoning":"` + streamed + `","reasoning_details":[` + strings.Join(parts, ",") + `],"tool_calls":[` + strings.Join(calls, ",") + `]}`
	if got := claudeHistoryAfter(t, assembled); got != claudeProgressUpdateHistory {
		t.Fatalf("after a stream Claude gets\n%s\nwant\n%s\nfrom %s", got, claudeProgressUpdateHistory, assembled)
	}
}

// A Responses client asks for progress updates alone with reasoning.summary "updates". Each of
// Claude's thinking blocks becomes a reasoning item, an update with its text as the summary, and
// the items sent back give Claude the same history as a Chat reply does.
func TestClaudeProgressUpdatesReachResponsesClients(t *testing.T) {
	request := `{"model":"anthropic-claude-fable-5-1","reasoning":{"effort":"medium","summary":"updates"},"include":["reasoning.encrypted_content"],` +
		`"tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"}}}}],"input":[{"role":"user","content":"hi"}`
	body, ctx, state := providerBody(t, "/v1/responses", request+`],"stream":true}`)
	if display := string(body["thinking"]); !strings.Contains(display, `"display":"updates"`) {
		t.Fatalf("thinking = %s", display)
	}
	streamState := anthropic.AcquireAnthropicResponsesStreamState()
	defer anthropic.ReleaseAnthropicResponsesStreamState(streamState)
	var items, summaries []string
	sequence := 0
	for _, event := range anthropicStreamEvents(t, claudeProgressUpdateBlocks, "tool_use") {
		chunks, bifrostErr, _ := event.ToBifrostResponsesStream(ctx, sequence, streamState)
		if bifrostErr != nil {
			t.Fatalf("convert %s: %v", event.Type, bifrostErr.Error)
		}
		for _, chunk := range chunks {
			if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: chunk}); err != nil {
				t.Fatalf("ingest %s: %v", chunk.Type, err)
			}
			if chunk.Type != schemas.ResponsesStreamResponseTypeCompleted {
				continue
			}
			for _, item := range chunk.Response.Output {
				encoded, err := json.Marshal(item)
				if err != nil {
					t.Fatal(err)
				}
				items = append(items, string(encoded))
				if item.ResponsesReasoning != nil {
					for _, summary := range item.ResponsesReasoning.Summary {
						summaries = append(summaries, summary.Text)
					}
				}
			}
		}
		sequence += len(chunks)
	}
	if got := strings.Join(summaries, ""); len(items) != 5 || got != claudeProgressUpdateText {
		t.Fatalf("output = %d items with summaries %q", len(items), got)
	}
	next, _, _ := providerBody(t, "/v1/responses", request+`,`+strings.Join(items, ",")+
		`,{"type":"function_call_output","call_id":"toolu_01","output":"a"},{"type":"function_call_output","call_id":"toolu_02","output":"b"}]}`)
	if got := blockFields(assistantBlocks(t, next)[0], "type", "thinking", "signature", "id"); got != claudeProgressUpdateHistory {
		t.Fatalf("Claude gets\n%s\nwant\n%s", got, claudeProgressUpdateHistory)
	}
}

// anthropicStreamEvents streams the content blocks of a reply as Anthropic does.
func anthropicStreamEvents(t *testing.T, blocks, stopReason string) []anthropic.AnthropicStreamEvent {
	t.Helper()
	var content []map[string]json.RawMessage
	if err := json.Unmarshal([]byte("["+blocks+"]"), &content); err != nil {
		t.Fatal(err)
	}
	lines := []string{`{"type":"message_start","message":{"id":"msg_01updates","type":"message","role":"assistant","model":"claude-fable-5-1","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":1}}}`}
	for index, block := range content {
		var deltas []string
		switch string(block["type"]) {
		case `"thinking"`:
			// Hidden reasoning streams its signature alone.
			if string(block["thinking"]) != `""` {
				deltas = []string{`{"type":"thinking_delta","thinking":` + string(block["thinking"]) + `}`}
			}
			deltas = append(deltas, `{"type":"signature_delta","signature":`+string(block["signature"])+`}`)
			block["thinking"], block["signature"] = json.RawMessage(`""`), json.RawMessage(`""`)
		case `"tool_use"`:
			partial, err := json.Marshal(string(block["input"]))
			if err != nil {
				t.Fatal(err)
			}
			deltas = []string{`{"type":"input_json_delta","partial_json":` + string(partial) + `}`}
			block["input"] = json.RawMessage(`{}`)
		}
		start, err := json.Marshal(block)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, `{"type":"content_block_start","index":`+strconv.Itoa(index)+`,"content_block":`+string(start)+`}`)
		for _, delta := range deltas {
			lines = append(lines, `{"type":"content_block_delta","index":`+strconv.Itoa(index)+`,"delta":`+delta+`}`)
		}
		lines = append(lines, `{"type":"content_block_stop","index":`+strconv.Itoa(index)+`}`)
	}
	lines = append(lines, `{"type":"message_delta","delta":{"stop_reason":"`+stopReason+`","stop_sequence":null},"usage":{"output_tokens":60}}`, `{"type":"message_stop"}`)
	events := make([]anthropic.AnthropicStreamEvent, len(lines))
	for index, line := range lines {
		if err := json.Unmarshal([]byte(line), &events[index]); err != nil {
			t.Fatal(err)
		}
	}
	return events
}
