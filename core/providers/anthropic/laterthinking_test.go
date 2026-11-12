package anthropic

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// laterThinkingReply starts with summarized thinking and redacted thinking, then continues
// with text, a progress update before its tool call, and late redacted thinking.
func laterThinkingReply() []AnthropicContentBlock {
	return []AnthropicContentBlock{
		{Type: AnthropicContentBlockTypeThinking, Thinking: schemas.Ptr("Plan the lookup."), Signature: schemas.Ptr("sig-plan")},
		{Type: AnthropicContentBlockTypeRedactedThinking, Data: schemas.Ptr("redacted-plan")},
		{Type: AnthropicContentBlockTypeText, Text: schemas.Ptr("Checking the weather.")},
		{Type: AnthropicContentBlockTypeThinking, Thinking: schemas.Ptr(" Asking for Paris."), Signature: schemas.Ptr("sig-update")},
		{Type: AnthropicContentBlockTypeToolUse, ID: schemas.Ptr("toolu_01"), Name: schemas.Ptr("get_weather"), Input: json.RawMessage(`{"city":"Paris"}`)},
		{Type: AnthropicContentBlockTypeRedactedThinking, Data: schemas.Ptr("redacted-late")},
	}
}

// laterThinkingStream streams laterThinkingReply as Anthropic does.
func laterThinkingStream() []*AnthropicStreamEvent {
	events := []*AnthropicStreamEvent{{Type: AnthropicStreamEventTypeMessageStart, Message: &AnthropicMessageResponse{ID: "msg_01", Role: "assistant"}}}
	for index, block := range laterThinkingReply() {
		start := block
		var deltas []AnthropicStreamDelta
		switch block.Type {
		case AnthropicContentBlockTypeThinking:
			start.Thinking, start.Signature = schemas.Ptr(""), schemas.Ptr("")
			deltas = []AnthropicStreamDelta{{Type: AnthropicStreamDeltaTypeThinking, Thinking: block.Thinking}, {Type: AnthropicStreamDeltaTypeSignature, Signature: block.Signature}}
		case AnthropicContentBlockTypeText:
			start.Text = schemas.Ptr("")
			deltas = []AnthropicStreamDelta{{Type: AnthropicStreamDeltaTypeText, Text: block.Text}}
		case AnthropicContentBlockTypeToolUse:
			start.Input = json.RawMessage(`{}`)
			deltas = []AnthropicStreamDelta{{Type: AnthropicStreamDeltaTypeInputJSON, PartialJSON: schemas.Ptr(string(block.Input))}}
		}
		events = append(events, &AnthropicStreamEvent{Type: AnthropicStreamEventTypeContentBlockStart, Index: schemas.Ptr(index), ContentBlock: &start})
		for _, delta := range deltas {
			events = append(events, &AnthropicStreamEvent{Type: AnthropicStreamEventTypeContentBlockDelta, Index: schemas.Ptr(index), Delta: &delta})
		}
		events = append(events, &AnthropicStreamEvent{Type: AnthropicStreamEventTypeContentBlockStop, Index: schemas.Ptr(index)})
	}
	return append(events, &AnthropicStreamEvent{Type: AnthropicStreamEventTypeMessageStop})
}

// A Chat client sends reasoning_details back before the text and tool calls, so a reply keeps
// only the thinking that starts it there, and the replay keeps every block in its place.
func TestChatReplyReturnsTheThinkingThatStartsIt(t *testing.T) {
	t.Parallel()

	ctx := schemas.NewBifrostContext(nil, time.Time{})
	response := &AnthropicMessageResponse{ID: "msg_01", Model: "claude-fable-5-2", Content: laterThinkingReply(), StopReason: AnthropicStopReasonToolUse}
	message := response.ToBifrostChatResponse(ctx).Choices[0].ChatNonStreamResponseChoice.Message
	wantDetails := []schemas.ChatReasoningDetails{
		{Index: 0, Type: schemas.BifrostReasoningDetailsTypeText, Text: schemas.Ptr("Plan the lookup."), Signature: schemas.Ptr("sig-plan")},
		{Index: 1, Type: schemas.BifrostReasoningDetailsTypeEncrypted, Data: schemas.Ptr("redacted-plan")},
	}
	if got := message.ChatAssistantMessage.ReasoningDetails; !reflect.DeepEqual(got, wantDetails) {
		t.Fatalf("reasoning_details = %+v, want %+v", got, wantDetails)
	}
	// The progress update stays readable.
	if got := *message.ChatAssistantMessage.Reasoning; got != "Plan the lookup. Asking for Paris." {
		t.Fatalf("reasoning = %q", got)
	}

	// A stream returns the same reasoning.
	state := NewAnthropicStreamState()
	reasoning := ""
	streamed := map[int]*schemas.ChatReasoningDetails{}
	for _, event := range laterThinkingStream() {
		chunk, bifrostErr, _ := event.ToBifrostChatCompletionStream(ctx, "", state)
		if bifrostErr != nil {
			t.Fatalf("%s: %+v", event.Type, bifrostErr)
		}
		if chunk == nil {
			continue
		}
		delta := chunk.Choices[0].ChatStreamResponseChoice.Delta
		if delta.Reasoning != nil {
			reasoning += *delta.Reasoning
		}
		for _, detail := range delta.ReasoningDetails {
			entry := streamed[detail.Index]
			if entry == nil {
				entry = &schemas.ChatReasoningDetails{Index: detail.Index, Type: detail.Type}
				streamed[detail.Index] = entry
			}
			if detail.Text != nil {
				text := *detail.Text
				if entry.Text != nil {
					text = *entry.Text + text
				}
				entry.Text = &text
			}
			if detail.Signature != nil {
				entry.Signature = detail.Signature
			}
			if detail.Data != nil {
				entry.Data = detail.Data
			}
		}
	}
	if reasoning != *message.ChatAssistantMessage.Reasoning || len(streamed) != len(wantDetails) {
		t.Fatalf("stream reasoning = %q, details = %d, want the reply's", reasoning, len(streamed))
	}
	for index, want := range wantDetails {
		if got := streamed[index]; got == nil || !reflect.DeepEqual(*got, want) {
			t.Fatalf("stream reasoning_details[%d] = %+v, want %+v", index, got, want)
		}
	}

	request, err := ToAnthropicChatRequest(ctx, &schemas.BifrostChatRequest{
		Provider: schemas.Anthropic,
		Model:    "claude-fable-5-2",
		Input: []schemas.ChatMessage{
			{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Weather in Paris?")}},
			*message,
			{Role: schemas.ChatMessageRoleTool, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("18C")}, ChatToolMessage: &schemas.ChatToolMessage{ToolCallID: schemas.Ptr("toolu_01")}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"thinking:sig-plan", "redacted:redacted-plan", "text:Checking the weather.", "tool:toolu_01"}
	if got := blockLabels(request.Messages[1].Content.ContentBlocks); !reflect.DeepEqual(got, want) {
		t.Fatalf("replayed blocks = %v, want %v", got, want)
	}
}

// A turn's thinking after its first other block stays out, also when the turn spans
// consecutive assistant messages, and a message that held only such thinking goes with it.
func TestLeaveOutLaterThinkingReadsConsecutiveAssistantMessagesAsOneTurn(t *testing.T) {
	t.Parallel()

	thinking := AnthropicContentBlock{Type: AnthropicContentBlockTypeThinking, Thinking: schemas.Ptr(""), Signature: schemas.Ptr("sig")}
	redacted := AnthropicContentBlock{Type: AnthropicContentBlockTypeRedactedThinking, Data: schemas.Ptr("data")}
	text := AnthropicContentBlock{Type: AnthropicContentBlockTypeText, Text: schemas.Ptr("text")}
	call := AnthropicContentBlock{Type: AnthropicContentBlockTypeToolUse, ID: schemas.Ptr("toolu_01"), Name: schemas.Ptr("t"), Input: json.RawMessage(`{}`)}
	message := func(role AnthropicMessageRole, blocks ...AnthropicContentBlock) AnthropicMessage {
		return AnthropicMessage{Role: role, Content: AnthropicContent{ContentBlocks: blocks}}
	}
	got := leaveOutLaterThinking([]AnthropicMessage{
		message(AnthropicMessageRoleUser, text),
		message(AnthropicMessageRoleAssistant, thinking, redacted, text),
		message(AnthropicMessageRoleAssistant, thinking),
		message(AnthropicMessageRoleAssistant, redacted, call),
		message(AnthropicMessageRoleUser, text),
		message(AnthropicMessageRoleAssistant, thinking, call, thinking),
	})
	want := []AnthropicMessage{
		message(AnthropicMessageRoleUser, text),
		message(AnthropicMessageRoleAssistant, thinking, redacted, text),
		message(AnthropicMessageRoleAssistant, call),
		message(AnthropicMessageRoleUser, text),
		message(AnthropicMessageRoleAssistant, thinking, call),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("messages = %+v, want %+v", got, want)
	}
}
