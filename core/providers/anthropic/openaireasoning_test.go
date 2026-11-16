package anthropic

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// openAIReasoningReplyBlocks is a reply with summarized thinking, redacted thinking,
// text, an omitted progress update before a tool call, and the call.
func openAIReasoningReplyBlocks() []AnthropicContentBlock {
	return []AnthropicContentBlock{
		{Type: AnthropicContentBlockTypeThinking, Thinking: schemas.Ptr("Plan the lookup."), Signature: schemas.Ptr("sig-plan")},
		{Type: AnthropicContentBlockTypeRedactedThinking, Data: schemas.Ptr("redacted-data")},
		{Type: AnthropicContentBlockTypeText, Text: schemas.Ptr("Checking the weather.")},
		{Type: AnthropicContentBlockTypeThinking, Thinking: schemas.Ptr(""), Signature: schemas.Ptr("sig-update")},
		{Type: AnthropicContentBlockTypeToolUse, ID: schemas.Ptr("toolu_01"), Name: schemas.Ptr("get_weather"), Input: json.RawMessage(`{"city":"Paris"}`)},
	}
}

func openAIReasoningContext() *schemas.BifrostContext {
	ctx := schemas.NewBifrostContext(nil, time.Time{})
	SetOpenAIReasoning(ctx)
	return ctx
}

// replayedAssistantBlocks sends output items back as a client does, after a tool
// result, and returns the assistant blocks of the request in order. The request keeps
// only the thinking that starts the reply (laterthinking.go). Anthropic joins
// consecutive assistant messages into one turn.
func replayedAssistantBlocks(t *testing.T, output []schemas.ResponsesMessage, edit func([]schemas.ResponsesMessage)) []AnthropicContentBlock {
	t.Helper()
	wire, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var input []schemas.ResponsesMessage
	if err := json.Unmarshal(wire, &input); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(input)
	}
	input = append([]schemas.ResponsesMessage{{
		Type:    schemas.Ptr(schemas.ResponsesMessageTypeMessage),
		Role:    schemas.Ptr(schemas.ResponsesInputMessageRoleUser),
		Content: &schemas.ResponsesMessageContent{ContentStr: schemas.Ptr("Weather in Paris?")},
	}}, input...)
	input = append(input, schemas.ResponsesMessage{
		Type: schemas.Ptr(schemas.ResponsesMessageTypeFunctionCallOutput),
		ResponsesToolMessage: &schemas.ResponsesToolMessage{
			CallID: schemas.Ptr("toolu_01"),
			Output: &schemas.ResponsesToolMessageOutputStruct{ResponsesToolCallOutputStr: schemas.Ptr("18C")},
		},
	})
	request, err := ToAnthropicResponsesRequest(openAIReasoningContext(), &schemas.BifrostResponsesRequest{
		Provider: schemas.Anthropic,
		Model:    "claude-opus-5-5",
		Input:    input,
	})
	if err != nil {
		t.Fatal(err)
	}
	var blocks []AnthropicContentBlock
	for _, message := range request.Messages {
		if message.Role == AnthropicMessageRoleAssistant {
			blocks = append(blocks, message.Content.ContentBlocks...)
		}
	}
	return blocks
}

// requireReplayedReply wants the reply's blocks without the progress update, which follows
// the text.
func requireReplayedReply(t *testing.T, got []AnthropicContentBlock) {
	t.Helper()
	want := slices.Delete(openAIReasoningReplyBlocks(), 3, 4)
	if len(got) != len(want) {
		t.Fatalf("assistant blocks = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Type != want[i].Type {
			t.Fatalf("block %d type = %s, want %s", i, got[i].Type, want[i].Type)
		}
		switch want[i].Type {
		case AnthropicContentBlockTypeThinking:
			if !reflect.DeepEqual(got[i].Thinking, want[i].Thinking) || !reflect.DeepEqual(got[i].Signature, want[i].Signature) || got[i].Data != nil {
				t.Fatalf("block %d = %+v, want %+v", i, got[i], want[i])
			}
		case AnthropicContentBlockTypeRedactedThinking:
			if !reflect.DeepEqual(got[i].Data, want[i].Data) || got[i].Thinking != nil || got[i].Signature != nil {
				t.Fatalf("block %d = %+v, want %+v", i, got[i], want[i])
			}
		}
	}
}

func requireOpenAIReasoningItem(t *testing.T, item schemas.ResponsesMessage, summary string) {
	t.Helper()
	if item.Type == nil || *item.Type != schemas.ResponsesMessageTypeReasoning || item.Role != nil || item.Content != nil || item.ResponsesReasoning == nil {
		t.Fatalf("item = %+v, want a reasoning item without a role or content", item)
	}
	want := []schemas.ResponsesReasoningSummary{}
	if summary != "" {
		want = append(want, schemas.ResponsesReasoningSummary{Type: schemas.ResponsesReasoningContentBlockTypeSummaryText, Text: summary})
	}
	if !reflect.DeepEqual(item.ResponsesReasoning.Summary, want) {
		t.Fatalf("summary = %+v, want %+v", item.ResponsesReasoning.Summary, want)
	}
	if item.ResponsesReasoning.EncryptedContent == nil {
		t.Fatal("encrypted_content is missing")
	}
}

func TestOpenAIReasoningReplyGivesEachBlockAnItem(t *testing.T) {
	t.Parallel()

	response := &AnthropicMessageResponse{ID: "msg_01", Model: "claude-opus-5-5", Content: openAIReasoningReplyBlocks(), StopReason: AnthropicStopReasonToolUse}
	output := response.ToBifrostResponsesResponse(openAIReasoningContext()).Output
	if len(output) != 5 {
		t.Fatalf("output = %d items, want 5: %+v", len(output), output)
	}
	requireOpenAIReasoningItem(t, output[0], "Plan the lookup.")
	requireOpenAIReasoningItem(t, output[1], "")
	if output[2].Type == nil || *output[2].Type != schemas.ResponsesMessageTypeMessage {
		t.Fatalf("output[2] = %+v, want the message", output[2])
	}
	requireOpenAIReasoningItem(t, output[3], "")
	if output[4].Type == nil || *output[4].Type != schemas.ResponsesMessageTypeFunctionCall {
		t.Fatalf("output[4] = %+v, want the call", output[4])
	}

	// The blocks come back unchanged, also when the client drops a summary.
	requireReplayedReply(t, replayedAssistantBlocks(t, output, func(input []schemas.ResponsesMessage) {
		input[0].ResponsesReasoning.Summary = []schemas.ResponsesReasoningSummary{}
	}))
}

// openAIReasoningReplyStream streams the blocks of openAIReasoningReplyBlocks as
// Anthropic does: thinking opens empty and gets its signature last, an omitted block
// gets an empty thinking delta, and redacted thinking arrives whole.
func openAIReasoningReplyStream() []*AnthropicStreamEvent {
	stopReason := AnthropicStopReasonToolUse
	events := []*AnthropicStreamEvent{{
		Type:    AnthropicStreamEventTypeMessageStart,
		Message: &AnthropicMessageResponse{ID: "msg_01", Model: "claude-opus-5-5"},
	}}
	block := func(index int, start AnthropicContentBlock, deltas ...AnthropicStreamDelta) {
		events = append(events, &AnthropicStreamEvent{Type: AnthropicStreamEventTypeContentBlockStart, Index: schemas.Ptr(index), ContentBlock: &start})
		for _, delta := range deltas {
			events = append(events, &AnthropicStreamEvent{Type: AnthropicStreamEventTypeContentBlockDelta, Index: schemas.Ptr(index), Delta: &delta})
		}
		events = append(events, &AnthropicStreamEvent{Type: AnthropicStreamEventTypeContentBlockStop, Index: schemas.Ptr(index)})
	}
	thinking := AnthropicContentBlock{Type: AnthropicContentBlockTypeThinking, Thinking: schemas.Ptr(""), Signature: schemas.Ptr("")}
	block(0, thinking,
		AnthropicStreamDelta{Type: AnthropicStreamDeltaTypeThinking, Thinking: schemas.Ptr("Plan the ")},
		AnthropicStreamDelta{Type: AnthropicStreamDeltaTypeThinking, Thinking: schemas.Ptr("lookup.")},
		AnthropicStreamDelta{Type: AnthropicStreamDeltaTypeSignature, Signature: schemas.Ptr("sig-plan")})
	block(1, AnthropicContentBlock{Type: AnthropicContentBlockTypeRedactedThinking, Data: schemas.Ptr("redacted-data")})
	block(2, AnthropicContentBlock{Type: AnthropicContentBlockTypeText, Text: schemas.Ptr("")},
		AnthropicStreamDelta{Type: AnthropicStreamDeltaTypeText, Text: schemas.Ptr("Checking the weather.")})
	block(3, thinking,
		AnthropicStreamDelta{Type: AnthropicStreamDeltaTypeThinking, Thinking: schemas.Ptr("")},
		AnthropicStreamDelta{Type: AnthropicStreamDeltaTypeSignature, Signature: schemas.Ptr("sig-update")})
	block(4, AnthropicContentBlock{Type: AnthropicContentBlockTypeToolUse, ID: schemas.Ptr("toolu_01"), Name: schemas.Ptr("get_weather"), Input: json.RawMessage(`{}`)},
		AnthropicStreamDelta{Type: AnthropicStreamDeltaTypeInputJSON, PartialJSON: schemas.Ptr(`{"city":"Paris"}`)})
	return append(events,
		&AnthropicStreamEvent{Type: AnthropicStreamEventTypeMessageDelta, Delta: &AnthropicStreamDelta{StopReason: &stopReason}},
		&AnthropicStreamEvent{Type: AnthropicStreamEventTypeMessageStop},
	)
}

func TestOpenAIReasoningStreamFollowsOpenAIEventsAndRoundTrips(t *testing.T) {
	t.Parallel()

	ctx := openAIReasoningContext()
	state := AcquireAnthropicResponsesStreamState()
	defer ReleaseAnthropicResponsesStreamState(state)
	var events []*schemas.BifrostResponsesStreamResponse
	for _, event := range openAIReasoningReplyStream() {
		converted, err, _ := event.ToBifrostResponsesStream(ctx, len(events), state)
		if err != nil {
			t.Fatalf("%s: %v", event.Type, err)
		}
		events = append(events, converted...)
	}

	var first []schemas.ResponsesStreamResponseType
	done := map[int]schemas.ResponsesMessage{}
	var completed *schemas.BifrostResponsesResponse
	for _, event := range events {
		if event.Signature != nil || event.Part != nil && event.Part.Signature != nil {
			t.Fatalf("%s carries a signature", event.Type)
		}
		switch event.Type {
		case schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded, schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
			schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone, schemas.ResponsesStreamResponseTypeReasoningSummaryPartDone:
			if event.ContentIndex != nil || event.SummaryIndex == nil || *event.SummaryIndex != 0 || event.ItemID == nil {
				t.Fatalf("%s indexes = content %v, summary %v, item %v", event.Type, event.ContentIndex, event.SummaryIndex, event.ItemID)
			}
		case schemas.ResponsesStreamResponseTypeContentPartAdded, schemas.ResponsesStreamResponseTypeContentPartDone:
			if event.Part != nil && event.Part.Type == schemas.ResponsesOutputMessageContentTypeReasoning {
				t.Fatalf("%s opens a reasoning_text part", event.Type)
			}
		case schemas.ResponsesStreamResponseTypeOutputItemDone:
			done[*event.OutputIndex] = *event.Item
		case schemas.ResponsesStreamResponseTypeCompleted:
			completed = event.Response
		}
		if event.OutputIndex != nil && *event.OutputIndex == 0 {
			first = append(first, event.Type)
		}
	}
	wantFirst := []schemas.ResponsesStreamResponseType{
		schemas.ResponsesStreamResponseTypeOutputItemAdded,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartDone,
		schemas.ResponsesStreamResponseTypeOutputItemDone,
	}
	if !reflect.DeepEqual(first, wantFirst) {
		t.Fatalf("first item events = %v, want %v", first, wantFirst)
	}
	requireOpenAIReasoningItem(t, done[0], "Plan the lookup.")
	requireOpenAIReasoningItem(t, done[1], "")
	requireOpenAIReasoningItem(t, done[3], "")
	if completed == nil || len(completed.Output) != 5 {
		t.Fatalf("completed = %+v, want 5 items", completed)
	}
	for index, item := range done {
		if !reflect.DeepEqual(completed.Output[index], item) {
			t.Fatalf("completed output[%d] = %+v, want the done item %+v", index, completed.Output[index], item)
		}
	}
	requireReplayedReply(t, replayedAssistantBlocks(t, completed.Output, nil))
}

func TestDecodeThinkingBlockRejectsMalformedContent(t *testing.T) {
	t.Parallel()

	encode := func(state string) string {
		return encryptedThinkingPrefix + base64.RawURLEncoding.EncodeToString([]byte(state))
	}
	valid, ok := encodeThinkingBlock(AnthropicContentBlock{Type: AnthropicContentBlockTypeThinking, Thinking: schemas.Ptr(""), Signature: schemas.Ptr("sig")})
	if !ok {
		t.Fatal("encode thinking")
	}
	if block, ok := DecodeThinkingBlock(valid); !ok || *block.Thinking != "" || *block.Signature != "sig" {
		t.Fatalf("decode = %+v, %v", block, ok)
	}
	for name, encrypted := range map[string]string{
		"OpenAI's":               "gAAAAABq7uOMJ9W3sEQCz5VM",
		"not base64":             encryptedThinkingPrefix + "{}",
		"not JSON":               encode("thinking"),
		"thinking, no signature": encode(`{"type":"thinking","thinking":"x"}`),
		"thinking, no text":      encode(`{"type":"thinking","signature":"sig"}`),
		"thinking with data":     encode(`{"type":"thinking","thinking":"","signature":"sig","data":"d"}`),
		"redacted, no data":      encode(`{"type":"redacted_thinking"}`),
		"redacted with text":     encode(`{"type":"redacted_thinking","data":"d","thinking":""}`),
		"another block":          encode(`{"type":"text","thinking":"","signature":"sig"}`),
	} {
		if block, ok := DecodeThinkingBlock(encrypted); ok {
			t.Errorf("%s: decoded %+v", name, block)
		}
	}
	if _, ok := encodeThinkingBlock(AnthropicContentBlock{Type: AnthropicContentBlockTypeThinking, Thinking: schemas.Ptr("x"), Signature: schemas.Ptr("")}); ok {
		t.Error("encoded thinking without a signature")
	}
}
