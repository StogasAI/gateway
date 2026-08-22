package anthropic

import (
	"context"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// makeResponsesTextFormat returns a minimal json_schema text config for the
// Responses API structured-output request path.
func makeResponsesTextFormat(schemaName string) *schemas.ResponsesTextConfig {
	properties := map[string]any{
		"color":  map[string]interface{}{"type": "string"},
		"animal": map[string]interface{}{"type": "string"},
	}
	return &schemas.ResponsesTextConfig{
		Format: &schemas.ResponsesTextConfigFormat{
			Type: "json_schema",
			Name: schemas.Ptr(schemaName),
			JSONSchema: &schemas.ResponsesTextConfigFormatJSONSchema{
				Type:       schemas.Ptr("object"),
				Properties: schemas.OrderedMapFromMap(properties),
				Required:   []string{"color", "animal"},
			},
		},
	}
}

func TestAnthropicResponsesCompletionStatusTranslation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		stopReason     AnthropicStopReason
		wantStatus     string
		wantIncomplete bool
	}{
		{name: "end turn", stopReason: AnthropicStopReasonEndTurn, wantStatus: schemas.ResponsesResponseStatusCompleted},
		{name: "max tokens", stopReason: AnthropicStopReasonMaxTokens, wantStatus: schemas.ResponsesResponseStatusIncomplete, wantIncomplete: true},
		{name: "context window", stopReason: AnthropicStopReasonModelContextWindowExceeded, wantStatus: schemas.ResponsesResponseStatusIncomplete, wantIncomplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := (&AnthropicMessageResponse{
				ID: "msg_status", Type: "message", Role: string(AnthropicMessageRoleAssistant),
				Model: "claude-sonnet-4-6", StopReason: tc.stopReason, Usage: &AnthropicUsage{},
			}).ToBifrostResponsesResponse(schemas.NewBifrostContext(nil, time.Time{}))
			if response.Object != "response" || response.Status == nil || *response.Status != tc.wantStatus {
				t.Fatalf("translated object/status = %q/%v, want response/%s", response.Object, response.Status, tc.wantStatus)
			}
			if got := response.IncompleteDetails != nil; got != tc.wantIncomplete {
				t.Fatalf("incomplete_details present = %t, want %t: %#v", got, tc.wantIncomplete, response.IncompleteDetails)
			}
			if tc.wantIncomplete && response.IncompleteDetails.Reason != schemas.ResponsesResponseIncompleteReasonMaxOutputTokens {
				t.Fatalf("incomplete reason = %q", response.IncompleteDetails.Reason)
			}
		})
	}
}

func TestAnthropicResponsesStreamUsesIncompleteTerminalForTokenLimit(t *testing.T) {
	state := AcquireAnthropicResponsesStreamState()
	defer ReleaseAnthropicResponsesStreamState(state)
	ctx := context.Background()
	stopReason := AnthropicStopReasonMaxTokens
	events := []*AnthropicStreamEvent{
		{
			Type: AnthropicStreamEventTypeMessageStart,
			Message: &AnthropicMessageResponse{
				ID: "msg_incomplete", Model: "claude-sonnet-4-6",
			},
		},
		{
			Type:  AnthropicStreamEventTypeMessageDelta,
			Delta: &AnthropicStreamDelta{StopReason: &stopReason},
		},
		{Type: AnthropicStreamEventTypeMessageStop},
	}

	var converted []*schemas.BifrostResponsesStreamResponse
	sequence := 0
	for _, event := range events {
		responses, bifrostErr, _ := event.ToBifrostResponsesStream(ctx, sequence, state)
		if bifrostErr != nil {
			t.Fatalf("convert %s: %v", event.Type, bifrostErr)
		}
		converted = append(converted, responses...)
		sequence += len(responses)
	}
	if len(converted) != 3 {
		t.Fatalf("converted event count = %d, want 3", len(converted))
	}
	for index, event := range converted[:2] {
		if event.Response == nil || event.Response.Object != "response" || event.Response.Status == nil ||
			*event.Response.Status != schemas.ResponsesResponseStatusInProgress {
			t.Fatalf("start event %d lacks in-progress response identity: %#v", index, event.Response)
		}
	}
	terminal := converted[2]
	if terminal.Type != schemas.ResponsesStreamResponseTypeIncomplete || terminal.Response == nil ||
		terminal.Response.Status == nil || *terminal.Response.Status != schemas.ResponsesResponseStatusIncomplete ||
		terminal.Response.IncompleteDetails == nil ||
		terminal.Response.IncompleteDetails.Reason != schemas.ResponsesResponseIncompleteReasonMaxOutputTokens {
		t.Fatalf("terminal event was not translated as incomplete: %#v", terminal)
	}
}

func TestAnthropicResponsesPingIsOnlyPreservedForAnthropicWireClients(t *testing.T) {
	event := &AnthropicStreamEvent{Type: AnthropicStreamEventTypePing}
	state := AcquireAnthropicResponsesStreamState()
	defer ReleaseAnthropicResponsesStreamState(state)

	converted, bifrostErr, _ := event.ToBifrostResponsesStream(context.Background(), 0, state)
	if bifrostErr != nil || len(converted) != 0 {
		t.Fatalf("translated Responses ping = %#v, %v; want filtered", converted, bifrostErr)
	}
	ctx := context.WithValue(context.Background(), schemas.BifrostContextKeyIntegrationType, "anthropic")
	converted, bifrostErr, _ = event.ToBifrostResponsesStream(ctx, 0, state)
	if bifrostErr != nil || len(converted) != 1 || converted[0].Type != schemas.ResponsesStreamResponseTypePing {
		t.Fatalf("Anthropic-wire ping = %#v, %v; want one preserved ping", converted, bifrostErr)
	}
}

func TestAnthropicResponsesIncompleteReverseTranslationUsesMaxTokens(t *testing.T) {
	ctx, cancel := schemas.NewBifrostContextWithCancel(context.Background())
	defer cancel()
	events := ToAnthropicResponsesStreamResponse(ctx, &schemas.BifrostResponsesStreamResponse{
		Type: schemas.ResponsesStreamResponseTypeIncomplete,
		Response: &schemas.BifrostResponsesResponse{
			Status: schemas.Ptr(schemas.ResponsesResponseStatusIncomplete),
			IncompleteDetails: &schemas.ResponsesResponseIncompleteDetails{
				Reason: schemas.ResponsesResponseIncompleteReasonMaxOutputTokens,
			},
		},
	})
	if len(events) != 2 || events[0].Type != AnthropicStreamEventTypeMessageDelta ||
		events[0].Delta == nil || events[0].Delta.StopReason == nil ||
		*events[0].Delta.StopReason != AnthropicStopReasonMaxTokens ||
		events[1].Type != AnthropicStreamEventTypeMessageStop {
		t.Fatalf("incomplete reverse translation = %#v", events)
	}
}

func TestToBifrostResponsesStreamStructuredOutputUsesCompleteTextLifecycle(t *testing.T) {
	state := AcquireAnthropicResponsesStreamState()
	defer ReleaseAnthropicResponsesStreamState(state)
	state.StructuredOutputToolName = "bf_so_schema"

	index := 0
	toolID := "toolu_structured"
	toolName := state.StructuredOutputToolName
	payload := `{"answer":"safe"}`
	events := []*AnthropicStreamEvent{
		{
			Type: AnthropicStreamEventTypeMessageStart,
			Message: &AnthropicMessageResponse{
				ID: "msg_structured", Model: "claude-sonnet-4-6",
			},
		},
		{
			Type: AnthropicStreamEventTypeContentBlockStart, Index: &index,
			ContentBlock: &AnthropicContentBlock{
				Type: AnthropicContentBlockTypeToolUse, ID: &toolID, Name: &toolName,
			},
		},
		{
			Type: AnthropicStreamEventTypeContentBlockDelta, Index: &index,
			Delta: &AnthropicStreamDelta{Type: AnthropicStreamDeltaTypeInputJSON, PartialJSON: &payload},
		},
		{Type: AnthropicStreamEventTypeContentBlockStop, Index: &index},
		{Type: AnthropicStreamEventTypeMessageStop},
	}

	var responses []*schemas.BifrostResponsesStreamResponse
	sequence := 0
	for _, event := range events {
		converted, bifrostErr, _ := event.ToBifrostResponsesStream(context.Background(), sequence, state)
		if bifrostErr != nil {
			t.Fatalf("convert %s: %v", event.Type, bifrostErr)
		}
		responses = append(responses, converted...)
		sequence += len(converted)
	}

	wantLifecycle := []schemas.ResponsesStreamResponseType{
		schemas.ResponsesStreamResponseTypeOutputItemAdded,
		schemas.ResponsesStreamResponseTypeContentPartAdded,
		schemas.ResponsesStreamResponseTypeOutputTextDelta,
		schemas.ResponsesStreamResponseTypeOutputTextDone,
		schemas.ResponsesStreamResponseTypeContentPartDone,
		schemas.ResponsesStreamResponseTypeOutputItemDone,
	}
	var lifecycle []*schemas.BifrostResponsesStreamResponse
	var terminal *schemas.BifrostResponsesStreamResponse
	for _, response := range responses {
		switch response.Type {
		case schemas.ResponsesStreamResponseTypeOutputItemAdded,
			schemas.ResponsesStreamResponseTypeContentPartAdded,
			schemas.ResponsesStreamResponseTypeOutputTextDelta,
			schemas.ResponsesStreamResponseTypeOutputTextDone,
			schemas.ResponsesStreamResponseTypeContentPartDone,
			schemas.ResponsesStreamResponseTypeOutputItemDone:
			lifecycle = append(lifecycle, response)
		case schemas.ResponsesStreamResponseTypeCompleted:
			terminal = response
		}
	}
	if len(lifecycle) != len(wantLifecycle) {
		t.Fatalf("structured output lifecycle length = %d, want %d", len(lifecycle), len(wantLifecycle))
	}
	for index, want := range wantLifecycle {
		if lifecycle[index].Type != want {
			t.Fatalf("lifecycle[%d] = %s, want %s", index, lifecycle[index].Type, want)
		}
		if lifecycle[index].SequenceNumber != lifecycle[0].SequenceNumber+index {
			t.Fatalf("lifecycle[%d] sequence = %d, want %d", index, lifecycle[index].SequenceNumber, lifecycle[0].SequenceNumber+index)
		}
	}
	if lifecycle[0].Item == nil || lifecycle[0].Item.Status == nil || *lifecycle[0].Item.Status != "in_progress" ||
		lifecycle[0].Item.Content == nil || len(lifecycle[0].Item.Content.ContentBlocks) != 0 {
		t.Fatalf("structured output added item is not empty and in progress: %#v", lifecycle[0].Item)
	}
	if lifecycle[2].Delta == nil || *lifecycle[2].Delta != payload || lifecycle[3].Text == nil || *lifecycle[3].Text != payload {
		t.Fatalf("structured output text events lost payload %q", payload)
	}
	done := lifecycle[len(lifecycle)-1].Item
	if done == nil || done.Status == nil || *done.Status != "completed" || done.Content == nil ||
		len(done.Content.ContentBlocks) != 1 || done.Content.ContentBlocks[0].Text == nil ||
		*done.Content.ContentBlocks[0].Text != payload {
		t.Fatalf("structured output done item is incomplete: %#v", done)
	}
	if terminal == nil || terminal.Response == nil || len(terminal.Response.Output) != 1 ||
		terminal.Response.Output[0].Content == nil || len(terminal.Response.Output[0].Content.ContentBlocks) != 1 ||
		terminal.Response.Output[0].Content.ContentBlocks[0].Text == nil ||
		*terminal.Response.Output[0].Content.ContentBlocks[0].Text != payload {
		t.Fatalf("terminal response lost structured output: %#v", terminal)
	}
}

// TestToAnthropicResponsesRequest_StructuredOutput_ToolConversion verifies that,
// mirroring the Chat Completions path, providers whose native Anthropic endpoint
// rejects output_config.format get structured output converted into a synthetic
// bf_so_*/json_response tool instead. Any provider added to toolConversionProviders
// in the future must also be added to the branch under test in responses.go.
func TestToAnthropicResponsesRequest_StructuredOutput_ToolConversion(t *testing.T) {
	for _, provider := range toolConversionProviders {
		t.Run(string(provider), func(t *testing.T) {
			req := &schemas.BifrostResponsesRequest{
				Provider: provider,
				Model:    "claude-opus-4-6",
				Input: []schemas.ResponsesMessage{
					{
						Role: schemas.Ptr(schemas.ResponsesInputMessageRoleUser),
						Content: &schemas.ResponsesMessageContent{
							ContentStr: schemas.Ptr("Hello"),
						},
					},
				},
				Params: &schemas.ResponsesParameters{
					Text: makeResponsesTextFormat("my_schema"),
				},
			}

			ctx := schemas.NewBifrostContext(nil, time.Time{})
			result, err := ToAnthropicResponsesRequest(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.OutputConfig != nil {
				t.Errorf("expected OutputConfig to stay unset for %s (native field unsupported), got %+v", provider, result.OutputConfig)
			}

			found := false
			for _, tool := range result.Tools {
				if tool.Name == "bf_so_my_schema" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected a synthetic tool named %q to be added for %s structured output", "bf_so_my_schema", provider)
			}

			if result.ToolChoice == nil || result.ToolChoice.Name != "bf_so_my_schema" {
				t.Errorf("expected ToolChoice to be forced to the synthetic tool for %s, got %+v", provider, result.ToolChoice)
			}
		})
	}
}

// TestToAnthropicResponsesRequest_StructuredOutput_NativeOutputConfig_Anthropic is the
// negative-case control: Anthropic itself supports output_config.format natively, so no
// synthetic tool should be added. This is the branch that Azure incorrectly took before
// being added to toolConversionProviders.
func TestToAnthropicResponsesRequest_StructuredOutput_NativeOutputConfig_Anthropic(t *testing.T) {
	req := &schemas.BifrostResponsesRequest{
		Provider: schemas.Anthropic,
		Model:    "claude-opus-4-6",
		Input: []schemas.ResponsesMessage{
			{
				Role: schemas.Ptr(schemas.ResponsesInputMessageRoleUser),
				Content: &schemas.ResponsesMessageContent{
					ContentStr: schemas.Ptr("Hello"),
				},
			},
		},
		Params: &schemas.ResponsesParameters{
			Text: makeResponsesTextFormat("my_schema"),
		},
	}

	ctx := schemas.NewBifrostContext(nil, time.Time{})
	result, err := ToAnthropicResponsesRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.OutputConfig == nil || result.OutputConfig.Format == nil {
		t.Fatal("expected OutputConfig.Format to be set natively for Anthropic")
	}

	for _, tool := range result.Tools {
		if tool.Name == "bf_so_my_schema" {
			t.Errorf("did not expect a synthetic tool for Anthropic, got %q", tool.Name)
		}
	}
}
