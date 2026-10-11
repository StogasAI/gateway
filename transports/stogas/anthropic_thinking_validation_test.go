package stogas

import (
	"context"
	"encoding/json"
	"testing"

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
	state := resolvedResponseValidationState(t, `{"model":"anthropic-claude-sonnet-4-6","input":"hi","reasoning":{"effort":"medium"},"max_output_tokens":2048}`)
	streamState := anthropic.AcquireAnthropicResponsesStreamState()
	defer anthropic.ReleaseAnthropicResponsesStreamState(streamState)

	sequence := 0
	var terminal schemas.ResponsesStreamResponseType
	for _, line := range anthropicTruncatedThinkingStream {
		var event anthropic.AnthropicStreamEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		chunks, bifrostErr, _ := event.ToBifrostResponsesStream(context.Background(), sequence, streamState)
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
