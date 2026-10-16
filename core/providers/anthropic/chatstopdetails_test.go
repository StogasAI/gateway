package anthropic

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// The refusal category decides whether Anthropic bills a refusal that arrives
// before any output, so Chat conversion must keep stop_details even though Chat
// Completions has no wire field for it.

const anthropicCyberRefusal = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_refusal","type":"message","role":"assistant","model":"claude-repro","content":[],"usage":{"input_tokens":5,"output_tokens":0}}}` + "\n\n" +
	"event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"declined"}},"usage":{"output_tokens":0}}` + "\n\n" +
	"event: message_stop\n" +
	`data: {"type":"message_stop"}` + "\n\n"

func TestAnthropicChatResponseKeepsRefusalCategory(t *testing.T) {
	var response AnthropicMessageResponse
	if err := json.Unmarshal([]byte(`{"id":"msg_refusal","type":"message","role":"assistant","model":"claude-repro","content":[],"stop_reason":"refusal","stop_details":{"type":"refusal","category":"bio","explanation":"declined"},"usage":{"input_tokens":5,"output_tokens":0}}`), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	chat := response.ToBifrostChatResponse(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline))
	if chat.StopDetails == nil || chat.StopDetails.Category == nil || *chat.StopDetails.Category != "bio" {
		t.Fatalf("stop details = %#v, want category bio", chat.StopDetails)
	}
	encoded, err := json.Marshal(chat)
	if err != nil {
		t.Fatalf("encode chat response: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("decode chat wire: %v", err)
	}
	if _, ok := wire["stop_details"]; ok {
		t.Fatalf("Chat wire gained a stop_details field: %s", encoded)
	}
}

func TestAnthropicChatStreamFinalChunkKeepsRefusalCategory(t *testing.T) {
	server := anthropicSSEServer(t, anthropicCyberRefusal, false)
	defer server.Close()

	provider := newTruncationTestProvider(server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	stream, bifrostErr := provider.ChatCompletionStream(ctx, truncationPassthroughPostHook, nil,
		schemas.Key{Value: *schemas.NewSecretVar("test-key")}, truncationChatRequest())
	if bifrostErr != nil {
		t.Fatalf("stream setup failed: %v", bifrostErr)
	}
	chunks := collectTruncationChunks(t, stream)
	if len(chunks) == 0 || chunks[len(chunks)-1].BifrostChatResponse == nil {
		t.Fatalf("expected a final chat chunk, got %d chunks", len(chunks))
	}
	final := chunks[len(chunks)-1].BifrostChatResponse
	if len(final.Choices) == 0 || final.Choices[0].FinishReason == nil || *final.Choices[0].FinishReason != "refusal" {
		t.Fatalf("final chunk choices = %#v, want finish reason refusal", final.Choices)
	}
	if final.StopDetails == nil || final.StopDetails.Category == nil || *final.StopDetails.Category != "cyber" {
		t.Fatalf("final chunk stop details = %#v, want category cyber", final.StopDetails)
	}
}
