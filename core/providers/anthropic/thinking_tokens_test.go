package anthropic

import (
	"context"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
)

// realThinkingUsage is a verbatim usage block from a Claude extended-thinking
// response. Note thinking_tokens (39) is a SUBSET of output_tokens (87) — the two
// must never be summed.
const realThinkingUsage = `{
  "input_tokens": 23,
  "cache_creation_input_tokens": 0,
  "cache_read_input_tokens": 0,
  "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0},
  "output_tokens": 87,
  "output_tokens_details": {"thinking_tokens": 39}
}`

func mustParseUsage(t *testing.T, raw string) *AnthropicUsage {
	t.Helper()
	var u AnthropicUsage
	if err := sonic.Unmarshal([]byte(raw), &u); err != nil {
		t.Fatalf("unmarshal usage: %v", err)
	}
	return &u
}

func TestAnthropicUsage_UnmarshalsThinkingTokens(t *testing.T) {
	u := mustParseUsage(t, realThinkingUsage)
	if u.OutputTokensDetails == nil {
		t.Fatal("OutputTokensDetails is nil; thinking_tokens was dropped at unmarshal")
	}
	if got := u.OutputTokensDetails.ThinkingTokens; got != 39 {
		t.Errorf("ThinkingTokens = %d, want 39", got)
	}
}

func TestChatConversion_ThinkingTokensAreSubsetOfCompletion(t *testing.T) {
	resp := &AnthropicMessageResponse{Usage: mustParseUsage(t, realThinkingUsage)}
	got := resp.ToBifrostChatResponse(nil)

	if got.Usage == nil || got.Usage.CompletionTokensDetails == nil {
		t.Fatal("CompletionTokensDetails is nil; reasoning tokens were dropped")
	}
	if r := got.Usage.CompletionTokensDetails.ReasoningTokens; r != 39 {
		t.Errorf("ReasoningTokens = %d, want 39", r)
	}
	// The invariant: reasoning is inside completion, not added to it.
	if got.Usage.CompletionTokens != 87 {
		t.Errorf("CompletionTokens = %d, want 87 (thinking must not be added)", got.Usage.CompletionTokens)
	}
	if got.Usage.CompletionTokensDetails.ReasoningTokens > got.Usage.CompletionTokens {
		t.Error("invariant violated: ReasoningTokens > CompletionTokens")
	}
	if got.Usage.TotalTokens != got.Usage.PromptTokens+got.Usage.CompletionTokens {
		t.Errorf("TotalTokens = %d, want PromptTokens+CompletionTokens = %d",
			got.Usage.TotalTokens, got.Usage.PromptTokens+got.Usage.CompletionTokens)
	}
}

func TestChatConversion_NoThinkingLeavesReasoningZero(t *testing.T) {
	resp := &AnthropicMessageResponse{
		Usage: mustParseUsage(t, `{"input_tokens": 10, "output_tokens": 5}`),
	}
	got := resp.ToBifrostChatResponse(nil)
	if got.Usage.CompletionTokensDetails != nil &&
		got.Usage.CompletionTokensDetails.ReasoningTokens != 0 {
		t.Errorf("ReasoningTokens = %d on a non-thinking response, want 0",
			got.Usage.CompletionTokensDetails.ReasoningTokens)
	}
}

func TestResponsesConversion_CarriesThinkingTokens(t *testing.T) {
	got := ConvertAnthropicUsageToBifrostUsage(mustParseUsage(t, realThinkingUsage))
	if got == nil || got.OutputTokensDetails == nil {
		t.Fatal("OutputTokensDetails is nil; reasoning tokens were dropped")
	}
	if r := got.OutputTokensDetails.ReasoningTokens; r != 39 {
		t.Errorf("ReasoningTokens = %d, want 39", r)
	}
	if got.OutputTokens != 87 {
		t.Errorf("OutputTokens = %d, want 87 (thinking must not be added)", got.OutputTokens)
	}
}

func TestUsageRoundTrip_PreservesThinkingTokens(t *testing.T) {
	original := mustParseUsage(t, realThinkingUsage)
	back := ConvertBifrostUsageToAnthropicUsage(ConvertAnthropicUsageToBifrostUsage(original))

	if back == nil || back.OutputTokensDetails == nil {
		t.Fatal("thinking tokens lost on Anthropic->Bifrost->Anthropic round trip")
	}
	if back.OutputTokensDetails.ThinkingTokens != original.OutputTokensDetails.ThinkingTokens {
		t.Errorf("ThinkingTokens = %d after round trip, want %d",
			back.OutputTokensDetails.ThinkingTokens, original.OutputTokensDetails.ThinkingTokens)
	}
	if back.OutputTokens != original.OutputTokens {
		t.Errorf("OutputTokens = %d after round trip, want %d", back.OutputTokens, original.OutputTokens)
	}
}

// Anthropic reports thinking tokens as a running per-request total across
// message_start and message_delta. The accumulator must max-merge, not sum.
func TestResponsesAccumulator_MaxMergesRatherThanSums(t *testing.T) {
	usage := &schemas.ResponsesResponseUsage{}
	billed := &schemas.BifrostLLMUsage{}

	for _, raw := range []string{
		`{"input_tokens": 23, "output_tokens": 20, "output_tokens_details": {"thinking_tokens": 20}}`,
		`{"input_tokens": 23, "output_tokens": 87, "output_tokens_details": {"thinking_tokens": 39}}`,
		// Out-of-order/stale event must not regress the accumulated value.
		`{"input_tokens": 23, "output_tokens": 50, "output_tokens_details": {"thinking_tokens": 30}}`,
	} {
		accumulateAnthropicResponsesUsage(usage, billed, mustParseUsage(t, raw))
	}

	if usage.OutputTokensDetails == nil {
		t.Fatal("OutputTokensDetails is nil after accumulation")
	}
	if r := usage.OutputTokensDetails.ReasoningTokens; r != 39 {
		t.Errorf("ReasoningTokens = %d, want 39 (max, not sum of 20+39+30=89)", r)
	}
	if billed.CompletionTokensDetails == nil {
		t.Fatal("billed usage did not receive reasoning tokens")
	}
	if r := billed.CompletionTokensDetails.ReasoningTokens; r != 39 {
		t.Errorf("billed ReasoningTokens = %d, want 39", r)
	}
	if usage.OutputTokensDetails.ReasoningTokens > usage.OutputTokens {
		t.Error("invariant violated: ReasoningTokens > OutputTokens")
	}
}

// Adaptive thinking that chose not to think streams an explicit thinking_tokens: 0
// on message_delta. The accumulator must keep that breakdown, as the non-streaming
// converter does, or the Bedrock invoke stream egress drops output_tokens_details
// (#7649 follow-up). The billing handle keeps it as a reported count, so a stream
// cut later still records reasoning as 0 rather than unknown; a zero adds no cost.
func TestResponsesAccumulator_KeepsExplicitZeroThinkingTokens(t *testing.T) {
	usage := &schemas.ResponsesResponseUsage{}
	billed := &schemas.BifrostLLMUsage{}

	accumulateAnthropicResponsesUsage(usage, billed, mustParseUsage(t, `{"input_tokens": 63, "output_tokens": 1}`))
	accumulateAnthropicResponsesUsage(usage, billed, mustParseUsage(t, zeroThinkingUsage))

	if usage.OutputTokensDetails == nil {
		t.Fatal("OutputTokensDetails is nil; an explicit thinking_tokens: 0 breakdown was dropped in streaming")
	}
	if r := usage.OutputTokensDetails.ReasoningTokens; r != 0 || !usage.OutputTokensDetails.ReasoningTokensReported {
		t.Errorf("ReasoningTokens = %d, reported %v; want a reported 0", r, usage.OutputTokensDetails.ReasoningTokensReported)
	}
	if billed.CompletionTokensDetails == nil || billed.CompletionTokensDetails.ReasoningTokens != 0 ||
		!billed.CompletionTokensDetails.ReasoningTokensReported {
		t.Errorf("billed CompletionTokensDetails = %+v, want a reported 0", billed.CompletionTokensDetails)
	}
}

func TestResponsesAccumulator_AbsentDetailsStayAbsent(t *testing.T) {
	usage := &schemas.ResponsesResponseUsage{}
	accumulateAnthropicResponsesUsage(usage, nil, mustParseUsage(t, `{"input_tokens": 10, "output_tokens": 5}`))
	if usage.OutputTokensDetails != nil {
		t.Errorf("OutputTokensDetails = %+v on a stream without a breakdown, want nil", usage.OutputTokensDetails)
	}
	billed := &schemas.BifrostLLMUsage{}
	accumulateAnthropicResponsesUsage(&schemas.ResponsesResponseUsage{}, billed, mustParseUsage(t, `{"input_tokens": 10, "output_tokens": 5}`))
	if billed.CompletionTokensDetails != nil {
		t.Errorf("billed CompletionTokensDetails = %+v on a stream without a breakdown, want nil", billed.CompletionTokensDetails)
	}
}

func TestPassthroughStream_MergesThinkingTokensAcrossEvents(t *testing.T) {
	var acc AnthropicPassthroughStreamUsage

	// message_start nests usage under message.usage and has no output counts yet.
	acc.ObserveEvent([]byte(`{"type":"message_start","message":{"usage":{"input_tokens":23,"output_tokens":0}}}`))
	// message_delta carries usage at the top level, including the thinking breakdown.
	got := acc.ObserveEvent([]byte(`{"type":"message_delta","usage":{"input_tokens":23,"output_tokens":87,"output_tokens_details":{"thinking_tokens":39}}}`))

	if got == nil || got.LLMUsage == nil {
		t.Fatal("no usage assembled from stream")
	}
	if got.LLMUsage.CompletionTokensDetails == nil {
		t.Fatal("CompletionTokensDetails is nil; reasoning tokens were dropped in streaming passthrough")
	}
	if r := got.LLMUsage.CompletionTokensDetails.ReasoningTokens; r != 39 {
		t.Errorf("ReasoningTokens = %d, want 39", r)
	}
	if got.LLMUsage.CompletionTokens != 87 {
		t.Errorf("CompletionTokens = %d, want 87", got.LLMUsage.CompletionTokens)
	}
}

// zeroThinkingUsage is a verbatim usage block from a Bedrock InvokeModel Sonnet 5
// response where adaptive thinking was requested but the model chose not to think
// (#7649 follow-up). Anthropic still reports the breakdown, as an explicit zero.
const zeroThinkingUsage = `{
  "input_tokens": 63,
  "cache_creation_input_tokens": 0,
  "cache_read_input_tokens": 0,
  "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0},
  "output_tokens": 281,
  "output_tokens_details": {"thinking_tokens": 0}
}`

// A breakdown the upstream explicitly sent must survive the round trip even when
// it is zero: presence is the signal, not the count. Absent upstream details
// (TestChatConversion_NoThinkingLeavesReasoningZero) still stay absent.
func TestResponsesConversion_KeepsExplicitZeroThinkingTokens(t *testing.T) {
	got := ConvertAnthropicUsageToBifrostUsage(mustParseUsage(t, zeroThinkingUsage))
	if got == nil || got.OutputTokensDetails == nil {
		t.Fatal("OutputTokensDetails is nil; an explicit thinking_tokens: 0 breakdown was dropped")
	}
	if got.OutputTokensDetails.ReasoningTokens != 0 || !got.OutputTokensDetails.ReasoningTokensReported {
		t.Errorf("ReasoningTokens = %d, reported %v; want a reported 0", got.OutputTokensDetails.ReasoningTokens, got.OutputTokensDetails.ReasoningTokensReported)
	}
	if got.OutputTokens != 281 {
		t.Errorf("OutputTokens = %d, want 281", got.OutputTokens)
	}
}

func TestUsageRoundTrip_PreservesExplicitZeroThinkingTokens(t *testing.T) {
	back := ConvertBifrostUsageToAnthropicUsage(ConvertAnthropicUsageToBifrostUsage(mustParseUsage(t, zeroThinkingUsage)))
	if back == nil || back.OutputTokensDetails == nil {
		t.Fatal("explicit thinking_tokens: 0 lost on Anthropic->Bifrost->Anthropic round trip")
	}
	if back.OutputTokensDetails.ThinkingTokens != 0 {
		t.Errorf("ThinkingTokens = %d after round trip, want 0", back.OutputTokensDetails.ThinkingTokens)
	}
}

func TestUsageConversion_AbsentDetailsStayAbsent(t *testing.T) {
	got := ConvertAnthropicUsageToBifrostUsage(mustParseUsage(t, `{"input_tokens": 10, "output_tokens": 5}`))
	if got.OutputTokensDetails != nil {
		t.Errorf("OutputTokensDetails = %+v on a response without a breakdown, want nil", got.OutputTokensDetails)
	}
	back := ConvertBifrostUsageToAnthropicUsage(got)
	if back.OutputTokensDetails != nil {
		t.Errorf("Anthropic OutputTokensDetails = %+v without an upstream breakdown, want nil", back.OutputTokensDetails)
	}
}

func TestChatConversion_KeepsExplicitZeroThinkingTokens(t *testing.T) {
	resp := &AnthropicMessageResponse{Usage: mustParseUsage(t, zeroThinkingUsage)}
	got := resp.ToBifrostChatResponse(nil)
	if got.Usage == nil || got.Usage.CompletionTokensDetails == nil {
		t.Fatal("CompletionTokensDetails is nil; an explicit thinking_tokens: 0 breakdown was dropped")
	}
	if got.Usage.CompletionTokensDetails.ReasoningTokens != 0 || !got.Usage.CompletionTokensDetails.ReasoningTokensReported {
		t.Errorf("ReasoningTokens = %d, reported %v; want a reported 0", got.Usage.CompletionTokensDetails.ReasoningTokens, got.Usage.CompletionTokensDetails.ReasoningTokensReported)
	}
	if encoded, err := schemas.Marshal(got.Usage.CompletionTokensDetails); err != nil || string(encoded) != `{"reasoning_tokens":0}` {
		t.Errorf("client completion_tokens_details = %s, %v; want the reported 0", encoded, err)
	}
}

func TestPassthroughUsage_KeepsExplicitZeroThinkingTokens(t *testing.T) {
	got := buildAnthropicPassthroughUsage(mustParseUsage(t, zeroThinkingUsage))
	if got == nil || got.LLMUsage == nil || got.LLMUsage.CompletionTokensDetails == nil {
		t.Fatal("CompletionTokensDetails is nil; an explicit thinking_tokens: 0 breakdown was dropped")
	}
	if details := got.LLMUsage.CompletionTokensDetails; details.ReasoningTokens != 0 || !details.ReasoningTokensReported {
		t.Errorf("ReasoningTokens = %d, reported %v; want a reported 0", details.ReasoningTokens, details.ReasoningTokensReported)
	}
	if absent := buildAnthropicPassthroughUsage(mustParseUsage(t, `{"input_tokens": 10, "output_tokens": 5}`)); absent.LLMUsage.CompletionTokensDetails != nil {
		t.Errorf("CompletionTokensDetails = %+v without an upstream breakdown, want nil", absent.LLMUsage.CompletionTokensDetails)
	}
}

// The chat stream reads thinking tokens from message_delta itself, apart from the
// Responses accumulator, so it needs its own check of the explicit zero.
func TestChatStream_KeepsExplicitZeroThinkingTokens(t *testing.T) {
	for name, test := range map[string]struct {
		usage    string
		reported bool
	}{
		"explicit zero": {`{"output_tokens":3,"output_tokens_details":{"thinking_tokens":0}}`, true},
		"no breakdown":  {`{"output_tokens":3}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			server := anthropicSSEServer(t, anthropicMessageStartPriority+anthropicTextDelta+
				"event: content_block_stop\n"+`data: {"type":"content_block_stop","index":0}`+"\n\n"+
				"event: message_delta\n"+
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":`+test.usage+"}\n\n"+
				"event: message_stop\n"+`data: {"type":"message_stop"}`+"\n\n", false)
			defer server.Close()
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			stream, bifrostErr := newTruncationTestProvider(server.URL).ChatCompletionStream(ctx, truncationPassthroughPostHook, nil,
				schemas.Key{Value: *schemas.NewSecretVar("test-key")}, truncationChatRequest())
			if bifrostErr != nil {
				t.Fatalf("stream setup failed: %v", bifrostErr)
			}
			var usage *schemas.BifrostLLMUsage
			for _, chunk := range collectTruncationChunks(t, stream) {
				if chunk.BifrostError != nil {
					t.Fatalf("unexpected stream error: %+v", chunk.BifrostError)
				}
				if chunk.BifrostChatResponse != nil && chunk.BifrostChatResponse.Usage != nil {
					usage = chunk.BifrostChatResponse.Usage
				}
			}
			if usage == nil {
				t.Fatal("the stream reported no usage")
			}
			reported := usage.CompletionTokensDetails != nil && usage.CompletionTokensDetails.ReasoningTokensReported
			if reported != test.reported || usage.CompletionTokensDetails != nil && usage.CompletionTokensDetails.ReasoningTokens != 0 {
				t.Fatalf("completion details = %+v; want reported %v with 0 reasoning tokens", usage.CompletionTokensDetails, test.reported)
			}
		})
	}
}
