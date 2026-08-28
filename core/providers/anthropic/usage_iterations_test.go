package anthropic

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestAnthropicUsageBillingTotalsSumsEveryIteration(t *testing.T) {
	usage := &AnthropicUsage{
		InputTokens:  23_000,
		OutputTokens: 1_000,
		ServerToolUse: &AnthropicServerToolUseUsage{
			WebSearchRequests: 2,
		},
		Iterations: []AnthropicUsage{
			{
				InputTokens:              180_000,
				CacheCreationInputTokens: 2_000,
				CacheCreation:            AnthropicUsageCacheCreation{Ephemeral5mInputTokens: 2_000},
				OutputTokens:             3_500,
				OutputTokensDetails:      &AnthropicOutputTokensDetails{ThinkingTokens: 2_500},
				ServerToolUse:            &AnthropicServerToolUseUsage{WebSearchRequests: 1},
			},
			{
				InputTokens:          23_000,
				CacheReadInputTokens: 4_000,
				OutputTokens:         1_000,
				OutputTokensDetails:  &AnthropicOutputTokensDetails{ThinkingTokens: 400},
				ServerToolUse:        &AnthropicServerToolUseUsage{WebSearchRequests: 1},
			},
		},
	}

	total := usage.BillingTotals()
	if total.InputTokens != 203_000 || total.CacheCreationInputTokens != 2_000 || total.CacheReadInputTokens != 4_000 || total.OutputTokens != 4_500 {
		t.Fatalf("unexpected billing total: %#v", total)
	}
	if total.CacheCreation.Ephemeral5mInputTokens != 2_000 || total.OutputTokensDetails == nil || total.OutputTokensDetails.ThinkingTokens != 2_900 {
		t.Fatalf("iteration details were not summed: %#v", total)
	}
	if total.ServerToolUse == nil || total.ServerToolUse.WebSearchRequests != 2 {
		t.Fatalf("server tool count was not preserved: %#v", total.ServerToolUse)
	}

	converted := ConvertAnthropicUsageToBifrostUsage(usage)
	if converted.InputTokens != 209_000 || converted.OutputTokens != 4_500 || converted.TotalTokens != 213_500 {
		t.Fatalf("converted response did not expose billable totals: %#v", converted)
	}
	if len(converted.Iterations) != 2 || converted.InputTokensDetails == nil || converted.InputTokensDetails.CachedReadTokens != 4_000 || converted.InputTokensDetails.CachedWriteTokens != 2_000 {
		t.Fatalf("converted response lost iteration details: %#v", converted)
	}
	if converted.OutputTokensDetails == nil || converted.OutputTokensDetails.ReasoningTokens != 2_900 || converted.OutputTokensDetails.NumSearchQueries == nil || *converted.OutputTokensDetails.NumSearchQueries != 2 {
		t.Fatalf("converted output details were not aggregated: %#v", converted.OutputTokensDetails)
	}
}

func TestAnthropicChatUsageUsesIterationBillingTotals(t *testing.T) {
	response := (&AnthropicMessageResponse{
		ID:    "msg_test",
		Model: "claude-opus-5",
		Usage: &AnthropicUsage{
			InputTokens:  3,
			OutputTokens: 4,
			Iterations: []AnthropicUsage{
				{InputTokens: 100, CacheReadInputTokens: 20, OutputTokens: 30},
				{InputTokens: 40, CacheCreationInputTokens: 10, CacheCreation: AnthropicUsageCacheCreation{Ephemeral1hInputTokens: 10}, OutputTokens: 15},
			},
		},
	}).ToBifrostChatResponse(schemas.NewBifrostContext(t.Context(), schemas.NoDeadline))

	if response.Usage == nil || response.Usage.PromptTokens != 170 || response.Usage.CompletionTokens != 45 || response.Usage.TotalTokens != 215 {
		t.Fatalf("chat usage did not use iteration totals: %#v", response.Usage)
	}
	if response.Usage.PromptTokensDetails == nil || response.Usage.PromptTokensDetails.CachedReadTokens != 20 || response.Usage.PromptTokensDetails.CachedWriteTokens != 10 {
		t.Fatalf("chat cache details were not aggregated: %#v", response.Usage.PromptTokensDetails)
	}
}

func TestAnthropicStreamingUsageAccumulatesIterationBillingTotals(t *testing.T) {
	reported := &AnthropicUsage{
		InputTokens:  2,
		OutputTokens: 3,
		Iterations: []AnthropicUsage{
			{InputTokens: 100, CacheReadInputTokens: 20, OutputTokens: 30},
			{InputTokens: 40, CacheCreationInputTokens: 10, OutputTokens: 15},
		},
	}
	responseUsage := &schemas.ResponsesResponseUsage{}
	billedUsage := &schemas.BifrostLLMUsage{}
	accumulateAnthropicResponsesUsage(responseUsage, billedUsage, reported)
	normalizeCachedUsage(billedUsage)

	if responseUsage.InputTokens != 140 || responseUsage.OutputTokens != 45 || len(responseUsage.Iterations) != 2 {
		t.Fatalf("stream response accumulator lost iteration usage: %#v", responseUsage)
	}
	if billedUsage.PromptTokens != 170 || billedUsage.CompletionTokens != 45 || billedUsage.TotalTokens != 215 {
		t.Fatalf("stream billing accumulator did not sum iterations: %#v", billedUsage)
	}
}

func TestAnthropicUsageBillingTotalsRetainsUsableMalformedCounts(t *testing.T) {
	negative := (&AnthropicUsage{Iterations: []AnthropicUsage{{InputTokens: 10}, {InputTokens: -1}}}).BillingTotals()
	if negative.InputTokens != 10 {
		t.Fatalf("negative iteration usage erased a usable count: %#v", negative)
	}
	converted := ConvertAnthropicUsageToBifrostUsage(&AnthropicUsage{InputTokens: -1, OutputTokens: 7})
	if converted.TotalTokens != 7 {
		t.Fatalf("negative input usage erased usable output usage: %#v", converted)
	}
	overflow := (&AnthropicUsage{Iterations: []AnthropicUsage{{InputTokens: math.MaxInt}, {InputTokens: 1}}}).BillingTotals()
	if overflow.InputTokens != math.MaxInt {
		t.Fatalf("overflowing iteration usage was not saturated: %#v", overflow)
	}
}

func TestAnthropicCompactionNegativeFieldsCannotPoisonOtherUsableIterationUsage(t *testing.T) {
	tests := []struct {
		name string
		set  func(*AnthropicUsage, int)
		get  func(*AnthropicUsage) int
	}{
		{name: "input", set: func(usage *AnthropicUsage, value int) { usage.InputTokens = value }, get: func(usage *AnthropicUsage) int { return usage.InputTokens }},
		{name: "cache creation", set: func(usage *AnthropicUsage, value int) { usage.CacheCreationInputTokens = value }, get: func(usage *AnthropicUsage) int { return usage.CacheCreationInputTokens }},
		{name: "cache read", set: func(usage *AnthropicUsage, value int) { usage.CacheReadInputTokens = value }, get: func(usage *AnthropicUsage) int { return usage.CacheReadInputTokens }},
		{name: "five minute cache write", set: func(usage *AnthropicUsage, value int) { usage.CacheCreation.Ephemeral5mInputTokens = value }, get: func(usage *AnthropicUsage) int { return usage.CacheCreation.Ephemeral5mInputTokens }},
		{name: "one hour cache write", set: func(usage *AnthropicUsage, value int) { usage.CacheCreation.Ephemeral1hInputTokens = value }, get: func(usage *AnthropicUsage) int { return usage.CacheCreation.Ephemeral1hInputTokens }},
		{name: "output", set: func(usage *AnthropicUsage, value int) { usage.OutputTokens = value }, get: func(usage *AnthropicUsage) int { return usage.OutputTokens }},
		{
			name: "thinking",
			set: func(usage *AnthropicUsage, value int) {
				usage.OutputTokensDetails = &AnthropicOutputTokensDetails{ThinkingTokens: value}
			},
			get: func(usage *AnthropicUsage) int {
				if usage.OutputTokensDetails == nil {
					return 0
				}
				return usage.OutputTokensDetails.ThinkingTokens
			},
		},
		{
			name: "web search",
			set: func(usage *AnthropicUsage, value int) {
				usage.ServerToolUse = &AnthropicServerToolUseUsage{WebSearchRequests: value}
			},
			get: func(usage *AnthropicUsage) int {
				if usage.ServerToolUse == nil {
					return 0
				}
				return usage.ServerToolUse.WebSearchRequests
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			usable := AnthropicUsage{}
			malformed := AnthropicUsage{}
			test.set(&usable, 10)
			test.set(&malformed, -1)
			total := (&AnthropicUsage{Iterations: []AnthropicUsage{usable, malformed}}).BillingTotals()
			if got := test.get(total); got != 10 {
				t.Fatalf("usable %s count was poisoned: got %d, want 10; total=%#v", test.name, got, total)
			}
		})
	}
}

func TestAnthropicUsageBillingTotalsPreservesMixedRateIterationTopLevel(t *testing.T) {
	for _, iterationType := range []string{AnthropicUsageIterationTypeFallbackMessage, "advisor_message"} {
		t.Run(iterationType, func(t *testing.T) {
			usage := &AnthropicUsage{
				InputTokens:  12,
				OutputTokens: 34,
				Iterations: []AnthropicUsage{
					{Type: schemas.Ptr("message"), InputTokens: 100, OutputTokens: 10},
					{Type: schemas.Ptr(iterationType), Model: schemas.Ptr("claude-opus-4-8"), InputTokens: 200, OutputTokens: 20},
				},
			}

			if total := usage.BillingTotals(); total != usage {
				t.Fatalf("mixed-rate %s iterations must preserve authoritative top-level usage: %#v", iterationType, total)
			}
			converted := ConvertAnthropicUsageToBifrostUsage(usage)
			if converted.InputTokens != 12 || converted.OutputTokens != 34 || converted.TotalTokens != 46 || len(converted.Iterations) != 2 {
				t.Fatalf("mixed-rate %s conversion changed top-level billing: %#v", iterationType, converted)
			}
		})
	}
}

func TestContextManagementUsesClearAtLeastWireName(t *testing.T) {
	var contextManagement ContextManagement
	input := `{"edits":[{"type":"clear_tool_uses_20250919","clear_at_least":{"type":"input_tokens","value":5000}}]}`
	if err := json.Unmarshal([]byte(input), &contextManagement); err != nil {
		t.Fatalf("unmarshal context management: %v", err)
	}
	wire, err := json.Marshal(contextManagement)
	if err != nil {
		t.Fatalf("marshal context management: %v", err)
	}
	if !strings.Contains(string(wire), `"clear_at_least"`) || strings.Contains(string(wire), `"clear_at_last"`) {
		t.Fatalf("wrong clear-at-least wire name: %s", wire)
	}
}
