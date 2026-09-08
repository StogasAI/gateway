package catalog

import (
	"fmt"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestRequestInputHoldStatsIncludesToolArgumentsAndAnthropicControls(t *testing.T) {
	arguments := strings.Repeat("A1+/", 2048)
	instructions := strings.Repeat("retain this detail ", 512)
	stopSequence := strings.Repeat("STOP", 256)
	body := []byte(fmt.Sprintf(`{
		"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":%q}}]}],
		"context_management":{"edits":[{"type":"compact_20260112","instructions":%q}]},
		"task_budget":{"type":"tokens","total":20000},
		"stop_sequences":[%q]
	}`, arguments, instructions, stopSequence))
	raw, err := rawRequestBody(body)
	if err != nil {
		t.Fatalf("parse request body: %v", err)
	}

	stats := requestInputHoldStats(raw, RouteChat)
	if stats.TextBytes < len(arguments)+len(instructions)+len(stopSequence) {
		t.Fatalf("provider-visible text was omitted from the input hold: got %d bytes", stats.TextBytes)
	}
	if stats.Messages != 1 || stats.ToolEvents != 1 {
		t.Fatalf("unexpected request structure counts: %#v", stats)
	}
}

func TestInputHoldSupportsTwoMillionTokenCatalogLimit(t *testing.T) {
	text := strings.Repeat("x", 2_000_001)
	body := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":%q}]}`, text))
	raw, err := rawRequestBody(body)
	if err != nil {
		t.Fatalf("parse large request body: %v", err)
	}
	if got := inputTokenHoldEstimate(body, raw, schemas.Anthropic, "future-model", RouteChat, 2_000_000); got != 2_000_000 {
		t.Fatalf("two-million-token hold = %d, want catalog limit", got)
	}
	if got := maxInputTokenHold(2_000_000, 128_000); got != 1_872_000 {
		t.Fatalf("two-million-token remaining context = %d, want 1872000", got)
	}
}

func TestInputHoldDoesNotDependOnJSONObjectKeyOrder(t *testing.T) {
	bodies := [][]byte{
		[]byte(`{"messages":[{"role":"user","content":"hello"}],"tools":[{"type":"function","function":{"name":"lookup","description":"find it","parameters":{"type":"object","properties":{"value":{"type":"string"}}}}}]}`),
		[]byte(`{"tools":[{"function":{"parameters":{"properties":{"value":{"type":"string"}},"type":"object"},"description":"find it","name":"lookup"},"type":"function"}],"messages":[{"content":"hello","role":"user"}]}`),
	}
	want := -1
	for _, body := range bodies {
		raw, err := rawRequestBody(body)
		if err != nil {
			t.Fatalf("parse request body: %v", err)
		}
		got := inputTokenHoldEstimate(body, raw, schemas.OpenAI, "gpt-5.6-sol", RouteChat, 1_000_000)
		if want < 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("equivalent object order changed hold from %d to %d", want, got)
		}
	}
}

func TestAnthropicAdversarialInputHoldUsesByteFloor(t *testing.T) {
	payload := strings.Repeat("A1+/", 4096)
	body := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":%q}]}`, payload))
	raw, err := rawRequestBody(body)
	if err != nil {
		t.Fatalf("parse request body: %v", err)
	}

	stats := requestInputHoldStats(raw, RouteChat)
	if !stats.AnthropicStrict {
		t.Fatal("adversarial high-entropy input did not select the strict hold")
	}
	structuralOverhead := anthropicInputHoldBaseTokens +
		anthropicInputHoldMessageTokens*stats.Messages +
		anthropicInputHoldBlockTokens*stats.ContentBlocks +
		anthropicInputHoldToolTokens*stats.ToolDefinitions +
		anthropicInputHoldToolEventTokens*stats.ToolEvents
	if got, wantMinimum := anthropicInputTokenHold(stats), stats.TextBytes+structuralOverhead; got < wantMinimum {
		t.Fatalf("adversarial input hold = %d, want at least byte floor %d", got, wantMinimum)
	}
}
