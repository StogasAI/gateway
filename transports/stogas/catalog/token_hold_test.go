package catalog

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func inputTokenHoldEstimate(t *testing.T, rawData map[string]json.RawMessage, author string, route Route, maxInputTokens int) int {
	t.Helper()
	stats := requestInputHoldStats(rawData, route)
	result, err := estimateInputContent(stats, maxInputTokens)
	if err != nil {
		t.Fatal(err)
	}
	result += inputHoldFraming(stats, author)
	if maxInputTokens > 0 {
		result = min(result, maxInputTokens)
	}
	return result
}

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
	raw, err := DecodeRequestBody(body, nil)
	if err != nil {
		t.Fatalf("parse request body: %v", err)
	}

	stats := requestInputHoldStats(raw, RouteChat)
	fields := strings.Join(stats.TextFields, "\n")
	if !strings.Contains(fields, arguments) || !strings.Contains(fields, instructions) || !strings.Contains(fields, stopSequence) {
		t.Fatal("provider-visible text was omitted from the input hold")
	}
	if stats.Messages != 1 || stats.ToolEvents != 1 {
		t.Fatalf("unexpected request structure counts: %#v", stats)
	}
}

func TestInputHoldSupportsTwoMillionTokenCatalogLimit(t *testing.T) {
	text := strings.Repeat("\ufdd0", 1_000_000)
	body := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":%q}]}`, text))
	raw, err := DecodeRequestBody(body, nil)
	if err != nil {
		t.Fatalf("parse large request body: %v", err)
	}
	if got := inputTokenHoldEstimate(t, raw, "anthropic", RouteChat, 2_000_000); got != 2_000_000 {
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
		raw, err := DecodeRequestBody(body, nil)
		if err != nil {
			t.Fatalf("parse request body: %v", err)
		}
		got := inputTokenHoldEstimate(t, raw, "openai", RouteChat, 1_000_000)
		if want < 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("equivalent object order changed hold from %d to %d", want, got)
		}
	}
}

func TestOpaqueReasoningUsesBytesWithoutTokenizingCiphertext(t *testing.T) {
	opaque := strings.Repeat("opaqueCiphertext_", 128)
	for _, tc := range []struct {
		name, body string
		route      Route
	}{
		{"responses", `{"input":[{"type":"reasoning","summary":[{"type":"summary_text","text":"summary"}],"encrypted_content":%q}]}`, RouteResponses},
		{"signed chat", `{"messages":[{"role":"assistant","reasoning_details":[{"type":"reasoning.text","text":"summary","signature":%q}]}]}`, RouteChat},
		{"redacted chat", `{"messages":[{"role":"assistant","reasoning_details":[{"type":"reasoning.encrypted","data":%q}]}]}`, RouteChat},
		{"thinking block", `{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"summary","signature":%q}]}]}`, RouteChat},
		{"redacted block", `{"messages":[{"role":"assistant","content":[{"type":"redacted_thinking","data":%q}]}]}`, RouteChat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := DecodeRequestBody([]byte(fmt.Sprintf(tc.body, opaque)), nil)
			if err != nil {
				t.Fatal(err)
			}
			stats := requestInputHoldStats(raw, tc.route)
			if stats.OpaqueReasoningBytes != len(opaque) || strings.Contains(strings.Join(stats.TextFields, ""), opaque) {
				t.Fatal("reasoning ciphertext was omitted or sent to the text tokenizer")
			}
			if strings.Contains(strings.Join(stats.TextFields, ""), "summary") {
				t.Fatal("a display summary was counted again beside its encrypted thinking")
			}
			estimate, err := estimateInputContent(stats, 100_000)
			if err != nil {
				t.Fatal(err)
			}
			visible := stats
			visible.OpaqueReasoningBytes = 0
			textEstimate, err := estimateInputContent(visible, 100_000)
			if err != nil {
				t.Fatal(err)
			}
			if estimate != textEstimate+len(opaque) {
				t.Fatalf("opaque bytes must be counted exactly once: %d versus %d visible", estimate, textEstimate)
			}
			capped, err := estimateInputContent(stats, 1000)
			if err != nil || capped != 1000 {
				t.Fatalf("context cap: %d, %v", capped, err)
			}
		})
	}
}

func TestSignedReasoningSummaryDoesNotMultiplyTheEstimate(t *testing.T) {
	opaque := strings.Repeat("encoded_", 64)
	var expected int
	for _, summary := range []string{"", "short", strings.Repeat("visible summary ", 4096)} {
		body := fmt.Sprintf(`{"messages":[{"role":"user","content":"question"},{"role":"assistant","content":"answer","reasoning":%q,"reasoning_details":[{"index":0,"type":"reasoning.text","text":%q,"signature":%q}]},{"role":"user","content":"continue"}]}`, summary, summary, opaque)
		raw, err := DecodeRequestBody([]byte(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		estimate, err := estimateInputContent(requestInputHoldStats(raw, RouteChat), 100_000)
		if err != nil {
			t.Fatal(err)
		}
		if expected == 0 {
			expected = estimate
		} else if estimate != expected {
			t.Fatalf("display summary changed the estimate: %d versus %d", estimate, expected)
		}
	}
	// Unsigned reasoning is text on providers that accept it, and must retain
	// its cost. Do not classify arbitrary reasoning-like strings as ciphertext.
	raw, err := DecodeRequestBody([]byte(`{"messages":[{"role":"assistant","content":"answer","reasoning":"actual plaintext thinking"}]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	stats := requestInputHoldStats(raw, RouteChat)
	if stats.OpaqueReasoningBytes != 0 || !strings.Contains(strings.Join(stats.TextFields, ""), "actual plaintext thinking") {
		t.Fatal("unsigned thinking was dropped")
	}
}

func TestReasoningPropertiesInToolInputRemainText(t *testing.T) {
	raw, err := DecodeRequestBody([]byte(`{"messages":[{"role":"tool","content":"{\"type\":\"reasoning\",\"encrypted_content\":\"ordinary user text\"}"}]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	stats := requestInputHoldStats(raw, RouteChat)
	if stats.OpaqueReasoningBytes != 0 || !strings.Contains(strings.Join(stats.TextFields, ""), "ordinary user text") {
		t.Fatal("user text was mistaken for a provider reasoning envelope")
	}
}

func TestRequestEstimatorUsesEachDeploymentsIndependentInputCeiling(t *testing.T) {
	snap := loadTestCatalog(t)
	raw, err := DecodeRequestBody([]byte(`{"input":"`+strings.Repeat("UNCOMMONWORD ", 1000)+`"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	model := "gpt-5.6-sol"
	small := Deployment{ModelID: model, ContextWindowTokens: 10000, MaxInputTokens: 100, snapshot: snap}
	large := Deployment{ModelID: model, ContextWindowTokens: 10000, MaxInputTokens: 300, snapshot: snap}
	estimate := requestTokenEstimator(raw, RouteResponses, []routingSelection{{deployment: small}, {deployment: large}})
	for _, deployment := range []Deployment{small, large, small} {
		got, err := estimate(deployment)
		if err != nil || got != deployment.MaxInputTokens {
			t.Fatalf("input ceiling %d: got %d, %v", deployment.MaxInputTokens, got, err)
		}
	}
}
