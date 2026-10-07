package catalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEveryRuntimeDeploymentHasUniversalInputEstimate(t *testing.T) {
	snap := loadTestCatalog(t)
	seen := make(map[string]bool)
	for id, compiled := range snap.graph.Deployments {
		for _, routeID := range compiled.RouteIDs {
			// Include retained, deprecated deployments: their estimator remains
			// reviewable even though the request resolver no longer admits them.
			deployment := Deployment{ModelID: compiled.ModelID, ContextWindowTokens: compiled.ContextWindowTokens, MaxInputTokens: compiled.MaxInputTokens, snapshot: snap}
			for _, input := range []string{"Hello world", "你好 👩🏽‍💻 a\u0344", strings.Repeat("x", 20000)} {
				body, _ := json.Marshal(map[string]string{"input": input})
				raw, _ := DecodeRequestBody(body, nil)
				estimate := requestTokenEstimator(raw, RouteResponses, []routingSelection{{deployment: deployment}})
				got, err := estimate(deployment)
				if err != nil || got <= 0 || got > deployment.MaxInputTokens {
					t.Fatalf("%s/%s: invalid hold %d (%v)", id, routeID, got, err)
				}
			}
			seen[deployment.ModelID] = true
		}
	}
	for model := range snap.graph.Models {
		if !seen[model] {
			t.Errorf("model %s has no tested deployment", model)
		}
	}
}

func TestUniversalContentKeepsCandidateFramingSeparate(t *testing.T) {
	snap := loadTestCatalog(t)
	// The independent decimal text estimate is 34. All candidates share that
	// content estimate, while retaining their existing template allowances.
	raw, _ := DecodeRequestBody([]byte(`{"input":"Hello, world! 你好世界 👩🏽‍💻"}`), nil)
	cases := []struct {
		model string
		want  int
	}{
		{"gpt-5.6-sol", 118},
		{"claude-sonnet-5", 194},
		{"minimax-m3", 222},
		{"qwen3-32b", 194},
		{"qwen3.5-397b-a17b", 194},
	}
	for _, reverse := range []bool{false, true} {
		selections := make([]routingSelection, len(cases))
		for i, tc := range cases {
			selections[i].deployment = Deployment{ModelID: tc.model, MaxInputTokens: 10000, snapshot: snap}
		}
		estimate := requestTokenEstimator(raw, RouteResponses, selections)
		for i := range cases {
			if reverse {
				i = len(cases) - 1 - i
			}
			if got, err := estimate(selections[i].deployment); err != nil || got != cases[i].want {
				t.Fatalf("%s: %d want %d (%v)", cases[i].model, got, cases[i].want, err)
			}
		}
	}
}

func TestMiniMaxEmptyPromptFraming(t *testing.T) {
	// Pinned M3 public template, one empty user message, generation prompt.
	raw, _ := DecodeRequestBody([]byte(`{"messages":[{"role":"user","content":""}]}`), nil)
	if got := inputTokenHoldEstimate(t, raw, "minimax", RouteChat, 10000); got < 176 {
		t.Fatalf("hold %d misses the 176-token public template", got)
	}
}

func TestUniversalEstimateRejectsInvalidText(t *testing.T) {
	stats := inputHoldStats{TextFields: []string{"invalid\xff"}}
	if _, err := estimateInputContent(stats, 0); err == nil {
		t.Fatal("invalid input silently estimated")
	}
}

func TestClaudeHoldsRetainEmpiricalFloorForOfficialAdversarialCounts(t *testing.T) {
	// Official count_tokens captures, 2026-09-20: largest reference across
	// Opus 5, Sonnet 5 and Fable 5.1, each in one user message.
	for _, tc := range []struct {
		text   string
		tokens int
	}{
		{"Cmd ", 1036}, {"Iİıißẞſ ", 2321}, {"a\u0344\u0f73 ", 1549}, {"\ufdd0\ufdd1\ufdd2\ufdd3\ufdd4", 3863},
	} {
		body, _ := json.Marshal(map[string]any{"messages": []map[string]string{{"role": "user", "content": strings.Repeat(tc.text, 257)}}})
		raw, _ := DecodeRequestBody(body, nil)
		if got := inputTokenHoldEstimate(t, raw, "anthropic", RouteChat, 2_000_000); got*2 < tc.tokens {
			t.Fatalf("%q: %d below half of %d", tc.text, got, tc.tokens)
		}
	}
}

func TestLongInputAndEveryNonemptyFieldCountBeforeContextClipping(t *testing.T) {
	// Decimal reference: ceil(6.5897 + 0.4763 * 1,048,576) = 499,444.
	for _, text := range []string{strings.Repeat("a", 1<<20), strings.Repeat(" ", 1<<20)} {
		stats := inputHoldStats{TextFields: []string{text}}
		if got, err := estimateInputContent(stats, 2_000_000); err != nil || got != 499444 {
			t.Fatalf("long text: %d (%v)", got, err)
		}
		if got, err := estimateInputContent(stats, 100); err != nil || got != 100 {
			t.Fatalf("context cap: %d %v", got, err)
		}
	}
	stats := inputHoldStats{TextFields: make([]string, 600)}
	for i := 0; i < len(stats.TextFields); i += 2 {
		stats.TextFields[i] = "hello world"
	}
	// Each of 300 nonempty fields contributes 12; empty fields contribute zero.
	if got, err := estimateInputContent(stats, 0); err != nil || got != 3600 {
		t.Fatalf("fields omitted or rounded together: %d (%v)", got, err)
	}
}

func TestClaudeToolFramingCoversCatalogGenerationDifferences(t *testing.T) {
	// Same one-tool request: Opus 4.7 count_tokens reported 876 on
	// 2026-09-20, more than newer models. One author allowance covers both.
	body := []byte(`{"input":[{"role":"user","content":"Look up project status."}],"tools":[{"type":"function","name":"lookup_0","description":"The writer checked the invoice on Tuesday. Record 4074189 includes clear instructions and useful examples.\nThe teacher checked t","parameters":{"type":"object","properties":{"query":{"type":"string"},"nested":{"type":"array","items":{"type":"object","properties":{"value":{"type":"string"}},"additionalProperties":false,"required":["value"]}}},"required":["query","nested"],"additionalProperties":false},"strict":true}]}`)
	raw, err := DecodeRequestBody(body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := inputTokenHoldEstimate(t, raw, "anthropic", RouteResponses, 1_000_000); got < 876 {
		t.Fatalf("tool-format allowance missed an official reference: %d < 876", got)
	}
}

func TestSharedContentEstimateDoesNotReuseSmallContextCap(t *testing.T) {
	snap := loadTestCatalog(t)
	body, _ := json.Marshal(map[string]string{"input": strings.Repeat("hello world ", 1000)})
	raw, _ := DecodeRequestBody(body, nil)
	small := Deployment{ModelID: "gpt-5.6-sol", ContextWindowTokens: 100, MaxInputTokens: 100, snapshot: snap}
	large := Deployment{ModelID: "gpt-5.6-terra", ContextWindowTokens: 10000, MaxInputTokens: 10000, snapshot: snap}
	estimate := requestTokenEstimator(raw, RouteResponses, []routingSelection{{deployment: small}, {deployment: large}})
	if got, err := estimate(small); err != nil || got != 100 {
		t.Fatalf("small context: %d %v", got, err)
	}
	want := inputTokenHoldEstimate(t, raw, "openai", RouteResponses, 10000)
	if got, err := estimate(large); err != nil || got != want || got <= 100 {
		t.Fatalf("larger context: %d want %d (%v)", got, want, err)
	}
}
