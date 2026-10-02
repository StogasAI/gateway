package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/tokenizer"
)

func TestEveryRuntimeDeploymentHasExplicitTokenization(t *testing.T) {
	snap := loadTestCatalog(t)
	seen := make(map[string]bool)
	for id, compiled := range snap.graph.Deployments {
		for _, routeID := range compiled.RouteIDs {
			// Include retained, deprecated deployments: their estimator remains
			// reviewable even though the request resolver no longer admits them.
			deployment := Deployment{ModelID: compiled.ModelID, ContextWindowTokens: compiled.ContextWindowTokens, snapshot: snap}
			for _, input := range []string{"Hello world", "你好 👩🏽‍💻 a\u0344", strings.Repeat("x", 20000)} {
				body, _ := json.Marshal(map[string]string{"input": input})
				raw, _ := DecodeRequestBody(body, nil)
				estimate := requestTokenEstimator(raw, RouteResponses, []routingSelection{{deployment: deployment}})
				got, err := estimate(deployment)
				if err != nil || got <= 0 || got > deployment.ContextWindowTokens {
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

func TestQwenVocabularyVersionAndRoutingCache(t *testing.T) {
	snap := loadTestCatalog(t)
	// This string differs between the two published Qwen vocabularies.
	raw, _ := DecodeRequestBody([]byte(`{"input":"Hello, world! 你好世界 👩🏽‍💻"}`), nil)
	old := Deployment{ModelID: "qwen3-32b", ContextWindowTokens: 10000, snapshot: snap}
	current := Deployment{ModelID: "qwen3.5-397b-a17b", ContextWindowTokens: 10000, snapshot: snap}
	for _, order := range [][]Deployment{{old, current}, {current, old}} {
		estimate := requestTokenEstimator(raw, RouteResponses, []routingSelection{{deployment: order[0]}, {deployment: order[1]}})
		for _, deployment := range order {
			// Published tokenizer text references: Qwen3=13, Qwen3.5=16.
			textTokens := 16
			if deployment.ModelID == old.ModelID {
				textTokens = 13
			}
			want := (textTokens*103+99)/100 + 128 + 20 + 12
			if got, err := estimate(deployment); err != nil || got != want {
				t.Fatalf("%s: %d want %d (%v)", deployment.ModelID, got, want, err)
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

func TestCatalogRejectsMissingOrUnknownTokenizerFamily(t *testing.T) {
	for _, family := range []any{nil, "", "automatic", "qwen", "Qwen3", " qwen3", 1, []string{"qwen3"}} {
		var data map[string]any
		if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &data); err != nil {
			t.Fatal(err)
		}
		models := data["graph"].(map[string]any)["models"].(map[string]any)
		model := models["qwen3-32b"].(map[string]any)
		if family == nil {
			delete(model, "tokenizerFamily")
		} else {
			model["tokenizerFamily"] = family
		}
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := snapshotFromCatalogBytes(raw); err == nil || !strings.Contains(err.Error(), "tokenizerFamily") {
			t.Fatalf("family %#v: catalog should reject unsupported tokenization: %v", family, err)
		}
	}
}

func TestCatalogTokenizerChangeIsExplicitAndSnapshotBound(t *testing.T) {
	old, err := loadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	var data compiledCatalog
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &data); err != nil {
		t.Fatal(err)
	}
	// A model name that used to be special-cased now explicitly selects the
	// newer vocabulary. Even a new author must not change that selection.
	model := data.Graph.Models["qwen3-32b"]
	model.TokenizerFamily = tokenizationQwen35
	model.AuthorID = "new-author"
	data.Graph.Models["qwen3-32b"] = model
	data.Graph.Authors["new-author"] = compiledAuthor{Name: "New author"}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	current, err := snapshotFromCatalogBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := DecodeRequestBody([]byte(`{"input":"Hello, world! 你好世界 👩🏽‍💻"}`), nil)
	for _, tc := range []struct {
		snapshot *snapshot
		want     int
	}{{old, 174}, {current, 177}, {old, 174}} {
		deployment := Deployment{ModelID: "qwen3-32b", ContextWindowTokens: 10000, snapshot: tc.snapshot}
		estimate := requestTokenEstimator(body, RouteResponses, []routingSelection{{deployment: deployment}})
		if got, err := estimate(deployment); err != nil || got != tc.want {
			t.Fatalf("snapshot hold %d want %d (%v)", got, tc.want, err)
		}
	}
}

func TestInputHoldRejectsInvalidTextAndUnknownFamily(t *testing.T) {
	stats := inputHoldStats{TextFields: []string{"invalid\xff"}}
	for _, strategy := range []tokenizationStrategy{tokenizationOpenAI, tokenizationAnthropic, ""} {
		if _, err := estimateInputHold(stats, strategy, 0); err == nil {
			t.Fatal("invalid input silently estimated")
		}
	}
}

func TestClaudeHoldsCoverOfficialAdversarialCounts(t *testing.T) {
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
		if got := inputTokenHoldEstimate(t, raw, "anthropic", RouteChat, 2_000_000); got < tc.tokens {
			t.Fatalf("%q: %d < %d", tc.text, got, tc.tokens)
		}
	}
}

func TestLongInputCountsAllFieldsBeforeContextClipping(t *testing.T) {
	codec, _ := tokenizer.Get(tokenizer.O200kBase)
	for _, text := range []string{strings.Repeat("x", 1<<20), strings.Repeat(" ", 1<<20), strings.Repeat("hello world ", 100000)} {
		stats := inputHoldStats{TextFields: []string{text}}
		tokens, _ := codec.Count(text)
		want := ceilMulDiv(tokens, openAIInputHoldTextBufferBps, 10000) + openAIInputHoldBaseTokens
		got, err := estimateInputHold(stats, tokenizationOpenAI, 2_000_000)
		if err != nil || got != want || got >= len(text) {
			t.Fatalf("unnecessary byte hold: %d want %d (%v)", got, want, err)
		}
		if got, err := estimateInputHold(stats, tokenizationOpenAI, 100); err != nil || got != 100 {
			t.Fatalf("context cap: %d %v", got, err)
		}
	}
	stats := inputHoldStats{TextFields: make([]string, 300)}
	for i := range stats.TextFields {
		stats.TextFields[i] = "hello world"
	}
	got, err := openAIInputTokenHold(stats, 0)
	count, _ := codec.Count("hello world")
	want := ceilMulDiv(300*count, openAIInputHoldTextBufferBps, 10000) + openAIInputHoldBaseTokens
	if err != nil || got != want {
		t.Fatalf("fields omitted: %d want %d (%v)", got, want, err)
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

func TestSharedAuthorEstimateDoesNotReuseSmallContextCap(t *testing.T) {
	snap := loadTestCatalog(t)
	body, _ := json.Marshal(map[string]string{"input": strings.Repeat("hello world ", 1000)})
	raw, _ := DecodeRequestBody(body, nil)
	small := Deployment{ModelID: "gpt-5.6-sol", ContextWindowTokens: 100, snapshot: snap}
	large := Deployment{ModelID: "gpt-5.6-terra", ContextWindowTokens: 10000, snapshot: snap}
	estimate := requestTokenEstimator(raw, RouteResponses, []routingSelection{{deployment: small}, {deployment: large}})
	if got, err := estimate(small); err != nil || got != 100 {
		t.Fatalf("small context: %d %v", got, err)
	}
	want := inputTokenHoldEstimate(t, raw, "openai", RouteResponses, 10000)
	if got, err := estimate(large); err != nil || got != want || got <= 100 {
		t.Fatalf("larger context: %d want %d (%v)", got, want, err)
	}
}
