package tokenizer

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUniversalEstimateGolden(t *testing.T) {
	// Expected values use decimal arithmetic and independently established
	// Unicode normalization lengths. Contracting normalization never removes
	// original bytes; canonical and compatibility expansion have distinct costs.
	for _, tc := range []struct {
		text string
		want int
	}{
		{"", 0}, {"hello world", 12}, {"HELLO WORLD", 17}, {"12345", 10},
		{" \t\r\n\v\f", 10}, {"\x00\x01\x1f\x7f", 9}, {"你好世界", 15},
		{"é", 8}, {"e\u0301", 9}, {"\u0344", 12}, {"\U0001d160", 25},
		{"\ufdfa", 19}, {"ＡＢＣ", 13}, {"👩🏽‍💻", 17},
		{"Hello, world! 你好世界 👩🏽‍💻", 34},
		// Stream-safe normalization inserts a two-byte CGJ before the 31st
		// consecutive nonstarter: 62 original bytes, 64 normalized bytes.
		{strings.Repeat("\u0300", 31), 52},
		{strings.Repeat("\u0300", 1024), 1510},
		{strings.Repeat("a", 1<<20), 499444},
	} {
		got, err := Estimate(tc.text)
		if err != nil || got != tc.want {
			t.Fatalf("%q: got %d (%v), want %d", abbreviate(tc.text), got, err, tc.want)
		}
		for _, limit := range []int{-1, 0, 1, 8, 20, tc.want - 1, tc.want, tc.want + 1} {
			want := tc.want
			if limit > 0 {
				want = min(want, limit)
			}
			if got, err := EstimateAtMost(tc.text, limit); err != nil || got != want {
				t.Fatalf("%q capped at %d: got %d (%v), want %d", abbreviate(tc.text), limit, got, err, want)
			}
		}
	}
}

func TestUniversalEstimateRejectsInvalidUTF8(t *testing.T) {
	for _, text := range []string{"\xff", "\xc0\xaf", "\xed\xa0\x80", strings.Repeat("a", 10000) + "\xf0\x9f"} {
		for _, limit := range []int{0, 1, 100000} {
			if _, err := EstimateAtMost(text, limit); err == nil {
				t.Fatalf("invalid UTF-8 accepted with limit %d", limit)
			}
		}
	}
}

func TestUniversalEstimatePublishedReferenceFloor(t *testing.T) {
	// Frozen independent tokenizer captures are regressions for the empirical
	// 50% floor, not proof of future tokenization or complete provider billing.
	var published struct {
		Cases []struct {
			Text   string         `json:"text"`
			Repeat int            `json:"repeat"`
			Counts map[string]int `json:"counts"`
		} `json:"cases"`
	}
	readEstimateFixture(t, "testdata/published.json", &published)
	for _, row := range published.Cases {
		text := strings.Repeat(row.Text, row.Repeat)
		for reference, tokens := range row.Counts {
			checkReferenceFloor(t, text, reference, tokens)
		}
	}
	var openai []struct {
		Text   string `json:"text"`
		Counts [2]int `json:"counts"`
	}
	readEstimateFixture(t, "testdata/tiktoken-0.12.0.json", &openai)
	for _, row := range openai {
		checkReferenceFloor(t, row.Text, "cl100k_base", row.Counts[0])
		checkReferenceFloor(t, row.Text, "o200k_base", row.Counts[1])
	}
}

func checkReferenceFloor(t *testing.T, text, reference string, tokens int) {
	t.Helper()
	if text == "" {
		return // Empty fields contribute zero; framing belongs to the request.
	}
	got, err := Estimate(text)
	if err != nil || got*2 < tokens {
		t.Fatalf("%s %q: estimate %d (%v) below half of reference %d", reference, abbreviate(text), got, err, tokens)
	}
}

func readEstimateFixture(t *testing.T, name string, value any) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}

func abbreviate(text string) string {
	if len(text) > 100 {
		return text[:100] + "…"
	}
	return text
}

func FuzzEstimateAtMost(f *testing.F) {
	for _, text := range []string{"", "hello world", "\ufdfa\U0001d160", strings.Repeat("\u0300", 64), "bad\xff"} {
		f.Add(text, uint32(20))
	}
	f.Fuzz(func(t *testing.T, text string, cap uint32) {
		limit := int(cap & 0x7fffffff)
		full, err := Estimate(text)
		capped, cappedErr := EstimateAtMost(text, limit)
		if !utf8.ValidString(text) {
			if err == nil || cappedErr == nil {
				t.Fatal("invalid UTF-8 accepted")
			}
			return
		}
		want := full
		if limit > 0 {
			want = min(want, limit)
		}
		if err != nil || cappedErr != nil || capped != want || full < 0 || (text != "" && full == 0) {
			t.Fatalf("full=%d (%v), limit=%d, capped=%d (%v)", full, err, limit, capped, cappedErr)
		}
	})
}

func BenchmarkUniversalEstimate(b *testing.B) {
	for _, tc := range []struct {
		name, text string
		limit      int
	}{
		{"english", strings.Repeat("The project handles retries and resource allocation.\n", 20000), 0},
		{"unicode", strings.Repeat("你好世界 👩🏽‍💻\n", 32768), 0},
		{"combining", strings.Repeat("a\u0344\u0f73 ", 16384), 0},
		{"capped_combining", strings.Repeat("a\u0344\u0f73 ", 16384), 1000},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.text)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := EstimateAtMost(tc.text, tc.limit); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
