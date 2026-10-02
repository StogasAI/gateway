package tokenizer

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestPublishedVocabularyReferences(t *testing.T) {
	raw, err := os.ReadFile("testdata/published.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Cases []struct {
			Text   string
			Repeat int
			Counts map[string]int
		}
	}
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for index, fixture := range data.Cases {
		text := strings.Repeat(fixture.Text, fixture.Repeat)
		for family, want := range fixture.Counts {
			codec, err := Get(family)
			if err != nil {
				t.Fatal(err)
			}
			got, err := codec.Count(text)
			buffer := 103
			if family == "glm" {
				buffer = 107
			}
			// Independent source counts check the calibrated text margin. The
			// estimator intentionally treats special-token strings as plain text.
			if err != nil || (got*buffer+99)/100 < want || got < 0 || got > len(text)*2 {
				t.Errorf("case %d %s: %d (%v), reference %d", index, family, got, err, want)
			}
			for _, limit := range []int{1, 31, got, got + 1} {
				if limit <= 0 {
					continue
				}
				bounded, err := codec.CountAtMost(text, limit)
				if err != nil || bounded != min(got, limit) {
					t.Fatalf("case %d %s cap %d: %d != min(%d,cap): %v", index, family, limit, bounded, got, err)
				}
			}
		}
	}
}

func TestPublishedCountersShareImmutableState(t *testing.T) {
	var group sync.WaitGroup
	for family := range publishedCounters {
		group.Go(func() {
			first, err := Get(family)
			if err != nil {
				t.Error(err)
				return
			}
			for range 20 {
				current, _ := Get(family)
				if current != first {
					t.Error("duplicated vocabulary")
				}
				if _, err := current.Count("hello 世界 👩🏽‍💻"); err != nil {
					t.Error(err)
				}
			}
		})
	}
	group.Wait()
}

func FuzzPublishedCounters(f *testing.F) {
	for _, text := range []string{"", " Janus  ክፍል", "\u2066A\u2069 ", "▁▁", "a\u0344", "x'ſ", "\xff", strings.Repeat("\n", 16385)} {
		f.Add(text, uint8(0))
	}
	f.Fuzz(func(t *testing.T, text string, choice uint8) {
		families := []string{"deepseek", "qwen3", "qwen35", "gemma", "minimax", "mistral", "kimi", "glm"}
		c, _ := Get(families[int(choice)%len(families)])
		got, err := c.CountAtMost(text, 1000)
		if !utf8.ValidString(text) {
			if err == nil {
				t.Fatal("invalid UTF-8 accepted")
			}
			return
		}
		if err != nil || got < 0 || got > 1000 {
			t.Fatalf("count %d: %v", got, err)
		}
		if len(text) < 4096 {
			full, err := c.Count(text)
			if err != nil || got != min(full, 1000) {
				t.Fatalf("cap differs: %d/%d %v", got, full, err)
			}
		}
	})
}
