package tokenizer

import (
	"strings"
	"testing"
)

func TestClaudeBoundedCount(t *testing.T) {
	c := Claude()
	for _, text := range []string{"", "hello", "Hello world.", "Cmd Cmd Cmd ", "Iİıißẞſ ", "\ufdd0\ufdd1\ufdd2\ufdd3\ufdd4", "\ue000A\uf8ff", "x'll x'LL 'First ('word)", strings.Repeat("👩🏽‍💻", 200), "a" + strings.Repeat("\u0301", 1000), strings.Repeat("x\n", 1000)} {
		full, err := c.Count(text)
		if err != nil {
			t.Fatal(err)
		}
		for _, limit := range []int{1, 2, 3, 31, 32, 33, 100, full, full + 1} {
			if limit <= 0 {
				continue
			}
			got, err := c.CountAtMost(text, limit)
			if err != nil || got != min(full, limit) {
				t.Fatalf("bounded count %q at %d: %d %v, full %d", text[:min(len(text), 30)], limit, got, err, full)
			}
		}
	}
	if _, err := c.Count("\xff"); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestClaudeLiteralMarkersCannotBecomeVocabularyInstructions(t *testing.T) {
	for _, text := range []string{"\ufdd0\ufdd1\ufdd2\ufdd3\ufdd4", strings.Repeat("\ufdd0\ufdd1\ufdd2\ufdd3\ufdd4", 257)} {
		got, err := Claude().Count(text)
		// Official counting endpoints charge one token per byte for these
		// noncharacters; internal word/case markers must never discount them.
		if err != nil || got != len(text) {
			t.Fatalf("literal markers: %d, want %d (%v)", got, len(text), err)
		}
	}
}

func TestClaudeVocabularyWordFastPathPreservesBoundaryCounts(t *testing.T) {
	fast := Claude()
	reference := *fast
	reference.words = nil
	for word := range fast.words {
		for _, text := range []string{word, "first " + word + " next", "x'" + word + "!", word + "\u0301 word"} {
			got, _ := fast.Count(text)
			want, _ := reference.Count(text)
			if got != want {
				t.Fatalf("word optimization changed %q: %d != %d", text, got, want)
			}
		}
	}
}

func BenchmarkClaude(b *testing.B) {
	c := Claude()
	text := strings.Repeat("The engineer reviewed the report on Tuesday. Record 104829 includes clear instructions and useful examples.\n", 1000)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = c.Count(text)
	}
}

func FuzzClaudeBoundedCount(f *testing.F) {
	for _, s := range []string{"Hello world.", "Cmd ", "Iİıißẞſ", "\ufdd0\ue000", "\u0344\u0f73", "a\x00b\n", "👩🏽‍💻", "\xff"} {
		f.Add(s, uint16(32))
	}
	c := Claude()
	f.Fuzz(func(t *testing.T, s string, limit uint16) {
		if len(s) > 16384 {
			return
		}
		a, err := c.Count(s)
		b, bErr := c.CountAtMost(s, int(limit)+1)
		if (err == nil) != (bErr == nil) || err == nil && b != min(a, int(limit)+1) {
			t.Fatalf("inconsistent cap: full=%d bounded=%d limit=%d errors=%v,%v", a, b, limit, err, bErr)
		}
	})
}
