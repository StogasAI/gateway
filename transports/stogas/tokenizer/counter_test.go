package tokenizer

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/dlclark/regexp2/v2"
	reference "github.com/tiktoken-go/tokenizer"
)

func TestUnicodeClassesMatchStandardCategories(t *testing.T) {
	for r := rune(-1); r <= unicode.MaxRune+1; r++ {
		var want uint8
		switch {
		case unicode.IsLower(r):
			want = classLetter | classLower
		case unicode.IsUpper(r) || unicode.IsTitle(r):
			want = classLetter | classUpper
		case unicode.IsLetter(r):
			want = classLetter | classCommon
		case unicode.IsMark(r):
			want = classCommon
		case unicode.IsNumber(r):
			want = classNumber
		case unicode.IsSpace(r):
			want = classSpace
		}
		if got := runeClass(r); got != want {
			t.Fatalf("U+%04X: class %d, want %d", r, got, want)
		}
	}
}

func TestOfficialTiktokenFixtures(t *testing.T) {
	// encode_ordinary from OpenAI's tiktoken 0.12.0, with both vocabularies.
	data, err := os.ReadFile("testdata/tiktoken-0.12.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Text   string
		Counts [2]int
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for index, encoding := range []string{Cl100kBase, O200kBase} {
		c, _ := Get(encoding)
		for _, fixture := range fixtures {
			got, err := c.Count(fixture.Text)
			if err != nil || got != fixture.Counts[index] {
				t.Fatalf("%s %q: %d (%v) want %d", encoding, fixture.Text, got, err, fixture.Counts[index])
			}
		}
	}
}

func TestCountsAgainstReference(t *testing.T) {
	cases := []string{"", "hello world", "I'm WE'RE we'll I'd they've can't won't", "HTTPServer JSONParserABC xyzABC", "  x", "\t\tword", "\r\n\t\n  x", " \n  ", "\u00a0\u2003x", "a\u2028\u2029b", "汉字 日本語 हिन्दी عربي русский", "café café 👩‍👩‍👧‍👦 🇬🇧", "<|endoftext|><|fim_prefix|>", "123456789001 ٢٣٤५६७", "\x00\x01\x0b\x0c", strings.Repeat("abc", 3000), strings.Repeat("!", 4096), strings.Repeat(" ", 1000) + "x", strings.Repeat("\n", 1000) + "x"}
	rng := rand.New(rand.NewPCG(17, 83))
	cases = append(cases, "word'ſ", "word'ſx", "'ſx", "word'K", "a'ſt")
	alphabet := []rune(" abcABCXYZ01234567'!?/\t\n\r\v\f\u0085\u00a0\u2003\u2028\u2029é汉字क्ष🤗\u0301\x00")
	for range 3000 {
		var s strings.Builder
		for range rng.IntN(500) {
			s.WriteRune(alphabet[rng.IntN(len(alphabet))])
		}
		cases = append(cases, s.String())
	}
	for _, encoding := range []string{Cl100kBase, O200kBase} {
		t.Run(encoding, func(t *testing.T) {
			c, _ := Get(encoding)
			ref := referenceCounter(c)
			for _, input := range cases {
				want, err := ref(input)
				if err != nil {
					t.Fatal(err)
				}
				got, err := c.Count(input)
				if err != nil || got != want {
					short := []rune(input)
					for i := 0; i < len(short); {
						candidate := string(short[:i]) + string(short[i+1:])
						a, e := c.Count(candidate)
						w, _ := ref(candidate)
						if e == nil && a != w {
							short = []rune(candidate)
							i = 0
						} else {
							i++
						}
					}
					t.Fatalf("input %q: got %d (%v), want %d; reduced %q", input, got, err, want, string(short))
				}
			}
		})
	}
}

// The dependency's generated regexp engine has a newline-backtracking bug
// ("\n\t\n" is one token in both official vocabularies). Use the original
// pattern with the independent interpreter, bypassing generated registration.
func referenceCounter(c *Counter) func(string) (int, error) {
	pattern := `(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+`
	if c.name == O200kBase {
		pattern = `[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n/]*|\s*[\r\n]+|\s+(?!\S)|\s+`
	}
	re := regexp2.MustCompile("(?:"+pattern+")", regexp2.None)
	return func(s string) (int, error) {
		n := 0
		m, err := re.FindStringMatch(s)
		for m != nil && err == nil {
			piece := m.String()
			if _, ok := c.ranks[piece]; ok {
				n++
			} else {
				n += referenceMergeCount(c, piece)
			}
			m, err = re.FindNextMatch(m)
		}
		return n, err
	}
}

func TestHeapAgainstList(t *testing.T) {
	// Treat every input as one pretoken to exercise merge order independently
	// of the splitter, including equal-rank pairs and arbitrary byte sequences.
	rng := rand.New(rand.NewPCG(91, 46))
	for _, encoding := range []string{Cl100kBase, O200kBase} {
		c, _ := Get(encoding)
		var scratch mergeHeap
		for i := 0; i < 1000; i++ {
			input := make([]byte, 65+rng.IntN(500))
			for j := range input {
				if i%2 == 0 {
					input[j] = byte(rng.IntN(256))
				} else {
					input[j] = "abcde 0123!?"[rng.IntN(11)]
				}
			}
			want := referenceMergeCount(c, string(input))
			if got := c.mergeCount(string(input), &scratch); got != want {
				t.Fatalf("%s %x: got %d want %d", encoding, input, got, want)
			}
		}
	}
}

func TestUnicodeCategoryBoundaries(t *testing.T) {
	// Exercise every pair/triple of the categories used by the ordered word,
	// symbol and whitespace alternatives. Include case-folding contractions,
	// shared Lm/Lo/M categories, title case and non-ASCII numeric categories.
	alphabet := []rune("aAǅʰ界\u0301\u0903\u20dd0²Ⅳ①\t\n\r \u0085\u00a0\u2028'ſ!?/👩\u200d")
	for _, encoding := range []string{Cl100kBase, O200kBase} {
		c, _ := Get(encoding)
		ref := referenceCounter(c)
		check := func(s string) {
			t.Helper()
			got, err := c.Count(s)
			want, refErr := ref(s)
			if err != nil || refErr != nil || got != want {
				t.Fatalf("%s %q: got %d (%v), want %d (%v)", encoding, s, got, err, want, refErr)
			}
		}
		for _, a := range alphabet {
			for _, b := range alphabet {
				for _, d := range alphabet {
					check(string([]rune{a, b, d}))
				}
			}
		}
		rng := rand.New(rand.NewPCG(815, 3301))
		for range 3000 {
			runes := make([]rune, 1+rng.IntN(80))
			for i := range runes {
				if rng.IntN(4) != 0 {
					runes[i] = alphabet[rng.IntN(len(alphabet))]
				} else {
					runes[i] = rune(rng.IntN(0x110000))
					if !utf8.ValidRune(runes[i]) {
						runes[i] = '\ufffd'
					}
				}
			}
			check(string(runes))
		}
	}
}

func referenceMergeCount(c *Counter, input string) int {
	parts := make([]string, len(input))
	for i := range parts {
		parts[i] = input[i : i+1]
	}
	for {
		index, rank := -1, uint32(0xffffffff)
		for i := 0; i+1 < len(parts); i++ {
			if candidate := c.rank(parts[i] + parts[i+1]); candidate < rank {
				index, rank = i, candidate
			}
		}
		if index < 0 {
			return len(parts)
		}
		parts[index] += parts[index+1]
		parts = append(parts[:index+1], parts[index+2:]...)
	}
}

func TestResourceBoundAndSharedCounter(t *testing.T) {
	c, _ := Get(O200kBase)
	input := strings.Repeat("a", maxMergePieceBytes+1)
	if got, err := c.Count(input); err != nil || got != maxMergePieceBytes/8+1 {
		t.Fatalf("oversized pretoken: %d %v", got, err)
	}
	prose := strings.Repeat("Ordinary words are fully counted. ", 10000)
	ref, _ := reference.Get(reference.O200kBase)
	want, _ := ref.Count(prose)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			got, err := c.Count(prose)
			if err != nil || got != want {
				t.Errorf("concurrent count: %d %v want %d", got, err, want)
			}
		})
	}
	wg.Wait()
	if _, err := c.Count("\xff"); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	if _, err := Get("invented"); err == nil {
		t.Fatal("unknown encoding accepted")
	}
}

func TestRequestLocalMemoCollisions(t *testing.T) {
	// Same length and first/last bytes deliberately collide in the tiny memo.
	// Different middle bytes must never reuse another piece's count.
	rng := rand.New(rand.NewPCG(83, 92))
	var pieces []string
	for range 512 {
		middle := make([]byte, 16)
		for j := range middle {
			middle[j] = "abcxyzqjk"[rng.IntN(9)]
		}
		pieces = append(pieces, "abcdefghijkl"+string(middle)+"mnopqrstuvwx")
	}
	text := strings.Join(pieces, " ")
	for _, encoding := range []string{Cl100kBase, O200kBase} {
		c, _ := Get(encoding)
		want, err := referenceCounter(c)(text)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if got, err := c.Count(text); err != nil || got != want {
				t.Fatalf("%s: %d %v want %d", encoding, got, err, want)
			}
		}
	}
}

func TestCountAtMostPreservesCappedResult(t *testing.T) {
	for _, encoding := range []string{Cl100kBase, O200kBase} {
		c, _ := Get(encoding)
		for _, text := range []string{"", "word'ſ", strings.Repeat("word 界! ", 1000), strings.Repeat("a", maxMergePieceBytes+1)} {
			full, err := c.Count(text)
			if err != nil {
				t.Fatal(err)
			}
			for _, limit := range []int{-1, 0, 1, 2, 100, full, full + 1} {
				want := full
				if limit > 0 {
					want = min(full, limit)
				}
				if got, err := c.CountAtMost(text, limit); err != nil || got != want {
					t.Fatalf("%s limit %d: %d %v want %d", encoding, limit, got, err, want)
				}
			}
		}
	}
}

func FuzzCount(f *testing.F) {
	for _, s := range []string{"hello", "\r\n\tword", "👩🏽‍💻", strings.Repeat("abc", 80)} {
		f.Add(s)
	}
	c, _ := Get(O200kBase)
	ref := referenceCounter(c)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1024 || !utf8.ValidString(s) {
			t.Skip()
		}
		got, err := c.Count(s)
		if err != nil {
			t.Fatal(err)
		}
		want, err := ref(s)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%q: %d != %d", s, got, want)
		}
	})
}

func BenchmarkCount(b *testing.B) {
	for _, encoding := range []string{Cl100kBase, O200kBase} {
		c, _ := Get(encoding)
		ref, _ := reference.Get(reference.Encoding(encoding))
		for name, input := range map[string]string{
			"prose":   strings.Repeat("The project needs a clear explanation of how the system works. ", 10000),
			"unicode": strings.Repeat("汉字 日本語 हिन्दी عربي русский 👩🏽‍💻 café. ", 10000),
			"merge8k": strings.Repeat("abcdef", 1365),
			"long":    strings.Repeat("a", 2<<20),
		} {
			for impl, fn := range map[string]func(string) (int, error){"new": c.Count, "reference": ref.Count} {
				if name == "long" && impl == "reference" {
					continue
				}
				b.Run(encoding+"/"+name+"/"+impl, func(b *testing.B) {
					b.SetBytes(int64(len(input)))
					b.ReportAllocs()
					for b.Loop() {
						if _, err := fn(input); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		}
	}
}
