package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

func boolPtr(value bool) *bool { return &value }

// Independent optimal-string-alignment oracle; deliberately not used at runtime.
func editDistance(a, b string) int {
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(a)][len(b)]
}

func TestLiteralOneEditExhaustiveOracle(t *testing.T) {
	words := []string{""}
	level := []string{""}
	for range 5 {
		var next []string
		for _, word := range level {
			for _, c := range "abC" {
				next = append(next, word+string(c))
			}
		}
		words = append(words, next...)
		level = next
	}
	for _, a := range words {
		for _, b := range words {
			for _, fold := range []bool{false, true} {
				x, y := a, b
				if fold {
					x, y = folded(x), folded(y)
				}
				if got, want := oneASCIIEdit(a, []byte(b), fold), editDistance(x, y) <= 1; got != want {
					t.Fatalf("%q/%q fold=%v: %v != %v", a, b, fold, got, want)
				}
			}
		}
	}
}

func TestLiteralMatcherEveryEditPositionAndCase(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 17))
	for length := 8; length <= 64; length++ {
		word := make([]byte, length)
		for i := range word {
			word[i] = "aBCd012_"[rng.IntN(8)]
		}
		policy, err := CompilePolicy(Options{Literals: []Literal{{Text: string(word), Fuzzy: true}}})
		if err != nil {
			t.Fatal(err)
		}
		variants := []string{string(word)}
		for i := range word {
			variants = append(variants, string(word[:i])+string(word[i+1:]), string(word[:i])+"x"+string(word[i+1:]), string(word[:i])+"x"+string(word[i:]))
			if i > 0 && i+1 < len(word) {
				variants = append(variants, string(word[:i])+" "+string(word[i+1:]), string(word[:i])+" "+string(word[i:]))
			}
			if i+1 < len(word) {
				swap := bytes.Clone(word)
				swap[i], swap[i+1] = swap[i+1], swap[i]
				variants = append(variants, string(swap))
			}
		}
		variants = append(variants, string(word)+"x")
		for _, variant := range variants {
			out, changed, err := NewWithPolicy(policy).redactBytes([]byte("[" + variant + "]"))
			if err != nil || !changed || string(out) != "[<CUSTOM_PII>]" {
				t.Fatalf("%q -> %q: %s/%v/%v", word, variant, out, changed, err)
			}
		}
	}
}

func TestSharedDictionariesSkipTextWithoutAnyPossibleSeed(t *testing.T) {
	var parts []*Policy
	for i := range 7 {
		parts = append(parts, mustCompilePolicy(t, Options{Literals: []Literal{{
			Text: fmt.Sprintf("%064x", i+1), Fuzzy: true,
		}}}))
	}
	policy, err := CombinePolicies(parts)
	if err != nil {
		t.Fatal(err)
	}
	text := bytes.Repeat([]byte("small words and spaces "), 10_000)
	redactor := NewWithPolicy(policy)
	redactor.scanWork = maxScanWork - 1
	out, changed, err := redactor.redactBytes(text)
	if err != nil || changed || !bytes.Equal(out, text) {
		t.Fatalf("impossible dictionary matches used lookahead work: changed=%t error=%v", changed, err)
	}
	withMatch := append(bytes.Clone(text), []byte(fmt.Sprintf("%064x", 7))...)
	out, changed, err = NewWithPolicy(policy).redactBytes(withMatch)
	if err != nil || !changed || !bytes.HasSuffix(out, []byte("<CUSTOM_PII>")) {
		t.Fatalf("necessary seed was skipped: changed=%t error=%v", changed, err)
	}
}

func TestLiteralMixedOptionsOverlapsAndOriginalText(t *testing.T) {
	rules := []Literal{
		{Text: "ProjectAurora", IgnoreCase: true},
		{Text: "ProjectAurora", Fuzzy: true},
		{Text: "https://private.test/", IgnoreCase: true, WholeWord: boolPtr(false)},
		{Text: "日本語"}, {Text: "abcdef", WholeWord: boolPtr(false)}, {Text: "defgh", WholeWord: boolPtr(false)},
	}
	p, err := CompilePolicy(Options{Literals: rules})
	if err != nil {
		t.Fatal(err)
	}
	for input, expected := range map[string]string{
		"PROJECTAURORA ProjectAruora projectaruora": "<CUSTOM_PII> <CUSTOM_PII> projectaruora",
		"xHTTPS://PRIVATE.TEST/page":                "x<CUSTOM_PII>page",
		"[日本語] 日本語学":                                "[<CUSTOM_PII>] 日本語学",
		"abcdefgh":                                  "<CUSTOM_PII>",
		"éProjectAurora ProjectAurorá":             "éProjectAurora ProjectAurorá",
	} {
		out, _, err := NewWithPolicy(p).redactBytes([]byte(input))
		if err != nil || string(out) != expected {
			t.Fatalf("%q: %s, %v", input, out, err)
		}
	}
	rules[0].Text = "mutated"
	*rules[2].WholeWord = true
	out, _, _ := NewWithPolicy(p).redactBytes([]byte("PROJECTAURORA"))
	if string(out) != "<CUSTOM_PII>" {
		t.Fatal("retained caller-owned rules")
	}
}

func TestLiteralResourceBoundsAndAdversarialSeeds(t *testing.T) {
	for _, rule := range []Literal{{Text: ""}, {Text: strings.Repeat("x", 257)}, {Text: "abcdefgh", Fuzzy: true, WholeWord: boolPtr(false)}, {Text: "短い文字列", Fuzzy: true}, {Text: "abcdefg", Fuzzy: true}, {Text: "abcdefgh\n", Fuzzy: true}, {Text: "\xff"}} {
		if _, err := CompilePolicy(Options{Literals: []Literal{rule}}); err == nil {
			t.Fatalf("accepted invalid rule %#v", rule)
		}
	}
	rules := make([]Literal, 1001)
	for i := range rules {
		rules[i] = Literal{Text: "validword"}
	}
	if _, err := CompilePolicy(Options{Literals: rules}); err == nil {
		t.Fatal("accepted 1001 literals")
	}
	for i := range rules[:1000] {
		rules[i] = Literal{Text: fmt.Sprintf("aaaaaaaa%056d", i), Fuzzy: true}
	}
	p, err := CompilePolicy(Options{Literals: rules[:1000]})
	if err != nil {
		t.Fatal(err)
	}
	if p.MemoryBytes() > 32<<20 {
		t.Fatalf("unexpected retained matcher size: %d", p.MemoryBytes())
	}
	// Defensive runtime parsing must also meter noncanonical duplicate rules.
	attack := make([]Literal, 1000)
	for i := range attack {
		attack[i] = Literal{Text: strings.Repeat("a", 64), Fuzzy: true}
	}
	attackPolicy, err := CompilePolicy(Options{Literals: attack})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewWithPolicy(attackPolicy).redactBytes([]byte(strings.Repeat("a", 1<<20))); !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("unmetered rejected candidates: %v", err)
	}
	for i := range rules[:1000] {
		rules[i].Text += "x"
	}
	if _, err := CompilePolicy(Options{Literals: rules[:1000]}); err == nil {
		t.Fatal("accepted overlong fuzzy rules")
	}
}

func TestASCIIInputChecksDecodedOriginalTextTransactionally(t *testing.T) {
	for _, text := range []string{`"héllo"`, `"\u00e9"`, `"\ud83d\ude00"`} {
		raw := map[string]json.RawMessage{"input": json.RawMessage(text), "model": json.RawMessage(`"模型"`)}
		before := string(raw["input"])
		if err := ValidateASCII(raw, SurfaceResponses); !errors.Is(err, ErrNonASCII) {
			t.Fatalf("accepted %s: %v", text, err)
		}
		if string(raw["input"]) != before {
			t.Fatal("validation mutated input")
		}
	}
	raw := map[string]json.RawMessage{"input": json.RawMessage(`"ASCII \n \u0041"`), "model": json.RawMessage(`"模型"`)}
	if err := ValidateASCII(raw, SurfaceResponses); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		surface     Surface
		field, body string
		allowed     bool
	}{
		{SurfaceChat, "messages", `[{"reasoning":"é","reasoning_details":[],"content":"safe"}]`, true},
		{SurfaceChat, "messages", `[{"reasoning_details":[],"reasoning":"\u00e9","content":"safe"}]`, true},
		{SurfaceChat, "messages", `[{"reasoning":"é","reasoning_details":[],"content":"é"}]`, false},
		{SurfaceChat, "messages", `[{"reasoning":"é","content":"safe"}]`, false},
		{SurfaceResponses, "input", `[{"summary":"é","encrypted_content":"opaque","type":"reasoning"}]`, true},
		{SurfaceResponses, "input", `[{"type":"reasoning","encrypted_content":"opaque","summary":"é"}]`, true},
		{SurfaceResponses, "input", `[{"summary":"é","encrypted_content":"opaque","type":"message"}]`, false},
		{SurfaceResponses, "input", `[{"summary":"é","type":"reasoning"}]`, false},
	} {
		err := ValidateASCII(map[string]json.RawMessage{test.field: json.RawMessage(test.body)}, test.surface)
		if test.allowed != (err == nil) {
			t.Fatalf("protected field order %s: %v", test.body, err)
		}
	}
}

func TestMaximumCombinedPlanSharesOneWorkBudget(t *testing.T) {
	options := Options{Patterns: supportedPatterns[:]}
	for i := range 1000 {
		options.Literals = append(options.Literals, Literal{
			Text: fmt.Sprintf("Project-%056x", i*7919), Fuzzy: true, IgnoreCase: true,
		})
	}
	for _, prefix := range []string{"a", "b", "c"} {
		options.CustomPatterns = append(options.CustomPatterns, CustomPattern{Expression: prefix + `[ab]{1000}z`})
	}
	policy, err := CompilePolicy(options)
	if err != nil {
		t.Fatal(err)
	}
	if policy.MemoryBytes() > 32<<20 {
		t.Fatalf("combined plan exceeds expected retained bound: %d", policy.MemoryBytes())
	}
	// A valid maximum dictionary plus three expensive expressions need not be
	// cheap for every input. Exhaustion must stop all scanners atomically.
	input := json.RawMessage(`"` + strings.Repeat("a", 32768) + `"`)
	raw := map[string]json.RawMessage{"input": bytes.Clone(input)}
	r := NewWithPolicy(policy)
	if err := r.RedactRequestFields(raw, SurfaceResponses, nil); !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("maximum combined plan did not fail closed: %v", err)
	}
	if !bytes.Equal(raw["input"], input) || r.items != 0 || r.scanWork != maxScanWork {
		t.Fatalf("partial replacement or renewed work budget: items=%d work=%d", r.items, r.scanWork)
	}
}

func FuzzLiteralSeedCompleteness(f *testing.F) {
	f.Add("abcdefgh", "abcedfgh")
	f.Add("Project Aurora", "project aurroa")
	f.Fuzz(func(t *testing.T, word, text string) {
		if len(text) > 128 {
			return
		}
		rule := Literal{Text: word, Fuzzy: true, IgnoreCase: true}
		if ValidateLiterals([]Literal{rule}) != nil {
			return
		}
		for _, c := range []byte(text) {
			if !asciiWord(c) && c != ' ' {
				return
			}
		}
		if len(text) == 0 || !asciiWord(text[0]) || !asciiWord(text[len(text)-1]) {
			return
		}
		p, err := CompilePolicy(Options{Literals: []Literal{rule}})
		if err != nil {
			t.Fatal(err)
		}
		if editDistance(folded(word), folded(text)) <= 1 {
			out, _, err := NewWithPolicy(p).redactBytes([]byte("[" + text + "]"))
			if err != nil || string(out) != "[<CUSTOM_PII>]" {
				t.Fatalf("missed %q in %q: %s %v", word, text, out, err)
			}
		}
	})
}

func BenchmarkLiteralMaximum(b *testing.B) {
	rules := make([]Literal, 1000)
	for i := range rules {
		rules[i] = Literal{Text: fmt.Sprintf("Project-%056x", i*7919), Fuzzy: true, IgnoreCase: true}
	}
	p, err := CompilePolicy(Options{Literals: rules})
	if err != nil {
		b.Fatal(err)
	}
	text := []byte(strings.Repeat("Ordinary prose for a large context with no private project identifiers. ", 120000))
	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := NewWithPolicy(p).redactBytes(text); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(p.MemoryBytes()), "matcher-bytes")
}
