package tokenizer

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	reference "github.com/tiktoken-go/tokenizer"
)

// This compares warm text counting with decode/redact/encode on the same
// synthetic input. Neither includes HTTP, policy fetching, billing, or a
// provider call. Token counts are exact o200k counts, not chars/4 estimates.
func BenchmarkRequestWork(b *testing.B) {
	c, _ := Get(O200kBase)
	ref, _ := reference.Get(reference.O200kBase)
	options := benchmarkRedactionOptions()
	pii, err := redaction.CompilePolicy(redaction.Options{Patterns: options.Patterns})
	if err != nil {
		b.Fatal(err)
	}
	full, err := redaction.CompilePolicy(options)
	if err != nil {
		b.Fatal(err)
	}
	for _, kind := range []string{"prose", "unicode"} {
		seed := "The project review explains how distributed services handle retries and resource allocation. Each section describes customer expectations, testing, ordinary source code, and confidential document handling. The reference material is public and available to everyone.\n"
		if kind == "unicode" {
			seed = "これは分散システムの設計に関する公開文書です。服务应该正确处理项目说明和客户请求。 La documentación explica cómo probar el sistema. Пример описывает обработку данных.\n"
		}
		seedTokens, _ := ref.Count(seed)
		for _, target := range []int{1000000, 2000000} {
			_, pieces, err := ref.Encode(strings.Repeat(seed, target/seedTokens+3))
			if err != nil {
				b.Fatal(err)
			}
			text := strings.Join(pieces[:target], "")
			for !utf8.ValidString(text) {
				text = text[:len(text)-1]
			}
			expected, err := ref.Count(text)
			if err != nil {
				b.Fatal(err)
			}
			if got, err := c.Count(text); err != nil || got != expected {
				b.Fatalf("fixture mismatch: %d != %d (%v)", got, expected, err)
			}
			body, _ := json.Marshal(map[string]string{"input": text})
			prefix := fmt.Sprintf("%s/%d", kind, expected)
			for _, impl := range []struct {
				name  string
				count func(string) (int, error)
			}{{"optimized", c.Count}, {"reference", ref.Count}} {
				b.Run(prefix+"/"+impl.name, func(b *testing.B) {
					b.SetBytes(int64(len(text)))
					b.ReportAllocs()
					for b.Loop() {
						n, err := impl.count(text)
						if err != nil || n != expected {
							b.Fatalf("count: %d %v", n, err)
						}
					}
				})
			}
			for _, plan := range []struct {
				name   string
				policy *redaction.Policy
			}{{"pii9", pii}, {"pii9_fuzzy1000_regex", full}} {
				b.Run(prefix+"/"+plan.name, func(b *testing.B) {
					b.SetBytes(int64(len(text)))
					b.ReportAllocs()
					b.ReportMetric(float64(plan.policy.MemoryBytes()), "matcher-bytes")
					for b.Loop() {
						var raw map[string]json.RawMessage
						if err := json.Unmarshal(body, &raw); err != nil {
							b.Fatal(err)
						}
						if err := redaction.NewWithPolicy(plan.policy).RedactRequestFields(raw, redaction.SurfaceResponses, nil); err != nil {
							b.Fatal(err)
						}
						if _, err := json.Marshal(raw); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func benchmarkRedactionOptions() redaction.Options {
	options := redaction.Options{Patterns: []redaction.Pattern{
		redaction.PatternEmailAddress, redaction.PatternPhoneNumber, redaction.PatternSocialSecurityNumber,
		redaction.PatternCreditCardNumber, redaction.PatternIPAddress, redaction.PatternAPIKeysAndSecrets,
		redaction.PatternBankIdentifiers, redaction.PatternNationalIdentifiers, redaction.PatternHealthIdentifiers,
	}, CustomPatterns: []redaction.CustomPattern{{Expression: `EMP-[0-9]{1,12}`}}}
	rng := rand.New(rand.NewPCG(37, 19))
	for range 1000 {
		var word [64]byte
		for i := range word {
			word[i] = byte('a' + rng.IntN(26))
		}
		options.Literals = append(options.Literals, redaction.Literal{Text: string(word[:]), Fuzzy: true, IgnoreCase: true})
	}
	return options
}

func BenchmarkPlanBuild(b *testing.B) {
	options := benchmarkRedactionOptions()
	b.ReportAllocs()
	for b.Loop() {
		p, err := redaction.CompilePolicy(options)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(p.MemoryBytes()), "matcher-bytes")
	}
}
