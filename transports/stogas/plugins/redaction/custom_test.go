package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestCustomMatcherPreservesRE2Semantics(t *testing.T) {
	patterns := []string{
		`a.*z|a`, `a|ab`, `a.*?b`, `a[^z]{1,8}`, `(?:a|b){1,3}`,
		`\Aa`, `a\z`, `^a`, `a$`, `(?m)^a`, `(?m)a$`, `(?s)a.b`,
		`\ba\b`, `\Ba\B`, `(?:\b|\B)a`, `a(?:\b|\B)`,
		`(?i)élise`, `客户-\p{Han}{2}`, `(?i)k-id`, `a\x{FFFD}`,
		`.[0-9]{2}`, `(?s:.)Z-ID`,
		`\Qabc`, `\Qabc\E`, `\Qabc\\E`, `\\Qabc`, `(?P<id>a+)`,
	}
	inputs := []string{"", "a", "aa", "aba ab", "a\na\nz", " a a ", "baab", "abc", "abc\\", "\\Qabc", "a\xffa", "éaélise ÉLISE", "客户-张三客户-李四", "k-id K-ID K-id", "\na\na\n", "a12 é34 \nZ-ID xZ-ID"}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			policy := mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{{Expression: pattern}}})
			oracle := regexp.MustCompile(pattern)
			oracle.Longest()
			for _, input := range inputs {
				out, _, err := NewWithPolicy(policy).redactBytes([]byte(input))
				want := oracle.ReplaceAllLiteral([]byte(input), []byte("<CUSTOM_PII>"))
				if err != nil || !bytes.Equal(out, want) {
					t.Fatalf("input %q: got %q, %v; want %q", input, out, err, want)
				}
			}
		})
	}
}

func TestCustomBudgetExactBoundary(t *testing.T) {
	policy := mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{{Expression: "abc"}}})
	first := NewWithPolicy(policy)
	if _, _, err := first.redactBytes([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	for _, deficit := range []uint64{0, 1} {
		redactor := NewWithPolicy(policy)
		redactor.scanWork = maxScanWork - first.scanWork + deficit
		out, changed, err := redactor.redactBytes([]byte("abc"))
		if deficit == 0 {
			if err != nil || !changed || string(out) != "<CUSTOM_PII>" {
				t.Fatalf("exact budget: %q, %v", out, err)
			}
		} else if !errors.Is(err, ErrWorkLimit) || changed || out != nil {
			t.Fatalf("insufficient budget: %q, %v", out, err)
		}
	}
}

func TestCustomWorkBudgetStopsAdversarialScans(t *testing.T) {
	for _, pattern := range []string{`a.*z|a`, `[ab]{1000}c`, `a.{0,1000}z|a`, `(?:a{1,500}){1,2}z`} {
		t.Run(pattern, func(t *testing.T) {
			policy := mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{{Expression: pattern}}})
			redactor := NewWithPolicy(policy)
			out, changed, err := redactor.redactBytes(bytes.Repeat([]byte("a"), 32768))
			if !errors.Is(err, ErrWorkLimit) || out != nil || changed || redactor.items != 0 || redactor.scanWork != maxScanWork {
				t.Fatalf("changed=%t error=%v items=%d work=%d", changed, err, redactor.items, redactor.scanWork)
			}
		})
	}
}

func TestCustomBudgetNeverTreatsExhaustionAsRealEOF(t *testing.T) {
	policy := mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{{Expression: `a+$`}}})
	redactor := NewWithPolicy(policy)
	redactor.scanWork = maxScanWork - policy.custom[0].weight*4
	out, changed, err := redactor.redactBytes([]byte("aaaaaaaaaz"))
	if !errors.Is(err, ErrWorkLimit) || out != nil || changed {
		t.Fatalf("got %q, changed=%t, error=%v", out, changed, err)
	}
}

func TestCustomBudgetSharedAcrossFieldsAndPatterns(t *testing.T) {
	policy := mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{{Expression: `EMP-[0-9]+`}, {Expression: `OTHER-[0-9]+`}}})
	redactor := NewWithPolicy(policy)
	redactor.scanWork = maxScanWork - 300
	input := map[string]json.RawMessage{
		"input":        json.RawMessage(`"EMP-123"`),
		"instructions": json.RawMessage(`"` + strings.Repeat("x", 300) + `"`),
	}
	err := redactor.RedactRequestFields(input, SurfaceResponses)
	if !errors.Is(err, ErrWorkLimit) || string(input["input"]) != `"EMP-123"` || redactor.items != 0 {
		t.Fatalf("error=%v input=%s items=%d", err, input["input"], redactor.items)
	}
	// Failure does not reset the work budget and let a caller retry for free.
	if _, _, err := redactor.redactBytes([]byte("EMP-456")); !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("expected persistent work exhaustion, got %v", err)
	}
}

func TestCustomSparseLargeInput(t *testing.T) {
	policy := mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{{Expression: `EMP-[0-9]{6}\b`}}})
	for _, phrase := range []string{"ordinary text ", "普通文本文档 "} {
		input := append(bytes.Repeat([]byte(phrase), 1_000_000), []byte("EMP-123456")...)
		out, changed, err := NewWithPolicy(policy).redactBytes(input)
		if err != nil || !changed || !bytes.HasSuffix(out, []byte("<CUSTOM_PII>")) {
			t.Fatalf("changed=%t error=%v", changed, err)
		}
	}
}

func BenchmarkCustomAdversarial(b *testing.B) {
	for _, expression := range []string{`a.*z|a`, `[ab]{1000}c`} {
		policy, err := CompilePolicy(Options{CustomPatterns: []CustomPattern{{Expression: expression}}})
		if err != nil {
			b.Fatal(err)
		}
		input := bytes.Repeat([]byte("a"), 32768)
		b.Run(expression, func(b *testing.B) {
			for b.Loop() {
				if _, _, err := NewWithPolicy(policy).redactBytes(input); !errors.Is(err, ErrWorkLimit) {
					b.Fatal(err)
				}
			}
		})
	}
}
