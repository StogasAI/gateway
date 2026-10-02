package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

var testDetectorPolicy = func() *Policy {
	patterns := make([]Pattern, 0, len(supportedPatterns))
	for _, pattern := range supportedPatterns {
		if pattern != PatternIPAddress {
			patterns = append(patterns, pattern)
		}
	}
	policy, err := CompilePolicy(Options{Patterns: patterns})
	if err != nil {
		panic(err)
	}
	return policy
}()

func newTestRedactor() *Redactor {
	return NewWithPolicy(testDetectorPolicy)
}

func TestExplicitPatternSelection(t *testing.T) {
	t.Parallel()
	source := []byte("email alice@corp.io phone +44 (20) 7123 4567 SSN 856-45-6789 card 4532015112830366 IP 198.51.100.24 SERVICE_SECRET=AbCdEf0123456789GhIjKlMn")

	defaultOut, changed, err := newTestRedactor().redactBytes(source)
	if err != nil || !changed || !bytes.Contains(defaultOut, []byte("198.51.100.24")) || bytes.Contains(defaultOut, []byte("alice@corp.io")) {
		t.Fatalf("default policy output=%q changed=%t err=%v", defaultOut, changed, err)
	}

	allPolicy := mustCompilePolicy(t, Options{Patterns: supportedPatterns[:]})
	allOut, changed, err := NewWithPolicy(allPolicy).redactBytes(source)
	if err != nil || !changed || bytes.Contains(allOut, []byte("198.51.100.24")) || !bytes.Contains(allOut, []byte("<IP_ADDRESS>")) {
		t.Fatalf("explicit all-pattern policy output=%q changed=%t err=%v", allOut, changed, err)
	}

	selected := mustCompilePolicy(t, Options{Patterns: []Pattern{PatternEmailAddress, PatternIPAddress, PatternEmailAddress}})
	selectedRedactor := NewWithPolicy(selected)
	selectedOut, changed, err := selectedRedactor.redactBytes(source)
	if err != nil || !changed || selectedRedactor.Summary().ItemsRedacted != 2 {
		t.Fatalf("selected policy failed: changed=%t summary=%#v err=%v", changed, selectedRedactor.Summary(), err)
	}
	for _, hidden := range []string{"alice@corp.io", "198.51.100.24"} {
		if bytes.Contains(selectedOut, []byte(hidden)) {
			t.Fatalf("selected value %q remained in %q", hidden, selectedOut)
		}
	}
	for _, preserved := range []string{"+44 (20) 7123 4567", "856-45-6789", "4532015112830366", "AbCdEf0123456789GhIjKlMn"} {
		if !bytes.Contains(selectedOut, []byte(preserved)) {
			t.Fatalf("disabled value %q changed in %q", preserved, selectedOut)
		}
	}
}

func TestEmptyPolicyUsesTheOriginalCleanBytes(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{})
	source := []byte("alice@corp.io 192.168.1.1 SERVICE_SECRET=AbCdEf0123456789GhIjKlMn")
	redactor := NewWithPolicy(policy)
	out, changed, err := redactor.redactBytes(source)
	if err != nil || changed || !bytes.Equal(out, source) || redactor.Summary() != nil {
		t.Fatalf("empty policy output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
	}
	if &out[0] != &source[0] {
		t.Fatal("empty policy copied clean input")
	}
}

func TestCompiledPoliciesDoNotRetainOptionSlices(t *testing.T) {
	t.Parallel()
	options := Options{
		Patterns:       []Pattern{PatternEmailAddress},
		CustomPatterns: []CustomPattern{{Expression: `EMP-[0-9]{6}\b`}},
	}
	policy := mustCompilePolicy(t, options)
	options.Patterns[0] = PatternPhoneNumber
	options.CustomPatterns[0].Expression = `OTHER-[0-9]+`
	out, changed, err := NewWithPolicy(policy).redactBytes([]byte("alice@corp.io EMP-123456 OTHER-9"))
	if err != nil || !changed || string(out) != "<EMAIL_ADDRESS> <CUSTOM_PII> OTHER-9" {
		t.Fatalf("compiled policy followed caller mutation: output=%q changed=%t err=%v", out, changed, err)
	}
}

func TestPatternsCoverEveryBuiltInEntityOnce(t *testing.T) {
	t.Parallel()
	var covered entityMask
	for _, pattern := range supportedPatterns {
		entities, supported := entitiesForPattern(pattern)
		if !supported || entities == 0 {
			t.Fatalf("pattern %q has no entity mapping", pattern)
		}
		if overlap := covered & entities; overlap != 0 {
			t.Fatalf("pattern %q overlaps an earlier pattern: %#x", pattern, overlap)
		}
		covered |= entities
		policy := mustCompilePolicy(t, Options{Patterns: []Pattern{pattern}})
		if policy.entities != entities {
			t.Fatalf("pattern %q compiled as mask %#x, want %#x", pattern, policy.entities, entities)
		}
	}
	if covered != allBuiltInEntityMask {
		t.Fatalf("pattern coverage=%#x, want %#x", covered, allBuiltInEntityMask)
	}
}

func TestAbsentPolicyLeavesTextUnchanged(t *testing.T) {
	t.Parallel()
	source := []byte("alice@corp.io 192.168.1.1 SERVICE_SECRET=AbCdEf0123456789GhIjKlMn")
	for _, redactor := range []*Redactor{NewWithPolicy(nil), {}, nil} {
		out, changed, err := redactor.redactBytes(source)
		if err != nil || changed || !bytes.Equal(out, source) || redactor.Summary() != nil {
			t.Fatalf("absent policy output=%q changed=%t err=%v", out, changed, err)
		}
	}
}

func TestCommonUserSelectionsAreIndependent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern     Pattern
		source      string
		placeholder string
		preserved   string
	}{
		{
			pattern:     PatternEmailAddress,
			source:      "alice@corp.io and +44 (20) 7123 4567",
			placeholder: "<EMAIL_ADDRESS>",
			preserved:   "+44 (20) 7123 4567",
		},
		{
			pattern:     PatternPhoneNumber,
			source:      "alice@corp.io and +44 (20) 7123 4567",
			placeholder: "<PHONE_NUMBER>",
			preserved:   "alice@corp.io",
		},
		{
			pattern:     PatternSocialSecurityNumber,
			source:      "SSN 856-45-6789 and ITIN 911-53-1234",
			placeholder: "<US_SSN>",
			preserved:   "911-53-1234",
		},
		{
			pattern:     PatternCreditCardNumber,
			source:      "card 4532015112830366 and +44 (20) 7123 4567",
			placeholder: "<PAYMENT_CARD>",
			preserved:   "+44 (20) 7123 4567",
		},
		{
			pattern:     PatternIPAddress,
			source:      "10.0.0.1 and alice@corp.io",
			placeholder: "<IP_ADDRESS>",
			preserved:   "alice@corp.io",
		},
	}
	for _, test := range tests {
		redactor := NewWithPolicy(mustCompilePolicy(t, Options{Patterns: []Pattern{test.pattern}}))
		out, changed, err := redactor.redactBytes([]byte(test.source))
		if err != nil || !changed || redactor.Summary().ItemsRedacted != 1 ||
			!bytes.Contains(out, []byte(test.placeholder)) || !bytes.Contains(out, []byte(test.preserved)) {
			t.Errorf("pattern %q output=%q changed=%t summary=%#v err=%v", test.pattern, out, changed, redactor.Summary(), err)
		}
	}
}

func TestGroupedPresetsCoverRelatedIdentifiers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern      Pattern
		source       string
		placeholders []string
		preserved    string
	}{
		{
			pattern:      PatternAPIKeysAndSecrets,
			source:       "Authorization: Bearer AbCdEf0123456789-_\n-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\neyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c postgresql://app:Sup3rSecret!@db.internal:5432/stogas ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 alice@corp.io",
			placeholders: []string{"<CREDENTIAL>", "<PRIVATE_KEY>", "<JSON_WEB_TOKEN>", "<DATABASE_URL>", "<VENDOR_TOKEN>"},
			preserved:    "alice@corp.io",
		},
		{
			pattern:      PatternBankIdentifiers,
			source:       "IBAN GB82 WEST 1234 5698 7654 32 and ABA routing number 021000021 and card 4532015112830366",
			placeholders: []string{"<IBAN>", "<US_ROUTING_NUMBER>"},
			preserved:    "4532015112830366",
		},
		{
			pattern:      PatternNationalIdentifiers,
			source:       "ITIN 900-70-0001 and National Insurance AB 12 34 56 C and SSN 856-45-6789",
			placeholders: []string{"<US_ITIN>", "<UK_NATIONAL_INSURANCE_NUMBER>"},
			preserved:    "856-45-6789",
		},
		{
			pattern:      PatternHealthIdentifiers,
			source:       "NHS number 943 476 5919 and NPI 1234567893 and ITIN 900-70-0001",
			placeholders: []string{"<UK_NHS_NUMBER>", "<US_NPI>"},
			preserved:    "900-70-0001",
		},
	}
	for _, test := range tests {
		t.Run(string(test.pattern), func(t *testing.T) {
			redactor := NewWithPolicy(mustCompilePolicy(t, Options{Patterns: []Pattern{test.pattern}}))
			out, changed, err := redactor.redactBytes([]byte(test.source))
			if err != nil || !changed || redactor.Summary().ItemsRedacted != uint32(len(test.placeholders)) ||
				!bytes.Contains(out, []byte(test.preserved)) {
				t.Fatalf("output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
			}
			for _, placeholder := range test.placeholders {
				if !bytes.Contains(out, []byte(placeholder)) {
					t.Errorf("output %q lacks %s", out, placeholder)
				}
			}
			preserved, changed, err := NewWithPolicy(mustCompilePolicy(t, Options{})).redactBytes([]byte(test.source))
			if err != nil || changed || string(preserved) != test.source {
				t.Fatalf("disabled preset output=%q changed=%t err=%v", preserved, changed, err)
			}
		})
	}
}

func TestInvalidPoliciesFailWithoutEchoingExpressions(t *testing.T) {
	t.Parallel()
	tests := []Options{
		{Patterns: []Pattern{""}},
		{Patterns: []Pattern{"person_name"}},
		{Patterns: []Pattern{"address"}},
		{Patterns: []Pattern{"iban"}},
		{Patterns: []Pattern{"uk_nhs"}},
		{Patterns: []Pattern{"credentials"}},
		{Patterns: []Pattern{"TOPSECRET"}},
		{CustomPatterns: []CustomPattern{{Expression: ""}}},
		{CustomPatterns: []CustomPattern{{Expression: "TOPSECRET("}}},
		{CustomPatterns: []CustomPattern{{Expression: string([]byte{0xff})}}},
		{CustomPatterns: []CustomPattern{{Expression: strings.Repeat("q", maxCustomPatternBytes+1)}}},
		{CustomPatterns: []CustomPattern{{Expression: `a*`}}},
		{CustomPatterns: []CustomPattern{{Expression: `^`}}},
		{CustomPatterns: []CustomPattern{{Expression: `(?:value)?`}}},
		{CustomPatterns: []CustomPattern{{Expression: `.`}}},
		{CustomPatterns: []CustomPattern{{Expression: `<CUSTOM_PII>`}}},
	}
	tooMany := Options{CustomPatterns: make([]CustomPattern, maxCustomPatterns+1)}
	tests = append(tests, tooMany)
	totalTooLarge := Options{}
	for index := 0; index < 9; index++ {
		totalTooLarge.CustomPatterns = append(totalTooLarge.CustomPatterns, CustomPattern{Expression: fmt.Sprintf("Q%d%s", index, strings.Repeat("q", 495))})
	}
	tests = append(tests, totalTooLarge)
	tooComplex := Options{}
	for character := 'g'; character <= 'k'; character++ {
		tooComplex.CustomPatterns = append(tooComplex.CustomPatterns, CustomPattern{Expression: fmt.Sprintf("%c{1000}", character)})
	}
	tests = append(tests, tooComplex)

	for index, options := range tests {
		if _, err := CompilePolicy(options); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("invalid policy %d returned %v", index, err)
		} else if strings.Contains(err.Error(), "TOPSECRET") {
			t.Fatalf("policy error exposed expression: %v", err)
		}
	}
}

func TestCustomPatternsAreCombinedLongestAndIdempotent(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{
		Patterns: []Pattern{PatternEmailAddress},
		CustomPatterns: []CustomPattern{
			{Expression: `ID-[0-9]{3}`},
			{Expression: `ID-[0-9]+`},
			{Expression: `ID-[0-9]+`},
			{Expression: `客户-\p{Han}{2}`},
		},
	})
	source := []byte("alice@corp.io ID-123456 客户-张三")
	redactor := NewWithPolicy(policy)
	out, changed, err := redactor.redactBytes(source)
	if err != nil || !changed || string(out) != "<EMAIL_ADDRESS> <CUSTOM_PII> <CUSTOM_PII>" || redactor.Summary().ItemsRedacted != 3 {
		t.Fatalf("custom output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
	}
	second := NewWithPolicy(policy)
	stable, changed, err := second.redactBytes(out)
	if err != nil || changed || !bytes.Equal(stable, out) || second.Summary().ItemsRedacted != 0 {
		t.Fatalf("custom output was not stable: output=%q changed=%t summary=%#v err=%v", stable, changed, second.Summary(), err)
	}
}

func TestCustomPatternAnchorsFlagsAndBoundariesRemainExact(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{
		{Expression: `^START-[0-9]+$`},
		{Expression: `(?i)\bcase-[a-z]+\b`},
	}})
	for _, test := range []struct {
		source  string
		changed bool
	}{
		{source: "START-123", changed: true},
		{source: "prefix START-123", changed: false},
		{source: "CASE-Secret", changed: true},
		{source: "showcase-secretive", changed: false},
	} {
		redactor := NewWithPolicy(policy)
		out, changed, err := redactor.redactBytes([]byte(test.source))
		if err != nil || changed != test.changed {
			t.Errorf("custom pattern on %q output=%q changed=%t want=%t err=%v", test.source, out, changed, test.changed, err)
		}
		if test.changed && (string(out) != "<CUSTOM_PII>" || redactor.Summary().ItemsRedacted != 1) {
			t.Errorf("custom replacement on %q output=%q summary=%#v", test.source, out, redactor.Summary())
		}
	}
}

func TestCustomPatternsComposeWithBuiltInsAndJSON(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{
		Patterns:       []Pattern{PatternEmailAddress, PatternIPAddress},
		CustomPatterns: []CustomPattern{{Expression: `owner alice@corp\.io and EMP-[0-9]{6}`}},
	})
	raw := map[string]json.RawMessage{
		"messages": json.RawMessage(`[
			{"role":"user","content":"owner alice@corp.io and EMP-123456 at 2001:db8::7"},
			{"role":"assistant","reasoning":"owner alice@corp.io and EMP-123456","reasoning_details":[{"type":"reasoning.text","text":"owner alice@corp.io and EMP-123456","signature":"opaque"}]}
		]`),
	}
	redactor := NewWithPolicy(policy)
	if err := redactor.RedactRequestFields(raw, SurfaceChat, nil); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw["messages"], []byte("EMP-123456 at")) ||
		bytes.Contains(raw["messages"], []byte("2001:db8::7")) ||
		!bytes.Contains(raw["messages"], []byte("<EMAIL_ADDRESS> at <IP_ADDRESS>")) ||
		!bytes.Contains(raw["messages"], []byte(`"reasoning":"owner alice@corp.io and EMP-123456"`)) ||
		redactor.Summary().ItemsRedacted != 2 {
		t.Fatalf("configured JSON output=%s summary=%#v", raw["messages"], redactor.Summary())
	}
}

func TestDisabledDetectorMatchesDoNotConsumeTheLimit(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{Patterns: []Pattern{PatternEmailAddress}})
	source := []byte(strings.Repeat("+44 (20) 7123 4567 ", maxMatchesPerText+1) + "alice@corp.io")
	redactor := NewWithPolicy(policy)
	out, changed, err := redactor.redactBytes(source)
	if err != nil || !changed || redactor.Summary().ItemsRedacted != 1 || bytes.Contains(out, []byte("alice@corp.io")) {
		t.Fatalf("disabled matches affected selected detector: changed=%t summary=%#v err=%v", changed, redactor.Summary(), err)
	}
}

func TestCustomPatternMatchLimitFailsClosed(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{{Expression: `z`}}})
	redactor := NewWithPolicy(policy)
	if _, _, err := redactor.redactBytes(bytes.Repeat([]byte("z"), maxMatchesPerText+1)); !errors.Is(err, ErrMatchLimit) {
		t.Fatalf("custom match limit error=%v", err)
	}
	if redactor.Summary().ItemsRedacted != 0 {
		t.Fatalf("failed custom redaction changed metrics: %#v", redactor.Summary())
	}
}

func TestCustomMatchBudgetAllowsAnUnmatchedLaterRequirement(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{
		{Expression: "z"}, {Expression: "EMP-[0-9]+"},
	}})
	for _, count := range []int{maxMatchesPerText - 1, maxMatchesPerText, maxMatchesPerText + 1} {
		for _, suffix := range []string{"", " EMP-1"} {
			redactor := NewWithPolicy(policy)
			_, _, err := redactor.redactBytes([]byte(strings.Repeat("z", count) + suffix))
			matches := count
			if suffix != "" {
				matches++
			}
			if matches > maxMatchesPerText {
				if !errors.Is(err, ErrMatchLimit) || redactor.Summary().ItemsRedacted != 0 {
					t.Fatalf("over budget: matches=%d err=%v summary=%#v", matches, err, redactor.Summary())
				}
			} else if err != nil || redactor.Summary().ItemsRedacted != uint32(matches) {
				t.Fatalf("within budget: matches=%d err=%v summary=%#v", matches, err, redactor.Summary())
			}
		}
	}
}

func TestCompiledPolicyCanBeSharedConcurrently(t *testing.T) {
	t.Parallel()
	policy := mustCompilePolicy(t, Options{
		Patterns:       []Pattern{PatternEmailAddress, PatternIPAddress},
		CustomPatterns: []CustomPattern{{Expression: `EMP-[0-9]{6}`}},
	})
	const workers = 32
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			redactor := NewWithPolicy(policy)
			out, changed, err := redactor.redactBytes([]byte("alice@corp.io 10.0.0.1 EMP-123456"))
			if err != nil || !changed || string(out) != "<EMAIL_ADDRESS> <IP_ADDRESS> <CUSTOM_PII>" || redactor.Summary().ItemsRedacted != 3 {
				errorsFound <- fmt.Errorf("output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}

func FuzzConfiguredRedaction(f *testing.F) {
	f.Add(uint64(0), []byte("alice@corp.io 192.168.1.1"))
	f.Add(^uint64(0), []byte("alice@corp.io [2001:db8::1] +44 (20) 7123 4567"))
	f.Fuzz(func(t *testing.T, selection uint64, source []byte) {
		var patterns []Pattern
		for index, pattern := range supportedPatterns {
			if selection&(uint64(1)<<uint(index)) != 0 {
				patterns = append(patterns, pattern)
			}
		}
		policy, err := CompilePolicy(Options{Patterns: patterns})
		if err != nil {
			t.Fatal(err)
		}
		redactor := NewWithPolicy(policy)
		out, changed, err := redactor.redactBytes(source)
		if errors.Is(err, ErrMatchLimit) || errors.Is(err, ErrWorkLimit) {
			return
		}
		summary := redactor.Summary()
		if (summary != nil) != (len(patterns) > 0) {
			t.Fatalf("redaction metrics do not match selected rules: %#v", summary)
		}
		if err != nil || changed != !bytes.Equal(source, out) || changed != (summary != nil && summary.ItemsRedacted > 0) {
			t.Fatalf("configured result output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
		}
		if utf8.Valid(source) && !utf8.Valid(out) {
			t.Fatal("replacement split a UTF-8 character")
		}
	})
}

func TestCustomPatternValidationCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/custom-patterns.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Expression string
		Valid            bool
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			_, err := CompilePolicy(Options{CustomPatterns: []CustomPattern{{Expression: test.Expression}}})
			if (err == nil) != test.Valid {
				t.Fatalf("valid=%t err=%v", test.Valid, err)
			}
		})
	}
}

func TestCustomRequirementsCannotWeakenOtherMatches(t *testing.T) {
	t.Parallel()
	for _, patterns := range [][]CustomPattern{
		{{Expression: "12345"}, {Expression: "ABC123"}},
		{{Expression: "ABC123"}, {Expression: "12345"}},
		{{Expression: "12345"}, {Expression: "ABC123"}, {Expression: "12345"}},
	} {
		redactor := NewWithPolicy(mustCompilePolicy(t, Options{CustomPatterns: patterns}))
		out, _, err := redactor.redactBytes([]byte("ABC12345"))
		if err != nil || string(out) != "<CUSTOM_PII>" {
			t.Fatalf("out=%q err=%v", out, err)
		}
	}
	redactor := NewWithPolicy(mustCompilePolicy(t, Options{CustomPatterns: []CustomPattern{{Expression: `EMP-[^\n]+`}}}))
	for _, marker := range []string{"<EMAIL_ADDRESS>", "<CUSTOM_PII>", "<REDACTED>"} {
		out, _, err := redactor.redactBytes([]byte("EMP-123456 " + marker))
		if err != nil || string(out) != "<CUSTOM_PII>" {
			t.Fatalf("marker=%s out=%q err=%v", marker, out, err)
		}
	}
}

func TestStogasTokenDetectionIsBounded(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("Ab3_", 36)
	for _, test := range []struct {
		input           string
		enabled, hidden bool
	}{
		{"sk_stogas_v1_" + body, true, true},
		{"(sk_stogas_v1_" + body + ")", true, true},
		{"sk_stogas_v1_" + body, false, false},
		{"sk_stogas_v1_" + body[:143], true, false},
		{"sk_stogas_v1_" + body + "A", true, false},
		{"sk_stogas_v1_...1234", true, false},
		{"xsk_stogas_v1_" + body, true, false},
	} {
		options := Options{}
		if test.enabled {
			options.Patterns = []Pattern{PatternAPIKeysAndSecrets}
		}
		out, changed, err := NewWithPolicy(mustCompilePolicy(t, options)).redactBytes([]byte(test.input))
		if err != nil || changed != test.hidden || (changed && !bytes.Contains(out, []byte("<VENDOR_TOKEN>"))) {
			t.Fatalf("changed=%t want=%t out=%q err=%v", changed, test.hidden, out, err)
		}
	}
}

func FuzzCustomPatternRedaction(f *testing.F) {
	f.Add(`EMP-[0-9]{6}\b`, []byte("EMP-123456"))
	f.Add(`客户-\p{Han}{2}`, []byte("客户-张三"))
	f.Add(`a*`, []byte("aaaa"))
	f.Add(`EMP-[^\n]+`, []byte("EMP-123456 <EMAIL_ADDRESS>"))
	f.Fuzz(func(t *testing.T, expression string, source []byte) {
		// Keep the unmetered standard-library oracle small. Separate tests use
		// large adversarial and million-token-sized inputs against the budget.
		source = source[:min(len(source), 4096)]
		policy, err := CompilePolicy(Options{CustomPatterns: []CustomPattern{{Expression: expression}}})
		if errors.Is(err, ErrInvalidPolicy) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		redactor := NewWithPolicy(policy)
		out, changed, err := redactor.redactBytes(source)
		if errors.Is(err, ErrMatchLimit) || errors.Is(err, ErrWorkLimit) {
			return
		}
		if err != nil || changed != !bytes.Equal(source, out) || changed != (redactor.Summary().ItemsRedacted > 0) {
			t.Fatalf("custom result output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
		}
		// Arbitrary expressions match the original input, including user-supplied
		// markers. Replacements can create new contexts, so universal idempotence
		// is not a valid property for custom patterns.
		expected := regexp.MustCompile(expression)
		expected.Longest()
		want := expected.ReplaceAllLiteral(source, []byte("<CUSTOM_PII>"))
		if !bytes.Equal(out, want) {
			t.Fatalf("custom output=%q want=%q", out, want)
		}
	})
}

func mustCompilePolicy(t *testing.T, options Options) *Policy {
	t.Helper()
	policy, err := CompilePolicy(options)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestSharedPolicyCompositionScansOriginalTextAndPrunesCoveredLiterals(t *testing.T) {
	word := true
	parentOptions := Options{Patterns: []Pattern{PatternEmailAddress}, CustomPatterns: []CustomPattern{{Expression: "ABCD"}}, Literals: []Literal{{Text: "SECRETABC", IgnoreCase: true, WholeWord: &word}}}
	childOptions := Options{CustomPatterns: []CustomPattern{{Expression: "BCDE"}, {Expression: "ABCD"}}, Literals: []Literal{{Text: "secretabc", IgnoreCase: true, WholeWord: &word}, {Text: "SECRETABC", Fuzzy: true, WholeWord: &word}, {Text: "NEXTSECRET"}}}
	parent := mustCompilePolicy(t, parentOptions)
	child := mustCompilePolicy(t, childOptions)
	combined, err := CombinePolicies([]*Policy{parent, child})
	if err != nil {
		t.Fatal(err)
	}
	if combined.literals[0].matcher != parent.literals[0].matcher || combined.literals[1].matcher != child.literals[0].matcher {
		t.Fatal("composition copied matchers")
	}
	if len(combined.custom) != 2 {
		t.Fatal("duplicate custom expression retained")
	}
	literals := NormalizeLiterals(append(append([]Literal{}, parentOptions.Literals...), childOptions.Literals...))
	flat := mustCompilePolicy(t, Options{Patterns: parentOptions.Patterns, CustomPatterns: append(append([]CustomPattern{}, parentOptions.CustomPatterns...), childOptions.CustomPatterns...), Literals: literals})
	for _, input := range []string{"ABCDE", "secretabc SECRETABC SECERTABC NextSecret NEXTSECRET", "ABCDE secretabc alice@example.com", strings.Repeat("secretabc ", 500)} {
		actual, changed, err := NewWithPolicy(combined).redactBytes([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		expected, wantChanged, err := NewWithPolicy(flat).redactBytes([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(expected) || changed != wantChanged {
			t.Fatalf("input=%q actual=%q expected=%q", input, actual, expected)
		}
	}
	// A request-local combination cannot change either cached parent matcher.
	if parent.literals[0].enabled != nil || len(parent.custom) != 1 {
		t.Fatal("composition mutated a parent")
	}
}

func TestSharedCaseInsensitiveLiteralIdentityRetainsOneCoveringMatcher(t *testing.T) {
	parent := mustCompilePolicy(t, Options{Literals: []Literal{{Text: "PRIVATEWORD", IgnoreCase: true}}})
	child := mustCompilePolicy(t, Options{Patterns: []Pattern{PatternEmailAddress}})
	duplicate := mustCompilePolicy(t, Options{Literals: []Literal{{Text: "privateword", IgnoreCase: true}}})
	for _, parts := range [][]*Policy{{parent, child}, {parent, duplicate, child}} {
		combined, err := CombinePolicies(parts)
		if err != nil {
			t.Fatal(err)
		}
		if len(combined.literals) != 1 || combined.literals[0].matcher != parent.literals[0].matcher {
			t.Fatal("equivalent dictionaries retained another scan or lost their shared matcher")
		}
		out, changed, err := NewWithPolicy(combined).redactBytes([]byte("privateWORD and alice@corp.io"))
		if err != nil || !changed || string(out) != "<CUSTOM_PII> and <EMAIL_ADDRESS>" {
			t.Fatalf("case-insensitive parent was lost: %s changed=%t error=%v", out, changed, err)
		}
	}
}
