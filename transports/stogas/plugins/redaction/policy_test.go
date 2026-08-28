package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestExplicitPatternSelectionAndFixedDefault(t *testing.T) {
	t.Parallel()
	source := []byte("email alice@corp.io phone +44 (20) 7123 4567 SSN 856-45-6789 card 4532015112830366 IP 198.51.100.24 SERVICE_SECRET=AbCdEf0123456789GhIjKlMn")

	defaultOut, changed, err := New().redactBytes(source)
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
	if err != nil || changed || !bytes.Equal(out, source) || redactor.Summary().ItemsRedacted != 0 {
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

func TestPatternGroupsCoverEveryBuiltInEntityOnce(t *testing.T) {
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
	if defaultEntityMask != allBuiltInEntityMask.without(EntityIPAddress) {
		t.Fatalf("default mask=%#x", defaultEntityMask)
	}
	if redactor := NewWithPolicy(nil); redactor == nil || redactor.policy != defaultPolicy {
		t.Fatal("nil policy did not select the secure default")
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

func TestSecretPatternsAreIndependentAndComplete(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern     Pattern
		source      string
		placeholder string
		want        string
	}{
		{pattern: PatternCredentials, source: "Authorization: Bearer AbCdEf0123456789-_", placeholder: "<CREDENTIAL>", want: "Authorization: Bearer <CREDENTIAL>"},
		{pattern: PatternPrivateKeys, source: "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----", placeholder: "<PRIVATE_KEY>", want: "<PRIVATE_KEY>"},
		{pattern: PatternJSONWebTokens, source: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", placeholder: "<JSON_WEB_TOKEN>", want: "<JSON_WEB_TOKEN>"},
		{pattern: PatternDatabaseURLs, source: "postgresql://app:Sup3rSecret!@db.internal:5432/stogas", placeholder: "<DATABASE_URL>", want: "<DATABASE_URL>"},
		{pattern: PatternVendorTokens, source: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", placeholder: "<VENDOR_TOKEN>", want: "<VENDOR_TOKEN>"},
	}
	values := make([]string, 0, len(tests))
	patterns := make([]Pattern, 0, len(tests))
	for _, test := range tests {
		values = append(values, test.source)
		patterns = append(patterns, test.pattern)
		redactor := NewWithPolicy(mustCompilePolicy(t, Options{Patterns: []Pattern{test.pattern}}))
		out, changed, err := redactor.redactBytes([]byte(test.source))
		if err != nil || !changed || string(out) != test.want || redactor.Summary().ItemsRedacted != 1 {
			t.Errorf("pattern %q output=%q changed=%t summary=%#v err=%v", test.pattern, out, changed, redactor.Summary(), err)
		}
	}
	source := []byte(strings.Join(values, " "))
	redactor := NewWithPolicy(mustCompilePolicy(t, Options{Patterns: patterns}))
	out, changed, err := redactor.redactBytes(source)
	if err != nil || !changed || redactor.Summary().ItemsRedacted != uint32(len(tests)) {
		t.Fatalf("combined secret output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
	}
	for _, test := range tests {
		if !bytes.Contains(out, []byte(test.placeholder)) {
			t.Errorf("combined secret output %q lacks %s", out, test.placeholder)
		}
	}
	preserved, changed, err := NewWithPolicy(mustCompilePolicy(t, Options{})).redactBytes(source)
	if err != nil || changed || !bytes.Equal(preserved, source) {
		t.Fatalf("disabled secret pattern output=%q changed=%t err=%v", preserved, changed, err)
	}
}

func TestIdentifierPatternGroupsAreIndependent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern     Pattern
		source      string
		placeholder string
		preserved   string
	}{
		{pattern: PatternBankIdentifiers, source: "IBAN GB82 WEST 1234 5698 7654 32 and ITIN 900-70-0001", placeholder: "<IBAN>", preserved: "900-70-0001"},
		{pattern: PatternNationalIdentifiers, source: "ITIN 900-70-0001 and NHS number 943 476 5919", placeholder: "<US_ITIN>", preserved: "943 476 5919"},
		{pattern: PatternHealthIdentifiers, source: "NHS number 943 476 5919 and IBAN GB82 WEST 1234 5698 7654 32", placeholder: "<UK_NHS_NUMBER>", preserved: "GB82 WEST 1234 5698 7654 32"},
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

func TestInvalidPoliciesFailWithoutEchoingExpressions(t *testing.T) {
	t.Parallel()
	tests := []Options{
		{Patterns: []Pattern{""}},
		{Patterns: []Pattern{"person_name"}},
		{Patterns: []Pattern{"address"}},
		{Patterns: []Pattern{"api_keys_and_secrets"}},
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
	if err := redactor.RedactRequestFields(raw, SurfaceChat); err != nil {
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
		if errors.Is(err, ErrMatchLimit) {
			return
		}
		if err != nil || changed != !bytes.Equal(source, out) || changed != (redactor.Summary().ItemsRedacted > 0) {
			t.Fatalf("configured result output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
		}
		stable, changed, err := NewWithPolicy(policy).redactBytes(out)
		if err != nil || changed || !bytes.Equal(stable, out) {
			t.Fatalf("configured output was not stable: output=%q changed=%t err=%v", stable, changed, err)
		}
	})
}

func FuzzCustomPatternRedaction(f *testing.F) {
	f.Add(`EMP-[0-9]{6}\b`, []byte("EMP-123456"))
	f.Add(`客户-\p{Han}{2}`, []byte("客户-张三"))
	f.Add(`a*`, []byte("aaaa"))
	f.Fuzz(func(t *testing.T, expression string, source []byte) {
		policy, err := CompilePolicy(Options{CustomPatterns: []CustomPattern{{Expression: expression}}})
		if errors.Is(err, ErrInvalidPolicy) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		redactor := NewWithPolicy(policy)
		out, changed, err := redactor.redactBytes(source)
		if errors.Is(err, ErrMatchLimit) {
			return
		}
		if err != nil || changed != !bytes.Equal(source, out) || changed != (redactor.Summary().ItemsRedacted > 0) {
			t.Fatalf("custom result output=%q changed=%t summary=%#v err=%v", out, changed, redactor.Summary(), err)
		}
		stable, changed, err := NewWithPolicy(policy).redactBytes(out)
		if err != nil || changed || !bytes.Equal(stable, out) {
			t.Fatalf("custom output was not stable: output=%q changed=%t err=%v", stable, changed, err)
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
