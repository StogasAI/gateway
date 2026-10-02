package policy

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCELConditionsUseTypedCatalogFactsAndExactPrices(t *testing.T) {
	input, _ := DecimalValue("1.000000000000000000000000000000000001")
	output, _ := DecimalValue("2")
	values := testValues{
		"model.id": {Type: "string", String: "model-a"},
		"deployment.pricing.input_tokens.per_mill_tokens":  input,
		"deployment.pricing.output_tokens.per_mill_tokens": output,
		"deployment.inputModalities":                       {Type: "string_list", Strings: []string{"text", "image"}},
	}
	for _, source := range []string{
		`model.id == "model-a" && "image" in deployment.inputModalities`,
		`deployment.inputModalities.exists(m, m == "text")`,
		`deployment.pricing.input_tokens.per_mill_tokens > decimal("1")`,
		`blended_price(1, 1, "per_mill_tokens") > decimal("1.5")`,
		`request.time.getHours("UTC") == 12`,
		`!has(deployment.deprecationDate)`,
	} {
		t.Run(source, func(t *testing.T) {
			program, err := CompileCEL(source)
			if err != nil {
				t.Fatal(err)
			}
			known, matched, cost, err := program.Evaluate(values, time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
			if err != nil || !known || !matched || cost == 0 {
				t.Fatalf("known=%v matched=%v cost=%d err=%v", known, matched, cost, err)
			}
		})
	}
}

func TestCELMissingFactsNeverWeakenConditions(t *testing.T) {
	for _, source := range []string{`deployment.deprecationDate == "x"`, `!(deployment.deprecationDate == "x")`} {
		program, err := CompileCEL(source)
		if err != nil {
			t.Fatal(err)
		}
		known, matched, _, err := program.Evaluate(testValues{}, time.Time{})
		if err != nil || known || matched {
			t.Fatalf("%s: known=%v matched=%v err=%v", source, known, matched, err)
		}
	}
}

func TestCELRejectsUnknownFieldsWrongTypesAndInvalidPriceConstants(t *testing.T) {
	for _, source := range []string{
		`model.misspelled == "x"`, `model.id < 4`, `42`,
		`blended_price(0, 0, "per_mill_tokens") < decimal("1")`,
		`blended_price(-1, 1, "per_mill_tokens") < decimal("1")`,
		`blended_price(1, 1, "unknown") < decimal("1")`,
		`decimal("NaN") > decimal("0")`, `decimal(model.id) > decimal("0")`,
		`decimal("1") < 1.0`, `decimal("1") * decimal("2") > decimal("1")`,
		strings.Repeat(" ", MaxCELBytes+1),
	} {
		if _, err := CompileCEL(source); err == nil {
			t.Errorf("accepted %s", source)
		}
	}
	for _, source := range []string{
		`request.estimatedInputTokens > 10`,
		`has(request.maximumOutputTokens)`,
		`estimated_cost("per_mill_tokens") < decimal("1")`,
		`[request].all(r, r.estimatedInputTokens > 10)`,
		`dyn(request).estimatedInputTokens > 10`,
		`deployment.estimated_cost("per_mill_tokens", 10, 10) < decimal("1")`,
	} {
		if _, err := CompileCEL(source); err == nil {
			t.Errorf("accepted late facts before plugins: %s", source)
		}
	}
}

func BenchmarkCELConditions(b *testing.B) {
	for _, size := range []int{1, 64, 256} {
		source := strings.Repeat(`model.id == "model-a" && `, size-1) + `blended_price(3, 1, "per_mill_tokens") < decimal("2")`
		b.Run(fmt.Sprintf("compile/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := CompileCEL(source); err != nil {
					b.Fatal(err)
				}
			}
		})
		program, err := CompileCEL(source)
		if err != nil {
			b.Fatal(err)
		}
		price, _ := DecimalValue("1")
		values := testValues{"model.id": {Type: "string", String: "model-a"},
			"deployment.pricing.input_tokens.per_mill_tokens":  price,
			"deployment.pricing.output_tokens.per_mill_tokens": price}
		b.Run(fmt.Sprintf("evaluate/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				known, matches, _, err := program.Evaluate(values, time.Time{})
				if err != nil || !known || !matches {
					b.Fatalf("%v %v %v", known, matches, err)
				}
			}
		})
	}
}

func TestCELProgramsAreConcurrentAndCostBounded(t *testing.T) {
	program, err := CompileCEL(`deployment.inputModalities.all(a, deployment.inputModalities.all(b, a == b))`)
	if err != nil {
		t.Fatal(err)
	}
	values := testValues{"deployment.inputModalities": {Type: "string_list", Strings: make([]string, 500)}}
	_, _, cost, err := program.Evaluate(values, time.Time{})
	if err == nil || cost <= MaxCELCost {
		t.Fatalf("unbounded evaluation: cost=%d err=%v", cost, err)
	}
	program, err = CompileCEL(`model.id == "expected"`)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for i := range 32 {
		wait.Go(func() {
			text := "expected"
			if i%2 != 0 {
				text = "different"
			}
			for range 20 {
				known, matched, _, err := program.Evaluate(testValues{"model.id": {Type: "string", String: text}}, time.Time{})
				if err != nil || !known || matched != (i%2 == 0) {
					t.Errorf("concurrent evaluation leaked values: %v %v %v", known, matched, err)
				}
			}
		})
	}
	wait.Wait()
}
