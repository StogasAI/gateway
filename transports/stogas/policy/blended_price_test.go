package policy

import (
	"math/big"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/money"
)

// Only the catalog weighted average is timed. Parsing, routing predicates,
// candidate enumeration, and tokenization are separate operations.
func BenchmarkBlendedPrice(b *testing.B) {
	input, _ := DecimalValue("1.25")
	output, _ := DecimalValue("7.50")
	values := testValues{
		"deployment.pricing.input_tokens.per_mill_tokens":  input,
		"deployment.pricing.output_tokens.per_mill_tokens": output,
	}
	for _, weights := range []struct {
		name          string
		input, output int64
	}{
		{"1_to_3", 1, 3},
		{"maximum", maxPriceWeight, maxPriceWeight - 1},
	} {
		b.Run(weights.name, func(b *testing.B) {
			blend := BlendedPrice{InputWeight: weights.input, OutputWeight: weights.output, Rate: "per_mill_tokens"}
			b.ReportAllocs()
			for b.Loop() {
				value, ok := blend.Value(values)
				if !ok || value.Decimal.Sign() <= 0 {
					b.Fatal("invalid weighted price")
				}
			}
		})
	}
}

func decimalRat(value *Decimal) *big.Rat {
	denominator := new(big.Int).Exp(big.NewInt(10), big.NewInt(money.Scale), nil)
	denominator.Mul(denominator, value.divisor)
	return new(big.Rat).SetFrac(value.coefficient, denominator)
}

func decimalFromRat(value *big.Rat) *Decimal {
	factor := new(big.Int).Exp(big.NewInt(10), big.NewInt(money.Scale), nil)
	return &Decimal{coefficient: factor.Mul(factor, value.Num()), divisor: new(big.Int).Set(value.Denom())}
}

func FuzzBlendedPriceExactArithmetic(f *testing.F) {
	f.Add("0.000000000000000000000000000000000001", "999999999999.999999999999999999999999999999999999", uint64(9007199254740991), uint64(9007199254740990))
	f.Add("1", "0", uint64(1), uint64(2))
	f.Add("2.50", "0.001", uint64(3), uint64(1))
	f.Add("4", "4", uint64(0), uint64(1))
	f.Fuzz(func(t *testing.T, inputText, outputText string, inputWeight, outputWeight uint64) {
		input, inOK := DecimalValue(inputText)
		output, outOK := DecimalValue(outputText)
		if !inOK || !outOK {
			t.Skip()
		}
		iw, ow := int64(inputWeight%uint64(maxPriceWeight+1)), int64(outputWeight%uint64(maxPriceWeight+1))
		gcd := priceWeightGCD(iw, ow)
		if gcd == 0 {
			t.Skip()
		}
		iw, ow = iw/gcd, ow/gcd
		values := testValues{"deployment.pricing.input_tokens.per_mill_tokens": input, "deployment.pricing.output_tokens.per_mill_tokens": output}
		beforeInput, beforeOutput := decimalRat(input.Decimal).RatString(), decimalRat(output.Decimal).RatString()
		got, ok := (BlendedPrice{InputWeight: iw, OutputWeight: ow, Rate: "per_mill_tokens"}).Value(values)
		inputRat, _ := new(big.Rat).SetString(inputText)
		outputRat, _ := new(big.Rat).SetString(outputText)
		want := new(big.Rat).Mul(inputRat, new(big.Rat).SetInt64(iw))
		want.Add(want, new(big.Rat).Mul(outputRat, new(big.Rat).SetInt64(ow)))
		want.Quo(want, new(big.Rat).SetInt64(iw+ow))
		if !ok || got.Decimal == nil || decimalRat(got.Decimal).Cmp(want) != 0 {
			t.Fatalf("exact blend differs: got %v, want %s", got.Decimal, want.RatString())
		}
		for _, reference := range []*big.Rat{inputRat, outputRat, new(big.Rat).SetInt64(0)} {
			if got.Decimal.Cmp(decimalFromRat(reference)) != want.Cmp(reference) {
				t.Fatal("unreduced price comparison differs from rational oracle")
			}
		}
		if decimalRat(input.Decimal).RatString() != beforeInput || decimalRat(output.Decimal).RatString() != beforeOutput {
			t.Fatal("blend changed shared catalog prices")
		}
	})
}

func TestBlendedPriceExactCatalogRates(t *testing.T) {
	decimal := func(raw string) Value {
		t.Helper()
		value, ok := DecimalValue(raw)
		if !ok {
			t.Fatal("invalid fixture price")
		}
		return value
	}
	values := testValues{
		"deployment.pricing.input_tokens.per_mill_tokens":            decimal("1"),
		"deployment.pricing.output_tokens.per_mill_tokens":           decimal("9"),
		"deployment.pricing.input_tokens.per_mill_context_lte_272k":  decimal("2"),
		"deployment.pricing.output_tokens.per_mill_context_lte_272k": decimal("10"),
		"deployment.pricing.input_tokens.per_mill_context_gt_272k":   decimal("4"),
		"deployment.pricing.output_tokens.per_mill_context_gt_272k":  decimal("20"),
	}
	check := func(source string, want bool) {
		t.Helper()
		query, err := CompileRouting(source, nil)
		if err != nil {
			t.Fatal(err)
		}
		matched, err := query.Matches(values)
		if err != nil || matched != want {
			t.Errorf("%s: match=%v err=%v", source, matched, err)
		}
	}
	for _, item := range []struct {
		source string
		want   bool
	}{
		{`blended_price(3, 1, 'per_mill_tokens') == decimal('3')`, true},
		{`blended_price(6, 2, 'per_mill_tokens') in [decimal('2'), decimal('3')]`, true},
		{`blended_price(3, 1, 'per_mill_context_lte_272k') < decimal('5')`, true},
		{`blended_price(3, 1, 'per_mill_context_gt_272k') < decimal('5')`, false},
		{`has(deployment.pricing.input_tokens.per_mill_tokens) && has(deployment.pricing.output_tokens.per_mill_tokens)`, true},
		{`blended_price(9007199254740991, 9007199254740990, 'per_mill_tokens') < decimal('5')`, true},
	} {
		check(item.source, item.want)
	}
	// A repeating third must remain greater than its finite 36-digit truncation.
	values["deployment.pricing.output_tokens.per_mill_tokens"] = decimal("0")
	check(`blended_price(1, 2, 'per_mill_tokens') > decimal('0.`+strings.Repeat("3", 36)+`')`, true)
	if got := decimalRat(values["deployment.pricing.input_tokens.per_mill_tokens"].Decimal).RatString(); got != "1" {
		t.Fatal("evaluation mutated a catalog price")
	}
	delete(values, "deployment.pricing.output_tokens.per_mill_tokens")
	for _, item := range []struct {
		source string
		want   bool
	}{
		{`blended_price(3, 1, 'per_mill_tokens') < decimal('5')`, false},
		{`!(blended_price(3, 1, 'per_mill_tokens') < decimal('5'))`, false},
		{`has(deployment.pricing.output_tokens.per_mill_tokens)`, false},
		{`!has(deployment.pricing.output_tokens.per_mill_tokens)`, true},
		{`blended_price(1, 0, 'per_mill_tokens') == decimal('1')`, true},
		{`has(deployment.pricing.input_tokens.per_mill_tokens)`, true},
		{`blended_price(3, 1, 'per_mill_context_lte_272k') == decimal('4')`, true},
	} {
		query, err := CompileRouting(item.source, nil)
		if err != nil {
			t.Fatal(err)
		}
		matched, err := query.Matches(values)
		if err != nil || matched != item.want {
			t.Errorf("%s: match=%v err=%v", item.source, matched, err)
		}
	}
}

func TestBlendedPriceSortingAndIntersection(t *testing.T) {
	cheap, _ := DecimalValue("1")
	expensive, _ := DecimalValue("9")
	left := testValues{"deployment.pricing.input_tokens.per_mill_tokens": cheap, "deployment.pricing.output_tokens.per_mill_tokens": expensive}
	right := testValues{"deployment.pricing.input_tokens.per_mill_tokens": expensive, "deployment.pricing.output_tokens.per_mill_tokens": cheap}
	parent := requestParent(t, `{"delegation":{"request":true},"rules":{"baseline":{"mode":"default","routing":{"sort":[{"by":"blended_price(3, 1, 'per_mill_tokens')","direction":"asc"}]}}}}`)
	child, err := applyRequestJSON(parent, []byte(`{"routing":{"sort":[{"by":"blended_price(6, 2, 'per_mill_tokens')","direction":"desc"},{"by":"blended_price(1, 3, 'per_mill_tokens')","direction":"desc"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	active, err := child.Activate(left)
	if err != nil {
		t.Fatal(err)
	}
	merged := active.Routing.Query
	order, err := merged.Sort([]Values{left, right})
	if err != nil || len(order) != 2 || order[0] != 1 {
		t.Fatalf("blended ordering=%v err=%v", order, err)
	}
	for _, direction := range []string{"asc", "desc"} {
		query, err := CompileRouting("", []Sort{{By: `blended_price(3, 1, 'per_mill_tokens')`, Direction: direction}})
		if err != nil {
			t.Fatal(err)
		}
		order, err := query.Sort([]Values{testValues{}, left})
		if err != nil || order[0] != 1 {
			t.Fatalf("missing blend did not sort last: %v %v", order, err)
		}
	}
}
