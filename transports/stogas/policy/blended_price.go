package policy

import (
	"math/big"

	"github.com/maximhq/bifrost/transports/stogas/money"
)

// BlendedPrice weighs input and output token prices at the rates that a prompt
// of PromptTokens pays. The policy states the prompt size because request token
// estimates are too rough to select a rate.
type BlendedPrice struct {
	InputWeight  int64
	OutputWeight int64
	PromptTokens int64
}

const maxPriceArgument = int64(9007199254740991) // Exact JSON integer shared with JavaScript.

// Decimal is an immutable ratio of fixed-precision USD units. Comparisons do
// not need reduced fractions: ordinary prices share divisor 1, and blends
// retain their exact weighted numerator and divisor without rounding or GCDs.
type Decimal struct {
	coefficient *big.Int
	divisor     *big.Int
}

var decimalUnit = big.NewInt(1)

func (d *Decimal) Sign() int { return d.coefficient.Sign() }

func (d *Decimal) Cmp(other *Decimal) int {
	if d == other {
		return 0
	}
	if d.divisor.Cmp(other.divisor) == 0 {
		return d.coefficient.Cmp(other.coefficient)
	}
	var left, right big.Int
	left.Mul(d.coefficient, other.divisor)
	right.Mul(other.coefficient, d.divisor)
	return left.Cmp(&right)
}

func priceWeightGCD(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func (b *BlendedPrice) valid() bool {
	return b.InputWeight >= 0 && b.OutputWeight >= 0 && b.PromptTokens >= 0 &&
		b.InputWeight <= maxPriceArgument && b.OutputWeight <= maxPriceArgument && b.PromptTokens <= maxPriceArgument &&
		priceWeightGCD(b.InputWeight, b.OutputWeight) == 1
}

func blendedPriceValue(b *BlendedPrice, values Values) (Value, bool) {
	if cached, ok := values.(interface {
		PolicyBlendedPrice(BlendedPrice) (Value, bool)
	}); ok {
		return cached.PolicyBlendedPrice(*b)
	}
	return b.Value(values)
}

// Value computes an exact catalog price. Values may retain this result for the
// lifetime of their immutable catalog view; it never depends on the request.
func (b BlendedPrice) Value(values Values) (Value, bool) {
	if !b.valid() {
		return Value{}, false
	}
	price := func(meter string) (*Decimal, bool) {
		value, ok := values.PolicyTokenPrice(meter, b.PromptTokens)
		return value.Decimal, ok && value.Type == "decimal" && value.Decimal != nil
	}
	if b.InputWeight == 0 || b.OutputWeight == 0 {
		meter := "input_tokens"
		if b.InputWeight == 0 {
			meter = "output_tokens"
		}
		value, ok := price(meter)
		return Value{Type: "decimal", Decimal: value}, ok
	}
	input, inputOK := price("input_tokens")
	output, outputOK := price("output_tokens")
	if !inputOK || !outputOK {
		return Value{}, false
	}
	if input.Cmp(output) == 0 {
		return Value{Type: "decimal", Decimal: input}, true
	}
	// Leave the fraction unreduced. Only exact comparison is needed at runtime.
	// Catalog values remain immutable, including when their divisors differ.
	var left, right, denominator, weight big.Int
	left.Mul(input.coefficient, weight.SetInt64(b.InputWeight))
	right.Mul(output.coefficient, weight.SetInt64(b.OutputWeight))
	if input.divisor.Cmp(output.divisor) == 0 {
		denominator.Set(input.divisor)
	} else {
		left.Mul(&left, output.divisor)
		right.Mul(&right, input.divisor)
		denominator.Mul(input.divisor, output.divisor)
	}
	left.Add(&left, &right)
	denominator.Mul(&denominator, weight.SetInt64(b.InputWeight+b.OutputWeight))
	return Value{Type: "decimal", Decimal: &Decimal{coefficient: &left, divisor: &denominator}}, true
}

// DecimalValue retains catalog/literal USD bounds while allowing exact rational
// arithmetic for blends whose decimal expansion does not terminate.
func DecimalValue(raw string) (Value, bool) {
	amount, err := money.Parse(raw)
	if err != nil {
		return Value{}, false
	}
	return Value{Type: "decimal", Decimal: &Decimal{coefficient: amount.ScaledInt(), divisor: decimalUnit}}, true
}
