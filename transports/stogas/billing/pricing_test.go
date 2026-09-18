package billing

import (
	"math/big"
	"testing"
)

func TestTokenAndCallCostPrecision(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rate     string
		quantity int
		divisor  int64
		want     string
	}{
		{"jev single token", "42000000000000000", 1, MillionTokens, "42000000000"},
		{"one thousandth dollar per million", "1000000000000000", 1, MillionTokens, "1000000000"},
		{"one thousandth dollar per search", "1000000000000000000", 1, ThousandCalls, "1000000000000000"},
		{"free output", "0", 1000, MillionTokens, "0"},
		{"no usage", maximumUSDAtoms, 0, MillionTokens, "0"},
		{"one atom per token", "1000000", 1, MillionTokens, "1"},
		{"fractional atom rounds up", "100000", 1, MillionTokens, "1"},
		{"quantity combines before rounding", "100000", 10, MillionTokens, "1"},
		{"smallest rate", "1", 999999, MillionTokens, "1"},
		{"above exact boundary", "1", 1000001, MillionTokens, "2"},
		{"large rate low atom", "100000000000000000000000000001", 1, MillionTokens, "100000000000000000000001"},
		{"maximum rate", maximumUSDAtoms, 1000000, MillionTokens, maximumUSDAtoms},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rate := mustBigInt(t, tc.rate)
			got := CeilingMulDiv(tc.quantity, rate, tc.divisor)
			if got.String() != tc.want || rate.String() != tc.rate {
				t.Fatalf("cost=%s rate=%s, want cost=%s and unchanged rate=%s", got, rate, tc.want, tc.rate)
			}
		})
	}
}

func TestMoneyCeilingBoundsAcrossIntegerWidths(t *testing.T) {
	for _, digits := range []int64{0, 9, 15, 18, 24, 29} {
		base := new(big.Int).Exp(big.NewInt(10), big.NewInt(digits), nil)
		for _, offset := range []int64{0, 1, 49, 50, 99, 999, 999999} {
			rate := new(big.Int).Add(base, big.NewInt(offset))
			for _, quantity := range []int{0, 1, 2, 999, 1000, 999999, 1000000, 1000001, 1000000000} {
				for _, divisor := range []int64{ThousandCalls, MillionTokens} {
					cost := CeilingMulDiv(quantity, rate, divisor)
					exactNumerator := new(big.Int).Mul(big.NewInt(int64(quantity)), rate)
					roundedNumerator := new(big.Int).Mul(cost, big.NewInt(divisor))
					excess := new(big.Int).Sub(roundedNumerator, exactNumerator)
					if excess.Sign() < 0 || excess.Cmp(big.NewInt(divisor)) >= 0 {
						t.Fatalf("quantity=%d rate=%s divisor=%d cost=%s has invalid rounding excess %s", quantity, rate, divisor, cost, excess)
					}
				}
			}
		}
	}
}

func TestBYOKFeePreservesLowAtomsAtLargeAmounts(t *testing.T) {
	for _, upstream := range []string{"1000000000000000001", "100000000000000000000000000001", maximumUSDAtoms} {
		amount := mustBigInt(t, upstream)
		for _, byok := range []string{"stogas", "stored-key", "passthrough-key"} {
			got := calculateBilledCostUSDAtoms(&Authorization{UpstreamByok: byok}, amount)
			want := new(big.Int).Set(amount)
			if byok != "stogas" {
				quotient, remainder := new(big.Int).QuoRem(amount, big.NewInt(50), new(big.Int))
				want = quotient
				if remainder.Sign() > 0 {
					want.Add(want, big.NewInt(1))
				}
			}
			if got.Cmp(want) != 0 || amount.String() != upstream {
				t.Fatalf("source=%s upstream=%s fee=%s, want %s with unchanged upstream", byok, amount, got, want)
			}
		}
	}
}
