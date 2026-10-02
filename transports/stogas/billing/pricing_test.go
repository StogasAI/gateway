package billing

import (
	"github.com/maximhq/bifrost/transports/stogas/money"
	"math/big"
	"testing"
)

func TestTokenAndCallCostPrecision(t *testing.T) {
	for _, tc := range []struct {
		name, rate string
		quantity   int
		divisor    int64
		want       string
	}{
		{"jev single token", "0.042", 1, MillionTokens, "0.000000042"},
		{"one thousandth dollar per million", "0.001", 1, MillionTokens, "0.000000001"},
		{"one thousandth dollar per search", "1", 1, ThousandCalls, "0.001"},
		{"free output", "0", 1000, MillionTokens, "0"},
		{"no usage", maximumUSD, 0, MillionTokens, "0"},
		{"below old accounting unit", "0.000000000000000000000001", 1, MillionTokens, "0.000000000000000000000000000001"},
		{"smallest USD per token", "0.000000000000000000000000000001", 1, MillionTokens, "0.000000000000000000000000000000000001"},
		{"fractional quantum rounds up", "0.0000000000000000000000000000001", 1, MillionTokens, "0.000000000000000000000000000000000001"},
		{"quantity combines before rounding", "0.0000000000000000000000000000001", 10, MillionTokens, "0.000000000000000000000000000000000001"},
		{"above exact boundary", "0.000000000000000000000000000000000001", 1000001, MillionTokens, "0.000000000000000000000000000000000002"},
		{"maximum rate", maximumUSD, 1000000, MillionTokens, maximumUSD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rate := mustUSDTest(t, tc.rate)
			got := CeilingMulDiv(tc.quantity, rate, tc.divisor)
			if got.String() != tc.want || rate.String() != tc.rate {
				t.Fatalf("cost=%s rate=%s, want %s", got, rate, tc.want)
			}
		})
	}
}

func TestFreeCallMeterRetainsCountWithoutInventingMissingRate(t *testing.T) {
	const meter = "web_search_calls"
	pricing := Pricing{meter: {RatePerThousandCalls: "0"}}
	meters := AppendCallMeterCost(nil, pricing, meter, 3, false)
	if len(meters) != 1 || meters[0].Quantity != "3" || meters[0].RateUSD != "0" || meters[0].AmountUSD != "0" {
		t.Fatalf("free tool count was lost: %#v", meters)
	}
	delete(pricing, meter)
	if meters := AppendCallMeterCost(nil, pricing, meter, 3, false); len(meters) != 0 {
		t.Fatalf("missing tool rate became free: %#v", meters)
	}
}

func TestMoneyCeilingBoundsAcrossDecimalWidths(t *testing.T) {
	quantum, _ := new(big.Rat).SetString("0.000000000000000000000000000000000001")
	for _, raw := range []string{"0", "0.000000000000000000000000000000000001", "0.0000000000000000001", "0.001", "0.042", "1.000000000000000000000000000000000001", "999999999999.999999999999999999999999999999999999"} {
		rate := mustUSDTest(t, raw)
		for _, quantity := range []int{0, 1, 2, 999, 1000, 999999, 1000000, 1000001, 1000000000} {
			for _, divisor := range []int64{ThousandCalls, MillionTokens} {
				got := CeilingMulDiv(quantity, rate, divisor)
				exact, _ := new(big.Rat).SetString(raw)
				exact.Mul(exact, new(big.Rat).SetFrac64(int64(quantity), divisor))
				result, _ := new(big.Rat).SetString(got.String())
				difference := new(big.Rat).Sub(result, exact)
				if difference.Sign() < 0 || difference.Cmp(quantum) >= 0 {
					t.Fatalf("rate=%s quantity=%d divisor=%d got=%s exact=%s", raw, quantity, divisor, got, exact)
				}
			}
		}
	}
}

func TestBYOKFeePreservesSmallestUSDAtLargeAmounts(t *testing.T) {
	for _, raw := range []string{"1.000000000000000000000000000000000001", "999999999999.000000000000000000000000000000000001", maximumUSD} {
		amount := mustUSDTest(t, raw)
		for _, byok := range []string{"stogas", "stored-key", "passthrough-key"} {
			got := calculateBilledCostUSD(&Authorization{UpstreamByok: byok}, amount)
			want := new(money.USD).Set(amount)
			if byok != "stogas" {
				want.MulRatioCeil(amount, big.NewInt(2), 100)
			}
			if got.Cmp(want) != 0 || amount.String() != raw {
				t.Fatalf("source=%s upstream=%s got=%s want=%s", byok, raw, got, want)
			}
		}
	}
}
