package money

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func mustUSD(t *testing.T, value string) *USD {
	t.Helper()
	amount, err := Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return amount
}

func TestDecimalBoundariesAndJSON(t *testing.T) {
	for _, value := range []string{"0", "0.001", "0.042", "9007199254740993.000000000000000001", "0." + strings.Repeat("0", 35) + "1", strings.Repeat("9", 40) + "." + strings.Repeat("9", 36)} {
		for _, sign := range []string{"", "-"} {
			if value == "0" && sign != "" {
				continue
			}
			want := sign + value
			amount := mustUSD(t, want)
			if amount.String() != want {
				t.Fatalf("roundtrip %s: %s", want, amount)
			}
			encoded, err := json.Marshal(amount)
			if err != nil || string(encoded) != `"`+want+`"` {
				t.Fatalf("JSON %s: %s, %v", want, encoded, err)
			}
			var decoded USD
			if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.Cmp(amount) != 0 {
				t.Fatalf("decode %s: %s, %v", encoded, &decoded, err)
			}
		}
	}
	for _, invalid := range []string{"", " ", "1 ", "+1", "01", ".1", "1.", "1e-36", "NaN", "Infinity", "-Infinity", "0x10", "１", "1\n", "1\x00", "1" + strings.Repeat("0", 40), "0." + strings.Repeat("0", 36) + "1", strings.Repeat("9", 10000)} {
		if _, err := Parse(invalid); err == nil {
			t.Errorf("accepted invalid %q", invalid)
		}
	}
	for _, raw := range []string{`0.001`, `1e-36`, `null`, `{}`, `"1.00"`, `"-0"`} {
		var amount USD
		if err := json.Unmarshal([]byte(raw), &amount); err == nil {
			t.Errorf("accepted noncanonical JSON %s", raw)
		}
	}
	for raw, want := range map[string]string{"1.000": "1", "-0.000": "0"} {
		if got := mustUSD(t, raw).String(); got != want {
			t.Errorf("normalize %s: %s", raw, got)
		}
	}
}

func TestExactArithmeticAndAliasing(t *testing.T) {
	large := mustUSD(t, "9007199254740993")
	tiny := mustUSD(t, "0."+strings.Repeat("0", 35)+"1")
	sum := new(USD).Add(large, tiny)
	if new(USD).Sub(sum, large).Cmp(tiny) != 0 || large.String() != "9007199254740993" {
		t.Fatal("lost low digits or mutated input")
	}
	sum.Sub(sum, tiny)
	if sum.Cmp(large) != 0 {
		t.Fatal("receiver aliasing lost value")
	}
	copy := new(USD).Set(large)
	copy.Add(copy, tiny)
	if large.Cmp(copy) >= 0 {
		t.Fatal("Set shared coefficient storage")
	}
	maximum := mustUSD(t, strings.Repeat("9", 40)+"."+strings.Repeat("9", 36))
	if _, err := json.Marshal(new(USD).Add(maximum, tiny)); err == nil {
		t.Fatal("serialized storage overflow")
	}
}

func TestRoundingMatchesIndependentRationalArithmetic(t *testing.T) {
	quantum := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Exp(big.NewInt(10), big.NewInt(36), nil))
	for _, rate := range []string{"0", "0.001", "0.042", "123.456789012345678901234567890123456789", "0." + strings.Repeat("0", 35) + "1", "-0.001"} {
		for _, quantity := range []int64{0, 1, 49, 50, 51, 999999, 1000000, 9223372036854775807} {
			for _, divisor := range []int64{1, 100, 1000, 1000000} {
				x := mustUSD(t, rate)
				got := new(USD).MulRatioCeil(x, big.NewInt(quantity), divisor)
				actual, _ := new(big.Rat).SetString(got.String())
				exact, _ := new(big.Rat).SetString(rate)
				exact.Mul(exact, new(big.Rat).SetFrac(big.NewInt(quantity), big.NewInt(divisor)))
				errorAmount := new(big.Rat).Sub(actual, exact)
				if errorAmount.Sign() < 0 || errorAmount.Cmp(quantum) >= 0 {
					t.Fatalf("ceil(%s * %d / %d) = %s, error %s", rate, quantity, divisor, got, errorAmount)
				}
				x.MulRatioCeil(x, big.NewInt(quantity), divisor)
				if x.Cmp(got) != 0 {
					t.Fatal("multiplication aliases receiver incorrectly")
				}
			}
		}
	}
}
