// Package money implements exact USD with the common numeric(76,36) storage range.
package money

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

const Scale = 36
const Precision = 76

var factor = new(big.Int).Exp(big.NewInt(10), big.NewInt(Scale), nil)

// USD keeps its integer coefficient private. Its zero value is zero dollars.
// Arithmetic follows big.Int's receiver convention and never uses floating point.
type USD struct{ coefficient big.Int }

func Parse(value string) (*USD, error) {
	if len(value) == 0 || len(value) > 78 {
		return nil, fmt.Errorf("invalid USD length")
	}
	raw := value
	negative := strings.HasPrefix(raw, "-")
	if negative {
		raw = raw[1:]
	}
	parts := strings.Split(raw, ".")
	if len(parts) > 2 || len(parts[0]) == 0 || len(parts[0]) > 40 || (len(parts[0]) > 1 && parts[0][0] == '0') {
		return nil, fmt.Errorf("invalid USD whole digits")
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
		if len(fraction) == 0 || len(fraction) > Scale {
			return nil, fmt.Errorf("invalid USD fractional digits")
		}
	}
	for _, char := range parts[0] + fraction {
		if char < '0' || char > '9' {
			return nil, fmt.Errorf("invalid USD decimal")
		}
	}
	coefficient, ok := new(big.Int).SetString(parts[0]+fraction+strings.Repeat("0", Scale-len(fraction)), 10)
	if !ok {
		return nil, fmt.Errorf("invalid USD decimal")
	}
	if negative {
		coefficient.Neg(coefficient)
	}
	return &USD{coefficient: *coefficient}, nil
}

func (z *USD) String() string {
	if z == nil {
		return "0"
	}
	magnitude := new(big.Int).Abs(&z.coefficient)
	whole, remainder := new(big.Int).QuoRem(magnitude, factor, new(big.Int))
	fraction := strings.TrimRight(strings.Repeat("0", Scale-len(remainder.String()))+remainder.String(), "0")
	result := whole.String()
	if fraction != "" {
		result += "." + fraction
	}
	if z.Sign() < 0 {
		result = "-" + result
	}
	return result
}
func (z *USD) Sign() int { return z.coefficient.Sign() }

// ScaledInt returns a copy of the value in units of 10^-Scale dollars.
// Exact ratios can use it without formatting or exposing mutable USD storage.
func (z *USD) ScaledInt() *big.Int { return new(big.Int).Set(&z.coefficient) }

func (z *USD) Cmp(y *USD) int     { return z.coefficient.Cmp(&y.coefficient) }
func (z *USD) Set(x *USD) *USD    { z.coefficient.Set(&x.coefficient); return z }
func (z *USD) Add(x, y *USD) *USD { z.coefficient.Add(&x.coefficient, &y.coefficient); return z }
func (z *USD) Sub(x, y *USD) *USD { z.coefficient.Sub(&x.coefficient, &y.coefficient); return z }

// JSON is an exact decimal string. Intermediate arithmetic may exceed storage
// bounds, but those values cannot cross a monetary boundary.
func (z USD) MarshalJSON() ([]byte, error) {
	value := z.String()
	if _, err := Parse(value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func (z *USD) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	parsed, err := Parse(value)
	if err != nil {
		return err
	}
	if parsed.String() != value {
		return fmt.Errorf("USD must be canonical")
	}
	z.Set(parsed)
	return nil
}

// MulRatioCeil combines all usage before rounding once to 36 USD fractional digits.
func (z *USD) MulRatioCeil(x *USD, quantity *big.Int, divisor int64) *USD {
	numerator := new(big.Int).Mul(&x.coefficient, quantity)
	q, r := new(big.Int).QuoRem(numerator, big.NewInt(divisor), new(big.Int))
	if r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	z.coefficient.Set(q)
	return z
}
