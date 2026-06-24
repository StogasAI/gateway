package billing

import (
	"math/big"
	"strings"
)

const (
	MeterInputTokens             = "input_tokens"
	MeterCachedInputTokens       = "cached_input_tokens"
	MeterCacheWrite5mInputTokens = "cache_write_5m_input_tokens"
	MeterCacheWrite1hInputTokens = "cache_write_1h_input_tokens"
	MeterOutputTokens            = "output_tokens"

	RatePerMillionTokens         = "per_mill_tokens"
	RatePerMillionContextLTE272K = "per_mill_context_lte_272k"
	RatePerMillionContextGT272K  = "per_mill_context_gt_272k"
	RatePerThousandCalls         = "per_1k_calls"

	LongContextThresholdTokens = 272000
	MillionTokens              = 1000000
	ThousandCalls              = 1000
)

type Pricing map[string]map[string]string

type MeterEstimate struct {
	MeterKey       string
	RateKey        string
	Quantity       string
	AmountUSDAtoms string
	HoldRequired   bool
}

func AppendTokenMeterCost(meters []MeterEstimate, pricing Pricing, meterKey string, quantity int, holdRequired bool, useHighestRate bool) []MeterEstimate {
	if quantity <= 0 {
		return meters
	}
	rateKey, rateAtoms, ok := PricingRate(pricing, meterKey, useHighestRate)
	if !ok {
		return meters
	}
	amount := CostPerMillion(quantity, rateAtoms)
	if amount.Sign() == 0 {
		return meters
	}
	return append(meters, MeterEstimate{
		MeterKey:       meterKey,
		RateKey:        rateKey,
		Quantity:       big.NewInt(int64(quantity)).String(),
		AmountUSDAtoms: amount.String(),
		HoldRequired:   holdRequired,
	})
}

func AppendCallMeterCost(meters []MeterEstimate, pricing Pricing, meterKey string, quantity int, holdRequired bool) []MeterEstimate {
	return AppendCallMeterCostWithRate(meters, pricing, meterKey, RatePerThousandCalls, quantity, holdRequired)
}

func AppendCallMeterCostWithRate(meters []MeterEstimate, pricing Pricing, meterKey string, rateKey string, quantity int, holdRequired bool) []MeterEstimate {
	if quantity <= 0 {
		return meters
	}
	meter, ok := pricing[meterKey]
	if !ok {
		return meters
	}
	rateAtoms, ok := ParseRate(meter[rateKey])
	if !ok {
		return meters
	}
	amount := CostPerThousand(quantity, rateAtoms)
	if amount.Sign() == 0 {
		return meters
	}
	return append(meters, MeterEstimate{
		MeterKey:       meterKey,
		RateKey:        rateKey,
		Quantity:       big.NewInt(int64(quantity)).String(),
		AmountUSDAtoms: amount.String(),
		HoldRequired:   holdRequired,
	})
}

func PricingRate(pricing Pricing, meterKey string, useHighest bool) (string, *big.Int, bool) {
	if len(pricing) == 0 {
		return "", nil, false
	}
	meter, ok := pricing[meterKey]
	if !ok || len(meter) == 0 {
		return "", nil, false
	}
	if useHighest {
		return HighestRate(meter)
	}
	if rate, ok := ParseRate(meter[RatePerMillionTokens]); ok {
		return RatePerMillionTokens, rate, true
	}
	if rate, ok := ParseRate(meter[RatePerMillionContextLTE272K]); ok {
		return RatePerMillionContextLTE272K, rate, true
	}
	return HighestRate(meter)
}

func HighestRate(rates map[string]string) (string, *big.Int, bool) {
	var selectedKey string
	var selected *big.Int
	for key, raw := range rates {
		rate, ok := ParseRate(raw)
		if !ok {
			continue
		}
		if selected == nil || rate.Cmp(selected) > 0 || (rate.Cmp(selected) == 0 && strings.Compare(key, selectedKey) < 0) {
			selectedKey = key
			selected = rate
		}
	}
	if selected == nil {
		return "", nil, false
	}
	return selectedKey, selected, true
}

func ParseRate(raw string) (*big.Int, bool) {
	rate, ok := new(big.Int).SetString(strings.TrimSpace(raw), 10)
	return rate, ok && rate.Sign() >= 0
}

func CostPerMillion(quantity int, rateAtoms *big.Int) *big.Int {
	return CeilingMulDiv(quantity, rateAtoms, MillionTokens)
}

func CostPerThousand(quantity int, rateAtoms *big.Int) *big.Int {
	return CeilingMulDiv(quantity, rateAtoms, ThousandCalls)
}

func CeilingMulDiv(quantity int, rateAtoms *big.Int, divisorQuantity int64) *big.Int {
	cost := new(big.Int).Mul(big.NewInt(int64(quantity)), rateAtoms)
	divisor := big.NewInt(divisorQuantity)
	quotient, remainder := new(big.Int).QuoRem(cost, divisor, new(big.Int))
	if remainder.Sign() > 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}
