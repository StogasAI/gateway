package catalog

import (
	"math/big"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

const (
	meterInputTokens       = "input_tokens"
	meterCachedInputTokens = "cached_input_tokens"
	meterOutputTokens      = "output_tokens"

	ratePerMillionTokens         = "per_mill_tokens"
	ratePerMillionContextLTE272K = "per_mill_context_lte_272k"
	ratePerMillionContextGT272K  = "per_mill_context_gt_272k"
	ratePerThousandCalls         = "per_1k_calls"

	longContextThresholdTokens = 272000
	millionTokens              = 1000000
	thousandCalls              = 1000
)

type MeterEstimate struct {
	MeterKey       string
	RateKey        string
	Quantity       string
	AmountUSDAtoms string
	HoldRequired   bool
}

func estimateHold(provider schemas.ModelProvider, deployment Deployment, outputTokenLimit int, inputTokenLimit int, pricingContext requestPricingContext) HoldEstimate {
	meters := []MeterEstimate{}
	if deployment.ContextWindowTokens > 0 && inputTokenLimit > deployment.ContextWindowTokens-outputTokenLimit {
		inputTokenLimit = deployment.ContextWindowTokens - outputTokenLimit
	}
	if inputTokenLimit < 0 {
		inputTokenLimit = 0
	}
	if inputTokenLimit > 0 {
		meters = appendMeterCost(meters, deployment.Pricing, meterInputTokens, inputTokenLimit, true, true)
	}
	meters = appendMeterCost(meters, deployment.Pricing, meterOutputTokens, outputTokenLimit, true, true)
	meters = appendProviderHoldMeterCosts(meters, provider, deployment, outputTokenLimit, inputTokenLimit, pricingContext)
	return HoldEstimate{
		MaxUSDAtoms: sumMeterAmounts(meters),
		ProductKey:  deployment.ID,
		ProviderKey: string(provider),
		Meters:      meters,
	}
}

func SettlementCost(resolution *ResolvedRequest, usage *schemas.BifrostLLMUsage) string {
	if resolution == nil || usage == nil {
		return "0"
	}
	cachedInputTokens := 0
	if usage.PromptTokensDetails != nil {
		cachedInputTokens = usage.PromptTokensDetails.CachedReadTokens
	}
	inputTokens := usage.PromptTokens - cachedInputTokens
	if inputTokens < 0 {
		inputTokens = 0
	}
	totalTokens := usage.TotalTokens
	if totalTokens == 0 {
		totalTokens = usage.PromptTokens + usage.CompletionTokens
	}

	meters := []MeterEstimate{}
	meters = appendMeterCost(meters, resolution.Deployment.Pricing, meterInputTokens, inputTokens, false, totalTokens > longContextThresholdTokens)
	meters = appendMeterCost(meters, resolution.Deployment.Pricing, meterCachedInputTokens, cachedInputTokens, false, totalTokens > longContextThresholdTokens)
	meters = appendMeterCost(meters, resolution.Deployment.Pricing, meterOutputTokens, usage.CompletionTokens, false, totalTokens > longContextThresholdTokens)
	meters = appendProviderSettlementMeterCosts(meters, resolution)
	return sumMeterAmounts(meters)
}

func appendMeterCost(meters []MeterEstimate, pricing Pricing, meterKey string, quantity int, holdRequired bool, useHighestRate bool) []MeterEstimate {
	if quantity <= 0 {
		return meters
	}
	rateKey, rateAtoms, ok := pricingRate(pricing, meterKey, useHighestRate)
	if !ok {
		return meters
	}
	amount := costPerMillion(quantity, rateAtoms)
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

func appendCallMeterCost(meters []MeterEstimate, pricing Pricing, meterKey string, quantity int, holdRequired bool) []MeterEstimate {
	return appendCallMeterCostWithRate(meters, pricing, meterKey, ratePerThousandCalls, quantity, holdRequired)
}

func appendCallMeterCostWithRate(meters []MeterEstimate, pricing Pricing, meterKey string, rateKey string, quantity int, holdRequired bool) []MeterEstimate {
	if quantity <= 0 {
		return meters
	}
	meter, ok := pricing[meterKey]
	if !ok {
		return meters
	}
	rateAtoms, ok := parseRate(meter[rateKey])
	if !ok {
		return meters
	}
	amount := costPerThousand(quantity, rateAtoms)
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

func pricingRate(pricing Pricing, meterKey string, useHighest bool) (string, *big.Int, bool) {
	if len(pricing) == 0 {
		return "", nil, false
	}
	meter, ok := pricing[meterKey]
	if !ok || len(meter) == 0 {
		return "", nil, false
	}
	if useHighest {
		return highestRate(meter)
	}
	if rate, ok := parseRate(meter[ratePerMillionTokens]); ok {
		return ratePerMillionTokens, rate, true
	}
	if rate, ok := parseRate(meter[ratePerMillionContextLTE272K]); ok {
		return ratePerMillionContextLTE272K, rate, true
	}
	return highestRate(meter)
}

func highestRate(rates map[string]string) (string, *big.Int, bool) {
	var selectedKey string
	var selected *big.Int
	for key, raw := range rates {
		rate, ok := parseRate(raw)
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

func parseRate(raw string) (*big.Int, bool) {
	rate, ok := new(big.Int).SetString(strings.TrimSpace(raw), 10)
	return rate, ok && rate.Sign() >= 0
}

func costPerMillion(quantity int, rateAtoms *big.Int) *big.Int {
	return ceilingMulDiv(quantity, rateAtoms, millionTokens)
}

func costPerThousand(quantity int, rateAtoms *big.Int) *big.Int {
	return ceilingMulDiv(quantity, rateAtoms, thousandCalls)
}

func ceilingMulDiv(quantity int, rateAtoms *big.Int, divisorQuantity int64) *big.Int {
	cost := new(big.Int).Mul(big.NewInt(int64(quantity)), rateAtoms)
	divisor := big.NewInt(divisorQuantity)
	quotient, remainder := new(big.Int).QuoRem(cost, divisor, new(big.Int))
	if remainder.Sign() > 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}

func sumMeterAmounts(meters []MeterEstimate) string {
	total := big.NewInt(0)
	for _, meter := range meters {
		amount, ok := new(big.Int).SetString(meter.AmountUSDAtoms, 10)
		if ok {
			total.Add(total, amount)
		}
	}
	return total.String()
}
