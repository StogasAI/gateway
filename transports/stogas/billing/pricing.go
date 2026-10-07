package billing

import (
	"github.com/maximhq/bifrost/transports/stogas/money"
	"math/big"
	"strings"
)

const (
	MeterInputTextBytes        = "input_text_bytes"
	MeterInputFileCount        = "input_file_count"
	MeterInputFileURLCount     = "input_file_url_count"
	MeterInputInlineFileBytes  = "input_inline_file_bytes"
	MeterOutputTextBytes       = "output_text_bytes"
	MeterReasoningTextBytes    = "reasoning_text_bytes"
	MeterEstimatedInputTokens  = "estimated_input_tokens"
	MeterTotalInputTokens      = "total_input_tokens"
	MeterTotalOutputTokens     = "total_output_tokens"
	MeterTotalTokens           = "total_tokens"
	MeterTotalCacheWriteTokens = "total_cache_write_tokens"
	MeterHostedToolCalls       = "hosted_tool_calls"
	MeterClientToolCalls       = "client_tool_calls"

	MeterInputTokens             = "input_tokens"
	MeterCachedInputTokens       = "cached_input_tokens"
	MeterCacheWriteInputTokens   = "cache_write_input_tokens"
	MeterCacheWrite5mInputTokens = "cache_write_5m_input_tokens"
	MeterCacheWrite1hInputTokens = "cache_write_1h_input_tokens"
	MeterOutputTokens            = "output_tokens"
	MeterReasoningTokens         = "reasoning_tokens"

	RatePerMillionTokens         = "per_mill_tokens"
	RatePerMillionContextLTE272K = "per_mill_context_lte_272k"
	RatePerMillionContextGT272K  = "per_mill_context_gt_272k"
	RatePerThousandCalls         = "per_1k_calls"

	LongContextThresholdTokens = 272000
	MillionTokens              = 1000000
	ThousandCalls              = 1000
)

type Pricing map[string]map[string]string

// WithReasoningTokenFallback makes reasoning a canonical meter without forcing
// every provider deployment to duplicate its output rates. An explicitly
// cataloged reasoning rate always wins.
func WithReasoningTokenFallback(pricing Pricing) Pricing {
	if len(pricing) == 0 || len(pricing[MeterReasoningTokens]) > 0 || len(pricing[MeterOutputTokens]) == 0 {
		return pricing
	}
	withFallback := make(Pricing, len(pricing)+1)
	for meterKey, rates := range pricing {
		withFallback[meterKey] = rates
	}
	withFallback[MeterReasoningTokens] = pricing[MeterOutputTokens]
	return withFallback
}

type MeterEstimate struct {
	MeterKey     string
	RateKey      string
	RateUSD      string
	Quantity     string
	AmountUSD    string
	HoldRequired bool
}

type TokenRateMode int

const (
	TokenRateStandard TokenRateMode = iota
	TokenRateLongContext
	TokenRateHighest
)

func AppendTokenMeterCost(meters []MeterEstimate, pricing Pricing, meterKey string, quantity int, holdRequired bool, mode TokenRateMode) []MeterEstimate {
	if quantity <= 0 {
		return meters
	}
	rateKey, rateUsd, ok := PricingRate(pricing, meterKey, mode)
	if !ok {
		return meters
	}
	amount := CostPerMillion(quantity, rateUsd)
	return appendMeterCost(meters, meterKey, rateKey, rateUsd, quantity, amount, holdRequired)
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
	rateUsd, ok := ParseRate(meter[rateKey])
	if !ok {
		return meters
	}
	amount := CostPerThousand(quantity, rateUsd)
	return appendMeterCost(meters, meterKey, rateKey, rateUsd, quantity, amount, holdRequired)
}

func appendMeterCost(meters []MeterEstimate, meterKey string, rateKey string, rateUsd *money.USD, quantity int, amount *money.USD, holdRequired bool) []MeterEstimate {
	return append(meters, MeterEstimate{
		MeterKey:     meterKey,
		RateKey:      rateKey,
		RateUSD:      rateUsd.String(),
		Quantity:     big.NewInt(int64(quantity)).String(),
		AmountUSD:    amount.String(),
		HoldRequired: holdRequired,
	})
}

func PricingRate(pricing Pricing, meterKey string, mode TokenRateMode) (string, *money.USD, bool) {
	if len(pricing) == 0 {
		return "", nil, false
	}
	meter, ok := pricing[meterKey]
	if !ok || len(meter) == 0 {
		return "", nil, false
	}
	if mode == TokenRateHighest {
		return HighestRate(meter)
	}
	if mode == TokenRateLongContext {
		if rate, ok := ParseRate(meter[RatePerMillionContextGT272K]); ok {
			return RatePerMillionContextGT272K, rate, true
		}
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

func HighestRate(rates map[string]string) (string, *money.USD, bool) {
	var selectedKey string
	var selected *money.USD
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

func ParseRate(raw string) (*money.USD, bool) {
	rate, err := ParseUSD(raw)
	return rate, err == nil
}

func CostPerMillion(quantity int, rateUsd *money.USD) *money.USD {
	return CeilingMulDiv(quantity, rateUsd, MillionTokens)
}

func CostPerThousand(quantity int, rateUsd *money.USD) *money.USD {
	return CeilingMulDiv(quantity, rateUsd, ThousandCalls)
}

func CeilingMulDiv(quantity int, rateUsd *money.USD, divisorQuantity int64) *money.USD {
	return new(money.USD).MulRatioCeil(rateUsd, big.NewInt(int64(quantity)), divisorQuantity)
}
