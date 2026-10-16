package billing

import (
	"github.com/maximhq/bifrost/transports/stogas/money"
	"math"
	"math/big"
	"strconv"
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

	RatePerMillionTokens = "per_mill_tokens"
	RatePerThousandCalls = "per_1k_calls"

	MillionTokens = 1000000
	ThousandCalls = 1000

	// A per_mill_context_gt_<N>k rate replaces per_mill_tokens for every token
	// of its meter when the prompt, counting cached and cache write tokens, has
	// more than N thousand tokens. The largest cutoff below the prompt applies.
	contextRatePrefix = "per_mill_context_gt_"
)

// ContextCutoff returns the prompt size above which a context rate applies.
func ContextCutoff(rateKey string) (int, bool) {
	digits, ok := strings.CutPrefix(rateKey, contextRatePrefix)
	if !ok {
		return 0, false
	}
	digits, ok = strings.CutSuffix(digits, "k")
	if !ok || digits == "" || digits[0] < '1' || digits[0] > '9' {
		return 0, false
	}
	thousands, err := strconv.Atoi(digits)
	if err != nil || thousands > math.MaxInt/1000 {
		return 0, false
	}
	return thousands * 1000, true
}

// TokenRateKey returns the rate that a prompt of promptTokens pays.
func TokenRateKey(rates map[string]string, promptTokens int) string {
	rateKey, rateCutoff := RatePerMillionTokens, 0
	for key := range rates {
		if cutoff, ok := ContextCutoff(key); ok && cutoff < promptTokens && cutoff > rateCutoff {
			rateKey, rateCutoff = key, cutoff
		}
	}
	return rateKey
}

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

// TokenRateMode selects token rates for a known prompt size, or the highest
// rate for holds placed before the prompt size is known.
type TokenRateMode struct {
	promptTokens int
	highest      bool
}

var (
	TokenRateStandard = TokenRateMode{}
	TokenRateHighest  = TokenRateMode{highest: true}
)

func TokenRateForPrompt(promptTokens int) TokenRateMode {
	return TokenRateMode{promptTokens: promptTokens}
}

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
	meter := pricing[meterKey]
	if len(meter) == 0 {
		return "", nil, false
	}
	if mode.highest {
		return HighestRate(meter)
	}
	rateKey := TokenRateKey(meter, mode.promptTokens)
	if rate, ok := ParseRate(meter[rateKey]); ok {
		return rateKey, rate, true
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
