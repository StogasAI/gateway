package catalog

import (
	"math/big"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/providers"
)

const (
	meterInputTokens       = providers.MeterInputTokens
	meterCachedInputTokens = providers.MeterCachedInputTokens
	meterOutputTokens      = providers.MeterOutputTokens

	ratePerMillionTokens         = providers.RatePerMillionTokens
	ratePerMillionContextLTE272K = providers.RatePerMillionContextLTE272K
	ratePerMillionContextGT272K  = providers.RatePerMillionContextGT272K
	ratePerThousandCalls         = providers.RatePerThousandCalls

	longContextThresholdTokens = providers.LongContextThresholdTokens
	millionTokens              = providers.MillionTokens
	thousandCalls              = providers.ThousandCalls
)

type MeterEstimate = providers.MeterEstimate

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
	meters = appendProviderExtraHoldMeterCosts(meters, provider, deployment, outputTokenLimit, inputTokenLimit, pricingContext)
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
	meters = appendProviderExtraSettlementMeterCosts(meters, resolution)
	return sumMeterAmounts(meters)
}

func appendMeterCost(meters []MeterEstimate, pricing Pricing, meterKey string, quantity int, holdRequired bool, useHighestRate bool) []MeterEstimate {
	return providers.AppendTokenMeterCost(meters, pricing, meterKey, quantity, holdRequired, useHighestRate)
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
