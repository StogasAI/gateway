package stogas

import (
	"math/big"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const longContextThresholdTokens = billing.LongContextThresholdTokens

func baseHoldEstimate(state *State) HoldEstimate {
	if state == nil || state.Resolution == nil {
		return HoldEstimate{}
	}
	resolution := state.Resolution
	inputTokenLimit := resolution.InputTokenLimit()
	outputTokenLimit := resolution.OutputTokenLimit()
	if resolution.Deployment.ContextWindowTokens > 0 && inputTokenLimit > resolution.Deployment.ContextWindowTokens-outputTokenLimit {
		inputTokenLimit = resolution.Deployment.ContextWindowTokens - outputTokenLimit
	}
	if inputTokenLimit < 0 {
		inputTokenLimit = 0
	}
	meters := []catalog.MeterEstimate{}
	if inputTokenLimit > 0 {
		meters = billing.AppendTokenMeterCost(meters, resolution.Deployment.Pricing, billing.MeterInputTokens, inputTokenLimit, true, true)
	}
	meters = billing.AppendTokenMeterCost(meters, resolution.Deployment.Pricing, billing.MeterOutputTokens, outputTokenLimit, true, true)
	return HoldEstimate{
		MaxUSDAtoms: sumMeterAmounts(meters),
		ProductKey:  resolution.Deployment.ID,
		ProviderKey: string(resolution.Provider),
		Meters:      meters,
	}
}

func baseFinalPrice(state *State, extraMeters []catalog.MeterEstimate) string {
	if state == nil {
		return billing.ZeroChargeUSDAtoms
	}
	if state.Signals == nil {
		return noUsageFinalPrice(state)
	}
	promptTokens := state.Signals.PromptTokens()
	completionTokens := state.Signals.CompletionTokens()
	cachedInputTokens := state.Signals.CachedInputTokens()
	cacheWrite5mTokens := state.Signals.CacheWrite5mInputTokens()
	cacheWrite1hTokens := state.Signals.CacheWrite1hInputTokens()
	inputTokens := promptTokens - cachedInputTokens - cacheWrite5mTokens - cacheWrite1hTokens
	if inputTokens < 0 {
		inputTokens = 0
	}
	totalTokens := promptTokens + completionTokens

	meters := []catalog.MeterEstimate{}
	if state.Resolution != nil {
		pricing := state.Resolution.Deployment.Pricing
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterInputTokens, inputTokens, false, totalTokens > longContextThresholdTokens)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCachedInputTokens, cachedInputTokens, false, totalTokens > longContextThresholdTokens)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWrite5mInputTokens, cacheWrite5mTokens, false, totalTokens > longContextThresholdTokens)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWrite1hInputTokens, cacheWrite1hTokens, false, totalTokens > longContextThresholdTokens)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterOutputTokens, completionTokens, false, totalTokens > longContextThresholdTokens)
	}
	meters = append(meters, extraMeters...)
	return sumMeterAmounts(meters)
}

func noUsageFinalPrice(state *State) string {
	if state == nil || state.BifrostError == nil || billing.ProviderErrorIsInsured(state.BifrostError) {
		return billing.ZeroChargeUSDAtoms
	}
	if state.Authorization != nil && state.Authorization.AuthorizedAmount != nil {
		return state.Authorization.AuthorizedAmount.String()
	}
	return billing.ZeroChargeUSDAtoms
}

func sumMeterAmounts(meters []catalog.MeterEstimate) string {
	total := big.NewInt(0)
	for _, meter := range meters {
		amount, ok := new(big.Int).SetString(meter.AmountUSDAtoms, 10)
		if ok {
			total.Add(total, amount)
		}
	}
	return total.String()
}
