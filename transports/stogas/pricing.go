package stogas

import (
	"math/big"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const longContextThresholdTokens = billing.LongContextThresholdTokens

func baseHoldEstimate(state *State) HoldEstimate {
	if state == nil || state.Resolution == nil {
		return HoldEstimate{}
	}
	resolution := state.Resolution
	deployment := resolution.Deployment
	inputTokenLimit := resolution.InputTokenLimit()
	outputTokenLimit := resolution.OutputTokenLimit()
	if deployment.ContextWindowTokens > 0 && inputTokenLimit > deployment.ContextWindowTokens {
		inputTokenLimit = deployment.ContextWindowTokens
	}
	if inputTokenLimit < 0 {
		inputTokenLimit = 0
	}
	meters := []catalog.MeterEstimate{}
	pricing := effectivePricingForState(state)
	if inputTokenLimit > 0 {
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterInputTokens, inputTokenLimit, true, billing.TokenRateHighest)
	}
	meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterOutputTokens, outputTokenLimit, true, billing.TokenRateHighest)
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
		state.FinalMeters = nil
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
	rateMode := billing.TokenRateStandard
	if promptTokens > longContextThresholdTokens {
		rateMode = billing.TokenRateLongContext
	}

	meters := []catalog.MeterEstimate{}
	pricing := catalog.Pricing{}
	if state.Resolution != nil {
		pricing = effectivePricingForState(state)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterInputTokens, inputTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCachedInputTokens, cachedInputTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWrite5mInputTokens, cacheWrite5mTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWrite1hInputTokens, cacheWrite1hTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterOutputTokens, completionTokens, false, rateMode)
	}
	meters = append(meters, extraMeters...)
	meters = compactMeterEstimates(meters, pricing)
	state.FinalMeters = meters
	return sumMeterAmounts(meters)
}

func effectivePricingForState(state *State) catalog.Pricing {
	if state == nil || state.Resolution == nil {
		return nil
	}
	return mergePricing(catalog.ProviderPricing(state.Resolution.Provider), pricingDeploymentForState(state).Pricing)
}

func mergePricing(base catalog.Pricing, overrides catalog.Pricing) catalog.Pricing {
	if len(base) == 0 {
		return clonePricing(overrides)
	}
	merged := make(catalog.Pricing, len(base)+len(overrides))
	for meterKey, rates := range base {
		merged[meterKey] = copyRates(rates)
	}
	for meterKey, rates := range overrides {
		merged[meterKey] = copyRates(rates)
	}
	return merged
}

func clonePricing(pricing catalog.Pricing) catalog.Pricing {
	if len(pricing) == 0 {
		return nil
	}
	copied := make(catalog.Pricing, len(pricing))
	for meterKey, rates := range pricing {
		copied[meterKey] = copyRates(rates)
	}
	return copied
}

func copyRates(rates map[string]string) map[string]string {
	if len(rates) == 0 {
		return nil
	}
	copied := make(map[string]string, len(rates))
	for key, value := range rates {
		copied[key] = value
	}
	return copied
}

func pricingDeploymentForState(state *State) catalog.Deployment {
	if state == nil || state.Resolution == nil {
		return catalog.Deployment{}
	}
	deployment := state.Resolution.Deployment
	signals, ok := state.Signals.(*StandardSignals)
	if !ok || signals == nil || (signals.ActualServiceTier == nil && signals.ActualSpeed == "") {
		return deployment
	}
	actual, ok := catalog.DeploymentForActualExecution(state.Resolution.Provider, state.Resolution.Route, deployment, signals.ActualServiceTier, signals.ActualSpeed)
	if !ok {
		return deployment
	}
	return actual
}

func noUsageFinalPrice(state *State) string {
	if state == nil || state.BifrostError == nil || billing.ProviderErrorIsInsured(state.BifrostError) {
		return billing.ZeroChargeUSDAtoms
	}
	if state.Authorization != nil && state.Authorization.AuthorizedAmount != nil {
		amount := state.Authorization.AuthorizedAmount.String()
		state.FinalMeters = holdCaptureFinalMeters(state, amount)
		return amount
	}
	return billing.ZeroChargeUSDAtoms
}

func holdCaptureFinalMeters(state *State, chargedAmount string) []catalog.MeterEstimate {
	if state == nil || len(state.Hold.Meters) == 0 || sumMeterAmounts(state.Hold.Meters) != chargedAmount {
		return nil
	}
	meters := make([]catalog.MeterEstimate, len(state.Hold.Meters))
	for i, meter := range state.Hold.Meters {
		meter.HoldRequired = false
		meters[i] = meter
	}
	return meters
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

func compactMeterEstimates(meters []catalog.MeterEstimate, pricing catalog.Pricing) []catalog.MeterEstimate {
	if len(meters) < 2 {
		return meters
	}
	type meterGroup struct {
		meter    catalog.MeterEstimate
		quantity *big.Int
		amount   *big.Int
	}
	order := make([]string, 0, len(meters))
	groups := map[string]*meterGroup{}
	for _, meter := range meters {
		if meter.MeterKey == "" || meter.RateKey == "" {
			continue
		}
		quantity, ok := new(big.Int).SetString(meter.Quantity, 10)
		if !ok || quantity.Sign() < 0 {
			continue
		}
		amount, ok := new(big.Int).SetString(meter.AmountUSDAtoms, 10)
		if !ok || amount.Sign() < 0 {
			continue
		}
		key := meter.MeterKey + "\x00" + meter.RateKey + "\x00" + boolKey(meter.HoldRequired)
		group := groups[key]
		if group == nil {
			order = append(order, key)
			groups[key] = &meterGroup{meter: meter, quantity: quantity, amount: amount}
			continue
		}
		group.quantity.Add(group.quantity, quantity)
		group.amount.Add(group.amount, amount)
	}
	if len(groups) == len(meters) {
		return meters
	}
	compacted := make([]catalog.MeterEstimate, 0, len(groups))
	for _, key := range order {
		group := groups[key]
		meter := group.meter
		meter.Quantity = group.quantity.String()
		meter.AmountUSDAtoms = compactedMeterAmount(pricing, meter.MeterKey, meter.RateKey, group.quantity, group.amount).String()
		compacted = append(compacted, meter)
	}
	return compacted
}

func compactedMeterAmount(pricing catalog.Pricing, meterKey string, rateKey string, quantity *big.Int, fallback *big.Int) *big.Int {
	meterPricing := pricing[meterKey]
	rate, ok := billing.ParseRate(meterPricing[rateKey])
	if !ok {
		return new(big.Int).Set(fallback)
	}
	divisor := int64(billing.MillionTokens)
	if strings.HasPrefix(rateKey, "per_1k") {
		divisor = billing.ThousandCalls
	}
	cost := new(big.Int).Mul(new(big.Int).Set(quantity), rate)
	quotient, remainder := new(big.Int).QuoRem(cost, big.NewInt(divisor), new(big.Int))
	if remainder.Sign() > 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}

func boolKey(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
