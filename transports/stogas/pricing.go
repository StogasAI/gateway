package stogas

import (
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const longContextThresholdTokens = billing.LongContextThresholdTokens

func baseHoldEstimate(state *State) (HoldEstimate, error) {
	if state == nil || state.Resolution == nil {
		return HoldEstimate{}, nil
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
	pricing := holdPricingForState(state)
	if inputTokenLimit > 0 {
		meters = appendInputTokenHoldCost(
			meters,
			pricing,
			inputTokenLimit,
			openAICacheWriteHoldMeter(state),
		)
	}
	meters = appendOutputTokenHoldCost(meters, pricing, outputTokenLimit)
	meters, estimatedUpstreamCostUSDAtoms, err := canonicalizeMeters(meters, pricing)
	if err != nil {
		return HoldEstimate{}, err
	}
	return HoldEstimate{
		EstimatedUpstreamCostUSDAtoms: estimatedUpstreamCostUSDAtoms,
		ProductKey:                    resolution.Deployment.ID,
		ProviderKey:                   string(resolution.Provider),
		Meters:                        meters,
	}, nil
}

func calculateBaseUpstreamCost(state *State, extraMeters []catalog.MeterEstimate) (string, error) {
	if state == nil {
		return billing.ZeroChargeUSDAtoms, nil
	}
	if !hasMeasuredUsage(state.Signals) && len(extraMeters) == 0 {
		state.FinalMeters = nil
		return billing.ZeroChargeUSDAtoms, nil
	}
	promptTokens := 0
	completionTokens := 0
	reasoningTokens := 0
	cachedInputTokens := 0
	cacheWriteTokens := 0
	cacheWrite5mTokens := 0
	cacheWrite1hTokens := 0
	if state.Signals != nil {
		promptTokens = state.Signals.PromptTokens()
		completionTokens = state.Signals.CompletionTokens()
		reasoningTokens = state.Signals.ReasoningTokens()
		cachedInputTokens = state.Signals.CachedInputTokens()
		cacheWriteTokens = state.Signals.CacheWriteInputTokens()
		cacheWrite5mTokens = state.Signals.CacheWrite5mInputTokens()
		cacheWrite1hTokens = state.Signals.CacheWrite1hInputTokens()
	}
	rateMode := billing.TokenRateStandard
	if promptTokens > longContextThresholdTokens {
		rateMode = billing.TokenRateLongContext
	}
	pricing := catalog.Pricing{}
	if state.Resolution != nil {
		pricing = effectivePricingForState(state)
	}
	// A provider can add a cache detail before its price reaches the catalog. Keep
	// the usable prompt aggregate as ordinary input instead of subtracting an
	// unpriced partition and silently losing billable usage.
	cacheQuantities := []struct {
		meterKey string
		quantity *int
	}{
		{meterKey: billing.MeterCachedInputTokens, quantity: &cachedInputTokens},
		{meterKey: billing.MeterCacheWriteInputTokens, quantity: &cacheWriteTokens},
		{meterKey: billing.MeterCacheWrite5mInputTokens, quantity: &cacheWrite5mTokens},
		{meterKey: billing.MeterCacheWrite1hInputTokens, quantity: &cacheWrite1hTokens},
	}
	for _, cache := range cacheQuantities {
		_, rate, ok := billing.PricingRate(pricing, cache.meterKey, rateMode)
		if !ok || rate.Sign() <= 0 {
			*cache.quantity = 0
		}
	}
	if reasoningTokens < 0 {
		reasoningTokens = 0
	}
	if reasoningTokens > completionTokens {
		reasoningTokens = completionTokens
	}
	outputTokens := completionTokens - reasoningTokens
	inputTokens := 0
	partitionedInputTokens, ok := addTokenCounts(
		cachedInputTokens,
		cacheWriteTokens,
		cacheWrite5mTokens,
		cacheWrite1hTokens,
	)
	if ok && partitionedInputTokens <= promptTokens {
		inputTokens = promptTokens - partitionedInputTokens
	} else {
		// The aggregate prompt count is still usable when optional cache detail
		// is contradictory. Bill the aggregate as ordinary input and discard only
		// the invalid partition instead of failing or losing the whole prompt.
		inputTokens = promptTokens
		cachedInputTokens = 0
		cacheWriteTokens = 0
		cacheWrite5mTokens = 0
		cacheWrite1hTokens = 0
	}
	meters := []catalog.MeterEstimate{}
	if state.Resolution != nil {
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterInputTokens, inputTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCachedInputTokens, cachedInputTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWriteInputTokens, cacheWriteTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWrite5mInputTokens, cacheWrite5mTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWrite1hInputTokens, cacheWrite1hTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterOutputTokens, outputTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterReasoningTokens, reasoningTokens, false, rateMode)
	}
	meters = append(meters, extraMeters...)
	meters, upstreamCostUSDAtoms, err := canonicalizeMeters(meters, pricing)
	if err != nil {
		return "", err
	}
	if len(state.Hold.Meters) > 0 {
		meters, upstreamCostUSDAtoms, err = capFinalMetersToHold(meters, state.Hold.Meters, pricing)
		if err != nil {
			return "", err
		}
	}
	state.FinalMeters = meters
	return upstreamCostUSDAtoms, nil
}

func cacheReadSavingsUSDAtoms(state *State) (*string, error) {
	if state == nil || state.Resolution == nil {
		return nil, nil
	}
	quantity, cachedCost, err := cacheMeterTotals(
		state.FinalMeters,
		func(meterKey string) bool { return meterKey == billing.MeterCachedInputTokens },
	)
	if err != nil {
		return nil, fmt.Errorf("cached input %w", err)
	}
	uncachedCost, err := ordinaryInputMarginalCost(state, quantity)
	if err != nil {
		return nil, fmt.Errorf("calculate uncached input counterfactual: %w", err)
	}
	savings := big.NewInt(0)
	if uncachedCost.Cmp(cachedCost) > 0 {
		savings.Sub(uncachedCost, cachedCost)
	}
	value := savings.String()
	return &value, nil
}

// cacheWriteOverheadUSDAtoms reports only the extra cost of cache
// creation compared with sending the same tokens as ordinary input. The full
// cache-write charge remains in FinalMeters and the request pricing bag.
func cacheWriteOverheadUSDAtoms(state *State) (*string, error) {
	if state == nil || state.Resolution == nil {
		return nil, nil
	}
	quantity, writeCost, err := cacheMeterTotals(
		state.FinalMeters,
		func(meterKey string) bool {
			switch meterKey {
			case billing.MeterCacheWriteInputTokens,
				billing.MeterCacheWrite5mInputTokens,
				billing.MeterCacheWrite1hInputTokens:
				return true
			default:
				return false
			}
		},
	)
	if err != nil {
		return nil, fmt.Errorf("cache write %w", err)
	}
	ordinaryCost, err := ordinaryInputMarginalCost(state, quantity)
	if err != nil {
		return nil, fmt.Errorf("calculate ordinary input counterfactual: %w", err)
	}
	overhead := big.NewInt(0)
	if writeCost.Cmp(ordinaryCost) > 0 {
		overhead.Sub(writeCost, ordinaryCost)
	}
	value := overhead.String()
	return &value, nil
}

func cacheMeterTotals(
	meters []catalog.MeterEstimate,
	matches func(string) bool,
) (*big.Int, *big.Int, error) {
	quantity := big.NewInt(0)
	amount := big.NewInt(0)
	for _, meter := range meters {
		if !matches(meter.MeterKey) {
			continue
		}
		meterQuantity, ok := new(big.Int).SetString(meter.Quantity, 10)
		if !ok || meterQuantity.Sign() <= 0 {
			return nil, nil, fmt.Errorf("meter has an invalid quantity")
		}
		meterAmount, err := billing.ParseUSDAtoms(meter.AmountUSDAtoms)
		if err != nil {
			return nil, nil, fmt.Errorf("meter has an invalid amount: %w", err)
		}
		quantity.Add(quantity, meterQuantity)
		amount.Add(amount, meterAmount)
	}
	return quantity, amount, nil
}

func ordinaryInputMarginalCost(state *State, quantity *big.Int) (*big.Int, error) {
	if quantity == nil || quantity.Sign() == 0 {
		return big.NewInt(0), nil
	}
	mode := billing.TokenRateStandard
	if state.Signals != nil && state.Signals.PromptTokens() > longContextThresholdTokens {
		mode = billing.TokenRateLongContext
	}
	rateKey, rate, ok := billing.PricingRate(
		effectivePricingForState(state),
		billing.MeterInputTokens,
		mode,
	)
	if !ok {
		return nil, fmt.Errorf("cache meter has no comparable ordinary input rate")
	}
	ordinaryQuantity, _, err := cacheMeterTotals(
		state.FinalMeters,
		func(meterKey string) bool { return meterKey == billing.MeterInputTokens },
	)
	if err != nil {
		return nil, fmt.Errorf("ordinary input %w", err)
	}
	combinedQuantity := new(big.Int).Add(ordinaryQuantity, quantity)
	combinedCost, err := calculatedMeterAmount(rateKey, combinedQuantity, rate)
	if err != nil {
		return nil, err
	}
	ordinaryCost, err := calculatedMeterAmount(rateKey, ordinaryQuantity, rate)
	if err != nil {
		return nil, err
	}
	return combinedCost.Sub(combinedCost, ordinaryCost), nil
}

func appendInputTokenHoldCost(
	meters []catalog.MeterEstimate,
	pricing catalog.Pricing,
	quantity int,
	alternativeMeterKey string,
) []catalog.MeterEstimate {
	meterKey := highestInputHoldMeter(pricing, alternativeMeterKey)
	return billing.AppendTokenMeterCost(meters, pricing, meterKey, quantity, true, billing.TokenRateHighest)
}

func highestInputHoldMeter(pricing catalog.Pricing, alternativeMeterKey string) string {
	meterKey := billing.MeterInputTokens
	if alternativeMeterKey == "" || alternativeMeterKey == meterKey {
		return meterKey
	}
	_, inputRate, hasInputRate := billing.PricingRate(pricing, meterKey, billing.TokenRateHighest)
	_, alternativeRate, hasAlternativeRate := billing.PricingRate(pricing, alternativeMeterKey, billing.TokenRateHighest)
	if hasAlternativeRate && (!hasInputRate || alternativeRate.Cmp(inputRate) > 0) {
		return alternativeMeterKey
	}
	return meterKey
}

func openAICacheWriteHoldMeter(state *State) string {
	if state == nil ||
		state.Resolution == nil ||
		(state.Resolution.Provider != schemas.OpenAI && state.Resolution.Provider != schemas.Azure) ||
		!strings.HasPrefix(state.Resolution.Deployment.Upstream.Model, "gpt-5.6-") {
		return ""
	}
	raw := state.Resolution.RawBody()
	breakpoints, err := validatePromptCacheBreakpoints(
		rawPromptContent(state.Resolution.Route, raw),
		state.Resolution.Route,
	)
	if err != nil {
		return billing.MeterCacheWriteInputTokens
	}
	mode := "implicit"
	if options, ok := rawObject(raw["prompt_cache_options"]); ok {
		if configured := rawString(options["mode"]); configured != "" {
			mode = configured
		}
	}
	if mode == "explicit" && breakpoints == 0 {
		return ""
	}
	return billing.MeterCacheWriteInputTokens
}

func effectivePricingForState(state *State) catalog.Pricing {
	if state == nil || state.Resolution == nil {
		return nil
	}
	return effectivePricingForDeployment(pricingDeploymentForState(state))
}

func effectivePricingForDeployment(deployment catalog.Deployment) catalog.Pricing {
	return billing.WithReasoningTokenFallback(clonePricing(deployment.Pricing))
}

// Authorization uses the deployment selected by the request. Paid execution
// upgrades are explicit deployments; documented Fast-to-Standard fallback can
// only reduce the final charge.
func holdPricingForState(state *State) catalog.Pricing {
	if state == nil || state.Resolution == nil {
		return nil
	}
	return effectivePricingForDeployment(state.Resolution.Deployment)
}

func appendOutputTokenHoldCost(meters []catalog.MeterEstimate, pricing catalog.Pricing, quantity int) []catalog.MeterEstimate {
	_, outputRate, hasOutputRate := billing.PricingRate(pricing, billing.MeterOutputTokens, billing.TokenRateHighest)
	_, reasoningRate, hasReasoningRate := billing.PricingRate(pricing, billing.MeterReasoningTokens, billing.TokenRateHighest)
	if hasReasoningRate && (!hasOutputRate || reasoningRate.Cmp(outputRate) > 0) {
		return billing.AppendTokenMeterCost(meters, pricing, billing.MeterReasoningTokens, quantity, true, billing.TokenRateHighest)
	}
	if hasOutputRate {
		return billing.AppendTokenMeterCost(meters, pricing, billing.MeterOutputTokens, quantity, true, billing.TokenRateHighest)
	}
	return meters
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
	actualTier := state.ActualServiceTier
	actualSpeed := state.ActualSpeed
	if signals, ok := state.Signals.(*StandardSignals); ok && signals != nil {
		if actualTier == nil {
			actualTier = signals.ActualServiceTier
		}
		if actualSpeed == "" {
			actualSpeed = signals.ActualSpeed
		}
	}
	actualTier, actualSpeed = permittedActualExecution(state.Resolution.Provider, deployment, actualTier, actualSpeed)
	if actualTier == nil && actualSpeed == "" {
		return deployment
	}
	// A provider-reported fallback model is diagnostic metadata. It cannot
	// change the deployment, price, or receipt authorized for this request.
	actual, ok := catalog.DeploymentForActualExecution(state.Resolution.Provider, state.Resolution.Route, deployment, actualTier, actualSpeed)
	if !ok {
		return deployment
	}
	return actual
}

func permittedActualExecution(
	provider schemas.ModelProvider,
	selected catalog.Deployment,
	actualTier *schemas.BifrostServiceTier,
	actualSpeed string,
) (*schemas.BifrostServiceTier, string) {
	selectedTier := strings.ToLower(strings.TrimSpace(selected.Upstream.ServiceTier))
	actualTierClass := executionTierClass(provider, actualTier)
	if actualTierClass == "" {
		actualTier = nil
	}
	actualSpeed = strings.ToLower(strings.TrimSpace(actualSpeed))

	switch provider {
	case schemas.OpenAI:
		switch selectedTier {
		case "flex":
			if actualTierClass != "flex" {
				actualTier = nil
			}
		case "priority":
			if actualTierClass != "priority" && actualTierClass != "standard" {
				actualTier = nil
			}
		default:
			if actualTierClass != "standard" {
				actualTier = nil
			}
		}
		actualSpeed = ""
	case schemas.Azure:
		if selectedTier == "priority" {
			if actualTierClass != "priority" && actualTierClass != "standard" {
				actualTier = nil
			}
		} else if actualTierClass != "standard" {
			actualTier = nil
		}
		actualSpeed = ""
	case schemas.Anthropic:
		if actualTierClass != "standard" {
			actualTier = nil
		}
		selectedSpeed := strings.ToLower(strings.TrimSpace(selected.Upstream.Speed))
		if selectedSpeed == "fast" {
			if !stringInSet(actualSpeed, "fast", "") {
				actualSpeed = ""
			}
		} else if actualSpeed != "standard" {
			actualSpeed = ""
		}
	default:
		actualTier = nil
		actualSpeed = ""
	}
	return actualTier, actualSpeed
}

// ExecutionDeployment returns an allowed concrete execution variant for the
// authorized deployment. Unrecognized provider metadata cannot retarget it.
func ExecutionDeployment(state *State) catalog.Deployment {
	return pricingDeploymentForState(state)
}

func canonicalizeMeters(meters []catalog.MeterEstimate, pricing catalog.Pricing) ([]catalog.MeterEstimate, string, error) {
	if len(meters) == 0 {
		return nil, billing.ZeroChargeUSDAtoms, nil
	}
	type meterGroup struct {
		meter    catalog.MeterEstimate
		quantity *big.Int
		rate     *big.Int
	}
	order := make([]string, 0, len(meters))
	groups := map[string]*meterGroup{}
	for _, meter := range meters {
		if meter.MeterKey == "" || strings.TrimSpace(meter.MeterKey) != meter.MeterKey ||
			meter.RateKey == "" || strings.TrimSpace(meter.RateKey) != meter.RateKey {
			return nil, "", fmt.Errorf("meter identity is invalid")
		}
		quantity, err := billing.ParseNonnegativeInteger(meter.Quantity)
		if err != nil || quantity.Sign() <= 0 || !quantity.IsUint64() {
			return nil, "", fmt.Errorf("meter %s has an invalid quantity", meter.MeterKey)
		}
		rates, meterExists := pricing[meter.MeterKey]
		catalogRateRaw, rateExists := rates[meter.RateKey]
		if !meterExists || !rateExists || catalogRateRaw == "" {
			return nil, "", fmt.Errorf("meter %s has no catalog rate", meter.MeterKey)
		}
		rateRaw := meter.RateUSDAtoms
		if rateRaw == "" {
			rateRaw = catalogRateRaw
		}
		rate, rateErr := billing.ParseUSDAtoms(rateRaw)
		amount, amountErr := billing.ParseUSDAtoms(meter.AmountUSDAtoms)
		if rateErr != nil || amountErr != nil || rate.Sign() <= 0 || amount.Sign() <= 0 {
			return nil, "", fmt.Errorf("meter %s has an invalid rate or amount", meter.MeterKey)
		}
		catalogRate, err := billing.ParseUSDAtoms(catalogRateRaw)
		if err != nil || catalogRate.Cmp(rate) != 0 {
			return nil, "", fmt.Errorf("meter %s does not match its catalog rate", meter.MeterKey)
		}
		expected, err := calculatedMeterAmount(meter.RateKey, quantity, rate)
		if err != nil || expected.Cmp(amount) != 0 {
			return nil, "", fmt.Errorf("meter %s has an inconsistent amount", meter.MeterKey)
		}
		key := meter.MeterKey + "\x00" + meter.RateKey + "\x00" + boolKey(meter.HoldRequired)
		group := groups[key]
		if group == nil {
			order = append(order, key)
			meter.RateUSDAtoms = rate.String()
			groups[key] = &meterGroup{meter: meter, quantity: quantity, rate: rate}
			continue
		}
		if group.rate.Cmp(rate) != 0 {
			return nil, "", fmt.Errorf("meter %s uses conflicting rates", meter.MeterKey)
		}
		group.quantity.Add(group.quantity, quantity)
		if !group.quantity.IsUint64() {
			return nil, "", fmt.Errorf("meter %s quantity exceeds the supported range", meter.MeterKey)
		}
	}
	compacted := make([]catalog.MeterEstimate, 0, len(groups))
	total := big.NewInt(0)
	for _, key := range order {
		group := groups[key]
		meter := group.meter
		meter.Quantity = group.quantity.String()
		amount, err := calculatedMeterAmount(meter.RateKey, group.quantity, group.rate)
		if err != nil {
			return nil, "", err
		}
		if _, err := billing.ParseUSDAtoms(amount.String()); err != nil {
			return nil, "", fmt.Errorf("meter %s amount exceeds the settlement limit", meter.MeterKey)
		}
		meter.AmountUSDAtoms = amount.String()
		total.Add(total, amount)
		compacted = append(compacted, meter)
	}
	if _, err := billing.ParseUSDAtoms(total.String()); err != nil {
		return nil, "", fmt.Errorf("meter total exceeds the settlement limit")
	}
	return compacted, total.String(), nil
}

func capFinalMetersToHold(finalMeters []catalog.MeterEstimate, holdMeters []catalog.MeterEstimate, pricing catalog.Pricing) ([]catalog.MeterEstimate, string, error) {
	capacities := map[string]*big.Int{}
	for _, meter := range holdMeters {
		if !meter.HoldRequired {
			continue
		}
		class, ok := meterQuantityClass(meter.MeterKey)
		quantity, quantityOK := new(big.Int).SetString(meter.Quantity, 10)
		if !ok || !quantityOK || quantity.Sign() < 0 {
			return nil, "", fmt.Errorf("held meter quantity is invalid")
		}
		if capacities[class] == nil {
			capacities[class] = big.NewInt(0)
		}
		capacities[class].Add(capacities[class], quantity)
	}

	bounded := make([]catalog.MeterEstimate, 0, len(finalMeters))
	for _, meter := range finalMeters {
		class, ok := meterQuantityClass(meter.MeterKey)
		quantity, quantityOK := new(big.Int).SetString(meter.Quantity, 10)
		if !ok || !quantityOK || quantity.Sign() <= 0 {
			return nil, "", fmt.Errorf("final meter quantity is invalid")
		}
		remaining := capacities[class]
		if remaining == nil || remaining.Sign() <= 0 {
			continue
		}
		allowed := new(big.Int).Set(quantity)
		if allowed.Cmp(remaining) > 0 {
			allowed.Set(remaining)
		}
		remaining.Sub(remaining, allowed)
		rate, err := billing.ParseUSDAtoms(meter.RateUSDAtoms)
		if err != nil || rate.Sign() <= 0 {
			return nil, "", fmt.Errorf("final meter rate is invalid")
		}
		amount, err := calculatedMeterAmount(meter.RateKey, allowed, rate)
		if err != nil {
			return nil, "", err
		}
		meter.Quantity = allowed.String()
		meter.AmountUSDAtoms = amount.String()
		bounded = append(bounded, meter)
	}
	return canonicalizeMeters(bounded, pricing)
}

func calculatedMeterAmount(rateKey string, quantity *big.Int, rate *big.Int) (*big.Int, error) {
	var divisor int64
	switch {
	case strings.HasPrefix(rateKey, "per_mill"):
		divisor = billing.MillionTokens
	case strings.HasPrefix(rateKey, "per_1k"):
		divisor = billing.ThousandCalls
	default:
		return nil, fmt.Errorf("unsupported meter rate key %s", rateKey)
	}
	cost := new(big.Int).Mul(new(big.Int).Set(quantity), rate)
	quotient, remainder := new(big.Int).QuoRem(cost, big.NewInt(divisor), new(big.Int))
	if remainder.Sign() > 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient, nil
}

func validateCanonicalMeterSummary(meters []catalog.MeterEstimate, pricing catalog.Pricing, total string) error {
	canonical, canonicalTotal, err := canonicalizeMeters(meters, pricing)
	if err != nil {
		return err
	}
	if canonicalTotal != total || !slices.Equal(canonical, meters) {
		return fmt.Errorf("meter summary is not canonical")
	}
	return nil
}

func boolKey(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
