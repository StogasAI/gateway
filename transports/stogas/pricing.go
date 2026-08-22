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

const minimumPromptCacheWriteTokens = 1024

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
	meters, total, err := canonicalizeMeters(meters, pricing)
	if err != nil {
		return HoldEstimate{}, err
	}
	return HoldEstimate{
		MaxUSDAtoms: total,
		ProductKey:  resolution.Deployment.ID,
		ProviderKey: string(resolution.Provider),
		Meters:      meters,
	}, nil
}

func baseFinalPrice(state *State, extraMeters []catalog.MeterEstimate) (string, error) {
	if state == nil {
		return billing.ZeroChargeUSDAtoms, nil
	}
	if !hasMeasuredUsage(state.Signals) && len(extraMeters) == 0 {
		state.FinalMeters = nil
		return noUsageFinalPrice(state)
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
	if reasoningTokens < 0 {
		reasoningTokens = 0
	}
	if reasoningTokens > completionTokens {
		reasoningTokens = completionTokens
	}
	outputTokens := completionTokens - reasoningTokens
	if inferred := azureUnreportedCacheWriteTokens(
		state,
		promptTokens,
		cachedInputTokens,
		cacheWriteTokens,
		cacheWrite5mTokens,
		cacheWrite1hTokens,
	); inferred > 0 {
		cacheWriteTokens = inferred
	}
	inputTokens := 0
	partitionedInputTokens, ok := addTokenCounts(
		cachedInputTokens,
		cacheWriteTokens,
		cacheWrite5mTokens,
		cacheWrite1hTokens,
	)
	if ok && partitionedInputTokens <= promptTokens {
		inputTokens = promptTokens - partitionedInputTokens
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
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWriteInputTokens, cacheWriteTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWrite5mInputTokens, cacheWrite5mTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterCacheWrite1hInputTokens, cacheWrite1hTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterOutputTokens, outputTokens, false, rateMode)
		meters = billing.AppendTokenMeterCost(meters, pricing, billing.MeterReasoningTokens, reasoningTokens, false, rateMode)
	}
	meters = append(meters, extraMeters...)
	meters, total, err := canonicalizeMeters(meters, pricing)
	if err != nil {
		return "", err
	}
	state.FinalMeters = meters
	return total, nil
}

// Azure bills GPT-5.6 cache writes but currently exposes only cached reads in
// request usage. Classify the unreported uncached portion conservatively only
// at Microsoft's 1,024-token cache threshold. Explicit write usage takes
// precedence if Azure adds it.
func azureUnreportedCacheWriteTokens(
	state *State,
	promptTokens int,
	cachedInputTokens int,
	cacheWriteTokens int,
	cacheWrite5mTokens int,
	cacheWrite1hTokens int,
) int {
	if state == nil || state.Resolution == nil ||
		state.Resolution.Provider != schemas.Azure ||
		!strings.HasPrefix(state.Resolution.Deployment.Upstream.Model, "gpt-5.6-") ||
		promptTokens < minimumPromptCacheWriteTokens ||
		cachedInputTokens < 0 || cachedInputTokens > promptTokens ||
		cacheWriteTokens != 0 || cacheWrite5mTokens != 0 || cacheWrite1hTokens != 0 {
		return 0
	}
	return promptTokens - cachedInputTokens
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

func noUsageFinalPrice(state *State) (string, error) {
	if state == nil {
		return billing.ZeroChargeUSDAtoms, nil
	}
	managed := state.Authorization == nil || state.Authorization.UpstreamByok == "" || state.Authorization.UpstreamByok == "stogas"
	if state.BifrostError != nil && billing.ProviderErrorIsInsured(state.BifrostError, managed) {
		return billing.ZeroChargeUSDAtoms, nil
	}
	if state.Authorization != nil && state.Authorization.AuthorizedAmount != nil {
		amount := state.Authorization.AuthorizedAmount.String()
		if !managed && state.Hold.MaxUSDAtoms != "" {
			amount = state.Hold.MaxUSDAtoms
		}
		meters, err := holdCaptureFinalMeters(state, amount)
		if err != nil {
			return "", err
		}
		state.FinalMeters = meters
		return amount, nil
	}
	return billing.ZeroChargeUSDAtoms, nil
}

func holdCaptureFinalMeters(state *State, chargedAmount string) ([]catalog.MeterEstimate, error) {
	if state == nil || len(state.Hold.Meters) == 0 {
		return nil, nil
	}
	meters, total, err := canonicalizeMeters(state.Hold.Meters, holdPricingForState(state))
	if err != nil {
		return nil, err
	}
	if total != chargedAmount {
		return nil, nil
	}
	for i, meter := range meters {
		meter.HoldRequired = false
		meters[i] = meter
	}
	return meters, nil
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
