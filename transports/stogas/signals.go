package stogas

import (
	"errors"
	"strconv"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

var (
	ErrProviderUsageMissing      = errors.New("upstream response did not report token usage")
	ErrProviderUsageMalformed    = errors.New("upstream response reported invalid token usage")
	ErrProviderUsageExceedsHold  = errors.New("upstream response usage exceeds the authorized request bounds")
	ErrProviderExecutionMismatch = errors.New("upstream response reported unauthorized or inconsistent execution metadata")
	ErrProviderResponseMalformed = errors.New("upstream response violated the selected API contract")
	ErrProviderResponseTooLarge  = errors.New("upstream response exceeded the gateway response limit")
)

type Signals interface {
	PromptTokens() int
	CompletionTokens() int
	ReasoningTokens() int
	CachedInputTokens() int
	CacheWriteInputTokens() int
	CacheWrite5mInputTokens() int
	CacheWrite1hInputTokens() int
}

type SearchUsageSignals interface {
	WebSearchCalls() int
}

type StandardSignals struct {
	Prompt            int
	Completion        int
	Reasoning         int
	Cached            int
	CacheWrite        int
	CacheWrite5m      int
	CacheWrite1h      int
	WebSearch         int
	ActualServiceTier *schemas.BifrostServiceTier
	ActualSpeed       string

	webSearchCallIDs map[string]struct{}
	webSearchEvents  map[string]struct{}
}

func hasMeasuredUsage(signals Signals) bool {
	if signals == nil {
		return false
	}
	return signals.PromptTokens() > 0 ||
		signals.CompletionTokens() > 0 ||
		signals.ReasoningTokens() > 0 ||
		signals.CachedInputTokens() > 0 ||
		signals.CacheWriteInputTokens() > 0 ||
		signals.CacheWrite5mInputTokens() > 0 ||
		signals.CacheWrite1hInputTokens() > 0
}

func HasMeasuredUsage(state *State) bool {
	return state != nil && hasMeasuredUsage(state.Signals)
}

func validateReportedUsage(state *State, usage *schemas.BifrostLLMUsage) error {
	if usage == nil {
		return ErrProviderUsageMissing
	}
	if usage.PromptTokens < 0 || usage.CompletionTokens < 0 || usage.TotalTokens < 0 || usage.ReasoningTokens < 0 {
		return ErrProviderUsageMalformed
	}
	if err := validateActualExecutionReport(state, nil, usage.Speed, usage.InferenceGeo); err != nil {
		return err
	}
	if usage.ServerSideFallbackModel != nil && strings.TrimSpace(*usage.ServerSideFallbackModel) != "" {
		// Every client and provider fallback surface is closed. A fallback model
		// can have different prices and proof identity, so it cannot be settled as
		// the deployment that the gateway authorized.
		return ErrProviderExecutionMismatch
	}
	promptTokens, completionTokens, ok := reportedUsageTokenTotals(usage)
	if !ok {
		return ErrProviderUsageMalformed
	}
	if usage.TotalTokens > 0 {
		total, ok := addTokenCounts(promptTokens, completionTokens)
		if !ok || total != usage.TotalTokens {
			return ErrProviderUsageMalformed
		}
	}
	if details := usage.PromptTokensDetails; details != nil {
		if details.TextTokens < 0 || details.AudioTokens != 0 || details.ImageTokens != 0 ||
			details.CachedReadTokens < 0 || details.CachedWriteTokens < 0 {
			return ErrProviderUsageMalformed
		}
		if split := details.CachedWriteTokenDetails; split != nil &&
			(split.CachedWriteTokens5m < 0 || split.CachedWriteTokens1h < 0) {
			return ErrProviderUsageMalformed
		}
		cacheWriteTokens, ok := cacheWriteTokenTotalChecked(details)
		if !ok {
			return ErrProviderUsageMalformed
		}
		if split := details.CachedWriteTokenDetails; split != nil {
			splitTotal, ok := addTokenCounts(split.CachedWriteTokens5m, split.CachedWriteTokens1h)
			if !ok || (details.CachedWriteTokens > 0 && splitTotal > 0 && details.CachedWriteTokens != splitTotal) {
				return ErrProviderUsageMalformed
			}
		}
		cachePartition, ok := addTokenCounts(details.CachedReadTokens, cacheWriteTokens)
		if !ok || cachePartition > promptTokens {
			return ErrProviderUsageMalformed
		}
		promptDetails, ok := promptTokenFallbackChecked(details)
		if !ok || promptDetails > promptTokens {
			return ErrProviderUsageMalformed
		}
	}
	if details := usage.CompletionTokensDetails; details != nil {
		if details.TextTokens < 0 || details.AcceptedPredictionTokens < 0 || details.AudioTokens != 0 ||
			details.ReasoningTokens < 0 || details.RejectedPredictionTokens < 0 ||
			(details.ImageTokens != nil && *details.ImageTokens != 0) ||
			(details.CitationTokens != nil && *details.CitationTokens < 0) ||
			(details.NumSearchQueries != nil && *details.NumSearchQueries < 0) {
			return ErrProviderUsageMalformed
		}
		completionDetails, ok := completionTokenFallbackChecked(details)
		if !ok || completionDetails > completionTokens || details.ReasoningTokens > completionTokens {
			return ErrProviderUsageMalformed
		}
		if usage.ReasoningTokens > 0 && details.ReasoningTokens > 0 && usage.ReasoningTokens != details.ReasoningTokens {
			return ErrProviderUsageMalformed
		}
	}
	if usage.ReasoningTokens > completionTokens {
		return ErrProviderUsageMalformed
	}
	if usageRegresses(state, usage) {
		return ErrProviderUsageMalformed
	}
	if exceedsTokenHold(state, promptTokens, completionTokens) {
		return ErrProviderUsageExceedsHold
	}
	return nil
}

func usageRegresses(state *State, usage *schemas.BifrostLLMUsage) bool {
	if state == nil || usage == nil {
		return false
	}
	current, ok := state.Signals.(*StandardSignals)
	if !ok || current == nil {
		return false
	}
	next := signalsFromUsage(usage)
	if next == nil {
		return false
	}
	return next.Prompt < current.Prompt ||
		next.Completion < current.Completion ||
		next.Reasoning < current.Reasoning ||
		next.Cached < current.Cached ||
		next.CacheWrite < current.CacheWrite ||
		next.CacheWrite5m < current.CacheWrite5m ||
		next.CacheWrite1h < current.CacheWrite1h
}

func exceedsTokenHold(state *State, promptTokens int, completionTokens int) bool {
	if inputLimit, ok := tokenHoldCapacity(state, true); ok && promptTokens > inputLimit {
		return true
	}
	if outputLimit, ok := tokenHoldCapacity(state, false); ok && completionTokens > outputLimit {
		return true
	}
	return false
}

func tokenHoldCapacity(state *State, input bool) (int, bool) {
	if state == nil || len(state.Hold.Meters) == 0 {
		return 0, false
	}
	total := 0
	found := false
	for _, meter := range state.Hold.Meters {
		if !meter.HoldRequired || input != isInputTokenMeter(meter.MeterKey) {
			continue
		}
		if !input && !isOutputTokenMeter(meter.MeterKey) {
			continue
		}
		quantity, err := strconv.Atoi(meter.Quantity)
		if err != nil || quantity < 0 {
			return 0, true
		}
		var ok bool
		total, ok = addTokenCounts(total, quantity)
		if !ok {
			return 0, true
		}
		found = true
	}
	return total, found
}

func isOutputTokenMeter(meterKey string) bool {
	return meterKey == billing.MeterOutputTokens || meterKey == billing.MeterReasoningTokens
}

func isInputTokenMeter(meterKey string) bool {
	switch meterKey {
	case billing.MeterInputTokens,
		billing.MeterCachedInputTokens,
		billing.MeterCacheWriteInputTokens,
		billing.MeterCacheWrite5mInputTokens,
		billing.MeterCacheWrite1hInputTokens:
		return true
	default:
		return false
	}
}

func reportedUsageTokenTotals(usage *schemas.BifrostLLMUsage) (int, int, bool) {
	if usage == nil {
		return 0, 0, false
	}
	promptTokens := usage.PromptTokens
	completionTokens := usage.CompletionTokens
	promptKnown := promptTokens > 0
	completionKnown := completionTokens > 0

	if usage.TotalTokens > 0 &&
		((promptKnown && promptTokens > usage.TotalTokens) || (completionKnown && completionTokens > usage.TotalTokens)) {
		return 0, 0, false
	}
	// Aggregate partitions are stronger than detail counters. Derive one absent
	// partition from a valid total before consulting optional detail counters.
	if usage.TotalTokens > 0 {
		if promptKnown && !completionKnown && promptTokens <= usage.TotalTokens {
			completionTokens = usage.TotalTokens - promptTokens
			completionKnown = true
		} else if completionKnown && !promptKnown && completionTokens <= usage.TotalTokens {
			promptTokens = usage.TotalTokens - completionTokens
			promptKnown = true
		}
	}
	if !promptKnown && usage.PromptTokensDetails != nil {
		var ok bool
		promptTokens, ok = promptTokenFallbackChecked(usage.PromptTokensDetails)
		if !ok {
			return 0, 0, false
		}
		promptKnown = promptTokens > 0
	}
	if !completionKnown && usage.CompletionTokensDetails != nil {
		var ok bool
		completionTokens, ok = completionTokenFallbackChecked(usage.CompletionTokensDetails)
		if !ok {
			return 0, 0, false
		}
		completionKnown = completionTokens > 0
	}
	if usage.TotalTokens <= 0 {
		if !promptKnown && !completionKnown {
			// Streaming providers can attach an empty usage object before the
			// terminal event. Keep it structurally valid; the terminal boundary
			// still requires HasMeasuredUsage before a successful response is sent.
			return 0, 0, true
		}
		_, ok := addTokenCounts(promptTokens, completionTokens)
		return promptTokens, completionTokens, ok
	}
	if !promptKnown && !completionKnown {
		return 0, 0, false
	}
	if !promptKnown && completionTokens <= usage.TotalTokens {
		promptTokens = usage.TotalTokens - completionTokens
		promptKnown = true
	} else if !completionKnown && promptTokens <= usage.TotalTokens {
		completionTokens = usage.TotalTokens - promptTokens
		completionKnown = true
	}
	if !promptKnown || !completionKnown {
		return 0, 0, false
	}
	total, ok := addTokenCounts(promptTokens, completionTokens)
	return promptTokens, completionTokens, ok && total == usage.TotalTokens
}

// UpstreamProtocolError converts an untrusted provider response failure into a
// stable protocol error. The public HTTP layer hides the internal distinction
// while billing treats the request as an insured provider failure.
func UpstreamProtocolError(err error) *schemas.BifrostError {
	statusCode := 502
	errorType := "upstream_protocol_error"
	code := "upstream_usage_invalid"
	message := "Upstream response reported invalid token usage"
	if errors.Is(err, ErrProviderUsageMissing) {
		code = "upstream_usage_missing"
		message = "Upstream response did not report token usage"
	} else if errors.Is(err, ErrProviderExecutionMismatch) {
		code = "upstream_execution_invalid"
		message = "Upstream response reported invalid execution metadata"
	} else if errors.Is(err, ErrProviderResponseTooLarge) {
		code = "upstream_response_too_large"
		message = "Upstream response exceeded the gateway response limit"
	} else if errors.Is(err, ErrProviderResponseMalformed) {
		code = "upstream_response_invalid"
		message = "Upstream response violated the selected API contract"
	}
	allowFallbacks := false
	return &schemas.BifrostError{
		IsBifrostError: true,
		StatusCode:     &statusCode,
		Type:           &errorType,
		AllowFallbacks: &allowFallbacks,
		Error: &schemas.ErrorField{
			Type:    &errorType,
			Code:    &code,
			Message: message,
		},
	}
}

func validateActualExecutionReport(state *State, tier *schemas.BifrostServiceTier, speed *string, inferenceGeo *string) error {
	if state == nil || state.Resolution == nil {
		return nil
	}
	tierValue := ""
	if tier != nil {
		tierValue = strings.ToLower(strings.TrimSpace(string(*tier)))
	}
	speedValue := ""
	if speed != nil {
		speedValue = strings.ToLower(strings.TrimSpace(*speed))
	}
	allowedTier, allowedSpeed := permittedActualExecution(
		state.Resolution.Provider,
		state.Resolution.Deployment,
		tier,
		speedValue,
	)
	if tierValue != "" && executionTierClass(state.Resolution.Provider, tier) != "" && allowedTier == nil {
		return ErrProviderExecutionMismatch
	}
	if speedValue != "" && executionSpeedClass(state.Resolution.Provider, speedValue) != "" && allowedSpeed == "" {
		return ErrProviderExecutionMismatch
	}
	if inferenceGeo != nil {
		reportedGeo := strings.ToLower(strings.TrimSpace(*inferenceGeo))
		if reportedGeo != "" {
			selectedGeo := strings.ToLower(strings.TrimSpace(state.Resolution.Deployment.Upstream.InferenceGeo))
			if state.Resolution.Provider != schemas.Anthropic {
				return ErrProviderExecutionMismatch
			}
			if selectedGeo == "" {
				if reportedGeo != "not_available" {
					return ErrProviderExecutionMismatch
				}
			} else if !stringInSet(selectedGeo, "global", "us") || reportedGeo != selectedGeo {
				return ErrProviderExecutionMismatch
			}
		}
	}
	reportedTierClass := executionTierClass(state.Resolution.Provider, tier)
	if reportedTierClass != "" && executionTierClass(state.Resolution.Provider, state.ActualServiceTier) != "" &&
		reportedTierClass != executionTierClass(state.Resolution.Provider, state.ActualServiceTier) {
		return ErrProviderExecutionMismatch
	}
	reportedSpeedClass := executionSpeedClass(state.Resolution.Provider, speedValue)
	if reportedSpeedClass != "" && executionSpeedClass(state.Resolution.Provider, state.ActualSpeed) != "" &&
		reportedSpeedClass != executionSpeedClass(state.Resolution.Provider, state.ActualSpeed) {
		return ErrProviderExecutionMismatch
	}
	return nil
}

// ValidateCompletedExecution checks stream topology. Missing optional provider
// metadata keeps the catalog-selected deployment; explicit contradictions are
// rejected as each response or chunk is ingested.
func ValidateCompletedExecution(state *State) error {
	if state == nil {
		return nil
	}
	return validateProviderStreamCompleted(state)
}

// ValidateStreamExecutionBeforeOutput remains an explicit transport boundary.
// Ingestion already rejects reported model, tier, speed, and geography
// conflicts before a chunk reaches the client; omitted metadata is compatible.
func ValidateStreamExecutionBeforeOutput(state *State) error {
	return nil
}

func executionTierClass(provider schemas.ModelProvider, tier *schemas.BifrostServiceTier) string {
	if tier == nil {
		return ""
	}
	value := strings.ToLower(strings.TrimSpace(string(*tier)))
	switch provider {
	case schemas.OpenAI, schemas.Azure:
		switch value {
		case "fast", "priority":
			return "priority"
		case "flex":
			return "flex"
		case "auto", "default", "standard", "standard_only":
			return "standard"
		}
	case schemas.Anthropic:
		if stringInSet(value, "auto", "default", "standard", "standard_only") {
			return "standard"
		}
	}
	return ""
}

func executionSpeedClass(provider schemas.ModelProvider, speed string) string {
	if provider != schemas.Anthropic {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(speed)) {
	case "fast":
		return "fast"
	case "standard":
		return "standard"
	default:
		return ""
	}
}

func (s *StandardSignals) PromptTokens() int {
	if s == nil {
		return 0
	}
	return s.Prompt
}

func (s *StandardSignals) CompletionTokens() int {
	if s == nil {
		return 0
	}
	return s.Completion
}

func (s *StandardSignals) ReasoningTokens() int {
	if s == nil {
		return 0
	}
	return s.Reasoning
}

func (s *StandardSignals) CachedInputTokens() int {
	if s == nil {
		return 0
	}
	return s.Cached
}

func (s *StandardSignals) CacheWrite5mInputTokens() int {
	if s == nil {
		return 0
	}
	return s.CacheWrite5m
}

func (s *StandardSignals) CacheWriteInputTokens() int {
	if s == nil {
		return 0
	}
	return s.CacheWrite
}

func (s *StandardSignals) CacheWrite1hInputTokens() int {
	if s == nil {
		return 0
	}
	return s.CacheWrite1h
}

func (s *StandardSignals) WebSearchCalls() int {
	if s == nil {
		return 0
	}
	return s.WebSearch
}

func signalsFromUsage(usage *schemas.BifrostLLMUsage) *StandardSignals {
	if usage == nil {
		return nil
	}
	promptTokens, completionTokens, ok := reportedUsageTokenTotals(usage)
	if !ok {
		return nil
	}

	cached := 0
	cacheWrite := 0
	cacheWrite5m := 0
	cacheWrite1h := 0
	if usage.PromptTokensDetails != nil {
		cached = usage.PromptTokensDetails.CachedReadTokens
		if usage.PromptTokensDetails.CachedWriteTokenDetails != nil {
			cacheWrite5m = usage.PromptTokensDetails.CachedWriteTokenDetails.CachedWriteTokens5m
			cacheWrite1h = usage.PromptTokensDetails.CachedWriteTokenDetails.CachedWriteTokens1h
			if splitTotal, ok := addTokenCounts(cacheWrite5m, cacheWrite1h); ok &&
				usage.PromptTokensDetails.CachedWriteTokens > splitTotal {
				cacheWrite = usage.PromptTokensDetails.CachedWriteTokens - splitTotal
			}
		} else {
			cacheWrite = usage.PromptTokensDetails.CachedWriteTokens
		}
	}
	webSearch := 0
	reasoningTokens := usage.ReasoningTokens
	if usage.CompletionTokensDetails != nil {
		if usage.CompletionTokensDetails.ReasoningTokens > 0 {
			reasoningTokens = usage.CompletionTokensDetails.ReasoningTokens
		}
		if usage.CompletionTokensDetails.NumSearchQueries != nil {
			webSearch = *usage.CompletionTokensDetails.NumSearchQueries
		}
	}
	if promptTokens <= 0 && completionTokens <= 0 && reasoningTokens <= 0 && cached <= 0 &&
		cacheWrite <= 0 && cacheWrite5m <= 0 && cacheWrite1h <= 0 && webSearch <= 0 {
		return nil
	}
	return &StandardSignals{Prompt: promptTokens, Completion: completionTokens, Reasoning: reasoningTokens, Cached: cached, CacheWrite: cacheWrite, CacheWrite5m: cacheWrite5m, CacheWrite1h: cacheWrite1h, WebSearch: webSearch}
}

func cacheWriteTokenTotalChecked(details *schemas.ChatPromptTokensDetails) (int, bool) {
	if details == nil {
		return 0, true
	}
	splitTotal := 0
	if details.CachedWriteTokenDetails != nil {
		var ok bool
		splitTotal, ok = addTokenCounts(
			details.CachedWriteTokenDetails.CachedWriteTokens5m,
			details.CachedWriteTokenDetails.CachedWriteTokens1h,
		)
		if !ok {
			return 0, false
		}
	}
	if details.CachedWriteTokens > splitTotal {
		return details.CachedWriteTokens, true
	}
	return splitTotal, true
}

func promptTokenFallbackChecked(details *schemas.ChatPromptTokensDetails) (int, bool) {
	if details == nil {
		return 0, true
	}
	cacheWriteTokens, ok := cacheWriteTokenTotalChecked(details)
	if !ok {
		return 0, false
	}
	return addTokenCounts(
		details.TextTokens,
		details.AudioTokens,
		details.ImageTokens,
		details.CachedReadTokens,
		cacheWriteTokens,
	)
}

func completionTokenFallbackChecked(details *schemas.ChatCompletionTokensDetails) (int, bool) {
	if details == nil {
		return 0, true
	}
	values := []int{
		details.TextTokens,
		details.AcceptedPredictionTokens,
		details.AudioTokens,
		details.ReasoningTokens,
		details.RejectedPredictionTokens,
	}
	if details.ImageTokens != nil {
		values = append(values, *details.ImageTokens)
	}
	if details.CitationTokens != nil {
		values = append(values, *details.CitationTokens)
	}
	return addTokenCounts(values...)
}

func addTokenCounts(values ...int) (int, bool) {
	maximumInt := int(^uint(0) >> 1)
	total := 0
	for _, value := range values {
		if value < 0 || value > maximumInt-total {
			return 0, false
		}
		total += value
	}
	return total, true
}

func setSignalsFromUsage(state *State, usage *schemas.BifrostLLMUsage) {
	if state == nil {
		return
	}
	next := signalsFromUsage(usage)
	if next == nil {
		return
	}
	observeUsageExecution(state, usage)
	if state.Resolution != nil &&
		state.Resolution.Provider == schemas.Anthropic &&
		next.CacheWrite > 0 {
		combined, ok := addTokenCounts(next.CacheWrite5m, next.CacheWrite)
		if !ok {
			return
		}
		next.CacheWrite5m = combined
		next.CacheWrite = 0
	}
	current, ok := state.Signals.(*StandardSignals)
	if !ok || current == nil {
		state.Signals = next
		return
	}
	current.Prompt = next.Prompt
	current.Completion = next.Completion
	current.Reasoning = next.Reasoning
	current.Cached = next.Cached
	current.CacheWrite = next.CacheWrite
	current.CacheWrite5m = next.CacheWrite5m
	current.CacheWrite1h = next.CacheWrite1h
	if next.WebSearch > current.WebSearch {
		current.WebSearch = next.WebSearch
	}
	if next.ActualServiceTier != nil {
		tier := *next.ActualServiceTier
		current.ActualServiceTier = &tier
	}
	if next.ActualSpeed != "" {
		current.ActualSpeed = next.ActualSpeed
	}
}

func observeActualExecution(state *State, tier *schemas.BifrostServiceTier, speed *string, inferenceGeo ...*string) {
	if state == nil {
		return
	}
	provider := schemas.ModelProvider("")
	if state.Resolution != nil {
		provider = state.Resolution.Provider
	}
	if tier != nil && executionTierClass(provider, tier) != "" {
		value := schemas.BifrostServiceTier(strings.ToLower(strings.TrimSpace(string(*tier))))
		state.ActualServiceTier = &value
	}
	if speed != nil && executionSpeedClass(provider, *speed) != "" {
		state.ActualSpeed = strings.ToLower(strings.TrimSpace(*speed))
	}
	if len(inferenceGeo) > 0 && inferenceGeo[0] != nil && strings.TrimSpace(*inferenceGeo[0]) != "" {
		state.ActualInferenceGeo = strings.ToLower(strings.TrimSpace(*inferenceGeo[0]))
	}
}

func validateActualResponseModel(state *State, model string) error {
	if state == nil || state.Resolution == nil {
		return nil
	}
	model = strings.TrimSpace(model)
	if model == "" {
		return nil
	}
	expected := strings.TrimSpace(state.Resolution.Model)
	if expected == "" {
		return nil
	}
	if !providerModelMatchesSelected(expected, model) || (state.ActualModel != "" && state.ActualModel != model) {
		return ErrProviderExecutionMismatch
	}
	return nil
}

func providerModelMatchesSelected(expected, actual string) bool {
	if actual == expected {
		return true
	}
	prefix := expected + "-"
	if !strings.HasPrefix(actual, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(actual, prefix)
	if len(suffix) == 8 {
		return asciiDigits(suffix)
	}
	return len(suffix) == 10 && suffix[4] == '-' && suffix[7] == '-' &&
		asciiDigits(suffix[:4]) && asciiDigits(suffix[5:7]) && asciiDigits(suffix[8:])
}

func asciiDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func observeActualResponseModel(state *State, model string) {
	if state == nil {
		return
	}
	model = strings.TrimSpace(model)
	if model != "" {
		state.ActualModel = model
	}
}

func responseHasFallbackModel(model *string) bool {
	return model != nil && strings.TrimSpace(*model) != ""
}

func observeUsageExecution(state *State, usage *schemas.BifrostLLMUsage) {
	if state == nil || usage == nil {
		return
	}
	observeActualExecution(state, nil, usage.Speed, usage.InferenceGeo)
}

func setWebSearchSignals(state *State, count int) {
	if state == nil || count <= 0 {
		return
	}
	signals := standardSignals(state)
	if count > signals.WebSearch {
		signals.WebSearch = count
	}
}

func observeWebSearchCall(state *State, id string) {
	if state == nil {
		return
	}
	signals := standardSignals(state)
	id = strings.TrimSpace(id)
	if id == "" {
		signals.WebSearch++
		return
	}
	if signals.webSearchCallIDs == nil {
		signals.webSearchCallIDs = map[string]struct{}{}
	}
	if _, ok := signals.webSearchCallIDs[id]; ok {
		return
	}
	signals.webSearchCallIDs[id] = struct{}{}
	if len(signals.webSearchCallIDs) > signals.WebSearch {
		signals.WebSearch = len(signals.webSearchCallIDs)
	}
}

func observeWebSearchEvent(state *State, eventKey string, callID string) {
	if state == nil {
		return
	}
	signals := standardSignals(state)
	eventKey = strings.TrimSpace(eventKey)
	if eventKey != "" {
		if signals.webSearchEvents == nil {
			signals.webSearchEvents = map[string]struct{}{}
		}
		if _, ok := signals.webSearchEvents[eventKey]; ok {
			return
		}
		signals.webSearchEvents[eventKey] = struct{}{}
	}
	observeWebSearchCall(state, callID)
}

func standardSignals(state *State) *StandardSignals {
	signals, ok := state.Signals.(*StandardSignals)
	if !ok || signals == nil {
		signals = &StandardSignals{}
		state.Signals = signals
	}
	return signals
}
