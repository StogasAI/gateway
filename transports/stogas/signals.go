package stogas

import (
	"errors"
	"strconv"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

var (
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

func validateReportedUsageMetadata(state *State, usage *schemas.BifrostLLMUsage) error {
	if usage == nil {
		return nil
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
	return nil
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

func reportedUsageTokenTotals(usage *schemas.BifrostLLMUsage) (int, int) {
	if usage == nil {
		return 0, 0
	}
	promptTokens := nonnegativeTokenCount(usage.PromptTokens)
	completionTokens := nonnegativeTokenCount(usage.CompletionTokens)
	totalTokens := nonnegativeTokenCount(usage.TotalTokens)
	promptKnown := promptTokens > 0
	completionKnown := completionTokens > 0

	// Aggregate prompt and completion counts are independent billing evidence.
	// Use a coherent total only to fill one missing side; a contradictory total
	// does not invalidate the two usable aggregates.
	if totalTokens > 0 {
		if promptKnown && !completionKnown && promptTokens <= totalTokens {
			completionTokens = totalTokens - promptTokens
			completionKnown = true
		} else if completionKnown && !promptKnown && completionTokens <= totalTokens {
			promptTokens = totalTokens - completionTokens
			promptKnown = true
		}
	}
	if !promptKnown && usage.PromptTokensDetails != nil {
		promptTokens = promptTokenFallback(usage.PromptTokensDetails)
		promptKnown = promptTokens > 0
	}
	if !completionKnown && usage.CompletionTokensDetails != nil {
		completionTokens = completionTokenFallback(usage.CompletionTokensDetails)
		completionKnown = completionTokens > 0
	}
	if !promptKnown && completionKnown && completionTokens <= totalTokens {
		promptTokens = totalTokens - completionTokens
		promptKnown = true
	} else if !completionKnown && promptKnown && promptTokens <= totalTokens {
		completionTokens = totalTokens - promptTokens
		completionKnown = true
	}
	return promptTokens, completionTokens
}

// UpstreamProtocolError converts an untrusted provider response failure into a
// stable protocol error. The public HTTP layer hides the internal distinction.
func UpstreamProtocolError(err error) *schemas.BifrostError {
	statusCode := 502
	errorType := "upstream_protocol_error"
	code := "upstream_response_invalid"
	message := "Upstream response violated the selected API contract"
	if errors.Is(err, ErrProviderExecutionMismatch) {
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
	promptTokens, completionTokens := reportedUsageTokenTotals(usage)

	cached := 0
	cacheWrite := 0
	cacheWrite5m := 0
	cacheWrite1h := 0
	if usage.PromptTokensDetails != nil {
		cached = nonnegativeTokenCount(usage.PromptTokensDetails.CachedReadTokens)
		if usage.PromptTokensDetails.CachedWriteTokenDetails != nil {
			cacheWrite5m = nonnegativeTokenCount(usage.PromptTokensDetails.CachedWriteTokenDetails.CachedWriteTokens5m)
			cacheWrite1h = nonnegativeTokenCount(usage.PromptTokensDetails.CachedWriteTokenDetails.CachedWriteTokens1h)
			splitTotal := saturatingTokenTotal(cacheWrite5m, cacheWrite1h)
			reportedWrite := nonnegativeTokenCount(usage.PromptTokensDetails.CachedWriteTokens)
			if reportedWrite > 0 && splitTotal > 0 && reportedWrite != splitTotal {
				if splitTotal < reportedWrite {
					// Keep the usable TTL split and leave only the unexplained
					// remainder unspecified.
					cacheWrite = reportedWrite - splitTotal
				} else {
					// The details exceed the usable aggregate, so their TTL
					// classification cannot be trusted.
					cacheWrite = reportedWrite
					cacheWrite5m = 0
					cacheWrite1h = 0
				}
			} else if splitTotal == 0 {
				cacheWrite = reportedWrite
			}
		} else {
			cacheWrite = nonnegativeTokenCount(usage.PromptTokensDetails.CachedWriteTokens)
		}
	}
	webSearch := 0
	reasoningTokens := nonnegativeTokenCount(usage.ReasoningTokens)
	if usage.CompletionTokensDetails != nil {
		if usage.CompletionTokensDetails.ReasoningTokens > 0 {
			reasoningTokens = usage.CompletionTokensDetails.ReasoningTokens
		}
		if usage.CompletionTokensDetails.NumSearchQueries != nil && *usage.CompletionTokensDetails.NumSearchQueries > 0 {
			webSearch = *usage.CompletionTokensDetails.NumSearchQueries
		}
	}
	next := &StandardSignals{Prompt: promptTokens, Completion: completionTokens, Reasoning: reasoningTokens, Cached: cached, CacheWrite: cacheWrite, CacheWrite5m: cacheWrite5m, CacheWrite1h: cacheWrite1h, WebSearch: webSearch}
	if !hasMeasuredUsage(next) && next.WebSearch <= 0 {
		return nil
	}
	return next
}

func cacheWriteTokenTotal(details *schemas.ChatPromptTokensDetails) int {
	if details == nil {
		return 0
	}
	splitTotal := 0
	if details.CachedWriteTokenDetails != nil {
		splitTotal = saturatingTokenTotal(
			details.CachedWriteTokenDetails.CachedWriteTokens5m,
			details.CachedWriteTokenDetails.CachedWriteTokens1h,
		)
	}
	reported := nonnegativeTokenCount(details.CachedWriteTokens)
	if reported > splitTotal {
		return reported
	}
	return splitTotal
}

func promptTokenFallback(details *schemas.ChatPromptTokensDetails) int {
	if details == nil {
		return 0
	}
	return saturatingTokenTotal(
		details.TextTokens,
		details.AudioTokens,
		details.ImageTokens,
		details.CachedReadTokens,
		cacheWriteTokenTotal(details),
	)
}

func completionTokenFallback(details *schemas.ChatCompletionTokensDetails) int {
	if details == nil {
		return 0
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
	return saturatingTokenTotal(values...)
}

func nonnegativeTokenCount(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func saturatingTokenTotal(values ...int) int {
	maximumInt := int(^uint(0) >> 1)
	total := 0
	for _, raw := range values {
		value := nonnegativeTokenCount(raw)
		if value > maximumInt-total {
			return maximumInt
		}
		total += value
	}
	return total
}

func clampSignalsToAuthorizedUsage(state *State, signals *StandardSignals) {
	if signals == nil {
		return
	}
	if inputLimit, ok := tokenHoldCapacity(state, true); ok && signals.Prompt > inputLimit {
		signals.Prompt = inputLimit
	}
	if outputLimit, ok := tokenHoldCapacity(state, false); ok && signals.Completion > outputLimit {
		signals.Completion = outputLimit
	}
	cachePartition, cachePartitionOK := addTokenCounts(
		signals.Cached,
		signals.CacheWrite,
		signals.CacheWrite5m,
		signals.CacheWrite1h,
	)
	if !cachePartitionOK || cachePartition > signals.Prompt {
		// The aggregate input count remains usable, but an inconsistent cache
		// breakdown cannot safely select discounted or premium cache rates.
		signals.Cached = 0
		signals.CacheWrite = 0
		signals.CacheWrite5m = 0
		signals.CacheWrite1h = 0
	}
	if signals.Reasoning > signals.Completion {
		// Keep the usable completion aggregate and ignore an impossible detail
		// partition instead of converting provider drift into a request failure.
		signals.Reasoning = 0
	}
}

func cachePartitionTotal(signals *StandardSignals) int {
	if signals == nil {
		return 0
	}
	return saturatingTokenTotal(
		signals.Cached,
		signals.CacheWrite,
		signals.CacheWrite5m,
		signals.CacheWrite1h,
	)
}

func cachePartitionSpecificity(signals *StandardSignals) int {
	if signals == nil {
		return 0
	}
	return saturatingTokenTotal(signals.CacheWrite5m, signals.CacheWrite1h)
}

func mergeCachePartition(current, next *StandardSignals) {
	if current == nil || next == nil {
		return
	}
	currentTotal := cachePartitionTotal(current)
	nextTotal := cachePartitionTotal(next)
	if nextTotal < currentTotal ||
		(nextTotal == currentTotal &&
			cachePartitionSpecificity(next) < cachePartitionSpecificity(current)) {
		return
	}
	current.Cached = next.Cached
	current.CacheWrite = next.CacheWrite
	current.CacheWrite5m = next.CacheWrite5m
	current.CacheWrite1h = next.CacheWrite1h
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
	clampSignalsToAuthorizedUsage(state, next)
	if state.Resolution != nil &&
		(state.Resolution.Provider == schemas.Anthropic || azureDeploymentUsesAnthropicWire(state)) &&
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
	current.Prompt = max(current.Prompt, next.Prompt)
	current.Completion = max(current.Completion, next.Completion)
	current.Reasoning = max(current.Reasoning, next.Reasoning)
	mergeCachePartition(current, next)
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
	clampSignalsToAuthorizedUsage(state, current)
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
