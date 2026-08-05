package stogas

import (
	"errors"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

var (
	ErrProviderUsageMissing   = errors.New("upstream response did not report token usage")
	ErrProviderUsageMalformed = errors.New("upstream response reported invalid token usage")
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

func validateReportedUsage(_ *State, usage *schemas.BifrostLLMUsage) error {
	if usage == nil {
		return ErrProviderUsageMissing
	}
	if usage.PromptTokens < 0 || usage.CompletionTokens < 0 || usage.TotalTokens < 0 || usage.ReasoningTokens < 0 {
		return ErrProviderUsageMalformed
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
		if details.TextTokens < 0 || details.AudioTokens < 0 || details.ImageTokens < 0 ||
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
		if details.TextTokens < 0 || details.AcceptedPredictionTokens < 0 || details.AudioTokens < 0 ||
			details.ReasoningTokens < 0 || details.RejectedPredictionTokens < 0 ||
			(details.ImageTokens != nil && *details.ImageTokens < 0) ||
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
	return nil
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

// UpstreamUsageProtocolError converts an untrusted usage report failure into a
// stable provider protocol error. The public HTTP layer hides the internal
// distinction while billing treats the request as an insured provider failure.
func UpstreamUsageProtocolError(err error) *schemas.BifrostError {
	statusCode := 502
	errorType := "upstream_protocol_error"
	code := "upstream_usage_invalid"
	message := "Upstream response reported invalid token usage"
	if errors.Is(err, ErrProviderUsageMissing) {
		code = "upstream_usage_missing"
		message = "Upstream response did not report token usage"
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

func cacheWriteTokenTotal(details *schemas.ChatPromptTokensDetails) int {
	tokens, _ := cacheWriteTokenTotalChecked(details)
	return tokens
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

func observeActualExecution(state *State, tier *schemas.BifrostServiceTier, speed *string) {
	if state == nil {
		return
	}
	if tier != nil {
		value := *tier
		state.ActualServiceTier = &value
	}
	if speed != nil {
		state.ActualSpeed = strings.ToLower(strings.TrimSpace(*speed))
	}
}

func observeActualModel(state *State, model *string) {
	if state == nil || model == nil {
		return
	}
	state.ActualModel = strings.TrimSpace(*model)
}

func observeUsageExecution(state *State, usage *schemas.BifrostLLMUsage) {
	if state == nil || usage == nil {
		return
	}
	observeActualExecution(state, nil, usage.Speed)
	observeActualModel(state, usage.ServerSideFallbackModel)
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
