package stogas

import (
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

type Signals interface {
	PromptTokens() int
	CompletionTokens() int
	CachedInputTokens() int
	CacheWrite5mInputTokens() int
	CacheWrite1hInputTokens() int
}

type SearchUsageSignals interface {
	WebSearchCalls() int
}

type StandardSignals struct {
	Prompt            int
	Completion        int
	Cached            int
	CacheWrite5m      int
	CacheWrite1h      int
	WebSearch         int
	ActualServiceTier *schemas.BifrostServiceTier
	ActualSpeed       string

	webSearchCallIDs map[string]struct{}
	webSearchEvents  map[string]struct{}
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
	promptTokens := usage.PromptTokens
	completionTokens := usage.CompletionTokens

	cached := 0
	cacheWrite5m := 0
	cacheWrite1h := 0
	if usage.PromptTokensDetails != nil {
		cached = usage.PromptTokensDetails.CachedReadTokens
		if usage.PromptTokensDetails.CachedWriteTokenDetails != nil {
			cacheWrite5m = usage.PromptTokensDetails.CachedWriteTokenDetails.CachedWriteTokens5m
			cacheWrite1h = usage.PromptTokensDetails.CachedWriteTokenDetails.CachedWriteTokens1h
			if residual := usage.PromptTokensDetails.CachedWriteTokens - cacheWrite5m - cacheWrite1h; residual > 0 {
				cacheWrite1h += residual
			}
		} else {
			cacheWrite5m = usage.PromptTokensDetails.CachedWriteTokens
		}
	}
	webSearch := 0
	if usage.CompletionTokensDetails != nil {
		if usage.CompletionTokensDetails.NumSearchQueries != nil {
			webSearch = *usage.CompletionTokensDetails.NumSearchQueries
		}
	}
	if usage.TotalTokens > 0 {
		if promptTokens == 0 && usage.TotalTokens > completionTokens {
			promptTokens = usage.TotalTokens - completionTokens
		}
		if completionTokens == 0 && usage.TotalTokens > promptTokens {
			completionTokens = usage.TotalTokens - promptTokens
		}
	}
	if promptTokens == 0 && usage.PromptTokensDetails != nil {
		promptTokens = promptTokenFallback(usage.PromptTokensDetails)
	}
	if completionTokens == 0 && usage.CompletionTokensDetails != nil {
		completionTokens = completionTokenFallback(usage.CompletionTokensDetails)
	}
	return &StandardSignals{Prompt: promptTokens, Completion: completionTokens, Cached: cached, CacheWrite5m: cacheWrite5m, CacheWrite1h: cacheWrite1h, WebSearch: webSearch}
}

func promptTokenFallback(details *schemas.ChatPromptTokensDetails) int {
	if details == nil {
		return 0
	}
	return details.TextTokens + details.AudioTokens + details.ImageTokens + details.CachedReadTokens + cacheWriteTokenTotal(details)
}

func cacheWriteTokenTotal(details *schemas.ChatPromptTokensDetails) int {
	if details == nil {
		return 0
	}
	splitTotal := 0
	if details.CachedWriteTokenDetails != nil {
		splitTotal = details.CachedWriteTokenDetails.CachedWriteTokens5m + details.CachedWriteTokenDetails.CachedWriteTokens1h
	}
	if details.CachedWriteTokens > splitTotal {
		return details.CachedWriteTokens
	}
	return splitTotal
}

func completionTokenFallback(details *schemas.ChatCompletionTokensDetails) int {
	if details == nil {
		return 0
	}
	tokens := details.TextTokens + details.AcceptedPredictionTokens + details.AudioTokens + details.ReasoningTokens + details.RejectedPredictionTokens
	if details.ImageTokens != nil {
		tokens += *details.ImageTokens
	}
	if details.CitationTokens != nil {
		tokens += *details.CitationTokens
	}
	return tokens
}

func setSignalsFromUsage(state *State, usage *schemas.BifrostLLMUsage) {
	if state == nil {
		return
	}
	next := signalsFromUsage(usage)
	if next == nil {
		return
	}
	current, ok := state.Signals.(*StandardSignals)
	if !ok || current == nil {
		state.Signals = next
		return
	}
	current.Prompt = next.Prompt
	current.Completion = next.Completion
	current.Cached = next.Cached
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
	signals := standardSignals(state)
	if tier != nil {
		value := *tier
		signals.ActualServiceTier = &value
	}
	if speed != nil {
		signals.ActualSpeed = strings.ToLower(strings.TrimSpace(*speed))
	}
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
