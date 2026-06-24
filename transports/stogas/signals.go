package stogas

import "github.com/maximhq/bifrost/core/schemas"

type Signals interface {
	PromptTokens() int
	CompletionTokens() int
	CachedInputTokens() int
	CacheWrite5mInputTokens() int
	CacheWrite1hInputTokens() int
}

type StandardSignals struct {
	Prompt       int
	Completion   int
	Cached       int
	CacheWrite5m int
	CacheWrite1h int
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

func signalsFromUsage(usage *schemas.BifrostLLMUsage) *StandardSignals {
	if usage == nil {
		return nil
	}
	cached := 0
	cacheWrite5m := 0
	cacheWrite1h := 0
	if usage.PromptTokensDetails != nil {
		cached = usage.PromptTokensDetails.CachedReadTokens
		if usage.PromptTokensDetails.CachedWriteTokenDetails != nil {
			cacheWrite5m = usage.PromptTokensDetails.CachedWriteTokenDetails.CachedWriteTokens5m
			cacheWrite1h = usage.PromptTokensDetails.CachedWriteTokenDetails.CachedWriteTokens1h
		} else {
			cacheWrite5m = usage.PromptTokensDetails.CachedWriteTokens
		}
	}
	return &StandardSignals{Prompt: usage.PromptTokens, Completion: usage.CompletionTokens, Cached: cached, CacheWrite5m: cacheWrite5m, CacheWrite1h: cacheWrite1h}
}
