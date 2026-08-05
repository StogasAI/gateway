package stogas

import (
	"errors"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestDefaultAdapterRejectsMalformedProviderUsage(t *testing.T) {
	negativeSearches := -1
	maximumInt := int(^uint(0) >> 1)
	tests := map[string]*schemas.BifrostLLMUsage{
		"negative prompt":         {PromptTokens: -1},
		"negative completion":     {CompletionTokens: -1},
		"negative total":          {TotalTokens: -1},
		"negative reasoning":      {ReasoningTokens: -1},
		"total without partition": {TotalTokens: 8},
		"negative cache split": {
			PromptTokens: 3,
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{CachedWriteTokens5m: -1},
			},
		},
		"negative search count": {
			PromptTokens:            1,
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{NumSearchQueries: &negativeSearches},
		},
		"overflowed cache partition": {
			PromptTokens: maximumInt,
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedReadTokens:  maximumInt,
				CachedWriteTokens: 1,
			},
		},
		"overflowed cache split": {
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: maximumInt,
					CachedWriteTokens1h: 1,
				},
			},
		},
		"overflowed completion details": {
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
				TextTokens:      maximumInt,
				ReasoningTokens: 1,
			},
		},
		"overflowed aggregate total": {
			PromptTokens:     maximumInt,
			CompletionTokens: 1,
			TotalTokens:      maximumInt,
		},
		"overflowed aggregate without total": {
			PromptTokens:     maximumInt,
			CompletionTokens: 1,
		},
	}
	for name, usage := range tests {
		t.Run(name, func(t *testing.T) {
			state := &State{}
			err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
				ChatResponse: &schemas.BifrostChatResponse{Usage: usage},
			}, nil)
			if !errors.Is(err, ErrProviderUsageMalformed) {
				t.Fatalf("IngestResponse error = %v, want malformed provider usage", err)
			}
			if HasMeasuredUsage(state) {
				t.Fatalf("malformed provider usage was retained: %#v", state.Signals)
			}
		})
	}
}

func TestDefaultAdapterRejectsInconsistentProviderUsage(t *testing.T) {
	tests := map[string]*schemas.BifrostLLMUsage{
		"aggregate total differs": {
			PromptTokens: 3, CompletionTokens: 5, TotalTokens: 9,
		},
		"detail partitions differ from total": {
			TotalTokens:             8,
			PromptTokensDetails:     &schemas.ChatPromptTokensDetails{TextTokens: 3},
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{TextTokens: 4},
		},
		"known partition exceeds total": {
			PromptTokens: 9, TotalTokens: 8,
		},
		"reasoning without completion": {
			PromptTokens: 1, TotalTokens: 1, ReasoningTokens: 1,
		},
		"cached input exceeds prompt": {
			PromptTokens:        3,
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{CachedReadTokens: 4},
		},
		"cache write exceeds uncached prompt": {
			PromptTokens:        3,
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{CachedReadTokens: 1, CachedWriteTokens: 3},
		},
		"reasoning exceeds completion": {
			CompletionTokens:        3,
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{ReasoningTokens: 4},
		},
		"cache write aggregate differs from TTL split": {
			PromptTokens: 3,
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedWriteTokens: 3,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 1,
					CachedWriteTokens1h: 1,
				},
			},
		},
		"top-level reasoning differs from detail": {
			CompletionTokens: 3,
			ReasoningTokens:  1,
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
				ReasoningTokens: 2,
			},
		},
	}
	for name, usage := range tests {
		t.Run(name, func(t *testing.T) {
			state := &State{}
			err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
				ChatResponse: &schemas.BifrostChatResponse{Usage: usage},
			}, nil)
			if !errors.Is(err, ErrProviderUsageMalformed) {
				t.Fatalf("IngestResponse error = %v, want malformed provider usage", err)
			}
			if HasMeasuredUsage(state) {
				t.Fatalf("inconsistent provider usage was retained: %#v", state.Signals)
			}
		})
	}
}

func TestDefaultAdapterDerivesOneMissingUsagePartitionFromTotal(t *testing.T) {
	state := &State{}
	usage := &schemas.BifrostLLMUsage{
		PromptTokens:    100,
		TotalTokens:     175,
		ReasoningTokens: 50,
	}
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
		ChatResponse: &schemas.BifrostChatResponse{Usage: usage},
	}, nil); err != nil {
		t.Fatalf("valid partial aggregate usage was rejected: %v", err)
	}
	signals, ok := state.Signals.(*StandardSignals)
	if !ok || signals.Prompt != 100 || signals.Completion != 75 || signals.Reasoning != 50 {
		t.Fatalf("partial aggregate usage was not normalized exactly: %#v", state.Signals)
	}
}

func TestDefaultAdapterPrefersAggregateDerivedPartitionOverContradictoryDetails(t *testing.T) {
	state := &State{}
	usage := &schemas.BifrostLLMUsage{
		PromptTokens: 100,
		TotalTokens:  175,
		CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
			TextTokens:      20,
			ReasoningTokens: 30,
		},
	}
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
		ChatResponse: &schemas.BifrostChatResponse{Usage: usage},
	}, nil); err != nil {
		t.Fatalf("reconcilable aggregate usage was rejected: %v", err)
	}
	signals, ok := state.Signals.(*StandardSignals)
	if !ok || signals.Prompt != 100 || signals.Completion != 75 || signals.Reasoning != 30 {
		t.Fatalf("aggregate partition did not take precedence: %#v", state.Signals)
	}
}

func TestDefaultAdapterDerivesAggregatePartitionAfterDetailFallback(t *testing.T) {
	state := &State{}
	usage := &schemas.BifrostLLMUsage{
		TotalTokens:         80,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{TextTokens: 30},
	}
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
		ChatResponse: &schemas.BifrostChatResponse{Usage: usage},
	}, nil); err != nil {
		t.Fatalf("detail-backed aggregate usage was rejected: %v", err)
	}
	signals, ok := state.Signals.(*StandardSignals)
	if !ok || signals.Prompt != 30 || signals.Completion != 50 {
		t.Fatalf("missing aggregate partition was not derived: %#v", state.Signals)
	}
}

func TestOpenAIExplicitCacheWriteUsageIsOnePromptPartition(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Body:   []byte(`{"model":"gpt-5.6-luna","messages":[{"role":"user","content":[{"type":"text","text":"one","prompt_cache_breakpoint":{"mode":"explicit"}},{"type":"text","text":"two","prompt_cache_breakpoint":{"mode":"explicit"}}]}],"prompt_cache_options":{"mode":"explicit"},"max_completion_tokens":16}`),
	})
	if err != nil {
		t.Fatalf("resolve request: %v", err)
	}
	state := &State{Resolution: resolution}
	usage := &schemas.BifrostLLMUsage{
		PromptTokens:        100,
		CompletionTokens:    1,
		TotalTokens:         101,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{CachedWriteTokens: 100},
	}
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
		ChatResponse: &schemas.BifrostChatResponse{Usage: usage},
	}, nil); err != nil {
		t.Fatalf("valid cache-write partition was rejected: %v", err)
	}
	if signals, ok := state.Signals.(*StandardSignals); !ok || signals.CacheWrite != 100 {
		t.Fatalf("cache-write usage was not retained: %#v", state.Signals)
	}

	usage.PromptTokensDetails.CachedWriteTokens = 101
	rejectedState := &State{Resolution: resolution}
	if err := (DefaultAdapter{}).IngestResponse(rejectedState, &schemas.BifrostResponse{
		ChatResponse: &schemas.BifrostChatResponse{Usage: usage},
	}, nil); !errors.Is(err, ErrProviderUsageMalformed) {
		t.Fatalf("overlapping cache-write usage error = %v, want malformed provider usage", err)
	}
}

func TestProviderErrorBilledUsageIsValidatedAndSettledExactly(t *testing.T) {
	speed := "fast"
	fallbackModel := "gpt-5.6-terra"
	statusCode := 500
	state := &State{
		Adapter: OpenAIAdapter{},
		Resolution: &catalog.ResolvedRequest{
			Provider: schemas.OpenAI,
			Route:    catalog.RouteResponses,
			Deployment: catalog.Deployment{Pricing: catalog.Pricing{
				billing.MeterInputTokens:       {billing.RatePerMillionTokens: "1000000"},
				billing.MeterCachedInputTokens: {billing.RatePerMillionTokens: "100000"},
				billing.MeterOutputTokens:      {billing.RatePerMillionTokens: "2000000"},
				billing.MeterReasoningTokens:   {billing.RatePerMillionTokens: "3000000"},
			}},
		},
	}
	providerErr := &schemas.BifrostError{
		StatusCode: &statusCode,
		Error:      &schemas.ErrorField{Message: "provider failed after processing"},
		ExtraFields: schemas.BifrostErrorExtraFields{BilledUsage: &schemas.BifrostLLMUsage{
			PromptTokens:     100,
			CompletionTokens: 20,
			TotalTokens:      120,
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedReadTokens: 10,
			},
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{ReasoningTokens: 5},
			Speed:                   &speed,
			ServerSideFallbackModel: &fallbackModel,
		}},
	}
	if err := state.Adapter.IngestResponse(state, nil, providerErr); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	if !HasMeasuredUsage(state) {
		t.Fatalf("provider billed usage was not retained: %#v", state.Signals)
	}
	if state.ActualSpeed != "fast" || state.ActualModel != fallbackModel {
		t.Fatalf("actual execution metadata was not retained: speed=%q model=%q", state.ActualSpeed, state.ActualModel)
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms == billing.ZeroChargeUSDAtoms || len(state.FinalMeters) != 4 {
		t.Fatalf("partial provider usage was not settled exactly: cost=%s meters=%#v", state.FinalCostUSDAtoms, state.FinalMeters)
	}
}

func TestProviderUsageProtocolErrorIsInsuredAndStable(t *testing.T) {
	for _, source := range []error{ErrProviderUsageMissing, ErrProviderUsageMalformed} {
		bifrostErr := UpstreamUsageProtocolError(source)
		if bifrostErr.StatusCode == nil || *bifrostErr.StatusCode != 502 || bifrostErr.Error == nil || bifrostErr.Error.Code == nil {
			t.Fatalf("invalid protocol error: %#v", bifrostErr)
		}
		if !billing.ProviderErrorIsInsured(bifrostErr) {
			t.Fatalf("usage protocol error must be insured: %#v", bifrostErr)
		}
	}
}

func TestAllZeroUsageDoesNotSatisfyTerminalUsageRequirement(t *testing.T) {
	state := &State{}
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
		ChatResponse: &schemas.BifrostChatResponse{Usage: &schemas.BifrostLLMUsage{}},
	}, nil); err != nil {
		t.Fatalf("structurally valid empty usage should be classified at the terminal boundary: %v", err)
	}
	if HasMeasuredUsage(state) {
		t.Fatalf("all-zero usage was classified as measured: %#v", state.Signals)
	}
}
