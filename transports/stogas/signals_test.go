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
	oneImageToken := 1
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
		"audio input on text request": {
			PromptTokens:        1,
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{AudioTokens: 1},
		},
		"image output on text request": {
			CompletionTokens:        1,
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{ImageTokens: &oneImageToken},
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

func TestWebSearchBillingIdentityMatchesStreamItemIdentity(t *testing.T) {
	itemID := "ws_1"
	callID := "ws_1"
	item := schemas.ResponsesMessage{
		ID:   &itemID,
		Type: schemas.Ptr(schemas.ResponsesMessageTypeWebSearchCall),
		ResponsesToolMessage: &schemas.ResponsesToolMessage{
			CallID: &callID,
		},
	}
	if got := responsesMessageWebSearchCallID(item); got != "id:ws_1" {
		t.Fatalf("web-search billing identity = %q, want stream item identity", got)
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

func TestDefaultAdapterRejectsRegressingStreamUsage(t *testing.T) {
	for name, usage := range map[string]*schemas.BifrostLLMUsage{
		"aggregate": {
			PromptTokens:     9,
			CompletionTokens: 5,
			TotalTokens:      14,
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedReadTokens: 4,
			},
		},
		"partition": {
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
			PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedReadTokens: 3,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := &State{}
			first := &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
				Usage: &schemas.BifrostLLMUsage{
					PromptTokens:     10,
					CompletionTokens: 5,
					TotalTokens:      15,
					PromptTokensDetails: &schemas.ChatPromptTokensDetails{
						CachedReadTokens: 4,
					},
				},
			}}
			if err := (DefaultAdapter{}).IngestChunk(state, first); err != nil {
				t.Fatalf("first cumulative usage was rejected: %v", err)
			}
			err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{Usage: usage},
			})
			if !errors.Is(err, ErrProviderUsageMalformed) {
				t.Fatalf("regressing usage error = %v, want malformed provider usage", err)
			}
			if HasMeasuredUsage(state) {
				t.Fatalf("regressing usage retained billable signals: %#v", state.Signals)
			}
		})
	}
}

func TestUsageAboveHoldClearsEarlierCumulativeUsage(t *testing.T) {
	state := &State{Hold: HoldEstimate{Meters: []catalog.MeterEstimate{
		{MeterKey: billing.MeterInputTokens, Quantity: "10", HoldRequired: true},
		{MeterKey: billing.MeterOutputTokens, Quantity: "5", HoldRequired: true},
	}}}
	first := &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{Usage: &schemas.BifrostLLMUsage{
		PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15,
	}}}
	if err := (DefaultAdapter{}).IngestChunk(state, first); err != nil {
		t.Fatalf("usage within the hold was rejected: %v", err)
	}
	excess := &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{Usage: &schemas.BifrostLLMUsage{
		PromptTokens: 11, CompletionTokens: 5, TotalTokens: 16,
	}}}
	if err := (DefaultAdapter{}).IngestChunk(state, excess); !errors.Is(err, ErrProviderUsageExceedsHold) {
		t.Fatalf("usage above the hold error = %v, want usage above authorized bounds", err)
	}
	if HasMeasuredUsage(state) {
		t.Fatalf("usage above the hold retained billable signals: %#v", state.Signals)
	}
}

func TestProviderUsageCannotExceedAuthorizedTokenMeters(t *testing.T) {
	holdMeters := []catalog.MeterEstimate{
		{MeterKey: billing.MeterCacheWrite1hInputTokens, Quantity: "10", HoldRequired: true},
		{MeterKey: billing.MeterInputTokens, Quantity: "3", HoldRequired: true},
		{MeterKey: billing.MeterReasoningTokens, Quantity: "4", HoldRequired: true},
		{MeterKey: "web_search_calls", Quantity: "1000", HoldRequired: true},
	}
	tests := []struct {
		name    string
		meters  []catalog.MeterEstimate
		usage   *schemas.BifrostLLMUsage
		wantErr bool
	}{
		{
			name:   "exact aggregate limits",
			meters: holdMeters,
			usage:  &schemas.BifrostLLMUsage{PromptTokens: 13, CompletionTokens: 4, TotalTokens: 17},
		},
		{
			name:    "input above limit",
			meters:  holdMeters,
			usage:   &schemas.BifrostLLMUsage{PromptTokens: 14, CompletionTokens: 4, TotalTokens: 18},
			wantErr: true,
		},
		{
			name:    "output above limit",
			meters:  holdMeters,
			usage:   &schemas.BifrostLLMUsage{PromptTokens: 13, CompletionTokens: 5, TotalTokens: 18},
			wantErr: true,
		},
		{
			name: "malformed authorized quantity",
			meters: []catalog.MeterEstimate{
				{MeterKey: billing.MeterInputTokens, Quantity: "invalid", HoldRequired: true},
				{MeterKey: billing.MeterOutputTokens, Quantity: "4", HoldRequired: true},
			},
			usage:   &schemas.BifrostLLMUsage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &State{Hold: HoldEstimate{Meters: tc.meters}}
			err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
				ChatResponse: &schemas.BifrostChatResponse{Usage: tc.usage},
			}, nil)
			if tc.wantErr {
				if !errors.Is(err, ErrProviderUsageExceedsHold) {
					t.Fatalf("IngestResponse error = %v, want usage above authorized bounds", err)
				}
				if HasMeasuredUsage(state) {
					t.Fatalf("excess provider usage was retained: %#v", state.Signals)
				}
				return
			}
			if err != nil {
				t.Fatalf("exact authorized usage was rejected: %v", err)
			}
		})
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
	validResponse := validUnaryChatProviderResponse()
	validResponse.Usage = usage
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
		ChatResponse: validResponse,
	}, nil); err != nil {
		t.Fatalf("valid cache-write partition was rejected: %v", err)
	}
	if signals, ok := state.Signals.(*StandardSignals); !ok || signals.CacheWrite != 100 {
		t.Fatalf("cache-write usage was not retained: %#v", state.Signals)
	}

	usage.PromptTokensDetails.CachedWriteTokens = 101
	rejectedState := &State{Resolution: resolution}
	rejectedResponse := validUnaryChatProviderResponse()
	rejectedResponse.Usage = usage
	if err := (DefaultAdapter{}).IngestResponse(rejectedState, &schemas.BifrostResponse{
		ChatResponse: rejectedResponse,
	}, nil); !errors.Is(err, ErrProviderUsageMalformed) {
		t.Fatalf("overlapping cache-write usage error = %v, want malformed provider usage", err)
	}
}

func TestProviderExecutionReportsStayWithinAuthorizedClass(t *testing.T) {
	tests := []struct {
		name          string
		provider      schemas.ModelProvider
		selectedTier  string
		selectedSpeed string
		selectedGeo   string
		currentTier   string
		currentSpeed  string
		reportedTier  string
		reportedSpeed string
		reportedGeo   string
		wantError     bool
	}{
		{name: "OpenAI Standard cannot become Priority", provider: schemas.OpenAI, reportedTier: "priority", wantError: true},
		{name: "OpenAI Fast can fall back to Standard", provider: schemas.OpenAI, selectedTier: "priority", reportedTier: "default"},
		{name: "OpenAI Flex remains Flex", provider: schemas.OpenAI, selectedTier: "flex", reportedTier: "flex"},
		{name: "Azure Priority can fall back to Standard", provider: schemas.Azure, selectedTier: "priority", reportedTier: "default"},
		{name: "Anthropic Fast cannot silently become Standard", provider: schemas.Anthropic, selectedSpeed: "fast", reportedSpeed: "standard", wantError: true},
		{name: "OpenAI Flex cannot become Priority", provider: schemas.OpenAI, selectedTier: "flex", reportedTier: "priority", wantError: true},
		{name: "Azure Standard cannot become Priority", provider: schemas.Azure, reportedTier: "priority", wantError: true},
		{name: "Anthropic Standard cannot become Fast", provider: schemas.Anthropic, reportedSpeed: "fast", wantError: true},
		{name: "unknown OpenAI tier is ignored", provider: schemas.OpenAI, reportedTier: "scale"},
		{name: "unknown OpenAI speed is ignored", provider: schemas.OpenAI, reportedSpeed: "fast"},
		{name: "unknown Chutes tier is ignored", provider: catalog.ProviderChutes, reportedTier: "priority"},
		{name: "equivalent OpenAI Priority labels", provider: schemas.OpenAI, selectedTier: "priority", currentTier: "priority", reportedTier: "fast"},
		{name: "OpenAI tier changes during response", provider: schemas.OpenAI, selectedTier: "priority", currentTier: "priority", reportedTier: "default", wantError: true},
		{name: "Anthropic speed changes during response", provider: schemas.Anthropic, selectedSpeed: "fast", currentSpeed: "fast", reportedSpeed: "standard", wantError: true},
		{name: "Anthropic Global geography", provider: schemas.Anthropic, selectedGeo: "global", reportedGeo: "global"},
		{name: "Anthropic US geography", provider: schemas.Anthropic, selectedGeo: "us", reportedGeo: "us"},
		{name: "Anthropic geography unavailable when none was selected", provider: schemas.Anthropic, reportedGeo: "not_available"},
		{name: "Anthropic cannot report a priced geography when none was selected", provider: schemas.Anthropic, reportedGeo: "global", wantError: true},
		{name: "Anthropic geography mismatch", provider: schemas.Anthropic, selectedGeo: "us", reportedGeo: "global", wantError: true},
		{name: "unknown Anthropic geography", provider: schemas.Anthropic, reportedGeo: "eu", wantError: true},
		{name: "unexpected OpenAI geography", provider: schemas.OpenAI, reportedGeo: "global", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &State{Resolution: &catalog.ResolvedRequest{
				Provider: tc.provider,
				Deployment: catalog.Deployment{Upstream: catalog.Upstream{
					ServiceTier:  tc.selectedTier,
					Speed:        tc.selectedSpeed,
					InferenceGeo: tc.selectedGeo,
				}},
			}}
			if tc.currentTier != "" {
				value := schemas.BifrostServiceTier(tc.currentTier)
				state.ActualServiceTier = &value
			}
			state.ActualSpeed = tc.currentSpeed

			var tier *schemas.BifrostServiceTier
			if tc.reportedTier != "" {
				value := schemas.BifrostServiceTier(tc.reportedTier)
				tier = &value
			}
			var speed *string
			if tc.reportedSpeed != "" {
				value := tc.reportedSpeed
				speed = &value
			}
			var inferenceGeo *string
			if tc.reportedGeo != "" {
				value := tc.reportedGeo
				inferenceGeo = &value
			}
			err := validateActualExecutionReport(state, tier, speed, inferenceGeo)
			if tc.wantError && !errors.Is(err, ErrProviderExecutionMismatch) {
				t.Fatalf("execution report error = %v, want mismatch", err)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("documented execution report was rejected: %v", err)
			}
		})
	}
}

func TestStreamingExecutionObservationCannotBeErased(t *testing.T) {
	state := &State{Resolution: &catalog.ResolvedRequest{
		Provider:   schemas.OpenAI,
		Deployment: catalog.Deployment{Upstream: catalog.Upstream{ServiceTier: "priority"}},
	}}
	priority := schemas.BifrostServiceTierPriority
	if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostChatResponse: &schemas.BifrostChatResponse{ServiceTier: &priority},
	}); err != nil {
		t.Fatalf("priority chunk was rejected: %v", err)
	}
	blank := schemas.BifrostServiceTier("  ")
	blankSpeed := " "
	if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostChatResponse: &schemas.BifrostChatResponse{ServiceTier: &blank, Speed: &blankSpeed},
	}); err != nil {
		t.Fatalf("blank execution metadata was rejected: %v", err)
	}
	if state.ActualServiceTier == nil || *state.ActualServiceTier != schemas.BifrostServiceTierPriority {
		t.Fatalf("blank terminal metadata erased Priority execution: %#v", state.ActualServiceTier)
	}
}

func TestOptionalExecutionMetadataCanBeOmitted(t *testing.T) {
	state := &State{Resolution: &catalog.ResolvedRequest{
		Model:    "claude-opus-4-8",
		Provider: schemas.Anthropic,
		Deployment: catalog.Deployment{Upstream: catalog.Upstream{
			ServiceTier:  "default",
			Speed:        "fast",
			InferenceGeo: "us",
		}},
	}}
	if err := ValidateStreamExecutionBeforeOutput(state); err != nil {
		t.Fatalf("missing optional stream metadata was rejected: %v", err)
	}
	if err := ValidateCompletedExecution(state); err != nil {
		t.Fatalf("missing optional terminal metadata was rejected: %v", err)
	}
}

func TestUnknownExecutionMetadataCannotRetargetPricing(t *testing.T) {
	state := &State{Resolution: &catalog.ResolvedRequest{Provider: schemas.OpenAI}}
	unknownTier := schemas.BifrostServiceTier("future-tier")
	unknownSpeed := "future-speed"
	if err := validateActualExecutionReport(state, &unknownTier, &unknownSpeed, nil); err != nil {
		t.Fatalf("unknown additive execution metadata was rejected: %v", err)
	}
	observeActualExecution(state, &unknownTier, &unknownSpeed)
	if state.ActualServiceTier != nil || state.ActualSpeed != "" {
		t.Fatalf("unknown metadata changed pricing selection: tier=%v speed=%q", state.ActualServiceTier, state.ActualSpeed)
	}
}

func TestValidUsageSurvivesLaterResponseShapeFailure(t *testing.T) {
	state := &State{Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}}
	err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
		ChatResponse: &schemas.BifrostChatResponse{Usage: &schemas.BifrostLLMUsage{
			PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5,
		}},
	}, nil)
	if !errors.Is(err, ErrProviderResponseMalformed) {
		t.Fatalf("IngestResponse error = %v, want malformed provider response", err)
	}
	if !HasMeasuredUsage(state) {
		t.Fatalf("valid provider usage was discarded after a later shape error: %#v", state.Signals)
	}
}

func TestProviderErrorBilledUsageIsValidatedAndSettledExactly(t *testing.T) {
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
		}},
	}
	if err := state.Adapter.IngestResponse(state, nil, providerErr); err != nil {
		t.Fatalf("IngestResponse returned error: %v", err)
	}
	if !HasMeasuredUsage(state) {
		t.Fatalf("provider billed usage was not retained: %#v", state.Signals)
	}
	if state.ActualSpeed != "" || state.ActualModel != "" {
		t.Fatalf("actual execution metadata was not retained: speed=%q model=%q", state.ActualSpeed, state.ActualModel)
	}
	if err := state.Adapter.FinalPrice(state); err != nil {
		t.Fatalf("FinalPrice returned error: %v", err)
	}
	if state.FinalCostUSDAtoms == billing.ZeroChargeUSDAtoms || len(state.FinalMeters) != 4 {
		t.Fatalf("partial provider usage was not settled exactly: cost=%s meters=%#v", state.FinalCostUSDAtoms, state.FinalMeters)
	}
}

func TestProviderUsageRejectsUnauthorizedFallbackModel(t *testing.T) {
	fallbackModel := "gpt-5.6-terra"
	state := &State{Resolution: &catalog.ResolvedRequest{
		Route:      catalog.RouteChat,
		Provider:   schemas.OpenAI,
		Deployment: catalog.Deployment{Upstream: catalog.Upstream{Model: "gpt-5.5-2026-04-23"}},
	}}
	response := validUnaryChatProviderResponse()
	response.Usage = &schemas.BifrostLLMUsage{
		PromptTokens:            1,
		CompletionTokens:        1,
		TotalTokens:             2,
		ServerSideFallbackModel: &fallbackModel,
	}
	err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{ChatResponse: response}, nil)
	if !errors.Is(err, ErrProviderExecutionMismatch) {
		t.Fatalf("fallback-model usage error = %v, want execution mismatch", err)
	}
	if HasMeasuredUsage(state) || state.ActualModel != "" {
		t.Fatalf("unauthorized fallback metadata was retained: signals=%#v model=%q", state.Signals, state.ActualModel)
	}
}

func TestProviderResponseRejectsModelSubstitutionAndRoutingFallback(t *testing.T) {
	expectedModel := "gpt-5.5-2026-04-23"
	fallbackModel := "gpt-5-nano-2025-08-07"
	validUsage := &schemas.BifrostLLMUsage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}
	for name, response := range map[string]*schemas.BifrostChatResponse{
		"top-level model substitution": {
			ID:    "chatcmpl_model_guard",
			Model: fallbackModel,
			Usage: validUsage,
		},
		"routing fallback metadata": {
			ID:    "chatcmpl_model_guard",
			Model: expectedModel,
			Usage: validUsage,
			ExtraFields: schemas.BifrostResponseExtraFields{RoutingInfo: schemas.RoutingInfo{
				ServerSideFallbackModel: &fallbackModel,
			}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			validShape := validUnaryChatProviderResponse()
			response.Object = validShape.Object
			response.Choices = validShape.Choices
			state := &State{Resolution: &catalog.ResolvedRequest{
				Route:      catalog.RouteChat,
				Model:      expectedModel,
				Provider:   schemas.OpenAI,
				Deployment: catalog.Deployment{Upstream: catalog.Upstream{Model: expectedModel}},
			}}
			err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{ChatResponse: response}, nil)
			if !errors.Is(err, ErrProviderExecutionMismatch) {
				t.Fatalf("model substitution error = %v, want execution mismatch", err)
			}
			if !HasMeasuredUsage(state) || state.ActualModel != "" {
				t.Fatalf("valid usage was not retained independently of unauthorized model metadata: signals=%#v model=%q", state.Signals, state.ActualModel)
			}
		})
	}
}

func TestProviderModelRevisionCompatibility(t *testing.T) {
	for _, test := range []struct {
		expected string
		actual   string
		want     bool
	}{
		{expected: "claude-sonnet-4-6", actual: "claude-sonnet-4-6-20251112", want: true},
		{expected: "gpt-5.5", actual: "gpt-5.5-2026-04-23", want: true},
		{expected: "gpt-5.5", actual: "gpt-5.5", want: true},
		{expected: "gpt-5.5", actual: "gpt-5.5-mini"},
		{expected: "gpt-5.5", actual: "gpt-5.5-2026-04-23-extra"},
		{expected: "gpt-5.5", actual: "gpt-5-nano-2025-08-07"},
	} {
		if got := providerModelMatchesSelected(test.expected, test.actual); got != test.want {
			t.Fatalf("providerModelMatchesSelected(%q, %q) = %t, want %t", test.expected, test.actual, got, test.want)
		}
	}
}

func TestProviderStreamModelCannotChangeAfterFirstChunk(t *testing.T) {
	expectedModel := "gpt-5.5-2026-04-23"
	state := &State{Resolution: &catalog.ResolvedRequest{
		Route:      catalog.RouteChat,
		Model:      expectedModel,
		Provider:   schemas.OpenAI,
		Deployment: catalog.Deployment{Upstream: catalog.Upstream{Model: expectedModel}},
	}}
	if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostChatResponse: func() *schemas.BifrostChatResponse {
			response := validChatProviderChunk("chatcmpl_model_guard", false)
			response.Model = expectedModel
			return response
		}(),
	}); err != nil {
		t.Fatalf("selected model was rejected: %v", err)
	}
	if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostChatResponse: func() *schemas.BifrostChatResponse {
			response := validChatProviderChunk("chatcmpl_model_guard", true)
			response.Model = "gpt-5-nano-2025-08-07"
			return response
		}(),
	}); !errors.Is(err, ErrProviderExecutionMismatch) {
		t.Fatalf("changed streamed model error = %v, want execution mismatch", err)
	}
	if state.ActualModel != expectedModel {
		t.Fatalf("changed streamed model replaced selected model: %q", state.ActualModel)
	}
}

func TestProviderProtocolErrorIsInsuredAndStable(t *testing.T) {
	for _, source := range []error{ErrProviderUsageMissing, ErrProviderUsageMalformed, ErrProviderUsageExceedsHold, ErrProviderExecutionMismatch, ErrProviderResponseMalformed, ErrProviderResponseTooLarge} {
		bifrostErr := UpstreamProtocolError(source)
		if bifrostErr.StatusCode == nil || *bifrostErr.StatusCode != 502 || bifrostErr.Error == nil || bifrostErr.Error.Code == nil {
			t.Fatalf("invalid protocol error: %#v", bifrostErr)
		}
		if !billing.ProviderErrorIsInsured(bifrostErr, false) {
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
