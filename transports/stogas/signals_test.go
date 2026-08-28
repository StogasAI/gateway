package stogas

import (
	"errors"
	"strconv"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestDefaultAdapterSalvagesMalformedProviderUsage(t *testing.T) {
	negativeSearches := -1
	oneImageToken := 1
	maximumInt := int(^uint(0) >> 1)
	tests := map[string]struct {
		usage          *schemas.BifrostLLMUsage
		wantPrompt     int
		wantCompletion int
		wantReasoning  int
		wantMeasured   bool
	}{
		"negative prompt":         {usage: &schemas.BifrostLLMUsage{PromptTokens: -1}},
		"negative completion":     {usage: &schemas.BifrostLLMUsage{CompletionTokens: -1}},
		"negative total":          {usage: &schemas.BifrostLLMUsage{TotalTokens: -1}},
		"negative reasoning":      {usage: &schemas.BifrostLLMUsage{ReasoningTokens: -1}},
		"total without partition": {usage: &schemas.BifrostLLMUsage{TotalTokens: 8}},
		"negative cache split": {
			usage: &schemas.BifrostLLMUsage{PromptTokens: 3, PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{CachedWriteTokens5m: -1},
			}},
			wantPrompt: 3, wantMeasured: true,
		},
		"negative search count": {
			usage: &schemas.BifrostLLMUsage{
				PromptTokens:            1,
				CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{NumSearchQueries: &negativeSearches},
			},
			wantPrompt: 1, wantMeasured: true,
		},
		"audio input on text request": {
			usage:      &schemas.BifrostLLMUsage{PromptTokens: 1, PromptTokensDetails: &schemas.ChatPromptTokensDetails{AudioTokens: 1}},
			wantPrompt: 1, wantMeasured: true,
		},
		"image output on text request": {
			usage:          &schemas.BifrostLLMUsage{CompletionTokens: 1, CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{ImageTokens: &oneImageToken}},
			wantCompletion: 1, wantMeasured: true,
		},
		"overflowed cache partition": {
			usage: &schemas.BifrostLLMUsage{PromptTokens: maximumInt, PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedReadTokens:  maximumInt,
				CachedWriteTokens: 1,
			}},
			wantPrompt: maximumInt, wantMeasured: true,
		},
		"overflowed cache split": {
			usage: &schemas.BifrostLLMUsage{PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: maximumInt,
					CachedWriteTokens1h: 1,
				},
			}},
			wantPrompt: maximumInt, wantMeasured: true,
		},
		"overflowed completion details": {
			usage: &schemas.BifrostLLMUsage{CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
				TextTokens:      maximumInt,
				ReasoningTokens: 1,
			}},
			wantCompletion: maximumInt, wantReasoning: 1, wantMeasured: true,
		},
		"overflowed aggregate total": {
			usage:      &schemas.BifrostLLMUsage{PromptTokens: maximumInt, CompletionTokens: 1, TotalTokens: maximumInt},
			wantPrompt: maximumInt, wantCompletion: 1, wantMeasured: true,
		},
		"overflowed aggregate without total": {
			usage:      &schemas.BifrostLLMUsage{PromptTokens: maximumInt, CompletionTokens: 1},
			wantPrompt: maximumInt, wantCompletion: 1, wantMeasured: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			state := &State{}
			if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
				ChatResponse: &schemas.BifrostChatResponse{Usage: tc.usage},
			}, nil); err != nil {
				t.Fatalf("IngestResponse rejected provider usage: %v", err)
			}
			if HasMeasuredUsage(state) != tc.wantMeasured {
				t.Fatalf("measured usage = %t, want %t: %#v", HasMeasuredUsage(state), tc.wantMeasured, state.Signals)
			}
			if !tc.wantMeasured {
				return
			}
			signals, ok := state.Signals.(*StandardSignals)
			if !ok || signals.Prompt != tc.wantPrompt || signals.Completion != tc.wantCompletion || signals.Reasoning != tc.wantReasoning {
				t.Fatalf("salvaged usage = %#v, want prompt=%d completion=%d reasoning=%d", state.Signals, tc.wantPrompt, tc.wantCompletion, tc.wantReasoning)
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

func TestDefaultAdapterSalvagesInconsistentProviderUsage(t *testing.T) {
	tests := map[string]struct {
		usage                           *schemas.BifrostLLMUsage
		prompt, completion, reasoning   int
		cached, write, write5m, write1h int
	}{
		"aggregate total differs": {
			usage:  &schemas.BifrostLLMUsage{PromptTokens: 3, CompletionTokens: 5, TotalTokens: 9},
			prompt: 3, completion: 5,
		},
		"detail partitions differ from total": {
			usage:  &schemas.BifrostLLMUsage{TotalTokens: 8, PromptTokensDetails: &schemas.ChatPromptTokensDetails{TextTokens: 3}, CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{TextTokens: 4}},
			prompt: 3, completion: 4,
		},
		"known partition exceeds total": {
			usage: &schemas.BifrostLLMUsage{PromptTokens: 9, TotalTokens: 8}, prompt: 9,
		},
		"reasoning without completion": {
			usage: &schemas.BifrostLLMUsage{PromptTokens: 1, TotalTokens: 1, ReasoningTokens: 1}, prompt: 1,
		},
		"cached input exceeds prompt": {
			usage: &schemas.BifrostLLMUsage{PromptTokens: 3, PromptTokensDetails: &schemas.ChatPromptTokensDetails{CachedReadTokens: 4}}, prompt: 3,
		},
		"cache write exceeds uncached prompt": {
			usage: &schemas.BifrostLLMUsage{PromptTokens: 3, PromptTokensDetails: &schemas.ChatPromptTokensDetails{CachedReadTokens: 1, CachedWriteTokens: 3}}, prompt: 3,
		},
		"reasoning exceeds completion": {
			usage: &schemas.BifrostLLMUsage{CompletionTokens: 3, CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{ReasoningTokens: 4}}, completion: 3,
		},
		"cache write aggregate differs from TTL split": {
			usage: &schemas.BifrostLLMUsage{PromptTokens: 3, PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedWriteTokens: 3,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 1,
					CachedWriteTokens1h: 1,
				},
			}},
			prompt: 3, write: 1, write5m: 1, write1h: 1,
		},
		"cache write TTL split exceeds aggregate": {
			usage: &schemas.BifrostLLMUsage{PromptTokens: 3, PromptTokensDetails: &schemas.ChatPromptTokensDetails{
				CachedWriteTokens: 2,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 2,
					CachedWriteTokens1h: 1,
				},
			}},
			prompt: 3, write: 2,
		},
		"top-level reasoning differs from detail": {
			usage: &schemas.BifrostLLMUsage{CompletionTokens: 3, ReasoningTokens: 1, CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
				ReasoningTokens: 2,
			}},
			completion: 3, reasoning: 2,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			state := &State{}
			if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
				ChatResponse: &schemas.BifrostChatResponse{Usage: tc.usage},
			}, nil); err != nil {
				t.Fatalf("IngestResponse rejected provider usage: %v", err)
			}
			signals, ok := state.Signals.(*StandardSignals)
			if !ok || signals.Prompt != tc.prompt || signals.Completion != tc.completion || signals.Reasoning != tc.reasoning ||
				signals.Cached != tc.cached || signals.CacheWrite != tc.write || signals.CacheWrite5m != tc.write5m || signals.CacheWrite1h != tc.write1h {
				t.Fatalf("salvaged usage = %#v, want %+v", state.Signals, tc)
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

func TestDefaultAdapterKeepsLargestUsableCumulativeStreamUsage(t *testing.T) {
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
			if err := (DefaultAdapter{}).IngestChunk(state, &schemas.BifrostStreamChunk{
				BifrostChatResponse: &schemas.BifrostChatResponse{Usage: usage},
			}); err != nil {
				t.Fatalf("regressing provider usage was rejected: %v", err)
			}
			signals, ok := state.Signals.(*StandardSignals)
			if !ok || signals.Prompt != 10 || signals.Completion != 5 || signals.Cached != 4 {
				t.Fatalf("largest cumulative usage was not retained: %#v", state.Signals)
			}
		})
	}
}

func TestUsageAboveHoldIsCappedWithoutDiscardingEarlierUsage(t *testing.T) {
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
	if err := (DefaultAdapter{}).IngestChunk(state, excess); err != nil {
		t.Fatalf("usage above the hold was rejected: %v", err)
	}
	if signals, ok := state.Signals.(*StandardSignals); !ok || signals.Prompt != 10 || signals.Completion != 5 {
		t.Fatalf("usage was not capped to the authorized dimensions: %#v", state.Signals)
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
		name           string
		meters         []catalog.MeterEstimate
		usage          *schemas.BifrostLLMUsage
		wantPrompt     int
		wantCompletion int
	}{
		{
			name:       "exact aggregate limits",
			meters:     holdMeters,
			usage:      &schemas.BifrostLLMUsage{PromptTokens: 13, CompletionTokens: 4, TotalTokens: 17},
			wantPrompt: 13, wantCompletion: 4,
		},
		{
			name:       "input above limit",
			meters:     holdMeters,
			usage:      &schemas.BifrostLLMUsage{PromptTokens: 14, CompletionTokens: 4, TotalTokens: 18},
			wantPrompt: 13, wantCompletion: 4,
		},
		{
			name:       "output above limit",
			meters:     holdMeters,
			usage:      &schemas.BifrostLLMUsage{PromptTokens: 13, CompletionTokens: 5, TotalTokens: 18},
			wantPrompt: 13, wantCompletion: 4,
		},
		{
			name: "malformed authorized quantity",
			meters: []catalog.MeterEstimate{
				{MeterKey: billing.MeterInputTokens, Quantity: "invalid", HoldRequired: true},
				{MeterKey: billing.MeterOutputTokens, Quantity: "4", HoldRequired: true},
			},
			usage:      &schemas.BifrostLLMUsage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
			wantPrompt: 0, wantCompletion: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &State{Hold: HoldEstimate{Meters: tc.meters}}
			err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
				ChatResponse: &schemas.BifrostChatResponse{Usage: tc.usage},
			}, nil)
			if err != nil {
				t.Fatalf("provider usage was rejected: %v", err)
			}
			signals, ok := state.Signals.(*StandardSignals)
			if !ok || signals.Prompt != tc.wantPrompt || signals.Completion != tc.wantCompletion {
				t.Fatalf("authorized usage = %#v, want prompt=%d completion=%d", state.Signals, tc.wantPrompt, tc.wantCompletion)
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
	}, nil); err != nil {
		t.Fatalf("overlapping cache-write usage was rejected: %v", err)
	}
	if signals, ok := rejectedState.Signals.(*StandardSignals); !ok || signals.Prompt != 100 || signals.CacheWrite != 0 {
		t.Fatalf("contradictory cache details were not ignored: %#v", rejectedState.Signals)
	}
}

func TestAnthropicWireCacheWriteTTLReconciliation(t *testing.T) {
	pricing := catalog.Pricing{
		billing.MeterInputTokens:             {billing.RatePerMillionTokens: "1000000"},
		billing.MeterCacheWrite5mInputTokens: {billing.RatePerMillionTokens: "1250000"},
		billing.MeterCacheWrite1hInputTokens: {billing.RatePerMillionTokens: "2000000"},
	}
	providers := []struct {
		name        string
		provider    schemas.ModelProvider
		modelFormat string
	}{
		{name: "direct Anthropic", provider: schemas.Anthropic},
		{name: "Azure Claude", provider: schemas.Azure, modelFormat: "Anthropic"},
	}
	cases := []struct {
		name         string
		details      *schemas.ChatCachedWriteTokenDetails
		want5m       int
		want1h       int
		wantCost     string
		wantOverhead string
	}{
		{name: "no TTL detail", want5m: 40, wantCost: "110", wantOverhead: "10"},
		{
			name:         "partial TTL detail",
			details:      &schemas.ChatCachedWriteTokenDetails{CachedWriteTokens5m: 10, CachedWriteTokens1h: 20},
			want5m:       20,
			want1h:       20,
			wantCost:     "125",
			wantOverhead: "25",
		},
		{
			name:         "TTL detail exceeds aggregate",
			details:      &schemas.ChatCachedWriteTokenDetails{CachedWriteTokens5m: 30, CachedWriteTokens1h: 20},
			want5m:       40,
			wantCost:     "110",
			wantOverhead: "10",
		},
	}
	for _, provider := range providers {
		for _, tc := range cases {
			t.Run(provider.name+"/"+tc.name, func(t *testing.T) {
				state := &State{Resolution: &catalog.ResolvedRequest{
					Provider: provider.provider,
					Deployment: catalog.Deployment{
						Pricing:  pricing,
						Upstream: catalog.Upstream{ModelFormat: provider.modelFormat},
					},
				}}
				usage := &schemas.BifrostLLMUsage{
					PromptTokens: 100,
					PromptTokensDetails: &schemas.ChatPromptTokensDetails{
						CachedWriteTokens:       40,
						CachedWriteTokenDetails: tc.details,
					},
				}
				response := validUnaryChatProviderResponse()
				response.Usage = usage
				adapter := AdapterFor(provider.provider)
				if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ChatResponse: response}, nil); err != nil {
					t.Fatalf("IngestResponse returned error: %v", err)
				}
				signals, ok := state.Signals.(*StandardSignals)
				if !ok || signals.CacheWrite != 0 || signals.CacheWrite5m != tc.want5m || signals.CacheWrite1h != tc.want1h {
					t.Fatalf("Anthropic-wire cache usage = %#v", state.Signals)
				}
				if err := adapter.CalculateUpstreamCost(state); err != nil {
					t.Fatalf("CalculateUpstreamCost returned error: %v", err)
				}
				want5mMeter := ""
				if tc.want5m > 0 {
					want5mMeter = strconv.Itoa(tc.want5m)
				}
				want1hMeter := ""
				if tc.want1h > 0 {
					want1hMeter = strconv.Itoa(tc.want1h)
				}
				if meterQuantity(findMeterEstimate(state.FinalMeters, billing.MeterInputTokens)) != "60" ||
					meterQuantity(findMeterEstimate(state.FinalMeters, billing.MeterCacheWrite5mInputTokens)) != want5mMeter ||
					meterQuantity(findMeterEstimate(state.FinalMeters, billing.MeterCacheWrite1hInputTokens)) != want1hMeter ||
					state.UpstreamCostUSDAtoms != tc.wantCost {
					t.Fatalf("Anthropic-wire cache billing = cost %s meters %#v", state.UpstreamCostUSDAtoms, state.FinalMeters)
				}
				overhead, err := cacheWriteOverheadUSDAtoms(state)
				if err != nil || overhead == nil || *overhead != tc.wantOverhead {
					t.Fatalf("Anthropic-wire cache overhead = %#v, %v; want %s", overhead, err, tc.wantOverhead)
				}
			})
		}
	}
}

func TestCumulativeCacheSnapshotsDoNotDoubleCountReclassification(t *testing.T) {
	tests := []struct {
		name        string
		provider    schemas.ModelProvider
		modelFormat string
		first       *schemas.ChatPromptTokensDetails
		second      *schemas.ChatPromptTokensDetails
		wantRead    int
		wantGeneric int
		want5m      int
		want1h      int
	}{
		{
			name:     "generic write becomes TTL split",
			provider: schemas.OpenAI,
			first:    &schemas.ChatPromptTokensDetails{CachedWriteTokens: 10},
			second: &schemas.ChatPromptTokensDetails{
				CachedWriteTokens: 10,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 4,
					CachedWriteTokens1h: 6,
				},
			},
			want5m: 4,
			want1h: 6,
		},
		{
			name:     "less specific snapshot does not erase TTL split",
			provider: schemas.OpenAI,
			first: &schemas.ChatPromptTokensDetails{
				CachedWriteTokens: 10,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 4,
					CachedWriteTokens1h: 6,
				},
			},
			second: &schemas.ChatPromptTokensDetails{CachedWriteTokens: 10},
			want5m: 4,
			want1h: 6,
		},
		{
			name:        "Anthropic unspecified write becomes authoritative TTL split",
			provider:    schemas.Azure,
			modelFormat: "Anthropic",
			first:       &schemas.ChatPromptTokensDetails{CachedWriteTokens: 10},
			second: &schemas.ChatPromptTokensDetails{
				CachedWriteTokens: 10,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 4,
					CachedWriteTokens1h: 6,
				},
			},
			want5m: 4,
			want1h: 6,
		},
		{
			name:     "larger later write replaces the complete partition",
			provider: schemas.OpenAI,
			first: &schemas.ChatPromptTokensDetails{
				CachedWriteTokens: 10,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 4,
					CachedWriteTokens1h: 6,
				},
			},
			second: &schemas.ChatPromptTokensDetails{
				CachedWriteTokens: 12,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 5,
					CachedWriteTokens1h: 7,
				},
			},
			want5m: 5,
			want1h: 7,
		},
		{
			name:     "cache read corrected to TTL cache write",
			provider: schemas.OpenAI,
			first:    &schemas.ChatPromptTokensDetails{CachedReadTokens: 10},
			second: &schemas.ChatPromptTokensDetails{
				CachedWriteTokens: 10,
				CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{
					CachedWriteTokens5m: 10,
				},
			},
			want5m: 10,
		},
		{
			name:     "cache write corrected to cache read",
			provider: schemas.OpenAI,
			first:    &schemas.ChatPromptTokensDetails{CachedWriteTokens: 10},
			second:   &schemas.ChatPromptTokensDetails{CachedReadTokens: 10},
			wantRead: 10,
		},
		{
			name:        "cache read corrected to generic cache write",
			provider:    schemas.OpenAI,
			first:       &schemas.ChatPromptTokensDetails{CachedReadTokens: 10},
			second:      &schemas.ChatPromptTokensDetails{CachedWriteTokens: 10},
			wantGeneric: 10,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := &State{Resolution: &catalog.ResolvedRequest{
				Provider: test.provider,
				Deployment: catalog.Deployment{Upstream: catalog.Upstream{
					ModelFormat: test.modelFormat,
				}},
			}}
			setSignalsFromUsage(state, &schemas.BifrostLLMUsage{
				PromptTokens:        100,
				PromptTokensDetails: test.first,
			})
			setSignalsFromUsage(state, &schemas.BifrostLLMUsage{
				PromptTokens:        100,
				PromptTokensDetails: test.second,
			})
			signals, ok := state.Signals.(*StandardSignals)
			if !ok || signals.Cached != test.wantRead || signals.CacheWrite != test.wantGeneric ||
				signals.CacheWrite5m != test.want5m || signals.CacheWrite1h != test.want1h ||
				cachePartitionTotal(signals) != test.wantRead+test.wantGeneric+test.want5m+test.want1h {
				t.Fatalf("merged cache partition = %#v", state.Signals)
			}
		})
	}
}

func TestCacheUsageNormalizationExhaustsSupportedProviderStateSpace(t *testing.T) {
	providers := []struct {
		provider          schemas.ModelProvider
		modelFormat       string
		unspecifiedIsFive bool
	}{
		{provider: schemas.OpenAI},
		{provider: schemas.Anthropic, unspecifiedIsFive: true},
		{provider: schemas.Azure, modelFormat: "OpenAI"},
		{provider: schemas.Azure, modelFormat: "  aNtHrOpIc  ", unspecifiedIsFive: true},
		{provider: catalog.ProviderChutes},
	}
	values := []int{-1, 0, 1, 2}
	prompts := []int{-1, 0, 1, 2, 3, 4}
	cases := 0

	for _, provider := range providers {
		for _, withTTLDetails := range []bool{false, true} {
			for _, prompt := range prompts {
				for _, read := range values {
					for _, write := range values {
						for _, write5m := range values {
							for _, write1h := range values {
								details := &schemas.ChatPromptTokensDetails{
									CachedReadTokens:  read,
									CachedWriteTokens: write,
								}
								if withTTLDetails {
									details.CachedWriteTokenDetails = &schemas.ChatCachedWriteTokenDetails{
										CachedWriteTokens5m: write5m,
										CachedWriteTokens1h: write1h,
									}
								}
								state := &State{Resolution: &catalog.ResolvedRequest{
									Provider: provider.provider,
									Deployment: catalog.Deployment{Upstream: catalog.Upstream{
										ModelFormat: provider.modelFormat,
									}},
								}}
								setSignalsFromUsage(state, &schemas.BifrostLLMUsage{
									PromptTokens:        prompt,
									PromptTokensDetails: details,
								})

								want := referenceCacheSignals(prompt, read, write, write5m, write1h, withTTLDetails, provider.unspecifiedIsFive)
								got, _ := state.Signals.(*StandardSignals)
								if want == nil {
									if got != nil {
										t.Fatalf("provider=%s format=%q prompt=%d read=%d write=%d 5m=%d 1h=%d details=%t: got %#v, want nil", provider.provider, provider.modelFormat, prompt, read, write, write5m, write1h, withTTLDetails, got)
									}
								} else if got == nil || got.Prompt != want.Prompt || got.Cached != want.Cached || got.CacheWrite != want.CacheWrite || got.CacheWrite5m != want.CacheWrite5m || got.CacheWrite1h != want.CacheWrite1h {
									t.Fatalf("provider=%s format=%q prompt=%d read=%d write=%d 5m=%d 1h=%d details=%t: got %#v, want %#v", provider.provider, provider.modelFormat, prompt, read, write, write5m, write1h, withTTLDetails, got, want)
								}
								cases++
							}
						}
					}
				}
			}
		}
	}
	if cases != len(providers)*2*len(prompts)*len(values)*len(values)*len(values)*len(values) {
		t.Fatalf("executed %d cache cases", cases)
	}
}

func TestCachePartitionMergeExhaustsAllSmallCumulativeSequences(t *testing.T) {
	partitions := make([]StandardSignals, 0)
	for read := 0; read <= 3; read++ {
		for generic := 0; generic <= 3; generic++ {
			for write5m := 0; write5m <= 3; write5m++ {
				for write1h := 0; write1h <= 3; write1h++ {
					if read+generic+write5m+write1h <= 3 {
						partitions = append(partitions, StandardSignals{
							Cached:       read,
							CacheWrite:   generic,
							CacheWrite5m: write5m,
							CacheWrite1h: write1h,
						})
					}
				}
			}
		}
	}

	for firstIndex := range partitions {
		for secondIndex := range partitions {
			for thirdIndex := range partitions {
				got := partitions[firstIndex]
				mergeCachePartition(&got, &partitions[secondIndex])
				mergeCachePartition(&got, &partitions[thirdIndex])

				want := referenceCachePartitionWinner(
					partitions[firstIndex],
					partitions[secondIndex],
					partitions[thirdIndex],
				)
				if !sameCachePartition(got, want) {
					t.Fatalf("sequence %d,%d,%d merged to %#v, want %#v", firstIndex, secondIndex, thirdIndex, got, want)
				}
				if cachePartitionTotal(&got) > 3 {
					t.Fatalf("sequence %d,%d,%d fabricated cache tokens: %#v", firstIndex, secondIndex, thirdIndex, got)
				}
			}
		}
	}
}

func FuzzProviderUsageNormalization(f *testing.F) {
	seeds := []struct {
		prompt, completion, total, reasoning int
		read, write, write5m, write1h        int
		provider                             uint8
		withTTL, withHold                    bool
		hold                                 int
	}{
		{prompt: 100, completion: 10, total: 110, read: 20, write: 30, write5m: 10, write1h: 5, provider: 1, withTTL: true},
		{prompt: 3, read: 4, write: 1, provider: 0, withTTL: true},
		{prompt: -1, completion: -1, total: -1, reasoning: -1, read: -1, write: -1, write5m: -1, write1h: -1, provider: 3, withTTL: true},
		{prompt: int(^uint(0) >> 1), read: int(^uint(0) >> 1), write: 1, provider: 4, withTTL: true},
		{prompt: 100, completion: 20, reasoning: 30, provider: 2, withHold: true, hold: 10},
	}
	for _, seed := range seeds {
		f.Add(seed.prompt, seed.completion, seed.total, seed.reasoning, seed.read, seed.write, seed.write5m, seed.write1h, seed.provider, seed.withTTL, seed.withHold, seed.hold)
	}

	f.Fuzz(func(t *testing.T, prompt int, completion int, total int, reasoning int, read int, write int, write5m int, write1h int, providerIndex uint8, withTTL bool, withHold bool, hold int) {
		providers := []struct {
			provider    schemas.ModelProvider
			modelFormat string
		}{
			{provider: schemas.OpenAI},
			{provider: schemas.Anthropic},
			{provider: schemas.Azure, modelFormat: "OpenAI"},
			{provider: schemas.Azure, modelFormat: "Anthropic"},
			{provider: catalog.ProviderChutes},
		}
		provider := providers[int(providerIndex)%len(providers)]
		state := &State{Resolution: &catalog.ResolvedRequest{
			Provider: provider.provider,
			Deployment: catalog.Deployment{Upstream: catalog.Upstream{
				ModelFormat: provider.modelFormat,
			}},
		}}
		if withHold {
			state.Hold.Meters = []catalog.MeterEstimate{{
				HoldRequired: true,
				MeterKey:     billing.MeterInputTokens,
				Quantity:     strconv.Itoa(hold),
			}, {
				HoldRequired: true,
				MeterKey:     billing.MeterOutputTokens,
				Quantity:     strconv.Itoa(hold),
			}}
		}
		details := &schemas.ChatPromptTokensDetails{
			CachedReadTokens:  read,
			CachedWriteTokens: write,
		}
		if withTTL {
			details.CachedWriteTokenDetails = &schemas.ChatCachedWriteTokenDetails{
				CachedWriteTokens5m: write5m,
				CachedWriteTokens1h: write1h,
			}
		}
		usage := &schemas.BifrostLLMUsage{
			PromptTokens:        prompt,
			CompletionTokens:    completion,
			TotalTokens:         total,
			ReasoningTokens:     reasoning,
			PromptTokensDetails: details,
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{
				ReasoningTokens: reasoning,
			},
		}
		setSignalsFromUsage(state, usage)
		got, _ := state.Signals.(*StandardSignals)
		if got == nil {
			return
		}
		if got.Prompt < 0 || got.Completion < 0 || got.Reasoning < 0 || got.Cached < 0 || got.CacheWrite < 0 || got.CacheWrite5m < 0 || got.CacheWrite1h < 0 {
			t.Fatalf("negative normalized usage: %#v", got)
		}
		cacheTotal, ok := addTokenCounts(got.Cached, got.CacheWrite, got.CacheWrite5m, got.CacheWrite1h)
		if !ok || cacheTotal > got.Prompt {
			t.Fatalf("cache partition exceeds prompt: %#v", got)
		}
		if got.Reasoning > got.Completion {
			t.Fatalf("reasoning partition exceeds completion: %#v", got)
		}
		if provider.provider == schemas.Anthropic || provider.modelFormat == "Anthropic" {
			if got.CacheWrite != 0 {
				t.Fatalf("Anthropic-wire generic cache write was not normalized: %#v", got)
			}
		}
		before := *got
		setSignalsFromUsage(state, usage)
		after, _ := state.Signals.(*StandardSignals)
		if after == nil || before.Prompt != after.Prompt || before.Completion != after.Completion || before.Reasoning != after.Reasoning || !sameCachePartition(before, *after) {
			t.Fatalf("replaying cumulative usage changed normalization: before=%#v after=%#v", before, after)
		}
	})
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
	if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
		t.Fatalf("CalculateUpstreamCost returned error: %v", err)
	}
	if state.UpstreamCostUSDAtoms == billing.ZeroChargeUSDAtoms || len(state.FinalMeters) != 4 {
		t.Fatalf("partial provider usage was not settled exactly: cost=%s meters=%#v", state.UpstreamCostUSDAtoms, state.FinalMeters)
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
	if !HasMeasuredUsage(state) || state.ActualModel != "" {
		t.Fatalf("usable usage was not retained independently of fallback metadata: signals=%#v model=%q", state.Signals, state.ActualModel)
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

func TestProviderProtocolErrorIsStable(t *testing.T) {
	for _, source := range []error{ErrProviderExecutionMismatch, ErrProviderResponseMalformed, ErrProviderResponseTooLarge} {
		bifrostErr := UpstreamProtocolError(source)
		if bifrostErr.StatusCode == nil || *bifrostErr.StatusCode != 502 || bifrostErr.Error == nil || bifrostErr.Error.Code == nil {
			t.Fatalf("invalid protocol error: %#v", bifrostErr)
		}
	}
}

func TestAllZeroUsageProducesNoChargeableSignals(t *testing.T) {
	state := &State{}
	if err := (DefaultAdapter{}).IngestResponse(state, &schemas.BifrostResponse{
		ChatResponse: &schemas.BifrostChatResponse{Usage: &schemas.BifrostLLMUsage{}},
	}, nil); err != nil {
		t.Fatalf("empty provider usage was rejected: %v", err)
	}
	if HasMeasuredUsage(state) {
		t.Fatalf("all-zero usage was classified as measured: %#v", state.Signals)
	}
}

func referenceCacheSignals(prompt int, read int, write int, write5m int, write1h int, withTTLDetails bool, unspecifiedIsFive bool) *StandardSignals {
	read = testNonnegative(read)
	write = testNonnegative(write)
	if withTTLDetails {
		write5m = testNonnegative(write5m)
		write1h = testNonnegative(write1h)
	} else {
		write5m = 0
		write1h = 0
	}
	reportedWrite := write
	splitTotal := write5m + write1h
	fallbackWrite := reportedWrite
	if splitTotal > fallbackWrite {
		fallbackWrite = splitTotal
	}
	wantPrompt := testNonnegative(prompt)
	if wantPrompt == 0 {
		wantPrompt = read + fallbackWrite
	}

	genericWrite := 0
	if withTTLDetails {
		switch {
		case reportedWrite > 0 && splitTotal > 0 && reportedWrite != splitTotal && splitTotal < reportedWrite:
			genericWrite = reportedWrite - splitTotal
		case reportedWrite > 0 && splitTotal > reportedWrite:
			genericWrite = reportedWrite
			write5m = 0
			write1h = 0
		case splitTotal == 0:
			genericWrite = reportedWrite
		}
	} else {
		genericWrite = reportedWrite
	}
	if read+genericWrite+write5m+write1h > wantPrompt {
		read = 0
		genericWrite = 0
		write5m = 0
		write1h = 0
	}
	if unspecifiedIsFive {
		write5m += genericWrite
		genericWrite = 0
	}
	want := &StandardSignals{
		Prompt:       wantPrompt,
		Cached:       read,
		CacheWrite:   genericWrite,
		CacheWrite5m: write5m,
		CacheWrite1h: write1h,
	}
	if want.Prompt == 0 && cachePartitionTotal(want) == 0 {
		return nil
	}
	return want
}

func referenceCachePartitionWinner(partitions ...StandardSignals) StandardSignals {
	winner := partitions[0]
	winnerTotal := winner.Cached + winner.CacheWrite + winner.CacheWrite5m + winner.CacheWrite1h
	winnerSpecificity := winner.CacheWrite5m + winner.CacheWrite1h
	for _, candidate := range partitions[1:] {
		candidateTotal := candidate.Cached + candidate.CacheWrite + candidate.CacheWrite5m + candidate.CacheWrite1h
		candidateSpecificity := candidate.CacheWrite5m + candidate.CacheWrite1h
		if candidateTotal > winnerTotal || (candidateTotal == winnerTotal && candidateSpecificity >= winnerSpecificity) {
			winner = candidate
			winnerTotal = candidateTotal
			winnerSpecificity = candidateSpecificity
		}
	}
	return winner
}

func sameCachePartition(left StandardSignals, right StandardSignals) bool {
	return left.Cached == right.Cached &&
		left.CacheWrite == right.CacheWrite &&
		left.CacheWrite5m == right.CacheWrite5m &&
		left.CacheWrite1h == right.CacheWrite1h
}

func testNonnegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}
