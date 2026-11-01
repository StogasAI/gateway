package stogas

import (
	"encoding/json"
	"strconv"
	"testing"

	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestEstimatedInputMeterIsIndependentOfReportedAndChargedUsage(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions",
		Body: []byte(`{"model":"openai/gpt-5.5","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":16}`)})
	if err != nil {
		t.Fatal(err)
	}
	estimate, known := resolution.EstimatedInputTokens()
	if !known || estimate <= 0 {
		t.Fatal("request has no local estimate")
	}
	state := &State{Pair: Pair{Resolution: resolution}}
	before := metersForState(state)
	if _, invented := before[billing.MeterTotalInputTokens]; invented {
		t.Fatal("estimate became observed usage")
	}
	setSignalsFromUsage(state, &schemas.BifrostLLMUsage{PromptTokens: 4, CompletionTokens: 1, TotalTokens: 5})
	after := metersForState(state)
	for _, meters := range []billing.EventMeters{before, after} {
		meter := meters[billing.MeterEstimatedInputTokens]
		if meter.Quantity != strconv.Itoa(estimate) || meter.RateKey != nil || meter.RateUSD != nil || meter.USD != nil {
			t.Fatalf("estimate changed or acquired a price: %#v", meter)
		}
	}
	if after[billing.MeterTotalInputTokens].Quantity != "4" {
		t.Fatal("estimate replaced actual usage")
	}
}

func TestMetersKeepActualUsageAboveHold(t *testing.T) {
	state := &State{
		Pair: Pair{
			Hold: HoldEstimate{Meters: []catalog.MeterEstimate{
				{MeterKey: billing.MeterInputTokens, Quantity: "50", HoldRequired: true},
				{MeterKey: billing.MeterOutputTokens, Quantity: "20", HoldRequired: true},
			}},
		},
		FinalMeters: []catalog.MeterEstimate{
			{MeterKey: billing.MeterInputTokens, Quantity: "100", RateKey: billing.RatePerMillionTokens, RateUSD: "2", AmountUSD: "0.0002"},
		},
	}
	usage := &schemas.BifrostLLMUsage{PromptTokens: 100, CompletionTokens: 30, TotalTokens: 130}
	setSignalsFromUsage(state, usage)
	setSignalsFromUsage(state, usage) // A terminal usage snapshot is cumulative.
	meters := metersForState(state)
	if state.Signals.PromptTokens() != 100 || meters[billing.MeterInputTokens].Quantity != "100" {
		t.Fatalf("actual billed usage was lost: %#v", meters)
	}
	for key, quantity := range map[string]string{billing.MeterTotalInputTokens: "100", billing.MeterTotalOutputTokens: "30", billing.MeterTotalTokens: "130"} {
		meter := meters[key]
		if meter.Quantity != quantity || meter.RateKey != nil || meter.RateUSD != nil || meter.USD != nil {
			t.Fatalf("%s: %#v", key, meter)
		}
	}
	encoded, err := json.Marshal(meters[billing.MeterTotalTokens])
	if err != nil || string(encoded) != `{"quantity":"130"}` {
		t.Fatalf("informational meter = %s, %v", encoded, err)
	}
}

func TestMeterTotalsDoNotDoubleCountCacheDurationsOrUnknownUsage(t *testing.T) {
	state := &State{}
	setSignalsFromUsage(state, &schemas.BifrostLLMUsage{
		PromptTokens: 1300, CompletionTokens: 10, TotalTokens: 1310,
		PromptTokensDetails: &schemas.ChatPromptTokensDetails{CachedReadTokens: 300, CachedWriteTokens: 300,
			CachedWriteTokenDetails: &schemas.ChatCachedWriteTokenDetails{CachedWriteTokens5m: 100, CachedWriteTokens1h: 200}},
	})
	meters := metersForState(state)
	if meters[billing.MeterTotalCacheWriteTokens].Quantity != "300" || meters[billing.MeterTotalInputTokens].Quantity != "1300" || meters[billing.MeterTotalTokens].Quantity != "1310" {
		t.Fatalf("cache parts counted twice: %#v", meters)
	}
	partial := &State{}
	setSignalsFromUsage(partial, &schemas.BifrostLLMUsage{CompletionTokens: 10})
	if _, invented := metersForState(partial)[billing.MeterTotalTokens]; invented {
		t.Fatal("partial usage became a known total")
	}
	if len(metersForState(&State{})) != 0 {
		t.Fatal("unknown usage became zero")
	}
}

func TestReasoningMeterIsZeroOnlyWhenTheProviderReportsIt(t *testing.T) {
	chat := func(payload string) *schemas.BifrostLLMUsage {
		var usage schemas.BifrostLLMUsage
		if err := schemas.Unmarshal([]byte(payload), &usage); err != nil {
			t.Fatal(err)
		}
		usage.NormalizeReasoningTokens()
		return &usage
	}
	responses := func(payload string) *schemas.BifrostLLMUsage {
		var usage schemas.ResponsesResponseUsage
		if err := schemas.Unmarshal([]byte(payload), &usage); err != nil {
			t.Fatal(err)
		}
		return usage.ToBifrostLLMUsage()
	}
	claude := func(payload string) *schemas.BifrostLLMUsage {
		var usage anthropicprovider.AnthropicUsage
		if err := schemas.Unmarshal([]byte(payload), &usage); err != nil {
			t.Fatal(err)
		}
		return anthropicprovider.ConvertAnthropicUsageToBifrostUsage(&usage).ToBifrostLLMUsage()
	}
	const counts = `"prompt_tokens":4,"completion_tokens":6,"total_tokens":10`
	for name, test := range map[string]struct {
		snapshots []*schemas.BifrostLLMUsage
		want      string // "" means the meter is absent.
	}{
		"reported zero":              {[]*schemas.BifrostLLMUsage{chat(`{` + counts + `,"completion_tokens_details":{"reasoning_tokens":0}}`)}, "0"},
		"reported count":             {[]*schemas.BifrostLLMUsage{chat(`{` + counts + `,"completion_tokens_details":{"reasoning_tokens":4}}`)}, "4"},
		"top-level count":            {[]*schemas.BifrostLLMUsage{chat(`{` + counts + `,"reasoning_tokens":4}`)}, "4"},
		"top-level default zero":     {[]*schemas.BifrostLLMUsage{chat(`{` + counts + `,"reasoning_tokens":0}`)}, ""},
		"no details":                 {[]*schemas.BifrostLLMUsage{chat(`{` + counts + `}`)}, ""},
		"details without reasoning":  {[]*schemas.BifrostLLMUsage{chat(`{` + counts + `,"completion_tokens_details":{"audio_tokens":0}}`)}, ""},
		"null count":                 {[]*schemas.BifrostLLMUsage{chat(`{` + counts + `,"completion_tokens_details":{"reasoning_tokens":null}}`)}, ""},
		"count above completion":     {[]*schemas.BifrostLLMUsage{chat(`{` + counts + `,"completion_tokens_details":{"reasoning_tokens":9}}`)}, ""},
		"Responses reported zero":    {[]*schemas.BifrostLLMUsage{responses(`{"input_tokens":4,"output_tokens":6,"total_tokens":10,"output_tokens_details":{"reasoning_tokens":0}}`)}, "0"},
		"Responses without details":  {[]*schemas.BifrostLLMUsage{responses(`{"input_tokens":4,"output_tokens":6,"total_tokens":10}`)}, ""},
		"Claude reported zero":       {[]*schemas.BifrostLLMUsage{claude(`{"input_tokens":4,"output_tokens":6,"output_tokens_details":{"thinking_tokens":0}}`)}, "0"},
		"Claude reported count":      {[]*schemas.BifrostLLMUsage{claude(`{"input_tokens":4,"output_tokens":6,"output_tokens_details":{"thinking_tokens":5}}`)}, "5"},
		"Claude without a breakdown": {[]*schemas.BifrostLLMUsage{claude(`{"input_tokens":4,"output_tokens":6}`)}, ""},
		"a later report is kept": {[]*schemas.BifrostLLMUsage{
			chat(`{` + counts + `}`),
			chat(`{` + counts + `,"completion_tokens_details":{"reasoning_tokens":0}}`),
			chat(`{` + counts + `}`),
		}, "0"},
		"a count survives a later snapshot without one": {[]*schemas.BifrostLLMUsage{
			chat(`{` + counts + `,"completion_tokens_details":{"reasoning_tokens":2}}`),
			chat(`{` + counts + `}`),
		}, "2"},
	} {
		t.Run(name, func(t *testing.T) {
			state := &State{}
			for _, usage := range test.snapshots {
				setSignalsFromUsage(state, usage)
			}
			meters := metersForState(state)
			meter, ok := meters[billing.MeterReasoningTokens]
			if test.want == "" && ok || test.want != "" && meter.Quantity != test.want {
				t.Fatalf("reasoning meter = %#v (present %v), want %q", meter, ok, test.want)
			}
			// Output tokens stay completion minus reported reasoning, so unknown reasoning
			// never changes them.
			if meters[billing.MeterTotalOutputTokens].Quantity != "6" {
				t.Fatalf("total output = %#v", meters[billing.MeterTotalOutputTokens])
			}
		})
	}
}
