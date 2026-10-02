package stogas

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestEstimatedInputMeterIsIndependentOfReportedAndChargedUsage(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions",
		Body: []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}],"max_completion_tokens":16}`)})
	if err != nil {
		t.Fatal(err)
	}
	estimate, known := resolution.EstimatedInputTokens()
	if !known || estimate <= 0 {
		t.Fatal("request has no local estimate")
	}
	state := &State{Resolution: resolution}
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
	state := &State{Hold: HoldEstimate{Meters: []catalog.MeterEstimate{
		{MeterKey: billing.MeterInputTokens, Quantity: "50", HoldRequired: true},
		{MeterKey: billing.MeterOutputTokens, Quantity: "20", HoldRequired: true},
	}}, FinalMeters: []catalog.MeterEstimate{
		{MeterKey: billing.MeterInputTokens, Quantity: "100", RateKey: billing.RatePerMillionTokens, RateUSD: "2", AmountUSD: "0.0002"},
	}}
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
