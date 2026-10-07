package stogas

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter"
)

// FinalizeExportState snapshots only customer-visible metadata. Export outcome
// includes delivery/proof failures occurring after the immutable billing event.
func FinalizeExportState(state *State) {
	if state == nil || state.Export == nil {
		return
	}
	capture := state.Export
	state.Export = nil
	r := exporter.Record{RequestID: state.RequestID, Model: state.Model, ResponseModel: state.ActualModel, RequestType: state.RequestType, Version: state.GatewayVersion, StartedAt: state.StartedAt, EndedAt: time.Now(), Outcome: "success", CostUSD: billing.ZeroChargeUSD}
	if state.Resolution != nil {
		r.Provider = string(state.Resolution.Provider)
		if r.Model == "" {
			r.Model = state.Resolution.Model
		}
		if r.RequestType == "" {
			r.RequestType = string(state.Resolution.RequestType)
		}
	}
	if state.FinalEvent != nil {
		event := state.FinalEvent
		r.CostUSD = event.BilledCostUSD
		r.InputTokens = exportTokenCount(event.Meters, billing.MeterTotalInputTokens)
		r.OutputTokens = exportTokenCount(event.Meters, billing.MeterTotalOutputTokens)
		r.CachedInputTokens = exportTokenCount(event.Meters, billing.MeterCachedInputTokens)
		r.CacheWriteTokens = exportTokenCount(event.Meters, billing.MeterTotalCacheWriteTokens)
		r.ReasoningTokens = exportTokenCount(event.Meters, billing.MeterReasoningTokens)
		r.TimeToFirstTokenMS = event.Performance.TTFTMS
		if len(event.ProviderAttempts) > 0 {
			r.FinishReason = event.ProviderAttempts[len(event.ProviderAttempts)-1].FinishReason
		}
		raw, err := json.Marshal(event)
		if err == nil {
			r.Metadata = string(raw)
		}
	}
	if failure := state.ResponseError(); failure != nil {
		r.Outcome = "failure"
		r.ErrorCode = "gateway_error"
		if failure.StatusCode != nil {
			r.ErrorStatus = *failure.StatusCode
		}
		if failure.Error != nil && failure.Error.Code != nil {
			r.ErrorCode = *failure.Error.Code
		}
	}
	if state.Cancelled {
		r.Outcome = "cancelled"
	}
	capture.Finish(r)
}

// An absent or unusable meter is unknown, not measured zero.
func exportTokenCount(meters billing.EventMeters, key string) *int64 {
	meter, ok := meters[key]
	if !ok {
		return nil
	}
	value, err := strconv.ParseInt(meter.Quantity, 10, 64)
	if err != nil || value < 0 {
		return nil
	}
	return &value
}
