package stogas

import (
	"context"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

// FinalizeExportState reuses the canonical event that feeds billing and Tinybird.
// Content and contextual response metadata are the only export-specific fields.
func FinalizeExportState(ctx context.Context, state *State) {
	if state == nil || state.Export == nil {
		return
	}
	capture := state.Export
	if state.FinalEvent == nil {
		failure := state.ResponseError()
		if state.APIKeyClaims == nil || failure == nil {
			capture.Discard()
			return
		}
		status, code := 500, "gateway_error"
		if failure.StatusCode != nil {
			status = *failure.StatusCode
		}
		if failure.Error != nil && failure.Error.Code != nil {
			code = *failure.Error.Code
		}
		event := billing.NewRejectionEvent(billing.RejectionInput{
			Claims: state.APIKeyClaims, RequestID: state.RequestID, RequestType: string(state.Resolution.RequestType),
			Code: code, StatusCode: status, CreatedAt: state.StartedAt,
			PolicyVersions: state.PolicyVersions, NodeID: state.NodeID, GatewayVersion: state.GatewayVersion,
		})
		state.FinalEvent = &event
	}
	finalizeExportMetrics(state)
	state.Export = nil
	metadata := struct {
		proof.Metadata
		NodeID string `json:"node_id"`
	}{FinalMetadata(ctx, state), state.NodeID}
	capture.Finish(state.RequestID, state.FinalEvent, metadata)
}

func finalizeExportMetrics(state *State) {
	if state == nil || state.FinalEvent == nil {
		return
	}
	if duration := state.Export.CaptureDuration(); duration != nil {
		state.FinalEvent.Plugins.StogasExport = &plugins.StogasExportMetrics{CaptureUS: *duration}
	}
}
