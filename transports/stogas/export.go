package stogas

import (
	"context"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

// FinalizeExportState reuses the canonical event that settlement stores as the
// request log.
// Content and contextual response metadata are the only export-specific fields.
// A request without that event has no export.
func FinalizeExportState(ctx context.Context, state *State) {
	if state == nil || state.Export == nil {
		return
	}
	if state.FinalEvent == nil {
		state.Export.Discard()
		return
	}
	finishExport(ctx, state)
}

// FinalizeRejectedExport exports a request that ended without a hold. Such a
// request costs nothing, so it is exported only when the request log keeps its
// rejection as a row of its own: the caller cannot make the gateway send more
// records than the request log shows. Its content was never captured, because
// capture copies the request only after its hold.
func FinalizeRejectedExport(ctx context.Context, state *State, logged bool) {
	if state == nil || state.Export == nil {
		return
	}
	failure := state.ResponseError()
	if !logged || state.APIKeyClaims == nil || failure == nil {
		state.Export.Discard()
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
		Transport: state.Transport,
	})
	state.FinalEvent = &event
	finishExport(ctx, state)
}

func finishExport(ctx context.Context, state *State) {
	capture := state.Export
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
	if duration := state.Export.Duration(); duration != nil {
		state.FinalEvent.Plugins.StogasExport = &plugins.StogasExportMetrics{DurationUS: *duration}
	}
}
