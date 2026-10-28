package stogas

import (
	"context"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter"
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

// HoldRejectedExport takes the export of a request that ended without a hold,
// to send with the request record that holds its rejection. Such a request
// costs nothing, so its export follows the request log: the caller cannot make
// the gateway send more records than the request log shows. Its content was
// never captured, because capture copies the request only after its hold.
func HoldRejectedExport(ctx context.Context, state *State) billing.RejectionExport {
	if state == nil || state.Export == nil {
		return nil
	}
	held := state.Export.Hold()
	state.Export = nil
	if held == nil {
		return nil
	}
	return &rejectedExport{held: held, metadata: FinalMetadata(ctx, state)}
}

// rejectedExport sends the request record unchanged, so that the export of a
// count has its request_count. The metadata stays the request's, whose ID the
// record keeps; a count keeps its first repeat's.
type rejectedExport struct {
	held     *exporter.Held
	metadata proof.Metadata
}

func (e *rejectedExport) Finish(row billing.RequestEvent) {
	metadata := e.metadata
	recordMetadata(&metadata, &row)
	e.held.Finish(row.RequestID, &row, exportMetadata{metadata, row.NodeID})
}

func (e *rejectedExport) Discard() { e.held.Discard() }

type exportMetadata struct {
	proof.Metadata
	NodeID string `json:"node_id"`
}

func finishExport(ctx context.Context, state *State) {
	capture := state.Export
	finalizeExportMetrics(state)
	state.Export = nil
	capture.Finish(state.RequestID, state.FinalEvent, exportMetadata{FinalMetadata(ctx, state), state.NodeID})
}

func finalizeExportMetrics(state *State) {
	if state == nil || state.FinalEvent == nil {
		return
	}
	if duration := state.Export.Duration(); duration != nil {
		state.FinalEvent.Plugins.StogasExport = &plugins.StogasExportMetrics{DurationUS: *duration}
	}
}
