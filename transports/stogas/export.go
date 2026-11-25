package stogas

import (
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter"
)

// FinalizeExportState reuses the canonical event that settlement stores as the
// request record. Content, and the signed metadata of a response that carried a
// receipt, are the only export-specific fields. A request without that event has
// no export.
func FinalizeExportState(state *State) {
	if state == nil || state.Export == nil {
		return
	}
	if state.FinalEvent == nil {
		state.Export.Discard()
		return
	}
	finishExport(state)
}

// HoldRejectedExport takes the export of a request that ended without a hold,
// to send with the request record that holds its rejection. Such a request
// costs nothing, so its export follows the request log: the caller cannot make
// the gateway send more records than the request log shows. Its content was
// never captured, because capture copies the request only after its hold.
func HoldRejectedExport(state *State) billing.RejectionExport {
	if state == nil || state.Export == nil {
		return nil
	}
	held := state.Export.Hold()
	state.Export = nil
	if held == nil {
		return nil
	}
	return &rejectedExport{held: held}
}

// rejectedExport sends the request record unchanged, so that the export of a
// count has its request_count.
type rejectedExport struct{ held *exporter.Held }

func (e *rejectedExport) Finish(row billing.RequestEvent) {
	e.held.Finish(row.RequestID, row.Outcome(), &row)
}

func (e *rejectedExport) Discard() { e.held.Discard() }

func finishExport(state *State) {
	capture := state.Export
	finalizeExportMetrics(state)
	state.Export = nil
	capture.Finish(state.RequestID, state.FinalEvent.Outcome(), state.FinalEvent)
}

// finalizeExportMetrics marks the record of a request whose record a
// destination gets, so that a receiver can tell the records it should hold.
func finalizeExportMetrics(state *State) {
	if state == nil || state.FinalEvent == nil {
		return
	}
	state.FinalEvent.Plugins.Export = nil
	if state.Export.Due(state.FinalEvent.Outcome()) {
		state.FinalEvent.Plugins.Export = &plugins.ExportMetrics{DurationUS: *state.Export.Duration()}
	}
}
