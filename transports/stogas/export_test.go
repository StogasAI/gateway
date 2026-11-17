package stogas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
)

type exportTestLease struct{}

func (exportTestLease) Grow(int) bool { return true }
func (exportTestLease) Release()      {}

// The request record marks export only when a destination gets the record,
// and only then does the record leave.
func TestExportFollowsTheRequestOutcome(t *testing.T) {
	var received atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	defer receiver.Close()
	engine := exporter.New(context.Background(), exporter.Options{Local: true, NewLease: func() exporter.Lease { return exportTestLease{} }})
	defer engine.Close()
	failures := &exportconfig.Config{Destinations: []exportconfig.Destination{{URL: receiver.URL, Sample: &exportconfig.Sample{0, 1, 0, 1, 0}}}}
	served := []billing.ProviderAttempt{{Status: "success"}}
	failed := []billing.ProviderAttempt{{Status: "timeout"}}

	finish := func(attempts []billing.ProviderAttempt) *billing.RequestEvent {
		state := &State{RequestID: "request", Export: engine.Start(failures, "request")}
		// An earlier pass over the same event may have marked it.
		state.FinalEvent = &billing.RequestEvent{RequestID: "request", ProviderAttempts: attempts, Plugins: plugins.Metrics{Export: &plugins.ExportMetrics{}}}
		finalizeExportMetrics(state)
		marked := state.FinalEvent.Plugins.Export != nil
		FinalizeExportState(context.Background(), state)
		if state.Export != nil || marked != (state.FinalEvent.Plugins.Export != nil) {
			t.Fatal("finishing the export kept the capture or changed the record's mark")
		}
		return state.FinalEvent
	}
	if event := finish(served); event.Plugins.Export != nil {
		t.Fatal("a served request is marked as exported to a destination that gets only failures")
	}
	if event := finish(failed); event.Plugins.Export == nil {
		t.Fatal("a failed request is not marked as exported")
	}
	deadline := time.Now().Add(10 * time.Second)
	for engine.Diagnostics().Delivered != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if d := engine.Diagnostics(); received.Load() != 1 || d.Delivered != 1 || d.ReservedBytes != 0 || d.Failed != 0 {
		t.Fatalf("received %d records, diagnostics %+v", received.Load(), d)
	}

	// Without a capture, the record carries no mark.
	state := &State{RequestID: "request", FinalEvent: &billing.RequestEvent{ProviderAttempts: failed, Plugins: plugins.Metrics{Export: &plugins.ExportMetrics{}}}}
	finalizeExportMetrics(state)
	if state.FinalEvent.Plugins.Export != nil {
		t.Fatal("a request without a capture is marked as exported")
	}
}
