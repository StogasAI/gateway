package stogashttp

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
)

func TestPrivateDiagnosticsRetainsCountersWhenDetailOverflows(t *testing.T) {
	node := privateNodeDiagnostics{HTTPServerErrors: 91}
	node.Process.AllocatedBytes = 900000
	node.Requests.JSONDecode.InputBytes = 50000
	node.Requests.JSONDecode.InputBytesBuckets[16] = 1
	node.Requests.Preprocessing.WallTimeMicrosBuckets[8] = 2
	node.Requests.Memory.BudgetBytes = 123456
	node.ChutesE2EE.TargetRejections = 77
	node.OperationalLogs = []stogas.OperationalLogSeries{{Event: strings.Repeat("\x00", maximumResourceDiagnosticBytes)}, {Event: "http2_error", Occurrences: 42}}
	for range 512 {
		node.ChutesE2EE.Chutes = append(node.ChutesE2EE.Chutes, chutese2ee.ChuteDiagnostic{ChuteID: "known", UpstreamModels: []string{strings.Repeat("\x00", 3000)}})
	}
	bounded := boundPrivateDiagnostics(node)
	encoded, err := json.Marshal(bounded)
	if err != nil || len(encoded) > maximumResourceDiagnosticBytes {
		t.Fatalf("diagnostic budget exceeded: bytes=%d err=%v", len(encoded), err)
	}
	if bounded.HTTPServerErrors != 91 || bounded.Requests.Memory.BudgetBytes != 123456 || bounded.ChutesE2EE.TargetRejections != 77 ||
		bounded.Process.AllocatedBytes != 900000 || bounded.Requests.JSONDecode.InputBytes != 50000 || bounded.Requests.JSONDecode.InputBytesBuckets[16] != 1 || bounded.Requests.Preprocessing.WallTimeMicrosBuckets[8] != 2 {
		t.Fatal("detail truncation lost fixed counters")
	}
	if bounded.OmittedOperationalLogs != 1 || len(bounded.OperationalLogs) != 1 || bounded.OperationalLogs[0].Occurrences != 42 {
		t.Fatal("one oversized row hid a later useful row or its omission")
	}
	if bounded.OmittedChutes == 0 || bounded.OmittedChutes+len(bounded.ChutesE2EE.Chutes) != 512 || len(bounded.ChutesE2EE.Chutes) == 0 {
		t.Fatal("detail loss is uncounted or discarded all useful detail")
	}
	if len(node.OperationalLogs) != 2 || len(node.ChutesE2EE.Chutes) != 512 {
		t.Fatal("snapshot truncation mutated the source")
	}
}

type diagnosticLeaseWriter struct {
	*httptest.ResponseRecorder
	t      *testing.T
	memory *requestMemoryAdmission
	fail   bool
}

func (w diagnosticLeaseWriter) Write(data []byte) (int, error) {
	if w.memory.reserved.Load() == 0 {
		w.t.Error("diagnostic encoding reservation ended before delivery")
	}
	if w.fail {
		return 0, io.ErrClosedPipe
	}
	return w.ResponseRecorder.Write(data)
}

func TestDiagnosticMemoryOwnershipAndSaturatedFallback(t *testing.T) {
	for _, failedWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "disconnected"}[failedWrite], func(t *testing.T) {
			memory := &requestMemoryAdmission{budget: requestMemoryBudgetBytes}
			s := &Server{memory: memory}
			ctx := newTestRequest(t)
			ctx.writer = diagnosticLeaseWriter{ResponseRecorder: httptest.NewRecorder(), t: t, memory: memory, fail: failedWrite}
			s.diagnostics(ctx)
			if memory.reserved.Load() != 0 {
				t.Fatal("diagnostic reservation leaked after write completion")
			}
		})
	}
	s := &Server{memory: &requestMemoryAdmission{budget: 1}}
	ctx := newTestRequest(t)
	s.diagnostics(ctx)
	var payload struct {
		Node privateNodeDiagnostics `json:"node"`
	}
	if err := json.Unmarshal(testResponse(ctx).Body.Bytes(), &payload); err != nil || !payload.Node.DetailsUnavailable || payload.Node.Requests.Memory.BudgetBytes != 1 || testResponse(ctx).Code != 200 {
		t.Fatalf("saturated diagnostics lost their minimal snapshot: %v", err)
	}
	if s.memory.reserved.Load() != 0 {
		t.Fatal("failed snapshot admission retained memory")
	}
}
