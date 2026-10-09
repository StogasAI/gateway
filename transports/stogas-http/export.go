package stogashttp

import (
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter"
)

type exportMemoryLease struct{ lease *requestMemoryLease }

func (l exportMemoryLease) Grow(n int) bool { return l.lease.grow(n) }
func (l exportMemoryLease) Release()        { l.lease.release() }
func (s *Server) exportLease() exporter.Lease {
	return exportMemoryLease{s.memory.newLease(requestLifetimeMemory)}
}

// Unary exports keep the provider result even when the caller stopped waiting
// or its receipt failed; the canonical event records those outcomes.
func captureUnaryResult(ctx *schemas.BifrostContext, state *stogas.State, response *schemas.BifrostResponse, outcome *schemas.BifrostError) {
	if outcome != nil {
		captureExportError(state, outcome)
		return
	}
	if state == nil || state.Export == nil {
		return
	}
	encoded, err := marshalPayload(unaryResponsePayload(ctx, response))
	if err == nil {
		state.Export.Response(encoded)
		clear(encoded)
	}
}

func captureExportError(state *stogas.State, failure *schemas.BifrostError) {
	if state == nil || state.Export == nil {
		return
	}
	encoded, err := marshalPayload(bifrostErrorPayload(failure))
	if err == nil {
		state.Export.Response(encoded)
		clear(encoded)
	}
}
