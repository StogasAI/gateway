package stogashttp

import (
	"errors"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// Keep cold, retained state from consuming the space needed to admit a maximum
// configured request plus a byte-weighted maximum response. Additional response
// structure and codec scratch still require admission. Request work can use the
// full shared budget; this is a watermark, not a separate memory pool.
func (a *requestMemoryAdmission) protectRequestMemory(maxBodyBytes int) error {
	headroom := requestMemoryWeight(maxBodyBytes, catalog.MaxRequestJSONValues*requestJSONValueBytes) + maxInferenceStreamResponseBytes*requestBodyReservationFactor
	// Fail at startup if even one complete session cannot coexist with this
	// request. Silently clamping would remove the protection on smaller guests.
	if headroom+encryptedSessionRetainedBytes+connectionRetainedBytes+quoteRetainedBytes > a.budgetBytes() {
		return errors.New("confidential memory budget cannot fit the maximum request, response and session setup; increase GOMEMLIMIT or reduce max-request-body-mib")
	}
	a.confidentialHeadroom = headroom
	return nil
}

// Conservative retained-byte charges cover bounded evidence copies, local
// crypto state, sockets and request handlers. They share the application memory
// budget and remain charged through actual ownership, including cancellation.
// Qualify them on real guests.
const (
	quoteRetainedBytes = 64 * 1024
	// An idle TLS socket measured 80 KiB, and 106 KiB after a maximum frame.
	connectionRetainedBytes = 256 * 1024
	// A request whose response waits on the client measured 18 KiB, and 34 KiB
	// with 16 KiB of headers, for its handler, headers and HTTP/2 stream.
	requestRetainedBytes = 64 * 1024
	// The C allocator test bounds 256 retained header groups and transactional
	// replacement below 512 KiB; the other half covers setup evidence and Go state.
	encryptedSessionRetainedBytes = 1024 * 1024
)

// Finished exports are best effort and yield first. Unpaid responses whose
// clients stopped reading go next, then sockets that are not running a request,
// oldest first; those clients only retry or reconnect. An idle session costs its
// client a new handshake and attestation. The slowest upload goes last, because
// its client must send the request again.
func (s *Server) reclaimIdleMemory(needed int64) bool {
	remaining := needed - s.exports.Reclaim(needed)
	reclaimEach := func(reclaim func() int64) {
		for remaining > 0 {
			freed := reclaim()
			if freed == 0 {
				return
			}
			remaining -= freed
		}
	}
	reclaimEach(s.waitingClients.reclaimWrite)
	reclaimEach(s.idleConnections.reclaim)
	if remaining > 0 && s.sessions != nil {
		count := (remaining + encryptedSessionRetainedBytes - 1) / encryptedSessionRetainedBytes
		remaining -= int64(s.sessions.ReclaimIdle(int(count))) * encryptedSessionRetainedBytes
	}
	reclaimEach(s.waitingClients.reclaimUpload)
	return remaining < needed
}

func (a *requestMemoryAdmission) confidentialReservation(bytes int) func() (func(), bool) {
	return func() (func(), bool) {
		if a == nil {
			return nil, false
		}
		lease := a.newLease(confidentialStateMemory)
		if !lease.growWithin(bytes, a.budgetBytes()-a.confidentialHeadroom) {
			return nil, false
		}
		return lease.release, true
	}
}
