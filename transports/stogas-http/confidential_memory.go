package stogashttp

import (
	"errors"
	"net"
	"sync"

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
	if headroom+encryptedSessionRetainedBytes+sessionRetainedBytes+quoteRetainedBytes > a.budgetBytes() {
		return errors.New("confidential memory budget cannot fit the maximum request, response and session setup; increase GOMEMLIMIT or reduce max-request-body-mib")
	}
	a.confidentialHeadroom = headroom
	return nil
}

// Conservative retained-byte charges cover bounded evidence copies and local
// crypto state. They share the application memory budget and remain charged
// through actual ownership, including cancellation. Qualify them on real guests.
const (
	quoteRetainedBytes   = 64 * 1024
	sessionRetainedBytes = 256 * 1024
	// The C allocator test bounds 256 retained header groups and transactional
	// replacement below 512 KiB; the other half covers setup evidence and Go state.
	encryptedSessionRetainedBytes = 1024 * 1024
)

func (s *Server) reclaimIdleMemory(needed int64) bool {
	count := (needed + encryptedSessionRetainedBytes - 1) / encryptedSessionRetainedBytes
	remaining := needed - int64(s.sessions.ReclaimIdle(int(count)))*encryptedSessionRetainedBytes
	for remaining > 0 && s.idleConnections.reclaim() {
		remaining -= sessionRetainedBytes
	}
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

// A TLS connection retains its certificate and handshake state after setup.
// Charging the socket lifetime avoids returning quote memory while those bytes
// are still owned by crypto/tls.
type confidentialListener struct {
	net.Listener
	memory *requestMemoryAdmission
}
type confidentialConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *confidentialConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
func (l *confidentialListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		release, ok := l.memory.confidentialReservation(sessionRetainedBytes)()
		if !ok {
			_ = conn.Close()
			continue
		}
		return &confidentialConn{Conn: conn, release: release}, nil
	}
}
