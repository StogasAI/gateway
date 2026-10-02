package stogashttp

import (
	"net"
	"sync"
)

// Conservative retained-byte charges cover bounded evidence copies and local
// crypto state. They share the application memory budget and remain charged
// through actual ownership, including cancellation. Qualify them on real guests.
const (
	quoteRetainedBytes   = 64 * 1024
	sessionRetainedBytes = 256 * 1024
	// Covers the shared Rust ratchet's 4096 delayed keys per component and transactional
	// replacement peak; allocator qualification lives with the C embedding.
	encryptedSessionRetainedBytes = 3 * 1024 * 1024
)

func (a *requestMemoryAdmission) confidentialReservation(bytes int) func() (func(), bool) {
	return func() (func(), bool) {
		if a == nil {
			return nil, false
		}
		lease := a.newLease(streamStateMemory)
		if !lease.grow(bytes) {
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
