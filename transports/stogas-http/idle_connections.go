package stogashttp

import (
	"container/list"
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

type idleConnection struct {
	conn  net.Conn
	since time.Time
}

// Only net/http's idle state is eligible, including zero active HTTP/2 streams.
// The lock orders eviction against the transition to active, never request work.
type idleConnections struct {
	mu       sync.Mutex
	entries  map[net.Conn]*list.Element
	retiring map[net.Conn]struct{}
	oldest   list.List
	evicted  uint64
	rejected uint64
}

type httpConnectionKey struct{}

func withHTTPConnection(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, httpConnectionKey{}, conn)
}

// An aborted HTTP/1 upload cannot serve another request. Let net/http finish
// the response framing before closing its socket at the idle transition.
func (c *idleConnections) retireAfterReply(ctx context.Context) {
	conn, ok := ctx.Value(httpConnectionKey{}).(net.Conn)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.retiring == nil {
		c.retiring = make(map[net.Conn]struct{})
	}
	c.retiring[conn] = struct{}{}
}

func (c *idleConnections) observe(conn net.Conn, state http.ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, retiring := c.retiring[conn]; retiring && (state == http.StateIdle || state == http.StateClosed || state == http.StateHijacked) {
		delete(c.retiring, conn)
		if state == http.StateIdle {
			if secured, ok := conn.(interface{ NetConn() net.Conn }); ok {
				conn = secured.NetConn()
			}
			_ = conn.Close()
			return
		}
	}
	if item := c.entries[conn]; item != nil {
		if state == http.StateIdle {
			return
		}
		c.oldest.Remove(item)
		delete(c.entries, conn)
	}
	if state == http.StateIdle {
		if c.entries == nil {
			c.entries = make(map[net.Conn]*list.Element)
		}
		c.entries[conn] = c.oldest.PushBack(idleConnection{conn, time.Now()})
	}
}

func (c *idleConnections) reclaim() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.oldest.Front()
	if item == nil {
		return false
	}
	entry := item.Value.(idleConnection)
	// Preserve the existing one-minute idle allowance; pressure must not turn
	// every newly accepted socket into an eviction of a recent customer's pool.
	if time.Since(entry.since) < serverIdleTimeout {
		return false
	}
	c.oldest.Remove(item)
	delete(c.entries, entry.conn)
	conn := entry.conn
	if secured, ok := conn.(interface{ NetConn() net.Conn }); ok {
		// This socket has exhausted its idle allowance. Close the transport
		// directly: TLS close_notify could wait on a stalled peer while holding
		// the state lock. The server still performs its normal TLS cleanup.
		conn = secured.NetConn()
	}
	_ = conn.Close()
	c.evicted++
	return true
}

// Accept one candidate before checking slots so idle sockets are reclaimed only
// when there is actual new demand. At most one unadmitted socket is held by Serve.
type publicListener struct {
	net.Listener
	slots chan struct{}
	idle  *idleConnections
}

func (l *publicListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &publicConn{Conn: conn, slots: l.slots}, nil
		default:
		}
		l.idle.reclaim()
		select {
		case l.slots <- struct{}{}:
			return &publicConn{Conn: conn, slots: l.slots}, nil
		default:
			l.idle.mu.Lock()
			l.idle.rejected++
			l.idle.mu.Unlock()
			_ = conn.Close()
		}
	}
}

type publicConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *publicConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}
