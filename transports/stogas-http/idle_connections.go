package stogashttp

import (
	"container/list"
	"context"
	"net"
	"net/http"
	"sync"
)

// A socket that is not running a request is the cheapest state to give up: it
// is in setup, reading its first request headers or idle between requests.
// Memory pressure closes these sockets oldest first, so sockets that never
// send a request cannot keep new clients out, and a client whose idle socket
// closes only reconnects. A running request keeps its socket.
type idleConnections struct {
	mu sync.Mutex
	// Admitted sockets; the element is nil while a request runs.
	tracked map[net.Conn]*list.Element
	oldest  list.List
	evicted uint64
}

type httpConnectionKey struct{}

func withHTTPConnection(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, httpConnectionKey{}, conn)
}

func (c *idleConnections) track(conn *ingressTLSConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tracked == nil {
		c.tracked = make(map[net.Conn]*list.Element)
	}
	c.tracked[conn] = c.oldest.PushBack(conn)
}

// busy protects the request's socket until net/http reports it idle again.
func (c *idleConnections) busy(ctx context.Context) {
	conn, ok := ctx.Value(httpConnectionKey{}).(net.Conn)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if item := c.tracked[conn]; item != nil {
		c.oldest.Remove(item)
		c.tracked[conn] = nil
	}
}

func (c *idleConnections) observe(conn net.Conn, state http.ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, tracked := c.tracked[conn]
	if !tracked {
		return
	}
	switch state {
	case http.StateIdle:
		if item == nil {
			c.tracked[conn] = c.oldest.PushBack(conn)
		}
	case http.StateClosed, http.StateHijacked:
		if item != nil {
			c.oldest.Remove(item)
		}
		delete(c.tracked, conn)
	}
}

// reclaim closes the socket that has waited longest without running a request
// and returns the memory it released.
func (c *idleConnections) reclaim() int64 {
	c.mu.Lock()
	item := c.oldest.Front()
	if item == nil {
		c.mu.Unlock()
		return 0
	}
	conn := c.oldest.Remove(item).(*ingressTLSConn)
	delete(c.tracked, conn)
	c.evicted++
	c.mu.Unlock()
	conn.evict()
	return connectionRetainedBytes
}
