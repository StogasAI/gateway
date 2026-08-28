package stogashttp

import (
	"net"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

type writeIdleTimeoutListener struct {
	net.Listener
	timeout time.Duration
}

func withWriteIdleTimeout(listener net.Listener, timeout time.Duration) net.Listener {
	if listener == nil || timeout <= 0 {
		return listener
	}
	return &writeIdleTimeoutListener{Listener: listener, timeout: timeout}
}

func (l *writeIdleTimeoutListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &writeIdleTimeoutConn{Conn: connection, timeout: l.timeout}, nil
}

type writeIdleTimeoutConn struct {
	net.Conn
	timeout time.Duration
	limitMu sync.RWMutex
	limit   time.Time
}

func (c *writeIdleTimeoutConn) Write(p []byte) (int, error) {
	deadline := time.Now().Add(c.timeout)
	c.limitMu.RLock()
	limit := c.limit
	c.limitMu.RUnlock()
	if !limit.IsZero() && limit.Before(deadline) {
		deadline = limit
	}
	if err := c.Conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *writeIdleTimeoutConn) setWriteDeadlineLimit(deadline time.Time) {
	c.limitMu.Lock()
	c.limit = deadline
	c.limitMu.Unlock()
}

func resetDownstreamWriteLimit(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		setDownstreamWriteLimit(ctx.Conn(), time.Time{})
		next(ctx)
	}
}

func setDownstreamWriteLimit(connection net.Conn, deadline time.Time) {
	for connection != nil {
		if setter, ok := connection.(interface{ setWriteDeadlineLimit(time.Time) }); ok {
			setter.setWriteDeadlineLimit(deadline)
			return
		}
		unwrapper, ok := connection.(interface{ NetConn() net.Conn })
		if !ok {
			return
		}
		next := unwrapper.NetConn()
		if next == connection {
			return
		}
		connection = next
	}
}
