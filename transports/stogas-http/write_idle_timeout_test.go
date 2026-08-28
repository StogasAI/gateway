package stogashttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestWriteIdleTimeoutRefreshesForEveryWrite(t *testing.T) {
	connection := &deadlineRecordingConn{}
	timeout := time.Minute
	wrapped := &writeIdleTimeoutConn{Conn: connection, timeout: timeout}

	startedAt := time.Now()
	if _, err := wrapped.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if len(connection.deadlines) != 2 {
		t.Fatalf("write deadline count = %d, want 2", len(connection.deadlines))
	}
	for _, deadline := range connection.deadlines {
		remaining := deadline.Sub(startedAt)
		if remaining <= 0 || remaining > timeout+time.Second {
			t.Fatalf("write deadline remaining = %s, want within %s", remaining, timeout)
		}
	}
}

func TestWriteIdleTimeoutHonorsAbsoluteDeliveryLimit(t *testing.T) {
	connection := &deadlineRecordingConn{}
	wrapped := &writeIdleTimeoutConn{Conn: connection, timeout: time.Minute}
	limit := time.Now().Add(time.Second)

	setDownstreamWriteLimit(wrapped, limit)
	if _, err := wrapped.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if len(connection.deadlines) != 1 || !connection.deadlines[0].Equal(limit) {
		t.Fatalf("write deadline = %v, want absolute limit %v", connection.deadlines, limit)
	}
}

func TestSetDownstreamWriteLimitUnwrapsTLS(t *testing.T) {
	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	raw := &writeIdleTimeoutConn{Conn: serverConnection, timeout: time.Minute}
	secured := tls.Server(raw, &tls.Config{})
	limit := time.Now().Add(time.Minute)

	setDownstreamWriteLimit(secured, limit)
	raw.limitMu.RLock()
	got := raw.limit
	raw.limitMu.RUnlock()
	if !got.Equal(limit) {
		t.Fatalf("TLS write deadline limit = %s, want %s", got, limit)
	}
}

func TestRequestContextSetsAbsoluteDownstreamDeliveryLimit(t *testing.T) {
	raw := &writeIdleTimeoutConn{Conn: &deadlineRecordingConn{}, timeout: downstreamWriteIdleTimeout}
	ctx := &fasthttp.RequestCtx{}
	ctx.Init2(raw, nil, false)

	_, _, cancel, err := newRequestContext(ctx, testResolution(), apiCredential{Raw: "sk-test"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	raw.limitMu.RLock()
	limit := raw.limit
	raw.limitMu.RUnlock()
	remaining := time.Until(limit)
	if remaining <= billing.GatewayRequestLifetime || remaining > billing.GatewayRequestLifetime+downstreamWriteIdleTimeout+time.Second {
		t.Fatalf("downstream delivery limit remaining = %s, want request lifetime plus final delivery window", remaining)
	}
}

func TestWriteIdleTimeoutBoundsNonReadingClientDuringShutdown(t *testing.T) {
	const timeout = 25 * time.Millisecond

	requestStarted := make(chan struct{})
	server := &fasthttp.Server{Handler: func(ctx *fasthttp.RequestCtx) {
		close(requestStarted)
		ctx.Response.SetBodyStream(bytes.NewReader(make([]byte, 1<<20)), -1)
	}}
	listener := fasthttputil.NewInmemoryListener()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(withWriteIdleTimeout(listener, timeout))
	}()

	connection, err := listener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		_ = listener.Close()
	})
	if _, err := connection.Write([]byte("GET / HTTP/1.1\r\nHost: gateway.test\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request handler did not start")
	}

	shutdownCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	startedAt := time.Now()
	if err := server.ShutdownWithContext(shutdownCtx); err != nil {
		t.Fatalf("shutdown waited for its outer context instead of the write idle timeout: %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed >= time.Second {
		t.Fatalf("shutdown elapsed = %s, want less than outer context", elapsed)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("fasthttp Serve returned an error during shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fasthttp Serve did not stop")
	}
}

type deadlineRecordingConn struct {
	net.Conn
	deadlines []time.Time
}

func (c *deadlineRecordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *deadlineRecordingConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}
