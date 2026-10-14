package stogashttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// A client that opens HTTP/2 streams but grants no response window.
type stalledHTTP2Client struct {
	mu     sync.Mutex
	framer *http2.Framer
	frames chan http2.Frame
}

func dialStalledHTTP2(t *testing.T, address string) *stalledHTTP2Client {
	t.Helper()
	raw, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 60), Port: 1000}, raw.RemoteAddr()).WriteTo(raw); err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err := conn.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	client := &stalledHTTP2Client{framer: http2.NewFramer(conn, conn), frames: make(chan http2.Frame, 64)}
	client.write(t, func(f *http2.Framer) error {
		return f.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
	})
	go func() {
		defer close(client.frames)
		for {
			frame, err := client.framer.ReadFrame()
			if err != nil {
				return
			}
			if settings, ok := frame.(*http2.SettingsFrame); ok && !settings.IsAck() {
				client.mu.Lock()
				_ = client.framer.WriteSettingsAck()
				client.mu.Unlock()
				continue
			}
			switch frame.(type) {
			case *http2.HeadersFrame, *http2.RSTStreamFrame, *http2.WindowUpdateFrame, *http2.GoAwayFrame:
				client.frames <- frame
			}
		}
	}()
	return client
}

func (c *stalledHTTP2Client) write(t *testing.T, write func(*http2.Framer) error) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := write(c.framer); err != nil {
		t.Fatal(err)
	}
}

func (c *stalledHTTP2Client) request(t *testing.T, stream uint32, method, path string, endStream bool) {
	t.Helper()
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: method}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "gateway.test"}, {Name: ":path", Value: path}} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	c.write(t, func(f *http2.Framer) error {
		return f.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: endStream})
	})
}

// next returns the next frame that matches, or nil if none arrives in time.
func (c *stalledHTTP2Client) next(wait time.Duration, match func(http2.Frame) bool) http2.Frame {
	timeout := time.After(wait)
	for {
		select {
		case frame, ok := <-c.frames:
			if !ok {
				return nil
			}
			if match(frame) {
				return frame
			}
		case <-timeout:
			return nil
		}
	}
}

func TestMemoryPressureEndsOnlyUnpaidResponsesWaitingOnClients(t *testing.T) {
	gateway := &Server{
		config: stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure: &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
		// Two sockets, the two stalled requests and nothing more.
		memory: &requestMemoryAdmission{budget: 2*connectionRetainedBytes + 2*requestRetainedBytes},
	}
	gateway.memory.reclaim = gateway.reclaimIdleMemory
	if err := gateway.routes(); err != nil {
		t.Fatal(err)
	}
	gateway.server.Handler = gateway.publicConnections.handler(requestHandler(gateway.publicRequests(func(ctx *requestContext) {
		switch ctx.request.URL.Path {
		case "/paid":
			ctx.markPaid()
		case "/upload":
			closeUnreadRequest(ctx)
		}
		gateway.writeResponse(ctx, http.StatusOK, "text/plain", []byte(ctx.request.URL.Path))
	})))
	listener := testListener(t)
	t.Cleanup(func() { _ = gateway.server.Close() })
	go func() { _ = gateway.server.Serve(gateway.wrapListener(listener)) }()
	stalled := dialStalledHTTP2(t, listener.Addr().String())
	waitingWrites := func() int {
		gateway.waitingResponses.mu.Lock()
		defer gateway.waitingResponses.mu.Unlock()
		return gateway.waitingResponses.oldest.Len()
	}
	stalled.request(t, 1, "GET", "/paid", true)
	stalled.request(t, 3, "POST", "/upload", false)
	for start := time.Now(); waitingWrites() != 1 || gateway.publicConnections.snapshot(0).ActiveHandlers != 2; time.Sleep(time.Millisecond) {
		if time.Since(start) > 5*time.Second {
			t.Fatal("responses did not start waiting on the client")
		}
	}
	// The rejected upload no longer buffers: the gateway returns its window.
	for stalled.next(100*time.Millisecond, func(http2.Frame) bool { return true }) != nil {
	}
	stalled.write(t, func(f *http2.Framer) error { return f.WriteData(3, false, make([]byte, 4096)) })
	if stalled.next(2*time.Second, func(frame http2.Frame) bool {
		update, ok := frame.(*http2.WindowUpdateFrame)
		return ok && update.StreamID == 0 && update.Increment >= 4096
	}) == nil {
		t.Fatal("rejected upload data stayed buffered")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err == nil {
				_, err = proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 61), Port: 1000}, conn.RemoteAddr()).WriteTo(conn)
			}
			return conn, err
		},
	}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://" + listener.Addr().String() + "/fresh")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "/fresh" {
		t.Fatalf("new request behind waiting responses: %q %v", body, err)
	}
	if stalled.next(2*time.Second, func(frame http2.Frame) bool {
		reset, ok := frame.(*http2.RSTStreamFrame)
		return ok && reset.StreamID == 3
	}) == nil {
		t.Fatal("pressure did not end the unpaid response")
	}
	if frame := stalled.next(200*time.Millisecond, func(frame http2.Frame) bool {
		_, reset := frame.(*http2.RSTStreamFrame)
		_, away := frame.(*http2.GoAwayFrame)
		return reset || away
	}); frame != nil {
		t.Fatalf("pressure ended the paid response: %v", frame)
	}
	gateway.waitingResponses.mu.Lock()
	reset := gateway.waitingResponses.reset
	gateway.waitingResponses.mu.Unlock()
	if reset != 1 || gateway.publicConnections.snapshot(0).ActiveHandlers != 1 {
		t.Fatalf("ended %d responses; %d handlers remain", reset, gateway.publicConnections.snapshot(0).ActiveHandlers)
	}
}

type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestHTTP1ResponseEndCannotWaitForever(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gateway := &Server{memory: &requestMemoryAdmission{budget: requestRetainedBytes}}
		listener := &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
		// net/http writes this response after the handler returns.
		server := &http.Server{Handler: requestHandler(gateway.publicRequests(func(ctx *requestContext) {
			ctx.writer.WriteHeader(http.StatusNoContent)
		}))}
		go func() { _ = server.Serve(listener) }()
		client, conn := net.Pipe()
		listener.conns <- conn
		if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: gateway.test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(downstreamWriteIdleTimeout + time.Second)
		// The unread response end failed at its deadline and closed the socket.
		if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("response end still waiting: %v", err)
		}
		_ = client.Close()
		_ = server.Close()
		if gateway.memory.reserved.Load() != 0 {
			t.Fatal("request charge leaked")
		}
	})
}
