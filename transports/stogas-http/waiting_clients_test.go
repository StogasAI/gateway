package stogashttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// A client that writes HTTP/2 frames itself, so it can stop reading responses
// or stop sending a request body.
type stalledHTTP2Client struct {
	mu     sync.Mutex
	framer *http2.Framer
	frames chan http2.Frame
}

// window is the response window per stream; zero stops every response body.
func dialStalledHTTP2(t *testing.T, address string, window uint32) *stalledHTTP2Client {
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
	client.framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	client.write(t, func(f *http2.Framer) error {
		return f.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: window})
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
			case *http2.MetaHeadersFrame, *http2.RSTStreamFrame, *http2.WindowUpdateFrame, *http2.GoAwayFrame:
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

func (c *stalledHTTP2Client) request(t *testing.T, stream uint32, method, path string, endStream bool, fields ...hpack.HeaderField) {
	t.Helper()
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range append([]hpack.HeaderField{{Name: ":method", Value: method}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "gateway.test"}, {Name: ":path", Value: path}}, fields...) {
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

// proxiedClient sends each connection's PROXY header from a separate address.
func proxiedClient(t *testing.T) *http.Client {
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
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

// status returns the response status that a stream received, or 0 if none
// arrives in time.
func (c *stalledHTTP2Client) status(stream uint32, wait time.Duration) string {
	frame := c.next(wait, func(frame http2.Frame) bool {
		headers, ok := frame.(*http2.MetaHeadersFrame)
		return ok && headers.StreamID == stream
	})
	if frame == nil {
		return ""
	}
	return frame.(*http2.MetaHeadersFrame).PseudoValue("status")
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
	stalled := dialStalledHTTP2(t, listener.Addr().String(), 0)
	waitingWrites := func() int {
		gateway.waitingClients.mu.Lock()
		defer gateway.waitingClients.mu.Unlock()
		return gateway.waitingClients.writes.Len()
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

	response, err := proxiedClient(t).Get("https://" + listener.Addr().String() + "/fresh")
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
	gateway.waitingClients.mu.Lock()
	ended := gateway.waitingClients.ended
	gateway.waitingClients.mu.Unlock()
	if ended != 1 || gateway.publicConnections.snapshot(0).ActiveHandlers != 1 {
		t.Fatalf("ended %d responses; %d handlers remain", ended, gateway.publicConnections.snapshot(0).ActiveHandlers)
	}
}

func TestMemoryPressureEndsTheSlowestUpload(t *testing.T) {
	gateway := &Server{
		config: stogas.Config{MaxRequestBodyMiB: 1, Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure: &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
		// Two sockets, three requests and two bodies: a third body needs the
		// memory of one stalled upload.
		memory: &requestMemoryAdmission{budget: 2*connectionRetainedBytes + 3*requestRetainedBytes + 2*minimumRequestWeightBytes},
	}
	gateway.memory.reclaim = gateway.reclaimIdleMemory
	if err := gateway.routes(); err != nil {
		t.Fatal(err)
	}
	gateway.server.Handler = gateway.publicConnections.handler(requestHandler(gateway.publicRequests(gateway.requestBodyAdmission(func(ctx *requestContext) {
		gateway.writeResponse(ctx, http.StatusOK, "text/plain", ctx.body)
	}))))
	listener := testListener(t)
	t.Cleanup(func() { _ = gateway.server.Close() })
	go func() { _ = gateway.server.Serve(gateway.wrapListener(listener)) }()
	path := mustCatalogPath(t, catalog.RouteChat)
	stalled := dialStalledHTTP2(t, listener.Addr().String(), 65535)
	fields := []hpack.HeaderField{{Name: "authorization", Value: "Bearer test-key"}, {Name: "content-type", Value: "application/json"}}
	stalled.request(t, 1, "POST", path, false, fields...)
	stalled.request(t, 3, "POST", path, false, fields...)
	stalled.write(t, func(f *http2.Framer) error { return f.WriteData(3, false, make([]byte, 4096)) })
	for start := time.Now(); ; time.Sleep(time.Millisecond) {
		gateway.waitingClients.mu.Lock()
		waiting, received := len(gateway.waitingClients.uploads), int64(0)
		for _, upload := range gateway.waitingClients.uploads {
			received += upload.received.Load()
		}
		gateway.waitingClients.mu.Unlock()
		if waiting == 2 && received == 4096 {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("uploads did not start waiting on the client")
		}
	}

	request, err := http.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+path, strings.NewReader(`{"fresh":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-key")
	request.Header.Set("Content-Type", "application/json")
	response, err := proxiedClient(t).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != `{"fresh":true}` {
		t.Fatalf("new request behind stalled uploads: %d %q %v", response.StatusCode, body, err)
	}
	if status := stalled.status(1, 2*time.Second); status != "503" {
		t.Fatalf("slowest upload answered %q, want 503", status)
	}
	stalled.write(t, func(f *http2.Framer) error { return f.WriteData(3, true, []byte("{}")) })
	if status := stalled.status(3, 2*time.Second); status != "200" {
		t.Fatalf("faster upload answered %q, want 200", status)
	}
	gateway.waitingClients.mu.Lock()
	ended := gateway.waitingClients.ended
	gateway.waitingClients.mu.Unlock()
	if ended != 1 {
		t.Fatalf("pressure ended %d uploads, want 1", ended)
	}
}

// Encrypted requests reach the organization bucket only after their first
// record, so pressure must also end one that stalls before it.
func TestMemoryPressureEndsEncryptedUploadBeforeItsFirstRecord(t *testing.T) {
	f := newSessionHTTPFixture(t, func(*requestContext) { t.Error("stalled request reached dispatch") }, true)
	endpoint := httptest.NewUnstartedServer(f.server.publicRequests(f.server.ipRequestAdmission(f.server.sessionTransport(func(*requestContext) {
		t.Error("stalled request reached dispatch")
	}))))
	endpoint.EnableHTTP2 = true
	endpoint.StartTLS()
	t.Cleanup(endpoint.Close)
	metadata, err := json.Marshal(sessionRequestMetadata{Method: http.MethodPost, Path: "/v1/chat/completions", Headers: map[string]string{"Authorization": "Bearer test", "Content-Type": "application/json"}})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := f.request(t, metadata, []byte("{}"))
	baseline := f.server.memory.reserved.Load()
	body, upload := io.Pipe()
	t.Cleanup(func() { _ = upload.Close() })
	request, err := http.NewRequest(http.MethodPost, endpoint.URL+sessionPath, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", sessionContentType)
	request.Header.Set(sessionNodeHeader, f.server.sessionNodeID)
	responses := make(chan *http.Response, 1)
	go func() {
		response, err := endpoint.Client().Do(request)
		if err != nil {
			t.Error(err)
		}
		responses <- response
	}()
	if _, err := upload.Write(wire[:channel.RequestPrefixBytes/2]); err != nil {
		t.Fatal(err)
	}
	for start := time.Now(); ; time.Sleep(time.Millisecond) {
		f.server.waitingClients.mu.Lock()
		waiting := len(f.server.waitingClients.uploads)
		f.server.waitingClients.mu.Unlock()
		if waiting == 1 {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("encrypted upload did not start waiting on the client")
		}
	}

	pressure := f.server.memory.budgetBytes() - f.server.memory.reserved.Load() + 1
	if !f.server.memory.reserve(requestLifetimeMemory, pressure) {
		t.Fatal("pressure did not end the stalled encrypted upload")
	}
	f.server.memory.release(requestLifetimeMemory, pressure)
	response := <-responses
	if response == nil {
		return
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Retry-After") != "1" {
		t.Fatalf("ended encrypted upload answered %d with Retry-After %q", response.StatusCode, response.Header.Get("Retry-After"))
	}
	for start := time.Now(); f.server.memory.reserved.Load() != baseline; time.Sleep(time.Millisecond) {
		if time.Since(start) > 5*time.Second {
			t.Fatalf("ended encrypted upload left %d bytes charged", f.server.memory.reserved.Load()-baseline)
		}
	}
}

// stalledHTTP1Upload starts an HTTP/1 upload that declares a body and never
// sends it, and returns the client side of its socket.
func stalledHTTP1Upload(t *testing.T, gateway *Server) net.Conn {
	t.Helper()
	listener := &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
	server := &http.Server{ReadTimeout: serverReadTimeout, Handler: requestHandler(gateway.publicRequests(gateway.requestBodyAdmission(func(*requestContext) {
		t.Error("stalled upload finished")
	})))}
	go func() { _ = server.Serve(listener) }()
	client, conn := net.Pipe()
	listener.conns <- conn
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		synctest.Wait()
		if reserved := gateway.memory.reserved.Load(); reserved != 0 {
			t.Errorf("upload left %d bytes charged", reserved)
		}
	})
	if _, err := io.WriteString(client, "POST "+mustCatalogPath(t, catalog.RouteChat)+" HTTP/1.1\r\nHost: gateway.test\r\nAuthorization: Bearer test-key\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	return client
}

// readFinalResponse returns the status of the one response the socket carries
// before it closes.
func readFinalResponse(t *testing.T, client net.Conn) int {
	t.Helper()
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("socket stayed open after the ended upload: %v", err)
	}
	return response.StatusCode
}

func TestMemoryPressureEndsHTTP1Upload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gateway := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}, memory: &requestMemoryAdmission{budget: requestRetainedBytes + minimumRequestWeightBytes}}
		gateway.memory.reclaim = gateway.reclaimIdleMemory
		client := stalledHTTP1Upload(t, gateway)
		if !gateway.memory.reserve(requestLifetimeMemory, minimumRequestWeightBytes) {
			t.Fatal("pressure did not end the stalled upload")
		}
		defer gateway.memory.release(requestLifetimeMemory, minimumRequestWeightBytes)
		if status := readFinalResponse(t, client); status != http.StatusServiceUnavailable {
			t.Fatalf("ended upload answered %d, want 503", status)
		}
	})
}

func TestUploadPastReadTimeoutAnswers408(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gateway := &Server{config: stogas.Config{MaxRequestBodyMiB: 1}, memory: &requestMemoryAdmission{}}
		client := stalledHTTP1Upload(t, gateway)
		time.Sleep(serverReadTimeout)
		if status := readFinalResponse(t, client); status != http.StatusRequestTimeout {
			t.Fatalf("late upload answered %d, want 408", status)
		}
	})
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
