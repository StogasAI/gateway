package stogashttp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	proxyproto "github.com/pires/go-proxyproto"
)

func TestMemoryPressureClosesOldestSocketWithoutRequest(t *testing.T) {
	memory := &requestMemoryAdmission{budget: 3 * connectionRetainedBytes}
	var idle idleConnections
	open := func() (*ingressTLSConn, net.Conn) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		conn := &ingressTLSConn{Conn: tls.Server(server, &tls.Config{})}
		release, ok := memory.confidentialReservation(connectionRetainedBytes)()
		if !ok || !conn.hold(release) {
			t.Fatal("socket admission failed")
		}
		idle.track(conn)
		return conn, client
	}
	closed := func(peer net.Conn) bool {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		_, err := peer.Read(make([]byte, 1))
		return errors.Is(err, io.EOF)
	}
	running, runningPeer := open()
	reading, readingPeer := open()
	waiting, waitingPeer := open()
	idle.busy(withHTTPConnection(context.Background(), running))
	// Request headers still arriving do not protect a socket.
	idle.observe(reading, http.StateActive)
	if idle.reclaim() != connectionRetainedBytes || !closed(readingPeer) {
		t.Fatal("pressure did not close the oldest socket without a request")
	}
	if idle.reclaim() != connectionRetainedBytes || !closed(waitingPeer) {
		t.Fatal("pressure skipped a socket without a request")
	}
	if idle.reclaim() != 0 || memory.reserved.Load() != connectionRetainedBytes {
		t.Fatal("pressure closed a socket running a request")
	}
	idle.observe(running, http.StateIdle)
	// A repeated idle report must not move the socket or add an entry.
	idle.observe(running, http.StateIdle)
	if idle.reclaim() != connectionRetainedBytes || !closed(runningPeer) || idle.reclaim() != 0 {
		t.Fatal("finished request kept its socket from reclaim")
	}
	// net/http closes evicted sockets again later; memory returns only once.
	for _, conn := range []*ingressTLSConn{running, reading, waiting} {
		_ = conn.Close()
		idle.observe(conn, http.StateClosed)
	}
	if memory.reserved.Load() != 0 || len(idle.tracked) != 0 || idle.oldest.Len() != 0 || idle.evicted != 3 {
		t.Fatal("socket tracking or memory leaked")
	}
}

func TestStalledSocketsCannotKeepClientsOut(t *testing.T) {
	gateway := &Server{
		config:      stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure:      &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
		ipAdmission: newIPAdmission(),
		// Room for two sockets and one request.
		memory: &requestMemoryAdmission{budget: 2*connectionRetainedBytes + requestRetainedBytes},
	}
	gateway.memory.reclaim = gateway.reclaimIdleMemory
	if err := gateway.routes(); err != nil {
		t.Fatal(err)
	}
	gateway.server.Handler = requestHandler(gateway.publicRequests(func(ctx *requestContext) {
		_, _ = io.WriteString(ctx.writer, "ok")
	}))
	listener := testListener(t)
	t.Cleanup(func() { _ = gateway.server.Close() })
	go func() { _ = gateway.server.Serve(gateway.wrapListener(listener)) }()
	dial := func(ctx context.Context, source string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		address, _ := net.ResolveTCPAddr("tcp", source)
		if _, err := proxyproto.HeaderProxyFromAddrs(2, address, conn.RemoteAddr()).WriteTo(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
	// Sockets that send their PROXY header and never start TLS.
	stall := func(source string) net.Conn {
		conn, err := dial(t.Context(), source)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	open := func(conn net.Conn, wait time.Duration) bool {
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		_, err := conn.Read(make([]byte, 1))
		var timeout net.Error
		return errors.As(err, &timeout) && timeout.Timeout()
	}
	charged := func(sockets int64) {
		for start := time.Now(); gateway.memory.reserved.Load() != sockets*connectionRetainedBytes; time.Sleep(time.Millisecond) {
			if time.Since(start) > 5*time.Second {
				t.Fatal("stalled sockets were not charged")
			}
		}
	}
	// Each socket is charged and ordered on its own goroutine, so wait for the
	// first charge before opening the socket that must be newer.
	oldest := stall("192.0.2.30:1000")
	charged(1)
	newer := stall("192.0.2.31:1000")
	charged(2)
	// A source over its setup allowance is refused before its memory charge,
	// so it cannot make the gateway close anyone else's socket.
	exhaustedAt := time.Now().Add(time.Hour)
	for range ipSetupBurst {
		_, _ = gateway.ipAdmission.allow("192.0.2.40:1000", true, exhaustedAt)
	}
	if refused := stall("192.0.2.40:1000"); open(refused, 2*time.Second) {
		t.Fatal("source over its setup allowance was admitted")
	}
	if !open(oldest, 50*time.Millisecond) || !open(newer, 50*time.Millisecond) {
		t.Fatal("refused source displaced another socket")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx, "192.0.2.50:1000")
		},
	}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("client behind stalled sockets: %d %q %v", response.StatusCode, body, err)
	}
	if open(oldest, 2*time.Second) || !open(newer, 50*time.Millisecond) {
		t.Fatal("new client did not displace exactly the oldest stalled socket")
	}
}
