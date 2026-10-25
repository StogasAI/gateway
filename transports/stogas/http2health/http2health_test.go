package http2health

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// freezer forwards connections to a server. Once frozen, it drops everything
// on the connections it already has, as a network that loses a connection's
// packets does, and still forwards new connections.
type freezer struct {
	listener    net.Listener
	target      string
	connections atomic.Int32
	mu          sync.Mutex
	frozen      chan struct{}
}

func newFreezer(t *testing.T, target string) *freezer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &freezer{listener: listener, target: target, frozen: make(chan struct{})}
	var open sync.WaitGroup
	var conns []net.Conn
	var connsMu sync.Mutex
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			f.connections.Add(1)
			server, err := net.Dial("tcp", target)
			if err != nil {
				_ = client.Close()
				continue
			}
			connsMu.Lock()
			conns = append(conns, client, server)
			connsMu.Unlock()
			f.mu.Lock()
			frozen := f.frozen
			f.mu.Unlock()
			open.Add(2)
			go func() { defer open.Done(); forward(server, client, frozen) }()
			go func() { defer open.Done(); forward(client, server, frozen) }()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		connsMu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		connsMu.Unlock()
		open.Wait()
	})
	return f
}

// freeze silences the connections open now.
func (f *freezer) freeze() {
	f.mu.Lock()
	defer f.mu.Unlock()
	close(f.frozen)
	f.frozen = make(chan struct{})
}

func forward(to, from net.Conn, frozen <-chan struct{}) {
	buffer := make([]byte, 32<<10)
	for {
		n, err := from.Read(buffer)
		select {
		case <-frozen:
			n = 0
		default:
		}
		if n > 0 {
			if _, writeErr := to.Write(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			_ = to.Close()
			return
		}
	}
}

func TestSilentConnectionClosesSoTheNextRequestGetsANewOne(t *testing.T) {
	t.Parallel()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	proxy := newFreezer(t, server.Listener.Addr().String())
	transport := &http.Transport{
		TLSClientConfig:   server.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
		ForceAttemptHTTP2: true,
		HTTP2:             Config(),
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	get := func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+proxy.listener.Addr().String(), nil)
		if err != nil {
			return "", err
		}
		response, err := client.Do(request)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		if response.ProtoMajor != 2 {
			t.Fatalf("got HTTP/%d.%d, want HTTP/2", response.ProtoMajor, response.ProtoMinor)
		}
		body, err := io.ReadAll(response.Body)
		return string(body), err
	}

	if body, err := get(); body != "ok" || err != nil || proxy.connections.Load() != 1 {
		t.Fatalf("first request: %q %v, %d connections", body, err, proxy.connections.Load())
	}
	proxy.freeze()
	started := time.Now()
	if _, err := get(); err == nil {
		t.Fatal("a request over the silent connection succeeded")
	}
	if waited := time.Since(started); waited > quietTime+answerTime+2*time.Second {
		t.Fatalf("the silent connection closed after %s", waited)
	}
	if body, err := get(); body != "ok" || err != nil || proxy.connections.Load() != 2 {
		t.Fatalf("request after the silent connection: %q %v, %d connections", body, err, proxy.connections.Load())
	}
}
