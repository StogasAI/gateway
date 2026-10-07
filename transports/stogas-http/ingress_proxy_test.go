package stogashttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	proxyproto "github.com/pires/go-proxyproto"
)

func TestProxyIngressPreservesClientAddressThroughTLSAndHTTP2(t *testing.T) {
	gateway := &Server{
		config: stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure: &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
	}
	if err := gateway.routes(); err != nil {
		t.Fatal(err)
	}
	gateway.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.RemoteAddr)
	})
	listener := testListener(t)
	const setupBudget = 250 * time.Millisecond
	shortenProxyTestDeadline(gateway.server, setupBudget)
	t.Cleanup(func() { _ = gateway.server.Close() })
	go func() { _ = gateway.server.Serve(gateway.wrapListener(listener)) }()
	for _, clientIP := range []string{"192.0.2.10", "2001:db8::10"} {
		t.Run(clientIP, func(t *testing.T) {
			source := &net.TCPAddr{IP: net.ParseIP(clientIP), Port: 12345}
			destination := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
			if source.IP.To4() == nil {
				destination.IP = net.ParseIP("2001:db8::1")
			}
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
					if err != nil {
						return nil, err
					}
					if _, err := proxyproto.HeaderProxyFromAddrs(2, source, destination).WriteTo(conn); err != nil {
						_ = conn.Close()
						return nil, err
					}
					return conn, nil
				},
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for attempt := range 2 {
				if attempt == 1 {
					// The setup context must end at handshake completion, without
					// imposing its deadline on a warm HTTP/2 connection.
					time.Sleep(2 * setupBudget)
				}
				request, _ := http.NewRequestWithContext(t.Context(), "GET", "https://"+listener.Addr().String(), nil)
				request.Header.Set("X-Forwarded-For", "203.0.113.99")
				request.Header.Set("Forwarded", "for=203.0.113.99")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.ProtoMajor != 2 || string(body) != source.String() {
					t.Fatalf("forwarded address %q over %s: %v", body, response.Proto, err)
				}
			}
		})
	}
}

// Exercise connection-derived identity and the actual HTTP admission wrapper
// together, including an exhausted source reconnecting through the same proxy.
func TestProxyIngressAdmissionIsolatesSourcesAcrossReuseAndReconnect(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			gateway := &Server{
				config:      stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
				secure:      &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
				ipAdmission: newIPAdmission(),
			}
			if err := gateway.routes(); err != nil {
				t.Fatal(err)
			}
			gateway.server.Handler = gateway.ipRequestAdmission(func(ctx *requestContext) {
				_, _ = io.WriteString(ctx.writer, ctx.request.RemoteAddr)
			})
			listener := testListener(t)
			t.Cleanup(func() { _ = gateway.server.Close() })
			go func() { _ = gateway.server.Serve(gateway.wrapListener(listener)) }()
			clients := make([]*http.Client, 2)
			transports := make([]*http.Transport, 2)
			sources := []string{"192.0.2.10:12345", "192.0.2.11:12345"}
			for i, source := range sources {
				address, _ := net.ResolveTCPAddr("tcp", source)
				transport := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: h2,
					DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
						conn, err := (&net.Dialer{}).DialContext(ctx, network, target)
						if err != nil {
							return nil, err
						}
						if _, err := proxyproto.HeaderProxyFromAddrs(2, address, listener.Addr()).WriteTo(conn); err != nil {
							_ = conn.Close()
							return nil, err
						}
						return conn, nil
					},
				}
				transports[i] = transport
				clients[i] = &http.Client{Transport: transport, Timeout: 5 * time.Second}
				t.Cleanup(transport.CloseIdleConnections)
			}
			request := func(source, status int, reused bool) {
				t.Helper()
				var connection httptrace.GotConnInfo
				ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { connection = info }})
				req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+listener.Addr().String(), nil)
				req.Header.Set("X-Forwarded-For", "192.0.2.11")
				req.Header.Set("Forwarded", "for=192.0.2.11")
				response, err := clients[source].Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				protocol := 1
				if h2 {
					protocol = 2
				}
				if err != nil || response.StatusCode != status || response.ProtoMajor != protocol || connection.Reused != reused {
					t.Fatalf("source %s: status %d / %s, reused %v: %v", sources[source], response.StatusCode, response.Proto, connection.Reused, err)
				}
				if status == http.StatusOK && string(body) != sources[source] {
					t.Fatalf("source changed: %s", body)
				}
			}
			request(0, http.StatusOK, false)
			request(1, http.StatusOK, false)
			// Move this bucket's clock forward to keep its depletion deterministic
			// during real network I/O; no production clock hook or traffic flood.
			exhaustedAt := time.Now().Add(time.Hour)
			for range ipRequestBurst {
				_, _ = gateway.ipAdmission.allow(sources[0], false, exhaustedAt)
			}
			request(0, http.StatusTooManyRequests, true)
			request(1, http.StatusOK, true)
			transports[0].CloseIdleConnections()
			request(0, http.StatusTooManyRequests, false)
			request(1, http.StatusOK, true)
			if got := gateway.ipAdmission.diagnostics(); got.Entries != 2 || got.Request.Rejected != 2 {
				t.Fatalf("source buckets merged or reset: %+v", got)
			}
		})
	}
}

func TestProxyIngressRejectsMissingLegacyLocalAndDatagramHeaders(t *testing.T) {
	source, destination := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	for _, kind := range []string{"missing", "v1", "local", "datagram", "truncated", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			listener := testListener(t)
			defer listener.Close()
			proxy := proxyIngress(listener)
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// Accept never waits for a client's header, so one silent client
			// cannot block admission of all following connections.
			server, err := proxy.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			header := proxyproto.HeaderProxyFromAddrs(2, source, destination)
			switch kind {
			case "v1":
				header.Version = 1
			case "local":
				header.Command = proxyproto.LOCAL
			case "datagram":
				header.TransportProtocol = proxyproto.UDPv4
				header.SourceAddr = &net.UDPAddr{IP: source.IP, Port: source.Port}
				header.DestinationAddr = &net.UDPAddr{IP: destination.IP, Port: destination.Port}
			}
			var encoded bytes.Buffer
			if _, err := header.WriteTo(&encoded); err != nil {
				t.Fatal(err)
			}
			payload := encoded.Bytes()
			if kind == "missing" {
				payload = []byte("GET / HTTP/1.1\r\n\r\n")
			}
			if kind == "truncated" {
				payload = payload[:15]
			}
			if kind == "oversized" {
				payload = payload[:16]
				payload[14], payload[15] = 0xff, 0xff
			}
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			if kind != "oversized" {
				_ = client.(*net.TCPConn).CloseWrite()
			}
			_ = server.SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			_, err = server.Read(one[:])
			if err == nil {
				t.Fatal("invalid ingress header accepted")
			}
			if kind == "oversized" && !errors.Is(err, proxyproto.ErrInvalidLength) {
				t.Fatalf("oversized header was not rejected before reading its payload: %v", err)
			}
		})
	}
}

func TestProxyIngressIsolatesStalledAndMalformedConnections(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "stalled", true: "malformed"}[malformed], func(t *testing.T) {
			gateway := &Server{
				config: stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
				secure: &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
			}
			if err := gateway.routes(); err != nil {
				t.Fatal(err)
			}
			gateway.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, r.RemoteAddr)
			})
			listener := testListener(t)
			t.Cleanup(func() { _ = gateway.server.Close() })
			go func() { _ = gateway.server.Serve(gateway.wrapListener(listener)) }()
			bad, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer bad.Close()
			payload := []byte("\r\n\r\n\x00\r\nQUIT\n")[:6]
			if malformed {
				payload = []byte("not a PROXY header\r\n")
			}
			if _, err := bad.Write(payload); err != nil {
				t.Fatal(err)
			}
			if malformed {
				_ = bad.SetReadDeadline(time.Now().Add(2 * time.Second))
				var one [1]byte
				_, err := bad.Read(one[:])
				if err == nil {
					t.Fatal("malformed connection remained usable")
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("malformed connection was not closed")
				}
			}
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
					if err != nil {
						return nil, err
					}
					source := &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 12345}
					header := proxyproto.HeaderProxyFromAddrs(2, source, conn.RemoteAddr())
					if _, err := header.WriteTo(conn); err != nil {
						_ = conn.Close()
						return nil, err
					}
					return conn, nil
				},
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			response, err := client.Get("https://" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.ProtoMajor != 2 || string(body) != "192.0.2.20:12345" {
				t.Fatalf("healthy client after bad connection: %s %q %v", response.Proto, body, err)
			}
		})
	}
}

func TestProxyIngressAndTLSShareAcceptanceDeadline(t *testing.T) {
	gateway := &Server{
		config: stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure: &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
	}
	if err := gateway.routes(); err != nil {
		t.Fatal(err)
	}
	listener := testListener(t)
	shortenProxyTestDeadline(gateway.server, 250*time.Millisecond)
	accepted := make(chan time.Time, 1)
	connContext := gateway.server.ConnContext
	gateway.server.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		ctx = connContext(ctx, conn)
		accepted <- conn.(*ingressTLSConn).deadline
		return ctx
	}
	t.Cleanup(func() { _ = gateway.server.Close() })
	go func() { _ = gateway.server.Serve(gateway.wrapListener(listener)) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var header bytes.Buffer
	_, err = proxyproto.HeaderProxyFromAddrs(2, conn.LocalAddr(), conn.RemoteAddr()).WriteTo(&header)
	if err != nil {
		t.Fatal(err)
	}
	deadline := <-accepted
	if _, err := conn.Write(header.Bytes()[:6]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(deadline.Add(-50 * time.Millisecond)))
	if _, err := conn.Write(header.Bytes()[6:]); err != nil {
		t.Fatal(err)
	}
	// Leave TLS silent after spending most of the allowance on PROXY. A
	// fresh net/http TLS timeout would leave this socket open for 30 seconds.
	_ = conn.SetReadDeadline(deadline.Add(500 * time.Millisecond))
	var one [1]byte
	_, err = conn.Read(one[:])
	if err == nil {
		t.Fatal("unfinished TLS remained usable")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("TLS renewed the acceptance-time setup deadline")
	}
}

func shortenProxyTestDeadline(server *http.Server, budget time.Duration) {
	connContext := server.ConnContext
	server.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		secured := conn.(*ingressTLSConn)
		secured.deadline = secured.deadline.Add(budget - sessionSetupBudget)
		_ = secured.SetDeadline(secured.deadline)
		return connContext(ctx, conn)
	}
}
