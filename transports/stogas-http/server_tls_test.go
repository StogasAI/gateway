package stogashttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestGatewayTLSNegotiatesHTTP2AndDrainsActiveResponse(t *testing.T) {
	gateway := &Server{
		config:   stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure:   &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
		requests: newRequestDrain(),
	}
	if err := gateway.routes(); err != nil {
		t.Fatal(err)
	}
	finish := make(chan struct{})
	var finishOnce sync.Once
	defer finishOnce.Do(func() { close(finish) })
	gateway.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !gateway.requests.begin() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}
		defer gateway.requests.end()
		writer := &responseWriter{writer: w, control: http.NewResponseController(w), idle: time.Second}
		_, _ = writer.Write([]byte("before"))
		select {
		case <-finish:
		case <-r.Context().Done():
			return
		}
		_, _ = writer.Write([]byte("after"))
	})
	listener := testListener(t)
	limited := &publicListener{Listener: listener, slots: make(chan struct{}, 1), idle: &gateway.idleConnections}
	serveDone := make(chan error, 1)
	go func() { serveDone <- gateway.server.Serve(gateway.wrapListener(limited)) }()
	t.Cleanup(func() { _ = gateway.server.Close() })
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := proxyproto.HeaderProxyFromAddrs(2, raw.LocalAddr(), raw.RemoteAddr()).WriteTo(raw); err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err := conn.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("gateway listener did not negotiate HTTP/2")
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "gateway.test"}, {Name: ":path", Value: "/"}} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if settings, ok := frame.(*http2.SettingsFrame); ok && !settings.IsAck() {
			if err := framer.WriteSettingsAck(); err != nil {
				t.Fatal(err)
			}
		}
		if data, ok := frame.(*http2.DataFrame); ok && string(data.Data()) == "before" {
			break
		}
	}
	shutdownContext, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	// Saturation cannot evict the connection carrying this unfinished H2 stream.
	candidate, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = candidate.SetReadDeadline(time.Now().Add(time.Second))
	var rejected [1]byte
	_, rejectErr := candidate.Read(rejected[:])
	_ = candidate.Close()
	if !errors.Is(rejectErr, io.EOF) {
		t.Fatalf("full active pool did not reject new socket: %v", rejectErr)
	}
	gateway.idleConnections.mu.Lock()
	evicted, refused := gateway.idleConnections.evicted, gateway.idleConnections.rejected
	gateway.idleConnections.mu.Unlock()
	if evicted != 0 || refused != 1 {
		t.Fatalf("pressure evicted active work: %d/%d", evicted, refused)
	}
	defer cancel()
	shutdownDone := make(chan struct{})
	go func() { gateway.shutdownWithContext(shutdownContext); close(shutdownDone) }()
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if goaway, ok := frame.(*http2.GoAwayFrame); ok {
			if goaway.ErrCode != http2.ErrCodeNo || goaway.LastStreamID != 1 {
				t.Fatalf("unexpected GOAWAY: %v", goaway)
			}
			break
		}
	}
	if gateway.requests.begin() {
		t.Fatal("shutdown admitted new work")
	}
	select {
	case <-shutdownDone:
		t.Fatal("shutdown abandoned active response")
	default:
	}
	finishOnce.Do(func() { close(finish) })
	var tail bytes.Buffer
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if data, ok := frame.(*http2.DataFrame); ok && data.StreamID == 1 {
			tail.Write(data.Data())
			if data.StreamEnded() {
				break
			}
		}
	}
	if tail.String() != "after" {
		t.Fatalf("drained response = %q", tail.String())
	}
	select {
	case <-shutdownDone:
	case <-shutdownContext.Done():
		t.Fatal("shutdown did not finish")
	}
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve = %v", err)
	}
}

func TestConfidentialStagingWrapsListenerWithTLS(t *testing.T) {
	store := testCertificateStore(t)
	server := &Server{
		config: stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure: &confidentialruntime.Runtime{Certs: store},
	}
	listener := testListener(t)
	defer listener.Close()

	wrapped := server.wrapListener(listener)
	if wrapped == listener {
		t.Fatal("expected confidential staging listener to be TLS-wrapped")
	}
}

func TestConfidentialLocalKeepsPlainListener(t *testing.T) {
	store := testCertificateStore(t)
	server := &Server{
		config: stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "local"}},
		secure: &confidentialruntime.Runtime{Certs: store},
	}
	listener := testListener(t)
	defer listener.Close()

	wrapped := server.wrapListener(listener)
	if wrapped != listener {
		t.Fatalf("expected local listener to remain plain, got %T", wrapped)
	}
}

func TestConfidentialTLSConfigReadsCurrentActiveCertificate(t *testing.T) {
	material, err := identity.Generate(nil)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	firstChain, roots := testCertificateChainPEM(t, material, time.Now().Add(24*time.Hour))
	nextChain, _ := testCertificateChainPEM(t, material, time.Now().Add(48*time.Hour))
	nextCerts, err := parseTestCertificateChain(nextChain)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(nextCerts[0])
	store, err := identity.NewBootCertificateStore(material, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.InstallBootChain(firstChain, "api-staging.stogas.ai"); err != nil {
		t.Fatal(err)
	}
	server := &Server{
		config: stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure: &confidentialruntime.Runtime{Certs: store},
	}

	first, err := server.confidentialTLSConfig().GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("get initial certificate: %v", err)
	}
	firstHash := identity.CertSHA256Hex(first.Certificate[0])

	state, err := store.InstallBootChain(nextChain, "api-staging.stogas.ai")
	if err != nil {
		t.Fatalf("install active chain: %v", err)
	}
	second, err := server.confidentialTLSConfig().GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("get updated certificate: %v", err)
	}
	secondHash := identity.CertSHA256Hex(second.Certificate[0])

	if secondHash == firstHash {
		t.Fatal("expected TLS config to read the updated active certificate")
	}
	if secondHash != state.ActiveCertSHA256 {
		t.Fatalf("expected active cert hash %s, got %s", state.ActiveCertSHA256, secondHash)
	}
}

func TestConfidentialTLSConfigAllowsModernTLS12AndPrefersHybridTLS13(t *testing.T) {
	server := &Server{
		config: stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure: &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
	}
	config := server.confidentialTLSConfig()
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %x, want TLS 1.2", config.MinVersion)
	}
	wantCipherSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	if len(config.CipherSuites) != len(wantCipherSuites) {
		t.Fatalf("TLS 1.2 cipher suite count = %d, want %d", len(config.CipherSuites), len(wantCipherSuites))
	}
	for index := range wantCipherSuites {
		if config.CipherSuites[index] != wantCipherSuites[index] {
			t.Fatalf("TLS 1.2 cipher suite %d = %x, want %x", index, config.CipherSuites[index], wantCipherSuites[index])
		}
	}
	want := []tls.CurveID{
		tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
	if len(config.CurvePreferences) != len(want) {
		t.Fatalf("TLS curve count = %d, want %d", len(config.CurvePreferences), len(want))
	}
	for index := range want {
		if config.CurvePreferences[index] != want[index] {
			t.Fatalf("TLS curve %d = %v, want %v", index, config.CurvePreferences[index], want[index])
		}
	}
}

func TestConfidentialTLSConfigNegotiatesCompatibleAndHybridClients(t *testing.T) {
	server := &Server{
		config: stogas.Config{Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure: &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
	}
	tests := []struct {
		name        string
		client      *tls.Config
		wantVersion uint16
		wantCurve   tls.CurveID
	}{
		{
			name: "modern TLS 1.2",
			client: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
				CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				CurvePreferences:   []tls.CurveID{tls.X25519},
				InsecureSkipVerify: true, // Test certificate pinning is covered separately.
			},
			wantVersion: tls.VersionTLS12,
			wantCurve:   tls.X25519,
		},
		{
			name: "classical TLS 1.3",
			client: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				CurvePreferences:   []tls.CurveID{tls.X25519},
				InsecureSkipVerify: true, // Test certificate pinning is covered separately.
			},
			wantVersion: tls.VersionTLS13,
			wantCurve:   tls.X25519,
		},
		{
			name: "prefer hybrid TLS 1.3",
			client: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
				InsecureSkipVerify: true, // Test certificate pinning is covered separately.
			},
			wantVersion: tls.VersionTLS13,
			wantCurve:   tls.X25519MLKEM768,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := negotiateTLS(t, server.confidentialTLSConfig(), test.client)
			if state.Version != test.wantVersion {
				t.Fatalf("negotiated TLS version = %x, want %x", state.Version, test.wantVersion)
			}
			if state.CurveID != test.wantCurve {
				t.Fatalf("negotiated TLS curve = %v, want %v", state.CurveID, test.wantCurve)
			}
		})
	}
}

func negotiateTLS(t *testing.T, serverConfig, clientConfig *tls.Config) tls.ConnectionState {
	t.Helper()
	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	server := tls.Server(serverConnection, serverConfig)
	client := tls.Client(clientConnection, clientConfig)
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- server.Handshake()
	}()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server TLS handshake: %v", err)
	}
	return client.ConnectionState()
}

func TestStartFailsWhenPrivateReadinessListenerCannotBind(t *testing.T) {
	occupied := testListener(t)
	defer occupied.Close()
	_, occupiedPort, err := net.SplitHostPort(occupied.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{config: stogas.Config{
		Host:                 "127.0.0.1",
		MaxRequestBodyMiB:    1,
		Port:                 "0",
		PrivateReadinessPort: occupiedPort,
	}}
	if err := server.routes(); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err == nil || !strings.Contains(err.Error(), "listen for private readiness") {
		t.Fatalf("expected private readiness bind failure, got %v", err)
	}
}

func TestStartFailsClosedWithoutDiagnosticsClientPin(t *testing.T) {
	server := &Server{
		config: stogas.Config{Host: "127.0.0.1", Port: "0", PrivateReadinessPort: "0", MaxRequestBodyMiB: 1,
			Confidential: stogas.ConfidentialConfig{Environment: "staging"}},
		secure: &confidentialruntime.Runtime{Certs: testCertificateStore(t)},
	}
	if err := server.routes(); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err == nil || !strings.Contains(err.Error(), "diagnostics client SPKI pin is invalid") {
		t.Fatalf("expected diagnostics authorization failure before serving, got %v", err)
	}
}

func testListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return listener
}

func testCertificateStore(t *testing.T) *identity.CertificateStore {
	t.Helper()
	material, err := identity.Generate(nil)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	chain, roots := testCertificateChainPEM(t, material, time.Now().Add(24*time.Hour))
	store, err := identity.NewBootCertificateStore(material, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.InstallBootChain(chain, "api-staging.stogas.ai"); err != nil {
		t.Fatal(err)
	}
	return store
}

func testCertificateChainPEM(t *testing.T, material *identity.Material, notAfter time.Time) ([]byte, *x509.CertPool) {
	t.Helper()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "api-staging.stogas.ai",
		},
		DNSNames:              []string{"api-staging.stogas.ai"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter.UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &material.TLSPrivateKey.PublicKey, material.TLSPrivateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), roots
}

func parseTestCertificateChain(chain []byte) ([]*x509.Certificate, error) {
	block, _ := pem.Decode(chain)
	if block == nil {
		return nil, errors.New("test certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}
