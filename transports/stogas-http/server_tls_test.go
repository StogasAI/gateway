package stogashttp

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
)

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
	store, err := identity.NewProvisionalCertificateStore(material, time.Now().UTC())
	if err != nil {
		t.Fatalf("create certificate store: %v", err)
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

	nextChain := testCertificateChainPEM(t, material, time.Now().UTC().Add(90*24*time.Hour))
	state, err := store.InstallActiveChain(nextChain)
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
	store, err := identity.NewProvisionalCertificateStore(material, time.Now().UTC())
	if err != nil {
		t.Fatalf("create certificate store: %v", err)
	}
	return store
}

func testCertificateChainPEM(t *testing.T, material *identity.Material, notAfter time.Time) []byte {
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
