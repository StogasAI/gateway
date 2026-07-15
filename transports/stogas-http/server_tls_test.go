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
