package stogashttp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
)

func diagnosticsTestCertificate(t *testing.T, key ed25519.PrivateKey, start, end time.Time, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	if key == nil {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = generated
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "monitor"},
		NotBefore: start, NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestDiagnosticsTLSRejectsUnauthorizedClientsBeforeHTTP(t *testing.T) {
	now := time.Now()
	valid := diagnosticsTestCertificate(t, nil, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	pin := sha256.Sum256(valid.Leaf.RawSubjectPublicKeyInfo)
	server := &Server{config: stogas.Config{DiagnosticsClientSPKISHA256: hex.EncodeToString(pin[:])}}
	config, err := server.diagnosticsTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	config.GetCertificate = nil
	config.Certificates = fixture.TLS.Certificates
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	var requests atomic.Int32
	endpoint := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	endpoint.Config.ErrorLog = log.New(io.Discard, "", 0)
	endpoint.TLS = config
	endpoint.StartTLS()
	defer endpoint.Close()
	key := valid.PrivateKey.(ed25519.PrivateKey)
	for _, test := range []struct {
		name        string
		certificate *tls.Certificate
		maxVersion  uint16
		allowed     bool
	}{
		{name: "missing"},
		{name: "valid", certificate: &valid, allowed: true},
		{name: "TLS 1.2", certificate: &valid, maxVersion: tls.VersionTLS12},
		{name: "other key", certificate: ptrDiagnosticsCertificate(diagnosticsTestCertificate(t, nil, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth))},
		{name: "expired", certificate: ptrDiagnosticsCertificate(diagnosticsTestCertificate(t, key, now.Add(-2*time.Hour), now.Add(-time.Hour), x509.ExtKeyUsageClientAuth))},
		{name: "future", certificate: ptrDiagnosticsCertificate(diagnosticsTestCertificate(t, key, now.Add(time.Hour), now.Add(2*time.Hour), x509.ExtKeyUsageClientAuth))},
		{name: "wrong usage", certificate: ptrDiagnosticsCertificate(diagnosticsTestCertificate(t, key, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth))},
		{name: "renewed certificate same key", certificate: ptrDiagnosticsCertificate(diagnosticsTestCertificate(t, key, now.Add(-time.Minute), now.Add(2*time.Hour), x509.ExtKeyUsageClientAuth)), allowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientTLS := &tls.Config{RootCAs: roots, ServerName: "example.com", MaxVersion: test.maxVersion}
			if test.certificate != nil {
				clientTLS.Certificates = []tls.Certificate{*test.certificate}
			}
			transport := &http.Transport{TLSClientConfig: clientTLS}
			defer transport.CloseIdleConnections()
			before := requests.Load()
			response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(endpoint.URL)
			if response != nil {
				response.Body.Close()
			}
			if (err == nil) != test.allowed || (requests.Load() > before) != test.allowed {
				t.Fatalf("allowed=%t HTTP reached=%t error=%v", test.allowed, requests.Load() > before, err)
			}
		})
	}
}

func ptrDiagnosticsCertificate(certificate tls.Certificate) *tls.Certificate { return &certificate }

func TestDiagnosticsClientVerificationChecksResumedConnectionsAndExactExpiry(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	certificate := diagnosticsTestCertificate(t, nil, now.Add(-time.Hour), now, x509.ExtKeyUsageClientAuth)
	pin := sha256.Sum256(certificate.Leaf.RawSubjectPublicKeyInfo)
	state := tls.ConnectionState{DidResume: true, PeerCertificates: []*x509.Certificate{certificate.Leaf}}
	if err := verifyDiagnosticsClient(state, pin, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiagnosticsClient(state, pin, now.Add(time.Nanosecond)); err == nil {
		t.Fatal("expired resumed identity accepted")
	}
	state.PeerCertificates = append(state.PeerCertificates, certificate.Leaf)
	if err := verifyDiagnosticsClient(state, pin, now.Add(-time.Second)); err == nil {
		t.Fatal("multiple client certificates accepted")
	}
	if _, err := (&Server{}).diagnosticsTLSConfig(); err == nil {
		t.Fatal("missing client pin accepted")
	}
}
