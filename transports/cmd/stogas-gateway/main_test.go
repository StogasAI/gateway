package main

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

func TestGuestCertificateStoreControlsHTTPSUpstreamTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	caPath := writeTestRootCA(t, server.Certificate())

	fail := runTLSProbeHelper(t, server.URL, "")
	if fail == nil {
		t.Fatal("HTTPS probe unexpectedly trusted local test CA without SSL_CERT_FILE")
	}

	if err := runTLSProbeHelper(t, server.URL, caPath); err != nil {
		t.Fatalf("HTTPS probe did not trust SSL_CERT_FILE root: %v", err)
	}
}

func TestHTTPSProbeHelper(t *testing.T) {
	if os.Getenv("STOGAS_TLS_PROBE_HELPER") != "1" {
		return
	}

	url := os.Getenv("STOGAS_TLS_PROBE_URL")
	if url == "" {
		t.Fatal("STOGAS_TLS_PROBE_URL is required")
	}

	if caPath := os.Getenv("STOGAS_TLS_PROBE_CA_FILE"); caPath != "" {
		setDefaultGuestCertFileAt(caPath)
	}

	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
}

func runTLSProbeHelper(t *testing.T, url string, caPath string) error {
	t.Helper()

	command := exec.Command(os.Args[0], "-test.run=TestHTTPSProbeHelper")
	command.Env = append(os.Environ(),
		"SSL_CERT_DIR=",
		"SSL_CERT_FILE=",
		"STOGAS_TLS_PROBE_HELPER=1",
		"STOGAS_TLS_PROBE_URL="+url,
		"STOGAS_TLS_PROBE_CA_FILE="+caPath,
	)
	return command.Run()
}

func writeTestRootCA(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	caPath := t.TempDir() + "/test-root.pem"
	bytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if bytes == nil {
		t.Fatal("failed to PEM encode test root certificate")
	}
	if err := os.WriteFile(caPath, bytes, 0o444); err != nil {
		t.Fatal(err)
	}
	return caPath
}
