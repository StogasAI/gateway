package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestEnsureOpenFileLimit(t *testing.T) {
	t.Run("raises soft limit and preserves hard limit", func(t *testing.T) {
		setCalled := false
		err := ensureOpenFileLimit(
			func(resource int, limit *syscall.Rlimit) error {
				if resource != syscall.RLIMIT_NOFILE {
					t.Fatalf("resource = %d, want RLIMIT_NOFILE", resource)
				}
				*limit = syscall.Rlimit{Cur: 1024, Max: 131072}
				return nil
			},
			func(resource int, limit *syscall.Rlimit) error {
				setCalled = true
				if resource != syscall.RLIMIT_NOFILE {
					t.Fatalf("resource = %d, want RLIMIT_NOFILE", resource)
				}
				if limit.Cur != requiredOpenFiles || limit.Max != 131072 {
					t.Fatalf("set limit = %#v, want soft=%d hard=131072", limit, requiredOpenFiles)
				}
				return nil
			},
		)
		if err != nil {
			t.Fatalf("ensureOpenFileLimit returned error: %v", err)
		}
		if !setCalled {
			t.Fatal("expected soft limit to be raised")
		}
	})

	t.Run("accepts sufficient soft limit", func(t *testing.T) {
		err := ensureOpenFileLimit(
			func(_ int, limit *syscall.Rlimit) error {
				*limit = syscall.Rlimit{Cur: requiredOpenFiles, Max: requiredOpenFiles}
				return nil
			},
			func(_ int, _ *syscall.Rlimit) error {
				t.Fatal("setrlimit should not be called")
				return nil
			},
		)
		if err != nil {
			t.Fatalf("ensureOpenFileLimit returned error: %v", err)
		}
	})

	t.Run("raises insufficient hard limit", func(t *testing.T) {
		setCalled := false
		err := ensureOpenFileLimit(
			func(_ int, limit *syscall.Rlimit) error {
				*limit = syscall.Rlimit{Cur: 1024, Max: 4096}
				return nil
			},
			func(_ int, limit *syscall.Rlimit) error {
				setCalled = true
				if limit.Cur != requiredOpenFiles || limit.Max != requiredOpenFiles {
					t.Fatalf("set limit = %#v, want soft=hard=%d", limit, requiredOpenFiles)
				}
				return nil
			},
		)
		if err != nil {
			t.Fatalf("ensureOpenFileLimit returned error: %v", err)
		}
		if !setCalled {
			t.Fatal("expected soft and hard limits to be raised")
		}
	})

	t.Run("reports setrlimit failure", func(t *testing.T) {
		expected := errors.New("operation not permitted")
		err := ensureOpenFileLimit(
			func(_ int, limit *syscall.Rlimit) error {
				*limit = syscall.Rlimit{Cur: 1024, Max: requiredOpenFiles}
				return nil
			},
			func(_ int, _ *syscall.Rlimit) error { return expected },
		)
		if !errors.Is(err, expected) || !strings.Contains(err.Error(), "raise RLIMIT_NOFILE to 65536") {
			t.Fatalf("ensureOpenFileLimit error = %v", err)
		}
	})
}

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
