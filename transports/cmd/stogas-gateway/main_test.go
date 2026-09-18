package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	stogashttp "github.com/maximhq/bifrost/transports/stogas-http"
	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

func TestStartupEventContainsOnlyFixedFields(t *testing.T) {
	var output bytes.Buffer
	writeStartupEvent(&output, "gateway_startup_failed", "error", startupConfigurationLoadFailed)
	var event map[string]string
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339Nano, event["timestamp"]); err != nil || len(event) != 5 ||
		event["errorType"] != "Error" || event["event"] != "gateway_startup_failed" ||
		event["reasonCode"] != "configuration_load_failed" || event["severity"] != "error" {
		t.Fatalf("startup event has unexpected fields: %s", output.Bytes())
	}
}

func TestServerFailureReasonUsesErrorIdentity(t *testing.T) {
	listenError := func(err error) error {
		return fmt.Errorf("private address: %w", &net.OpError{Op: "listen", Err: err})
	}
	for _, tt := range []struct {
		err  error
		want startupReasonCode
	}{
		{listenError(syscall.EADDRINUSE), startupListenAddressInUse},
		{listenError(syscall.EADDRNOTAVAIL), startupListenAddressUnavailable},
		{listenError(syscall.EACCES), startupListenPermissionDenied},
		{listenError(syscall.EPERM), startupListenPermissionDenied},
		{syscall.EPERM, startupServerFailed},
		{errors.New("address already in use: private text"), startupServerFailed},
	} {
		if got := serverFailureReason(tt.err); got != tt.want {
			t.Fatalf("server reason = %q, want %q", got, tt.want)
		}
	}
}

func TestRuntimeInitializationReasonUsesOnlyFixedStages(t *testing.T) {
	tests := []struct {
		err  error
		want startupReasonCode
	}{
		{errors.New("unknown"), startupRuntimeInitFailed},
		{fmt.Errorf("wrapped: %w", stogashttp.ErrCatalogInitialization), startupCatalogInitFailed},
		{fmt.Errorf("wrapped: %w", secretstore.ErrReleaseAuthentication), startupConfidentialSecretReleaseAuthenticationFailed},
		{secretstore.ErrReleaseBindingMismatch, startupConfidentialSecretReleaseBindingFailed},
		{secretstore.ErrInvalidReleaseContents, startupConfidentialSecretReleaseContentsInvalid},
		{secretstore.ErrInvalidReleaseEncoding, startupConfidentialSecretReleaseEncodingInvalid},
		{secretstore.ErrInvalidReleaseIdentity, startupConfidentialSecretReleaseIdentityInvalid},
		{stogashttp.ErrConfidentialSecretReleaseInstallation, startupConfidentialSecretReleaseFailed},
		{stogashttp.ErrConfidentialCertificateProvisioning, startupCertificateProvisioningFailed},
		{stogashttp.ErrConfidentialHeartbeatConfirmation, startupConfidentialHeartbeatConfirmationFailed},
		{stogashttp.ErrConfidentialHeartbeat, startupConfidentialHeartbeatFailed},
		{stogashttp.ErrConfidentialRuntimeSecretApplication, startupConfidentialRuntimeSecretApplicationFailed},
		{stogashttp.ErrConfidentialRuntimeInitialization, startupConfidentialRuntimeInitFailed},
		{stogashttp.ErrGatewayRuntimeInitialization, startupGatewayRuntimeInitFailed},
		{stogashttp.ErrRouteInitialization, startupRouteInitFailed},
	}
	for _, test := range tests {
		if got := runtimeInitializationReason(test.err); got != test.want {
			t.Fatalf("runtimeInitializationReason(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}

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
