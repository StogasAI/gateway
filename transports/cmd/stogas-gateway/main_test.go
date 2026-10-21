package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	stogashttp "github.com/maximhq/bifrost/transports/stogas-http"
	"github.com/maximhq/bifrost/transports/stogas/billing"
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
		{secretstore.ErrInvalidReleaseContents, startupConfidentialSecretReleaseContentsInvalid},
		{stogashttp.ErrConfidentialSecretReleaseInstallation, startupConfidentialSecretReleaseFailed},
		{stogashttp.ErrConfidentialCertificateProvisioning, startupCertificateProvisioningFailed},
		{stogashttp.ErrConfidentialRuntimeSecretApplication, startupConfidentialRuntimeSecretApplicationFailed},
		{stogashttp.ErrConfidentialRuntimeInitialization, startupConfidentialRuntimeInitFailed},
		{stogashttp.ErrGatewayRuntimeInitialization, startupGatewayRuntimeInitFailed},
		{fmt.Errorf("%w: %w", stogashttp.ErrGatewayRuntimeInitialization, billing.ErrSchemaIncompatible), startupDatabaseSchemaIncompatible},
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
