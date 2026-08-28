package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"syscall"

	"go.uber.org/automaxprocs/maxprocs"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	stogashttp "github.com/maximhq/bifrost/transports/stogas-http"
	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

const defaultGuestCaBundlePath = "/etc/ssl/certs/ca-certificates.crt"

const requiredOpenFiles = 65536

type startupReasonCode string

const (
	startupCABundleInspectionFailed                      startupReasonCode = "ca_bundle_inspection_failed"
	startupCatalogInitFailed                             startupReasonCode = "catalog_initialization_failed"
	startupCertificateProvisioningFailed                 startupReasonCode = "confidential_certificate_provisioning_failed"
	startupConfigurationLoadFailed                       startupReasonCode = "configuration_load_failed"
	startupConfidentialHeartbeatFailed                   startupReasonCode = "confidential_heartbeat_failed"
	startupConfidentialHeartbeatConfirmationFailed       startupReasonCode = "confidential_heartbeat_confirmation_failed"
	startupConfidentialRuntimeInitFailed                 startupReasonCode = "confidential_runtime_initialization_failed"
	startupConfidentialRuntimeSecretApplicationFailed    startupReasonCode = "confidential_runtime_secret_application_failed"
	startupConfidentialSecretReleaseFailed               startupReasonCode = "confidential_secret_release_installation_failed"
	startupConfidentialSecretReleaseAuthenticationFailed startupReasonCode = "confidential_secret_release_authentication_failed"
	startupConfidentialSecretReleaseBindingFailed        startupReasonCode = "confidential_secret_release_binding_failed"
	startupConfidentialSecretReleaseContentsInvalid      startupReasonCode = "confidential_secret_release_contents_invalid"
	startupConfidentialSecretReleaseEncodingInvalid      startupReasonCode = "confidential_secret_release_encoding_invalid"
	startupConfidentialSecretReleaseIdentityInvalid      startupReasonCode = "confidential_secret_release_identity_invalid"
	startupGatewayRuntimeInitFailed                      startupReasonCode = "gateway_runtime_initialization_failed"
	startupMaxProcsAdjustmentFailed                      startupReasonCode = "maxprocs_adjustment_failed"
	startupOpenFileLimitFailed                           startupReasonCode = "open_file_limit_failed"
	startupRouteInitFailed                               startupReasonCode = "route_initialization_failed"
	startupRuntimeInitFailed                             startupReasonCode = "runtime_initialization_failed"
	startupServerFailed                                  startupReasonCode = "server_failed"
)

func main() {
	if err := ensureOpenFileLimit(syscall.Getrlimit, syscall.Setrlimit); err != nil {
		fatal(startupOpenFileLimitFailed)
	}
	setDefaultGuestCertFile()
	if _, err := maxprocs.Set(); err != nil {
		writeStartupEvent(os.Stderr, "gateway_startup_warning", "warn", startupMaxProcsAdjustmentFailed)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(stogashttp.DefaultGoMemoryLimitBytes)
	}

	config, err := stogas.LoadFromEnv()
	if err != nil {
		fatal(startupConfigurationLoadFailed)
	}

	flag.StringVar(&config.Host, "host", config.Host, "Host to bind the gateway to")
	flag.StringVar(&config.Port, "port", config.Port, "Port to bind the gateway to")
	flag.StringVar(&config.PrivateReadinessPort, "private-readiness-port", config.PrivateReadinessPort, "Port to bind the private readiness listener to")
	flag.StringVar(&config.LogLevel, "log-level", config.LogLevel, "Logger level (debug, info, warn, error)")
	flag.StringVar(&config.LogOutputStyle, "log-style", config.LogOutputStyle, "Logger output type (json or pretty)")
	flag.IntVar(&config.MaxRequestBodyMiB, "max-request-body-mib", config.MaxRequestBodyMiB, "Maximum request body size in MiB")
	flag.Parse()

	logger := bifrost.NewDefaultLogger(schemas.LogLevel(config.LogLevel))
	logger.SetOutputType(schemas.LoggerOutputType(config.LogOutputStyle))

	server, err := stogashttp.New(context.Background(), config, logger)
	if err != nil {
		fatal(runtimeInitializationReason(err))
	}

	if err := server.Start(); err != nil {
		fatal(startupServerFailed)
	}
}

func runtimeInitializationReason(err error) startupReasonCode {
	switch {
	case errors.Is(err, stogashttp.ErrCatalogInitialization):
		return startupCatalogInitFailed
	case errors.Is(err, secretstore.ErrReleaseAuthentication):
		return startupConfidentialSecretReleaseAuthenticationFailed
	case errors.Is(err, secretstore.ErrReleaseBindingMismatch):
		return startupConfidentialSecretReleaseBindingFailed
	case errors.Is(err, secretstore.ErrInvalidReleaseContents):
		return startupConfidentialSecretReleaseContentsInvalid
	case errors.Is(err, secretstore.ErrInvalidReleaseEncoding):
		return startupConfidentialSecretReleaseEncodingInvalid
	case errors.Is(err, secretstore.ErrInvalidReleaseIdentity):
		return startupConfidentialSecretReleaseIdentityInvalid
	case errors.Is(err, stogashttp.ErrConfidentialSecretReleaseInstallation):
		return startupConfidentialSecretReleaseFailed
	case errors.Is(err, stogashttp.ErrConfidentialCertificateProvisioning):
		return startupCertificateProvisioningFailed
	case errors.Is(err, stogashttp.ErrConfidentialHeartbeatConfirmation):
		return startupConfidentialHeartbeatConfirmationFailed
	case errors.Is(err, stogashttp.ErrConfidentialHeartbeat):
		return startupConfidentialHeartbeatFailed
	case errors.Is(err, stogashttp.ErrConfidentialRuntimeSecretApplication):
		return startupConfidentialRuntimeSecretApplicationFailed
	case errors.Is(err, stogashttp.ErrConfidentialRuntimeInitialization):
		return startupConfidentialRuntimeInitFailed
	case errors.Is(err, stogashttp.ErrGatewayRuntimeInitialization):
		return startupGatewayRuntimeInitFailed
	case errors.Is(err, stogashttp.ErrRouteInitialization):
		return startupRouteInitFailed
	default:
		return startupRuntimeInitFailed
	}
}

func ensureOpenFileLimit(
	getrlimit func(int, *syscall.Rlimit) error,
	setrlimit func(int, *syscall.Rlimit) error,
) error {
	var limit syscall.Rlimit
	if err := getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("read RLIMIT_NOFILE: %w", err)
	}
	if limit.Cur >= requiredOpenFiles {
		return nil
	}
	if limit.Max < requiredOpenFiles {
		limit.Max = requiredOpenFiles
	}

	limit.Cur = requiredOpenFiles
	if err := setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("raise RLIMIT_NOFILE to %d: %w", requiredOpenFiles, err)
	}
	return nil
}

func setDefaultGuestCertFile() {
	setDefaultGuestCertFileAt(defaultGuestCaBundlePath)
}

func setDefaultGuestCertFileAt(path string) {
	if os.Getenv("SSL_CERT_FILE") != "" {
		return
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Setenv("SSL_CERT_FILE", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		writeStartupEvent(os.Stderr, "gateway_startup_warning", "warn", startupCABundleInspectionFailed)
	}
}

func writeStartupEvent(output io.Writer, event string, severity string, reasonCode startupReasonCode) {
	payload, err := json.Marshal(struct {
		ErrorType  string `json:"errorType"`
		Event      string `json:"event"`
		ReasonCode string `json:"reasonCode"`
		Severity   string `json:"severity"`
	}{
		ErrorType:  "Error",
		Event:      event,
		ReasonCode: string(reasonCode),
		Severity:   severity,
	})
	if err == nil {
		_, _ = fmt.Fprintln(output, string(payload))
	}
}

func fatal(reasonCode startupReasonCode) {
	writeStartupEvent(os.Stderr, "gateway_startup_failed", "error", reasonCode)
	os.Exit(1)
}
