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
)

const defaultGuestCaBundlePath = "/etc/ssl/certs/ca-certificates.crt"

const requiredOpenFiles = 65536
const defaultGoMemoryLimitBytes = 10 * 1024 * 1024 * 1024

type startupReasonCode string

const (
	startupCABundleInspectionFailed startupReasonCode = "ca_bundle_inspection_failed"
	startupConfigurationLoadFailed  startupReasonCode = "configuration_load_failed"
	startupMaxProcsAdjustmentFailed startupReasonCode = "maxprocs_adjustment_failed"
	startupOpenFileLimitFailed      startupReasonCode = "open_file_limit_failed"
	startupRuntimeInitFailed        startupReasonCode = "runtime_initialization_failed"
	startupServerFailed             startupReasonCode = "server_failed"
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
		debug.SetMemoryLimit(defaultGoMemoryLimitBytes)
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
		fatal(startupRuntimeInitFailed)
	}

	if err := server.Start(); err != nil {
		fatal(startupServerFailed)
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
