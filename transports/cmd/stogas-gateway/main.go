package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"go.uber.org/automaxprocs/maxprocs"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	stogashttp "github.com/maximhq/bifrost/transports/stogas-http"
)

const defaultGuestCaBundlePath = "/etc/ssl/certs/ca-certificates.crt"

const requiredOpenFiles = 65536

func main() {
	if err := ensureOpenFileLimit(syscall.Getrlimit, syscall.Setrlimit); err != nil {
		fatal("gateway startup: " + err.Error())
	}
	setDefaultGuestCertFile()
	_, _ = maxprocs.Set()

	config, err := stogas.LoadFromEnv()
	if err != nil {
		fatal(err.Error())
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
		fatal(err.Error())
	}

	if err := server.Start(); err != nil {
		fatal(err.Error())
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
		_, _ = os.Stderr.WriteString("unable to inspect guest CA bundle: " + err.Error() + "\n")
	}
}

func fatal(message string) {
	_, _ = os.Stderr.WriteString(strings.TrimSpace(message) + "\n")
	os.Exit(1)
}
