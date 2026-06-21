package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"strings"

	"go.uber.org/automaxprocs/maxprocs"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	stogashttp "github.com/maximhq/bifrost/transports/stogas-http"
)

const defaultGuestCaBundlePath = "/etc/ssl/certs/ca-certificates.crt"

func main() {
	setDefaultGuestCertFile()
	_, _ = maxprocs.Set()

	config, err := stogas.LoadFromEnv()
	if err != nil {
		fatal(err.Error())
	}

	flag.StringVar(&config.Host, "host", config.Host, "Host to bind the gateway to")
	flag.StringVar(&config.Port, "port", config.Port, "Port to bind the gateway to")
	flag.StringVar(&config.LogLevel, "log-level", config.LogLevel, "Logger level (debug, info, warn, error)")
	flag.StringVar(&config.LogOutputStyle, "log-style", config.LogOutputStyle, "Logger output type (json or pretty)")
	flag.IntVar(&config.MaxRequestBodyMiB, "max-request-body-mib", config.MaxRequestBodyMiB, "Maximum request body size in MiB")
	flag.Parse()

	if err := config.Validate(); err != nil {
		fatal(err.Error())
	}

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
