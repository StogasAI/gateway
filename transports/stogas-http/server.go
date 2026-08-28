package stogashttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	"github.com/valyala/fasthttp"
)

const (
	// These explicit connection caps are starting values for the current guest,
	// not CPU-derived capacity claims. Calibrate them from production load.
	serverConcurrency       = 2048
	readinessConcurrency    = 64
	serverReadBufferSize    = 16 * 1024
	serverWriteBufferSize   = 4 * 1024
	readinessReadBufferSize = 4 * 1024
	serverReadTimeout       = 5 * time.Minute
	readinessReadTimeout    = 30 * time.Second
	serverIdleTimeout       = 60 * time.Second
	// A quiet model does not write to the client and does not use this timeout.
	// It applies only while a socket write cannot make progress.
	downstreamWriteIdleTimeout = time.Minute
	// Cleanup starts after admitted requests get their full lifetime. Keep this
	// separate from the client write timeout so billing retries can finish.
	serverShutdownTimeout    = 5 * time.Minute
	guestShutdownHardCap     = billing.GatewayRequestLifetime + serverShutdownTimeout
	serverTCPKeepalivePeriod = 30 * time.Second
)

var (
	ErrCatalogInitialization                 = errors.New("catalog initialization failed")
	ErrConfidentialCertificateProvisioning   = errors.New("confidential certificate provisioning failed")
	ErrConfidentialHeartbeat                 = errors.New("confidential heartbeat failed")
	ErrConfidentialHeartbeatConfirmation     = errors.New("confidential heartbeat confirmation failed")
	ErrConfidentialRuntimeInitialization     = errors.New("confidential runtime initialization failed")
	ErrConfidentialRuntimeSecretApplication  = errors.New("confidential runtime secret application failed")
	ErrConfidentialSecretReleaseInstallation = errors.New("confidential secret release installation failed")
	ErrGatewayRuntimeInitialization          = errors.New("gateway runtime initialization failed")
	ErrRouteInitialization                   = errors.New("route initialization failed")
)

type Server struct {
	config          stogas.Config
	logger          schemas.Logger
	router          *router.Router
	runtime         *stogas.Runtime
	server          *fasthttp.Server
	readinessServer *fasthttp.Server
	proofs          *proofhttp.Service
	secure          *confidentialruntime.Runtime
	catalogUpdater  *catalog.Updater
	requests        *requestDrain
	memory          *requestMemoryAdmission
	startedAt       time.Time
}

func New(ctx context.Context, config stogas.Config, logger schemas.Logger) (*Server, error) {
	if config.Confidential.ControlConfigured() {
		if err := config.Confidential.Validate(); err != nil {
			return nil, err
		}
	} else if err := config.Validate(); err != nil {
		return nil, err
	}

	catalogUpdater, err := catalog.StartUpdater(ctx, catalog.UpdaterConfig{
		ReleaseURL:     config.CatalogURL,
		RequireInitial: config.Confidential.Enabled && config.Confidential.Environment != "local",
		GatewayVersion: stogas.GatewayVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCatalogInitialization, err)
	}
	secure, err := confidentialruntime.Start(ctx, config.Confidential)
	if err != nil {
		catalogUpdater.Close()
		return nil, classifyConfidentialRuntimeInitializationError(err)
	}
	var releasedSecrets stogas.ConfidentialSecretLookup
	if secure != nil {
		releasedSecrets = secure.Secrets
	}
	if err := stogas.ApplyConfidentialRuntimeSecrets(&config, releasedSecrets); err != nil {
		catalogUpdater.Close()
		if secure != nil {
			secure.Close()
		}
		return nil, fmt.Errorf("%w: %w", ErrConfidentialRuntimeSecretApplication, err)
	}
	runtime, err := stogas.NewRuntime(ctx, config, logger)
	if err != nil {
		catalogUpdater.Close()
		if secure != nil {
			secure.Close()
		}
		return nil, fmt.Errorf("%w: %w", ErrGatewayRuntimeInitialization, err)
	}
	if secure != nil {
		secure.SetRuntimeDependencyProbe(func(ctx context.Context) error {
			if ready, reason := catalogUpdater.Ready(time.Now().UTC()); !ready {
				return fmt.Errorf("catalog is unhealthy: %s", reason)
			}
			return runtime.ProbeDependencies(ctx)
		})
	}
	s := &Server{
		catalogUpdater: catalogUpdater,
		config:         config,
		logger:         logger,
		requests:       newRequestDrain(),
		memory:         newRequestMemoryAdmission(),
		startedAt:      time.Now().UTC(),
		runtime:        runtime,
		secure:         secure,
	}
	if secure != nil {
		s.proofs = secure.Proofs
	}
	if err := s.routes(); err != nil {
		catalogUpdater.Close()
		if secure != nil {
			secure.Close()
		}
		runtime.Close()
		return nil, fmt.Errorf("%w: %w", ErrRouteInitialization, err)
	}
	return s, nil
}

func classifyConfidentialRuntimeInitializationError(err error) error {
	stage := ErrConfidentialRuntimeInitialization
	switch {
	case errors.Is(err, confidentialruntime.ErrSecretReleaseInstallation):
		stage = ErrConfidentialSecretReleaseInstallation
	case errors.Is(err, confidentialruntime.ErrCertificateInstruction):
		stage = ErrConfidentialCertificateProvisioning
	case errors.Is(err, confidentialruntime.ErrHeartbeatConfirmation):
		stage = ErrConfidentialHeartbeatConfirmation
	case errors.Is(err, confidentialruntime.ErrHeartbeatExchange):
		stage = ErrConfidentialHeartbeat
	}
	return fmt.Errorf("%w: %w", stage, err)
}

func (s *Server) routes() error {
	r := router.New()

	r.GET("/v1/catalog", s.catalog)
	r.GET("/v1/models", s.models)
	for _, path := range catalog.InferencePaths() {
		r.POST(path, s.inference)
	}
	r.NotFound = s.notFound

	s.router = r
	connectionLogger := newSecureFastHTTPLogger(os.Stderr)
	s.server = &fasthttp.Server{
		Handler:                      chain(r.Handler, resetDownstreamWriteLimit, securityHeaders, cors, s.requestBodyAdmission, s.requestDecompression),
		Concurrency:                  serverConcurrency,
		MaxRequestBodySize:           s.config.MaxRequestBodyMiB * 1024 * 1024,
		NoDefaultServerHeader:        true,
		ReadBufferSize:               serverReadBufferSize,
		WriteBufferSize:              serverWriteBufferSize,
		ReadTimeout:                  serverReadTimeout,
		WriteTimeout:                 0,
		IdleTimeout:                  serverIdleTimeout,
		Logger:                       connectionLogger,
		TCPKeepalive:                 true,
		TCPKeepalivePeriod:           serverTCPKeepalivePeriod,
		StreamRequestBody:            true,
		ReduceMemoryUsage:            true,
		SecureErrorLogMessage:        true,
		DisablePreParseMultipartForm: true,
		CloseOnShutdown:              true,
	}
	readinessRouter := router.New()
	readinessRouter.GET("/ready", s.readiness)
	readinessRouter.GET("/diagnostics/v1", s.diagnostics)
	s.readinessServer = &fasthttp.Server{
		Handler:               readinessRouter.Handler,
		Concurrency:           readinessConcurrency,
		GetOnly:               true,
		NoDefaultServerHeader: true,
		ReadBufferSize:        readinessReadBufferSize,
		WriteBufferSize:       serverWriteBufferSize,
		ReadTimeout:           readinessReadTimeout,
		IdleTimeout:           serverIdleTimeout,
		Logger:                connectionLogger,
		SecureErrorLogMessage: true,
		TCPKeepalive:          true,
		TCPKeepalivePeriod:    serverTCPKeepalivePeriod,
		CloseOnShutdown:       true,
	}
	return nil
}

func (s *Server) Start() error {
	serverAddr := net.JoinHostPort(s.config.Host, s.config.Port)
	readinessAddr := net.JoinHostPort(s.config.Host, s.config.PrivateReadinessPort)
	listenConfig := net.ListenConfig{KeepAlive: serverTCPKeepalivePeriod}
	listener, err := listenConfig.Listen(context.Background(), "tcp", serverAddr)
	if err != nil {
		s.shutdown()
		return fmt.Errorf("listen on %s: %w", serverAddr, err)
	}
	readinessListener, err := listenConfig.Listen(context.Background(), "tcp", readinessAddr)
	if err != nil {
		_ = listener.Close()
		s.shutdown()
		return fmt.Errorf("listen for private readiness on %s: %w", readinessAddr, err)
	}
	listener = withWriteIdleTimeout(listener, downstreamWriteIdleTimeout)
	listener = s.wrapListener(listener)
	readinessListener = withWriteIdleTimeout(readinessListener, downstreamWriteIdleTimeout)

	errCh := make(chan error, 2)
	go func() {
		errCh <- s.server.Serve(listener)
	}()
	go func() {
		errCh <- s.readinessServer.Serve(readinessListener)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	s.logger.Info("stogas gateway listening on %s", serverAddr)
	s.logger.Info("stogas gateway private readiness listening on %s", readinessAddr)

	select {
	case sig := <-sigCh:
		s.logger.Info("received signal %s", sig.String())
		s.logger.Info("request drain requested")
		s.drainRequests()
		s.shutdown()
		return nil
	case err := <-errCh:
		s.logger.Info("server stopped accepting connections; draining admitted requests")
		s.drainRequests()
		s.shutdown()
		return err
	case <-s.secureShutdownRequested():
		s.logger.Info("confidential guest drain requested")
		s.drainRequests()
		s.shutdown()
		return s.powerOffGuest()
	}
}

func (s *Server) drainRequests() {
	if s == nil || s.requests == nil {
		return
	}
	idle := s.requests.start()
	timer := time.NewTimer(guestDrainTimeout())
	defer timer.Stop()
	select {
	case <-idle:
	case <-timer.C:
	}
}

func (s *Server) secureShutdownRequested() <-chan struct{} {
	if s == nil || s.secure == nil {
		return nil
	}
	return s.secure.ShutdownRequested()
}

func guestDrainTimeout() time.Duration {
	return billing.GatewayRequestLifetime
}

func (s *Server) powerOffGuest() error {
	if os.Getpid() != 1 || (s.config.Confidential.Environment != "staging" && s.config.Confidential.Environment != "production") {
		return nil
	}
	return syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}

func (s *Server) wrapListener(listener net.Listener) net.Listener {
	if !s.serveConfidentialTLS() {
		return listener
	}
	return tls.NewListener(listener, s.confidentialTLSConfig())
}

func (s *Server) serveConfidentialTLS() bool {
	if s == nil || s.secure == nil || s.secure.Certs == nil {
		return false
	}
	switch s.config.Confidential.Environment {
	case "staging", "production":
		return true
	default:
		return false
	}
}

func (s *Server) confidentialTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024,
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if s == nil || s.secure == nil || s.secure.Certs == nil {
				return nil, errors.New("confidential certificate store is not initialized")
			}
			cert, ok := s.secure.Certs.ActiveTLSCertificate()
			if !ok {
				return nil, errors.New("active confidential TLS certificate is not available")
			}
			return &cert, nil
		},
	}
}
