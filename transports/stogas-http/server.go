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
	serverConcurrency        = 2048
	serverReadBufferSize     = 16 * 1024
	serverReadTimeout        = 30 * time.Second
	serverIdleTimeout        = 60 * time.Second
	serverTCPKeepalivePeriod = 30 * time.Second
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
		RequireInitial: config.Confidential.Enabled,
	})
	if err != nil {
		return nil, err
	}
	secure, err := confidentialruntime.Start(ctx, config.Confidential)
	if err != nil {
		catalogUpdater.Close()
		return nil, err
	}
	var releasedSecrets stogas.ConfidentialSecretLookup
	if secure != nil {
		releasedSecrets = secure.Secrets
	}
	if err := stogas.ApplyConfidentialRuntimeSecrets(&config, releasedSecrets); err != nil {
		if secure != nil {
			secure.Close()
		}
		return nil, err
	}
	runtime, err := stogas.NewRuntime(ctx, config, logger)
	if err != nil {
		if secure != nil {
			secure.Close()
		}
		return nil, err
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
		memory:         &requestMemoryAdmission{},
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
		return nil, err
	}
	return s, nil
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
	s.server = &fasthttp.Server{
		Handler:                      chain(r.Handler, securityHeaders, cors, s.requestDecompression),
		Concurrency:                  serverConcurrency,
		MaxRequestBodySize:           s.config.MaxRequestBodyMiB * 1024 * 1024,
		NoDefaultServerHeader:        true,
		ReadBufferSize:               serverReadBufferSize,
		ReadTimeout:                  serverReadTimeout,
		WriteTimeout:                 0,
		IdleTimeout:                  serverIdleTimeout,
		TCPKeepalive:                 true,
		TCPKeepalivePeriod:           serverTCPKeepalivePeriod,
		StreamRequestBody:            false,
		ReduceMemoryUsage:            true,
		SecureErrorLogMessage:        true,
		DisablePreParseMultipartForm: true,
	}
	readinessRouter := router.New()
	readinessRouter.GET("/ready", s.readiness)
	readinessRouter.GET("/diagnostics/v1", s.diagnostics)
	s.readinessServer = &fasthttp.Server{
		Handler:               readinessRouter.Handler,
		GetOnly:               true,
		NoDefaultServerHeader: true,
		ReadTimeout:           serverReadTimeout,
		IdleTimeout:           serverIdleTimeout,
		TCPKeepalive:          true,
		TCPKeepalivePeriod:    serverTCPKeepalivePeriod,
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
	listener = s.wrapListener(listener)

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
		s.shutdown()
		return nil
	case err := <-errCh:
		s.shutdown()
		return err
	case <-s.secureShutdownRequested():
		s.logger.Info("confidential guest drain requested")
		idle := s.requests.start()
		timer := time.NewTimer(guestDrainTimeout())
		select {
		case <-idle:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		s.shutdown()
		return s.powerOffGuest()
	}
}

func (s *Server) secureShutdownRequested() <-chan struct{} {
	if s == nil || s.secure == nil {
		return nil
	}
	return s.secure.ShutdownRequested()
}

func guestDrainTimeout() time.Duration {
	const hardCap = 65 * time.Minute
	if billing.GatewayRequestLifetime < hardCap {
		return billing.GatewayRequestLifetime
	}
	return hardCap
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
