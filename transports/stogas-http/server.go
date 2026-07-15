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
}

func New(ctx context.Context, config stogas.Config, logger schemas.Logger) (*Server, error) {
	if config.Confidential.ControlConfigured() {
		if err := config.Confidential.Validate(); err != nil {
			return nil, err
		}
	} else if err := config.Validate(); err != nil {
		return nil, err
	}

	secure, err := confidentialruntime.Start(ctx, config.Confidential)
	if err != nil {
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

	s := &Server{
		config:  config,
		logger:  logger,
		runtime: runtime,
		secure:  secure,
	}
	if secure != nil {
		s.proofs = secure.Proofs
	}
	if err := s.routes(); err != nil {
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
		Handler:               chain(r.Handler, securityHeaders, cors, s.requestDecompression),
		Concurrency:           serverConcurrency,
		MaxRequestBodySize:    s.config.MaxRequestBodyMiB * 1024 * 1024,
		NoDefaultServerHeader: true,
		ReadBufferSize:        serverReadBufferSize,
		ReadTimeout:           serverReadTimeout,
		WriteTimeout:          0,
		IdleTimeout:           serverIdleTimeout,
		TCPKeepalive:          true,
		TCPKeepalivePeriod:    serverTCPKeepalivePeriod,
		StreamRequestBody:     false,
	}
	readinessRouter := router.New()
	readinessRouter.GET("/ready", s.readiness)
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
	}
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
