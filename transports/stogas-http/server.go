package stogashttp

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	"github.com/valyala/fasthttp"
)

type Server struct {
	config  stogas.Config
	logger  schemas.Logger
	router  *router.Router
	runtime *stogas.Runtime
	server  *fasthttp.Server
	proofs  *proofhttp.Service
	secure  *confidentialruntime.Runtime
}

func New(ctx context.Context, config stogas.Config, logger schemas.Logger) (*Server, error) {
	if config.Confidential.RequestSecrets {
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

	r.GET("/ready", s.readiness)
	r.GET("/v1/catalog", s.catalog)
	r.GET("/v1/models", s.models)
	for _, path := range catalog.InferencePaths() {
		r.POST(path, s.inference)
	}
	r.NotFound = s.notFound

	s.router = r
	s.server = &fasthttp.Server{
		Handler:               chain(r.Handler, securityHeaders, cors, s.requestDecompression),
		MaxRequestBodySize:    s.config.MaxRequestBodyMiB * 1024 * 1024,
		NoDefaultServerHeader: true,
		ReadBufferSize:        64 * 1024,
		StreamRequestBody:     false,
	}
	return nil
}

func (s *Server) Start() error {
	serverAddr := net.JoinHostPort(s.config.Host, s.config.Port)
	listener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", serverAddr, err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.server.Serve(listener)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	s.logger.Info("stogas gateway listening on %s", serverAddr)

	select {
	case sig := <-sigCh:
		s.logger.Info("received signal %s", sig.String())
		s.shutdown()
		return nil
	case err := <-errCh:
		if err == nil {
			return nil
		}
		s.shutdown()
		return err
	}
}
