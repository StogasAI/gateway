package stogashttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/net/netutil"
)

const (
	// Public sockets have no count limit: each spends memory admission while it
	// is open. The private listeners serve only load-balancer checks and the
	// monitor.
	readinessConcurrency    = 64
	serverReadBufferSize    = 16 * 1024
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

var errInvalidIngressHeader = errors.New("invalid ingress PROXYv2 header")

var (
	ErrConfidentialCertificateProvisioning   = errors.New("confidential certificate provisioning failed")
	ErrConfidentialRuntimeInitialization     = errors.New("confidential runtime initialization failed")
	ErrConfidentialRuntimeSecretApplication  = errors.New("confidential runtime secret application failed")
	ErrConfidentialSecretReleaseInstallation = errors.New("confidential secret release installation failed")
	ErrGatewayRuntimeInitialization          = errors.New("gateway runtime initialization failed")
	ErrRouteInitialization                   = errors.New("route initialization failed")
)

type Server struct {
	exports               *exporter.Engine
	config                stogas.Config
	logger                schemas.Logger
	runtime               *stogas.Runtime
	server                *http.Server
	readinessServer       *http.Server
	diagnosticsServer     *http.Server
	proofs                *proofhttp.Service
	sessions              *channel.Store
	sessionNodeID         string
	secure                *confidentialruntime.Runtime
	requests              *requestDrain
	admission             requestAdmissionCounters
	ipAdmission           *ipAdmission
	sanctionedNetworks    *sanctionedNetworks
	idleConnections       idleConnections
	waitingClients        waitingClients
	jsonDecode            requestWorkActivity
	preprocessing         requestWorkActivity
	memory                *requestMemoryAdmission
	startedAt             time.Time
	publicConnections     connectionCounters
	privateConnections    connectionCounters
	diagnosticConnections connectionCounters
	httpErrors            *secureHTTPLogWriter
}

func New(ctx context.Context, config stogas.Config, logger schemas.Logger) (*Server, error) {
	if config.Confidential.ControlConfigured() {
		if err := config.Confidential.Validate(); err != nil {
			return nil, err
		}
	} else if err := config.Validate(); err != nil {
		return nil, err
	}

	memory := newRequestMemoryAdmission()
	if config.Confidential.ControlConfigured() {
		if err := memory.protectRequestMemory(config.MaxRequestBodyMiB * 1024 * 1024); err != nil {
			return nil, err
		}
	}
	secure, err := confidentialruntime.Start(ctx, config.Confidential, confidentialruntime.Resources{
		Quote:   memory.confidentialReservation(quoteRetainedBytes),
		Session: memory.confidentialReservation(encryptedSessionRetainedBytes),
	})
	if err != nil {
		return nil, classifyConfidentialRuntimeInitializationError(err)
	}
	var releasedSecrets stogas.ConfidentialSecretLookup
	nodeID := ""
	if secure != nil {
		releasedSecrets = secure.Secrets
		nodeID = secure.NodeID()
	}
	if err := stogas.ApplyConfidentialRuntimeSecrets(&config, releasedSecrets); err != nil {
		if secure != nil {
			secure.Close()
		}
		return nil, fmt.Errorf("%w: %w", ErrConfidentialRuntimeSecretApplication, err)
	}
	runtime, err := stogas.NewRuntime(ctx, config, nodeID)
	if err != nil {
		if secure != nil {
			secure.Close()
		}
		return nil, fmt.Errorf("%w: %w", ErrGatewayRuntimeInitialization, err)
	}
	sanctioned, err := startSanctionedNetworks(ctx, runtime.Billing(), logger)
	if err != nil {
		runtime.Close()
		if secure != nil {
			secure.Close()
		}
		return nil, fmt.Errorf("%w: load sanctioned networks: %w", ErrGatewayRuntimeInitialization, err)
	}

	s := &Server{
		config:             config,
		logger:             logger,
		requests:           newRequestDrain(),
		memory:             memory,
		startedAt:          time.Now().UTC(),
		runtime:            runtime,
		secure:             secure,
		sanctionedNetworks: sanctioned,
	}
	s.exports = exporter.New(context.Background(), exporter.Options{Local: config.Confidential.Environment == "local" && config.AllowPrivateProviderNetwork, NewLease: s.exportLease})
	if secure != nil {
		s.proofs = secure.Proofs
		s.sessions = secure.Sessions
		s.sessionNodeID = secure.NodeID()
	}
	memory.reclaim = s.reclaimIdleMemory
	if err := s.routes(); err != nil {
		sanctioned.close()
		s.exports.Close()
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
	}
	return fmt.Errorf("%w: %w", stage, err)
}

func (s *Server) routes() error {
	s.ipAdmission = newIPAdmission()
	dispatch := func(ctx *requestContext) {
		switch {
		case ctx.request.Method == http.MethodGet && ctx.request.URL.Path == "/v1/catalog":
			s.catalog(ctx)
		case ctx.request.Method == http.MethodGet && ctx.request.URL.Path == "/v1/models":
			s.models(ctx)
		case ctx.request.Method == http.MethodPost && ctx.request.URL.Path == policyValidationPath:
			s.validatePolicy(ctx)
		case ctx.request.Method == http.MethodPost && isInferencePath(ctx.request.URL.Path):
			s.inference(ctx)
		default:
			s.notFound(ctx)
		}
	}

	s.httpErrors = newSecureHTTPLogWriter(os.Stderr)
	connectionLogger := log.New(s.httpErrors, "", 0)
	newServer := func(handler http.Handler, private bool, counters *connectionCounters) *http.Server {
		readTimeout, headerBytes := serverReadTimeout, serverReadBufferSize
		if private {
			readTimeout, headerBytes = readinessReadTimeout, readinessReadBufferSize
		}
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetHTTP2(true)
		observe := counters.observe
		if !private {
			observe = func(conn net.Conn, state http.ConnState) {
				counters.observe(conn, state)
				s.idleConnections.observe(conn, state)
			}
		}
		return &http.Server{
			Handler: counters.handler(handler), ConnState: observe,
			ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
				deadline := time.Now().Add(sessionSetupBudget)
				if secured, ok := conn.(*ingressTLSConn); ok {
					deadline = secured.deadline
				}
				return attest.WithSetupDeadline(withHTTPConnection(ctx, conn), deadline)
			},
			Protocols: protocols, ReadHeaderTimeout: readinessReadTimeout,
			ReadTimeout: readTimeout, IdleTimeout: serverIdleTimeout, MaxHeaderBytes: headerBytes,
			ErrorLog: connectionLogger,
			HTTP2: &http.HTTP2Config{
				MaxConcurrentStreams: 250, MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096,
				// Go keeps a read buffer as large as the largest frame each connection
				// has sent. TLS records carry at most 16 KiB, so larger frames save
				// only frame headers.
				MaxReadFrameSize: 16 << 10, MaxReceiveBufferPerConnection: 1 << 20, MaxReceiveBufferPerStream: 1 << 20,
				WriteByteTimeout: downstreamWriteIdleTimeout,
				CountError:       stogas.RecordHTTP2Error,
			},
		}
	}
	s.server = newServer(chain(dispatch, s.publicRequests, securityHeaders, s.ipRequestAdmission, cors, s.sessionTransport, s.publicAdmission, s.requestBodyAdmission, s.requestDecompression), false, &s.publicConnections)
	// Shared pools check /ready. The pool that routes a node's encryption
	// sessions checks /live, so it keeps delivering their requests while the
	// node refuses them during a drain or pause.
	checks := http.NewServeMux()
	checks.Handle("GET /ready", requestHandler(s.readiness))
	checks.Handle("GET /live", requestHandler(func(ctx *requestContext) { ctx.writer.WriteHeader(http.StatusNoContent) }))
	s.readinessServer = newServer(checks, true, &s.privateConnections)
	management := http.NewServeMux()
	management.Handle("GET /diagnostics/v1", requestHandler(s.diagnostics))
	management.Handle("POST /drain", requestHandler(s.drain))
	s.diagnosticsServer = newServer(management, true, &s.diagnosticConnections)
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
	readinessListener = netutil.LimitListener(readinessListener, readinessConcurrency)
	var diagnosticsListener net.Listener
	if s.serveConfidentialTLS() {
		config, tlsErr := s.diagnosticsTLSConfig()
		if tlsErr == nil {
			diagnosticsListener, tlsErr = listenConfig.Listen(context.Background(), "tcp", net.JoinHostPort(s.config.Host, privateDiagnosticsPort))
		}
		if tlsErr != nil {
			_ = listener.Close()
			_ = readinessListener.Close()
			s.shutdown()
			return fmt.Errorf("listen for private diagnostics: %w", tlsErr)
		}
		diagnosticsListener = tls.NewListener(netutil.LimitListener(diagnosticsListener, readinessConcurrency), config)
	}

	type serveResult struct {
		public bool
		err    error
	}
	errCh := make(chan serveResult, 3)
	go func() {
		errCh <- serveResult{public: true, err: s.server.Serve(listener)}
	}()
	go func() {
		errCh <- serveResult{err: s.readinessServer.Serve(readinessListener)}
	}()
	if diagnosticsListener != nil {
		go func() { errCh <- serveResult{err: s.diagnosticsServer.Serve(diagnosticsListener)} }()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	s.logger.Info("stogas gateway listening on %s", serverAddr)
	s.logger.Info("stogas gateway private readiness listening on %s", readinessAddr)

	drainRequested := s.secureShutdownRequested()
	for {
		select {
		case sig := <-sigCh:
			s.logger.Info("received signal %s", sig.String())
			s.logger.Info("request drain requested")
			s.shutdown()
			return nil
		case result := <-errCh:
			if result.public && errors.Is(result.err, http.ErrServerClosed) && s.requests.diagnostics().Draining {
				continue
			}
			s.logger.Info("server stopped accepting connections; draining admitted requests")
			s.shutdown()
			return result.err
		case <-drainRequested:
			drainRequested = nil
			s.logger.Info("confidential guest drain requested; awaiting host stop")
			go s.drainPublic()
		}
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

func (s *Server) wrapListener(listener net.Listener) net.Listener {
	if !s.serveConfidentialTLS() {
		return listener
	}
	if s.memory == nil {
		s.memory = newRequestMemoryAdmission()
	}
	return &ingressTLSListener{Listener: proxyIngress(listener), config: s.confidentialTLSConfig(), admit: s.admitConnection}
}

type ingressTLSListener struct {
	net.Listener
	config *tls.Config
	admit  func(*ingressTLSConn) error
}

func (l *ingressTLSListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(sessionSetupBudget)
	// PROXY parsing remains lazy, in net/http's connection goroutine. Its
	// deadline and TLS authentication share the same acceptance-time budget.
	_ = conn.SetDeadline(deadline)
	return &ingressTLSConn{Conn: tls.Server(conn, l.config), deadline: deadline, admit: l.admit}, nil
}

// The socket's memory stays charged until its transport closes, because
// crypto/tls retains the certificate and handshake state after setup.
type ingressTLSConn struct {
	*tls.Conn
	deadline time.Time
	admit    func(*ingressTLSConn) error
	mu       sync.Mutex
	closed   bool
	release  func()
}

func (c *ingressTLSConn) HandshakeContext(ctx context.Context) error {
	if c.admit != nil {
		if err := c.admit(c); err != nil {
			return err
		}
	}
	// net/http sets its TLS deadlines after RemoteAddr has parsed PROXY. A
	// handshake-only context prevents that from renewing the setup allowance.
	ctx, cancel := context.WithDeadline(ctx, c.deadline)
	defer cancel()
	return c.Conn.HandshakeContext(ctx)
}

// hold keeps the memory until the socket closes, or returns it at once if the
// socket closed during admission.
func (c *ingressTLSConn) hold(release func()) bool {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		release()
		return false
	}
	c.release = release
	c.mu.Unlock()
	return true
}

func (c *ingressTLSConn) Close() error {
	err := c.Conn.Close()
	c.releaseMemory()
	return err
}

// evict closes the transport directly: TLS close_notify could wait on a stalled
// peer. net/http still runs its normal TLS cleanup afterwards.
func (c *ingressTLSConn) evict() {
	_ = c.NetConn().Close()
	c.releaseMemory()
}

func (c *ingressTLSConn) releaseMemory() {
	c.mu.Lock()
	release := c.release
	c.closed, c.release = true, nil
	c.mu.Unlock()
	if release != nil {
		release()
	}
}

// A socket spends its source's setup allowance as soon as the PROXY header
// names the client, before TLS and before its memory charge. Sources over
// their allowance therefore never make the gateway close other sockets.
func (s *Server) admitConnection(c *ingressTLSConn) error {
	proxied, ok := c.NetConn().(*proxyproto.Conn)
	if !ok || proxied.ProxyHeader() == nil {
		return errInvalidIngressHeader
	}
	if s.ipAdmission != nil {
		if wait, err := s.ipAdmission.allow(proxied.RemoteAddr().String(), true, time.Now()); err != nil || wait > 0 {
			return errIPAdmission
		}
	}
	release, ok := s.memory.confidentialReservation(connectionRetainedBytes)()
	if !ok || !c.hold(release) {
		return errRequestMemoryCapacity
	}
	s.idleConnections.track(c)
	return nil
}

// The deployment firewall restricts this listener to the load-balancer
// allocation range and the private monitor. Both proxy paths must send v2;
// HTTP forwarding headers never establish client identity.
func proxyIngress(listener net.Listener) net.Listener {
	return &proxyproto.Listener{
		Listener: listener, ReadHeaderTimeout: sessionSetupBudget,
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
		ValidateHeader: func(header *proxyproto.Header) error {
			if header.Version != 2 || header.Command != proxyproto.PROXY ||
				(header.TransportProtocol != proxyproto.TCPv4 && header.TransportProtocol != proxyproto.TCPv6) {
				return errInvalidIngressHeader
			}
			return nil
		},
	}
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

func (s *Server) ordinaryTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
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

func (s *Server) confidentialTLSConfig() *tls.Config {
	base := s.ordinaryTLSConfig()
	if s.secure == nil || s.secure.NativeIssuer == nil {
		return base
	}
	configured, err := attest.ConfigureTLS(base, s.admissionReady, s.secure.NativeIssuer)
	if err != nil {
		panic(err) // All inputs are constructed locally above.
	}
	return configured
}
