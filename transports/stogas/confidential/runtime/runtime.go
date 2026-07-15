package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/drand"
	"github.com/maximhq/bifrost/transports/stogas/confidential/entropy"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
	"github.com/maximhq/bifrost/transports/stogas/confidential/quote"
	"github.com/maximhq/bifrost/transports/stogas/confidential/readiness"
	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

type Runtime struct {
	Identity     *identity.Material
	Certs        *identity.CertificateStore
	Proofs       *proofhttp.Service
	Quotes       *quote.Manager
	Secrets      *secretstore.Store
	Control      *ControlLoop
	EntropyReady bool
	cancel       context.CancelFunc
}

type ControlLoop struct {
	client       provision.Client
	config       stogas.ConfidentialConfig
	certs        *identity.CertificateStore
	entropyReady bool
	identity     *identity.Material
	nodeID       string
	quotes       *quote.Manager
	secrets      *secretstore.Store

	heartbeatMu             sync.Mutex
	mu                      sync.RWMutex
	generationID            string
	admissionReadyUntil     time.Time
	lastHeartbeatError      error
	lastSecretError         error
	lastCertificateError    error
}

var waitForEntropy = func(ctx context.Context, timeout time.Duration) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return entropy.Wait(ctx, nil)
}

const controlRequestTimeout = 25 * time.Second
const localQuoteReadyWindow = 10 * time.Minute

func Start(ctx context.Context, config stogas.ConfidentialConfig) (*Runtime, error) {
	if !config.Enabled {
		return nil, nil
	}
	config = config.WithRuntimeDefaults()
	if config.AttesterMode == "" {
		config.AttesterMode = config.DerivedAttesterMode()
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := waitForEntropy(ctx, config.EntropyTimeout); err != nil {
		return nil, fmt.Errorf("confidential entropy readiness failed: %w", err)
	}

	material, err := identity.Generate(nil)
	if err != nil {
		return nil, err
	}
	certs, err := newCertificateStore(material, config)
	if err != nil {
		return nil, err
	}
	drandSource, err := newDrandSource(config)
	if err != nil {
		return nil, err
	}
	attester, err := newAttester(config)
	if err != nil {
		return nil, err
	}
	builder := func(ctx context.Context) (reportdata.Payload, error) {
		catalogHash, ok := catalog.PublicCatalogHash()
		if !ok {
			return reportdata.Payload{}, catalog.ErrCatalogUnavailable
		}
		if err := drandSource.Refresh(ctx); err != nil {
			if _, currentErr := drandSource.Current(ctx); currentErr != nil {
				return reportdata.Payload{}, err
			}
		}
		beacon, err := drandSource.Current(ctx)
		if err != nil {
			return reportdata.Payload{}, err
		}
		certState := certs.State()
		return reportdata.NewPayload(reportdata.Payload{
			CatalogHash:        catalogHash,
			TLSSPKISHA256:      material.TLSSPKISHA256,
			ActiveCertSHA256:   certState.ActiveCertSHA256,
			AcceptedCertSHA256: append([]string(nil), certState.AcceptedCertSHA256...),
			HPKEPublicKey:      material.HPKEPublicKey,
			Ed25519PublicKey:   material.Ed25519PublicKey,
			Drand:              beacon,
		})
	}
	manager, err := quote.New(attester, builder, config.QuoteRefresh)
	if err != nil {
		return nil, err
	}

	runtimeCtx, cancel := context.WithCancel(ctx)
	if err := manager.Refresh(runtimeCtx); err != nil {
		cancel()
		return nil, fmt.Errorf("initial confidential quote refresh failed: %w", err)
	}
	manager.Start(runtimeCtx)
	secrets := secretstore.NewStore()
	var controlLoop *ControlLoop
	if config.ControlConfigured() {
		catalogHash, ok := catalog.PublicCatalogHash()
		if !ok {
			cancel()
			return nil, fmt.Errorf("confidential catalog hash unavailable: %w", catalog.ErrCatalogUnavailable)
		}
		controlLoop = newControlLoop(config, material, certs, manager, secrets, catalogHash, true)
		heartbeatCtx, heartbeatCancel := controlLoop.controlAttemptContext(runtimeCtx)
		err := controlLoop.sendHeartbeat(heartbeatCtx)
		heartbeatCancel()
		if err != nil {
			cancel()
			return nil, fmt.Errorf("initial confidential heartbeat failed: %w", err)
		}
		controlLoop.Start(runtimeCtx)
	}

	return &Runtime{
		Identity: material,
		Certs:    certs,
		Proofs: &proofhttp.Service{
			Quotes: manager,
			Signer: material.Ed25519PrivateKey,
		},
		Quotes:       manager,
		Secrets:      secrets,
		Control:      controlLoop,
		EntropyReady: true,
		cancel:       cancel,
	}, nil
}

func newCertificateStore(material *identity.Material, config stogas.ConfidentialConfig) (*identity.CertificateStore, error) {
	if strings.TrimSpace(config.ActiveCertSHA256) == "" && len(config.AcceptedCertSHA256) == 0 && config.CertExpiresAt.IsZero() {
		return identity.NewProvisionalCertificateStore(material, time.Now().UTC())
	}
	return identity.NewCertificateStore(
		material,
		config.ActiveCertSHA256,
		config.AcceptedCertSHA256,
		config.CertExpiresAt,
	)
}

func (r *Runtime) Close() {
	if r == nil || r.cancel == nil {
		return
	}
	r.cancel()
}

func (r *Runtime) Readiness() readiness.Result {
	if r == nil {
		return readiness.Result{Ready: true}
	}
	if r.Control == nil {
		return readiness.Result{Ready: false, Reasons: []string{"control loop is not configured"}}
	}
	return r.Control.Readiness()
}

func (r *Runtime) CreateCertificateCSR(input identity.CSRInput) ([]byte, error) {
	if r == nil || r.Certs == nil {
		return nil, errors.New("confidential certificate store is not initialized")
	}
	return r.Certs.CreateCSR(input)
}

func (r *Runtime) StageRenewedCertificate(ctx context.Context, chain []byte) (identity.CertificateState, error) {
	if r == nil || r.Certs == nil {
		return identity.CertificateState{}, errors.New("confidential certificate store is not initialized")
	}
	state, err := r.Certs.StageRenewedChain(chain)
	if err != nil {
		return identity.CertificateState{}, err
	}
	if err := r.refreshQuoteAfterCertificateChange(ctx); err != nil {
		return state, err
	}
	return state, nil
}

func (r *Runtime) ActivateStagedCertificate(ctx context.Context, hash string) (identity.CertificateState, error) {
	if r == nil || r.Certs == nil {
		return identity.CertificateState{}, errors.New("confidential certificate store is not initialized")
	}
	state, err := r.Certs.ActivateStaged(hash)
	if err != nil {
		return identity.CertificateState{}, err
	}
	if err := r.refreshQuoteAfterCertificateChange(ctx); err != nil {
		return state, err
	}
	return state, nil
}

func (r *Runtime) PruneAcceptedCertificates(ctx context.Context) (identity.CertificateState, error) {
	if r == nil || r.Certs == nil {
		return identity.CertificateState{}, errors.New("confidential certificate store is not initialized")
	}
	state, err := r.Certs.PruneAcceptedToActive()
	if err != nil {
		return identity.CertificateState{}, err
	}
	if err := r.refreshQuoteAfterCertificateChange(ctx); err != nil {
		return state, err
	}
	return state, nil
}

func (r *Runtime) refreshQuoteAfterCertificateChange(ctx context.Context) error {
	if r == nil || r.Quotes == nil {
		return errors.New("confidential quote manager is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.Quotes.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh quote after certificate state change: %w", err)
	}
	return nil
}

func (l *ControlLoop) Readiness() readiness.Result {
	if l == nil {
		return readiness.Result{Ready: false, Reasons: []string{"control loop is not configured"}}
	}
	return l.readinessResult()
}

func newControlLoop(config stogas.ConfidentialConfig, material *identity.Material, certs *identity.CertificateStore, manager *quote.Manager, secrets *secretstore.Store, catalogHash string, entropyReady bool) *ControlLoop {
	return &ControlLoop{
		client: provision.Client{
			AccessClientID:     config.AccessClientID,
			AccessClientSecret: config.AccessClientSecret,
			AllowInsecureLocal: config.ControlAllowHTTP,
			BaseURL:            config.ControlURL,
		},
		config:       config,
		certs:        certs,
		entropyReady: entropyReady,
		identity:     material,
		nodeID:       deriveNodeID(config, material, catalogHash),
		quotes:       manager,
		secrets:      secrets,
	}
}

func (l *ControlLoop) Start(ctx context.Context) {
	if l == nil {
		return
	}
	go l.runHeartbeats(ctx)
}

func (l *ControlLoop) GenerationID() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.generationID
}

func (l *ControlLoop) LastHeartbeatError() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastHeartbeatError
}

func (l *ControlLoop) LastSecretError() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastSecretError
}

func (l *ControlLoop) LastCertificateError() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastCertificateError
}

func (l *ControlLoop) runHeartbeats(ctx context.Context) {
	ticker := time.NewTicker(l.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			heartbeatCtx, cancel := l.controlAttemptContext(ctx)
			err := l.sendHeartbeat(heartbeatCtx)
			cancel()
			if err != nil {
				log.Printf("stogas confidential heartbeat failed: %v", err)
			}
		}
	}
}

func (l *ControlLoop) controlAttemptContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, controlRequestTimeout)
}

func (l *ControlLoop) sendHeartbeat(ctx context.Context) error {
	l.heartbeatMu.Lock()
	defer l.heartbeatMu.Unlock()

	response, err := l.sendHeartbeatOnce(ctx)
	if err != nil {
		return err
	}
	changed := false
	if response.Secrets != nil {
		if err := l.secrets.Install(secretstore.InstallInput{
			Bundle:   response.Secrets,
			Identity: l.identity,
		}); err != nil {
			l.recordSecretError(err)
			return err
		}
		l.recordSecretError(nil)
		changed = true
	}
	certificateChanged, err := l.handleCertificateInstruction(ctx, response.CertificateInstruction)
	if err != nil {
		l.recordCertificateError(err)
		return err
	}
	changed = changed || certificateChanged
	if changed {
		if _, err := l.sendHeartbeatOnce(ctx); err != nil {
			return err
		}
	}
	l.recordCertificateError(nil)
	return nil
}

func (l *ControlLoop) sendHeartbeatOnce(ctx context.Context) (*provision.HeartbeatResponse, error) {
	snapshot, err := l.quotes.Current(ctx)
	if err != nil {
		l.recordHeartbeatError(err)
		return nil, err
	}
	input := provision.HeartbeatInput{
		CertExpiresAt: l.certs.State().ExpiresAt,
		Health: provision.NodeHealth{
			LastQuoteError: lastErrorString(l.quotes.LastError()),
			Ready:          l.localReadinessResultAt(time.Now()).Ready,
			SecretVersions: l.secrets.Versions(),
		},
		NodeID:     l.nodeID,
		ObservedAt: time.Now().UTC(),
		Quote:      snapshot,
	}
	response, err := l.client.SendHeartbeat(ctx, input)
	if err != nil {
		l.recordHeartbeatError(err)
		return nil, err
	}
	l.mu.Lock()
	l.generationID = response.GenerationID
	if response.ReadyUntil != nil {
		l.admissionReadyUntil = response.ReadyUntil.UTC()
	} else {
		l.admissionReadyUntil = time.Time{}
	}
	l.lastHeartbeatError = nil
	l.mu.Unlock()
	return response, nil
}

func (l *ControlLoop) handleCertificateInstruction(ctx context.Context, instruction *provision.CertificateInstruction) (bool, error) {
	if instruction == nil {
		return false, nil
	}
	switch instruction.Action {
	case "request_csr":
		csr, err := l.certs.CreateCSR(identity.CSRInput{
			CommonName: instruction.CommonName,
			DNSNames:   instruction.DNSNames,
		})
		if err != nil {
			return false, fmt.Errorf("create certificate CSR: %w", err)
		}
		generationID := l.GenerationID()
		if generationID == "" {
			return false, errors.New("generation id is not available for certificate CSR")
		}
		if _, err := l.client.SubmitCertificateCSR(ctx, provision.CertificateCSRSubmission{
			CommonName:    instruction.CommonName,
			CSRDER:        csr,
			DNSNames:      instruction.DNSNames,
			GenerationID:  generationID,
			OrderID:       instruction.OrderID,
			TLSSPKISHA256: l.identity.TLSSPKISHA256,
		}); err != nil {
			return false, fmt.Errorf("submit certificate CSR: %w", err)
		}
		return false, nil
	case "install_renewed_chain":
		current := l.certs.State()
		if current.ActiveCertSHA256 == instruction.NewCertSHA256 && containsString(current.AcceptedCertSHA256, instruction.NewCertSHA256) {
			return false, nil
		}
		state, err := l.certs.StageRenewedChain([]byte(instruction.CertChainPEM))
		if err != nil {
			return false, fmt.Errorf("stage renewed certificate chain: %w", err)
		}
		if !containsString(state.AcceptedCertSHA256, instruction.NewCertSHA256) {
			return false, errors.New("staged certificate hash did not match control instruction")
		}
		if err := l.refreshQuoteAfterCertificateChange(ctx); err != nil {
			return false, err
		}
		return true, nil
	case "install_active_chain":
		current := l.certs.State()
		if current.ActiveCertSHA256 == instruction.NewCertSHA256 && len(current.AcceptedCertSHA256) == 1 && current.AcceptedCertSHA256[0] == instruction.NewCertSHA256 {
			return false, nil
		}
		state, err := l.certs.InstallActiveChainWithExpectedHash([]byte(instruction.CertChainPEM), instruction.NewCertSHA256)
		if err != nil {
			return false, fmt.Errorf("install active certificate chain: %w", err)
		}
		if state.ActiveCertSHA256 != instruction.NewCertSHA256 || len(state.AcceptedCertSHA256) != 1 || state.AcceptedCertSHA256[0] != instruction.NewCertSHA256 {
			return false, errors.New("installed active certificate state did not match control instruction")
		}
		if err := l.refreshQuoteAfterCertificateChange(ctx); err != nil {
			return false, err
		}
		return true, nil
	case "activate_staged":
		if l.certs.State().ActiveCertSHA256 == instruction.CertSHA256 {
			return false, nil
		}
		state, err := l.certs.ActivateStaged(instruction.CertSHA256)
		if err != nil {
			return false, fmt.Errorf("activate staged certificate: %w", err)
		}
		if state.ActiveCertSHA256 != instruction.CertSHA256 {
			return false, errors.New("active certificate hash did not match control instruction")
		}
		if err := l.refreshQuoteAfterCertificateChange(ctx); err != nil {
			return false, err
		}
		return true, nil
	case "prune_accepted":
		before := l.certs.State()
		if before.ActiveCertSHA256 != instruction.ActiveCertSHA256 {
			return false, errors.New("cannot prune accepted certificates for non-active control hash")
		}
		state, err := l.certs.PruneAcceptedToActive()
		if err != nil {
			return false, fmt.Errorf("prune accepted certificates: %w", err)
		}
		if state.ActiveCertSHA256 != instruction.ActiveCertSHA256 || len(state.AcceptedCertSHA256) != 1 || state.AcceptedCertSHA256[0] != instruction.ActiveCertSHA256 {
			return false, errors.New("pruned certificate state did not match control instruction")
		}
		if err := l.refreshQuoteAfterCertificateChange(ctx); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported certificate instruction %q", instruction.Action)
	}
}

func (l *ControlLoop) refreshQuoteAfterCertificateChange(ctx context.Context) error {
	if l == nil || l.quotes == nil {
		return errors.New("confidential quote manager is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := l.quotes.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh quote after certificate state change: %w", err)
	}
	return nil
}

func (l *ControlLoop) readinessResult() readiness.Result {
	return l.readinessResultAt(time.Now())
}

func (l *ControlLoop) readinessResultAt(now time.Time) readiness.Result {
	local := l.localReadinessStateAt(now)
	l.mu.RLock()
	admissionReadyUntil := l.admissionReadyUntil
	l.mu.RUnlock()
	local.ControlAdmitted = !admissionReadyUntil.IsZero() && now.Before(admissionReadyUntil)
	return readiness.Evaluate(local)
}

func (l *ControlLoop) localReadinessResultAt(now time.Time) readiness.Result {
	state := l.localReadinessStateAt(now)
	state.ControlAdmitted = true
	return readiness.Evaluate(state)
}

func (l *ControlLoop) localReadinessStateAt(now time.Time) readiness.State {
	quoteReady := false
	quoteForwardSafe := false
	if snapshot, err := l.quotes.Current(context.Background()); err == nil && snapshot != nil {
		quoteReady = len(snapshot.Quote) > 0
		quoteAge := now.Sub(snapshot.GeneratedAt)
		quoteForwardSafe = quoteAge >= 0 && quoteAge <= localQuoteReadyWindow
	}
	certState := l.certs.State()
	return readiness.State{
		CertificateReady:           !certState.ExpiresAt.IsZero(),
		CertificateSafe:            certState.ExpiresAt.Sub(now) > 48*time.Hour,
		Draining:                   false,
		EntropyReady:               l.entropyReady,
		IdentityReady:              true,
		QuoteForwardSafe:           quoteForwardSafe,
		QuoteReady:                 quoteReady,
		RuntimeDependenciesHealthy: true,
		SecretsReady:               l.secrets != nil && l.secrets.Ready(),
		Serving:                    true,
	}
}

func (l *ControlLoop) recordHeartbeatError(err error) {
	l.mu.Lock()
	l.lastHeartbeatError = err
	l.mu.Unlock()
}

func (l *ControlLoop) recordSecretError(err error) {
	l.mu.Lock()
	l.lastSecretError = err
	l.mu.Unlock()
}

func (l *ControlLoop) recordCertificateError(err error) {
	l.mu.Lock()
	l.lastCertificateError = err
	l.mu.Unlock()
}

func deriveNodeID(config stogas.ConfidentialConfig, material *identity.Material, catalogHash string) string {
	preimage, _ := json.Marshal(map[string]string{
		"catalog_hash":       catalogHash,
		"ed25519_public_key": material.Ed25519PublicKey,
		"hpke_public_key":    material.HPKEPublicKey,
		"tls_spki_sha256":    material.TLSSPKISHA256,
	})
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:])
}

func lastErrorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type mockQuote struct {
	AttesterMode     string `json:"attester_mode"`
	ReportDataSHA512 string `json:"report_data_sha512"`
	Schema           string `json:"schema"`
	QuoteGeneratedAt string `json:"quote_generated_at"`
}

type mockAttester struct {
	mode string
	now  func() time.Time
}

func (a mockAttester) Quote(ctx context.Context, reportData [64]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := a.now
	if now == nil {
		now = time.Now
	}
	payload, err := json.Marshal(mockQuote{
		AttesterMode:     a.mode,
		ReportDataSHA512: fmt.Sprintf("%x", reportData[:]),
		Schema:           "stogas.local-mock-quote.v1",
		QuoteGeneratedAt: now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func newAttester(config stogas.ConfidentialConfig) (quote.Attester, error) {
	switch config.AttesterMode {
	case "mock", "igvm-native":
		return mockAttester{mode: config.AttesterMode}, nil
	case "sev-snp":
		return attest.DefaultSEVSNP(), nil
	default:
		return nil, fmt.Errorf("unsupported attester mode %q", config.AttesterMode)
	}
}

func newDrandSource(config stogas.ConfidentialConfig) (*drand.Source, error) {
	switch config.AttesterMode {
	case "mock", "igvm-native":
		return drand.NewSource(drand.FetcherFunc(func(ctx context.Context) (reportdata.Drand, error) {
			if err := ctx.Err(); err != nil {
				return reportdata.Drand{}, err
			}
			return mockDrandBeacon(), nil
		}), drand.SignatureVerifierFunc(func(ctx context.Context, beacon reportdata.Drand) error {
			return ctx.Err()
		}))
	case "sev-snp":
		fetcher := drand.NewHTTPFetcher(nil, "")
		verifier, err := drand.NewQuicknetVerifier()
		if err != nil {
			return nil, err
		}
		return drand.NewSource(fetcher, verifier)
	default:
		return nil, fmt.Errorf("unsupported attester mode %q", config.AttesterMode)
	}
}

func mockDrandBeacon() reportdata.Drand {
	signature := base64.RawURLEncoding.EncodeToString([]byte("stogas-local-mock-drand-signature"))
	randomness, _ := drand.RandomnessFromSignature(hexish(signature, 96))
	return reportdata.Drand{
		Network:    reportdata.DrandNetworkQuicknet,
		ChainHash:  reportdata.QuicknetChainHash,
		Round:      1,
		Randomness: randomness,
		Signature:  hexish(signature, 96),
	}
}

func hexish(seed string, length int) string {
	const alphabet = "0123456789abcdef"
	var builder strings.Builder
	for builder.Len() < length {
		for _, ch := range seed {
			builder.WriteByte(alphabet[int(ch)%len(alphabet)])
			if builder.Len() == length {
				break
			}
		}
	}
	return builder.String()
}
