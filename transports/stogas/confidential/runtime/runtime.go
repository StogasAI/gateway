package runtime

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
	"github.com/maximhq/bifrost/transports/stogas/confidential/entropy"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
	"github.com/maximhq/bifrost/transports/stogas/confidential/readiness"
	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

const sessionIdleTimeout = 10 * time.Minute

var (
	ErrCertificateInstruction    = errors.New("confidential certificate installation failed")
	ErrSecretReleaseInstallation = errors.New("confidential secret installation failed")
)

// Resources uses the listener's aggregate memory admission, not a separate pool.
type Resources struct {
	Quote   attest.QuoteReservation
	Session channel.SessionReservation
}

type Runtime struct {
	Certs        *identity.CertificateStore
	Proofs       *proofhttp.Service
	Secrets      *secretstore.Store
	Sessions     *channel.Store
	NativeIssuer attest.NativeCertificateIssuer
	maintenance  *bootMaintenance
	region       provision.Region
	batcher      *attest.Batcher
	material     *identity.Material
	keys         *verifier.NodeKeys
	cancel       context.CancelFunc
	done         chan struct{}
	shutdown     chan struct{}
	drainOnce    sync.Once
	closeOnce    sync.Once
}

type MaintenanceDiagnostics struct {
	Region                   provision.Region           `json:"region"`
	ConsecutiveFailures      uint32                     `json:"consecutive_failures"`
	LastAttemptAt            *time.Time                 `json:"last_attempt_at"`
	LastSuccessAt            *time.Time                 `json:"last_success_at"`
	EvidenceReason           string                     `json:"evidence_reason,omitempty"`
	CertificateRenewalFailed bool                       `json:"certificate_renewal_failed"`
	Quotes                   attest.QuoteDiagnostics    `json:"quotes"`
	Sessions                 channel.SessionDiagnostics `json:"sessions"`
}

func Start(ctx context.Context, config stogas.ConfidentialConfig, resources Resources) (*Runtime, error) {
	if !config.Enabled {
		return nil, nil
	}
	config = config.WithRuntimeDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Environment != "staging" && config.Environment != "production" {
		return nil, errors.New("confidential startup requires a deployment environment")
	}
	if config.InstanceID == "" || resources.Quote == nil || resources.Session == nil {
		return nil, errors.New("confidential startup requires an instance and memory admission")
	}
	entropyContext, cancel := context.WithTimeout(ctx, config.EntropyTimeout)
	err := entropy.Wait(entropyContext, nil)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("confidential entropy readiness: %w", err)
	}
	evidence, err := newCurrentEvidence(config.Environment)
	if err != nil {
		return nil, err
	}
	material, err := identity.Generate(nil)
	if err != nil {
		evidence.close()
		return nil, err
	}
	keys, err := verifier.GenerateNodeKeys(nil)
	if err != nil {
		evidence.close()
		return nil, err
	}
	r, err := startBoot(ctx, config, resources, evidence, material, keys, attest.DefaultSEVSNP(), nil)
	if err != nil {
		evidence.close()
		keys.Close()
		material.TLSPrivateKey = nil
	}
	return r, err
}

// startBoot does not expose listeners or secrets until registration, logged boot
// verification and the reused-address route barrier have all completed.
func startBoot(ctx context.Context, config stogas.ConfidentialConfig, resources Resources, evidence *currentEvidence, material *identity.Material, keys *verifier.NodeKeys, reporter attest.Attester, roots *x509.CertPool) (*Runtime, error) {
	environment, hostname := attest.Production, "api.stogas.ai"
	if config.Environment == "staging" {
		environment, hostname = attest.Staging, "api-staging.stogas.ai"
	}
	certs, err := identity.NewBootCertificateStore(material, roots)
	if err != nil {
		return nil, err
	}
	client := provision.Client{BaseURL: config.ControlURL, AccessClientID: config.AccessClientID, AccessClientSecret: config.AccessClientSecret, AllowInsecureLocal: config.ControlAllowHTTP}
	secrets := secretstore.NewStore()
	installed := false
	defer func() {
		if !installed {
			secrets.Close()
		}
	}()
	var boot *preparedBoot
	var response *provision.RegistrationResponse
	// A challenge is renewed only before registration or after Control explicitly
	// confirms that it expired unconsumed. Lost replies retry the exact boot and CSR.
	for {
		var challenge *provision.RegistrationChallenge
		err = retryStartup(ctx, func() (bool, error) {
			var e error
			challenge, e = client.RegistrationChallenge(ctx, config.InstanceID)
			return e == nil, e
		})
		if err != nil {
			return nil, err
		}
		quoted, e := quoteBoot(ctx, environment, material, keys, challenge.Challenge, reporter)
		if e != nil {
			return nil, e
		}
		err = retryStartup(ctx, func() (bool, error) {
			var e error
			boot, e = quoted.prepare(ctx, evidence, environment, material, keys)
			return e == nil, e
		})
		if err != nil {
			return nil, err
		}
		if !evidence.now().Before(challenge.ExpiresAt) {
			continue
		}
		csr, e := certs.CreateCSR(identity.CSRInput{CommonName: hostname, DNSNames: []string{hostname}})
		if e != nil {
			return nil, e
		}
		request := provision.NewBootRegistration(config.InstanceID, boot.document, csr)
		err = retryStartup(ctx, func() (bool, error) {
			var e error
			response, e = client.RegisterBoot(ctx, request, boot.identity.NodeID)
			return e == nil && response.Status == "ready", e
		})
		var rejected *provision.HTTPResponseError
		if errors.As(err, &rejected) && rejected.Code == "challenge_expired" {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	err = retryStartup(ctx, func() (bool, error) {
		err := evidence.refresh(ctx, func(snapshot *verifier.EvidenceSnapshot, _ evidenceSummary) error {
			_, e := snapshot.VerifyLoggedBootAt(boot.document, response.Inclusion, evidence.now())
			return e
		})
		return err == nil, err
	})
	if err != nil {
		return nil, err
	}
	completion, err := installBootCompletion(boot, response, evidence.snapshot, evidence.now(), keys, certs, secrets, hostname)
	if err != nil {
		return nil, err
	}
	logged, checked := completion.boot, completion.identity
	proofs, err := proofhttp.New(sha256.Sum256(logged.Document), checked.NodeID, keys)
	if err != nil {
		return nil, err
	}
	batcher, err := attest.NewBatcher(reporter, resources.Quote)
	if err != nil {
		return nil, err
	}
	cleanupBatcher := func() { _ = batcher.Close(context.Background()) }
	issuer, err := attest.NewNativeIssuer(environment, hostname, logged, batcher)
	if err != nil {
		cleanupBatcher()
		return nil, err
	}
	setup, err := channel.NewServerSetup(environment, logged, sessionIdleTimeout, batcher)
	if err != nil {
		cleanupBatcher()
		return nil, err
	}
	sessions, err := channel.NewStore(setup, resources.Session)
	if err != nil {
		cleanupBatcher()
		return nil, err
	}
	maintenance := &bootMaintenance{evidence: evidence, boot: logged, certs: certs, client: client, hostname: hostname, keys: keys, identity: checked}
	// A catalog delivery outage leaves this registered VM alive but unready; the
	// same maintenance loop recovers it without a new quote or registration.
	_ = maintenance.maintain(ctx)
	runtimeContext, cancel := context.WithCancel(ctx)
	r := &Runtime{Certs: certs, Proofs: proofs, Secrets: secrets, Sessions: sessions, NativeIssuer: issuer, maintenance: maintenance, region: completion.region, batcher: batcher, material: material, keys: keys, cancel: cancel, done: make(chan struct{}), shutdown: make(chan struct{})}
	installed = true
	go r.run(runtimeContext)
	return r, nil
}

// Startup retries are bounded in pace and memory, not by an arbitrary fleet
// provisioning timeout. Cancellation and definitive Control rejection stop them.
func retryStartup(ctx context.Context, attempt func() (bool, error)) error {
	delay := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := attempt()
		if done && err == nil {
			return nil
		}
		if provision.IsAuthoritativeRejection(err) {
			return err
		}
		if err := waitContext(ctx, jitter(delay)); err != nil {
			return err
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func jitter(interval time.Duration) time.Duration {
	return interval - interval/10 + time.Duration(rand.Int64N(int64(interval/5)+1))
}
func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (r *Runtime) run(ctx context.Context) {
	defer close(r.done)
	// Acknowledgement only releases Control's recovery storage. Delivery failure
	// cannot take away a locally verified boot's permission to serve.
	_ = r.maintenance.completeRegistration(ctx)
	// Idle-session cleanup is local and shares the maintenance owner; it does not
	// cause a Control/evidence request on every cleanup tick.
	timer := time.NewTimer(jitter(evidencePollInterval))
	defer timer.Stop()
	idle := time.NewTicker(time.Minute)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-idle.C:
			r.Sessions.ExpireIdle()
		case <-timer.C:
			_ = r.maintenance.maintain(ctx)
			_ = r.maintenance.completeRegistration(ctx)
			err := r.maintenance.renewCertificate(ctx)
			r.maintenance.mu.Lock()
			r.maintenance.renewalFailed = err != nil
			r.maintenance.mu.Unlock()
			timer.Reset(jitter(evidencePollInterval))
		}
	}
}

func (r *Runtime) NodeID() string {
	if r == nil || r.maintenance == nil {
		return ""
	}
	r.maintenance.mu.RLock()
	defer r.maintenance.mu.RUnlock()
	return r.maintenance.identity.NodeID
}
func (r *Runtime) Readiness() readiness.Result {
	if r == nil {
		return readiness.Result{Ready: true}
	}
	if r.maintenance == nil {
		return readiness.Result{Reasons: []string{"confidential runtime is not initialized"}}
	}
	return r.maintenance.readiness()
}
func (r *Runtime) Diagnostics() *MaintenanceDiagnostics {
	if r == nil || r.maintenance == nil {
		return nil
	}
	m := r.maintenance
	m.mu.RLock()
	result := &MaintenanceDiagnostics{Region: r.region, ConsecutiveFailures: m.failures, LastAttemptAt: timePointer(m.lastAttempt), LastSuccessAt: timePointer(m.lastSuccess), EvidenceReason: m.evidenceReason, CertificateRenewalFailed: m.renewalFailed}
	if result.EvidenceReason == "" && (m.identity.NodeID == "" || m.evidence.now().UnixMilli() < m.identity.ValidFromUnixMS || m.evidence.now().UnixMilli() >= m.identity.ValidUntilUnixMS) {
		result.EvidenceReason = "required collateral is not valid"
	}
	m.mu.RUnlock()
	result.Quotes = r.batcher.Diagnostics()
	result.Sessions = r.Sessions.Diagnostics()
	return result
}
func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

// Drain is terminal. Evidence recovery never overrides an operator removal.
func (r *Runtime) Drain() {
	if r == nil {
		return
	}
	r.drainOnce.Do(func() {
		if r.maintenance != nil {
			r.maintenance.drain()
		}
		if r.Sessions != nil {
			r.Sessions.Close()
		}
		if r.shutdown != nil {
			close(r.shutdown)
		}
	})
}
func (r *Runtime) ShutdownRequested() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.shutdown
}

// Close follows HTTP/provider drain. It joins maintenance before freeing the
// offline verifier and keys; canceling a caller is not resource destruction.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.Drain()
		if r.cancel != nil {
			r.cancel()
			<-r.done
		}
		if r.Sessions != nil {
			r.Sessions.Close()
		}
		if r.batcher != nil {
			_ = r.batcher.Close(context.Background())
		}
		if r.maintenance != nil {
			r.maintenance.evidence.close()
		}
		if r.Secrets != nil {
			r.Secrets.Close()
		}
		if r.Proofs != nil {
			r.Proofs.Close()
		}
		if r.keys != nil {
			r.keys.Close()
		}
		if r.material != nil {
			r.material.TLSPrivateKey = nil
		}
	})
}
