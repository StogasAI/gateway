package runtime

import (
	"context"
	"errors"
	"sync"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
	"github.com/maximhq/bifrost/transports/stogas/confidential/readiness"
)

// bootMaintenance has one I/O owner. Public admission reads only this small
// local state; neither a health probe nor a request performs evidence network I/O.
// A policy pause is reversible. Terminal drain cannot be undone by maintenance.
type bootMaintenance struct {
	evidence *currentEvidence
	boot     attest.BootEvidence
	certs    *identity.CertificateStore
	client   provision.Client
	hostname string
	keys     *verifier.NodeKeys

	mu                   sync.RWMutex
	identity             verifier.BootIdentity
	evidenceReason       string
	catalogReady         bool
	terminal             bool
	lastAttempt          time.Time
	lastSuccess          time.Time
	renewalFailed        bool
	failures             uint32
	registrationComplete bool // owned by the maintenance loop
}

func (m *bootMaintenance) appraise(snapshot *verifier.EvidenceSnapshot, summary evidenceSummary) error {
	checked, err := snapshot.VerifyLoggedBootAt(m.boot.Document, m.boot.Inclusion, m.evidence.now())
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.evidenceReason = "required evidence is not valid"
		return err
	}
	if m.identity.NodeID != "" && (checked.NodeID != m.identity.NodeID || checked.BootSHA256 != m.identity.BootSHA256) {
		m.evidenceReason = "boot identity differs"
		return errors.New(m.evidenceReason)
	}
	m.identity = checked
	m.evidenceReason = ""
	m.catalogReady = summary.activeCatalogApproved(checked.GatewayReleaseID)
	return nil
}

func (m *bootMaintenance) maintain(ctx context.Context) error {
	m.mu.Lock()
	m.lastAttempt = m.evidence.now()
	m.mu.Unlock()
	err := m.evidence.refresh(ctx, m.appraise)
	// Catalog delivery failure may keep an older still-approved catalog in use.
	// Never keep one omitted from the authenticated current approval set.
	if m.evidence.snapshot != nil {
		m.mu.RLock()
		gatewayID := m.identity.GatewayReleaseID
		m.mu.RUnlock()
		catalogErr := m.evidence.updateCatalog(ctx, gatewayID)
		m.mu.Lock()
		m.catalogReady = m.evidence.summary.activeCatalogApproved(gatewayID)
		m.mu.Unlock()
		err = errors.Join(err, catalogErr)
	}
	m.mu.Lock()
	if err == nil {
		m.lastSuccess = m.evidence.now()
		m.failures = 0
	} else if m.failures < ^uint32(0) {
		m.failures++
	}
	m.mu.Unlock()
	return err
}

func (m *bootMaintenance) readiness() readiness.Result {
	m.mu.RLock()
	defer m.mu.RUnlock()
	reasons := make([]string, 0, 4)
	if m.terminal {
		reasons = append(reasons, "node is draining")
	}
	if m.evidenceReason != "" {
		reasons = append(reasons, m.evidenceReason)
	}
	now := m.evidence.now()
	if m.identity.NodeID == "" || now.UnixMilli() < m.identity.ValidFromUnixMS || now.UnixMilli() >= m.identity.ValidUntilUnixMS {
		reasons = append(reasons, "required collateral is not valid")
	}
	if !m.catalogReady {
		reasons = append(reasons, "approved compatible catalog is not installed")
	}
	certificate := m.certs.State()
	if certificate.NotBefore.IsZero() || now.Before(certificate.NotBefore) || !now.Before(certificate.ExpiresAt) {
		reasons = append(reasons, "certificate is not valid")
	}
	return readiness.Result{Ready: len(reasons) == 0, Reasons: reasons}
}

func (m *bootMaintenance) drain() {
	m.mu.Lock()
	m.terminal = true
	m.mu.Unlock()
}

func (m *bootMaintenance) completeRegistration(ctx context.Context) error {
	if m.registrationComplete {
		return nil
	}
	m.mu.RLock()
	nodeID, terminal := m.identity.NodeID, m.terminal
	m.mu.RUnlock()
	if terminal {
		return nil
	}
	if err := m.client.CompleteBootRegistration(ctx, nodeID, m.boot, m.keys); err != nil {
		return err
	}
	m.registrationComplete = true
	return nil
}

// Renewal is maintenance, never a serving lease. A pending/failed renewal keeps
// the installed certificate until its actual expiry. Runtime secrets do not change.
func (m *bootMaintenance) renewCertificate(ctx context.Context) error {
	certificate := m.certs.State()
	if certificate.NotBefore.IsZero() {
		return errors.New("certificate is not installed")
	}
	due := certificate.NotBefore.Add(certificate.ExpiresAt.Sub(certificate.NotBefore) * 2 / 3)
	if earlier := certificate.ExpiresAt.Add(-30 * 24 * time.Hour); earlier.After(certificate.NotBefore) && earlier.Before(due) {
		due = earlier
	}
	if m.evidence.now().Before(due) {
		return nil
	}
	m.mu.RLock()
	nodeID, terminal := m.identity.NodeID, m.terminal
	m.mu.RUnlock()
	if terminal {
		return nil
	}
	csr, err := m.certs.CreateCSR(identity.CSRInput{CommonName: m.hostname, DNSNames: []string{m.hostname}})
	if err != nil {
		return err
	}
	response, err := m.client.RenewBootCertificate(ctx, nodeID, m.boot, csr, m.keys)
	if err != nil {
		return err
	}
	if response.Status == "pending" {
		return nil
	}
	_, err = m.certs.InstallBootChain([]byte(response.CertificatePEM), m.hostname)
	return err
}
