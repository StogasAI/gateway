package runtime

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
)

func maintenanceCertificate(t *testing.T, fixtureNow time.Time) *identity.CertificateStore {
	t.Helper()
	material, err := identity.Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Installation uses the real clock; appraisal uses the recorded evidence's
	// clock. The certificate must cover both, regardless of when this test runs.
	start, end := time.Now(), time.Now()
	if fixtureNow.Before(start) {
		start = fixtureNow
	}
	if fixtureNow.After(end) {
		end = fixtureNow
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api-staging.stogas.ai"}, DNSNames: []string{"api-staging.stogas.ai"}, NotBefore: start.Add(-24 * time.Hour), NotAfter: end.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &material.TLSPrivateKey.PublicKey, material.TLSPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	store, err := identity.NewBootCertificateStore(material, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.InstallBootChain(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "api-staging.stogas.ai"); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestMaintenanceLocalExpiryPolicyRecoveryAndTerminalDrain(t *testing.T) {
	fixture := evidenceFixture(t)
	evidence := fixtureEvidence(t, fixture)
	snapshot, err := evidence.verifier.RefreshAt(fixture.Bundle, evidence.now())
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	document := fixture.Boot.document(t)
	m := &bootMaintenance{evidence: evidence, boot: attest.BootEvidence{Document: document, Inclusion: fixture.Inclusion}, certs: maintenanceCertificate(t, evidence.now())}
	if m.readiness().Ready {
		t.Fatal("unappraised node became ready")
	}
	if err := m.appraise(snapshot, evidenceSummary{}); err != nil {
		t.Fatal(err)
	}
	// Artifact loading has separate hash/compatibility tests. This isolates admission
	// transitions once an approved catalog is installed.
	m.catalogReady = true
	if !m.readiness().Ready {
		t.Fatal(m.readiness())
	}
	initial := m.identity
	evidence.now = func() time.Time { return time.UnixMilli(initial.ValidUntilUnixMS) }
	if !slices.Contains(m.readiness().Reasons, "required collateral is not valid") {
		t.Fatal("expiry waited for a network refresh")
	}
	evidence.now = func() time.Time { return time.UnixMilli(fixture.Now) }
	m.boot.Inclusion = []byte(`{}`)
	if err := m.appraise(snapshot, evidenceSummary{}); err == nil || m.readiness().Ready {
		t.Fatal("rejected boot did not close admission")
	}
	m.boot.Inclusion = fixture.Inclusion
	if err := m.appraise(snapshot, evidenceSummary{}); err != nil {
		t.Fatal(err)
	}
	m.catalogReady = true
	if !m.readiness().Ready {
		t.Fatal("policy recovery did not reopen admission")
	}
	m.drain()
	if err := m.appraise(snapshot, evidenceSummary{}); err != nil {
		t.Fatal(err)
	}
	m.catalogReady = true
	if m.readiness().Ready || !slices.Contains(m.readiness().Reasons, "node is draining") {
		t.Fatal("evidence refresh undid terminal drain")
	}
}

func TestMaintenanceAdmissionReadsRaceSafelyWithAppraisalAndDrain(t *testing.T) {
	fixture := evidenceFixture(t)
	evidence := fixtureEvidence(t, fixture)
	snapshot, err := evidence.verifier.RefreshAt(fixture.Bundle, evidence.now())
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	document := fixture.Boot.document(t)
	m := &bootMaintenance{evidence: evidence, boot: attest.BootEvidence{Document: document, Inclusion: fixture.Inclusion}, certs: maintenanceCertificate(t, evidence.now())}
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			for range 25 {
				_ = m.readiness()
			}
		})
	}
	group.Go(func() {
		for range 5 {
			if err := m.appraise(snapshot, evidenceSummary{}); err != nil {
				t.Error(err)
			}
		}
	})
	group.Go(m.drain)
	group.Wait()
	if m.readiness().Ready {
		t.Fatal("terminal drain was lost")
	}
}

func testNodeKeys(t *testing.T) *verifier.NodeKeys {
	t.Helper()
	keys, err := verifier.GenerateNodeKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	return keys
}

func TestCertificateRenewalRetainsInstalledStateAndRespectsTerminalDrain(t *testing.T) {
	keys := testNodeKeys(t)
	for _, tc := range []struct {
		name                        string
		status                      string
		notDue, terminal, wantError bool
	}{
		{name: "not due", notDue: true},
		{name: "terminal drain", terminal: true},
		{name: "pending", status: "pending"},
		{name: "unavailable", status: "unavailable", wantError: true},
		{name: "invalid certificate", status: "invalid", wantError: true},
		{name: "ready certificate", status: "ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := maintenanceCertificate(t, time.Now())
			before := store.State()
			active, _ := store.ActiveTLSCertificate()
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: active.Certificate[0]})
			now := before.ExpiresAt.Add(-29 * 24 * time.Hour)
			if tc.notDue {
				now = before.NotBefore.Add(time.Hour)
			}
			var calls atomic.Int32
			node := "amber-anchor-01"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if tc.status == "unavailable" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				response := provision.BootCertificateResponse{Status: tc.status, NodeID: node}
				if tc.status == "ready" {
					response.CertificatePEM = string(pemBytes)
				} else if tc.status == "invalid" {
					response.Status, response.CertificatePEM = "ready", "invalid certificate"
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			m := &bootMaintenance{
				certs: store, evidence: &currentEvidence{now: func() time.Time { return now }},
				client:   provision.Client{BaseURL: server.URL, AllowInsecureLocal: true},
				hostname: "api-staging.stogas.ai", keys: keys, terminal: tc.terminal,
			}
			m.identity.NodeID = node
			if err := m.renewCertificate(t.Context()); (err != nil) != tc.wantError {
				t.Fatalf("renewal error = %v, want error %t", err, tc.wantError)
			}
			wantCalls := int32(1)
			if tc.notDue || tc.terminal {
				wantCalls = 0
			}
			if calls.Load() != wantCalls || store.State() != before || m.terminal != tc.terminal {
				t.Fatal("renewal changed the installed certificate or terminal state unexpectedly")
			}
		})
	}
}

func TestRegistrationAcknowledgementRetriesWithoutChangingLocalAdmission(t *testing.T) {
	fixture := evidenceFixture(t)
	evidence := fixtureEvidence(t, fixture)
	snapshot, err := evidence.verifier.RefreshAt(fixture.Bundle, evidence.now())
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	document := fixture.Boot.document(t)
	keys := testNodeKeys(t)
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry recovers", true: "drain cancels retry"}[terminal], func(t *testing.T) {
			m := &bootMaintenance{evidence: evidence, boot: attest.BootEvidence{Document: document, Inclusion: fixture.Inclusion}, certs: maintenanceCertificate(t, evidence.now()), keys: keys}
			if err := m.appraise(snapshot, evidenceSummary{}); err != nil {
				t.Fatal(err)
			}
			m.catalogReady = true
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/fleet/registration/complete" {
					t.Error("unexpected maintenance request")
				}
				if calls.Add(1) == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "complete", "node_id": m.identity.NodeID})
			}))
			defer server.Close()
			m.client = provision.Client{BaseURL: server.URL, AllowInsecureLocal: true}
			if err := m.completeRegistration(t.Context()); err == nil || !m.readiness().Ready || m.registrationComplete {
				t.Fatal("failed acknowledgement changed admission or completion")
			}
			if terminal {
				m.drain()
			}
			if err := m.completeRegistration(t.Context()); err != nil {
				t.Fatal(err)
			}
			if terminal {
				if calls.Load() != 1 || m.registrationComplete || m.readiness().Ready {
					t.Fatal("draining boot retried completion")
				}
			} else {
				if !m.registrationComplete || !m.readiness().Ready {
					t.Fatal("retry failed to acknowledge while preserving admission")
				}
				if err := m.completeRegistration(t.Context()); err != nil || calls.Load() != 2 {
					t.Fatal("completed registration kept polling Control")
				}
			}
		})
	}
}
