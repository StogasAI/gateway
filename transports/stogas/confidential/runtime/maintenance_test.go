package runtime

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifier "github.com/StogasAI/stogas/go"
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

// fixtureSnapshot verifies a sample bundle at the evidence clock, as refresh does.
func fixtureSnapshot(t *testing.T, evidence *currentEvidence, bundle []byte) (*verifier.EvidenceSnapshot, evidenceSummary) {
	t.Helper()
	snapshot, err := evidence.verifier.RefreshAt(bundle, evidence.now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	summary, err := summarize(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, summary
}

// evidenceReasons is readiness apart from the catalog: the samples approve
// catalogs without shipping their bytes, and catalog admission has its own tests.
func evidenceReasons(m *bootMaintenance) []string {
	return slices.DeleteFunc(m.readiness().Reasons, func(reason string) bool { return reason == catalogReason(nil) })
}

func sampleOrigin(t *testing.T, bundle json.RawMessage) (*httptest.Server, *atomic.Value, *atomic.Bool) {
	t.Helper()
	var delivery atomic.Value
	delivery.Store(bundle)
	var blocked atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if blocked.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(delivery.Load().(json.RawMessage))
	}))
	t.Cleanup(server.Close)
	return server, &delivery, &blocked
}

// An online key change publishes a key manifest that makes a new key active and
// retires the boot's key, then one that omits it. Admission stays open through the
// first while requests read it; the second closes it, so gateways are replaced in between.
func TestMaintenanceKeyChangeKeepsAdmissionUntilTheOldKeyIsOmitted(t *testing.T) {
	fixture := evidenceFixture(t)
	server, delivery, _ := sampleOrigin(t, fixture.Bundle)
	evidence := fixtureEvidence(t, fixture, server.URL)
	m := &bootMaintenance{evidence: evidence, boot: attest.BootEvidence{Document: fixture.Boot.document(t), Inclusion: fixture.Inclusion}, certs: maintenanceCertificate(t, evidence.now())}
	if err := evidence.refresh(t.Context(), m.appraise); err != nil {
		t.Fatal(err)
	}
	if reasons := evidenceReasons(m); len(reasons) != 0 {
		t.Fatal(reasons)
	}
	var closed atomic.Value
	stop := make(chan struct{})
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if reasons := evidenceReasons(m); len(reasons) != 0 {
					closed.Store(reasons)
				}
			}
		})
	}
	initial := evidence.snapshot
	delivery.Store(fixture.RotatedBundle)
	err := evidence.refresh(t.Context(), m.appraise)
	close(stop)
	group.Wait()
	if err != nil || evidence.snapshot == initial {
		t.Fatalf("the new key manifest was not installed: %v", err)
	}
	if reasons := closed.Load(); reasons != nil {
		t.Fatalf("the key change closed admission: %v", reasons)
	}
	delivery.Store(fixture.PrunedBundle)
	if err := evidence.refresh(t.Context(), m.appraise); err == nil || !slices.Equal(evidenceReasons(m), []string{"required evidence is not valid"}) {
		t.Fatalf("omitting the boot's key kept admission open: %v %v", err, m.readiness().Reasons)
	}
}

// Blocked downloads keep admission open until the key manifest expires, close it at
// that instant without network I/O, and the next newer copy reopens it.
func TestMaintenanceEvidenceExpiryClosesAdmissionUntilANewerCopyArrives(t *testing.T) {
	fixture := evidenceFixture(t)
	server, delivery, blocked := sampleOrigin(t, fixture.Expiring.Bundle)
	evidence := fixtureEvidence(t, fixture, server.URL)
	now := time.UnixMilli(fixture.Expiring.Now)
	evidence.now = func() time.Time { return now }
	m := &bootMaintenance{evidence: evidence, boot: attest.BootEvidence{Document: fixture.Boot.document(t), Inclusion: fixture.Inclusion}, certs: maintenanceCertificate(t, now)}
	if err := evidence.refresh(t.Context(), m.appraise); err != nil {
		t.Fatal(err)
	}
	expiry := evidence.summary.Keys.Document.ExpiresAt
	if m.identity.ValidUntilUnixMS != expiry.UnixMilli() {
		t.Fatal("the sample's AMD collateral expires before its key manifest; make the samples again")
	}
	if reasons := evidenceReasons(m); len(reasons) != 0 {
		t.Fatal(reasons)
	}
	blocked.Store(true)
	now = expiry.Add(-time.Millisecond)
	if err := evidence.refresh(t.Context(), m.appraise); err == nil {
		t.Fatal("a blocked download succeeded")
	}
	if reasons := evidenceReasons(m); len(reasons) != 0 {
		t.Fatalf("blocked downloads closed admission before expiry: %v", reasons)
	}
	now = expiry
	if reasons := evidenceReasons(m); !slices.Equal(reasons, []string{"current evidence has expired"}) {
		t.Fatalf("expiry waited for a network refresh: %v", reasons)
	}

	// A gateway without newer evidence refuses the expired copy outright.
	fresh := fixtureEvidence(t, fixture, server.URL)
	fresh.now = evidence.now
	blocked.Store(false)
	var failure *verifier.VerificationError
	if err := fresh.refresh(t.Context(), fixtureAppraisal(t, fixture)); !errors.As(err, &failure) || failure.Code != "expired_key_authorization" || fresh.snapshot != nil {
		t.Fatalf("an expired copy was accepted: %v", err)
	}

	delivery.Store(fixture.RotatedBundle)
	if err := evidence.refresh(t.Context(), m.appraise); err != nil {
		t.Fatal(err)
	}
	if reasons := evidenceReasons(m); len(reasons) != 0 {
		t.Fatalf("a newer copy did not reopen admission: %v", reasons)
	}
}

func TestMaintenanceLocalExpiryClockPolicyRecoveryAndTerminalDrain(t *testing.T) {
	fixture := evidenceFixture(t)
	evidence := fixtureEvidence(t, fixture)
	snapshot, summary := fixtureSnapshot(t, evidence, fixture.Bundle)
	document := fixture.Boot.document(t)
	m := &bootMaintenance{evidence: evidence, boot: attest.BootEvidence{Document: document, Inclusion: fixture.Inclusion}, certs: maintenanceCertificate(t, evidence.now())}
	if m.readiness().Ready {
		t.Fatal("unappraised node became ready")
	}
	if err := m.appraise(snapshot, summary); err != nil {
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
	evidence.synchronized = func() bool { return false }
	if !slices.Contains(m.readiness().Reasons, "clock is not synchronized") {
		t.Fatal("an unsynchronized clock kept admission open")
	}
	evidence.synchronized = func() bool { return true }
	m.boot.Inclusion = []byte(`{}`)
	if err := m.appraise(snapshot, summary); err == nil || m.readiness().Ready {
		t.Fatal("rejected boot did not close admission")
	}
	m.boot.Inclusion = fixture.Inclusion
	if err := m.appraise(snapshot, summary); err != nil {
		t.Fatal(err)
	}
	m.catalogReady = true
	if !m.readiness().Ready {
		t.Fatal("policy recovery did not reopen admission")
	}
	m.drain()
	if err := m.appraise(snapshot, summary); err != nil {
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
	snapshot, summary := fixtureSnapshot(t, evidence, fixture.Bundle)
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
			if err := m.appraise(snapshot, summary); err != nil {
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
	snapshot, summary := fixtureSnapshot(t, evidence, fixture.Bundle)
	document := fixture.Boot.document(t)
	keys := testNodeKeys(t)
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry recovers", true: "drain cancels retry"}[terminal], func(t *testing.T) {
			m := &bootMaintenance{evidence: evidence, boot: attest.BootEvidence{Document: document, Inclusion: fixture.Inclusion}, certs: maintenanceCertificate(t, evidence.now()), keys: keys}
			if err := m.appraise(snapshot, summary); err != nil {
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
