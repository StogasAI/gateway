package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	ref "github.com/StogasAI/verifier/go/reference"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

type bootReporter struct {
	report     []byte
	calls      int
	commitment [64]byte
}

func (r *bootReporter) Quote(_ context.Context, commitment [64]byte) ([]byte, error) {
	r.calls++
	r.commitment = commitment
	return attest.EncodeEnvelope(attest.Envelope{Provider: attest.ProviderSEVGuest, Report: base64.RawURLEncoding.EncodeToString(r.report)})
}

func TestBootPreparationUsesOneQuoteAndAppraisesBeforeRegistration(t *testing.T) {
	fixture := evidenceFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(fixture.Bundle) }))
	defer server.Close()
	material, keys := bootFixtureKeys(t, fixture)
	report, err := base64.RawURLEncoding.DecodeString(fixture.Boot.Report)
	if err != nil {
		t.Fatal(err)
	}
	reporter := &bootReporter{report: report}
	e := fixtureEvidence(t, fixture, server.URL)
	quoted, err := quoteBoot(t.Context(), attest.Staging, material, keys, fixture.Boot.ReportData.RegistrationChallenge, reporter)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := quoted.prepare(t.Context(), e, attest.Staging, material, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quoted.prepare(t.Context(), e, attest.Staging, material, keys); err != nil {
		t.Fatal(err)
	}
	if reporter.calls != 1 || !bytes.Equal(reporter.commitment[:], report[0x50:0x90]) {
		t.Fatal("boot made extra quotes or changed report binding")
	}
	if !bytes.Equal(boot.document, fixture.Boot.document(t)) || boot.identity.NodeID == "" {
		t.Fatal("prepared boot differs from verified hardware fixture")
	}
	other, err := quoteBoot(t.Context(), attest.Staging, material, keys, strings.Repeat("33", 32), reporter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.prepare(t.Context(), e, attest.Staging, material, keys); err == nil {
		t.Fatal("old report passed a fresh challenge")
	}
	reporter.report = bytes.Clone(report)
	reporter.report[0x90] ^= 1
	other, err = quoteBoot(t.Context(), attest.Staging, material, keys, fixture.Boot.ReportData.RegistrationChallenge, reporter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.prepare(t.Context(), e, attest.Staging, material, keys); err == nil {
		t.Fatal("unapproved measurement reached registration")
	}
}

func TestControlReadyCannotReplaceBootInclusionVerification(t *testing.T) {
	fixture := evidenceFixture(t)
	e := fixtureEvidence(t, fixture)
	snapshot, err := e.verifier.RefreshAt(fixture.Bundle, e.now())
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	document := fixture.Boot.document(t)
	checked, err := snapshot.VerifyLoggedBootAt(document, fixture.Inclusion, e.now())
	if err != nil {
		t.Fatal(err)
	}
	boot := &preparedBoot{document: document, identity: checked}
	_, keys := bootFixtureKeys(t, fixture)
	secrets := secretstore.NewStore()
	sealed := json.RawMessage(`{"sealed":true}`)
	for _, response := range []*provision.RegistrationResponse{
		{Status: "pending", NodeID: checked.NodeID},
		{Status: "ready", NodeID: "other", Provisioning: sealed},
		{Status: "ready", NodeID: checked.NodeID, Inclusion: []byte(`{}`), Provisioning: sealed},
		{Status: "ready", NodeID: checked.NodeID, Inclusion: fixture.Inclusion, Provisioning: sealed},
	} {
		if _, err := installBootCompletion(boot, response, snapshot, e.now(), keys, nil, secrets, "api-staging.stogas.ai"); err == nil {
			t.Fatal("Control ready bypassed guest completion checks")
		}
		if secrets.Ready() {
			t.Fatal("failed completion installed secrets")
		}
	}
}

// This uses a real SNP report and logged evidence. Only Control's delivery and
// the test CA are local; no verifier success path is mocked.
func TestBootRuntimeRetainsIdentityAcrossPolicyRejectionAndPendingRegistration(t *testing.T) {
	fixture := evidenceFixture(t)
	material, keys := bootFixtureKeys(t, fixture)
	report, err := base64.RawURLEncoding.DecodeString(fixture.Boot.Report)
	if err != nil {
		t.Fatal(err)
	}
	reporter := &bootReporter{report: report}
	digest := sha256.Sum256(fixture.Boot.document(t))
	roots, chain := bootFixtureCertificate(t, material)
	values := []provision.BootSecretValue{}
	for _, name := range []string{"CHUTES_API_KEY", "API_KEY_PEPPER", "BYOK_ENCRYPTION_SECRET", "DATABASE_SCHEMA", "DATABASE_URL", "INFERENCE_TOKEN_PUBLIC_KEY"} {
		values = append(values, provision.BootSecretValue{Name: name, KeyID: name, Version: "1", Plaintext: "fixture"})
	}
	plain, err := json.Marshal(provision.BootSecrets{CertificatePEM: string(chain), Region: provision.RegionUSVA, Secrets: values})
	if err != nil {
		t.Fatal(err)
	}
	// Control's sealing format, built independently with Go's X-Wing HPKE.
	recipient, err := hpke.MLKEM768X25519().NewPublicKey(mustBase64(t, fixture.Boot.ReportData.HPKEPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(recipient, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("stogas.secret-release.v1"))
	if err != nil {
		t.Fatal(err)
	}
	digestHex := hex.EncodeToString(digest[:])
	aad := []byte("{\"boot_sha256\":\"" + digestHex + "\",\"schema\":\"stogas.boot-provisioning.v1\"}\n")
	ciphertext, err := sender.Seal(aad, plain)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := json.Marshal(map[string]string{"schema": "stogas.boot-provisioning.v1", "boot_sha256": digestHex, "encapsulated_key": base64.RawURLEncoding.EncodeToString(enc), "ciphertext": base64.RawURLEncoding.EncodeToString(ciphertext)})
	if err != nil {
		t.Fatal(err)
	}
	nodeID := ref.SNPNodeID([32]byte(report[0x140:0x160]))
	var calls atomic.Int32
	var first []byte
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fleet/registration/challenge":
			_ = json.NewEncoder(w).Encode(provision.RegistrationChallenge{Challenge: fixture.Boot.ReportData.RegistrationChallenge, ExpiresAt: time.Now().Add(time.Hour)})
		case "/api/fleet/registration/complete":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "complete", "node_id": nodeID})
		case "/api/fleet/registration":
			body, _ := io.ReadAll(r.Body)
			count := calls.Add(1)
			if count == 1 {
				first = bytes.Clone(body)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"not_approved"}`))
				return
			}
			if !bytes.Equal(first, body) {
				t.Error("registration changed its exact boot or CSR after policy rejection or pending reply")
			}
			if count == 2 {
				_ = json.NewEncoder(w).Encode(provision.RegistrationResponse{Status: "pending", NodeID: nodeID})
				return
			}
			_ = json.NewEncoder(w).Encode(provision.RegistrationResponse{Status: "ready", NodeID: nodeID, Inclusion: fixture.Inclusion, Provisioning: sealed})
		default:
			t.Error("unexpected Control maintenance request", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	evidenceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/evidence/latest.json" {
			_, _ = w.Write(fixture.Bundle)
			return
		}
		http.NotFound(w, r) // Catalog unavailable: remain registered but locally unready.
	}))
	defer evidenceServer.Close()
	evidence := fixtureEvidence(t, fixture, evidenceServer.URL)
	reserve := func() (func(), bool) { return func() {}, true }
	runtime, err := startBoot(t.Context(), stogas.ConfidentialConfig{Environment: "staging", ControlURL: control.URL, ControlAllowHTTP: true, InstanceID: "00000000-0000-4000-8000-000000000001"}, Resources{Quote: reserve, Session: reserve}, evidence, material, keys, reporter, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if calls.Load() != 3 || reporter.calls != 1 || runtime.NodeID() != nodeID {
		t.Fatal("boot repeated hardware work or changed identity")
	}
	if !runtime.Secrets.Ready() || runtime.Sessions == nil || runtime.NativeIssuer == nil || runtime.Proofs == nil {
		t.Fatal("incomplete boot runtime")
	}
	if runtime.Readiness().Ready {
		t.Fatal("catalog delivery failure opened admission")
	}
	if _, err := keys.OpenProvisioning(digest, sealed); err == nil {
		t.Fatal("provisioning decryption key retained")
	}
	if runtime.Diagnostics() == nil || runtime.Diagnostics().Region != provision.RegionUSVA {
		t.Fatal("missing provisioned region in maintenance diagnostics")
	}
	runtime.Close()
	runtime.Close()
	if runtime.Secrets.Ready() || runtime.Readiness().Ready {
		t.Fatal("closed runtime retained serving state")
	}
	if _, err := keys.SignReceipt(digest, digest, digest, []byte(`{}`)); err == nil {
		t.Fatal("receipt signer retained after close")
	}
}

// bootFixtureKeys rebuilds the seeded keys committed by the real hardware report.
func bootFixtureKeys(t *testing.T, fixture bootEvidenceFixture) (*identity.Material, *verifier.NodeKeys) {
	t.Helper()
	scalar := big.NewInt(1)
	x, y := elliptic.P256().ScalarBaseMult(scalar.Bytes())
	tlsKey := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: scalar}
	spki, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	seeds := bytes.Repeat([]byte{42}, 64)
	for i := range 32 {
		seeds = append(seeds, byte(i))
	}
	keys, err := verifier.GenerateNodeKeys(bytes.NewReader(seeds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	material := &identity.Material{TLSPrivateKey: tlsKey, TLSSPKISHA256: sha256.Sum256(spki)}
	challenge := [32]byte(mustHex(t, fixture.Boot.ReportData.RegistrationChallenge))
	data, err := keys.ReportData(byte(attest.Staging), material.TLSSPKISHA256, challenge)
	if err != nil || !bytes.Equal(data[:], mustBase64(t, fixture.Boot.Report)[0x50:0x90]) {
		t.Fatal("test keys differ from hardware report", err)
	}
	return material, keys
}

func mustBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func bootFixtureCertificate(t *testing.T, material *identity.Material) (*x509.CertPool, []byte) {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "api-staging.stogas.ai"}, DNSNames: []string{"api-staging.stogas.ai"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
	return roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
