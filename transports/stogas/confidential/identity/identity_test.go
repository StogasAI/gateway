package identity

import (
	"crypto/rand"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestGenerateCreatesDistinctInMemoryKeys(t *testing.T) {
	first, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.TLSSPKISHA256 == second.TLSSPKISHA256 {
		t.Fatal("tls spki hashes should be unique per generation")
	}
	if first.HPKEPublicKey == second.HPKEPublicKey {
		t.Fatal("hpke public keys should be unique per generation")
	}
	if first.Ed25519PublicKey == second.Ed25519PublicKey {
		t.Fatal("ed25519 public keys should be unique per generation")
	}
	if _, err := base64.RawURLEncoding.DecodeString(first.HPKEPublicKey); err != nil {
		t.Fatalf("hpke key is not base64url: %v", err)
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(first.Ed25519PublicKey); err != nil {
		t.Fatalf("ed25519 key is not base64url: %v", err)
	} else if len(decoded) != ed25519.PublicKeySize {
		t.Fatalf("unexpected ed25519 public key length: %d", len(decoded))
	}
	if len(first.TLSSPKISHA256) != 64 {
		t.Fatalf("unexpected spki hash length: %d", len(first.TLSSPKISHA256))
	}
}

func TestCertSHA256Hex(t *testing.T) {
	hash := CertSHA256Hex([]byte("certificate-der"))
	if len(hash) != 64 {
		t.Fatalf("unexpected cert hash length: %d", len(hash))
	}
	if hash != SHA256Hex([]byte("certificate-der")) {
		t.Fatal("certificate hash should be sha256 over der bytes")
	}
}

func TestCertificateStoreCreatesCSRWithExistingTLSKey(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewCertificateStore(material, strings.Repeat("a", 64), []string{strings.Repeat("a", 64)}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	csrDER, err := store.CreateCSR(CSRInput{
		CommonName: "gateway.stogas.ai",
		DNSNames:   []string{"gateway.stogas.ai", "api.stogas.ai"},
	})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature did not verify: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if SHA256Hex(spki) != material.TLSSPKISHA256 {
		t.Fatal("csr did not use existing TLS key")
	}
	if got := strings.Join(csr.DNSNames, ","); got != "api.stogas.ai,gateway.stogas.ai" {
		t.Fatalf("unexpected sorted DNS SANs: %s", got)
	}
}

func TestCertificateStoreStagesActivatesAndPrunesRenewedChain(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldHash := strings.Repeat("a", 64)
	oldExpiry := time.Now().UTC().Add(30 * 24 * time.Hour)
	store, err := NewCertificateStore(material, oldHash, []string{oldHash}, oldExpiry)
	if err != nil {
		t.Fatal(err)
	}
	newExpiry := time.Now().UTC().Truncate(time.Second).Add(90 * 24 * time.Hour)
	chainPEM, leafDER := selfSignedLeaf(t, material, 2, newExpiry)
	newHash := CertSHA256Hex(leafDER)

	staged, err := store.StageRenewedChain(chainPEM)
	if err != nil {
		t.Fatal(err)
	}
	if staged.ActiveCertSHA256 != oldHash || staged.ExpiresAt != oldExpiry {
		t.Fatalf("staging must keep active certificate unchanged: %#v", staged)
	}
	if !hasHash(staged.AcceptedCertSHA256, oldHash) || !hasHash(staged.AcceptedCertSHA256, newHash) {
		t.Fatalf("staging must quote-accept old and new hashes: %#v", staged)
	}
	if _, ok := store.ActiveTLSCertificate(); ok {
		t.Fatal("staged certificate must not be served before activation")
	}

	active, err := store.ActivateStaged(newHash)
	if err != nil {
		t.Fatal(err)
	}
	if active.ActiveCertSHA256 != newHash || !active.ExpiresAt.Equal(newExpiry) {
		t.Fatalf("activation did not switch active certificate: %#v", active)
	}
	tlsCert, ok := store.ActiveTLSCertificate()
	if !ok || len(tlsCert.Certificate) != 1 || CertSHA256Hex(tlsCert.Certificate[0]) != newHash {
		t.Fatalf("active TLS certificate not installed: %#v", tlsCert)
	}

	pruned, err := store.PruneAcceptedToActive()
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned.AcceptedCertSHA256) != 1 || pruned.AcceptedCertSHA256[0] != newHash {
		t.Fatalf("old certificate hash was not pruned: %#v", pruned)
	}
}

func TestCertificateStoreRejectsRenewedChainWithWrongTLSKey(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewCertificateStore(material, strings.Repeat("a", 64), []string{strings.Repeat("a", 64)}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, _ := selfSignedLeaf(t, other, 3, time.Now().Add(90*24*time.Hour))
	if _, err := store.StageRenewedChain(chainPEM); err == nil || !strings.Contains(err.Error(), "reuse the existing TLS public key") {
		t.Fatalf("expected TLS key reuse error, got %v", err)
	}
}

func TestCertificateStoreRejectsSameCertificateHashAsRenewal(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, leafDER := selfSignedLeaf(t, material, 4, time.Now().Add(90*24*time.Hour))
	hash := CertSHA256Hex(leafDER)
	store, err := NewCertificateStore(material, hash, []string{hash}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRenewedChain(chainPEM); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("expected same certificate hash rejection, got %v", err)
	}
}

func selfSignedLeaf(t *testing.T, material *Material, serial int64, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "gateway.stogas.ai"},
		DNSNames:              []string{"gateway.stogas.ai"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &material.TLSPrivateKey.PublicKey, material.TLSPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func hasHash(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
