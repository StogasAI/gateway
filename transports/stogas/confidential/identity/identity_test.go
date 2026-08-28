package identity

import (
	"crypto/ed25519"
	"crypto/rand"
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
	if decoded, err := base64.RawURLEncoding.DecodeString(first.HPKEPublicKey); err != nil {
		t.Fatalf("hpke key is not base64url: %v", err)
	} else if len(decoded) != 1_216 {
		t.Fatalf("unexpected X-Wing HPKE public key length: %d", len(decoded))
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
	store, err := NewCertificateStore(material, strings.Repeat("a", 64), []string{strings.Repeat("a", 64)}, time.Now().Add(90*24*time.Hour), nil)
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

func TestProvisionalCertificateStoreCreatesInMemoryActiveCertificate(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	store, err := NewProvisionalCertificateStore(material, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := store.State()
	if len(state.ActiveCertSHA256) != 64 || len(state.AcceptedCertSHA256) != 0 {
		t.Fatalf("unexpected provisional cert hashes: %#v", state)
	}
	if !state.ExpiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("unexpected provisional expiry: %s", state.ExpiresAt)
	}
	tlsCert, ok := store.ActiveTLSCertificate()
	if !ok || len(tlsCert.Certificate) != 1 {
		t.Fatalf("provisional certificate was not active in memory: %#v", tlsCert)
	}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if SHA256Hex(spki) != material.TLSSPKISHA256 {
		t.Fatal("provisional certificate did not use runtime TLS key")
	}
}

func TestCertificateStoreStagesActivatesAndPrunesRenewedChain(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldHash := strings.Repeat("a", 64)
	oldExpiry := time.Now().UTC().Add(30 * 24 * time.Hour)
	newExpiry := time.Now().UTC().Truncate(time.Second).Add(90 * 24 * time.Hour)
	chainPEM, leafDER := selfSignedLeaf(t, material, 2, newExpiry)
	newHash := CertSHA256Hex(leafDER)
	store, err := NewCertificateStore(material, oldHash, []string{oldHash}, oldExpiry, rootsForCertificate(t, leafDER))
	if err != nil {
		t.Fatal(err)
	}

	staged, err := store.StageRenewedChain(certificateChainInput(chainPEM, newHash, "gateway.stogas.ai"))
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

	pruned, err := store.PruneAcceptedToActive(newHash)
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
	chainPEM, _ := selfSignedLeaf(t, other, 3, time.Now().Add(90*24*time.Hour))
	certs, err := parseCertificateChain(chainPEM)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewCertificateStore(material, strings.Repeat("a", 64), []string{strings.Repeat("a", 64)}, time.Now().Add(90*24*time.Hour), rootsForCertificate(t, certs[0].Raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRenewedChain(certificateChainInput(chainPEM, CertSHA256Hex(certs[0].Raw), "gateway.stogas.ai")); err == nil || !strings.Contains(err.Error(), "reuse the existing TLS public key") {
		t.Fatalf("expected TLS key reuse error, got %v", err)
	}
}

func TestCertificateStoreRejectsUnexpectedPEMBlocks(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewCertificateStore(material, strings.Repeat("a", 64), []string{strings.Repeat("a", 64)}, time.Now().Add(90*24*time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, _ := selfSignedLeaf(t, material, 3, time.Now().Add(90*24*time.Hour))
	chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")}), chainPEM...)
	if _, err := store.StageRenewedChain(certificateChainInput(chainPEM, strings.Repeat("b", 64), "gateway.stogas.ai")); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("expected unexpected PEM block rejection, got %v", err)
	}
}

func TestCertificateStoreRejectsSameCertificateHashAsRenewal(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, leafDER := selfSignedLeaf(t, material, 4, time.Now().Add(90*24*time.Hour))
	hash := CertSHA256Hex(leafDER)
	store, err := NewCertificateStore(material, hash, []string{hash}, time.Now().Add(90*24*time.Hour), rootsForCertificate(t, leafDER))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRenewedChain(certificateChainInput(chainPEM, hash, "gateway.stogas.ai")); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("expected same certificate hash rejection, got %v", err)
	}
}

func TestCertificateStoreRejectsWrongExpectedHashWithoutChangingState(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, leafDER := selfSignedLeaf(t, material, 5, time.Now().Add(90*24*time.Hour))
	oldHash := strings.Repeat("a", 64)
	store, err := NewCertificateStore(
		material,
		oldHash,
		[]string{oldHash},
		time.Now().Add(30*24*time.Hour),
		rootsForCertificate(t, leafDER),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.InstallActiveChain(certificateChainInput(chainPEM, strings.Repeat("b", 64), "gateway.stogas.ai")); err == nil || !strings.Contains(err.Error(), "did not match expected hash") {
		t.Fatalf("expected hash mismatch rejection, got %v", err)
	}
	assertSingleCertificateHash(t, store.State(), oldHash)

	newHash := CertSHA256Hex(leafDER)
	state, err := store.StageRenewedChain(certificateChainInput(chainPEM, newHash, "gateway.stogas.ai"))
	if err != nil {
		t.Fatalf("valid certificate could not be staged after rejected instruction: %v", err)
	}
	if !hasHash(state.AcceptedCertSHA256, oldHash) || !hasHash(state.AcceptedCertSHA256, newHash) {
		t.Fatalf("unexpected accepted certificate state: %#v", state)
	}
}

func TestCertificateStoreRejectsInvalidRenewedCertificatesWithoutChangingState(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tests := []struct {
		dnsNames  []string
		name      string
		notAfter  time.Time
		notBefore time.Time
		roots     bool
		usages    []x509.ExtKeyUsage
	}{
		{
			dnsNames:  []string{"other.stogas.ai"},
			name:      "wrong DNS name",
			notAfter:  now.Add(24 * time.Hour),
			notBefore: now.Add(-time.Hour),
			roots:     true,
			usages:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			dnsNames:  []string{"gateway.stogas.ai"},
			name:      "expired",
			notAfter:  now.Add(-time.Minute),
			notBefore: now.Add(-24 * time.Hour),
			roots:     true,
			usages:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			dnsNames:  []string{"gateway.stogas.ai"},
			name:      "not yet valid",
			notAfter:  now.Add(48 * time.Hour),
			notBefore: now.Add(time.Hour),
			roots:     true,
			usages:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			dnsNames:  []string{"gateway.stogas.ai"},
			name:      "missing server auth",
			notAfter:  now.Add(24 * time.Hour),
			notBefore: now.Add(-time.Hour),
			roots:     true,
			usages:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			dnsNames:  []string{"gateway.stogas.ai"},
			name:      "untrusted chain",
			notAfter:  now.Add(24 * time.Hour),
			notBefore: now.Add(-time.Hour),
			roots:     false,
			usages:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chainPEM, leafDER := selfSignedLeafWithValidity(
				t,
				material,
				int64(10+index),
				test.notBefore,
				test.notAfter,
				test.usages,
			)
			var roots *x509.CertPool
			if test.roots {
				roots = rootsForCertificate(t, leafDER)
			} else {
				roots = x509.NewCertPool()
			}
			oldHash := strings.Repeat("a", 64)
			store, err := NewCertificateStore(
				material,
				oldHash,
				[]string{oldHash},
				now.Add(30*24*time.Hour),
				roots,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.StageRenewedChain(certificateChainInput(chainPEM, CertSHA256Hex(leafDER), test.dnsNames...)); err == nil {
				t.Fatal("expected renewed certificate rejection")
			}
			assertSingleCertificateHash(t, store.State(), oldHash)
		})
	}
}

func TestCertificateStoreRejectsThirdOrUnrelatedCertificate(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCertificateStore(
		material,
		strings.Repeat("a", 64),
		[]string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)},
		time.Now().Add(30*24*time.Hour),
		nil,
	); err == nil || !strings.Contains(err.Error(), "more than two") {
		t.Fatalf("expected three-hash constructor rejection, got %v", err)
	}

	firstPEM, firstDER := selfSignedLeaf(t, material, 30, time.Now().Add(30*24*time.Hour))
	secondPEM, secondDER := selfSignedLeaf(t, material, 31, time.Now().Add(31*24*time.Hour))
	roots := x509.NewCertPool()
	for _, der := range [][]byte{firstDER, secondDER} {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		roots.AddCert(certificate)
	}
	oldHash := strings.Repeat("a", 64)
	store, err := NewCertificateStore(material, oldHash, []string{oldHash}, time.Now().Add(15*24*time.Hour), roots)
	if err != nil {
		t.Fatal(err)
	}
	firstHash := CertSHA256Hex(firstDER)
	if _, err := store.StageRenewedChain(certificateChainInput(firstPEM, firstHash, "gateway.stogas.ai")); err != nil {
		t.Fatal(err)
	}
	secondHash := CertSHA256Hex(secondDER)
	if _, err := store.StageRenewedChain(certificateChainInput(secondPEM, secondHash, "gateway.stogas.ai")); err == nil || !strings.Contains(err.Error(), "unrelated staged") {
		t.Fatalf("expected unrelated staged certificate rejection, got %v", err)
	}
	state := store.State()
	if len(state.AcceptedCertSHA256) != 2 || !hasHash(state.AcceptedCertSHA256, oldHash) || !hasHash(state.AcceptedCertSHA256, firstHash) || hasHash(state.AcceptedCertSHA256, secondHash) {
		t.Fatalf("rejected certificate changed accepted state: %#v", state)
	}
	if _, err := store.ActivateStaged(firstHash); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRenewedChain(certificateChainInput(secondPEM, secondHash, "gateway.stogas.ai")); err == nil || !strings.Contains(err.Error(), "already accepts two") {
		t.Fatalf("expected third certificate rejection after activation, got %v", err)
	}
	if _, err := store.PruneAcceptedToActive(firstHash); err != nil {
		t.Fatal(err)
	}
	thirdStaged, err := store.StageRenewedChain(certificateChainInput(secondPEM, secondHash, "gateway.stogas.ai"))
	if err != nil {
		t.Fatalf("third certificate could not be staged after the old hash was pruned: %v", err)
	}
	if len(thirdStaged.AcceptedCertSHA256) != 2 || !hasHash(thirdStaged.AcceptedCertSHA256, firstHash) || !hasHash(thirdStaged.AcceptedCertSHA256, secondHash) || hasHash(thirdStaged.AcceptedCertSHA256, oldHash) {
		t.Fatalf("third certificate did not replace the pruned hash: %#v", thirdStaged)
	}
	if _, err := store.ActivateStaged(secondHash); err != nil {
		t.Fatal(err)
	}
	thirdActive, err := store.PruneAcceptedToActive(secondHash)
	if err != nil {
		t.Fatal(err)
	}
	if thirdActive.ActiveCertSHA256 != secondHash || len(thirdActive.AcceptedCertSHA256) != 1 || thirdActive.AcceptedCertSHA256[0] != secondHash {
		t.Fatalf("third certificate did not become the sole active hash: %#v", thirdActive)
	}
}

func selfSignedLeaf(t *testing.T, material *Material, serial int64, notAfter time.Time) ([]byte, []byte) {
	return selfSignedLeafWithValidity(
		t,
		material,
		serial,
		time.Now().Add(-time.Hour),
		notAfter,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
}

func selfSignedLeafWithValidity(t *testing.T, material *Material, serial int64, notBefore, notAfter time.Time, usages []x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "gateway.stogas.ai"},
		DNSNames:              []string{"gateway.stogas.ai"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &material.TLSPrivateKey.PublicKey, material.TLSPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func assertSingleCertificateHash(t *testing.T, state CertificateState, hash string) {
	t.Helper()
	if state.ActiveCertSHA256 != hash || len(state.AcceptedCertSHA256) != 1 || state.AcceptedCertSHA256[0] != hash {
		t.Fatalf("certificate state changed after rejection: %#v", state)
	}
}

func certificateChainInput(chainPEM []byte, hash string, dnsNames ...string) CertificateChainInput {
	return CertificateChainInput{
		ChainPEM:       chainPEM,
		DNSNames:       dnsNames,
		ExpectedSHA256: hash,
	}
}

func rootsForCertificate(t *testing.T, der []byte) *x509.CertPool {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return roots
}

func hasHash(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
