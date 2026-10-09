package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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
	store, err := NewBootCertificateStore(material, nil)
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
	if sha256.Sum256(spki) != material.TLSSPKISHA256 {
		t.Fatal("csr did not use existing TLS key")
	}
	if got := strings.Join(csr.DNSNames, ","); got != "api.stogas.ai,gateway.stogas.ai" {
		t.Fatalf("unexpected sorted DNS SANs: %s", got)
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
			store, err := NewBootCertificateStore(material, roots)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.InstallBootChain(chainPEM, test.dnsNames[0]); err == nil {
				t.Fatal("expected renewed certificate rejection")
			}
			if _, ok := store.ActiveTLSCertificate(); ok {
				t.Fatal("invalid renewal changed installed state")
			}
		})
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
