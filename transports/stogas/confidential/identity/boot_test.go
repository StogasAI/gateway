package identity

import (
	"bytes"
	"crypto/x509"
	"sync"
	"testing"
	"time"
)

func TestBootCertificateInstallationAndRenewal(t *testing.T) {
	material, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	first, firstDER := selfSignedLeaf(t, material, 1, time.Now().Add(24*time.Hour))
	next, nextDER := selfSignedLeaf(t, material, 2, time.Now().Add(48*time.Hour))
	roots := rootsForCertificate(t, firstDER)
	parsed, err := x509.ParseCertificate(nextDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	store, err := NewBootCertificateStore(material, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.ActiveTLSCertificate(); ok {
		t.Fatal("unregistered boot exposed a certificate")
	}
	for _, chain := range [][]byte{first, first, next, next} {
		if _, err := store.InstallBootChain(chain, "gateway.stogas.ai"); err != nil {
			t.Fatal(err)
		}
	}
	before := store.State()
	for _, chain := range [][]byte{nil, []byte("invalid"), bytes.Repeat([]byte{'x'}, 32*1024+1)} {
		if _, err := store.InstallBootChain(chain, "gateway.stogas.ai"); err == nil {
			t.Fatal("invalid chain accepted")
		}
		if store.State().ActiveCertSHA256 != before.ActiveCertSHA256 {
			t.Fatal("failed renewal changed certificate")
		}
	}
	if _, err := store.InstallBootChain(next, "wrong.stogas.ai"); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	other, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := selfSignedLeaf(t, other, 3, time.Now().Add(48*time.Hour))
	if _, err := store.InstallBootChain(wrong, "gateway.stogas.ai"); err == nil {
		t.Fatal("another guest key accepted")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 20 {
				if _, err := store.InstallBootChain(next, "gateway.stogas.ai"); err != nil {
					t.Error(err)
				}
				certificate, ok := store.ActiveTLSCertificate()
				if !ok || !bytes.Equal(certificate.Certificate[0], nextDER) {
					t.Error("partial certificate installation")
				}
			}
		})
	}
	group.Wait()
}
