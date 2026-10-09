package attest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"

	verifier "github.com/StogasAI/verifier/go"
	ref "github.com/StogasAI/verifier/go/reference"
)

// A synthetic boot; this package checks binding and size, not hardware appraisal.
func testBoot() BootEvidence {
	return BootEvidence{Document: []byte(`{"boot":"native"}`), Inclusion: []byte(`{}`)}
}

// maximumBoot fills the evidence bound beside a full batch's longest proof.
func maximumBoot(t *testing.T) BootEvidence {
	t.Helper()
	_, proofs, err := verifier.QuoteBatch(make([][64]byte, MaxBatchLeaves))
	if err != nil {
		t.Fatal(err)
	}
	document := MaxSessionEvidenceBytes - snpReportSize - 2 - len(proofs[0]) - 4 - 4 - 1
	return BootEvidence{Document: make([]byte, document), Inclusion: []byte{1}}
}

func TestNativeIssuerBindsActualTLSKeyAndCopiedBootEvidence(t *testing.T) {
	boot := testBoot()
	document := string(boot.Document)
	resources := &testReservations{limit: 1}
	b := newTestBatcher(t, quoteFunc(func(_ context.Context, data [64]byte) ([]byte, error) { return testReport(data), nil }), resources)
	defer b.Close(context.Background())
	issuer, err := NewNativeIssuer(Production, "gateway.test", boot, b)
	if err != nil {
		t.Fatal(err)
	}
	boot.Document[0] ^= 1 // constructor retains its own immutable boot snapshot
	server, err := ConfigureTLS(&tls.Config{}, func() bool { return true }, issuer)
	if err != nil {
		t.Fatal(err)
	}
	client := testNativeClient()
	client.VerifyPeerCertificate = func(chain [][]byte, _ [][]*x509.Certificate) error {
		if len(chain) != 1 {
			return errors.New("expected a single native certificate")
		}
		certificate, err := x509.ParseCertificate(chain[0])
		if err != nil {
			return err
		}
		for _, extension := range certificate.Extensions {
			if !extension.Id.Equal(cmwExtensionOID) {
				continue
			}
			evidence, err := ref.ParseCertificateExtension(extension.Value)
			if err != nil {
				return err
			}
			if string(evidence.Document) != document {
				return errors.New("boot evidence changed")
			}
			leaf := ref.TLSLeaf(byte(Production), sha256.Sum256(evidence.Document), [32]byte{1}, sha256.Sum256(certificate.RawSubjectPublicKeyInfo))
			return ref.VerifyBatchProof(leaf, evidence.Proof, [64]byte(evidence.Report[0x50:0x90]))
		}
		return errors.New("missing attestation")
	}
	_, clientErr, serverErr := testTLSExchange(server, client, nil)
	if clientErr != nil || serverErr != nil {
		t.Fatal(clientErr, serverErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := issuer(ctx, [32]byte{2}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Result delivery can finish before the worker releases its shared batch
	// storage. Closing joins that worker before checking physical ownership.
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resources.used.Load() != 0 || b.Diagnostics().Batches != 1 {
		t.Fatal(resources.used.Load(), b.Diagnostics())
	}
}

func TestNativeEvidenceSizeFitsTheLargestProof(t *testing.T) {
	boot := maximumBoot(t)
	if err := boot.CheckSize(); err != nil {
		t.Fatal("rejected maximum evidence", err)
	}
	for _, changed := range []BootEvidence{
		{Document: append(boot.Document, 0), Inclusion: boot.Inclusion},
		{Inclusion: boot.Inclusion},
		{Document: boot.Document},
	} {
		if changed.CheckSize() == nil {
			t.Fatal("accepted oversized or incomplete evidence")
		}
	}
}

func TestLargestNativeCertificateFitsTLS(t *testing.T) {
	// The issuer preflights a full batch path; a single handshake actually uses
	// less proof space. Both must fit with the largest accepted DNS name.
	boot := maximumBoot(t)
	b := newTestBatcher(t, quoteFunc(func(_ context.Context, data [64]byte) ([]byte, error) { return testReport(data), nil }), &testReservations{limit: 1})
	defer b.Close(context.Background())
	hostname := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	issuer, err := NewNativeIssuer(Production, hostname, boot, b)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := issuer(context.Background(), [32]byte{1})
	if err != nil {
		t.Fatal("maximum native certificate cannot be sent", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, proofs, err := verifier.QuoteBatch(make([][64]byte, MaxBatchLeaves))
	if err != nil {
		t.Fatal(err)
	}
	extension, err := verifier.SessionEvidence(make([]byte, snpReportSize), proofs[0], boot.Document, boot.Inclusion, true)
	if err != nil {
		t.Fatal(err)
	}
	leaf.ExtraExtensions = []pkix.Extension{{Id: cmwExtensionOID, Value: extension}}
	certificate.Certificate[0], err = x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, certificate.PrivateKey)
	if err != nil || len(certificate.Certificate[0]) > MaxNativeCertificateBytes {
		t.Fatal("full batch proof exceeded the TLS certificate limit", err)
	}
	// Exercise the actual wire parser too, rather than only comparing constants.
	config, err := ConfigureTLS(&tls.Config{}, func() bool { return true }, func(context.Context, [32]byte) (*tls.Certificate, error) { return certificate, nil })
	if err != nil {
		t.Fatal(err)
	}
	_, clientErr, serverErr := testTLSExchange(config, testNativeClient(), nil)
	if clientErr != nil || serverErr != nil {
		t.Fatal(clientErr, serverErr)
	}
}

func TestNativeTLSStillRequiresCertificatePrivateKeyPossession(t *testing.T) {
	certificate, other := testTLSCertificate(t), testTLSCertificate(t)
	certificate.PrivateKey = other.PrivateKey
	config, err := ConfigureTLS(&tls.Config{}, func() bool { return true }, func(context.Context, [32]byte) (*tls.Certificate, error) { return certificate, nil })
	if err != nil {
		t.Fatal(err)
	}
	_, clientErr, _ := testTLSExchange(config, testNativeClient(), nil)
	if clientErr == nil {
		t.Fatal("accepted incorrect CertificateVerify signer")
	}
}

// BenchmarkNativeTLSSigner measures one handshake's fresh signer: key generation,
// the certificate signature and CertificateVerify, excluding X.509 and the quote.
func BenchmarkNativeTLSSigner(b *testing.B) {
	certificate, transcript := make([]byte, 60*1024), make([]byte, 130)
	for b.Loop() {
		key, err := newTLSSigner()
		if err != nil {
			b.Fatal(err)
		}
		for _, message := range [][]byte{certificate, transcript} {
			if _, err := key.Sign(nil, message, crypto.Hash(0)); err != nil {
				b.Fatal(err)
			}
		}
	}
}
