package attest

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type certificateVector struct {
	Certificate      string `json:"certificate"`
	Extension        string `json:"extension"`
	SignerSPKISHA256 string `json:"signer_spki_sha256"`
	BootDocument     string `json:"boot_document"`
	BootInclusion    string `json:"boot_inclusion"`
}

func nativeFixture(t *testing.T) certificateVector {
	t.Helper()
	bytes, err := os.ReadFile("testdata/native-certificate-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector certificateVector
	if err := json.Unmarshal(bytes, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

// Decoder exists only in tests; the gateway emits this format and Rust parses it.
func decodeTestExtension(encoded []byte) (SessionEvidence, error) {
	var cmw []byte
	remaining, err := asn1.Unmarshal(encoded, &cmw)
	if err != nil || len(remaining) != 0 {
		return SessionEvidence{}, errors.New("bad CMW DER")
	}
	prefix := append([]byte{0x82, 0x78, byte(len(NativeEvidenceMediaType))}, NativeEvidenceMediaType...)
	if !bytes.HasPrefix(cmw, prefix) || len(cmw) < len(prefix)+3 || cmw[len(prefix)] != 0x59 {
		return SessionEvidence{}, errors.New("bad CMW type")
	}
	payload := cmw[len(prefix)+3:]
	if len(payload) != int(binary.BigEndian.Uint16(cmw[len(prefix)+1:])) || len(payload) < snpReportSize+6 {
		return SessionEvidence{}, errors.New("bad CMW length")
	}
	evidence := SessionEvidence{Report: payload[:snpReportSize]}
	payload = payload[snpReportSize:]
	proofLength := int(binary.BigEndian.Uint16(payload))
	payload = payload[2:]
	if len(payload) < proofLength {
		return SessionEvidence{}, errors.New("truncated proof")
	}
	evidence.Proof, err = ParseBatchProof(payload[:proofLength])
	if err != nil {
		return SessionEvidence{}, err
	}
	payload = payload[proofLength:]
	for _, destination := range []*[]byte{&evidence.Boot.Document, &evidence.Boot.Inclusion} {
		if len(payload) < 4 {
			return SessionEvidence{}, errors.New("truncated field length")
		}
		size := int(binary.BigEndian.Uint32(payload))
		payload = payload[4:]
		if len(payload) < size {
			return SessionEvidence{}, errors.New("truncated field")
		}
		*destination, payload = payload[:size], payload[size:]
	}
	if len(payload) != 0 {
		return SessionEvidence{}, errors.New("trailing bytes")
	}
	return evidence, nil
}

func TestNativeCertificateSharedEncodingVector(t *testing.T) {
	vector := nativeFixture(t)
	encoded, err := base64.RawURLEncoding.DecodeString(vector.Extension)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := decodeTestExtension(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(evidence.Boot.Document) != vector.BootDocument || string(evidence.Boot.Inclusion) != vector.BootInclusion {
		t.Fatal("boot fields differ")
	}
	extension, err := evidence.Extension()
	if err != nil || !bytes.Equal(extension.Value, encoded) {
		t.Fatal("Go/Rust vector encoding differs", err)
	}
	spki, _ := hex.DecodeString(vector.SignerSPKISHA256)
	if err := evidence.Proof.Verify(NativeTLSBinding{Environment: Production, Challenge: [32]byte{1}, BootEvidenceSHA256: sha256.Sum256(evidence.Boot.Document), SignerSPKISHA256: [32]byte(spki)}, [64]byte(evidence.Report[0x50:0x90])); err != nil {
		t.Fatal(err)
	}
	der, _ := base64.RawURLEncoding.DecodeString(vector.Certificate)
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := certificate.PublicKey.(*mldsa.PublicKey)
	if !ok || public.Parameters() != mldsa.MLDSA65() || certificate.SignatureAlgorithm != x509.MLDSA65 {
		t.Fatal("native certificate did not use ML-DSA-65")
	}
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestNativeIssuerBindsActualTLSKeyAndCopiedBootEvidence(t *testing.T) {
	vector := nativeFixture(t)
	boot := BootEvidence{Document: []byte(vector.BootDocument), Inclusion: []byte(vector.BootInclusion)}
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
			evidence, err := decodeTestExtension(extension.Value)
			if err != nil {
				return err
			}
			if string(evidence.Boot.Document) != vector.BootDocument {
				return errors.New("boot evidence changed")
			}
			return evidence.Proof.Verify(NativeTLSBinding{Environment: Production, Challenge: [32]byte{1}, BootEvidenceSHA256: sha256.Sum256(evidence.Boot.Document), SignerSPKISHA256: sha256.Sum256(certificate.RawSubjectPublicKeyInfo)}, [64]byte(evidence.Report[0x50:0x90]))
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
	proof := BatchProof{LeafCount: MaxBatchLeaves, Siblings: make([][64]byte, MaxProofHashes)}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	bootBytes := MaxSessionEvidenceBytes - snpReportSize - 2 - len(proofBytes) - 4 - 4 - 1
	evidence := SessionEvidence{Report: make([]byte, snpReportSize), Proof: proof, Boot: BootEvidence{Document: make([]byte, bootBytes), Inclusion: []byte{1}}}
	if _, err := evidence.Extension(); err != nil {
		t.Fatal("rejected maximum evidence", err)
	}
	evidence.Boot.Document = append(evidence.Boot.Document, 0)
	if _, err := evidence.Extension(); err == nil {
		t.Fatal("accepted oversized evidence")
	}
	evidence.Boot.Document = nil
	if _, err := evidence.Extension(); err == nil {
		t.Fatal("accepted missing boot document")
	}
	evidence.Report = nil
	if _, err := evidence.Extension(); err == nil {
		t.Fatal("accepted missing report")
	}
}

func TestLargestNativeCertificateFitsTLS(t *testing.T) {
	// The issuer preflights a full batch path; a single handshake actually uses
	// less proof space. Both must fit with the largest accepted DNS name.
	proof := BatchProof{LeafCount: MaxBatchLeaves, Siblings: make([][64]byte, MaxProofHashes)}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	bootBytes := MaxSessionEvidenceBytes - snpReportSize - 2 - len(proofBytes) - 4 - 4 - 1
	boot := BootEvidence{Document: make([]byte, bootBytes), Inclusion: []byte{1}}
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
	extension, err := (SessionEvidence{Report: make([]byte, snpReportSize), Proof: proof, Boot: boot}).Extension()
	if err != nil {
		t.Fatal(err)
	}
	leaf.ExtraExtensions = []pkix.Extension{extension}
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
