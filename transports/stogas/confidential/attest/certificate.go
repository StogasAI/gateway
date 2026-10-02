package attest

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

const (
	NativeEvidenceMediaType = "application/vnd.stogas.native-tls.v1"
	// rustls bounds a certificate handshake to 64 KiB. Leave room for DER/TLS
	// framing rather than allowing a valid evidence object that cannot be sent.
	MaxNativeCertificateBytes = 64*1024 - 13
)

var cmwExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 35}

func (e SessionEvidence) Extension() (pkix.Extension, error) {
	payload, err := e.MarshalBinary()
	if err != nil {
		return pkix.Extension{}, err
	}
	size := len(payload)
	// One canonical CBOR Record CMW: [media-type, byte-string]. This fixed
	// profile has no nested/optional fields or general-purpose CBOR decoder.
	cmw := make([]byte, 0, 3+len(NativeEvidenceMediaType)+3+size)
	cmw = append(cmw, 0x82, 0x78, byte(len(NativeEvidenceMediaType)))
	cmw = append(cmw, NativeEvidenceMediaType...)
	cmw = append(cmw, 0x59, byte(size>>8), byte(size))
	cmw = append(cmw, payload...)
	der, err := asn1.Marshal(cmw) // CMW's DER OCTET STRING choice, inside extnValue
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: append(asn1.ObjectIdentifier(nil), cmwExtensionOID...), Value: der}, nil
}

// NewNativeIssuer captures already-verified boot evidence once. Each invocation
// creates a fresh signer; the batcher only sees its locally computed SPKI digest.
func NewNativeIssuer(environment Environment, hostname string, boot BootEvidence, batcher *Batcher) (NativeCertificateIssuer, error) {
	if environment != Production && environment != Staging || hostname == "" || len(hostname) > 253 || batcher == nil {
		return nil, errors.New("invalid native certificate issuer configuration")
	}
	// Validate the largest supported proof before retaining boot bytes. It must
	// fit even when this VM is busy and a handshake joins a full batch.
	_, err := (SessionEvidence{Report: make([]byte, snpReportSize), Proof: BatchProof{LeafCount: MaxBatchLeaves, Siblings: make([][64]byte, MaxProofHashes)}, Boot: boot}).Extension()
	if err != nil {
		return nil, err
	}
	boot = BootEvidence{Document: append([]byte(nil), boot.Document...), Inclusion: append([]byte(nil), boot.Inclusion...)}
	bootHash := sha256.Sum256(boot.Document)
	return func(ctx context.Context, challenge [32]byte) (*tls.Certificate, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return nil, err
		}
		spki, err := x509.MarshalPKIXPublicKey(key.PublicKey())
		if err != nil {
			return nil, err
		}
		quote, err := batcher.Quote(ctx, NativeTLSBinding{Environment: environment, Challenge: challenge, BootEvidenceSHA256: bootHash, SignerSPKISHA256: sha256.Sum256(spki)})
		if err != nil {
			return nil, err
		}
		defer quote.Close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		extension, err := (SessionEvidence{Report: quote.Report, Proof: quote.Proof, Boot: boot}).Extension()
		if err != nil {
			return nil, err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		serial.Add(serial, big.NewInt(1))
		now := time.Now()
		template := &x509.Certificate{
			SerialNumber: serial, DNSNames: []string{hostname},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(5 * time.Minute),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			ExtraExtensions: []pkix.Extension{extension},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey(), key)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(der) > MaxNativeCertificateBytes {
			return nil, errors.New("native certificate exceeds TLS transport limit")
		}
		return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.MLDSA65}}, nil
	}, nil
}
