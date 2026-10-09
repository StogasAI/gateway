package attest

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"time"

	verifier "github.com/StogasAI/verifier/go"
)

// rustls bounds a certificate handshake to 64 KiB. Leave room for DER/TLS
// framing rather than allowing a valid evidence object that cannot be sent.
const MaxNativeCertificateBytes = 64*1024 - 13

var cmwExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 35}

// NewNativeIssuer captures already-verified boot evidence once. Each invocation
// creates a fresh signer; the batcher only sees its locally computed SPKI digest.
func NewNativeIssuer(environment Environment, hostname string, boot BootEvidence, batcher *Batcher) (NativeCertificateIssuer, error) {
	if environment != Production && environment != Staging || hostname == "" || len(hostname) > 253 || batcher == nil {
		return nil, errors.New("invalid native certificate issuer configuration")
	}
	// Validate the largest supported proof before retaining boot bytes. It must
	// fit even when this VM is busy and a handshake joins a full batch.
	if err := boot.CheckSize(); err != nil {
		return nil, err
	}
	boot = BootEvidence{Document: append([]byte(nil), boot.Document...), Inclusion: append([]byte(nil), boot.Inclusion...)}
	bootHash := sha256.Sum256(boot.Document)
	return func(ctx context.Context, challenge [32]byte) (*tls.Certificate, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := newTLSSigner()
		if err != nil {
			return nil, err
		}
		spki, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return nil, err
		}
		leaf, err := NativeTLSLeaf(environment, bootHash, challenge, sha256.Sum256(spki))
		if err != nil {
			return nil, err
		}
		quote, err := batcher.Quote(ctx, leaf)
		if err != nil {
			return nil, err
		}
		defer quote.Close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evidence, err := quote.Evidence(boot, true)
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
			ExtraExtensions: []pkix.Extension{{Id: append(asn1.ObjectIdentifier(nil), cmwExtensionOID...), Value: evidence}},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
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

// tlsSigner adapts a fresh Rust ML-DSA-65 key to the crypto.Signer used by Go's
// TLS stack and X.509 issuance; both sign pure ML-DSA with no prehash or context.
type tlsSigner struct {
	key    *verifier.TLSKey
	public *mldsa.PublicKey
}

func newTLSSigner() (*tlsSigner, error) {
	key, err := verifier.GenerateTLSKey()
	if err != nil {
		return nil, err
	}
	public, err := mldsa.NewPublicKey(mldsa.MLDSA65(), key.PublicKey())
	if err != nil {
		return nil, err
	}
	return &tlsSigner{key: key, public: public}, nil
}

func (s *tlsSigner) Public() crypto.PublicKey { return s.public }

func (s *tlsSigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != 0 {
		return nil, errors.New("native TLS signing requires pure ML-DSA")
	}
	if options, ok := opts.(*mldsa.Options); ok && options.Context != "" {
		return nil, errors.New("native TLS signing uses an empty context")
	}
	return s.key.Sign(message)
}
