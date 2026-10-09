package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
)

// Material is the boot's Web PKI TLS key. Its SPKI digest is committed by the
// boot quote; the boot's signing and provisioning keys stay in the verifier.
type Material struct {
	TLSPrivateKey *ecdsa.PrivateKey
	TLSSPKISHA256 [32]byte
}

func Generate(reader io.Reader) (*Material, error) {
	if reader == nil {
		reader = rand.Reader
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), reader)
	if err != nil {
		return nil, fmt.Errorf("generate tls key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal tls spki: %w", err)
	}
	return &Material{TLSPrivateKey: tlsKey, TLSSPKISHA256: sha256.Sum256(spki)}, nil
}

func CertSHA256Hex(der []byte) string {
	return SHA256Hex(der)
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
