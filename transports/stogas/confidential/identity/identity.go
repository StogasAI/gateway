package identity

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

type Material struct {
	TLSPrivateKey       *ecdsa.PrivateKey
	TLSSPKISHA256       string
	HPKEPrivateKey      *ecdh.PrivateKey
	HPKEPublicKey       string
	Ed25519PrivateKey   ed25519.PrivateKey
	Ed25519PublicKey    string
	Ed25519PublicKeyRaw ed25519.PublicKey
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
	hpkeKey, err := ecdh.P256().GenerateKey(reader)
	if err != nil {
		return nil, fmt.Errorf("generate hpke key: %w", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &Material{
		TLSPrivateKey:       tlsKey,
		TLSSPKISHA256:       SHA256Hex(spki),
		HPKEPrivateKey:      hpkeKey,
		HPKEPublicKey:       base64.RawURLEncoding.EncodeToString(hpkeKey.PublicKey().Bytes()),
		Ed25519PrivateKey:   edPriv,
		Ed25519PublicKey:    base64.RawURLEncoding.EncodeToString(edPub),
		Ed25519PublicKeyRaw: edPub,
	}, nil
}

func CertSHA256Hex(der []byte) string {
	return SHA256Hex(der)
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
