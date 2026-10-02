package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

type Material struct {
	TLSPrivateKey    *ecdsa.PrivateKey
	TLSSPKISHA256    string
	HPKEPrivateKey   hpke.PrivateKey
	HPKEPublicKey    string
	SigningKey       *mldsa.PrivateKey
	SigningPublicKey string
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
	hpkeSeed := make([]byte, 32)
	defer clear(hpkeSeed)
	if _, err := io.ReadFull(reader, hpkeSeed); err != nil {
		return nil, fmt.Errorf("read hpke key seed: %w", err)
	}
	hpkeKey, err := hpke.MLKEM768X25519().NewPrivateKey(hpkeSeed)
	clear(hpkeSeed)
	if err != nil {
		return nil, fmt.Errorf("generate hpke key: %w", err)
	}
	signingSeed := make([]byte, mldsa.PrivateKeySize)
	defer clear(signingSeed)
	if _, err := io.ReadFull(reader, signingSeed); err != nil {
		return nil, fmt.Errorf("read signing key seed: %w", err)
	}
	signingKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), signingSeed)
	if err != nil {
		return nil, fmt.Errorf("generate ML-DSA-65 key: %w", err)
	}
	return &Material{
		TLSPrivateKey:    tlsKey,
		TLSSPKISHA256:    SHA256Hex(spki),
		HPKEPrivateKey:   hpkeKey,
		HPKEPublicKey:    base64.RawURLEncoding.EncodeToString(hpkeKey.PublicKey().Bytes()),
		SigningKey:       signingKey,
		SigningPublicKey: base64.RawURLEncoding.EncodeToString(signingKey.PublicKey().Bytes()),
	}, nil
}

func CertSHA256Hex(der []byte) string {
	return SHA256Hex(der)
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
