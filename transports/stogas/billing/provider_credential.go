package billing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	providerCredentialCiphertextVersion = "v1"
	providerCredentialHKDFSalt          = "stogas:byok:encryption:salt:v1"
	providerCredentialHKDFInfo          = "stogas:byok:encryption:key:v1"
	providerCredentialAADPrefix         = "stogas:byok:credential:v1"
	providerCredentialMinimumSecretSize = 32
)

type providerCredentialDecryptor struct {
	aead cipher.AEAD
}

func newProviderCredentialDecryptor(masterSecret string) (*providerCredentialDecryptor, error) {
	if len([]byte(masterSecret)) < providerCredentialMinimumSecretSize {
		return nil, fmt.Errorf("BYOK encryption secret must contain at least %d bytes", providerCredentialMinimumSecretSize)
	}
	key := make([]byte, 32)
	reader := hkdf.New(
		sha256.New,
		[]byte(masterSecret),
		[]byte(providerCredentialHKDFSalt),
		[]byte(providerCredentialHKDFInfo),
	)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive BYOK encryption key: %w", err)
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, fmt.Errorf("initialize BYOK encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize BYOK authenticated encryption: %w", err)
	}
	return &providerCredentialDecryptor{aead: aead}, nil
}

func (d *providerCredentialDecryptor) decrypt(
	ciphertext string,
	credentialID string,
	organizationID string,
	workspaceID string,
	provider string,
) (string, error) {
	if d == nil || d.aead == nil {
		return "", errors.New("BYOK decryptor is unavailable")
	}
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 3 || parts[0] != providerCredentialCiphertextVersion {
		return "", errors.New("unsupported BYOK ciphertext")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(nonce) != d.aead.NonceSize() {
		return "", errors.New("invalid BYOK ciphertext nonce")
	}
	encrypted, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(encrypted) < d.aead.Overhead() {
		return "", errors.New("invalid BYOK ciphertext body")
	}
	aad := strings.Join(
		[]string{
			providerCredentialAADPrefix,
			credentialID,
			organizationID,
			workspaceID,
			provider,
		},
		"\x00",
	)
	plaintext, err := d.aead.Open(nil, nonce, encrypted, []byte(aad))
	if err != nil {
		return "", errors.New("BYOK ciphertext authentication failed")
	}
	defer clear(plaintext)
	secret := string(plaintext)
	if strings.TrimSpace(secret) == "" {
		return "", errors.New("BYOK credential is empty")
	}
	return secret, nil
}
