package billing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

const (
	byokCiphertextVersion = "v1"
	byokHKDFSalt          = "stogas:byok:encryption:salt:v1"
	byokHKDFInfo          = "stogas:byok:encryption:key:v1"
	byokAADPrefix         = "stogas:byok:key:v1"
	byokIdentityHKDFSalt  = "stogas:byok:identity:salt:v1"
	byokIdentityHKDFInfo  = "stogas:byok:identity:key:v1"
	byokIdentityPrefix    = "stogas:byok:credential:v1"
	byokMinimumSecretSize = 32
)

type byokDecryptor struct {
	aead        cipher.AEAD
	identityKey [32]byte
}

func newByokDecryptor(masterSecret string) (*byokDecryptor, error) {
	if len([]byte(masterSecret)) < byokMinimumSecretSize {
		return nil, fmt.Errorf("BYOK encryption secret must contain at least %d bytes", byokMinimumSecretSize)
	}
	key, err := deriveByokKey(masterSecret, byokHKDFSalt, byokHKDFInfo)
	if err != nil {
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
	identityKey, err := deriveByokKey(masterSecret, byokIdentityHKDFSalt, byokIdentityHKDFInfo)
	if err != nil {
		return nil, fmt.Errorf("derive BYOK identity key: %w", err)
	}
	decryptor := &byokDecryptor{aead: aead}
	copy(decryptor.identityKey[:], identityKey)
	clear(identityKey)
	return decryptor, nil
}

func deriveByokKey(masterSecret string, salt string, info string) ([]byte, error) {
	key := make([]byte, 32)
	reader := hkdf.New(sha256.New, []byte(masterSecret), []byte(salt), []byte(info))
	if _, err := io.ReadFull(reader, key); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

func (d *byokDecryptor) credentialID(
	plaintext string,
	organizationID string,
	workspaceID string,
	provider string,
) (string, error) {
	if d == nil || d.identityKey == [32]byte{} || plaintext == "" {
		return "", errors.New("BYOK identity derivation is unavailable")
	}
	message := strings.Join([]string{
		byokIdentityPrefix,
		organizationID,
		workspaceID,
		provider,
		plaintext,
	}, "\x00")
	mac := hmac.New(sha256.New, d.identityKey[:])
	_, _ = mac.Write([]byte(message))
	digest := mac.Sum(nil)
	defer clear(digest)
	var raw [16]byte
	copy(raw[:], digest[:16])
	raw[6] = (raw[6] & 0x0f) | 0x80
	raw[8] = (raw[8] & 0x3f) | 0x80
	return uuid.UUID(raw).String(), nil
}

func (d *byokDecryptor) decrypt(
	ciphertext string,
	byokID string,
	organizationID string,
	workspaceID string,
	provider string,
) (string, error) {
	if d == nil || d.aead == nil {
		return "", errors.New("BYOK decryptor is unavailable")
	}
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 3 || parts[0] != byokCiphertextVersion {
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
			byokAADPrefix,
			byokID,
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
		return "", errors.New("BYOK key is empty")
	}
	return secret, nil
}
