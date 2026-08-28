package billing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	byokCiphertextVersion = "v1"
	byokHKDFSalt          = "stogas:byok:encryption:salt:v1"
	byokHKDFInfo          = "stogas:byok:encryption:key:v1"
	byokAADPrefix         = "stogas:byok:key:v1"
	byokHashHKDFSalt      = "stogas:byok:credential-hash:salt:v1"
	byokHashHKDFInfo      = "stogas:byok:credential-hash:key:v1"
	byokHashPrefix        = "stogas:byok:credential-hash:v1"
	byokMinimumSecretSize = 32
)

type byokDecryptor struct {
	aead    cipher.AEAD
	hashKey [32]byte
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
	hashKey, err := deriveByokKey(masterSecret, byokHashHKDFSalt, byokHashHKDFInfo)
	if err != nil {
		return nil, fmt.Errorf("derive BYOK credential hash key: %w", err)
	}
	decryptor := &byokDecryptor{aead: aead}
	copy(decryptor.hashKey[:], hashKey)
	clear(hashKey)
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

// credentialHash returns the stable organization, workspace, and provider-scoped
// identifier used by holds, policies, and analytics. The plaintext never leaves
// the gateway process.
func (d *byokDecryptor) credentialHash(
	plaintext string,
	organizationID string,
	workspaceID string,
	provider string,
) (string, error) {
	if d == nil || d.hashKey == [32]byte{} || plaintext == "" || organizationID == "" || workspaceID == "" || provider == "" {
		return "", errors.New("BYOK credential hash is unavailable")
	}
	message := strings.Join([]string{
		byokHashPrefix,
		organizationID,
		workspaceID,
		provider,
		plaintext,
	}, "\x00")
	mac := hmac.New(sha256.New, d.hashKey[:])
	_, _ = mac.Write([]byte(message))
	digest := mac.Sum(nil)
	defer clear(digest)
	return hex.EncodeToString(digest), nil
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
