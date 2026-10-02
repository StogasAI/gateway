// Package customerkey opens customer-owned secrets. Root keys are request-owned;
// callers must clear them when the request ends and never persist them.
package customerkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

type failure string

func (e failure) Error() string   { return string(e) }
func (e failure) StatusCode() int { return 400 }

const (
	ErrKey      failure = "Supply the matching registered encryption keys"
	ErrEnvelope failure = "Invalid encrypted content"
)

// Envelope uses unpadded base64url. Salt gives each write an independent key.
type Envelope struct {
	Version int    `json:"version"`
	KeyID   string `json:"keyId"`
	Salt    string `json:"salt"`
	Nonce   string `json:"nonce"`
	Blob    string `json:"blob"`
}

type Key struct {
	material [32]byte
	id       string
}

func (k *Key) ID() string {
	if k == nil {
		return ""
	}
	return k.id
}

func (k *Key) String() string   { return "[redacted]" }
func (k *Key) GoString() string { return "[redacted]" }

func Parse(raw string) (*Key, error) {
	decoded, err := decode(raw, 32)
	if err != nil {
		return nil, ErrKey
	}
	defer clear(decoded)
	k := &Key{}
	copy(k.material[:], decoded)
	h := sha256.New()
	h.Write([]byte("stogas.customer-key.v1\x00"))
	h.Write(k.material[:])
	k.id = hex.EncodeToString(h.Sum(nil))
	return k, nil
}

func (k *Key) Matches(id string) bool {
	return k != nil && len(id) == 64 && hmac.Equal([]byte(k.id), []byte(id))
}

func (k *Key) Clear() {
	if k != nil {
		clear(k.material[:])
		k.id = ""
	}
}

func (e Envelope) Validate(maxPlaintext int) error {
	if e.Version != 1 || len(e.KeyID) != 64 || strings.Trim(e.KeyID, "0123456789abcdef") != "" ||
		len(e.Blob) < base64.RawURLEncoding.EncodedLen(16) || len(e.Blob) > base64.RawURLEncoding.EncodedLen(maxPlaintext+16) {
		return ErrEnvelope
	}
	if _, err := decode(e.Salt, 32); err != nil {
		return ErrEnvelope
	}
	if _, err := decode(e.Nonce, 12); err != nil {
		return ErrEnvelope
	}
	if strings.Trim(e.Blob, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return ErrEnvelope
	}
	return nil
}

// Open binds ciphertext to its organization and purpose (plugins or byok/provider).
// Errors deliberately omit decrypted content and cryptographic material.
func (k *Key) Open(e Envelope, organizationID, purpose string, maxPlaintext int) ([]byte, error) {
	if err := e.Validate(maxPlaintext); err != nil {
		return nil, err
	}
	if !k.Matches(e.KeyID) {
		return nil, ErrKey
	}
	if organizationID == "" || strings.ContainsRune(organizationID, 0) || purpose == "" || strings.ContainsRune(purpose, 0) {
		return nil, ErrEnvelope
	}
	salt, _ := decode(e.Salt, 32)
	nonce, _ := decode(e.Nonce, 12)
	body, err := base64.RawURLEncoding.Strict().DecodeString(e.Blob)
	if err != nil || len(body) < 16 || len(body) > maxPlaintext+16 {
		return nil, ErrEnvelope
	}
	context := strings.Join([]string{"stogas.customer-content.v1", organizationID, purpose, e.KeyID}, "\x00")
	derived, err := hkdf.Key(sha256.New, k.material[:], salt, context, 32)
	if err != nil {
		return nil, ErrEnvelope
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, ErrEnvelope
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEnvelope
	}
	plaintext, err := aead.Open(nil, nonce, body, []byte(context))
	if err != nil {
		return nil, ErrEnvelope
	}
	return plaintext, nil
}

func decode(raw string, size int) ([]byte, error) {
	if len(raw) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, ErrEnvelope
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != size {
		return nil, ErrEnvelope
	}
	return decoded, nil
}
