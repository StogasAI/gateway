package chutese2ee

import (
	"bytes"
	"compress/gzip"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	requestKeyInfo  = "e2e-req-v1"
	responseKeyInfo = "e2e-resp-v1"
	streamKeyInfo   = "e2e-stream-v1"
	nonceSize       = chacha20poly1305.NonceSize
)

type encryptedRequest struct {
	Body        []byte
	ResponseKey *mlkem.DecapsulationKey768
}

func encryptRequest(publicKeyBase64 string, payload []byte) (*encryptedRequest, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil || object == nil {
		return nil, fmt.Errorf("%w: body must be a JSON object", ErrInvalidE2EERequest)
	}
	if _, exists := object["e2e_response_pk"]; exists {
		return nil, fmt.Errorf("%w: reserved response key field", ErrInvalidE2EERequest)
	}

	responseKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate response key: %w", err)
	}
	responsePublicKey := base64.StdEncoding.EncodeToString(responseKey.EncapsulationKey().Bytes())
	encodedResponsePublicKey, err := json.Marshal(responsePublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode response key: %w", err)
	}
	object["e2e_response_pk"] = encodedResponsePublicKey
	plaintext, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("encode encrypted request: %w", err)
	}
	defer clear(plaintext)

	compressed, err := gzipBytes(plaintext)
	if err != nil {
		return nil, fmt.Errorf("compress encrypted request: %w", err)
	}
	defer clear(compressed)

	publicKeyBytes, err := base64.StdEncoding.Strict().DecodeString(publicKeyBase64)
	if err != nil || len(publicKeyBytes) != mlkem.EncapsulationKeySize768 {
		return nil, fmt.Errorf("%w: invalid instance public key", ErrInvalidE2EERequest)
	}
	publicKey, err := mlkem.NewEncapsulationKey768(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid instance public key", ErrInvalidE2EERequest)
	}
	sharedKey, kemCiphertext := publicKey.Encapsulate()
	defer clear(sharedKey)

	symmetricKey, err := deriveKey(sharedKey, kemCiphertext, requestKeyInfo)
	if err != nil {
		return nil, err
	}
	defer clear(symmetricKey)
	aead, err := chacha20poly1305.New(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("initialize request encryption: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate request nonce: %w", err)
	}

	body := make([]byte, 0, len(kemCiphertext)+len(nonce)+len(compressed)+aead.Overhead())
	body = append(body, kemCiphertext...)
	body = append(body, nonce...)
	body = aead.Seal(body, nonce, compressed, nil)
	return &encryptedRequest{Body: body, ResponseKey: responseKey}, nil
}

func decryptResponse(responseKey *mlkem.DecapsulationKey768, body []byte) ([]byte, error) {
	minimum := mlkem.CiphertextSize768 + nonceSize + chacha20poly1305.Overhead
	if responseKey == nil || len(body) < minimum {
		return nil, ErrInvalidE2EEResponse
	}
	kemCiphertext := body[:mlkem.CiphertextSize768]
	nonce := body[mlkem.CiphertextSize768 : mlkem.CiphertextSize768+nonceSize]
	ciphertext := body[mlkem.CiphertextSize768+nonceSize:]
	sharedKey, err := responseKey.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: response key exchange failed", ErrInvalidE2EEResponse)
	}
	defer clear(sharedKey)
	symmetricKey, err := deriveKey(sharedKey, kemCiphertext, responseKeyInfo)
	if err != nil {
		return nil, err
	}
	defer clear(symmetricKey)
	aead, err := chacha20poly1305.New(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("initialize response decryption: %w", err)
	}
	compressed, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: response authentication failed", ErrInvalidE2EEResponse)
	}
	defer clear(compressed)
	plaintext, err := gunzipBounded(compressed, maxDecryptedResponse)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid compressed response", ErrInvalidE2EEResponse)
	}
	if !json.Valid(plaintext) {
		clear(plaintext)
		return nil, fmt.Errorf("%w: decrypted response is not JSON", ErrInvalidE2EEResponse)
	}
	return plaintext, nil
}

func deriveStreamKey(responseKey *mlkem.DecapsulationKey768, ciphertextBase64 string) ([]byte, error) {
	if responseKey == nil {
		return nil, ErrInvalidE2EEResponse
	}
	kemCiphertext, err := base64.StdEncoding.Strict().DecodeString(ciphertextBase64)
	if err != nil || len(kemCiphertext) != mlkem.CiphertextSize768 {
		return nil, fmt.Errorf("%w: invalid stream initialization", ErrInvalidE2EEResponse)
	}
	sharedKey, err := responseKey.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: stream key exchange failed", ErrInvalidE2EEResponse)
	}
	defer clear(sharedKey)
	return deriveKey(sharedKey, kemCiphertext, streamKeyInfo)
}

func decryptStreamEvent(key []byte, valueBase64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(valueBase64)
	if err != nil || len(raw) < nonceSize+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("%w: invalid stream event", ErrInvalidE2EEResponse)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("initialize stream decryption: %w", err)
	}
	plaintext, err := aead.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("%w: stream event authentication failed", ErrInvalidE2EEResponse)
	}
	return plaintext, nil
}

func deriveKey(sharedKey, kemCiphertext []byte, info string) ([]byte, error) {
	if len(kemCiphertext) < 16 {
		return nil, ErrInvalidE2EEResponse
	}
	key := make([]byte, chacha20poly1305.KeySize)
	reader := hkdf.New(sha256.New, sharedKey, kemCiphertext[:16], []byte(info))
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive E2EE key: %w", err)
	}
	return key, nil
}

func gzipBytes(plaintext []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(plaintext); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func gunzipBounded(compressed []byte, maximum int64) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	plaintext, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(plaintext)) > maximum {
		clear(plaintext)
		return nil, errors.New("decompressed body is too large")
	}
	return plaintext, nil
}
