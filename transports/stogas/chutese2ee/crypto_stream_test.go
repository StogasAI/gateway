package chutese2ee

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestRequestAndUnaryResponseCryptoInteroperability(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"model":"example","messages":[{"role":"user","content":"private"}]}`)
	encrypted, err := encryptRequest(
		base64.StdEncoding.EncodeToString(instanceKey.EncapsulationKey().Bytes()),
		payload,
	)
	if err != nil {
		t.Fatalf("encrypt request: %v", err)
	}

	requestObject := decryptRequestForTest(t, instanceKey, encrypted.Body)
	if got := string(requestObject["model"]); got != `"example"` {
		t.Fatalf("decrypted model = %s", got)
	}
	var responsePublicKey string
	if err := json.Unmarshal(requestObject["e2e_response_pk"], &responsePublicKey); err != nil {
		t.Fatalf("decode response key: %v", err)
	}

	upstreamResponse := []byte(`{"id":"chatcmpl-private","choices":[]}`)
	responseBody := encryptUnaryResponseForTest(t, responsePublicKey, upstreamResponse)
	decrypted, err := decryptResponse(encrypted.ResponseKey, responseBody)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	if string(decrypted) != string(upstreamResponse) {
		t.Fatalf("decrypted response = %s", decrypted)
	}
}

func TestRequestCryptoRejectsReservedFieldAndNonObject(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(instanceKey.EncapsulationKey().Bytes())
	for _, body := range []string{
		`[]`,
		`null`,
		`{"e2e_response_pk":"attacker"}`,
	} {
		if _, err := encryptRequest(publicKey, []byte(body)); !errors.Is(err, ErrInvalidE2EERequest) {
			t.Fatalf("encryptRequest(%s) error = %v", body, err)
		}
	}
}

func TestUnaryResponseRejectsTamperingAndDecompressionBomb(t *testing.T) {
	responseKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	body := encryptUnaryResponseForTest(
		t,
		base64.StdEncoding.EncodeToString(responseKey.EncapsulationKey().Bytes()),
		[]byte(`{"ok":true}`),
	)
	body[len(body)-1] ^= 1
	if _, err := decryptResponse(responseKey, body); !errors.Is(err, ErrInvalidE2EEResponse) {
		t.Fatalf("tampered response error = %v", err)
	}

	compressed, err := gzipBytes(make([]byte, 1025))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gunzipBounded(compressed, 1024); err == nil {
		t.Fatal("expected bounded decompression to reject oversized plaintext")
	}
}

func TestEncryptedStreamInteroperability(t *testing.T) {
	responseKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	initialization, streamKey := streamInitializationForTest(t, responseKey)
	event := encryptStreamEventForTest(t, streamKey, `data: {"id":"chunk","choices":[]}`)
	outer := sseEnvelopeForTest(t, map[string]any{"e2e_init": initialization}) +
		sseEnvelopeForTest(t, map[string]any{"e2e": event}) +
		"data: [DONE]\n\n"

	var failures atomic.Int32
	reader := newStreamReader(strings.NewReader(outer), responseKey, func() { failures.Add(1) })
	decrypted, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read encrypted stream: %v", err)
	}
	want := "data: {\"id\":\"chunk\",\"choices\":[]}\n\ndata: [DONE]\n\n"
	if string(decrypted) != want {
		t.Fatalf("decrypted stream = %q, want %q", decrypted, want)
	}
	if failures.Load() != 0 {
		t.Fatalf("protocol failure callback count = %d", failures.Load())
	}
}

func TestEncryptedStreamAcceptsAuthenticatedCompletionMarker(t *testing.T) {
	responseKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	initialization, streamKey := streamInitializationForTest(t, responseKey)
	completion := encryptStreamEventForTest(t, streamKey, "data: [DONE]\n\n")
	outer := sseEnvelopeForTest(t, map[string]any{"e2e_init": initialization}) +
		sseEnvelopeForTest(t, map[string]any{"e2e": completion})
	decrypted, err := io.ReadAll(newStreamReader(strings.NewReader(outer), responseKey, nil))
	if err != nil {
		t.Fatalf("read encrypted completion marker: %v", err)
	}
	if string(decrypted) != "data: [DONE]\n\n" {
		t.Fatalf("decrypted completion = %q", decrypted)
	}
}

func TestEncryptedStreamFailsClosed(t *testing.T) {
	responseKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	initialization, streamKey := streamInitializationForTest(t, responseKey)
	validInit := sseEnvelopeForTest(t, map[string]any{"e2e_init": initialization})
	validEvent := encryptStreamEventForTest(t, streamKey, `data: {"id":"chunk"}`)

	tests := map[string]string{
		"plaintext usage":  validInit + sseEnvelopeForTest(t, map[string]any{"usage": map[string]any{"prompt_tokens": 1}}),
		"plaintext error":  validInit + sseEnvelopeForTest(t, map[string]any{"e2e_error": map[string]any{"message": "private"}}),
		"unknown field":    validInit + "data: {\"unknown\":true}\n\n",
		"extra field":      validInit + "data: {\"e2e\":\"" + validEvent + "\",\"unknown\":true}\n\n",
		"duplicate init":   validInit + validInit,
		"data before init": sseEnvelopeForTest(t, map[string]any{"e2e": validEvent}),
		"truncated":        validInit,
		"done before init": "data: [DONE]\n\n",
		"newline injection": validInit + sseEnvelopeForTest(t, map[string]any{
			"e2e": encryptStreamEventForTest(t, streamKey, "data: {\"id\":\"x\"}\n\ndata: {\"id\":\"y\"}"),
		}),
		"non-object plaintext": validInit + sseEnvelopeForTest(t, map[string]any{
			"e2e": encryptStreamEventForTest(t, streamKey, "data: null"),
		}),
	}
	for name, outer := range tests {
		t.Run(name, func(t *testing.T) {
			var failures atomic.Int32
			reader := newStreamReader(strings.NewReader(outer), responseKey, func() { failures.Add(1) })
			if _, err := io.ReadAll(reader); !errors.Is(err, ErrInvalidE2EEResponse) {
				t.Fatalf("stream error = %v", err)
			}
			if failures.Load() != 1 {
				t.Fatalf("protocol failure callback count = %d", failures.Load())
			}
		})
	}
}

func TestEncryptedStreamBoundsOuterEvent(t *testing.T) {
	responseKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	outer := "data: " + strings.Repeat("x", maxEncryptedSSELine) + "\n"
	reader := newStreamReader(strings.NewReader(outer), responseKey, nil)
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrInvalidE2EEResponse) {
		t.Fatalf("oversized event error = %v", err)
	}
}

func decryptRequestForTest(t *testing.T, key *mlkem.DecapsulationKey768, body []byte) map[string]json.RawMessage {
	t.Helper()
	object, err := decryptRequestObjectForTest(key, body)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func decryptRequestObjectForTest(key *mlkem.DecapsulationKey768, body []byte) (map[string]json.RawMessage, error) {
	minimum := mlkem.CiphertextSize768 + nonceSize + chacha20poly1305.Overhead
	if len(body) < minimum {
		return nil, fmt.Errorf("encrypted request is too short: %d", len(body))
	}
	kemCiphertext := body[:mlkem.CiphertextSize768]
	nonce := body[mlkem.CiphertextSize768 : mlkem.CiphertextSize768+nonceSize]
	sharedKey, err := key.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, err
	}
	symmetricKey, err := deriveKey(sharedKey, kemCiphertext, requestKeyInfo)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(symmetricKey)
	if err != nil {
		return nil, err
	}
	compressed, err := aead.Open(nil, nonce, body[mlkem.CiphertextSize768+nonceSize:], nil)
	if err != nil {
		return nil, err
	}
	plaintext, err := gunzipBounded(compressed, maxDecryptedResponse)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &object); err != nil {
		return nil, err
	}
	return object, nil
}

func encryptUnaryResponseForTest(t *testing.T, publicKeyBase64 string, plaintext []byte) []byte {
	t.Helper()
	publicKeyBytes, err := base64.StdEncoding.Strict().DecodeString(publicKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := mlkem.NewEncapsulationKey768(publicKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	sharedKey, kemCiphertext := publicKey.Encapsulate()
	symmetricKey, err := deriveKey(sharedKey, kemCiphertext, responseKeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(symmetricKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	compressed, err := gzipBytes(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte(nil), kemCiphertext...)
	body = append(body, nonce...)
	return aead.Seal(body, nonce, compressed, nil)
}

func streamInitializationForTest(t *testing.T, responseKey *mlkem.DecapsulationKey768) (string, []byte) {
	t.Helper()
	sharedKey, kemCiphertext := responseKey.EncapsulationKey().Encapsulate()
	streamKey, err := deriveKey(sharedKey, kemCiphertext, streamKeyInfo)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(kemCiphertext), streamKey
}

func encryptStreamEventForTest(t *testing.T, streamKey []byte, plaintext string) string {
	t.Helper()
	aead, err := chacha20poly1305.New(streamKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(append([]byte(nil), nonce...), nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed)
}

func sseEnvelopeForTest(t *testing.T, value map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return "data: " + string(encoded) + "\n\n"
}
