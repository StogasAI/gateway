package proof

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestContentReceiptVector(t *testing.T) {
	encoded, err := os.ReadFile("testdata/content-receipt-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PublicKey string          `json:"public_key"`
		Request   string          `json:"request"`
		Response  string          `json:"response"`
		Receipt   Receipt         `json:"receipt"`
		Metadata  json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := hex.DecodeString(vector.Receipt.BootSHA256)
	if err != nil {
		t.Fatal(err)
	}
	request, response := sha256.Sum256([]byte(vector.Request)), sha256.Sum256([]byte(vector.Response))
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, mldsa.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := SignReceipt(key, [32]byte(boot), request, response, vector.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyReceipt(publicKey, vector.Receipt, [32]byte(boot), request, response, vector.Metadata) {
		t.Fatal("independent receipt vector rejected")
	}
	if !VerifyReceipt(publicKey, receipt, [32]byte(boot), request, response, vector.Metadata) {
		t.Fatal("valid content receipt rejected")
	}
	var bag map[string]any
	if err := json.Unmarshal(vector.Metadata, &bag); err != nil {
		t.Fatal(err)
	}
	bag["receipt"] = receipt
	if !VerifyReceipt(publicKey, receipt, [32]byte(boot), request, response, bag) {
		t.Fatal("receipt did not exclude itself")
	}
	bag["provider"].(map[string]any)["instance"] = "substituted"
	if VerifyReceipt(publicKey, receipt, [32]byte(boot), request, response, bag) {
		t.Fatal("provider metadata substitution accepted")
	}
	for _, invalid := range []json.RawMessage{[]byte(`null`), []byte(`[]`), []byte(`{"provider":1,"provider":2}`)} {
		if _, err := SignReceipt(key, [32]byte(boot), request, response, invalid); err == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	for name, mutate := range map[string]func(*Receipt){
		"schema":                 func(v *Receipt) { v.Schema = "stogas.command.v1" },
		"boot":                   func(v *Receipt) { v.BootSHA256 = hex.EncodeToString(make([]byte, 32)) },
		"request":                func(v *Receipt) { v.RequestSHA256 = v.ResponseSHA256 },
		"response":               func(v *Receipt) { v.ResponseSHA256 = v.RequestSHA256 },
		"signature":              func(v *Receipt) { v.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64)) },
		"noncanonical signature": func(v *Receipt) { v.Signature += "=" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			mutate(&changed)
			if VerifyReceipt(publicKey, changed, [32]byte(boot), request, response, vector.Metadata) {
				t.Fatal("mutation accepted")
			}
		})
	}
	if VerifyReceipt(nil, receipt, [32]byte(boot), request, response, vector.Metadata) {
		t.Fatal("missing key accepted")
	}
	if _, err := SignReceipt(nil, [32]byte{}, request, response, vector.Metadata); err == nil {
		t.Fatal("missing signer accepted")
	}
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA87()} {
		other, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := SignReceipt(other, [32]byte(boot), request, response, vector.Metadata); err == nil {
			t.Fatal("another ML-DSA profile accepted")
		}
		if VerifyReceipt(other.PublicKey(), receipt, [32]byte(boot), request, response, vector.Metadata) {
			t.Fatal("another ML-DSA profile verified")
		}
	}
	// The boot reference selects the
	// separately verified key; it is not a claim about logging time or billing.
	other := receipt
	other.BootSHA256 = hex.EncodeToString(make([]byte, 32))
	if !VerifyReceipt(publicKey, other, [32]byte{}, request, response, vector.Metadata) {
		t.Fatal("non-content data entered receipt signature")
	}
}
