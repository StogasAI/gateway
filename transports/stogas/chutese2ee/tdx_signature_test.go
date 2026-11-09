package chutese2ee

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEvidenceKeyPossessionVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{PublicKey: &privateKey.PublicKey}
	quote := base64.StdEncoding.EncodeToString([]byte("bound quote"))
	gpuEvidence := []map[string]any{{"arch": "BLACKWELL", "evidence": "bound GPU evidence"}}
	encodedGPU, err := json.Marshal(gpuEvidence)
	if err != nil {
		t.Fatal(err)
	}
	signed := func(quoteField string) instanceEvidence {
		body, err := json.Marshal(map[string]any{
			"evidence": map[string]any{
				quoteField:         quote,
				"nvtrust_evidence": string(encodedGPU),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return instanceEvidence{
			Signature:    base64.StdEncoding.EncodeToString(signature),
			AttestedBody: base64.StdEncoding.EncodeToString(body),
			Quote:        quote,
			GPUEvidence:  gpuEvidence,
		}
	}
	// Chutes guests sign the quote as quote, and older ones as tdx_quote.
	for _, quoteField := range []string{"quote", "tdx_quote"} {
		verified, err := verifyEvidenceKeyPossession(signed(quoteField), certificate)
		if err != nil || !verified {
			t.Fatalf("valid %s proof verified=%t error=%v", quoteField, verified, err)
		}
	}
	valid := signed("quote")

	tests := map[string]instanceEvidence{
		"absent":              {},
		"signature only":      {Signature: valid.Signature, Quote: quote, GPUEvidence: gpuEvidence},
		"body only":           {AttestedBody: valid.AttestedBody, Quote: quote, GPUEvidence: gpuEvidence},
		"malformed signature": {Signature: "%%%", AttestedBody: valid.AttestedBody, Quote: quote, GPUEvidence: gpuEvidence},
		"malformed body":      {Signature: valid.Signature, AttestedBody: "%%%", Quote: quote, GPUEvidence: gpuEvidence},
		"wrong body": {
			Signature:    valid.Signature,
			AttestedBody: base64.StdEncoding.EncodeToString([]byte("different")),
			Quote:        quote,
			GPUEvidence:  gpuEvidence,
		},
		"oversized body": {
			Signature:    valid.Signature,
			AttestedBody: strings.Repeat("A", base64.StdEncoding.EncodedLen(maxAttestedBodySize+1)),
			Quote:        quote,
			GPUEvidence:  gpuEvidence,
		},
		"outer quote mismatch": {
			Signature:    valid.Signature,
			AttestedBody: valid.AttestedBody,
			Quote:        base64.StdEncoding.EncodeToString([]byte("different quote")),
			GPUEvidence:  gpuEvidence,
		},
		"outer GPU evidence mismatch": {
			Signature:    valid.Signature,
			AttestedBody: valid.AttestedBody,
			Quote:        quote,
			GPUEvidence:  []map[string]any{{"arch": "HOPPER"}},
		},
	}
	for name, evidence := range tests {
		t.Run(name, func(t *testing.T) {
			verified, verifyErr := verifyEvidenceKeyPossession(evidence, certificate)
			if verifyErr == nil || verified || !errors.Is(verifyErr, ErrAttestationFailed) {
				t.Fatalf("unsafe proof verified=%t error=%v", verified, verifyErr)
			}
		})
	}
}
