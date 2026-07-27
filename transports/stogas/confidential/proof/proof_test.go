package proof

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestProofSignsOnlyTheMinimalResolvedExchange(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		RequestBody:          []byte(`{"model":"gpt-5.5"}`),
		ResponseBody:         []byte(`{"id":"resp_1"}`),
		CatalogDigest:        "sha256:" + strings.Repeat("a", 64),
		CatalogNodeIDs:       []string{"author:openai", "model:gpt-5.5", "deployment:gpt-5.5", "route:openai-responses", "provider:openai"},
		E2EETranscriptSHA256: strings.Repeat("b", 64),
	}
	payload := PayloadFor(input)
	signature, err := Sign(privateKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInput(publicKey, input, signature) {
		t.Fatal("expected proof signature to verify")
	}

	for name, mutate := range map[string]func(*Input){
		"request":  func(value *Input) { value.RequestBody = []byte(`{"model":"other"}`) },
		"response": func(value *Input) { value.ResponseBody = []byte(`{"id":"resp_2"}`) },
		"catalog":  func(value *Input) { value.CatalogDigest = "sha256:" + strings.Repeat("c", 64) },
		"nodes": func(value *Input) {
			value.CatalogNodeIDs = append([]string(nil), value.CatalogNodeIDs...)
			value.CatalogNodeIDs[2] = "deployment:gpt-5.5-flex"
		},
		"transcript": func(value *Input) { value.E2EETranscriptSHA256 = strings.Repeat("d", 64) },
	} {
		tampered := input
		mutate(&tampered)
		if VerifyInput(publicKey, tampered, signature) {
			t.Fatalf("tampered %s should not verify", name)
		}
	}
}

func TestStreamingProofUsesExactSentChunks(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	input := StreamingInput{
		RequestBody:    []byte(`{"stream":true}`),
		CatalogDigest:  "sha256:" + strings.Repeat("a", 64),
		CatalogNodeIDs: []string{"author:openai", "model:gpt-5.5", "deployment:gpt-5.5", "route:openai-responses", "provider:openai"},
	}
	stream := NewStreamHasher(input)
	stream.WriteChunk([]byte("data: one\n\n"))
	stream.WriteChunk([]byte("data: two\n\n"))
	signature, err := Sign(privateKey, stream.FinalPayload())
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyStreamingInput(
		publicKey,
		input,
		[][]byte{[]byte("data: one\n\n"), []byte("data: two\n\n")},
		signature,
	) {
		t.Fatal("expected streaming proof to verify")
	}
	if VerifyStreamingInput(
		publicKey,
		input,
		[][]byte{[]byte("data: one\n\n"), []byte("data: changed\n\n")},
		signature,
	) {
		t.Fatal("tampered stream chunks should not verify")
	}
}
