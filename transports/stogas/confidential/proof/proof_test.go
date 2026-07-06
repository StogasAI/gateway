package proof

import (
	"crypto/ed25519"
	"testing"
)

func TestNonStreamingProofSignsProcessedRequestResponseAndReleasePath(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		ProcessedRequestJSON: []byte(`{"model":"gpt-5-mini"}`),
		ResponseJSON:         []byte(`{"id":"resp_1"}`),
		CatalogNodeIDs:       []string{"root", "openai", "gpt-5-mini"},
	}
	hash, err := Hash(input)
	if err != nil {
		t.Fatal(err)
	}
	signature := Sign(privateKey, hash)
	if !Verify(publicKey, hash, signature) {
		t.Fatal("expected proof signature to verify")
	}
	if !VerifyInput(publicKey, input, hash, signature) {
		t.Fatal("expected recomputed proof input to verify")
	}
	for name, tampered := range map[string]Input{
		"request": {
			ProcessedRequestJSON: []byte(`{"model":"other"}`),
			ResponseJSON:         input.ResponseJSON,
			CatalogNodeIDs:       input.CatalogNodeIDs,
		},
		"response": {
			ProcessedRequestJSON: input.ProcessedRequestJSON,
			ResponseJSON:         []byte(`{"id":"resp_2"}`),
			CatalogNodeIDs:       input.CatalogNodeIDs,
		},
		"catalog path": {
			ProcessedRequestJSON: input.ProcessedRequestJSON,
			ResponseJSON:         input.ResponseJSON,
			CatalogNodeIDs:       []string{"root", "anthropic", "claude"},
		},
	} {
		if VerifyInput(publicKey, tampered, hash, signature) {
			t.Fatalf("tampered %s should not verify", name)
		}
	}
}

func TestProofSignatureRejectsWrongKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		ProcessedRequestJSON: []byte(`{"model":"gpt-5-mini"}`),
		ResponseJSON:         []byte(`{"id":"resp_1"}`),
		CatalogNodeIDs:       []string{"root", "openai"},
	}
	hash, err := Hash(input)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyInput(publicKey, input, hash, Sign(otherPrivateKey, hash)) {
		t.Fatal("signature from a different report-data key should not verify")
	}
}

func TestCatalogNodeChainChangesProofHash(t *testing.T) {
	base := Input{
		ProcessedRequestJSON: []byte(`{"model":"gpt-5-mini"}`),
		ResponseJSON:         []byte(`{"id":"resp_1"}`),
		CatalogNodeIDs:       []string{"root", "openai"},
	}
	first, err := Hash(base)
	if err != nil {
		t.Fatal(err)
	}
	base.CatalogNodeIDs = []string{"root", "anthropic"}
	second, err := Hash(base)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("catalog node path should affect proof hash")
	}
}

func TestStreamingProofUsesRunningChunkHash(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	stream := NewStreamHasher(StreamingInput{
		ProcessedRequestJSON: []byte(`{"stream":true}`),
		CatalogNodeIDs:       []string{"root", "openai", "stream"},
	})
	stream.WriteChunk([]byte("data: one\n\n"))
	stream.WriteChunk([]byte("data: two\n\n"))
	hash, err := stream.FinalHash()
	if err != nil {
		t.Fatal(err)
	}
	signature := Sign(privateKey, hash)
	if !Verify(publicKey, hash, signature) {
		t.Fatal("expected streaming proof signature to verify")
	}
	if !VerifyStreamingInput(publicKey, StreamingInput{
		ProcessedRequestJSON: []byte(`{"stream":true}`),
		CatalogNodeIDs:       []string{"root", "openai", "stream"},
	}, [][]byte{[]byte("data: one\n\n"), []byte("data: two\n\n")}, hash, signature) {
		t.Fatal("expected recomputed streaming input to verify")
	}

	other := NewStreamHasher(StreamingInput{
		ProcessedRequestJSON: []byte(`{"stream":true}`),
		CatalogNodeIDs:       []string{"root", "openai", "stream"},
	})
	other.WriteChunk([]byte("data: one\n\n"))
	other.WriteChunk([]byte("data: changed\n\n"))
	otherHash, err := other.FinalHash()
	if err != nil {
		t.Fatal(err)
	}
	if hash == otherHash {
		t.Fatal("stream chunk content should affect proof hash")
	}
	if VerifyStreamingInput(publicKey, StreamingInput{
		ProcessedRequestJSON: []byte(`{"stream":true}`),
		CatalogNodeIDs:       []string{"root", "openai", "stream"},
	}, [][]byte{[]byte("data: one\n\n"), []byte("data: changed\n\n")}, hash, signature) {
		t.Fatal("tampered stream chunks should not verify")
	}
}
