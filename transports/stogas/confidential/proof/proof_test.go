package proof

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestNonStreamingProofSignsRequestResponseAndReleasePath(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		RequestID:      "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		RequestPath:    "/v1/responses",
		RequestBody:    []byte(`{"model":"gpt-5-mini"}`),
		ResponseBody:   []byte(`{"id":"resp_1"}`),
		CatalogNodeIDs: []string{"root", "openai", "gpt-5-mini"},
		DrandRound:     12_345,
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
			RequestID:      input.RequestID,
			RequestPath:    input.RequestPath,
			RequestBody:    []byte(`{"model":"other"}`),
			ResponseBody:   input.ResponseBody,
			CatalogNodeIDs: input.CatalogNodeIDs,
			DrandRound:     input.DrandRound,
		},
		"response": {
			RequestID:      input.RequestID,
			RequestPath:    input.RequestPath,
			RequestBody:    input.RequestBody,
			ResponseBody:   []byte(`{"id":"resp_2"}`),
			CatalogNodeIDs: input.CatalogNodeIDs,
			DrandRound:     input.DrandRound,
		},
		"catalog path": {
			RequestID:      input.RequestID,
			RequestPath:    input.RequestPath,
			RequestBody:    input.RequestBody,
			ResponseBody:   input.ResponseBody,
			CatalogNodeIDs: []string{"root", "anthropic", "claude"},
			DrandRound:     input.DrandRound,
		},
		"request id": {
			RequestID:      "018f4f70-7c88-7b9a-baf8-31a93d2cf614",
			RequestPath:    input.RequestPath,
			RequestBody:    input.RequestBody,
			ResponseBody:   input.ResponseBody,
			CatalogNodeIDs: input.CatalogNodeIDs,
			DrandRound:     input.DrandRound,
		},
		"drand round": {
			RequestID:      input.RequestID,
			RequestPath:    input.RequestPath,
			RequestBody:    input.RequestBody,
			ResponseBody:   input.ResponseBody,
			CatalogNodeIDs: input.CatalogNodeIDs,
			DrandRound:     input.DrandRound + 1,
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
		RequestID:      "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		RequestPath:    "/v1/responses",
		RequestBody:    []byte(`{"model":"gpt-5-mini"}`),
		ResponseBody:   []byte(`{"id":"resp_1"}`),
		CatalogNodeIDs: []string{"root", "openai"},
		DrandRound:     12_345,
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
		RequestID:      "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		RequestPath:    "/v1/responses",
		RequestBody:    []byte(`{"model":"gpt-5-mini"}`),
		ResponseBody:   []byte(`{"id":"resp_1"}`),
		CatalogNodeIDs: []string{"root", "openai"},
		DrandRound:     12_345,
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

func TestE2EETranscriptChannelBindingChangesProofHash(t *testing.T) {
	base := Input{
		RequestID:             "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		RequestPath:           "/v1/responses",
		RequestBody:           []byte(`{"model":"gpt-5-mini"}`),
		ResponseBody:          []byte(`{"id":"resp_1"}`),
		CatalogNodeIDs:        []string{"root", "openai"},
		DrandRound:            12_345,
		E2EETranscriptSHA256: strings.Repeat("a", 64),
	}
	first, err := Hash(base)
	if err != nil {
		t.Fatal(err)
	}
	base.E2EETranscriptSHA256 = strings.Repeat("b", 64)
	second, err := Hash(base)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("E2EE transcript channel binding should affect proof hash")
	}
}

func TestStreamingProofUsesRunningChunkHash(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	stream := NewStreamHasher(StreamingInput{
		RequestID:      "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		RequestPath:    "/v1/responses",
		RequestBody:    []byte(`{"stream":true}`),
		CatalogNodeIDs: []string{"root", "openai", "stream"},
		DrandRound:     12_345,
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
		RequestID:      "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		RequestPath:    "/v1/responses",
		RequestBody:    []byte(`{"stream":true}`),
		CatalogNodeIDs: []string{"root", "openai", "stream"},
		DrandRound:     12_345,
	}, [][]byte{[]byte("data: one\n\n"), []byte("data: two\n\n")}, hash, signature) {
		t.Fatal("expected recomputed streaming input to verify")
	}

	other := NewStreamHasher(StreamingInput{
		RequestID:      "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		RequestPath:    "/v1/responses",
		RequestBody:    []byte(`{"stream":true}`),
		CatalogNodeIDs: []string{"root", "openai", "stream"},
		DrandRound:     12_345,
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
		RequestID:      "018f4f70-7c88-7b9a-baf8-31a93d2cf613",
		RequestPath:    "/v1/responses",
		RequestBody:    []byte(`{"stream":true}`),
		CatalogNodeIDs: []string{"root", "openai", "stream"},
		DrandRound:     12_345,
	}, [][]byte{[]byte("data: one\n\n"), []byte("data: changed\n\n")}, hash, signature) {
		t.Fatal("tampered stream chunks should not verify")
	}
}
