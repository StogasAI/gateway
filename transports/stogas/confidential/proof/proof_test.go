package proof

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestProofSignsTheCompleteResolvedExchange(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		RequestBody:  []byte(`{"model":"gpt-5.5"}`),
		ResponseBody: []byte(`{"id":"resp_1"}`),
		Metadata:     testMetadata(),
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
		"request":    func(value *Input) { value.RequestBody = []byte(`{"model":"other"}`) },
		"response":   func(value *Input) { value.ResponseBody = []byte(`{"id":"resp_2"}`) },
		"node":       func(value *Input) { value.Metadata.NodeID = strings.Repeat("4", 64) },
		"catalog":    func(value *Input) { value.Metadata.Catalog.Digest = "sha256:" + strings.Repeat("c", 64) },
		"catalog ID": func(value *Input) { value.Metadata.Catalog.NodeIDs[2] = "deployment:other" },
		"pricing":    func(value *Input) { value.Metadata.Pricing.TotalCostUSDAtoms = "2" },
		"timing":     func(value *Input) { value.Metadata.Timing.TotalMS++ },
		"transcript": func(value *Input) { value.Metadata.E2EETranscriptSHA256 = strings.Repeat("d", 64) },
	} {
		tampered := input
		tampered.Metadata = cloneMetadata(input.Metadata)
		mutate(&tampered)
		if VerifyInput(publicKey, tampered, signature) {
			t.Fatalf("tampered %s should not verify", name)
		}
	}
}

func TestStreamingProofUsesExactSentChunksAndFinalMetadata(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	initialMetadata := testMetadata()
	initialMetadata.Pricing.TotalCostUSDAtoms = "0"
	input := StreamingInput{
		RequestBody: []byte(`{"stream":true}`),
		Metadata:    initialMetadata,
	}
	finalMetadata := testMetadata()
	stream := NewStreamHasher(input)
	stream.WriteChunk([]byte("data: one\n\n"))
	stream.WriteChunk([]byte("data: two\n\n"))
	stream.SetMetadata(finalMetadata)
	signature, err := Sign(privateKey, stream.FinalPayload())
	if err != nil {
		t.Fatal(err)
	}

	verified := NewStreamHasher(input)
	verified.WriteChunk([]byte("data: one\n\n"))
	verified.WriteChunk([]byte("data: two\n\n"))
	verified.SetMetadata(finalMetadata)
	if !Verify(publicKey, verified.FinalPayload(), signature) {
		t.Fatal("expected streaming proof to verify")
	}

	tampered := NewStreamHasher(input)
	tampered.WriteChunk([]byte("data: one\n\n"))
	tampered.WriteChunk([]byte("data: changed\n\n"))
	tampered.SetMetadata(finalMetadata)
	if Verify(publicKey, tampered.FinalPayload(), signature) {
		t.Fatal("tampered stream chunks should not verify")
	}
}

func testMetadata() Metadata {
	firstOutput := uint32(4)
	return Metadata{
		RequestID: "req_1",
		NodeID:    strings.Repeat("3", 64),
		Catalog: Catalog{
			Digest:   "sha256:" + strings.Repeat("a", 64),
			Sequence: 7,
			NodeIDs:  testCatalogNodeIDs(),
		},
		Pricing: Pricing{
			Meters: map[string]Meter{
				"input_tokens": {
					Quantity:     "10",
					RateKey:      "input_tokens",
					RateUSDAtoms: "2",
					USDAtoms:     "20",
				},
			},
			TotalCostUSDAtoms: "20",
		},
		Timing: Timing{
			TotalMS:             20,
			ProviderMS:          15,
			TimeToFirstOutputMS: &firstOutput,
		},
		E2EETranscriptSHA256: strings.Repeat("b", 64),
	}
}

func testCatalogNodeIDs() []string {
	return []string{
		"author:openai",
		"model:gpt-5.5",
		"deployment:openai-gpt-5.5",
		"route:openai-responses",
		"provider:openai",
	}
}
