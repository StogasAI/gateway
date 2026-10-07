package proofhttp

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/json"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
)

const testCatalogDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var testCatalogSelectionIDs = []string{"author:openai", "model:gpt-5.5", "deployment:openai-gpt-5.5", "route:openai-responses", "provider:openai"}

func receiptService(t *testing.T) (*Service, []byte, *mldsa.PrivateKey) {
	t.Helper()
	data, err := os.ReadFile("../attest/testdata/node-boot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Record attest.BootRecord `json:"record"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	document, err := fixture.Record.Document()
	if err != nil {
		t.Fatal(err)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(document, key)
	if err != nil {
		t.Fatal(err)
	}
	return service, document, key
}

func TestReceiptSignsContentAndFinalMetadata(t *testing.T) {
	service, document, key := receiptService(t)
	input := Input{RequestDigest: new(sha256.Sum256([]byte(`{"request":true}`))), ResponseBody: []byte(`{"response":true}`), Metadata: testMetadata()}
	output, err := service.Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded proof.Object
	if err = json.Unmarshal(output.JSON, &decoded); err != nil || !reflect.DeepEqual(decoded, output.Object) {
		t.Fatal("metadata encoding differs", err)
	}
	if !proof.VerifyReceipt(key.PublicKey(), decoded.Receipt, sha256.Sum256(document), *input.RequestDigest, sha256.Sum256(input.ResponseBody), decoded) {
		t.Fatal("receipt does not verify")
	}
	input.Metadata.BilledCostUSD = "21"
	input.Metadata.Timing.TotalMS++
	other, err := service.Build(context.Background(), input)
	if err != nil || other.Object.Receipt == decoded.Receipt {
		t.Fatal("metadata change did not change the signature", err)
	}
	if bytes.Contains(output.JSON, []byte("durability")) || bytes.Contains(output.JSON, []byte("observed")) {
		t.Fatal("unexpected receipt claim")
	}
}

func TestStreamSignsExactChunksAndFinalMetadataOnce(t *testing.T) {
	service, document, key := receiptService(t)
	request := []byte(`{"stream":true}`)
	requestDigest := sha256.Sum256(request)
	stream, err := service.NewStream(context.Background(), Input{RequestDigest: &requestDigest, Metadata: testMetadata()})
	if err != nil {
		t.Fatal(err)
	}
	clear(request) // The stream retains only the digest of the received bytes.
	stream.WriteSentChunk([]byte("data: one\n\n"))
	stream.WriteSentChunk([]byte("data: two\n\n"))
	final := testMetadata()
	final.BilledCostUSD = "21"
	stream.SetMetadata(final)
	output, err := service.FinishStream(context.Background(), stream)
	if err != nil {
		t.Fatal(err)
	}
	if output.Object.BilledCostUSD != "21" || !proof.VerifyReceipt(key.PublicKey(), output.Object.Receipt, sha256.Sum256(document), requestDigest, sha256.Sum256([]byte("data: one\n\ndata: two\n\n")), output.Object) {
		t.Fatal("stream signature or final metadata differs")
	}
	stream.WriteSentChunk([]byte("late"))
	if _, err := service.FinishStream(context.Background(), stream); err == nil {
		t.Fatal("stream finalized twice")
	}
}

func TestReceiptRejectsWrongIdentityAndInvalidOrCancelledWork(t *testing.T) {
	service, document, key := receiptService(t)
	other, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		document []byte
		key      *mldsa.PrivateKey
	}{
		{document, other}, {document, nil}, {append(bytes.Clone(document), ' '), key}, {[]byte(`{}`), key},
	} {
		if _, err := New(candidate.document, candidate.key); err == nil {
			t.Fatal("invalid receipt identity accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Build(ctx, Input{}); err == nil {
		t.Fatal("cancelled receipt built")
	}
	if _, err := service.NewStream(ctx, Input{}); err == nil {
		t.Fatal("cancelled stream created")
	}
	if _, err := service.Build(context.Background(), Input{RequestDigest: new(sha256.Sum256([]byte("a"))), ResponseBody: []byte("b")}); err == nil {
		t.Fatal("invalid metadata accepted")
	}
	if _, err := (&Service{}).NewStream(context.Background(), Input{}); err == nil {
		t.Fatal("uninitialized service accepted")
	}
	var absent *Service
	if out, err := absent.Build(context.Background(), Input{}); out != nil || err != nil {
		t.Fatal("absent service is not a no-op")
	}
}

func TestReceiptLeavesRoomForMetadataAndStillBoundsTheCompleteResponseBag(t *testing.T) {
	service, document, key := receiptService(t)
	input := Input{RequestDigest: new(sha256.Sum256([]byte(`{}`))), ResponseBody: []byte(`{}`), Metadata: testMetadata()}
	input.Metadata.Provider = map[string]any{"detail": strings.Repeat("x", 7*1024)}
	output, err := service.Build(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.JSON) <= 8*1024 || !proof.VerifyReceipt(key.PublicKey(), output.Object.Receipt,
		sha256.Sum256(document), *input.RequestDigest, sha256.Sum256(input.ResponseBody), output.Object) {
		t.Fatal("post-quantum signature crowded out previously supported metadata")
	}
	input.Metadata.Provider["detail"] = strings.Repeat("x", proof.MaxObjectBytes)
	if _, err := service.Build(t.Context(), input); err == nil {
		t.Fatal("oversized metadata accepted")
	}
}

func testMetadata() proof.Metadata {
	ttft := uint32(4)
	return proof.Metadata{
		RequestID: "req_1",
		CreatedAt: "2026-08-24T12:34:56.789Z",
		Catalog: proof.Catalog{
			ChainHash:    testCatalogDigest,
			Version:      7,
			SelectionIDs: append([]string(nil), testCatalogSelectionIDs...),
		},
		Meters: map[string]proof.Meter{
			"input_tokens": billing.PricedMeter("10", "input_tokens", "2", "20"),
		},
		UpstreamCostUSD: "20", BilledCostUSD: "20",
		Timing: proof.Timing{
			TotalMS:    20,
			ProviderMS: 15,
			TTFTMS:     &ttft,
		},
	}
}
