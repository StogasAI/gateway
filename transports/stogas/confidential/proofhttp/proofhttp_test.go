package proofhttp

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	verifier "github.com/StogasAI/verifier/go"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
)

const testCatalogDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var testCatalogSelectionIDs = []string{"author:openai", "model:gpt-5.5", "deployment:openai-gpt-5.5", "route:openai-responses", "provider:openai"}

// receiptService signs under fresh keys committed by a synthetic boot document.
func receiptService(t *testing.T) (*Service, [32]byte, *mldsa.PublicKey) {
	t.Helper()
	keys, err := verifier.GenerateNodeKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	report := make([]byte, 0x4a0)
	data, err := keys.ReportData(1, [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	copy(report[0x50:], data[:])
	document, err := keys.BootDocument(1, [32]byte{1}, [32]byte{2}, report, [32]byte{3}, [32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	var boot struct {
		ReportData struct {
			SigningPublicKey string `json:"signing_public_key"`
		} `json:"report_data"`
	}
	if err := json.Unmarshal(document, &boot); err != nil {
		t.Fatal(err)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(boot.ReportData.SigningPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := mldsa.NewPublicKey(mldsa.MLDSA65(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(sha256.Sum256(document), "amber-anchor-00", keys)
	if err != nil {
		t.Fatal(err)
	}
	return service, sha256.Sum256(document), public
}

// verifyReceipt is an independent Go check of the Rust signer's message and digests.
func verifyReceipt(public *mldsa.PublicKey, object proof.Object, boot, request, response [32]byte) bool {
	receipt := object.Receipt
	encoded, err := json.Marshal(object)
	var bag map[string]json.RawMessage
	if err != nil || json.Unmarshal(encoded, &bag) != nil {
		return false
	}
	delete(bag, "receipt")
	if encoded, err = json.Marshal(bag); err != nil {
		return false
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || signatureErr != nil || receipt.Schema != "stogas.receipt.v1" || receipt.BootSHA256 != hex.EncodeToString(boot[:]) ||
		receipt.RequestSHA256 != hex.EncodeToString(request[:]) || receipt.ResponseSHA256 != hex.EncodeToString(response[:]) {
		return false
	}
	digest := sha256.Sum256(canonical)
	message := bytes.Join([][]byte{[]byte("stogas.receipt.v1\x00"), request[:], response[:], digest[:]}, nil)
	return mldsa.Verify(public, message, signature, nil) == nil
}

func TestReceiptSignsContentAndFinalMetadata(t *testing.T) {
	service, boot, public := receiptService(t)
	input := Input{RequestDigest: new(sha256.Sum256([]byte(`{"request":true}`))), ResponseBody: []byte(`{"response":true}`), Metadata: testMetadata()}
	output, err := service.Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded proof.Object
	if err = json.Unmarshal(output.JSON, &decoded); err != nil || !reflect.DeepEqual(decoded, output.Object) {
		t.Fatal("metadata encoding differs", err)
	}
	if !verifyReceipt(public, decoded, boot, *input.RequestDigest, sha256.Sum256(input.ResponseBody)) {
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
	service, boot, public := receiptService(t)
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
	if output.Object.BilledCostUSD != "21" || !verifyReceipt(public, output.Object, boot, requestDigest, sha256.Sum256([]byte("data: one\n\ndata: two\n\n"))) {
		t.Fatal("stream signature or final metadata differs")
	}
	stream.WriteSentChunk([]byte("late"))
	if _, err := service.FinishStream(context.Background(), stream); err == nil {
		t.Fatal("stream finalized twice")
	}
}

func TestReceiptRejectsWrongIdentityAndInvalidOrCancelledWork(t *testing.T) {
	service, boot, _ := receiptService(t)
	keys, err := verifier.GenerateNodeKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	for _, candidate := range []struct {
		node string
		keys *verifier.NodeKeys
	}{{"amber-anchor-00", nil}, {"", keys}} {
		if _, err := New(boot, candidate.node, candidate.keys); err == nil {
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
	service, boot, public := receiptService(t)
	input := Input{RequestDigest: new(sha256.Sum256([]byte(`{}`))), ResponseBody: []byte(`{}`), Metadata: testMetadata()}
	input.Metadata.Provider = map[string]any{"detail": strings.Repeat("x", 7*1024)}
	output, err := service.Build(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.JSON) <= 8*1024 || !verifyReceipt(public, output.Object, boot, *input.RequestDigest, sha256.Sum256(input.ResponseBody)) {
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
