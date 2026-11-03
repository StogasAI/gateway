package proofhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	verifier "github.com/StogasAI/stogas/go"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/billing/batchtest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof/prooftest"
)

const testCatalogDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var testCatalogSelectionIDs = []string{"author:openai", "model:gpt-5.5", "deployment:openai-gpt-5.5", "route:openai-responses", "provider:openai"}

// receiptService signs under fresh keys committed by a synthetic boot document.
func receiptService(t *testing.T) (*Service, [32]byte, []byte) {
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
	document, err := keys.BootDocument(1, [32]byte{1}, [32]byte{2}, report, [32]byte{3})
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
	public, err := base64.RawURLEncoding.DecodeString(boot.ReportData.SigningPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(sha256.Sum256(document), "amber-anchor-00", keys)
	if err != nil {
		t.Fatal(err)
	}
	return service, sha256.Sum256(document), public
}

func requestDigest(t *testing.T, body []byte) *[64]byte {
	t.Helper()
	digest, err := verifier.RequestDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	return (*[64]byte)(&digest)
}

func TestReceiptSignsContentAndFinalMetadata(t *testing.T) {
	service, boot, public := receiptService(t)
	request := []byte(`{ "request" : true, "encryption_keys" : {"vault":"secret"} }`)
	input := Input{RequestDigest: requestDigest(t, request), ResponseBody: []byte(`{"response":true}`), Metadata: testMetadata()}
	output, err := service.Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded proof.Object
	if err = json.Unmarshal(output.JSON, &decoded); err != nil || !reflect.DeepEqual(decoded, output.Object) {
		t.Fatal("metadata encoding differs", err)
	}
	if !prooftest.VerifyReceipt(public, decoded, boot, []byte(`{"request":true}`), input.ResponseBody) {
		t.Fatal("receipt does not verify")
	}
	// Logs and exports keep the receipt but never the salts.
	var exported map[string]json.RawMessage
	if err := json.Unmarshal(output.Export, &exported); err != nil || exported["salts"] != nil || exported["receipt"] == nil {
		t.Fatalf("export holds the salts or lacks the receipt: %s", output.Export)
	}
	input.Metadata.BilledCostUSD = "21"
	input.Metadata.Timing.TotalMS++
	other, err := service.Build(context.Background(), input)
	if err != nil || other.Object.Receipt == decoded.Receipt || *other.Object.Salts == *decoded.Salts {
		t.Fatal("a new receipt reused a signature or salts", err)
	}
	if bytes.Contains(output.JSON, []byte("durability")) || bytes.Contains(output.JSON, []byte("observed")) {
		t.Fatal("unexpected receipt claim")
	}
}

func TestStreamSignsTheAssembledResponseAndFinalMetadataOnce(t *testing.T) {
	service, boot, public := receiptService(t)
	request := []byte(`{"stream":true}`)
	stream, err := service.NewStream(context.Background(), Input{RequestDigest: requestDigest(t, request), Metadata: testMetadata()})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	for _, event := range []string{
		"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"one\"}}]}\n\n",
		"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" two\"}}]}\n\n",
		"data: [DONE]\n\n",
	} {
		stream.SentEvent([]byte(event))
	}
	final := testMetadata()
	final.BilledCostUSD = "21"
	stream.SetMetadata(final)
	output, err := service.FinishStream(context.Background(), stream)
	if err != nil {
		t.Fatal(err)
	}
	completion := []byte(`{"object":"chat.completion","choices":[{"index":0,"message":{"content":"one two"}}]}`)
	if output.Object.BilledCostUSD != "21" || !prooftest.VerifyReceipt(public, output.Object, boot, request, completion) {
		t.Fatal("stream signature or final metadata differs")
	}
	stream.SentEvent([]byte("late"))
	if _, err := service.FinishStream(context.Background(), stream); err == nil {
		t.Fatal("stream finalized twice")
	}
	broken, err := service.NewStream(context.Background(), Input{RequestDigest: requestDigest(t, request), Metadata: testMetadata()})
	if err != nil {
		t.Fatal(err)
	}
	defer broken.Close()
	broken.SentEvent([]byte("data: not json\n\n"))
	broken.SentEvent([]byte("data: [DONE]\n\n"))
	if _, err := service.FinishStream(context.Background(), broken); err == nil {
		t.Fatal("signed a stream whose events carry no response")
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
	if _, err := service.Build(context.Background(), Input{RequestDigest: requestDigest(t, []byte(`{}`)), ResponseBody: []byte(`{}`)}); err == nil {
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
	input := Input{RequestDigest: requestDigest(t, []byte(`{}`)), ResponseBody: []byte(`{}`), Metadata: testMetadata()}
	input.Metadata.Provider = map[string]any{"detail": strings.Repeat("x", 7*1024)}
	output, err := service.Build(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.JSON) <= 8*1024 || !prooftest.VerifyReceipt(public, output.Object, boot, []byte(`{}`), input.ResponseBody) {
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

// The boot's key signs a log batch over leaves that a separate checker computes from the rows,
// and signs nothing once the runtime closes.
func TestLogBatchesSignUnderTheBootKeyUntilClosed(t *testing.T) {
	service, boot, public := receiptService(t)
	if service.NodeID() != "amber-anchor-00" {
		t.Fatalf("the service names node %q", service.NodeID())
	}
	// Key order and spacing never change a leaf.
	rows := [][]byte{
		[]byte(`{"node_id":"amber-anchor-00","log_batch":{"sequence":7,"index":0},"metadata":{"b":"<&>","a":"\u00e9"}}`),
		[]byte(`{ "log_batch": {"index": 1, "sequence": 7}, "node_id": "amber-anchor-00", "usage": {"input": 0.5} }`),
	}
	leaves := make([][64]byte, len(rows))
	raw := []byte{}
	for i, row := range rows {
		leaf, err := service.LogRowLeaf(row)
		if err != nil {
			t.Fatal(err)
		}
		if want, err := batchtest.Leaf(row); err != nil || leaf != want {
			t.Fatalf("row %d has leaf %x, the checker computes %x: %v", i, leaf, want, err)
		}
		leaves[i] = leaf
		raw = append(raw, leaf[:]...)
	}
	opened := time.UnixMilli(1_790_000_000_123)
	signed, err := service.SignLogBatch(7, opened, opened.Add(time.Minute), leaves)
	if err != nil {
		t.Fatal(err)
	}
	line := append(bytes.TrimSuffix(signed, []byte("}")), `,"leaves":"`+base64.RawURLEncoding.EncodeToString(raw)+`"}`...)
	batch, err := batchtest.Verify(public, boot, line, rows...)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Sequence != 7 || batch.NodeID != "amber-anchor-00" || batch.OpenedAt != "2026-09-21T14:13:20.123Z" || batch.SealedAt != "2026-09-21T14:14:20.123Z" {
		t.Fatalf("the batch is %+v", batch)
	}
	service.Close()
	if _, err := service.SignLogBatch(8, opened, opened, leaves); err == nil {
		t.Fatal("the service signed after closing")
	}
}
