package proofhttp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/quote"
	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

const testCatalogDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var testCatalogNodeIDs = []string{
	"author:openai",
	"model:gpt-5.5",
	"deployment:openai-gpt-5.5",
	"route:openai-responses",
	"provider:openai",
}

func TestBuildReturnsHeadersAndVerifiableSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("a", 128)))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{Quotes: staticQuotes{snapshot: testSnapshot(t, publicKey)}, Signer: privateKey}
	input := Input{
		RequestBody:  []byte(`{"request":true}`),
		ResponseBody: []byte(`{"response":true}`),
		Metadata:     testMetadata(),
	}
	output, err := service.Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Headers) != 1 || output.Headers[HeaderProof] == "" {
		t.Fatalf("expected one compact proof header: %#v", output.Headers)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(output.Headers[HeaderProof])
	if err != nil {
		t.Fatal(err)
	}
	var object proof.Object
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(object, output.Object) {
		t.Fatalf("proof header and output object diverged: %#v %#v", object, output.Object)
	}
	if object.Schema != proof.DomainV1 {
		t.Fatalf("proof identity context mismatch: %#v", object)
	}
	if !proof.VerifyInput(publicKey, proof.Input{
		RequestBody:  input.RequestBody,
		ResponseBody: input.ResponseBody,
		Metadata:     input.Metadata,
	}, object.Proof.Signature) {
		t.Fatal("response proof did not bind its complete receipt")
	}
}

func TestFinishStreamSignsRunningChunkHash(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("b", 128)))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{Quotes: staticQuotes{snapshot: testSnapshot(t, publicKey)}, Signer: privateKey}
	metadata := testMetadata()
	stream, err := service.NewStream(context.Background(), Input{
		RequestBody: []byte(`{"request":true}`),
		Metadata:    metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	stream.WriteSentChunk([]byte(`{"delta":"a"}`))
	stream.WriteSentChunk([]byte(`{"delta":"b"}`))
	output, err := service.FinishStream(context.Background(), stream)
	if err != nil {
		t.Fatal(err)
	}
	payload := proof.PayloadFromObject(output.Object)
	if !proof.Verify(publicKey, payload, output.Object.Proof.Signature) {
		t.Fatal("stream proof signature did not verify")
	}
	expected := proof.NewStreamHasher(proof.StreamingInput{
		RequestBody: []byte(`{"request":true}`),
		Metadata:    metadata,
	})
	expected.WriteChunk([]byte(`{"delta":"a"}`))
	expected.WriteChunk([]byte(`{"delta":"b"}`))
	if !reflect.DeepEqual(payload, expected.FinalPayload()) {
		t.Fatalf("stream payload mismatch: got %#v want %#v", payload, expected.FinalPayload())
	}
}

func TestNilServiceIsNoopAndIncompleteServiceFailsClosed(t *testing.T) {
	var service *Service
	output, err := service.Build(context.Background(), Input{})
	if err != nil || output != nil {
		t.Fatalf("nil service should be noop, got output=%#v err=%v", output, err)
	}
	_, err = (&Service{}).Build(context.Background(), Input{})
	if err == nil || !strings.Contains(err.Error(), "quote provider") {
		t.Fatalf("expected missing quote provider error, got %v", err)
	}
}

func TestEnabledServiceFailsClosedWhenSignerDoesNotMatchReportData(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("c", 128)))
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("d", 128)))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		Quotes: staticQuotes{snapshot: testSnapshot(t, publicKey)},
		Signer: otherPrivateKey,
	}
	_, err = service.Build(context.Background(), Input{
		RequestBody:  []byte(`{"request":true}`),
		ResponseBody: []byte(`{"response":true}`),
		Metadata:     testMetadata(),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match report-data ed25519 key") {
		t.Fatalf("expected mismatched signer failure, got %v", err)
	}
}

func TestEnabledServiceFailsClosedWhenSnapshotReportDataHashDoesNotMatchPayload(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("e", 128)))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot(t, publicKey)
	snapshot.ReportDataHex = strings.Repeat("0", 128)
	service := &Service{
		Quotes: staticQuotes{snapshot: snapshot},
		Signer: privateKey,
	}
	_, err = service.Build(context.Background(), Input{
		RequestBody:  []byte(`{"request":true}`),
		ResponseBody: []byte(`{"response":true}`),
		Metadata:     testMetadata(),
	})
	if err == nil || !strings.Contains(err.Error(), "report-data hash mismatch") {
		t.Fatalf("expected report-data mismatch failure, got %v", err)
	}
}

func TestValidateCatalogRefreshesOnceAndFailsClosedOnAStaleSnapshot(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("f", 128)))
	if err != nil {
		t.Fatal(err)
	}
	current := testSnapshot(t, publicKey)
	current.Payload.Catalog.Digest = "sha256:" + strings.Repeat("b", 64)
	current.ReportDataHex, err = reportdata.HashHex(current.Payload)
	if err != nil {
		t.Fatal(err)
	}
	next := testSnapshot(t, publicKey)
	provider := &refreshingQuotes{current: current, next: next}
	service := &Service{Quotes: provider, Signer: privateKey}

	if err := service.ValidateCatalog(
		context.Background(), testCatalogDigest, next.Payload.Catalog.Sequence,
	); err != nil {
		t.Fatal(err)
	}
	if provider.refreshes != 1 {
		t.Fatalf("catalog quote refreshes = %d, want 1", provider.refreshes)
	}
	stale := &Service{Quotes: staticQuotes{snapshot: current}, Signer: privateKey}
	if err := stale.ValidateCatalog(
		context.Background(), testCatalogDigest, next.Payload.Catalog.Sequence,
	); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected stale catalog quote failure, got %v", err)
	}
	matchingDigest := &Service{Quotes: staticQuotes{snapshot: next}, Signer: privateKey}
	if err := matchingDigest.ValidateCatalog(
		context.Background(), testCatalogDigest, next.Payload.Catalog.Sequence+1,
	); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected catalog sequence mismatch failure, got %v", err)
	}
}

type staticQuotes struct {
	snapshot *quote.Snapshot
}

type refreshingQuotes struct {
	current   *quote.Snapshot
	next      *quote.Snapshot
	refreshes int
}

func (q *refreshingQuotes) Current(context.Context) (*quote.Snapshot, error) {
	return q.current, nil
}

func (q *refreshingQuotes) Refresh(context.Context) error {
	q.refreshes++
	q.current = q.next
	return nil
}

func (s staticQuotes) Current(ctx context.Context) (*quote.Snapshot, error) {
	return s.snapshot, nil
}

func testSnapshot(t *testing.T, publicKey ed25519.PublicKey) *quote.Snapshot {
	t.Helper()
	payload, err := reportdata.NewPayload(reportdata.Payload{
		Catalog:            reportdata.CatalogIdentity{Digest: "sha256:" + strings.Repeat("a", 64), Sequence: 7},
		TLSSPKISHA256:      strings.Repeat("c", 64),
		ActiveCertSHA256:   strings.Repeat("d", 64),
		AcceptedCertSHA256: []string{strings.Repeat("d", 64)},
		HPKEPublicKey:      "aHBrZQ",
		Ed25519PublicKey:   base64.RawURLEncoding.EncodeToString(publicKey),
		Drand: reportdata.Drand{
			Round:      1,
			Randomness: strings.Repeat("e", 64),
			Signature:  strings.Repeat("f", 96),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := reportdata.HashHex(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &quote.Snapshot{
		Payload:       payload,
		ReportDataHex: hash,
		Quote:         []byte("quote"),
		GeneratedAt:   time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
	}
}

func testMetadata() proof.Metadata {
	firstOutput := uint32(4)
	return proof.Metadata{
		RequestID: "req_1",
		NodeID:    strings.Repeat("3", 64),
		Catalog: proof.Catalog{
			Digest:   testCatalogDigest,
			Sequence: 7,
			NodeIDs:  append([]string(nil), testCatalogNodeIDs...),
		},
		Pricing: proof.Pricing{
			Meters: map[string]proof.Meter{
				"input_tokens": {
					Quantity:     "10",
					RateKey:      "input_tokens",
					RateUSDAtoms: "2",
					USDAtoms:     "20",
				},
			},
			TotalCostUSDAtoms: "20",
		},
		Timing: proof.Timing{
			TotalMS:             20,
			ProviderMS:          15,
			TimeToFirstOutputMS: &firstOutput,
		},
		E2EETranscriptSHA256: strings.Repeat("b", 64),
	}
}
