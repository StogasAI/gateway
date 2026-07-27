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

func TestBuildReturnsHeadersAndVerifiableSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("a", 128)))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{Quotes: staticQuotes{snapshot: testSnapshot(t, publicKey)}, Signer: privateKey}
	input := Input{
		RequestBody:          []byte(`{"request":true}`),
		CatalogDigest:        testCatalogDigest,
		CatalogNodeIDs:       []string{"author:openai", "model:gpt-5", "deployment:gpt-5", "route:openai-responses", "provider:openai"},
		ResponseBody:         []byte(`{"response":true}`),
		E2EETranscriptSHA256: strings.Repeat("a", 64),
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
	var object Object
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(object, output.Object) {
		t.Fatalf("proof header and output object diverged: %#v %#v", object, output.Object)
	}
	if object.Schema != proof.DomainV4 {
		t.Fatalf("proof identity context mismatch: %#v", object)
	}
	if !proof.VerifyInput(publicKey, proof.Input{
		RequestBody:          input.RequestBody,
		ResponseBody:         input.ResponseBody,
		CatalogDigest:        input.CatalogDigest,
		CatalogNodeIDs:       input.CatalogNodeIDs,
		E2EETranscriptSHA256: input.E2EETranscriptSHA256,
	}, object.Signature) {
		t.Fatal("response proof did not bind its complete receipt")
	}
}

func TestFinishStreamSignsRunningChunkHash(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("b", 128)))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{Quotes: staticQuotes{snapshot: testSnapshot(t, publicKey)}, Signer: privateKey}
	stream, err := service.NewStream(context.Background(), Input{
		RequestBody:          []byte(`{"request":true}`),
		CatalogDigest:        testCatalogDigest,
		CatalogNodeIDs:       []string{"author:openai", "model:gpt-5", "deployment:gpt-5", "route:openai-responses", "provider:openai"},
		E2EETranscriptSHA256: strings.Repeat("b", 64),
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
	if !proof.Verify(publicKey, output.Object.Payload, output.Object.Signature) {
		t.Fatal("stream proof signature did not verify")
	}
	expected := proof.NewStreamHasher(proof.StreamingInput{
		RequestBody:          []byte(`{"request":true}`),
		CatalogDigest:        testCatalogDigest,
		CatalogNodeIDs:       []string{"author:openai", "model:gpt-5", "deployment:gpt-5", "route:openai-responses", "provider:openai"},
		E2EETranscriptSHA256: strings.Repeat("b", 64),
	})
	expected.WriteChunk([]byte(`{"delta":"a"}`))
	expected.WriteChunk([]byte(`{"delta":"b"}`))
	if !reflect.DeepEqual(output.Object.Payload, expected.FinalPayload()) {
		t.Fatalf("stream payload mismatch: got %#v want %#v", output.Object.Payload, expected.FinalPayload())
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
		RequestBody:    []byte(`{"request":true}`),
		ResponseBody:   []byte(`{"response":true}`),
		CatalogDigest:  testCatalogDigest,
		CatalogNodeIDs: []string{"author:openai", "model:gpt-5", "deployment:gpt-5", "route:openai-responses", "provider:openai"},
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
		RequestBody:    []byte(`{"request":true}`),
		ResponseBody:   []byte(`{"response":true}`),
		CatalogDigest:  testCatalogDigest,
		CatalogNodeIDs: []string{"author:openai", "model:gpt-5", "deployment:gpt-5", "route:openai-responses", "provider:openai"},
	})
	if err == nil || !strings.Contains(err.Error(), "report-data hash mismatch") {
		t.Fatalf("expected report-data mismatch failure, got %v", err)
	}
}

type staticQuotes struct {
	snapshot *quote.Snapshot
}

func (s staticQuotes) Current(ctx context.Context) (*quote.Snapshot, error) {
	return s.snapshot, nil
}

func testSnapshot(t *testing.T, publicKey ed25519.PublicKey) *quote.Snapshot {
	t.Helper()
	payload, err := reportdata.NewPayload(reportdata.Payload{
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
