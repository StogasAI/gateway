package proofhttp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/quote"
	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

func TestBuildReturnsHeadersAndVerifiableSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("a", 128)))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{Quotes: staticQuotes{snapshot: testSnapshot(t, publicKey)}, Signer: privateKey}
	output, err := service.Build(context.Background(), Input{
		CatalogHash:          strings.Repeat("1", 64),
		CatalogNodeIDs:       []string{"stogas_endpoint:responses", "provider:openai", "deployment:gpt-5"},
		ProcessedRequestJSON: []byte(`{"request":true}`),
		ResponseJSON:         []byte(`{"response":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if output.Headers[HeaderQuote] != base64.RawURLEncoding.EncodeToString([]byte("quote")) {
		t.Fatalf("quote header mismatch: %#v", output.Headers)
	}
	if output.Headers[HeaderResolvedCatalogNodeID] != "stogas_endpoint:responses,provider:openai,deployment:gpt-5" {
		t.Fatalf("catalog node header mismatch: %#v", output.Headers)
	}
	reportDataBytes, err := base64.RawURLEncoding.DecodeString(output.Headers[HeaderReportData])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reportDataBytes), `"schema":"stogas.node-report.v1"`) {
		t.Fatalf("report data header did not contain canonical report data: %s", reportDataBytes)
	}
	if !proof.Verify(publicKey, output.Headers[HeaderProcessedHash], output.Headers[HeaderProcessedSignature]) {
		t.Fatal("processed proof signature did not verify")
	}
	if output.Object.ProcessedHash != output.Headers[HeaderProcessedHash] || output.Object.Quote != output.Headers[HeaderQuote] {
		t.Fatalf("object and headers diverged: %#v %#v", output.Object, output.Headers)
	}
}

func TestFinishStreamSignsRunningChunkHash(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("b", 128)))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{Quotes: staticQuotes{snapshot: testSnapshot(t, publicKey)}, Signer: privateKey}
	stream, err := NewStream(Input{
		CatalogHash:          strings.Repeat("1", 64),
		CatalogNodeIDs:       []string{"node-a"},
		ProcessedRequestJSON: []byte(`{"request":true}`),
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
	if !proof.Verify(publicKey, output.Object.ProcessedHash, output.Object.ProcessedSignature) {
		t.Fatal("stream proof signature did not verify")
	}
	expected := proof.NewStreamHasher(proof.StreamingInput{
		ProcessedRequestJSON: []byte(`{"request":true}`),
		CatalogHash:          strings.Repeat("1", 64),
		CatalogNodeIDs:       []string{"node-a"},
	})
	expected.WriteChunk([]byte(`{"delta":"a"}`))
	expected.WriteChunk([]byte(`{"delta":"b"}`))
	expectedHash, err := expected.FinalHash()
	if err != nil {
		t.Fatal(err)
	}
	if output.Object.ProcessedHash != expectedHash {
		t.Fatalf("stream hash mismatch: got %s want %s", output.Object.ProcessedHash, expectedHash)
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
		CatalogHash:          strings.Repeat("1", 64),
		CatalogNodeIDs:       []string{"node-a"},
		ProcessedRequestJSON: []byte(`{"request":true}`),
		ResponseJSON:         []byte(`{"response":true}`),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match report-data ed25519 key") {
		t.Fatalf("expected mismatched signer failure, got %v", err)
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
		ReleaseMeasurement: strings.Repeat("a", 64),
		Region:             "global",
		CatalogHash:        strings.Repeat("b", 64),
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
