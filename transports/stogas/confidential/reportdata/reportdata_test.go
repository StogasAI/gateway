package reportdata

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testPayload() Payload {
	return Payload{
		CatalogHash:        strings.Repeat("b", 64),
		TLSSPKISHA256:      strings.Repeat("c", 64),
		ActiveCertSHA256:   strings.Repeat("d", 64),
		AcceptedCertSHA256: []string{strings.Repeat("e", 64), strings.Repeat("d", 64)},
		HPKEPublicKey:      base64.RawURLEncoding.EncodeToString([]byte("hpke-public-key")),
		Ed25519PublicKey:   base64.RawURLEncoding.EncodeToString([]byte("ed25519-public-key")),
		Drand: Drand{
			Round:      42,
			Randomness: strings.Repeat("f", 64),
			Signature:  strings.Repeat("1", 96),
		},
	}
}

func TestCanonicalJSONIsDeterministicAndSortsAcceptedCertHashes(t *testing.T) {
	first, err := CanonicalJSON(testPayload())
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload()
	payload.AcceptedCertSHA256 = []string{strings.Repeat("d", 64), strings.Repeat("e", 64)}
	second, err := CanonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("canonical payload changed with input order\nfirst:  %s\nsecond: %s", first, second)
	}
	if !strings.Contains(string(first), `"network":"quicknet"`) {
		t.Fatalf("quicknet default missing from canonical payload: %s", first)
	}
	if !strings.Contains(string(first), QuicknetChainHash) {
		t.Fatalf("quicknet chain hash missing from canonical payload: %s", first)
	}
}

func TestHashHexIsSHA512ReportData(t *testing.T) {
	hash, err := HashHex(testPayload())
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 128 {
		t.Fatalf("expected 64-byte sha512 hex, got %d chars", len(hash))
	}
	repeat, err := HashHex(testPayload())
	if err != nil {
		t.Fatal(err)
	}
	if hash != repeat {
		t.Fatal("hash is not deterministic")
	}
}

func TestValidateRejectsMissingActiveCertInAcceptedSet(t *testing.T) {
	payload := testPayload()
	payload.AcceptedCertSHA256 = []string{strings.Repeat("e", 64)}
	if _, err := NewPayload(payload); err == nil {
		t.Fatal("expected active cert hash membership validation error")
	}
}

func TestValidateRejectsWrongDrandNetwork(t *testing.T) {
	payload := testPayload()
	payload.Drand.Network = "default"
	if _, err := NewPayload(payload); err == nil {
		t.Fatal("expected drand network validation error")
	}
}

func TestValidateRejectsMalformedPublicKeys(t *testing.T) {
	payload := testPayload()
	payload.HPKEPublicKey = "***"
	if _, err := NewPayload(payload); err == nil {
		t.Fatal("expected hpke public key validation error")
	}
}
