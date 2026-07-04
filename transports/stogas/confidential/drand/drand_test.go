package drand

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

func testBeacon(round uint64) reportdata.Drand {
	return reportdata.Drand{
		Network:    reportdata.DrandNetworkQuicknet,
		ChainHash:  reportdata.QuicknetChainHash,
		Round:      round,
		Randomness: strings.Repeat("a", 64),
		Signature:  strings.Repeat("b", 96),
	}
}

func TestHTTPFetcherParsesQuicknetV2AndDerivesRandomness(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/beacons/quicknet/rounds/latest" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Fatalf("missing json accept header")
		}
		_, _ = w.Write([]byte(`{"round":42,"signature":"01020304"}`))
	}))
	defer server.Close()

	beacon, err := NewHTTPFetcher(server.Client(), server.URL+"/v2/beacons/quicknet/rounds/latest").Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectedRandomness, err := RandomnessFromSignature("01020304")
	if err != nil {
		t.Fatal(err)
	}
	if beacon.Network != reportdata.DrandNetworkQuicknet {
		t.Fatalf("unexpected network %q", beacon.Network)
	}
	if beacon.ChainHash != reportdata.QuicknetChainHash {
		t.Fatalf("unexpected chain hash %q", beacon.ChainHash)
	}
	if beacon.Round != 42 {
		t.Fatalf("unexpected round %d", beacon.Round)
	}
	if beacon.Randomness != expectedRandomness {
		t.Fatalf("unexpected derived randomness %q", beacon.Randomness)
	}
	if beacon.Signature != "01020304" {
		t.Fatalf("unexpected signature %q", beacon.Signature)
	}
}

func TestHTTPFetcherRejectsBadStatusAndMalformedSignature(t *testing.T) {
	badStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer badStatus.Close()
	if _, err := NewHTTPFetcher(badStatus.Client(), badStatus.URL).Fetch(context.Background()); err == nil {
		t.Fatal("expected bad status error")
	}

	malformed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"round":42,"signature":"not hex"}`))
	}))
	defer malformed.Close()
	if _, err := NewHTTPFetcher(malformed.Client(), malformed.URL).Fetch(context.Background()); err == nil {
		t.Fatal("expected malformed signature error")
	}
}

func TestSourceCurrentRefreshesOnDemandAndVerifiesSignature(t *testing.T) {
	var fetches atomic.Int32
	var verifies atomic.Int32
	source, err := NewSource(
		FetcherFunc(func(ctx context.Context) (reportdata.Drand, error) {
			fetches.Add(1)
			return testBeacon(7), nil
		}),
		SignatureVerifierFunc(func(ctx context.Context, beacon reportdata.Drand) error {
			verifies.Add(1)
			if beacon.Round != 7 {
				t.Fatalf("unexpected verified round %d", beacon.Round)
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	beacon, err := source.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if beacon.Round != 7 {
		t.Fatalf("unexpected round %d", beacon.Round)
	}
	if fetches.Load() != 1 || verifies.Load() != 1 {
		t.Fatalf("expected one fetch/verify, got %d/%d", fetches.Load(), verifies.Load())
	}
	again, err := source.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if again.Round != 7 {
		t.Fatalf("unexpected cached round %d", again.Round)
	}
	if fetches.Load() != 1 || verifies.Load() != 1 {
		t.Fatalf("expected cached current read, got %d/%d", fetches.Load(), verifies.Load())
	}
}

func TestSourceRejectsInvalidBeaconBeforeSignatureVerification(t *testing.T) {
	var verifies atomic.Int32
	source, err := NewSource(
		FetcherFunc(func(ctx context.Context) (reportdata.Drand, error) {
			beacon := testBeacon(1)
			beacon.ChainHash = strings.Repeat("0", 64)
			return beacon, nil
		}),
		SignatureVerifierFunc(func(ctx context.Context, beacon reportdata.Drand) error {
			verifies.Add(1)
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Refresh(context.Background()); err == nil {
		t.Fatal("expected chain hash validation error")
	}
	if verifies.Load() != 0 {
		t.Fatalf("signature verifier called before validation")
	}
}

func TestSourceRejectsSignatureFailure(t *testing.T) {
	source, err := NewSource(
		FetcherFunc(func(ctx context.Context) (reportdata.Drand, error) {
			return testBeacon(1), nil
		}),
		SignatureVerifierFunc(func(ctx context.Context, beacon reportdata.Drand) error {
			return errors.New("bad bls")
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Refresh(context.Background()); err == nil {
		t.Fatal("expected signature verification error")
	}
	if source.LastError() == nil {
		t.Fatal("expected last error")
	}
}

func TestSourceRejectsOlderRoundAndKeepsLastValidBeacon(t *testing.T) {
	var nextRound atomic.Uint64
	nextRound.Store(10)
	source, err := NewSource(
		FetcherFunc(func(ctx context.Context) (reportdata.Drand, error) {
			return testBeacon(nextRound.Load()), nil
		}),
		SignatureVerifierFunc(func(ctx context.Context, beacon reportdata.Drand) error {
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	nextRound.Store(9)
	if err := source.Refresh(context.Background()); err == nil {
		t.Fatal("expected replay rejection")
	}
	current, err := source.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current.Round != 10 {
		t.Fatalf("last valid beacon was not preserved: %d", current.Round)
	}
}

func TestSourceKeepsLastValidBeaconWhenFetchFails(t *testing.T) {
	fail := atomic.Bool{}
	source, err := NewSource(
		FetcherFunc(func(ctx context.Context) (reportdata.Drand, error) {
			if fail.Load() {
				return reportdata.Drand{}, errors.New("network unavailable")
			}
			return testBeacon(11), nil
		}),
		SignatureVerifierFunc(func(ctx context.Context, beacon reportdata.Drand) error {
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := source.Refresh(context.Background()); err == nil {
		t.Fatal("expected fetch failure")
	}
	current, err := source.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current.Round != 11 {
		t.Fatalf("last valid beacon was not preserved: %d", current.Round)
	}
}

func TestValidateRejectsWrongNetworkAndMissingRound(t *testing.T) {
	wrongNetwork := testBeacon(1)
	wrongNetwork.Network = "default"
	if err := Validate(wrongNetwork); err == nil {
		t.Fatal("expected network validation error")
	}
	missingRound := testBeacon(0)
	if err := Validate(missingRound); err == nil {
		t.Fatal("expected missing round validation error")
	}
}

func TestQuicknetVerifierAcceptsPinnedBeaconVector(t *testing.T) {
	const signature = "b79a809ed952e5b7def6f8494b8a909728b80f8d17d6d47f05ab1d43e1cc5391d9ab9ce77b871dc69bc4523db77d2f5c"
	randomness, err := RandomnessFromSignature(signature)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewQuicknetVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if QuicknetSchemeID != "bls-unchained-g1-rfc9380" {
		t.Fatalf("unexpected quicknet scheme id %q", QuicknetSchemeID)
	}
	if err := verifier.Verify(context.Background(), reportdata.Drand{
		Network:    reportdata.DrandNetworkQuicknet,
		ChainHash:  reportdata.QuicknetChainHash,
		Round:      30051238,
		Randomness: randomness,
		Signature:  signature,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQuicknetVerifierRejectsTamperedBeacon(t *testing.T) {
	const signature = "b79a809ed952e5b7def6f8494b8a909728b80f8d17d6d47f05ab1d43e1cc5391d9ab9ce77b871dc69bc4523db77d2f5c"
	randomness, err := RandomnessFromSignature(signature)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewQuicknetVerifier()
	if err != nil {
		t.Fatal(err)
	}
	beacon := reportdata.Drand{
		Network:    reportdata.DrandNetworkQuicknet,
		ChainHash:  reportdata.QuicknetChainHash,
		Round:      30051238,
		Randomness: randomness,
		Signature:  signature,
	}
	wrongRound := beacon
	wrongRound.Round++
	if err := verifier.Verify(context.Background(), wrongRound); err == nil {
		t.Fatal("expected wrong round to fail")
	}
	wrongRandomness := beacon
	wrongRandomness.Randomness = strings.Repeat("0", 64)
	if err := verifier.Verify(context.Background(), wrongRandomness); err == nil {
		t.Fatal("expected mismatched randomness to fail")
	}
	wrongChain := beacon
	wrongChain.ChainHash = strings.Repeat("0", 64)
	if err := verifier.Verify(context.Background(), wrongChain); err == nil {
		t.Fatal("expected wrong chain hash to fail")
	}
}
