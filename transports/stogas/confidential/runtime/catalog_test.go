package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCatalogArtifactRecoveryValidatesBytesAndFixedPaths(t *testing.T) {
	fixture := evidenceFixture(t)
	payload := []byte(`{"catalog":"accepted"}`)
	sum := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	var primaryReads, replicaReads atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryReads.Add(1)
		if r.URL.Path != "/catalog/blobs/sha256/"+digest[7:]+".json" {
			t.Error("wrong artifact path")
		}
		_, _ = w.Write([]byte(`{"catalog":"altered"}`))
	}))
	defer primary.Close()
	replica := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replicaReads.Add(1)
		_, _ = w.Write(payload)
	}))
	defer replica.Close()
	e := fixtureEvidence(t, fixture, primary.URL, replica.URL)
	got, err := e.artifact(t.Context(), digest, int64(len(payload)), 100)
	if err != nil || string(got) != string(payload) || primaryReads.Load() != 1 || replicaReads.Load() != 1 {
		t.Fatalf("replica recovery: %s %v", got, err)
	}
	for _, bad := range []string{"https://other.test", "sha256:../secret", "sha256:" + strings.ToUpper(digest[7:]), digest + "0"} {
		if _, err := e.artifact(t.Context(), bad, int64(len(payload)), 100); err == nil {
			t.Fatalf("accepted digest %q", bad)
		}
	}
	if primaryReads.Load() != 1 || replicaReads.Load() != 1 {
		t.Fatal("invalid digest caused network work")
	}
	if _, err := e.artifact(t.Context(), digest, int64(len(payload)-1), 100); err == nil {
		t.Fatal("accepted oversized decoded artifact")
	}
	if _, err := e.artifact(t.Context(), digest, int64(len(payload)+1), 100); err == nil {
		t.Fatal("accepted artifact shorter than its signed size")
	}
	reads := primaryReads.Load() + replicaReads.Load()
	for _, size := range []int64{0, -1, 101} {
		if _, err := e.artifact(t.Context(), digest, size, 100); err == nil {
			t.Fatal("accepted invalid approved size")
		}
	}
	if reads != primaryReads.Load()+replicaReads.Load() {
		t.Fatal("invalid approved size caused network work")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.artifact(ctx, digest, int64(len(payload)), 100); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestApprovedCatalogSelectionRespectsGatewayCompatibility(t *testing.T) {
	var summary evidenceSummary
	gateway := approvedGateway{ID: "gateway"}
	gateway.Release.Sequence = 4
	summary.Gateways = []approvedGateway{gateway}
	makeCatalog := func(id string, sequence, minimum uint64) approvedCatalog {
		value := approvedCatalog{ID: id}
		value.Release.Sequence = sequence
		value.Release.MinimumGatewaySequence = minimum
		return value
	}
	summary.Catalogs = []approvedCatalog{makeCatalog("newer-incompatible", 10, 5), makeCatalog("older", 2, 2), makeCatalog("compatible", 8, 4)}
	selected, ok := summary.catalog("gateway")
	if !ok || selected.ID != "compatible" {
		t.Fatal("selected incompatible or superseded catalog")
	}
	if _, ok := summary.catalog("unapproved"); ok {
		t.Fatal("selected catalog for unapproved gateway")
	}
	summary.Catalogs = summary.Catalogs[:1]
	if _, ok := summary.catalog("gateway"); ok {
		t.Fatal("selected catalog requiring a newer gateway")
	}
}

func TestRejectedCatalogIsNotDownloadedAgain(t *testing.T) {
	fixture := evidenceFixture(t)
	payload := []byte(`{"catalog":"not installable"}`)
	sum := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	e := fixtureEvidence(t, fixture, server.URL)
	gateway := approvedGateway{ID: "gateway"}
	gateway.Release.Sequence = 4
	approved := approvedCatalog{ID: "catalog"}
	approved.Release.Sequence = 9
	approved.Release.MinimumGatewaySequence = 4
	approved.Release.RuntimeDigest, approved.Release.RuntimeSizeBytes = digest, int64(len(payload))
	approved.Release.PublicDigest, approved.Release.PublicSizeBytes = digest, int64(len(payload))
	e.summary.Gateways, e.summary.Catalogs = []approvedGateway{gateway}, []approvedCatalog{approved}
	for range 2 {
		if err := e.updateCatalog(t.Context(), "gateway"); !errors.Is(err, errCatalogIncompatible) {
			t.Fatalf("installed or misreported an incompatible catalog: %v", err)
		}
	}
	if reads.Load() != 2 {
		t.Fatalf("refused catalog was downloaded again: %d reads", reads.Load())
	}
}

func TestCatalogFailureNamesItsReadinessReason(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	e := fixtureEvidence(t, evidenceFixture(t), server.URL)
	gateway := approvedGateway{ID: "gateway"}
	gateway.Release.Sequence = 4
	e.summary.Gateways = []approvedGateway{gateway}
	if reason := catalogReason(e.updateCatalog(t.Context(), "gateway")); reason != errCatalogUnapproved.Error() {
		t.Fatalf("missing approval reported as %q", reason)
	}
	approved := approvedCatalog{ID: "catalog"}
	approved.Release.Sequence, approved.Release.MinimumGatewaySequence = 9, 4
	digest := "sha256:" + strings.Repeat("0", 64)
	approved.Release.RuntimeDigest, approved.Release.RuntimeSizeBytes = digest, 1
	approved.Release.PublicDigest, approved.Release.PublicSizeBytes = digest, 1
	e.summary.Catalogs = []approvedCatalog{approved}
	if reason := catalogReason(e.updateCatalog(t.Context(), "gateway")); reason != errCatalogUnavailable.Error() {
		t.Fatalf("failed download reported as %q", reason)
	}
	if reason := catalogReason(nil); reason != "approved compatible catalog is not installed" {
		t.Fatalf("pending catalog reported as %q", reason)
	}
}
