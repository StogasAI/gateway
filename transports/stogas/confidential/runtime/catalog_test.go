package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
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
	gateway.Release.MinimumCatalogSequence = 2
	summary.Gateways = []approvedGateway{gateway}
	makeCatalog := func(id string, sequence, minimum uint64) approvedCatalog {
		value := approvedCatalog{ID: id}
		value.Release.Sequence = sequence
		value.Release.MinimumGatewaySequence = minimum
		return value
	}
	// The verifier summary orders catalogs by increasing sequence.
	summary.Catalogs = []approvedCatalog{makeCatalog("older", 2, 2), makeCatalog("compatible", 8, 4), makeCatalog("newer-incompatible", 10, 5)}
	var selected []string
	for _, approved := range summary.catalogs("gateway") {
		selected = append(selected, approved.ID)
	}
	if !slices.Equal(selected, []string{"compatible", "older"}) {
		t.Fatalf("selected %v, want compatible catalogs newest first", selected)
	}
	if summary.catalogs("unapproved") != nil {
		t.Fatal("selected catalog for unapproved gateway")
	}
	summary.Gateways[0].Release.MinimumCatalogSequence = 3
	if catalogs := summary.catalogs("gateway"); len(catalogs) != 1 || catalogs[0].ID != "compatible" {
		t.Fatalf("selected %v, want only catalogs the gateway reads", catalogs)
	}
	summary.Catalogs = summary.Catalogs[2:]
	if len(summary.catalogs("gateway")) != 0 {
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
	approved.Release.RootDigest, approved.Release.RootSizeBytes = digest, int64(len(payload))
	e.summary.Gateways, e.summary.Catalogs = []approvedGateway{gateway}, []approvedCatalog{approved}
	for range 2 {
		if err := e.updateCatalog(t.Context(), "gateway"); !errors.Is(err, errCatalogIncompatible) {
			t.Fatalf("installed or misreported an incompatible catalog: %v", err)
		}
	}
	if reads.Load() != 1 {
		t.Fatalf("refused catalog was downloaded again: %d reads", reads.Load())
	}
}

func TestRefusedCatalogLeavesOlderApprovedCatalogInUse(t *testing.T) {
	root, parts := fallbackCatalog(t)
	artifacts := maps.Clone(parts)
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		data, ok := artifacts[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/catalog/blobs/sha256/"), ".json")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	e := fixtureEvidence(t, evidenceFixture(t), server.URL)
	gateway := approvedGateway{ID: "gateway"}
	gateway.Release.Sequence = 4
	makeCatalog := func(sequence uint64, root []byte, served bool) approvedCatalog {
		approved := approvedCatalog{ID: "catalog-" + strconv.FormatUint(sequence, 10)}
		approved.Release.Sequence, approved.Release.MinimumGatewaySequence = sequence, 4
		sum := sha256.Sum256(root)
		if served {
			artifacts[hex.EncodeToString(sum[:])] = root
		}
		approved.Release.RootDigest, approved.Release.RootSizeBytes = "sha256:"+hex.EncodeToString(sum[:]), int64(len(root))
		return approved
	}
	// The active catalog is process state; no other test approves these bytes as catalog 7.
	older, newer := makeCatalog(7, root, true), makeCatalog(9, []byte(`{"catalog":"not installable"}`), true)
	e.summary.Gateways, e.summary.Catalogs = []approvedGateway{gateway}, []approvedCatalog{older, newer}
	if err := e.updateCatalog(t.Context(), "gateway"); err != nil || !older.active() || !e.summary.activeCatalogApproved("gateway") {
		t.Fatalf("older approved catalog was not installed after a refusal: %v", err)
	}
	if refusedSequences := e.refusedCatalogSequences(); !slices.Equal(refusedSequences, []uint64{9}) {
		t.Fatalf("refused catalogs = %v", refusedSequences)
	}
	reads.Store(0)
	if err := e.updateCatalog(t.Context(), "gateway"); err != nil || reads.Load() != 0 {
		t.Fatalf("refused catalog was downloaded again: %d reads, %v", reads.Load(), err)
	}
	// A failed download says nothing about compatibility, so it does not fall back,
	// and the installed approved catalog keeps serving.
	unavailable := makeCatalog(10, []byte(`{"catalog":"missing"}`), false)
	e.summary.Catalogs = []approvedCatalog{older, newer, unavailable}
	if err := e.updateCatalog(t.Context(), "gateway"); !errors.Is(err, errCatalogUnavailable) || !older.active() || !e.summary.activeCatalogApproved("gateway") {
		t.Fatalf("download failure replaced or withdrew the installed catalog: %v", err)
	}
	// Withdrawal forgets a refusal, so a later approval of the same bytes is tried again.
	e.summary.Catalogs = []approvedCatalog{older}
	if err := e.updateCatalog(t.Context(), "gateway"); err != nil || len(e.refusedCatalogSequences()) != 0 {
		t.Fatalf("withdrawn catalog stayed refused: %v", err)
	}
}

// fallbackCatalog is the embedded catalog: its root and every part that it names, by SHA-256 in
// hex.
func fallbackCatalog(t *testing.T) (root []byte, parts map[string][]byte) {
	t.Helper()
	read := func(path string) []byte {
		data, err := os.ReadFile("../../catalog/fallback/" + path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	root = read("catalog.json")
	// No record has retired at the zero time, so every part is in effect.
	files, err := catalog.PartsInEffect(root, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	parts = make(map[string][]byte, len(files))
	for _, file := range files {
		parts[file.SHA256] = read("catalog.parts/" + file.SHA256 + ".json")
	}
	return root, parts
}

// changedCatalog is the embedded catalog with an author renamed in its root and a space after
// each part at the given positions, which the root names by their new digests and sizes. It
// returns the root, every part, and the parts that changed.
func changedCatalog(t *testing.T, author string, positions ...int) (root []byte, parts map[string][]byte, changed []string) {
	t.Helper()
	fallback, parts := fallbackCatalog(t)
	var listed map[string]any
	if err := json.Unmarshal(fallback, &listed); err != nil {
		t.Fatal(err)
	}
	listed["summaries"].(map[string]any)["authors"].(map[string]any)["anthropic"].(map[string]any)["name"] = author
	for _, position := range positions {
		file := listed["parts"].([]any)[position].(map[string]any)
		data := append(bytes.Clone(parts[file["sha256"].(string)]), ' ')
		delete(parts, file["sha256"].(string))
		sum := sha256.Sum256(data)
		file["sha256"], file["size"] = hex.EncodeToString(sum[:]), len(data)
		parts[file["sha256"].(string)] = data
		changed = append(changed, file["sha256"].(string))
	}
	root, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	return root, parts, changed
}

func TestNewCatalogDownloadsOnlyThePartsThatChanged(t *testing.T) {
	hexDigest := func(data []byte) string {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	artifacts := map[string][]byte{}
	var mu sync.Mutex
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/catalog/blobs/sha256/"), ".json")
		mu.Lock()
		defer mu.Unlock()
		requested = append(requested, name)
		_, _ = w.Write(artifacts[name])
	}))
	defer server.Close()
	e := fixtureEvidence(t, evidenceFixture(t), server.URL)
	gateway := approvedGateway{ID: "gateway"}
	gateway.Release.Sequence = 4
	e.summary.Gateways = []approvedGateway{gateway}
	// The active catalog is process state; no other test approves these bytes as catalogs 20 to 22.
	root, parts := fallbackCatalog(t)
	if err := catalog.InstallApproved(root, parts, catalog.Identity{Sequence: 20, Digest: "sha256:" + hexDigest(root)}, e.now()); err != nil {
		t.Fatal(err)
	}
	for _, release := range []struct {
		sequence  uint64
		author    string
		positions []int
	}{
		{sequence: 21, author: "First"},
		{sequence: 22, author: "Second", positions: []int{0}},
	} {
		root, parts, changed := changedCatalog(t, release.author, release.positions...)
		artifacts[hexDigest(root)] = root
		maps.Copy(artifacts, parts)
		approved := approvedCatalog{ID: "catalog-" + strconv.FormatUint(release.sequence, 10)}
		approved.Release.Sequence, approved.Release.MinimumGatewaySequence = release.sequence, 4
		approved.Release.RootDigest, approved.Release.RootSizeBytes = "sha256:"+hexDigest(root), int64(len(root))
		e.summary.Catalogs = []approvedCatalog{approved}
		requested = nil
		if err := e.updateCatalog(t.Context(), "gateway"); err != nil || !approved.active() {
			t.Fatalf("catalog %d was not installed: %v", release.sequence, err)
		}
		// The release shares every other part with the one before it.
		if want := append([]string{hexDigest(root)}, changed...); !slices.Equal(requested, want) {
			t.Fatalf("catalog %d downloaded %v, want %v", release.sequence, requested, want)
		}
		for name, data := range parts {
			if held, ok := catalog.ActiveCatalogPart(name); !ok || !bytes.Equal(held, data) {
				t.Fatalf("catalog %d does not hold its part %s", release.sequence, name)
			}
		}
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
	approved.Release.RootDigest, approved.Release.RootSizeBytes = digest, 1
	e.summary.Catalogs = []approvedCatalog{approved}
	if reason := catalogReason(e.updateCatalog(t.Context(), "gateway")); reason != errCatalogUnavailable.Error() {
		t.Fatalf("failed download reported as %q", reason)
	}
	if reason := catalogReason(nil); reason != "approved compatible catalog is not installed" {
		t.Fatalf("pending catalog reported as %q", reason)
	}
}
