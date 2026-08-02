package catalog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestVerifyEnvelopeAuthenticatesTheMinimalReleaseIdentity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testReleaseManifest(7)
	envelope := signTestManifest(t, manifest, "test", privateKey)
	keys := map[string]ed25519.PublicKey{"test": publicKey}

	verified, err := verifyEnvelope(envelope, keys)
	if err != nil || verified.Sequence != 7 {
		t.Fatalf("verify envelope: manifest=%#v err=%v", verified, err)
	}
	badDigest := manifest
	badDigest.Runtime = "not-a-digest"
	if _, err := verifyEnvelope(signTestManifest(t, badDigest, "test", privateKey), keys); err == nil {
		t.Fatal("invalid runtime digest was accepted")
	}
	envelope[len(envelope)-3] ^= 1
	if _, err := verifyEnvelope(envelope, keys); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
}

func TestUpdaterBuildsCandidateBeforeAtomicActivation(t *testing.T) {
	previous := active.Load()
	defer active.Store(previous)
	fallback := loadTestCatalog(t)
	active.Store(fallback)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testReleaseManifest(fallback.identity.Sequence + 1)
	manifest.Runtime = testDigest(embeddedRuntimeCatalogJSON)
	manifest.Public = testDigest(embeddedPublicCatalogJSON)
	envelope := signTestManifest(t, manifest, "test", privateKey)

	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/catalog/latest.json":
			response.Header().Set("ETag", `"release-1"`)
			_, _ = response.Write(envelope)
		case "/catalog/blobs/sha256/" + strings.TrimPrefix(manifest.Runtime, "sha256:") + ".json":
			_, _ = response.Write(embeddedRuntimeCatalogJSON)
		case "/catalog/blobs/sha256/" + strings.TrimPrefix(manifest.Public, "sha256:") + ".json":
			_, _ = response.Write(embeddedPublicCatalogJSON)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	updater := &Updater{
		client: server.Client(),
		config: UpdaterConfig{
			ReleaseURL: server.URL + "/catalog/latest.json",
		},
		keys: map[string]ed25519.PublicKey{"test": publicKey},
	}
	if err := updater.pollOnce(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	identity, ok := ActiveIdentity()
	if !ok || identity.Sequence != manifest.Sequence || identity.Digest != manifest.Runtime {
		t.Fatalf("active identity = %#v", identity)
	}
	if updater.etags[server.URL+"/catalog/latest.json"] != `"release-1"` {
		t.Fatalf("etags = %#v", updater.etags)
	}
	if err := updater.pollOnce(context.Background()); err != nil {
		t.Fatalf("idempotent poll: %v", err)
	}
	equivocated := manifest
	equivocated.Public = "sha256:" + strings.Repeat("f", 64)
	envelope = signTestManifest(t, equivocated, "test", privateKey)
	if err := updater.pollOnce(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "different public content") {
		t.Fatalf("same-sequence public equivocation was accepted: %v", err)
	}
}

func TestUpdaterSelectsFreshestFullyVerifiedOrigin(t *testing.T) {
	previous := active.Load()
	defer active.Store(previous)
	fallback := loadTestCatalog(t)
	active.Store(fallback)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	primary := testReleaseManifest(fallback.identity.Sequence + 1)
	primary.Runtime = testDigest(embeddedRuntimeCatalogJSON)
	primary.Public = testDigest(embeddedPublicCatalogJSON)
	backup := primary
	backup.Sequence++
	backup.Source.Tag = fmt.Sprintf("catalog-v%d", backup.Sequence)
	envelopes := map[string][]byte{
		"/primary/latest.json": signTestManifest(t, primary, "test", privateKey),
		"/backup/latest.json":  signTestManifest(t, backup, "test", privateKey),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if envelope, ok := envelopes[request.URL.Path]; ok {
			_, _ = response.Write(envelope)
			return
		}
		switch path := request.URL.Path; {
		case strings.HasSuffix(path, strings.TrimPrefix(primary.Runtime, "sha256:")+".json"):
			_, _ = response.Write(embeddedRuntimeCatalogJSON)
		case strings.HasSuffix(path, strings.TrimPrefix(primary.Public, "sha256:")+".json"):
			_, _ = response.Write(embeddedPublicCatalogJSON)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	primaryURL, _ := url.Parse(server.URL + "/primary/latest.json")
	backupURL, _ := url.Parse(server.URL + "/backup/latest.json")
	updater := &Updater{
		client:      server.Client(),
		config:      UpdaterConfig{ReleaseURL: primaryURL.String()},
		etags:       map[string]string{},
		keys:        map[string]ed25519.PublicKey{"test": publicKey},
		releaseURLs: []*url.URL{primaryURL, backupURL},
	}
	if err := updater.pollOnce(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	identity, ok := ActiveIdentity()
	if !ok || identity.Sequence != backup.Sequence {
		t.Fatalf("active identity = %#v", identity)
	}
}

func TestCatalogReleaseURLsAddIndependentOriginOnlyForOfficialURLs(t *testing.T) {
	production, err := catalogReleaseURLs("https://evidence.stogas.ai/catalog/latest.json")
	if err != nil || len(production) != 2 ||
		production[1].Host != "evidence2.stogas.ai" {
		t.Fatalf("production URLs = %#v err=%v", production, err)
	}
	custom, err := catalogReleaseURLs("https://evidence.example/catalog/latest.json")
	if err != nil || len(custom) != 1 {
		t.Fatalf("custom URLs = %#v err=%v", custom, err)
	}
}

func TestUpdaterRejectsRollbackAndNonCanonicalArtifactPaths(t *testing.T) {
	previous := active.Load()
	defer active.Store(previous)
	snap := loadTestCatalog(t)
	snap.identity.Sequence = 10
	active.Store(snap)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testReleaseManifest(9)
	manifest.Runtime = testDigest(embeddedRuntimeCatalogJSON)
	manifest.Public = testDigest(embeddedPublicCatalogJSON)
	envelope := signTestManifest(t, manifest, "test", privateKey)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(envelope)
	}))
	defer server.Close()
	updater := &Updater{
		client: server.Client(),
		config: UpdaterConfig{
			ReleaseURL: server.URL + "/latest.json",
		},
		keys: map[string]ed25519.PublicKey{"test": publicKey},
	}
	if err := updater.pollOnce(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "does not advance") {
		t.Fatalf("rollback was accepted: %v", err)
	}

	if _, err := updater.fetchArtifact(context.Background(), "not-a-digest", runtimeSizeLimit); err == nil {
		t.Fatal("invalid artifact digest was accepted")
	}
}

func TestUpdaterCanRequireAValidInitialRelease(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	updater, err := StartUpdater(context.Background(), UpdaterConfig{
		ReleaseURL:     server.URL + "/latest.json",
		HTTPClient:     server.Client(),
		RequireInitial: true,
	})
	if updater != nil || err == nil || !strings.Contains(err.Error(), "load initial signed catalog") {
		t.Fatalf("required initial release did not fail closed: updater=%#v err=%v", updater, err)
	}
}

func TestUpdaterReadinessToleratesTransientFailuresAndRejectsStaleRefreshes(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	updater := &Updater{
		config: UpdaterConfig{PollInterval: 5 * time.Minute},
		status: UpdateStatus{
			Active:              Identity{Sequence: 8, Digest: "sha256:" + strings.Repeat("a", 64)},
			CheckedAt:           now.Add(-time.Minute),
			ConsecutiveFailures: 1,
			LastError:           "temporary failure",
			LastSuccess:         now.Add(-6 * time.Minute),
		},
	}
	if ready, reason := updater.Ready(now); !ready || reason != "" {
		t.Fatalf("one transient failure should remain ready: ready=%v reason=%q", ready, reason)
	}
	updater.status.ConsecutiveFailures = 3
	updater.status.LastSuccess = now.Add(-16 * time.Minute)
	if ready, reason := updater.Ready(now); ready || reason != "catalog_refresh_failing" {
		t.Fatalf("stale repeated failures should fail readiness: ready=%v reason=%q", ready, reason)
	}
	updater.status.CheckedAt = now.Add(-11 * time.Minute)
	if ready, reason := updater.Ready(now); ready || reason != "catalog_poll_stalled" {
		t.Fatalf("stalled polling should fail readiness: ready=%v reason=%q", ready, reason)
	}
}

func testReleaseManifest(sequence uint64) releaseManifest {
	return releaseManifest{
		Schema:        "stogas.catalog.release.v3",
		Sequence:      sequence,
		CatalogSchema: catalogSchema,
		Runtime:       testDigest(embeddedRuntimeCatalogJSON),
		Public:        testDigest(embeddedPublicCatalogJSON),
		Source: catalogReleaseSource{
			Commit:     strings.Repeat("a", 40),
			Repository: "https://github.com/StogasAI/catalog",
			Tag:        fmt.Sprintf("catalog-v%d", sequence),
			Tree:       strings.Repeat("b", 40),
		},
	}
}

func testDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func signTestManifest(t *testing.T, manifest releaseManifest, keyID string, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope := struct {
		Schema    string          `json:"schema"`
		KeyID     string          `json:"keyId"`
		Manifest  json.RawMessage `json:"manifest"`
		Signature string          `json:"signature"`
	}{
		Schema:   "stogas.catalog.signed.v3",
		KeyID:    keyID,
		Manifest: manifestJSON,
		Signature: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(privateKey, append(append([]byte{}, catalogSignatureDomain...), manifestJSON...)),
		),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
