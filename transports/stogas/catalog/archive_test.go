package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const retiredArchive = `{"graph":{"deployments":{"openai-gpt-retired":{"modelId":"gpt-retired"}},"models":{"gpt-retired":{"name":"GPT Retired"}}},"schema":"stogas.catalog.archive.v1"}`

// archivedRelease is the embedded release with an archive that holds a retired deployment and
// its model. change edits the runtime catalog before it commits to the public one.
func archivedRelease(t *testing.T, archiveData []byte, change func(runtime map[string]any)) (runtimeData, publicData []byte) {
	t.Helper()
	var public, runtime map[string]any
	if err := json.Unmarshal(embeddedPublicCatalogJSON, &public); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archiveData)
	public["archive"] = map[string]any{"sha256": hex.EncodeToString(sum[:]), "size": len(archiveData)}
	publicData, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	publicSum := sha256.Sum256(publicData)
	runtime["publicDigest"] = "sha256:" + hex.EncodeToString(publicSum[:])
	runtime["retired"] = map[string]any{
		"deployments": map[string]any{"openai-gpt-retired": "2026-06-01"},
		"models":      map[string]any{"gpt-retired": "2026-06-01"},
	}
	if change != nil {
		change(runtime)
	}
	runtimeData, err = json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	return runtimeData, publicData
}

func TestApprovedCatalogHoldsTheArchiveItsPublicCatalogNames(t *testing.T) {
	prior := active.Load()
	t.Cleanup(func() { active.Store(prior) })
	archiveData := []byte(retiredArchive)
	runtimeData, publicData := archivedRelease(t, archiveData, nil)
	runtimeHash, publicHash, archiveHash := sha256.Sum256(runtimeData), sha256.Sum256(publicData), sha256.Sum256(archiveData)
	identity := Identity{Sequence: 10, Digest: "sha256:" + hex.EncodeToString(runtimeHash[:])}
	publicDigest := "sha256:" + hex.EncodeToString(publicHash[:])
	archiveDigest := hex.EncodeToString(archiveHash[:])
	if err := InstallApproved(runtimeData, publicData, archiveData, identity, publicDigest); err != nil {
		t.Fatal(err)
	}
	held, ok := ActiveArchive(archiveDigest)
	if payload, listed := PublicCatalogPayload(); !ok || !bytes.Equal(held, archiveData) || !listed ||
		payload.Archive == nil || payload.Archive.SHA256 != archiveDigest {
		t.Fatal("the active catalog does not hold the archive that it names")
	}
	if _, ok := ActiveArchive(strings.Repeat("0", 64)); ok {
		t.Fatal("the active catalog served an archive that it does not name")
	}
	archiveData[0] ^= 1
	if held, _ := ActiveArchive(archiveDigest); held[0] == archiveData[0] {
		t.Fatal("caller retained mutable archive storage")
	}
	archiveData[0] ^= 1

	retained := active.Load()
	changed := append(bytes.Clone(archiveData), ' ')
	for name, archive := range map[string][]byte{"missing": nil, "changed": changed} {
		if err := InstallApproved(runtimeData, publicData, archive, identity, publicDigest); err == nil || active.Load() != retained {
			t.Fatalf("a catalog with a %s archive replaced the current catalog", name)
		}
	}
	unnamedRuntime, unnamedPublic := embeddedRuntimeCatalogJSON, embeddedPublicCatalogJSON
	if _, err := snapshotFromRelease(unnamedRuntime, unnamedPublic, archiveData, Identity{}); err == nil ||
		!strings.Contains(err.Error(), "differs from the public catalog") {
		t.Fatalf("an archive that the public catalog does not name was accepted: %v", err)
	}
}

func TestSnapshotValidationMatchesTheArchiveToTheRetiredNodes(t *testing.T) {
	for name, test := range map[string]struct {
		archive string
		change  func(runtime map[string]any)
		message string
	}{
		"archive schema": {
			archive: strings.Replace(retiredArchive, "archive.v1", "archive.v0", 1),
			message: "does not match the runtime catalog",
		},
		"unlisted archived deployment": {
			archive: strings.Replace(retiredArchive, `"openai-gpt-retired"`, `"openai-gpt-other"`, 1),
			message: "does not match the runtime catalog",
		},
		"retired node still in the graph": {
			archive: retiredArchive,
			change: func(runtime map[string]any) {
				retired := runtime["retired"].(map[string]any)
				retired["deployments"].(map[string]any)["openai-gpt-5.6-sol"] = "2026-06-01"
			},
			message: "retired deployment openai-gpt-5.6-sol is invalid",
		},
		"retirement date": {
			archive: retiredArchive,
			change: func(runtime map[string]any) {
				runtime["retired"].(map[string]any)["models"].(map[string]any)["gpt-retired"] = "2026-06-31"
			},
			message: "retired model gpt-retired is invalid",
		},
	} {
		t.Run(name, func(t *testing.T) {
			runtimeData, publicData := archivedRelease(t, []byte(test.archive), test.change)
			if _, err := snapshotFromRelease(runtimeData, publicData, []byte(test.archive), Identity{}); err == nil ||
				!strings.Contains(err.Error(), test.message) {
				t.Fatalf("the archive was accepted with this change: %v", err)
			}
		})
	}
}

func TestRequestsForRetiredModelsSayWhenTheyRetired(t *testing.T) {
	runtimeData, publicData := archivedRelease(t, []byte(retiredArchive), func(runtime map[string]any) {
		deployments := runtime["graph"].(map[string]any)["deployments"].(map[string]any)
		deployments["chutes-qwen3-32b"].(map[string]any)["retirementDate"] = "2026-01-01"
	})
	snap, err := snapshotFromRelease(runtimeData, publicData, []byte(retiredArchive), Identity{})
	if err != nil {
		t.Fatal(err)
	}
	previous := active.Load()
	t.Cleanup(func() { active.Store(previous) })
	active.Store(snap)
	for _, test := range []struct{ model, code, date string }{
		{model: "openai-gpt-retired", code: "model_retired", date: "2026-06-01"},
		{model: "openai/gpt-retired", code: "model_retired", date: "2026-06-01"},
		{model: "chutes-qwen3-32b", code: "model_retired", date: "2026-01-01"},
		{model: "qwen3-32b", code: "model_retired", date: "2026-01-01"},
		{model: "gpt-never-listed", code: ErrModelUnavailable.Code},
	} {
		_, err := ResolveRequest(RequestInput{
			Body:   []byte(`{"model":"` + test.model + `","messages":[{"role":"user","content":"hello"}]}`),
			Method: "POST",
			Path:   "/v1/chat/completions",
			Policy: policyConfig(1),
		})
		var apiErr APIError
		if !errors.As(err, &apiErr) || apiErr.Code != test.code || !strings.Contains(apiErr.Message, test.date) {
			t.Fatalf("%s: got %v, want %s on %s", test.model, err, test.code, test.date)
		}
	}
}
