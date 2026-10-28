package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"
)

// archivedRelease is the embedded release with an archive whose part holds a retired deployment
// and its model, which has an alias. change edits the archive's index and part and the runtime
// catalog before the root names the files and the runtime catalog commits to the root.
func archivedRelease(t *testing.T, change func(index, part, runtime map[string]any)) (runtimeData, publicData []byte, parts map[string][]byte) {
	t.Helper()
	decode := func(data []byte) map[string]any {
		var value map[string]any
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	encode := func(value map[string]any) []byte {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	public, runtime := decode(embeddedPublicCatalogJSON), decode(embeddedRuntimeCatalogJSON)
	index := decode([]byte(`{"deployments":{"openai-gpt-retired":{"modelId":"gpt-retired","part":0,"retirementDate":"2026-06-01","routeIds":[]}},"models":{"gpt-retired":{"aliases":["gpt.retired"],"part":0,"retirementDate":"2026-06-01"}},"schema":"stogas.catalog.archive.index.v1"}`))
	part := decode([]byte(`{"deployments":{"openai-gpt-retired":{"modelId":"gpt-retired"}},"models":{"gpt-retired":{"name":"GPT Retired"}},"schema":"stogas.catalog.archive.part.v1"}`))
	runtime["retired"] = map[string]any{
		"deployments": map[string]any{"openai-gpt-retired": "2026-06-01"},
		"models":      map[string]any{"gpt-retired": "2026-06-01", "gpt.retired": "2026-06-01"},
	}
	if change != nil {
		change(index, part, runtime)
	}
	parts = embeddedParts(t)
	file := func(value map[string]any) map[string]any {
		data := encode(value)
		sum := sha256.Sum256(data)
		parts[hex.EncodeToString(sum[:])] = data
		return map[string]any{"sha256": hex.EncodeToString(sum[:]), "size": len(data)}
	}
	public["archive"] = map[string]any{"index": file(index), "parts": []any{file(part)}}
	publicData = encode(public)
	publicSum := sha256.Sum256(publicData)
	runtime["publicDigest"] = "sha256:" + hex.EncodeToString(publicSum[:])
	return encode(runtime), publicData, parts
}

func TestApprovedCatalogHoldsEveryFileThatItsRootNames(t *testing.T) {
	prior := active.Load()
	t.Cleanup(func() { active.Store(prior) })
	runtimeData, publicData, parts := archivedRelease(t, nil)
	runtimeHash, publicHash := sha256.Sum256(runtimeData), sha256.Sum256(publicData)
	identity := Identity{Sequence: 10, Digest: "sha256:" + hex.EncodeToString(runtimeHash[:])}
	publicDigest := "sha256:" + hex.EncodeToString(publicHash[:])
	if err := InstallApproved(runtimeData, publicData, maps.Clone(parts), identity, publicDigest); err != nil {
		t.Fatal(err)
	}
	for name, data := range parts {
		if held, ok := ActivePublicPart(name); !ok || !bytes.Equal(held, data) {
			t.Fatalf("the active catalog does not hold %s, which its root names", name)
		}
	}
	unnamed := strings.Repeat("0", 64)
	if _, ok := ActivePublicPart(unnamed); ok {
		t.Fatal("the active catalog served a file that its root does not name")
	}

	retained := active.Load()
	files, err := PublicCatalogFiles(publicData)
	if err != nil {
		t.Fatal(err)
	}
	for problem, change := range map[string]func(parts map[string][]byte){
		"a missing part":          func(parts map[string][]byte) { delete(parts, files[0].SHA256) },
		"a missing archive part":  func(parts map[string][]byte) { delete(parts, files[len(files)-1].SHA256) },
		"a changed part":          func(parts map[string][]byte) { parts[files[0].SHA256] = bytes.ToUpper(parts[files[0].SHA256]) },
		"a file it does not name": func(parts map[string][]byte) { parts[unnamed] = []byte("{}") },
	} {
		changed := maps.Clone(parts)
		change(changed)
		if err := InstallApproved(runtimeData, publicData, changed, identity, publicDigest); err == nil ||
			!strings.Contains(err.Error(), "parts differ from the root") || active.Load() != retained {
			t.Fatalf("a catalog with %s replaced the current catalog: %v", problem, err)
		}
	}
}

func TestSnapshotValidationMatchesTheArchiveToTheRetiredNodes(t *testing.T) {
	retired := func(runtime map[string]any, kind string) map[string]any {
		return runtime["retired"].(map[string]any)[kind].(map[string]any)
	}
	for name, test := range map[string]struct {
		change  func(index, part, runtime map[string]any)
		message string
	}{
		"index schema": {
			change:  func(index, _, _ map[string]any) { index["schema"] = "stogas.catalog.archive.index.v0" },
			message: "does not match the runtime catalog",
		},
		"archive part schema": {
			change:  func(_, part, _ map[string]any) { part["schema"] = "stogas.catalog.archive.part.v0" },
			message: "archive part schema",
		},
		"unlisted archived deployment": {
			change: func(_, _, runtime map[string]any) {
				delete(retired(runtime, "deployments"), "openai-gpt-retired")
				retired(runtime, "deployments")["openai-gpt-other"] = "2026-06-01"
			},
			message: "does not match the runtime catalog",
		},
		"unlisted alias": {
			change:  func(_, _, runtime map[string]any) { delete(retired(runtime, "models"), "gpt.retired") },
			message: "does not match the runtime catalog",
		},
		"different retirement date": {
			change: func(_, _, runtime map[string]any) {
				retired(runtime, "deployments")["openai-gpt-retired"] = "2026-05-31"
			},
			message: "does not match the runtime catalog",
		},
		"record in another part": {
			change: func(index, _, _ map[string]any) {
				index["deployments"].(map[string]any)["openai-gpt-retired"].(map[string]any)["part"] = 1
			},
			message: "places elsewhere",
		},
		"archive part without a record": {
			change:  func(_, part, _ map[string]any) { delete(part["models"].(map[string]any), "gpt-retired") },
			message: "omit a record",
		},
		"retired node still in the graph": {
			change: func(_, _, runtime map[string]any) {
				retired(runtime, "deployments")["openai-gpt-5.6-sol"] = "2026-06-01"
			},
			message: "retired deployment openai-gpt-5.6-sol is invalid",
		},
		"invalid retirement date": {
			change:  func(_, _, runtime map[string]any) { retired(runtime, "models")["gpt-retired"] = "2026-06-31" },
			message: "retired model gpt-retired is invalid",
		},
	} {
		t.Run(name, func(t *testing.T) {
			runtimeData, publicData, parts := archivedRelease(t, test.change)
			if _, err := snapshotFromRelease(runtimeData, publicData, parts, Identity{}); err == nil ||
				!strings.Contains(err.Error(), test.message) {
				t.Fatalf("the archive was accepted with this change: %v", err)
			}
		})
	}

	// A root without an archive cannot pair with a runtime catalog that lists retired records.
	var runtime map[string]any
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &runtime); err != nil {
		t.Fatal(err)
	}
	runtime["retired"] = map[string]any{"deployments": map[string]any{"openai-gpt-retired": "2026-06-01"}, "models": map[string]any{}}
	runtimeData, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFromRelease(runtimeData, embeddedPublicCatalogJSON, embeddedParts(t), Identity{}); err == nil ||
		!strings.Contains(err.Error(), "does not match the runtime catalog") {
		t.Fatalf("retired records without an archive were accepted: %v", err)
	}
}

func TestRequestsForRetiredModelsSayWhenTheyRetired(t *testing.T) {
	runtimeData, publicData, parts := archivedRelease(t, func(_, _, runtime map[string]any) {
		deployments := runtime["graph"].(map[string]any)["deployments"].(map[string]any)
		deployments["chutes-qwen3-32b"].(map[string]any)["retirementDate"] = "2026-01-01"
	})
	snap, err := snapshotFromRelease(runtimeData, publicData, parts, Identity{})
	if err != nil {
		t.Fatal(err)
	}
	previous := active.Load()
	t.Cleanup(func() { active.Store(previous) })
	active.Store(snap)
	for _, test := range []struct{ model, code, date string }{
		{model: "openai-gpt-retired", code: "model_retired", date: "2026-06-01"},
		{model: "openai/gpt-retired", code: "model_retired", date: "2026-06-01"},
		{model: "openai/gpt.retired", code: "model_retired", date: "2026-06-01"},
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
