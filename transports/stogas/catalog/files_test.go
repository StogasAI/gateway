package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// embeddedFiles is the fallback's root and every part that it names, by SHA-256 in hex.
func embeddedFiles(tb testing.TB) ([]byte, map[string][]byte) {
	tb.Helper()
	root, err := fallbackFiles.ReadFile("fallback/catalog.json")
	if err != nil {
		tb.Fatal(err)
	}
	files, err := partFiles(root)
	if err != nil {
		tb.Fatal(err)
	}
	parts := make(map[string][]byte, len(files))
	for _, file := range files {
		if parts[file.SHA256], err = fallbackFiles.ReadFile("fallback/catalog.parts/" + file.SHA256 + ".json"); err != nil {
			tb.Fatal(err)
		}
	}
	return root, parts
}

// embeddedCatalogJSON is the fallback as the gateway reads it, with every record, as one
// document: the graph, each dated state's changes and the selectors that have retired. Tests
// change it and read it with snapshotFromCatalogBytes.
var embeddedCatalogJSON = func() []byte {
	root, err := fallbackFiles.ReadFile("fallback/catalog.json")
	if err != nil {
		panic(err)
	}
	files, err := partFiles(root)
	if err != nil {
		panic(err)
	}
	parts := make(map[string][]byte, len(files))
	for _, file := range files {
		if parts[file.SHA256], err = fallbackFiles.ReadFile("fallback/catalog.parts/" + file.SHA256 + ".json"); err != nil {
			panic(err)
		}
	}
	compiled, err := assemble(root, files, parts, time.Time{})
	if err != nil {
		panic(err)
	}
	data, err := json.Marshal(compiled)
	if err != nil {
		panic(err)
	}
	return data
}()

func snapshotFromCatalogBytes(data []byte) (*snapshot, error) {
	var compiled compiledCatalog
	if err := decodeStrict(data, &compiled, sharedJSON[Pricing]()); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	return snapshotFromCompiled(compiled)
}

// testRelease is a release's root and parts as JSON values. A test changes them and then writes
// them, which names each part in the root by its new digest and size.
type testRelease struct {
	root  map[string]any
	parts []map[string]any
}

func embeddedRelease(tb testing.TB) testRelease {
	tb.Helper()
	root, parts := embeddedFiles(tb)
	var release testRelease
	if err := json.Unmarshal(root, &release.root); err != nil {
		tb.Fatal(err)
	}
	for _, file := range release.root["parts"].([]any) {
		var part map[string]any
		if err := json.Unmarshal(parts[file.(map[string]any)["sha256"].(string)], &part); err != nil {
			tb.Fatal(err)
		}
		release.parts = append(release.parts, part)
	}
	return release
}

func (r testRelease) summary(kind, id string) map[string]any {
	return r.root["summaries"].(map[string]any)[kind].(map[string]any)[id].(map[string]any)
}

// record is the record that the summary of a model, route or deployment places in a part.
func (r testRelease) record(kind, id string) map[string]any {
	part := r.parts[int(r.summary(kind, id)["part"].(float64))]
	return part["graph"].(map[string]any)[kind].(map[string]any)[id].(map[string]any)
}

func (r testRelease) files(tb testing.TB) ([]byte, map[string][]byte) {
	tb.Helper()
	parts := make(map[string][]byte, len(r.parts))
	for index, part := range r.parts {
		data, err := json.Marshal(part)
		if err != nil {
			tb.Fatal(err)
		}
		sum := sha256.Sum256(data)
		file := r.root["parts"].([]any)[index].(map[string]any)
		file["sha256"], file["size"] = hex.EncodeToString(sum[:]), len(data)
		parts[file["sha256"].(string)] = data
	}
	root, err := json.Marshal(r.root)
	if err != nil {
		tb.Fatal(err)
	}
	return root, parts
}

// The fallback's dated part holds the records that retire, the last of them on 2028-03-11, so
// it leaves at 12:00 UTC on 2028-03-12.
var datedPartLeaves = time.Date(2028, time.March, 12, 12, 0, 0, 0, time.UTC)

func TestReleaseLeavesRecordsOutOnceTheyRetire(t *testing.T) {
	root, parts := embeddedFiles(t)
	files, err := partFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	dated := files[len(files)-1]
	if dated.Through == nil || *dated.Through != "2028-03-11" {
		t.Fatalf("the fallback's last part is not the dated one: %#v", dated)
	}
	before := datedPartLeaves.Add(-time.Nanosecond)
	if inEffect, err := PartsInEffect(root, before); err != nil || len(inEffect) != len(files) {
		t.Fatalf("parts in effect before the dated part leaves: %v, %v", inEffect, err)
	}
	if inEffect, err := PartsInEffect(root, datedPartLeaves); err != nil || len(inEffect) != len(files)-1 ||
		inEffect[len(inEffect)-1].SHA256 == dated.SHA256 {
		t.Fatalf("parts in effect once the dated part leaves: %v, %v", inEffect, err)
	}

	// Until then, the part's records that have not retired serve, and the others name the day
	// that they retired.
	snap, err := snapshotFromFiles(root, parts, Identity{}, before)
	if err != nil {
		t.Fatal(err)
	}
	if deployment, ok := snap.graph.Deployments["azure-gpt-6-luna"]; !ok || *deployment.RetirementDate != "2028-03-11" {
		t.Fatalf("a deployment that retires on 2028-03-11 left before it retired: %#v", deployment)
	}
	for selector, date := range map[string]string{
		"deepseek-v4-flash-0423":       "2028-02-20",
		"azure-deepseek-v4-flash-0423": "2028-02-20",
		"azure-gpt-5.6-luna":           "2028-01-11",
	} {
		if _, served := snap.graph.Deployments[selector]; served {
			t.Fatalf("retired %s is still in the graph", selector)
		}
		if retiredOn, retired := snap.retiredOn(selector, before); !retired || retiredOn != date {
			t.Fatalf("%s retired on %q (%t), want %s", selector, retiredOn, retired, date)
		}
	}
	if _, ok := snap.graph.Models["deepseek-v4-flash-0423"]; ok {
		t.Fatal("a model whose deployments retired is still in the graph")
	}

	// Once the part leaves, the release loads without it, and every one of its records names
	// the day that it retired.
	held := maps.Clone(parts)
	delete(held, dated.SHA256)
	if _, err := snapshotFromFiles(root, held, Identity{}, before); err == nil || !strings.Contains(err.Error(), "in effect but missing") {
		t.Fatalf("a release without a part in effect loaded: %v", err)
	}
	snap, err = snapshotFromFiles(root, held, Identity{}, datedPartLeaves)
	if err != nil {
		t.Fatal(err)
	}
	for id, deployment := range snap.graph.Deployments {
		if deployment.RetirementDate != nil {
			t.Fatalf("deployment %s of the dated part is in the graph", id)
		}
	}
	if retiredOn, retired := snap.retiredOn("azure-gpt-6-luna", datedPartLeaves); !retired || retiredOn != "2028-03-11" {
		t.Fatalf("azure-gpt-6-luna retired on %q (%t)", retiredOn, retired)
	}
	if _, ok := snap.parts[dated.SHA256]; ok || len(snap.parts) != len(held) {
		t.Fatal("the release holds a part that it did not come with")
	}
}

func TestDeploymentsServeUntilTheirDateHasEndedEverywhere(t *testing.T) {
	deployment := &compiledDeployment{RetirementDate: stringPointer("2026-08-01")}
	ends := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	for at, available := range map[time.Time]bool{
		time.Date(2026, time.August, 1, 23, 59, 59, 0, time.FixedZone("UTC-12", -12*60*60)): true,
		ends.Add(-time.Nanosecond): true,
		ends:                       false,
		ends.In(time.FixedZone("UTC+14", 14*60*60)): false,
	} {
		if deploymentAvailableAt(deployment, at) != available {
			t.Fatalf("at %s, available = %t", at, !available)
		}
	}
	if !deploymentAvailableAt(&compiledDeployment{}, ends.AddDate(100, 0, 0)) {
		t.Fatal("a deployment without a retirement date retired")
	}
}

func TestPartFilesCheckWhatARootNames(t *testing.T) {
	name := func(n int) string { return fmt.Sprintf("%064x", n) }
	part := func(n, size int, through string) string {
		return `{"sha256":"` + name(n) + `","size":` + strconv.Itoa(size) + `,"through":` + through + `}`
	}
	parts := func(count, size int) string {
		listed := make([]string, count)
		for n := range count {
			listed[n] = part(n+1, size, "null")
		}
		return strings.Join(listed, ",")
	}
	root := func(parts string) []byte {
		return []byte(`{"schema":"stogas.catalog.v9","parts":[` + parts + `]}`)
	}
	listed, err := partFiles(root(part(1, 1, "null") + "," + part(2, 3, `"2028-02-29"`)))
	if want := []PartFile{{name(1), 1, nil}, {name(2), 3, stringPointer("2028-02-29")}}; err != nil || !reflect.DeepEqual(listed, want) {
		t.Fatalf("listed %v, want %v: %v", listed, want, err)
	}
	const mebibyte = 1024 * 1024
	for problem, test := range map[string]struct {
		root    []byte
		message string
	}{
		"another schema":      {[]byte(`{"schema":"stogas.catalog.v8","parts":[]}`), "unsupported"},
		"no root":             {nil, "size is outside"},
		"a large root":        {append(root(""), bytes.Repeat([]byte(" "), rootSizeLimit)...), "size is outside"},
		"an uppercase digest": {root(`{"sha256":"` + strings.Repeat("A", 64) + `","size":1,"through":null}`), "invalid part"},
		"a short digest":      {root(`{"sha256":"` + strings.Repeat("a", 63) + `","size":1,"through":null}`), "invalid part"},
		"an empty part":       {root(part(1, 0, "null")), "invalid part"},
		"a large part":        {root(part(1, mebibyte+1, "null")), "invalid part"},
		"a repeated part":     {root(part(1, 1, "null") + "," + part(1, 1, "null")), "invalid part"},
		"an impossible date":  {root(part(1, 1, `"2027-02-29"`)), "invalid part"},
		"a time for a date":   {root(part(1, 1, `"2027-02-28T00:00:00Z"`)), "invalid part"},
		"a large catalog":     {root(parts(128, mebibyte)), "exceeds"},
	} {
		if _, err := partFiles(test.root); err == nil || !strings.Contains(err.Error(), test.message) {
			t.Fatalf("a root with %s was accepted: %v", problem, err)
		}
	}
}

func TestReleaseRefusesFilesThatDifferFromTheRoot(t *testing.T) {
	const deployment = "azure-gpt-6-luna"
	for problem, test := range map[string]struct {
		change  func(testRelease)
		message string
	}{
		"a record in another part": {func(r testRelease) {
			r.summary("deployments", "anthropic-claude-fable-5")["part"] = 1
		}, "places elsewhere"},
		"a missing record": {func(r testRelease) {
			delete(r.parts[2]["graph"].(map[string]any)["deployments"].(map[string]any), deployment)
		}, "omits a record"},
		"a summary without a part": {func(r testRelease) {
			r.summary("models", "deepseek-v4-flash-0423")["part"] = 3
		}, "names no part"},
		"a record that retires after its part": {func(r testRelease) {
			r.summary("deployments", deployment)["retirementDate"] = "2028-03-12"
			r.record("deployments", deployment)["retirementDate"] = "2028-03-12"
		}, "retires after its part"},
		"a record that never retires in a dated part": {func(r testRelease) {
			r.summary("routes", "azure-responses")["retirementDate"] = nil
		}, "retires after its part"},
		"a deployment whose date differs from its summary": {func(r testRelease) {
			r.record("deployments", deployment)["retirementDate"] = "2028-03-10"
		}, "another date than its summary"},
		"a change that the root does not list": {func(r testRelease) {
			r.parts[0]["schedule"] = []any{map[string]any{"start": "2027-01-01T00:00:00Z", "graph": map[string]any{}}}
		}, "does not list"},
		"another part schema": {func(r testRelease) {
			r.parts[1]["schema"] = "stogas.catalog.part.v8"
		}, "unsupported"},
		"an unknown record field": {func(r testRelease) {
			r.record("deployments", deployment)["notes"] = "unread"
		}, "unknown"},
		"an unknown root member": {func(r testRelease) {
			r.root["archive"] = nil
		}, "unknown"},
		"a part holding authors": {func(r testRelease) {
			r.parts[0]["graph"].(map[string]any)["authors"] = map[string]any{}
		}, "unknown"},
	} {
		t.Run(problem, func(t *testing.T) {
			release := embeddedRelease(t)
			test.change(release)
			root, parts := release.files(t)
			if _, err := snapshotFromFiles(root, parts, Identity{}, time.Time{}); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %v, want %q", err, test.message)
			}
		})
	}

	root, parts := embeddedRelease(t).files(t)
	if _, err := snapshotFromFiles(root, parts, Identity{}, time.Time{}); err != nil {
		t.Fatalf("the rewritten fallback was refused: %v", err)
	}
	for problem, change := range map[string]func(map[string][]byte){
		"a changed part": func(parts map[string][]byte) {
			for name, data := range parts {
				parts[name] = append(bytes.Clone(data[:len(data)-1]), ' ')
				return
			}
		},
		"a part that the root does not name": func(parts map[string][]byte) {
			parts[strings.Repeat("0", 64)] = []byte(`{}`)
		},
	} {
		changed := maps.Clone(parts)
		change(changed)
		if _, err := snapshotFromFiles(root, changed, Identity{}, time.Time{}); err == nil || !strings.Contains(err.Error(), "the root") {
			t.Fatalf("a release with %s loaded: %v", problem, err)
		}
	}
	if _, err := snapshotFromFiles(root, parts, Identity{Sequence: 1, Digest: "sha256:" + strings.Repeat("0", 64)}, time.Time{}); err == nil ||
		!strings.Contains(err.Error(), "does not match the signed release") {
		t.Fatalf("a root under another digest loaded: %v", err)
	}
}

func TestActiveCatalogServesTheRootWithItsRelease(t *testing.T) {
	prior := active.Load()
	t.Cleanup(func() { active.Store(prior) })
	root, parts := embeddedFiles(t)
	sum := sha256.Sum256(root)
	identity := Identity{Sequence: 7, Digest: "sha256:" + hex.EncodeToString(sum[:])}
	if err := InstallApproved(root, parts, identity, time.Now()); err != nil {
		t.Fatal(err)
	}
	served, ok := ActiveCatalog()
	if !ok {
		t.Fatal("the active catalog is unavailable")
	}
	var got, want map[string]any
	if err := json.Unmarshal(served, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(root, &want); err != nil {
		t.Fatal(err)
	}
	want["digest"], want["sequence"] = identity.Digest, float64(identity.Sequence)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("the served root differs from the root with its release")
	}
	for name, data := range parts {
		if held, ok := ActiveCatalogPart(name); !ok || !bytes.Equal(held, data) {
			t.Fatalf("part %s is not served", name)
		}
	}
	if _, ok := ActiveCatalogPart(strings.Repeat("0", 64)); ok {
		t.Fatal("a part that the release did not come with was served")
	}
}
