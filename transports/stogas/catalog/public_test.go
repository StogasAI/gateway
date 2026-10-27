package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"strings"
	"testing"
)

// withParts changes embedded parts, in order, and lists each under its new digest and size.
func withParts(t *testing.T, changes map[int]func(part map[string]any)) ([]byte, map[string][]byte) {
	t.Helper()
	parts, err := embeddedParts()
	if err != nil {
		t.Fatal(err)
	}
	parts = maps.Clone(parts)
	var root map[string]any
	if err := json.Unmarshal(embeddedPublicCatalogJSON, &root); err != nil {
		t.Fatal(err)
	}
	for index := range len(root["parts"].([]any)) {
		change, ok := changes[index]
		if !ok {
			continue
		}
		listed := root["parts"].([]any)[index].(map[string]any)
		var part map[string]any
		if err := json.Unmarshal(parts[listed["sha256"].(string)], &part); err != nil {
			t.Fatal(err)
		}
		change(part)
		data, err := json.Marshal(part)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		delete(parts, listed["sha256"].(string))
		listed["sha256"], listed["size"] = hex.EncodeToString(sum[:]), len(data)
		parts[listed["sha256"].(string)] = data
	}
	rootData, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return rootData, parts
}

func TestPublicCatalogPartsMatchTheirRoot(t *testing.T) {
	parts, err := embeddedParts()
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 2 {
		t.Fatalf("the embedded public catalog has %d parts; these checks need two", len(parts))
	}
	if _, err := snapshotFromRelease(embeddedRuntimeCatalogJSON, embeddedPublicCatalogJSON, parts, Identity{}); err != nil {
		t.Fatal(err)
	}
	extra := maps.Clone(parts)
	extra[strings.Repeat("0", 64)] = []byte("{}")
	if _, err := snapshotFromRelease(embeddedRuntimeCatalogJSON, embeddedPublicCatalogJSON, extra, Identity{}); err == nil ||
		!strings.Contains(err.Error(), "differ from the root") {
		t.Fatalf("an unlisted part was accepted: %v", err)
	}
	var movedID string
	var moved any
	for name, check := range map[string]struct {
		message string
		changes map[int]func(part map[string]any)
	}{
		"part schema": {"schema", map[int]func(map[string]any){
			0: func(part map[string]any) { part["schema"] = "stogas.catalog.public.part.v5" },
		}},
		"omitted deployment": {"omit a deployment", map[int]func(map[string]any){
			0: func(part map[string]any) {
				for id := range part["deployments"].(map[string]any) {
					delete(part["deployments"].(map[string]any), id)
					return
				}
			},
		}},
		"deployment of another part": {"places elsewhere", map[int]func(map[string]any){
			0: func(part map[string]any) {
				for id, record := range part["deployments"].(map[string]any) {
					movedID, moved = id, record
					delete(part["deployments"].(map[string]any), id)
					return
				}
			},
			1: func(part map[string]any) { part["deployments"].(map[string]any)[movedID] = moved },
		}},
	} {
		t.Run(name, func(t *testing.T) {
			root, changed := withParts(t, check.changes)
			if _, err := snapshotFromRelease(embeddedRuntimeCatalogJSON, root, changed, Identity{}); err == nil ||
				!strings.Contains(err.Error(), check.message) {
				t.Fatalf("the public catalog was accepted with this change: %v", err)
			}
		})
	}
}

func TestPublicPartsListsCheckedParts(t *testing.T) {
	digest := strings.Repeat("a", 64)
	listing := func(parts string) []byte { return []byte(`{"parts":` + parts + `}`) }
	if parts, err := PublicParts(listing(`[{"sha256":"` + digest + `","size":1}]`)); err != nil || len(parts) != 1 {
		t.Fatalf("a valid part listing was refused: %v", err)
	}
	for _, invalid := range []string{
		`[{"sha256":"` + digest + `","size":1},{"sha256":"` + digest + `","size":1}]`,
		`[{"sha256":"` + strings.ToUpper(digest) + `","size":1}]`,
		`[{"sha256":"` + digest[1:] + `","size":1}]`,
		`[{"sha256":"` + digest + `","size":0}]`,
		`[{"sha256":"` + digest + `","size":1048577}]`,
	} {
		if _, err := PublicParts(listing(invalid)); err == nil {
			t.Fatalf("an invalid part listing was accepted: %s", invalid)
		}
	}
	var many strings.Builder
	many.WriteString("[")
	for index := range 33 {
		if index > 0 {
			many.WriteString(",")
		}
		sum := sha256.Sum256([]byte{byte(index)})
		many.WriteString(`{"sha256":"` + hex.EncodeToString(sum[:]) + `","size":1048576}`)
	}
	many.WriteString("]")
	if _, err := PublicParts(listing(many.String())); err == nil || !strings.Contains(err.Error(), "accepted size") {
		t.Fatalf("a public catalog over its limit was accepted: %v", err)
	}
}
