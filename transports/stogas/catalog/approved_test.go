package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"testing"
	"time"
)

func TestApprovedCatalogReplacesAtomicallyAndRetainsRequestSnapshot(t *testing.T) {
	prior := active.Load()
	t.Cleanup(func() { active.Store(prior) })
	root, parts := embeddedFiles(t)
	root = bytes.Clone(root)
	sum := sha256.Sum256(root)
	identity := Identity{Sequence: 10, Digest: "sha256:" + hex.EncodeToString(sum[:])}
	now := time.Now()
	if err := InstallApproved(root, maps.Clone(parts), identity, now); err != nil {
		t.Fatal(err)
	}
	retained := active.Load()
	corrupt := bytes.Clone(root)
	corrupt[len(corrupt)-1] ^= 1
	for problem, install := range map[string]func() error{
		"a corrupt root":            func() error { return InstallApproved(corrupt, maps.Clone(parts), identity, now) },
		"no sequence":               func() error { return InstallApproved(root, maps.Clone(parts), Identity{Digest: identity.Digest}, now) },
		"no digest":                 func() error { return InstallApproved(root, maps.Clone(parts), Identity{Sequence: 10}, now) },
		"no part that is in effect": func() error { return InstallApproved(root, nil, identity, now) },
	} {
		if err := install(); err == nil || active.Load() != retained {
			t.Fatalf("a release with %s replaced the current catalog", problem)
		}
	}
	// The signed current set may explicitly withdraw a newer catalog. The loader
	// obeys that selected release; it does not invent a second approval policy.
	identity.Sequence = 9
	if err := InstallApproved(root, maps.Clone(parts), identity, now); err != nil {
		t.Fatal(err)
	}
	if active.Load().identity.Sequence != 9 || retained.identity.Sequence != 10 || prior == active.Load() {
		t.Fatal("catalog activation changed an in-flight snapshot")
	}
	served := bytes.Clone(active.Load().served)
	root[len(root)-1] ^= 1
	if !bytes.Equal(active.Load().served, served) {
		t.Fatal("caller retained mutable catalog storage")
	}
	for name, data := range parts {
		data[0] ^= 1
		if held, _ := ActiveCatalogPart(name); held[0] == data[0] {
			t.Fatal("caller retained mutable part storage")
		}
	}
}
