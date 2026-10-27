package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"testing"
)

func TestApprovedCatalogReplacesAtomicallyAndRetainsRequestSnapshot(t *testing.T) {
	prior := active.Load()
	t.Cleanup(func() { active.Store(prior) })
	runtimeData := bytes.Clone(embeddedRuntimeCatalogJSON)
	publicData := bytes.Clone(embeddedPublicCatalogJSON)
	parts, err := embeddedParts()
	if err != nil {
		t.Fatal(err)
	}
	parts = maps.Clone(parts)
	for digest, part := range parts {
		parts[digest] = bytes.Clone(part)
	}
	runtimeHash, publicHash := sha256.Sum256(runtimeData), sha256.Sum256(publicData)
	identity := Identity{Sequence: 10, Digest: "sha256:" + hex.EncodeToString(runtimeHash[:])}
	publicDigest := "sha256:" + hex.EncodeToString(publicHash[:])
	if err := InstallApproved(runtimeData, publicData, parts, identity, publicDigest); err != nil {
		t.Fatal(err)
	}
	retained := active.Load()
	corrupt := bytes.Clone(runtimeData)
	corrupt[0] ^= 1
	if err := InstallApproved(corrupt, publicData, parts, identity, publicDigest); err == nil || active.Load() != retained {
		t.Fatal("corrupt artifact replaced current catalog")
	}
	if err := InstallApproved(runtimeData, publicData, parts, identity, "sha256:"+string(bytes.Repeat([]byte{'0'}, 64))); err == nil || active.Load() != retained {
		t.Fatal("wrong public digest replaced current catalog")
	}
	for digest := range parts {
		missing := maps.Clone(parts)
		delete(missing, digest)
		if err := InstallApproved(runtimeData, publicData, missing, identity, publicDigest); err == nil || active.Load() != retained {
			t.Fatal("a catalog without one of its parts replaced current catalog")
		}
		changed := maps.Clone(parts)
		changed[digest] = append(bytes.Clone(parts[digest]), ' ')
		if err := InstallApproved(runtimeData, publicData, changed, identity, publicDigest); err == nil || active.Load() != retained {
			t.Fatal("a changed part replaced current catalog")
		}
	}
	// The signed current set may explicitly withdraw a newer catalog. The loader
	// obeys that selected release; it does not invent a second approval policy.
	identity.Sequence = 9
	if err := InstallApproved(runtimeData, publicData, parts, identity, publicDigest); err != nil {
		t.Fatal(err)
	}
	if active.Load().identity.Sequence != 9 || retained.identity.Sequence != 10 || prior == active.Load() {
		t.Fatal("catalog activation changed an in-flight snapshot")
	}
	runtimeData[0] ^= 1
	publicData[0] ^= 1
	for digest, part := range parts {
		part[0] ^= 1
		if held, _ := ActivePublicPart(digest); held[0] == part[0] {
			t.Fatal("caller retained mutable catalog part storage")
		}
	}
	if active.Load().raw[0] == runtimeData[0] || active.Load().publicRaw[0] == publicData[0] {
		t.Fatal("caller retained mutable catalog storage")
	}
}
