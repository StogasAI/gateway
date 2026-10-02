package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestApprovedCatalogReplacesAtomicallyAndRetainsRequestSnapshot(t *testing.T) {
	prior := active.Load()
	t.Cleanup(func() { active.Store(prior) })
	runtimeData := bytes.Clone(embeddedRuntimeCatalogJSON)
	publicData := bytes.Clone(embeddedPublicCatalogJSON)
	runtimeHash, publicHash := sha256.Sum256(runtimeData), sha256.Sum256(publicData)
	identity := Identity{Sequence: 10, Digest: "sha256:" + hex.EncodeToString(runtimeHash[:])}
	publicDigest := "sha256:" + hex.EncodeToString(publicHash[:])
	if err := InstallApproved(runtimeData, publicData, identity, publicDigest); err != nil {
		t.Fatal(err)
	}
	retained := active.Load()
	corrupt := bytes.Clone(runtimeData)
	corrupt[0] ^= 1
	if err := InstallApproved(corrupt, publicData, identity, publicDigest); err == nil || active.Load() != retained {
		t.Fatal("corrupt artifact replaced current catalog")
	}
	if err := InstallApproved(runtimeData, publicData, identity, "sha256:"+string(bytes.Repeat([]byte{'0'}, 64))); err == nil || active.Load() != retained {
		t.Fatal("wrong public digest replaced current catalog")
	}
	// The signed current set may explicitly withdraw a newer catalog. The loader
	// obeys that selected release; it does not invent a second approval policy.
	identity.Sequence = 9
	if err := InstallApproved(runtimeData, publicData, identity, publicDigest); err != nil {
		t.Fatal(err)
	}
	if active.Load().identity.Sequence != 9 || retained.identity.Sequence != 10 || prior == active.Load() {
		t.Fatal("catalog activation changed an in-flight snapshot")
	}
	runtimeData[0] ^= 1
	publicData[0] ^= 1
	if active.Load().raw[0] == runtimeData[0] || active.Load().publicRaw[0] == publicData[0] {
		t.Fatal("caller retained mutable catalog storage")
	}
}
