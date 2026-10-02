package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Artifact bounds are shared by delivery and decoding.
const MaxRuntimeBytes = runtimeSizeLimit
const MaxPublicBytes = publicSizeLimit

func ActiveMatchesApproved(identity Identity, publicDigest string) bool {
	current := active.Load()
	return current != nil && current.identity == identity && current.publicDigest == publicDigest
}

// InstallApproved installs artifacts selected by the shared offline verifier.
// The caller must authenticate the complete approval set before supplying these
// digests. Parsing and replacement remain atomic, including an approved rollback.
func InstallApproved(runtimeData, publicData []byte, identity Identity, publicDigest string) error {
	if identity.Sequence == 0 || len(runtimeData) > runtimeSizeLimit || len(publicData) > publicSizeLimit {
		return errors.New("invalid approved catalog size or sequence")
	}
	runtimeHash, publicHash := sha256.Sum256(runtimeData), sha256.Sum256(publicData)
	if "sha256:"+hex.EncodeToString(runtimeHash[:]) != identity.Digest || "sha256:"+hex.EncodeToString(publicHash[:]) != publicDigest {
		return errors.New("catalog artifacts differ from approved digests")
	}
	candidate, err := snapshotFromRelease(runtimeData, publicData, identity)
	if err != nil {
		return err
	}
	activationMu.Lock()
	defer activationMu.Unlock()
	active.Store(candidate)
	return nil
}
