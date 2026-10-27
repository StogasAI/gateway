package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Artifact bounds are shared by delivery and decoding.
const MaxRuntimeBytes = runtimeSizeLimit
const MaxPublicBytes = publicSizeLimit
const MaxPublicPartBytes = publicPartSizeLimit

func ActiveMatchesApproved(identity Identity, publicDigest string) bool {
	current := active.Load()
	return current != nil && current.identity == identity && current.publicDigest == publicDigest
}

// ActivePublicPart is a part of the active public catalog, by SHA-256 in hex, so a new release
// downloads only the parts that changed.
func ActivePublicPart(sha256 string) ([]byte, bool) {
	current := active.Load()
	if current == nil {
		return nil, false
	}
	part, ok := current.publicParts[sha256]
	return part, ok
}

// InstallApproved installs artifacts selected by the shared offline verifier.
// The caller must authenticate the complete approval set before supplying these
// digests. The public root names each of its parts, by SHA-256 in hex, so parts
// need no approval of their own. Parsing and replacement remain atomic, including
// an approved rollback.
func InstallApproved(runtimeData, publicData []byte, parts map[string][]byte, identity Identity, publicDigest string) error {
	if identity.Sequence == 0 || len(runtimeData) > runtimeSizeLimit || len(publicData) > publicSizeLimit {
		return errors.New("invalid approved catalog size or sequence")
	}
	runtimeHash, publicHash := sha256.Sum256(runtimeData), sha256.Sum256(publicData)
	if "sha256:"+hex.EncodeToString(runtimeHash[:]) != identity.Digest || "sha256:"+hex.EncodeToString(publicHash[:]) != publicDigest {
		return errors.New("catalog artifacts differ from approved digests")
	}
	candidate, err := snapshotFromRelease(runtimeData, publicData, parts, identity)
	if err != nil {
		return err
	}
	activationMu.Lock()
	defer activationMu.Unlock()
	active.Store(candidate)
	return nil
}
