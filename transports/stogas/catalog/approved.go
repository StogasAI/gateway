package catalog

import (
	"errors"
	"time"
)

// MaxRootBytes bounds a root's delivery and decoding.
const MaxRootBytes = rootSizeLimit

func ActiveMatchesApproved(identity Identity) bool {
	current := active.Load()
	return current != nil && current.identity == identity
}

// ActiveCatalogPart is a part that the active release came with, by SHA-256 in hex. A new
// release downloads only the parts that changed.
func ActiveCatalogPart(sha256 string) ([]byte, bool) {
	current := active.Load()
	if current == nil {
		return nil, false
	}
	part, ok := current.parts[sha256]
	return part, ok
}

// InstallApproved installs a release that the shared offline verifier selected, as it stands at
// an instant. The caller must authenticate the complete approval set before supplying the
// identity, whose digest is the root's. The root names each part by SHA-256, so parts need no
// approval of their own, and parts must hold each one in effect then. Parsing and replacement
// remain atomic, including an approved rollback.
func InstallApproved(root []byte, parts map[string][]byte, identity Identity, at time.Time) error {
	if identity.Sequence == 0 || identity.Digest == "" || len(root) > rootSizeLimit {
		return errors.New("invalid approved catalog size or identity")
	}
	candidate, err := snapshotFromFiles(root, parts, identity, at)
	if err != nil {
		return err
	}
	activationMu.Lock()
	defer activationMu.Unlock()
	active.Store(candidate)
	return nil
}
