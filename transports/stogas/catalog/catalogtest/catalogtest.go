// Package catalogtest holds the catalog that the gateway's tests read. It began as the catalog's
// source as it stood then, with each retirement date a century later, so a change to the real
// catalog cannot change what a test checks, and no record retires while the tests run. A test
// that needs another record adds it to data; `bun stogas gateway catalog` builds data into
// generated with the catalog's own build.
package catalogtest

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

//go:embed generated
var generated embed.FS

// Files returns the test catalog's root and every part that it names, by SHA-256 in hex.
func Files() ([]byte, map[string][]byte, error) {
	files, err := fs.Sub(generated, "generated")
	if err != nil {
		return nil, nil, err
	}
	return catalog.ReadBuild(files)
}

// Install makes the test catalog the active catalog, with every record, as a gateway reads its
// fallback.
func Install() error {
	root, parts, err := Files()
	if err != nil {
		return err
	}
	return install(root, parts)
}

// UseFallback makes the catalog that the gateway embeds the active catalog until the test ends,
// for a test that checks the gateway against every record that the gateway can serve.
func UseFallback(tb testing.TB) {
	tb.Helper()
	root, parts, err := catalog.Fallback()
	if err == nil {
		err = install(root, parts)
	}
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		if err := Install(); err != nil {
			tb.Error(err)
		}
	})
}

// install makes a build the active catalog, as the first release that a gateway approves.
func install(root []byte, parts map[string][]byte) error {
	sum := sha256.Sum256(root)
	return catalog.InstallApproved(root, parts, catalog.Identity{
		Sequence: 1,
		Digest:   "sha256:" + hex.EncodeToString(sum[:]),
	}, time.Time{})
}
