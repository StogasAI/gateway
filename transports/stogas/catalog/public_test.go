package catalog

import (
	"strings"
	"testing"
)

func TestPublicArchiveNamesACheckedArchive(t *testing.T) {
	digest := strings.Repeat("a", 64)
	naming := func(archive string) []byte { return []byte(`{"archive":` + archive + `}`) }
	if reference, err := PublicArchive(naming("null")); err != nil || reference != nil {
		t.Fatalf("a public catalog without an archive named one: %v", err)
	}
	if reference, err := PublicArchive(naming(`{"sha256":"` + digest + `","size":1}`)); err != nil ||
		reference == nil || reference.SHA256 != digest || reference.Size != 1 {
		t.Fatalf("a valid archive reference was refused: %v", err)
	}
	for _, invalid := range []string{
		`{"sha256":"` + strings.ToUpper(digest) + `","size":1}`,
		`{"sha256":"` + digest[1:] + `","size":1}`,
		`{"sha256":"` + digest + `","size":0}`,
		`{"sha256":"` + digest + `","size":33554433}`,
	} {
		if _, err := PublicArchive(naming(invalid)); err == nil || !strings.Contains(err.Error(), "invalid archive") {
			t.Fatalf("an invalid archive reference was accepted: %s", invalid)
		}
	}
}
