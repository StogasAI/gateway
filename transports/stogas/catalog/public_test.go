package catalog

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestPublicCatalogFilesListsTheFilesThatARootNames(t *testing.T) {
	name := func(n int) string { return fmt.Sprintf("%064x", n) }
	file := func(n, size int) string { return `{"sha256":"` + name(n) + `","size":` + strconv.Itoa(size) + `}` }
	files := func(first, count, size int) string {
		listed := make([]string, count)
		for n := range count {
			listed[n] = file(first+n, size)
		}
		return strings.Join(listed, ",")
	}
	root := func(parts, archive string) []byte {
		return []byte(`{"archive":` + archive + `,"parts":[` + parts + `]}`)
	}
	archive := func(index, parts string) string { return `{"index":` + index + `,"parts":[` + parts + `]}` }
	listed, err := PublicCatalogFiles(root(files(1, 2, 1), archive(file(3, 2), file(4, 3))))
	if want := []PublicFile{{name(1), 1}, {name(2), 1}, {name(3), 2}, {name(4), 3}}; err != nil || !slices.Equal(listed, want) {
		t.Fatalf("listed %v, want %v: %v", listed, want, err)
	}
	if listed, err := PublicCatalogFiles(root(file(1, 1), "null")); err != nil || len(listed) != 1 {
		t.Fatalf("a root without an archive listed %v: %v", listed, err)
	}
	const mebibyte = 1024 * 1024
	for problem, test := range map[string]struct {
		root    []byte
		message string
	}{
		"an uppercase digest": {root(`{"sha256":"`+strings.Repeat("A", 64)+`","size":1}`, "null"), "invalid file"},
		"a short digest":      {root(`{"sha256":"`+strings.Repeat("a", 63)+`","size":1}`, "null"), "invalid file"},
		"an empty part":       {root(file(1, 0), "null"), "invalid file"},
		"a large part":        {root(file(1, mebibyte+1), "null"), "invalid file"},
		"a repeated file":     {root(file(1, 1), archive(file(1, 1), file(2, 1))), "invalid file"},
		"an empty archive":    {root(file(1, 1), archive(file(2, 1), "")), "invalid file"},
		"a large index":       {root(file(1, 1), archive(file(2, 16*mebibyte+1), file(3, 1))), "invalid file"},
		"a large catalog":     {root(files(1, 64, mebibyte), "null"), "public catalog exceeds"},
		"a large archive":     {root(file(1, 1), archive(file(2, 16*mebibyte), files(3, 49, mebibyte))), "archive exceeds"},
	} {
		if _, err := PublicCatalogFiles(test.root); err == nil || !strings.Contains(err.Error(), test.message) {
			t.Fatalf("a root with %s was accepted: %v", problem, err)
		}
	}
}
