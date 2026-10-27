package stogashttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestCatalogServesTheArchiveThatItNames(t *testing.T) {
	server := &Server{}
	get := func(path string) *requestContext {
		ctx := newTestRequest(t)
		ctx.request.Method = http.MethodGet
		testRequestURI(ctx, path)
		return ctx
	}
	current := get("/v1/catalog")
	server.catalog(current)
	var payload catalog.PublicCatalog
	if err := json.Unmarshal(testResponse(current).Body.Bytes(), &payload); err != nil || testResponse(current).Code != http.StatusOK {
		t.Fatalf("catalog = %d, %v", testResponse(current).Code, err)
	}
	paths := []string{catalogArchivePath + strings.Repeat("0", 64), catalogArchivePath}
	if archive := payload.Archive; archive != nil {
		ctx := get(catalogArchivePath + archive.SHA256)
		server.catalogArchive(ctx)
		response := testResponse(ctx)
		sum := sha256.Sum256(response.Body.Bytes())
		if response.Code != http.StatusOK || hex.EncodeToString(sum[:]) != archive.SHA256 || int64(response.Body.Len()) != archive.Size {
			t.Fatalf("archive %s = %d with other bytes", archive.SHA256, response.Code)
		}
		if response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("archive %s is not cacheable: %q", archive.SHA256, response.Header().Get("Cache-Control"))
		}
		paths = append(paths, catalogArchivePath+archive.SHA256+".json")
	}
	for _, path := range paths {
		ctx := get(path)
		server.catalogArchive(ctx)
		if testResponse(ctx).Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404", path, testResponse(ctx).Code)
		}
	}
}
