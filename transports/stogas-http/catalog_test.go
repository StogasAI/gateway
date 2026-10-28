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

func TestCatalogServesEveryPartThatItsRootNames(t *testing.T) {
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
	root, err := json.Marshal(map[string]json.RawMessage{"archive": payload.Archive, "parts": payload.Parts})
	if err != nil {
		t.Fatal(err)
	}
	files, err := catalog.PublicCatalogFiles(root)
	if err != nil || len(files) == 0 {
		t.Fatalf("the catalog names no parts: %v", err)
	}
	paths := []string{catalogPartsPath + strings.Repeat("0", 64), catalogPartsPath}
	for _, file := range files {
		ctx := get(catalogPartsPath + file.SHA256)
		server.catalogPart(ctx)
		response := testResponse(ctx)
		sum := sha256.Sum256(response.Body.Bytes())
		if response.Code != http.StatusOK || hex.EncodeToString(sum[:]) != file.SHA256 || int64(response.Body.Len()) != file.Size {
			t.Fatalf("part %s = %d with other bytes", file.SHA256, response.Code)
		}
		if response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("part %s is not cacheable: %q", file.SHA256, response.Header().Get("Cache-Control"))
		}
		paths = append(paths, catalogPartsPath+file.SHA256+".json")
	}
	for _, path := range paths {
		ctx := get(path)
		server.catalogPart(ctx)
		if testResponse(ctx).Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404", path, testResponse(ctx).Code)
		}
	}
}
