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

func TestCatalogServesItsRootAndEveryPartThatTheRootLists(t *testing.T) {
	server := &Server{}
	get := func(path string) *requestContext {
		ctx := newTestRequest(t)
		ctx.request.Method = http.MethodGet
		testRequestURI(ctx, path)
		return ctx
	}
	root := get("/v1/catalog")
	server.catalog(root)
	var payload catalog.PublicCatalog
	if err := json.Unmarshal(testResponse(root).Body.Bytes(), &payload); err != nil || testResponse(root).Code != http.StatusOK {
		t.Fatalf("catalog root = %d, %v", testResponse(root).Code, err)
	}
	var parts []catalog.PublicPart
	if err := json.Unmarshal(payload.Parts, &parts); err != nil || len(parts) == 0 {
		t.Fatalf("catalog root lists no parts: %v", err)
	}
	for _, part := range parts {
		ctx := get(catalogPartsPath + part.SHA256)
		server.catalogPart(ctx)
		response := testResponse(ctx)
		sum := sha256.Sum256(response.Body.Bytes())
		if response.Code != http.StatusOK || hex.EncodeToString(sum[:]) != part.SHA256 || int64(response.Body.Len()) != part.Size {
			t.Fatalf("part %s = %d with other bytes", part.SHA256, response.Code)
		}
		if response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("part %s is not cacheable: %q", part.SHA256, response.Header().Get("Cache-Control"))
		}
	}
	for _, path := range []string{catalogPartsPath + strings.Repeat("0", 64), catalogPartsPath, catalogPartsPath + parts[0].SHA256 + ".json"} {
		ctx := get(path)
		server.catalogPart(ctx)
		if testResponse(ctx).Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404", path, testResponse(ctx).Code)
		}
	}
}
