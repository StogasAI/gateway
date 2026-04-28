package stogas

import (
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// The production catalog will resolve provider/model availability, pricing,
// billing mode, and cancellation capability. For now the gateway account only
// has an OpenAI platform key, so keep the placeholder equally constrained.
func resolveCatalogModel(provider schemas.ModelProvider, model string) bool {
	return provider == schemas.OpenAI && strings.TrimSpace(model) != ""
}
