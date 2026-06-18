package stogas

import (
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// SeedBifrostModelParams supplies the provider helpers with catalog-owned model limits.
func SeedBifrostModelParams(resolution *catalog.ResolvedRequest) {
	if resolution == nil || resolution.Model == "" || resolution.Deployment.MaxOutputTokens <= 0 {
		return
	}

	maxOutputTokens := resolution.Deployment.MaxOutputTokens
	params, _ := providerUtils.GetModelParams(resolution.Model)
	params.MaxOutputTokens = &maxOutputTokens
	providerUtils.SetModelParams(resolution.Model, params)
}
