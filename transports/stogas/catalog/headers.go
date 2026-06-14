package catalog

import "github.com/maximhq/bifrost/core/schemas"

func AllowsUpstreamRequestHeader(provider schemas.ModelProvider, model string, route Route, header string) bool {
	return false
}

func FilterProviderResponseHeaders(provider schemas.ModelProvider, model string, headers map[string]string) map[string]string {
	return nil
}
