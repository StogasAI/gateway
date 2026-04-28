package stogashttp

import (
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

type stogasRoute string

const (
	stogasRouteChat      stogasRoute = "chat"
	stogasRouteResponses stogasRoute = "responses"
)

// The real catalog will own provider/model resolution, provider-specific extra
// params, upstream/header exposure, cancellation capabilities, and pricing data.
// Until that lands, keep the policy intentionally narrow and safe.

func resolveCatalogModel(provider schemas.ModelProvider, model string) bool {
	return provider == schemas.OpenAI && strings.TrimSpace(model) != ""
}

func filterCatalogExtraParams(provider schemas.ModelProvider, model string, route stogasRoute, params map[string]interface{}) map[string]interface{} {
	if len(params) == 0 || !resolveCatalogModel(provider, model) {
		return nil
	}

	filtered := make(map[string]interface{})
	for name, value := range params {
		if catalogAllowsExtraParam(provider, model, route, name) {
			filtered[name] = value
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func catalogAllowsExtraParam(provider schemas.ModelProvider, model string, route stogasRoute, name string) bool {
	if !resolveCatalogModel(provider, model) {
		return false
	}

	// OpenAI chat max_tokens is a legacy compatibility field that Bifrost maps to
	// max_completion_tokens before provider dispatch. It is not generic passthrough.
	return route == stogasRouteChat && name == "max_tokens"
}

func catalogAllowsUpstreamRequestHeader(provider schemas.ModelProvider, model string, header string) bool {
	return false
}

func filterCatalogProviderResponseHeaders(provider schemas.ModelProvider, model string, headers map[string]string) map[string]string {
	if len(headers) == 0 || !resolveCatalogModel(provider, model) {
		return nil
	}

	filtered := make(map[string]string)
	for name, value := range headers {
		if catalogAllowsProviderResponseHeader(provider, model, name) {
			filtered[name] = value
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func catalogAllowsProviderResponseHeader(provider schemas.ModelProvider, model string, header string) bool {
	return false
}

func catalogSupportsInFlightStreamCancel(provider schemas.ModelProvider, model string) bool {
	return false
}
