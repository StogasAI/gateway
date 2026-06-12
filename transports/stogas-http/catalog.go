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

// Catalog owns semantic Stogas policy: provider/model resolution, core vs extra
// parameter allowlists, and global/per-provider request and response header
// allowlists between clients, Stogas, and providers.
//
// The HTTP layer owns mechanistic enforcement at the transport boundary, such as
// stripping invalid or dangerous wire-level headers immediately before mutating
// the response.
type catalogModelDeployment struct {
	model                string
	impliedServiceTier   *schemas.BifrostServiceTier
	allowedServiceTier   *schemas.BifrostServiceTier
}

var (
	catalogDefaultServiceTier  = schemas.BifrostServiceTierDefault
	catalogFlexServiceTier     = schemas.BifrostServiceTierFlex
	catalogPriorityServiceTier = schemas.BifrostServiceTierPriority
)

func resolveCatalogModel(provider schemas.ModelProvider, model string) bool {
	_, ok := catalogModelDeploymentFor(provider, model)
	return ok
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

func catalogModelDeploymentFor(provider schemas.ModelProvider, model string) (catalogModelDeployment, bool) {
	if provider != schemas.OpenAI {
		return catalogModelDeployment{}, false
	}

	switch strings.TrimSpace(model) {
	case "gpt-5.5", "gpt-5.5-latest", "gpt-5.5-2026-04-23":
		return catalogModelDeployment{
			model:              "gpt-5.5",
			allowedServiceTier: &catalogDefaultServiceTier,
		}, true
	case "gpt-5.5-flex":
		return catalogModelDeployment{
			model:              "gpt-5.5",
			impliedServiceTier: &catalogFlexServiceTier,
			allowedServiceTier: &catalogFlexServiceTier,
		}, true
	case "gpt-5.5-priority":
		return catalogModelDeployment{
			model:              "gpt-5.5",
			impliedServiceTier: &catalogPriorityServiceTier,
			allowedServiceTier: &catalogPriorityServiceTier,
		}, true
	default:
		return catalogModelDeployment{}, false
	}
}

func applyCatalogModelDeployment(model *string, serviceTier **schemas.BifrostServiceTier, deployment catalogModelDeployment) bool {
	if model == nil {
		return false
	}

	if deployment.allowedServiceTier != nil && *serviceTier != nil && **serviceTier != *deployment.allowedServiceTier {
		return false
	}
	if deployment.impliedServiceTier != nil && *serviceTier == nil {
		*serviceTier = deployment.impliedServiceTier
	}
	*model = deployment.model
	return true
}
