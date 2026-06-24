package catalog

import (
	"sort"
	"strings"
	"sync/atomic"

	"github.com/maximhq/bifrost/core/schemas"
)

var active atomic.Pointer[snapshot]

func init() {
	if snap, err := loadSnapshot(); err == nil {
		active.Store(snap)
	}
}

func DeploymentForRoute(provider schemas.ModelProvider, model string, route Route) (Deployment, bool) {
	snap := active.Load()
	if snap == nil {
		return Deployment{}, false
	}

	routeNode, ok := snap.route(provider, route)
	if !ok {
		return Deployment{}, false
	}
	deploymentID := snap.deploymentIDFor(routeNode, model)
	if deploymentID == "" {
		return Deployment{}, false
	}
	deployment, ok := snap.graph.Deployments[deploymentID]
	if !ok || deployment.ProviderID != string(provider) {
		return Deployment{}, false
	}
	modelNode, ok := snap.graph.Models[deployment.ModelID]
	if !ok {
		return Deployment{}, false
	}

	impliedTier := impliedServiceTierForDeployment(schemas.ModelProvider(deployment.ProviderID), deployment)
	return Deployment{
		ID:                  deploymentID,
		ModelID:             deployment.ModelID,
		Model:               deployment.UpstreamModelSlug,
		ContextWindowTokens: effectiveContextWindowTokens(deployment, modelNode),
		ImpliedServiceTier:  impliedTier,
		MaxOutputTokens:     effectiveMaxOutputTokens(deployment, modelNode),
		Pricing:             deployment.Pricing,
		ReasoningSupported:  modelNode.ReasoningSupport,
		ServiceTier:         deployment.ServiceTier,
	}, true
}

func ProviderForRoute(route Route) (schemas.ModelProvider, bool) {
	snap := active.Load()
	if snap == nil {
		return "", false
	}
	var selected schemas.ModelProvider
	for _, routeNode := range snap.graph.ProviderEndpoints {
		if !endpointSupportsRoute(routeNode, route) || routeNode.ProviderID == "" {
			continue
		}
		provider := schemas.ModelProvider(routeNode.ProviderID)
		if selected != "" && selected != provider {
			return "", false
		}
		selected = provider
	}
	return selected, selected != ""
}

func ProviderForRouteModel(route Route, requestedModel string) (schemas.ModelProvider, bool, error) {
	snap := active.Load()
	if snap == nil {
		return "", false, nil
	}
	requested := strings.TrimSpace(requestedModel)
	if requested == "" {
		return "", false, nil
	}

	var selected schemas.ModelProvider
	for _, routeNode := range snap.graph.ProviderEndpoints {
		if !endpointSupportsRoute(routeNode, route) {
			continue
		}
		if snap.deploymentIDFor(routeNode, requested) == "" {
			continue
		}
		provider := schemas.ModelProvider(routeNode.ProviderID)
		if selected != "" && selected != provider {
			return "", false, ErrModelAmbiguous
		}
		selected = provider
	}
	return selected, selected != "", nil
}

func PathForRoute(route Route) (string, bool) {
	spec, ok := specForRoute(route)
	return spec.Path, ok
}

func RouteForPath(path string) (Route, bool) {
	normalized := strings.TrimSpace(path)
	route, ok := routeByPath[normalized]
	return route, ok
}

func InferencePaths() []string {
	paths := []string{}
	for _, spec := range routeSpecs {
		paths = append(paths, spec.Path)
	}
	return stableStrings(paths)
}

func FilterExtraParams(_ schemas.ModelProvider, _ string, route Route, params map[string]interface{}) map[string]interface{} {
	if len(params) == 0 {
		return nil
	}
	known := parameterSet(route)
	if len(known) == 0 {
		return nil
	}
	filtered := make(map[string]interface{})
	for name, value := range params {
		if known[name] {
			filtered[name] = value
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func AuthHeaderNames(route Route) []string {
	spec, ok := specForRoute(route)
	if !ok || len(spec.AuthHeaders) == 0 {
		return []string{canonicalAuthHeader}
	}
	return stableAuthHeaderOrder(spec.AuthHeaders)
}

func ClientHeaderNames(route Route) []string {
	spec, ok := specForRoute(route)
	if !ok {
		return nil
	}
	return stableHeaderOrder(spec.Headers)
}

func AllClientHeaderNames() []string {
	return append([]string(nil), allClientHeaderNamesValue...)
}

func AllClientHeadersValue() string {
	return allClientHeadersValue
}

func AllowsResponseMetadataField(name string) bool {
	snap := active.Load()
	if snap == nil {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(name))
	_, ok := snap.responseMetadataFields[normalized]
	return ok
}

func KnownFields(route Route) map[string]bool {
	return parameterSet(route)
}

func ParameterAliasFor(route Route, name string) (string, bool) {
	if route == RouteChat && name == "max_tokens" {
		return "max_completion_tokens", true
	}
	return "", false
}

func (s *snapshot) route(provider schemas.ModelProvider, route Route) (compiledProviderEndpoint, bool) {
	for _, routeNode := range s.graph.ProviderEndpoints {
		if routeNode.ProviderID == string(provider) && endpointSupportsRoute(routeNode, route) {
			return routeNode, true
		}
	}
	return compiledProviderEndpoint{}, false
}

func providerEndpointForRoute(provider schemas.ModelProvider, route Route) (compiledProviderEndpoint, bool) {
	snap := active.Load()
	if snap == nil {
		return compiledProviderEndpoint{}, false
	}
	return snap.route(provider, route)
}

func (s *snapshot) deploymentIDFor(route compiledProviderEndpoint, requestedModel string) string {
	requested := strings.TrimSpace(requestedModel)
	if requested == "" {
		return ""
	}
	return s.providerNativeModelSlugs[route.ID+":"+requested]
}

func (s *snapshot) allowsParam(route compiledProviderEndpoint, name string) bool {
	known := parameterSet(firstPublicRouteName(route))
	return known[name]
}

func effectiveContextWindowTokens(deployment compiledDeployment, model compiledModel) int {
	if deployment.ContextWindowTokens != nil && *deployment.ContextWindowTokens > 0 {
		return *deployment.ContextWindowTokens
	}
	return model.ContextWindowTokens
}

func effectiveMaxOutputTokens(deployment compiledDeployment, model compiledModel) int {
	if deployment.MaxOutputTokens != nil && *deployment.MaxOutputTokens > 0 {
		return *deployment.MaxOutputTokens
	}
	return model.MaxOutputTokens
}

func stableAuthHeaderOrder(names []string) []string {
	priority := map[string]int{
		canonicalAuthHeader: 0,
		"api-key":           1,
		"x-api-key":         2,
		"x-goog-api-key":    3,
	}
	ordered := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		ordered = append(ordered, normalized)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		leftPriority := headerPriority(priority, ordered[i])
		rightPriority := headerPriority(priority, ordered[j])
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return ordered[i] < ordered[j]
	})
	return ordered
}

func stableHeaderOrder(names []string) []string {
	ordered := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		ordered = append(ordered, normalized)
	}
	return stableStrings(ordered)
}

func stableStrings(values []string) []string {
	sort.Strings(values)
	return values
}

func headerPriority(priority map[string]int, name string) int {
	if value, ok := priority[name]; ok {
		return value
	}
	return 100
}

func endpointSupportsRoute(endpoint compiledProviderEndpoint, route Route) bool {
	for _, stogasEndpointID := range endpoint.StogasEndpoints {
		if publicRouteName(stogasEndpointID) == route {
			return true
		}
	}
	return false
}

func firstPublicRouteName(endpoint compiledProviderEndpoint) Route {
	for _, stogasEndpointID := range endpoint.StogasEndpoints {
		if route := publicRouteName(stogasEndpointID); route != "" {
			return route
		}
	}
	return ""
}

func publicRouteName(stogasEndpointID string) Route {
	return Route(strings.TrimPrefix(stogasEndpointID, "stogas-"))
}
