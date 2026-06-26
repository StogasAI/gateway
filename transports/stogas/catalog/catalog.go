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
	return DeploymentForRouteServiceTier(provider, model, route, nil)
}

func DeploymentForRouteServiceTier(provider schemas.ModelProvider, model string, route Route, requestedTier *schemas.BifrostServiceTier) (Deployment, bool) {
	snap := active.Load()
	if snap == nil {
		return Deployment{}, false
	}

	for _, routeNode := range snap.routes(provider, route) {
		deploymentID := snap.deploymentIDFor(routeNode, model)
		if deploymentID == "" {
			continue
		}
		deploymentID = snap.deploymentIDForRequestedServiceTier(provider, routeNode, deploymentID, requestedTier)
		deployment, ok := snap.deploymentFromCompiled(deploymentID, routeNode)
		if ok {
			return deployment, true
		}
	}
	return Deployment{}, false
}

func (s *snapshot) deploymentIDForRequestedServiceTier(provider schemas.ModelProvider, routeNode compiledProviderEndpoint, currentID string, requestedTier *schemas.BifrostServiceTier) string {
	targetTier := deploymentServiceTierForRequest(provider, requestedTier)
	if targetTier == "" {
		return currentID
	}
	current, ok := s.graph.Deployments[currentID]
	if !ok || current.ServiceTier == targetTier {
		return currentID
	}
	currentFast := deploymentIsFast(currentID, current)
	for _, candidateID := range routeNode.DeploymentIDs {
		candidate, ok := s.graph.Deployments[candidateID]
		if !ok ||
			candidate.ProviderID != current.ProviderID ||
			candidate.UpstreamModelSlug != current.UpstreamModelSlug ||
			candidate.ServiceTier != targetTier ||
			deploymentIsFast(candidateID, candidate) != currentFast {
			continue
		}
		return candidateID
	}
	return currentID
}

func deploymentServiceTierForRequest(provider schemas.ModelProvider, requestedTier *schemas.BifrostServiceTier) string {
	if provider != schemas.Anthropic || requestedTier == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(string(*requestedTier))) {
	case "auto", "priority":
		return "auto"
	case "default", "flex", "standard", "standard_only":
		return "standard_only"
	default:
		return ""
	}
}

func deploymentIsFast(deploymentID string, deployment compiledDeployment) bool {
	if strings.Contains(strings.ToLower(deploymentID), "-fast") {
		return true
	}
	for _, alias := range deployment.AliasSlugs {
		if strings.Contains(strings.ToLower(alias), "-fast") {
			return true
		}
	}
	return false
}

func DeploymentForActualExecution(provider schemas.ModelProvider, route Route, current Deployment, actualTier *schemas.BifrostServiceTier, actualSpeed string) (Deployment, bool) {
	snap := active.Load()
	if snap == nil || current.Model == "" {
		return Deployment{}, false
	}
	actualSpeed = strings.ToLower(strings.TrimSpace(actualSpeed))
	for _, routeNode := range snap.routes(provider, route) {
		for _, deploymentID := range routeNode.DeploymentIDs {
			deployment, ok := snap.graph.Deployments[deploymentID]
			if !ok || deployment.ProviderID != string(provider) || deployment.UpstreamModelSlug != current.Model {
				continue
			}
			if current.RegionID != "" && routeNode.RegionID != current.RegionID {
				continue
			}
			if actualTier != nil && !deploymentMatchesActualServiceTier(provider, deployment.ServiceTier, *actualTier) {
				continue
			}
			if actualSpeed != "" && !deploymentMatchesActualSpeed(deploymentID, deployment, actualSpeed) {
				continue
			}
			resolved, ok := snap.deploymentFromCompiled(deploymentID, routeNode)
			if ok {
				return resolved, true
			}
		}
	}
	return Deployment{}, false
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
	return ProviderForRouteModelRouting(route, requestedModel, ProviderRoutingPreference{})
}

func ProviderForRouteModelPreference(route Route, requestedModel string, preferredProvider string) (schemas.ModelProvider, bool, error) {
	preferredProvider = strings.TrimSpace(preferredProvider)
	if preferredProvider == "" {
		return ProviderForRouteModelRouting(route, requestedModel, ProviderRoutingPreference{})
	}
	return ProviderForRouteModelRouting(route, requestedModel, ProviderRoutingPreference{Only: []string{preferredProvider}})
}

func ProviderForRouteModelRouting(route Route, requestedModel string, preference ProviderRoutingPreference) (schemas.ModelProvider, bool, error) {
	snap := active.Load()
	if snap == nil {
		return "", false, nil
	}
	requested := strings.TrimSpace(requestedModel)
	if requested == "" {
		return "", false, nil
	}

	if preference.Empty() {
		return snap.providerForRouteModel(route, requested, nil)
	}

	only, err := snap.resolveProviderPreferences(preference.Only)
	if err != nil {
		return "", false, err
	}
	order, err := snap.resolveProviderPreferences(preference.Order)
	if err != nil {
		return "", false, err
	}
	allowed := map[schemas.ModelProvider]bool(nil)
	if len(only) > 0 {
		allowed = make(map[schemas.ModelProvider]bool, len(only))
		for _, provider := range only {
			allowed[provider] = true
		}
	}
	candidates := snap.routeModelProviders(route, requested, allowed)
	if len(candidates) == 0 {
		return "", false, ErrModelUnavailable
	}
	for _, preferred := range order {
		for _, candidate := range candidates {
			if candidate == preferred {
				return candidate, true, nil
			}
		}
	}
	if len(candidates) == 1 {
		return candidates[0], true, nil
	}
	return "", false, ErrModelAmbiguous
}

func (s *snapshot) providerForRouteModel(route Route, requested string, allowed map[schemas.ModelProvider]bool) (schemas.ModelProvider, bool, error) {
	candidates := s.routeModelProviders(route, requested, allowed)
	if len(candidates) == 0 {
		return "", false, nil
	}
	if len(candidates) > 1 {
		return "", false, ErrModelAmbiguous
	}
	return candidates[0], true, nil
}

func (s *snapshot) routeModelProviders(route Route, requested string, allowed map[schemas.ModelProvider]bool) []schemas.ModelProvider {
	seen := map[schemas.ModelProvider]bool{}
	providers := []schemas.ModelProvider{}
	for _, routeNode := range s.graph.ProviderEndpoints {
		if !endpointSupportsRoute(routeNode, route) {
			continue
		}
		if s.deploymentIDFor(routeNode, requested) == "" {
			continue
		}
		provider := schemas.ModelProvider(routeNode.ProviderID)
		if allowed != nil && !allowed[provider] {
			continue
		}
		if seen[provider] {
			continue
		}
		seen[provider] = true
		providers = append(providers, provider)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i] < providers[j] })
	return providers
}

func (s *snapshot) resolveProviderPreferences(preferences []string) ([]schemas.ModelProvider, error) {
	if len(preferences) == 0 {
		return nil, nil
	}
	providers := make([]schemas.ModelProvider, 0, len(preferences))
	seen := map[schemas.ModelProvider]bool{}
	for _, preference := range preferences {
		provider, ok := s.providerForPreference(preference)
		if !ok {
			return nil, ErrProviderUnavailable
		}
		if seen[provider] {
			continue
		}
		seen[provider] = true
		providers = append(providers, provider)
	}
	return providers, nil
}

func (s *snapshot) providerForPreference(preference string) (schemas.ModelProvider, bool) {
	normalized := strings.ToLower(strings.TrimSpace(preference))
	if normalized == "" {
		return "", false
	}
	for providerID, provider := range s.graph.Providers {
		if strings.EqualFold(providerID, normalized) {
			return schemas.ModelProvider(providerID), true
		}
		for _, slug := range provider.ProviderSlugs {
			if strings.EqualFold(strings.TrimSpace(slug), normalized) {
				return schemas.ModelProvider(providerID), true
			}
		}
	}
	return "", false
}

func ProviderUsesPseudoanonymousUserID(provider schemas.ModelProvider) bool {
	snap := active.Load()
	if snap == nil {
		return false
	}
	providerNode, ok := snap.graph.Providers[string(provider)]
	return ok && providerNode.UsesPseudoanonymousUserID
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
	routes := s.routes(provider, route)
	if len(routes) == 0 {
		return compiledProviderEndpoint{}, false
	}
	return routes[0], true
}

func (s *snapshot) routes(provider schemas.ModelProvider, route Route) []compiledProviderEndpoint {
	routes := []compiledProviderEndpoint{}
	for _, routeNode := range s.graph.ProviderEndpoints {
		if routeNode.ProviderID == string(provider) && endpointSupportsRoute(routeNode, route) {
			routes = append(routes, routeNode)
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].ID < routes[j].ID
	})
	return routes
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
	return s.providerEndpointRequestSlugs[route.ID+":"+requested]
}

func (s *snapshot) deploymentFromCompiled(deploymentID string, route compiledProviderEndpoint) (Deployment, bool) {
	deployment, ok := s.graph.Deployments[deploymentID]
	if !ok || deployment.ProviderID != route.ProviderID {
		return Deployment{}, false
	}
	modelNode, ok := s.graph.Models[deployment.ModelID]
	if !ok {
		return Deployment{}, false
	}
	return Deployment{
		ID:                  deploymentID,
		ModelID:             deployment.ModelID,
		Model:               deployment.UpstreamModelSlug,
		ContextWindowTokens: effectiveContextWindowTokens(deployment, modelNode),
		ImpliedServiceTier:  impliedServiceTierForDeployment(schemas.ModelProvider(deployment.ProviderID), deployment),
		MaxOutputTokens:     effectiveMaxOutputTokens(deployment, modelNode),
		Pricing:             deployment.Pricing,
		ReasoningSupported:  modelNode.ReasoningSupport,
		RegionID:            route.RegionID,
		ServiceTier:         deployment.ServiceTier,
	}, true
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

func deploymentMatchesActualServiceTier(provider schemas.ModelProvider, deploymentTier string, actual schemas.BifrostServiceTier) bool {
	deploymentTier = strings.ToLower(strings.TrimSpace(deploymentTier))
	actualValue := strings.ToLower(strings.TrimSpace(string(actual)))
	if provider == schemas.Anthropic {
		switch actualValue {
		case "priority", "auto":
			return deploymentTier == "auto"
		case "default", "standard", "standard_only", "":
			return deploymentTier == "standard_only" || deploymentTier == "standard"
		default:
			return false
		}
	}
	switch actualValue {
	case "priority":
		return deploymentTier == "priority"
	case "flex":
		return deploymentTier == "flex"
	case "default", "standard", "standard_only", "auto", "":
		return deploymentTier == "" || deploymentTier == "default" || deploymentTier == "standard"
	default:
		return false
	}
}

func deploymentMatchesActualSpeed(deploymentID string, deployment compiledDeployment, actualSpeed string) bool {
	fast := deploymentIsFast(deploymentID, deployment)
	switch actualSpeed {
	case "fast":
		return fast
	case "standard":
		return !fast
	default:
		return true
	}
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
