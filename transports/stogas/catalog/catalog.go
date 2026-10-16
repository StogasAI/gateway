package catalog

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

var active atomic.Pointer[snapshot]
var activationMu sync.RWMutex

func init() {
	snap, err := loadSnapshot()
	if err != nil {
		panic("load embedded catalog: " + err.Error())
	}
	active.Store(snap)
}

// activeState returns the state of the active catalog in effect now.
func activeState() *snapshot {
	snap := active.Load()
	if snap == nil {
		return nil
	}
	return snap.at(time.Now())
}

// at returns the catalog state in effect at an instant.
func (s *snapshot) at(instant time.Time) *snapshot {
	state := s
	for _, entry := range s.schedule {
		if instant.Before(entry.start) {
			break
		}
		state = entry.state
	}
	return state
}

// DeploymentForUpstreamModel resolves the exact model identifier already placed
// on a provider request. It is intentionally exact: aliases and public model
// selectors must be resolved before the provider wire is built.
func DeploymentForUpstreamModel(provider schemas.ModelProvider, upstreamModel string, route Route) (Deployment, bool) {
	snap := activeState()
	if snap == nil || upstreamModel == "" {
		return Deployment{}, false
	}
	var match Deployment
	found := false
	for _, routeNode := range snap.routes(provider, route) {
		for _, deploymentID := range routeNode.DeploymentIDs {
			compiled, ok := snap.graph.Deployments[deploymentID]
			if !ok || !deploymentAvailableNow(compiled) || compiled.Upstream.Model != upstreamModel {
				continue
			}
			deployment, ok := snap.deploymentFromCompiled(deploymentID, routeNode)
			if !ok || found {
				return Deployment{}, false
			}
			match = deployment
			found = true
		}
	}
	return match, found
}

// deploymentForRouteTier resolves a model selector on the provider's routes. A requested tier
// moves a model selector to the deployment that runs at that tier; an exact deployment selector
// must already run at it.
func (s *snapshot) deploymentForRouteTier(provider schemas.ModelProvider, model string, route Route, tier string) (Deployment, bool) {
	for _, routeNode := range s.routes(provider, route) {
		deploymentID, pinned := s.deploymentIDFor(routeNode, model)
		if deploymentID == "" {
			continue
		}
		if current := s.graph.Deployments[deploymentID]; tier != "" && current.Upstream.ServiceTier != tier {
			if pinned {
				continue
			}
			deploymentID = s.tierSibling(routeNode, current, tier, time.Now())
		}
		deployment, ok := s.deploymentFromCompiled(deploymentID, routeNode)
		if ok {
			return deployment, true
		}
	}
	return Deployment{}, false
}

func deploymentAvailableAt(deployment compiledDeployment, now time.Time) bool {
	return deployment.DeprecationDate == nil ||
		*deployment.DeprecationDate > now.UTC().Format(time.DateOnly)
}

func deploymentAvailableNow(deployment compiledDeployment) bool {
	return deploymentAvailableAt(deployment, time.Now())
}

// tierSibling returns the deployment available at an instant on the route that differs from
// current only in running at tier.
func (s *snapshot) tierSibling(routeNode compiledRoute, current compiledDeployment, tier string, at time.Time) string {
	for _, candidateID := range routeNode.DeploymentIDs {
		candidate, ok := s.graph.Deployments[candidateID]
		if ok &&
			deploymentAvailableAt(candidate, at) &&
			candidate.Upstream.ServiceTier == tier &&
			candidate.ModelID == current.ModelID &&
			candidate.Upstream.Model == current.Upstream.Model &&
			candidate.Upstream.ReasoningMode == current.Upstream.ReasoningMode &&
			candidate.Upstream.Hosting == current.Upstream.Hosting &&
			candidate.Upstream.ModelFormat == current.Upstream.ModelFormat &&
			candidate.Upstream.ModelVersion == current.Upstream.ModelVersion &&
			candidate.Upstream.DeploymentType == current.Upstream.DeploymentType &&
			candidate.Upstream.InferenceGeo == current.Upstream.InferenceGeo {
			return candidateID
		}
	}
	return ""
}

// StandardTierDeployment returns the Standard tier sibling of current, which prices a Fast
// request that the provider ran at Standard.
func StandardTierDeployment(provider schemas.ModelProvider, route Route, current Deployment) (Deployment, bool) {
	snap, at := current.snapshot, current.startedAt
	if snap == nil {
		return Deployment{}, false
	}
	currentCompiled, ok := snap.graph.Deployments[current.ID]
	if !ok {
		return Deployment{}, false
	}
	for _, routeNode := range snap.routes(provider, route) {
		if routeNode.ProviderID != string(provider) {
			continue
		}
		standardID := snap.tierSibling(routeNode, currentCompiled, TierStandard, at)
		if standardID == "" {
			continue
		}
		if resolved, ok := snap.deploymentFromCompiledAt(standardID, routeNode, at); ok {
			return resolved, true
		}
	}
	return Deployment{}, false
}

func providerInList(provider schemas.ModelProvider, providers []schemas.ModelProvider) bool {
	for _, candidate := range providers {
		if candidate == provider {
			return true
		}
	}
	return false
}

func (s *snapshot) routeModelProviders(route Route, requested string, allowed map[string][]int) []schemas.ModelProvider {
	seen := map[schemas.ModelProvider]bool{}
	providers := []schemas.ModelProvider{}
	// Exact deployment selectors visit only that deployment's routes.
	_, selector := splitQualifiedModel(requested)
	if deployment, pinned := s.graph.Deployments[selector]; pinned {
		for _, routeID := range deployment.RouteIDs {
			routeNode := s.graph.Routes[routeID]
			provider := schemas.ModelProvider(routeNode.ProviderID)
			if !routeSupportsInterface(routeNode, route) || (allowed != nil && len(allowed[routeNode.ProviderID]) == 0) {
				continue
			}
			if deploymentID, _ := s.deploymentIDFor(routeNode, requested); deploymentID != "" && !seen[provider] {
				seen[provider] = true
				providers = append(providers, provider)
			}
		}
		return providers
	}
	for _, routeNode := range s.graph.Routes {
		if !routeSupportsInterface(routeNode, route) {
			continue
		}
		provider := schemas.ModelProvider(routeNode.ProviderID)
		if allowed != nil && len(allowed[string(provider)]) == 0 {
			continue
		}
		if deploymentID, _ := s.deploymentIDFor(routeNode, requested); deploymentID == "" {
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
		if qualifierMatchesIDOrAlias(normalized, providerID, provider.Aliases) {
			return schemas.ModelProvider(providerID), true
		}
	}
	return "", false
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

func FilterExtraParams(provider schemas.ModelProvider, _ string, route Route, params map[string]interface{}) map[string]interface{} {
	if len(params) == 0 {
		return nil
	}
	allowed := allowedClientExtraParams(provider, route)
	if len(allowed) == 0 {
		return nil
	}
	filtered := make(map[string]interface{})
	for name, value := range params {
		if allowed[name] {
			filtered[name] = value
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func allowedClientExtraParams(provider schemas.ModelProvider, route Route) map[string]bool {
	if provider == ProviderChutes && route == RouteChat {
		return map[string]bool{"repetition_penalty": true}
	}
	if provider == schemas.Anthropic && route == RouteResponses {
		return map[string]bool{
			"cache_control":      true,
			"context_management": true,
			"task_budget":        true,
		}
	}
	if provider == schemas.Azure && route == RouteResponses {
		return map[string]bool{
			"cache_control":      true,
			"context_management": true,
		}
	}
	return nil
}

func AuthHeaderNames(route Route) []string {
	spec, ok := specForRoute(route)
	if !ok || len(spec.AuthHeaders) == 0 {
		return []string{canonicalAuthHeader}
	}
	return stableAuthHeaderOrder(spec.AuthHeaders)
}

func AllClientHeadersValue() string {
	return allClientHeadersValue
}

func KnownFields(route Route) map[string]bool {
	return parameterSet(route)
}

func (s *snapshot) route(provider schemas.ModelProvider, route Route) (compiledRoute, bool) {
	routes := s.routes(provider, route)
	if len(routes) == 0 {
		return compiledRoute{}, false
	}
	return routes[0], true
}

func (s *snapshot) routes(provider schemas.ModelProvider, route Route) []compiledRoute {
	routes := []compiledRoute{}
	for _, routeNode := range s.graph.Routes {
		if routeNode.ProviderID == string(provider) && routeSupportsInterface(routeNode, route) {
			routes = append(routes, routeNode)
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].ID < routes[j].ID
	})
	return routes
}

func catalogRouteForRequest(provider schemas.ModelProvider, route Route) (compiledRoute, bool) {
	snap := activeState()
	if snap == nil {
		return compiledRoute{}, false
	}
	return snap.route(provider, route)
}

func (s *snapshot) deploymentIDFor(route compiledRoute, requestedModel string) (string, bool) {
	qualifier, selector := splitQualifiedModel(requestedModel)
	if selector == "" {
		return "", false
	}
	if deployment, ok := s.graph.Deployments[selector]; ok {
		if !deploymentAvailableNow(deployment) ||
			!stringIn(deployment.RouteIDs, route.ID) ||
			!s.qualifierMatches(qualifier, route.ProviderID, deployment.ModelID) {
			return "", false
		}
		return selector, true
	}
	modelID, ok := s.modelSelectors[selector]
	if !ok || !s.qualifierMatches(qualifier, route.ProviderID, modelID) {
		return "", false
	}
	matchingDeploymentIDs := make([]string, 0, 1)
	for _, deploymentID := range route.DeploymentIDs {
		deployment, exists := s.graph.Deployments[deploymentID]
		if exists &&
			deploymentAvailableNow(deployment) &&
			deployment.ModelID == modelID {
			matchingDeploymentIDs = append(matchingDeploymentIDs, deploymentID)
		}
	}
	if len(matchingDeploymentIDs) == 1 {
		return matchingDeploymentIDs[0], false
	}
	baseID := route.ProviderID + "-" + modelID
	if stringIn(matchingDeploymentIDs, baseID) {
		return baseID, false
	}
	return "", false
}

func splitQualifiedModel(requested string) ([]string, string) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(requested)), "/")
	switch len(parts) {
	case 1:
		if parts[0] == "" {
			return nil, ""
		}
		return nil, parts[0]
	case 2, 3:
		for _, part := range parts {
			if part == "" || strings.TrimSpace(part) != part {
				return nil, ""
			}
		}
		return parts[:len(parts)-1], parts[len(parts)-1]
	default:
		return nil, ""
	}
}

func (s *snapshot) qualifierMatches(qualifier []string, providerID, modelID string) bool {
	if len(qualifier) == 0 {
		return true
	}
	provider, ok := s.graph.Providers[providerID]
	if !ok ||
		!qualifierMatchesIDOrAlias(
			qualifier[len(qualifier)-1],
			providerID,
			provider.Aliases,
		) {
		return false
	}
	if len(qualifier) == 1 {
		return true
	}
	model, ok := s.graph.Models[modelID]
	if !ok {
		return false
	}
	author, ok := s.graph.Authors[model.AuthorID]
	return ok && qualifierMatchesIDOrAlias(qualifier[0], model.AuthorID, author.Aliases)
}

func qualifierMatchesIDOrAlias(value, id string, aliases []string) bool {
	if strings.EqualFold(value, id) {
		return true
	}
	for _, alias := range aliases {
		if strings.EqualFold(value, alias) {
			return true
		}
	}
	return false
}

func stringIn(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (s *snapshot) deploymentFromCompiled(deploymentID string, route compiledRoute) (Deployment, bool) {
	return s.deploymentFromCompiledAt(deploymentID, route, time.Now())
}

// deploymentFromCompiledAt resolves the deployment for a request that started at an instant.
func (s *snapshot) deploymentFromCompiledAt(deploymentID string, route compiledRoute, at time.Time) (Deployment, bool) {
	deployment, ok := s.graph.Deployments[deploymentID]
	if !ok ||
		!deploymentAvailableAt(deployment, at) ||
		!stringIn(deployment.RouteIDs, route.ID) {
		return Deployment{}, false
	}
	_, ok = s.graph.Models[deployment.ModelID]
	if !ok {
		return Deployment{}, false
	}
	capabilities := deployment.Capabilities
	capabilities.InputModalities = append([]string(nil), deployment.InputModalities...)
	capabilities.OutputModalities = append([]string(nil), deployment.OutputModalities...)
	dataHandling, exists := deployment.DataHandlingByRoute[route.ID]
	if !exists {
		return Deployment{}, false
	}
	nativeFileInputs, exists := deployment.NativeFileInputsByRoute[route.ID]
	if !exists {
		return Deployment{}, false
	}
	var reasoningMaxTokens *ReasoningMaxTokens
	if deployment.ReasoningMaxTokens != nil {
		value := *deployment.ReasoningMaxTokens
		reasoningMaxTokens = &value
	}
	reasoningEfforts := deployment.ReasoningEfforts
	if override, exists := deployment.RouteOverrides[route.ID]; exists {
		reasoningEfforts = override.ReasoningEfforts
	}
	return Deployment{
		ID:        deploymentID,
		ModelID:   deployment.ModelID,
		ChainHash: deployment.ChainHashes[route.ID],
		Upstream: Upstream{
			Model:          deployment.Upstream.Model,
			ModelFormat:    deployment.Upstream.ModelFormat,
			ModelVersion:   deployment.Upstream.ModelVersion,
			ChuteID:        deployment.Upstream.ChuteID,
			GPUCount:       deployment.Upstream.GPUCount,
			InferenceGeo:   deployment.Upstream.InferenceGeo,
			ReasoningMode:  deployment.Upstream.ReasoningMode,
			ServiceTier:    deployment.Upstream.ServiceTier,
			Hosting:        deployment.Upstream.Hosting,
			DeploymentType: deployment.Upstream.DeploymentType,
		},
		Capabilities:        capabilities,
		NativeFileInputs:    NativeFileInputs{MediaTypes: append([]string{}, nativeFileInputs.MediaTypes...), Extensions: append([]string{}, nativeFileInputs.Extensions...)},
		ContextWindowTokens: deployment.ContextWindowTokens,
		MaxInputTokens:      deployment.MaxInputTokens,
		MaxOutputTokens:     deployment.MaxOutputTokens,
		Pricing:             deployment.Pricing,
		RouteIDs:            []string{route.ID},
		Reasoning:           deployment.Reasoning,
		ReasoningEfforts:    append([]string(nil), reasoningEfforts...),
		ReasoningMaxTokens:  reasoningMaxTokens,
		ReasoningSupported:  deployment.Reasoning != "unsupported",
		DataHandling:        dataHandling,
		ApprovalRequired:    deployment.ApprovalRequired,
		WeightPrecision:     deployment.WeightPrecision,
		snapshot:            s,
		startedAt:           at,
	}, true
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

func routeSupportsInterface(catalogRoute compiledRoute, route Route) bool {
	for _, interfaceName := range catalogRoute.Interfaces {
		if publicRouteName(interfaceName) == route {
			return true
		}
	}
	return false
}

func firstInterfaceRoute(catalogRoute compiledRoute) Route {
	for _, interfaceName := range catalogRoute.Interfaces {
		if route := publicRouteName(interfaceName); route != "" {
			return route
		}
	}
	return ""
}

func publicRouteName(interfaceName string) Route {
	return Route(strings.ReplaceAll(strings.TrimSpace(interfaceName), "_", "-"))
}
