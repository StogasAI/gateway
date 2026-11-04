package catalog

import (
	"slices"
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
	return stateAt(time.Now())
}

// stateAt returns the state of the active catalog in effect at an instant. A request reads the
// catalog at the instant that it started, so every step sees the same state and dates.
func stateAt(at time.Time) *snapshot {
	snap := active.Load()
	if snap == nil {
		return nil
	}
	return snap.at(at)
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
	now := time.Now()
	for _, routeNode := range snap.routes(provider, route) {
		for _, deploymentID := range routeNode.DeploymentIDs {
			compiled, ok := snap.graph.Deployments[deploymentID]
			if !ok || !servesAt(compiled, routeNode, now) || compiled.Upstream.Model != upstreamModel {
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

// deploymentAvailableAt says whether a deployment serves at now: until its retirement date has
// ended everywhere on Earth.
func deploymentAvailableAt(deployment *compiledDeployment, now time.Time) bool {
	return !retiredAt(deployment.RetirementDate, now)
}

// servesAt says whether a deployment serves through a route at now: until the date of each has
// ended everywhere on Earth. A deployment that the route alone serves carries the route's date
// already; one that another route serves too goes on through that one.
func servesAt(deployment *compiledDeployment, route compiledRoute, now time.Time) bool {
	return deploymentAvailableAt(deployment, now) && !retiredAt(route.RetirementDate, now)
}

// sibling returns the deployment available at an instant on the route that differs from current
// only in its tier and reasoning mode. The provider's model name can differ, because Azure sells
// Claude Fast as its own model; the catalog allows one such deployment.
func (s *snapshot) sibling(routeNode compiledRoute, current *compiledDeployment, tier, mode string, at time.Time) string {
	for _, candidateID := range routeNode.DeploymentIDs {
		candidate, ok := s.graph.Deployments[candidateID]
		if ok &&
			servesAt(candidate, routeNode, at) &&
			candidate.Upstream.ServiceTier == tier &&
			candidate.ModelID == current.ModelID &&
			candidate.Upstream.ReasoningMode == mode &&
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
		standardID := snap.sibling(routeNode, currentCompiled, TierStandard, currentCompiled.Upstream.ReasoningMode, at)
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

// providerForPreference finds a provider by its ID or an alias, matched as the model field
// matches IDs.
func (s *snapshot) providerForPreference(preference string) (schemas.ModelProvider, bool) {
	providerID, ok := s.index.providers[normalizedID(strings.TrimSpace(preference))]
	return schemas.ModelProvider(providerID), ok
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
	if !ok || !servesAt(deployment, route, at) {
		return Deployment{}, false
	}
	served, ok := deployment.Routes[route.ID]
	if !ok {
		return Deployment{}, false
	}
	var reasoningMaxTokens *ReasoningMaxTokens
	if deployment.ReasoningMaxTokens != nil {
		value := *deployment.ReasoningMaxTokens
		reasoningMaxTokens = &value
	}
	return Deployment{
		ID:        deploymentID,
		ModelID:   deployment.ModelID,
		RouteID:   route.ID,
		ChainHash: served.ChainHash,
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
		Capabilities: served.Capabilities,
		DocumentFormats: DocumentFormats{
			MediaTypes: slices.Clone(route.DocumentFormats.MediaTypes),
			Extensions: slices.Clone(route.DocumentFormats.Extensions),
		},
		InputModalities:     slices.Clone(served.InputModalities),
		OutputModalities:    slices.Clone(deployment.OutputModalities),
		ContextWindowTokens: deployment.ContextWindowTokens,
		MaxInputTokens:      deployment.MaxInputTokens,
		MaxOutputTokens:     deployment.MaxOutputTokens,
		Pricing:             served.Pricing,
		Reasoning:           deployment.Reasoning,
		ReasoningEfforts:    slices.Clone(served.ReasoningEfforts),
		ReasoningMaxTokens:  reasoningMaxTokens,
		ReasoningSupported:  deployment.Reasoning != "unsupported",
		DataHandling:        served.DataHandling,
		HostedTools:         served.HostedTools,
		Locations:           s.places,
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
	return slices.Contains(catalogRoute.Interfaces, route.Interface())
}
