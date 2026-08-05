package catalog

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
)

var active atomic.Pointer[snapshot]
var activationMu sync.RWMutex

func init() {
	if snap, err := loadSnapshot(); err == nil {
		active.Store(snap)
	}
}

func DeploymentForRoute(provider schemas.ModelProvider, model string, route Route) (Deployment, bool) {
	return DeploymentForRouteServiceTier(provider, model, route, nil)
}

// DeploymentForUpstreamModel resolves the exact model identifier already placed
// on a provider request. It is intentionally exact: aliases and public model
// selectors must be resolved before the provider wire is built.
func DeploymentForUpstreamModel(provider schemas.ModelProvider, upstreamModel string, route Route) (Deployment, bool) {
	snap := active.Load()
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

func DeploymentForRouteServiceTier(provider schemas.ModelProvider, model string, route Route, requestedTier *schemas.BifrostServiceTier) (Deployment, bool) {
	snap := active.Load()
	if snap == nil {
		return Deployment{}, false
	}

	for _, routeNode := range snap.routes(provider, route) {
		deploymentID, pinned := snap.deploymentIDFor(routeNode, model)
		if deploymentID == "" {
			continue
		}
		if pinned {
			deployment, ok := snap.graph.Deployments[deploymentID]
			if !ok {
				continue
			}
			if !deploymentMatchesRequestedTier(provider, deployment, requestedTier) {
				if !deploymentAliasCanSelectTier(provider, model, deploymentID, deployment, requestedTier) {
					continue
				}
				deploymentID = snap.deploymentIDForRequestedServiceTier(provider, routeNode, deploymentID, requestedTier)
				deployment, ok = snap.graph.Deployments[deploymentID]
				if !ok || !deploymentMatchesRequestedTier(provider, deployment, requestedTier) {
					continue
				}
			}
		} else {
			deploymentID = snap.deploymentIDForRequestedServiceTier(provider, routeNode, deploymentID, requestedTier)
		}
		deployment, ok := snap.deploymentFromCompiled(deploymentID, routeNode)
		if ok {
			return deployment, true
		}
	}
	return Deployment{}, false
}

func deploymentAliasCanSelectTier(
	provider schemas.ModelProvider,
	requestedModel string,
	deploymentID string,
	deployment compiledDeployment,
	requestedTier *schemas.BifrostServiceTier,
) bool {
	if deploymentServiceTierForRequest(provider, requestedTier) == "" ||
		deployment.Upstream.ReasoningMode == "" ||
		impliedServiceTierForDeployment(provider, deployment) != nil {
		return false
	}
	_, selector := splitQualifiedModel(requestedModel)
	return selector != "" && selector != strings.ToLower(deploymentID)
}

func deploymentMatchesRequestedTier(
	provider schemas.ModelProvider,
	deployment compiledDeployment,
	requestedTier *schemas.BifrostServiceTier,
) bool {
	if requestedTier != nil {
		target := deploymentServiceTierForRequest(provider, requestedTier)
		if target == "" || deployment.Upstream.ServiceTier != target {
			return false
		}
	}
	return true
}

func deploymentAvailableAt(deployment compiledDeployment, now time.Time) bool {
	return deployment.DeprecationDate == nil ||
		*deployment.DeprecationDate > now.UTC().Format(time.DateOnly)
}

func deploymentAvailableNow(deployment compiledDeployment) bool {
	return deploymentAvailableAt(deployment, time.Now())
}

func (s *snapshot) deploymentIDForRequestedServiceTier(provider schemas.ModelProvider, routeNode compiledRoute, currentID string, requestedTier *schemas.BifrostServiceTier) string {
	targetTier := deploymentServiceTierForRequest(provider, requestedTier)
	if targetTier == "" {
		return currentID
	}
	current, ok := s.graph.Deployments[currentID]
	if !ok || !deploymentAvailableNow(current) {
		return ""
	}
	if current.Upstream.ServiceTier == targetTier {
		return currentID
	}
	if impliedServiceTierForDeployment(provider, current) != nil {
		return currentID
	}
	currentFast := deploymentIsFast(current)
	currentReasoningMode := current.Upstream.ReasoningMode
	for _, candidateID := range routeNode.DeploymentIDs {
		candidate, ok := s.graph.Deployments[candidateID]
		if !ok ||
			!deploymentAvailableNow(candidate) ||
			candidate.ModelID != current.ModelID ||
			candidate.Upstream.ServiceTier != targetTier ||
			candidate.Upstream.ReasoningMode != currentReasoningMode ||
			deploymentIsFast(candidate) != currentFast {
			continue
		}
		return candidateID
	}
	return currentID
}

func deploymentServiceTierForRequest(provider schemas.ModelProvider, requestedTier *schemas.BifrostServiceTier) string {
	if requestedTier == nil {
		return ""
	}
	value := strings.ToLower(strings.TrimSpace(string(*requestedTier)))
	switch provider {
	case schemas.OpenAI:
		switch value {
		case "auto", "default", "":
			return "default"
		case "flex":
			return value
		case "fast", "priority":
			return "priority"
		}
	case schemas.Azure:
		switch value {
		case "auto", "default", "":
			return ""
		}
	case schemas.Anthropic:
		switch value {
		case "default", "standard", "standard_only", "":
			return "standard_only"
		}
	}
	return ""
}

func applyResolvedDeployment(provider schemas.ModelProvider, model *string, serviceTier **schemas.BifrostServiceTier, deployment Deployment) bool {
	if model == nil {
		return false
	}
	if !applyDeploymentServiceTier(provider, serviceTier, deployment) {
		return false
	}
	*model = deployment.Upstream.Model
	return true
}

func applyDeploymentServiceTier(provider schemas.ModelProvider, serviceTier **schemas.BifrostServiceTier, deployment Deployment) bool {
	if provider == schemas.Anthropic {
		return applyAnthropicDeploymentServiceTier(serviceTier, deployment)
	}
	if provider == schemas.Azure {
		if serviceTier == nil || *serviceTier == nil {
			return deployment.Upstream.ServiceTier == ""
		}
		switch strings.ToLower(strings.TrimSpace(string(**serviceTier))) {
		case "", "auto", "default":
			*serviceTier = nil
			return deployment.Upstream.ServiceTier == ""
		default:
			return false
		}
	}
	if serviceTier == nil {
		return true
	}
	if implied := impliedServiceTier(provider, deployment.Upstream.ServiceTier); implied != nil {
		if *serviceTier == nil {
			*serviceTier = implied
			return true
		}
		if !equivalentServiceTier(provider, **serviceTier, *implied) {
			return false
		}
		*serviceTier = implied
		return true
	}
	switch deployment.Upstream.ServiceTier {
	case "", "default":
		if *serviceTier == nil {
			if provider == schemas.OpenAI {
				value := schemas.BifrostServiceTierDefault
				*serviceTier = &value
			}
			return true
		}
		switch **serviceTier {
		case schemas.BifrostServiceTierAuto, schemas.BifrostServiceTierDefault, "":
			if provider == schemas.OpenAI {
				value := schemas.BifrostServiceTierDefault
				*serviceTier = &value
			}
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func applyAnthropicDeploymentServiceTier(serviceTier **schemas.BifrostServiceTier, deployment Deployment) bool {
	if serviceTier == nil {
		return true
	}
	switch deployment.Upstream.ServiceTier {
	case "", "default", "standard_only":
		value := schemas.BifrostServiceTierDefault
		if *serviceTier != nil {
			switch strings.ToLower(strings.TrimSpace(string(**serviceTier))) {
			case "", "default", "standard", "standard_only":
				value = schemas.BifrostServiceTierDefault
			default:
				return false
			}
		}
		*serviceTier = &value
		return true
	default:
		return false
	}
}

func impliedServiceTierForDeployment(provider schemas.ModelProvider, deployment compiledDeployment) *schemas.BifrostServiceTier {
	return impliedServiceTier(provider, deployment.Upstream.ServiceTier)
}

func impliedServiceTier(provider schemas.ModelProvider, tier string) *schemas.BifrostServiceTier {
	if provider == schemas.Anthropic {
		switch tier {
		case "auto":
			value := schemas.BifrostServiceTierAuto
			return &value
		case "standard_only", "standard":
			value := schemas.BifrostServiceTierDefault
			return &value
		default:
			return nil
		}
	}
	switch tier {
	case "flex", "priority":
		value := schemas.BifrostServiceTier(tier)
		return &value
	default:
		return nil
	}
}

func equivalentServiceTier(provider schemas.ModelProvider, requested, implied schemas.BifrostServiceTier) bool {
	if requested == implied {
		return true
	}
	if provider == schemas.OpenAI {
		requestedValue := strings.ToLower(strings.TrimSpace(string(requested)))
		impliedValue := strings.ToLower(strings.TrimSpace(string(implied)))
		return impliedValue == "priority" &&
			(requestedValue == "fast" || requestedValue == "priority")
	}
	if provider != schemas.Anthropic {
		return false
	}
	switch implied {
	case schemas.BifrostServiceTierDefault:
		return requested == schemas.BifrostServiceTier("standard_only") ||
			requested == schemas.BifrostServiceTier("standard") ||
			requested == schemas.BifrostServiceTierDefault
	default:
		return false
	}
}

func deploymentIsFast(deployment compiledDeployment) bool {
	return strings.EqualFold(strings.TrimSpace(deployment.Upstream.Speed), "fast")
}

func rawStringField(object map[string]json.RawMessage, key string) string {
	raw, ok := object[key]
	if !ok {
		return ""
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func DeploymentForActualExecution(provider schemas.ModelProvider, route Route, current Deployment, actualTier *schemas.BifrostServiceTier, actualSpeed string, actualModel ...string) (Deployment, bool) {
	snap := current.snapshot
	if snap == nil {
		snap = active.Load()
	}
	if snap == nil || current.Upstream.Model == "" {
		return Deployment{}, false
	}
	actualSpeed = strings.ToLower(strings.TrimSpace(actualSpeed))
	targetModel := current.Upstream.Model
	if len(actualModel) > 0 && strings.TrimSpace(actualModel[0]) != "" {
		targetModel = strings.TrimSpace(actualModel[0])
	}
	if actualTier == nil && actualSpeed == "" && targetModel == current.Upstream.Model {
		for _, routeNode := range snap.routes(provider, route) {
			if resolved, ok := snap.deploymentFromCompiled(current.ID, routeNode); ok {
				return resolved, true
			}
		}
		return Deployment{}, false
	}
	currentCompiled, currentCompiledOK := snap.graph.Deployments[current.ID]
	currentFast := false
	currentReasoningMode := ""
	if currentCompiledOK {
		currentFast = deploymentIsFast(currentCompiled)
		currentReasoningMode = currentCompiled.Upstream.ReasoningMode
	}
	for _, routeNode := range snap.routes(provider, route) {
		for _, deploymentID := range routeNode.DeploymentIDs {
			deployment, ok := snap.graph.Deployments[deploymentID]
			if !ok ||
				!deploymentAvailableNow(deployment) ||
				routeNode.ProviderID != string(provider) ||
				deployment.Upstream.Model != targetModel {
				continue
			}
			if currentCompiledOK && deployment.Upstream.ReasoningMode != currentReasoningMode {
				continue
			}
			if current.Upstream.InferenceGeo != "" &&
				deployment.Upstream.InferenceGeo != current.Upstream.InferenceGeo {
				continue
			}
			if actualTier != nil && !deploymentMatchesActualServiceTier(provider, deployment.Upstream.ServiceTier, *actualTier) {
				continue
			}
			if actualSpeed != "" {
				if !deploymentMatchesActualSpeed(deployment, actualSpeed) {
					continue
				}
			} else if currentCompiledOK && deploymentIsFast(deployment) != currentFast {
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
	for _, routeNode := range snap.graph.Routes {
		if !routeSupportsInterface(routeNode, route) || routeNode.ProviderID == "" {
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

func ProviderPricing(provider schemas.ModelProvider) Pricing {
	return nil
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
		if native, ok := s.nativeProviderForModelSelector(requested, candidates); ok {
			return native, true, nil
		}
		return "", false, ErrModelAmbiguous
	}
	return candidates[0], true, nil
}

func (s *snapshot) nativeProviderForModelSelector(requested string, candidates []schemas.ModelProvider) (schemas.ModelProvider, bool) {
	_, selector := splitQualifiedModel(requested)
	modelID, ok := s.modelSelectors[selector]
	if !ok {
		return "", false
	}
	model, ok := s.graph.Models[modelID]
	if !ok {
		return "", false
	}
	for _, candidate := range candidates {
		if string(candidate) == model.AuthorID {
			return candidate, true
		}
	}
	return "", false
}

func (s *snapshot) routeModelProviders(route Route, requested string, allowed map[schemas.ModelProvider]bool) []schemas.ModelProvider {
	seen := map[schemas.ModelProvider]bool{}
	providers := []schemas.ModelProvider{}
	for _, routeNode := range s.graph.Routes {
		if !routeSupportsInterface(routeNode, route) {
			continue
		}
		if deploymentID, _ := s.deploymentIDFor(routeNode, requested); deploymentID == "" {
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
		if qualifierMatchesIDOrAlias(normalized, providerID, provider.Aliases) {
			return schemas.ModelProvider(providerID), true
		}
	}
	return "", false
}

func ProviderUsesPseudoanonymousUserID(provider schemas.ModelProvider) bool {
	return provider == schemas.OpenAI || provider == schemas.Anthropic
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
	return nil
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

func KnownFields(route Route) map[string]bool {
	return parameterSet(route)
}

func ParameterAliasFor(route Route, name string) (string, bool) {
	if route == RouteChat && name == "max_tokens" {
		return "max_completion_tokens", true
	}
	return "", false
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
	snap := active.Load()
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
	if deploymentID, ok := s.deploymentSelectors[selector]; ok {
		deployment, exists := s.graph.Deployments[deploymentID]
		if !exists ||
			!deploymentAvailableNow(deployment) ||
			!stringIn(deployment.RouteIDs, route.ID) ||
			!s.qualifierMatches(qualifier, route.ProviderID, deployment.ModelID) {
			return "", false
		}
		return deploymentID, true
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
	deployment, ok := s.graph.Deployments[deploymentID]
	if !ok ||
		!deploymentAvailableNow(deployment) ||
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
	var tee *TEE
	if deployment.TEE != nil {
		value := *deployment.TEE
		tee = &value
	}
	var reasoningMaxTokens *ReasoningMaxTokens
	if deployment.ReasoningMaxTokens != nil {
		value := *deployment.ReasoningMaxTokens
		reasoningMaxTokens = &value
	}
	return Deployment{
		ID:      deploymentID,
		ModelID: deployment.ModelID,
		Upstream: Upstream{
			Model:         deployment.Upstream.Model,
			ChuteID:       deployment.Upstream.ChuteID,
			GPUCount:      deployment.Upstream.GPUCount,
			InferenceGeo:  deployment.Upstream.InferenceGeo,
			ReasoningMode: deployment.Upstream.ReasoningMode,
			ServiceTier:   deployment.Upstream.ServiceTier,
			Speed:         deployment.Upstream.Speed,
		},
		Capabilities:          capabilities,
		ContextWindowTokens:   deployment.ContextWindowTokens,
		ImpliedServiceTier:    impliedServiceTierForDeployment(schemas.ModelProvider(route.ProviderID), deployment),
		MaxOutputTokens:       deployment.MaxOutputTokens,
		Pricing:               deployment.Pricing,
		RouteIDs:              []string{route.ID},
		ReasoningAvailability: deployment.ReasoningAvailability,
		ReasoningEfforts:      append([]string(nil), deployment.ReasoningEfforts...),
		ReasoningMaxTokens:    reasoningMaxTokens,
		ReasoningSupported:    deployment.ReasoningAvailability != "unsupported",
		TEE:                   tee,
		snapshot:              s,
	}, true
}

func (s *snapshot) allowsParam(route compiledRoute, name string) bool {
	known := parameterSet(firstInterfaceRoute(route))
	return known[name]
}

func deploymentMatchesActualServiceTier(provider schemas.ModelProvider, deploymentTier string, actual schemas.BifrostServiceTier) bool {
	deploymentTier = strings.ToLower(strings.TrimSpace(deploymentTier))
	actualValue := strings.ToLower(strings.TrimSpace(string(actual)))
	if provider == schemas.Anthropic {
		switch actualValue {
		case "default", "standard", "standard_only", "":
			return deploymentTier == "standard_only"
		default:
			return false
		}
	}
	switch actualValue {
	case "fast", "priority":
		return deploymentTier == "priority"
	case "flex":
		return deploymentTier == "flex"
	case "default", "standard", "standard_only", "auto", "":
		return deploymentTier == "" || deploymentTier == "default" || deploymentTier == "standard"
	default:
		return false
	}
}

func deploymentMatchesActualSpeed(deployment compiledDeployment, actualSpeed string) bool {
	fast := deploymentIsFast(deployment)
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
