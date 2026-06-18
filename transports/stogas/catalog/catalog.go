package catalog

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

var active atomic.Pointer[snapshot]

func init() {
	if snap, err := loadSnapshot(Source{}); err == nil {
		active.Store(snap)
	}
}

func StartRefresh(ctx context.Context, source Source) error {
	snap, err := loadSnapshot(source)
	if err != nil {
		return err
	}
	active.Store(snap)

	interval := source.RefreshInterval
	if interval <= 0 {
		interval = defaultRefreshInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if next, err := loadSnapshot(source); err == nil {
					active.Store(next)
				}
			}
		}
	}()
	return nil
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

	allowedTier, impliedTier, ok := serviceTierPolicy(deployment)
	if !ok {
		return Deployment{}, false
	}
	return Deployment{
		ID:                  deploymentID,
		ModelID:             deployment.ModelID,
		Model:               providerModelSlug(deploymentID, model, modelNode),
		ContextWindowTokens: effectiveContextWindowTokens(deployment, modelNode),
		ImpliedServiceTier:  impliedTier,
		AllowedServiceTier:  allowedTier,
		MaxOutputTokens:     effectiveMaxOutputTokens(deployment, modelNode),
		Pricing:             deployment.Pricing,
		ReasoningSupported:  modelNode.ReasoningSupport,
		ParameterPolicies:   deployment.ParameterPolicies,
	}, true
}

func ProviderForRoute(route Route) (schemas.ModelProvider, bool) {
	snap := active.Load()
	if snap == nil {
		return "", false
	}
	routeNode, ok := snap.routeByName(route)
	if !ok || routeNode.ProviderID == "" {
		return "", false
	}
	return schemas.ModelProvider(routeNode.ProviderID), true
}

func PathForRoute(route Route) (string, bool) {
	snap := active.Load()
	if snap == nil {
		return "", false
	}
	routeNode, ok := snap.routeByName(route)
	if !ok {
		return "", false
	}
	schemaNode, ok := snap.graph.StogasEndpoints[routeNode.StogasEndpointID]
	if !ok || schemaNode.Schema.Path == "" {
		return "", false
	}
	return schemaNode.Schema.Path, true
}

func RouteForPath(path string) (Route, bool) {
	snap := active.Load()
	if snap == nil {
		return "", false
	}
	normalized := strings.TrimSpace(path)
	for routeID, routeNode := range snap.graph.ProviderEndpoints {
		schemaNode, ok := snap.graph.StogasEndpoints[routeNode.StogasEndpointID]
		if !ok || schemaNode.Schema.Path != normalized {
			continue
		}
		return publicRouteName(routeID, routeNode.ProviderID), true
	}
	return "", false
}

func InferencePaths() []string {
	snap := active.Load()
	if snap == nil {
		return nil
	}
	paths := []string{}
	seen := map[string]bool{}
	for _, routeNode := range snap.graph.ProviderEndpoints {
		schemaNode, ok := snap.graph.StogasEndpoints[routeNode.StogasEndpointID]
		if !ok || schemaNode.Schema.Path == "" || seen[schemaNode.Schema.Path] {
			continue
		}
		seen[schemaNode.Schema.Path] = true
		paths = append(paths, schemaNode.Schema.Path)
	}
	return stableStrings(paths)
}

func FilterExtraParams(provider schemas.ModelProvider, model string, route Route, params map[string]interface{}) map[string]interface{} {
	if len(params) == 0 {
		return nil
	}

	snap := active.Load()
	if snap == nil {
		return nil
	}
	routeNode, ok := snap.route(provider, route)
	if !ok || snap.deploymentIDFor(routeNode, model) == "" {
		return nil
	}

	filtered := make(map[string]interface{})
	for name, value := range params {
		if snap.allowsParam(routeNode, name) {
			filtered[name] = value
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func AuthHeaderNames(route Route) []string {
	snap := active.Load()
	if snap == nil {
		return []string{canonicalAuthHeader}
	}
	routeNode, ok := snap.routeByName(route)
	if !ok {
		return []string{canonicalAuthHeader}
	}
	schemaNode, ok := snap.graph.StogasEndpoints[routeNode.StogasEndpointID]
	if !ok {
		return []string{canonicalAuthHeader}
	}

	names := []string{}
	for name, policy := range schemaNode.Schema.Headers {
		alias, hasAlias := headerAlias(policy)
		if name == canonicalAuthHeader || (hasAlias && strings.EqualFold(alias, canonicalAuthHeader)) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return []string{canonicalAuthHeader}
	}
	return stableAuthHeaderOrder(names)
}

func ClientHeaderNames(route Route) []string {
	snap := active.Load()
	if snap == nil {
		return nil
	}
	routeNode, ok := snap.routeByName(route)
	if !ok {
		return nil
	}
	schemaNode, ok := snap.graph.StogasEndpoints[routeNode.StogasEndpointID]
	if !ok {
		return nil
	}
	names := make([]string, 0, len(schemaNode.Schema.Headers))
	for name := range schemaNode.Schema.Headers {
		names = append(names, name)
	}
	return stableHeaderOrder(names)
}

func AllClientHeaderNames() []string {
	snap := active.Load()
	if snap == nil {
		return nil
	}
	seen := map[string]bool{}
	names := []string{}
	for _, routeNode := range snap.graph.ProviderEndpoints {
		schemaNode, ok := snap.graph.StogasEndpoints[routeNode.StogasEndpointID]
		if !ok {
			continue
		}
		for name := range schemaNode.Schema.Headers {
			normalized := strings.ToLower(strings.TrimSpace(name))
			if normalized == "" || seen[normalized] {
				continue
			}
			seen[normalized] = true
			names = append(names, normalized)
		}
	}
	return stableHeaderOrder(names)
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
	snap := active.Load()
	if snap == nil {
		return nil
	}
	routeNode, ok := snap.routeByName(route)
	if !ok {
		return nil
	}
	schemaNode, ok := snap.graph.StogasEndpoints[routeNode.StogasEndpointID]
	if !ok {
		return nil
	}
	fields := make(map[string]bool, len(schemaNode.Schema.Parameters))
	for name := range schemaNode.Schema.Parameters {
		fields[name] = true
	}
	return fields
}

func ParameterAliasFor(route Route, name string) (string, bool) {
	snap := active.Load()
	if snap == nil {
		return "", false
	}
	routeNode, ok := snap.routeByName(route)
	if !ok {
		return "", false
	}
	schemaNode, ok := snap.graph.StogasEndpoints[routeNode.StogasEndpointID]
	if !ok {
		return "", false
	}
	parameter, ok := schemaNode.Schema.Parameters[name]
	if !ok {
		return "", false
	}
	return parameterAlias(parameter)
}

func (s *snapshot) route(provider schemas.ModelProvider, route Route) (compiledProviderEndpoint, bool) {
	routeNode, ok := s.graph.ProviderEndpoints[string(provider)+"-"+string(route)]
	return routeNode, ok
}

func (s *snapshot) routeByName(route Route) (compiledProviderEndpoint, bool) {
	suffix := "-" + string(route)
	for id, routeNode := range s.graph.ProviderEndpoints {
		if strings.HasSuffix(id, suffix) {
			return routeNode, true
		}
	}
	return compiledProviderEndpoint{}, false
}

func (s *snapshot) deploymentIDFor(route compiledProviderEndpoint, requestedModel string) string {
	requested := strings.TrimSpace(requestedModel)
	if requested == "" {
		return ""
	}
	return s.providerNativeModelSlugs[route.ID+":"+requested]
}

func (s *snapshot) allowsParam(route compiledProviderEndpoint, name string) bool {
	schemaNode, ok := s.graph.StogasEndpoints[route.StogasEndpointID]
	if !ok {
		return false
	}
	policies := effectiveParameterPolicies(schemaNode.Schema, route, Deployment{})
	_, ok = policies[name]
	return ok
}

func providerModelSlug(deploymentID string, requestedModel string, model compiledModel) string {
	requested := leafSlug(strings.TrimSpace(requestedModel))
	if isDatedProviderModelAlias(requested, model) {
		return requested
	}
	for _, slug := range model.ModelSlugs {
		if slug == deploymentID {
			return slug
		}
	}
	for _, suffix := range []string{"-standard", "-flex", "-priority"} {
		base := strings.TrimSuffix(deploymentID, suffix)
		if base != deploymentID {
			for _, slug := range model.ModelSlugs {
				if slug == base {
					return slug
				}
			}
		}
	}
	return primaryModelSlug(model)
}

func isDatedProviderModelAlias(requested string, model compiledModel) bool {
	if !hasDateSuffix(requested) {
		return false
	}
	for _, slug := range model.ModelSlugs {
		if requested == slug {
			return true
		}
	}
	return false
}

func leafSlug(value string) string {
	if idx := strings.LastIndex(value, "/"); idx >= 0 {
		return value[idx+1:]
	}
	return value
}

func primaryModelSlug(model compiledModel) string {
	if len(model.ModelSlugs) == 0 {
		return ""
	}
	return model.ModelSlugs[0]
}

func hasDateSuffix(value string) bool {
	if len(value) < len("2006-01-02") {
		return false
	}
	suffix := value[len(value)-len("2006-01-02"):]
	for i, char := range suffix {
		switch i {
		case 4, 7:
			if char != '-' {
				return false
			}
		default:
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func effectiveContextWindowTokens(deployment compiledDeployment, model compiledModel) int {
	if deployment.ContextWindowTokens > 0 {
		return deployment.ContextWindowTokens
	}
	return model.ContextWindowTokens
}

func effectiveMaxOutputTokens(deployment compiledDeployment, model compiledModel) int {
	if deployment.MaxOutputTokens > 0 {
		return deployment.MaxOutputTokens
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
	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			if headerPriority(priority, ordered[j]) < headerPriority(priority, ordered[i]) {
				ordered[i], ordered[j] = ordered[j], ordered[i]
			}
		}
	}
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
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
	return values
}

func headerPriority(priority map[string]int, name string) int {
	if value, ok := priority[name]; ok {
		return value
	}
	return 100
}

func publicRouteName(routeID string, providerID string) Route {
	prefix := providerID + "-"
	if strings.HasPrefix(routeID, prefix) {
		return Route(strings.TrimPrefix(routeID, prefix))
	}
	return Route(routeID)
}
