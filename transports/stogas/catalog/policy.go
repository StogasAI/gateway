package catalog

import (
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

type routingSelection struct {
	deployment Deployment
	provider   schemas.ModelProvider
}

type policyDeploymentData struct {
	Aliases             []string            `json:"aliases"`
	Capabilities        Capabilities        `json:"capabilities"`
	ContextWindowTokens int                 `json:"contextWindowTokens"`
	DataHandling        DataHandling        `json:"dataHandling"`
	DeprecationDate     *string             `json:"deprecationDate"`
	InputModalities     []string            `json:"inputModalities"`
	MaxOutputTokens     int                 `json:"maxOutputTokens"`
	ModelID             string              `json:"modelId"`
	OutputModalities    []string            `json:"outputModalities"`
	Pricing             Pricing             `json:"pricing"`
	Reasoning           string              `json:"reasoning"`
	ReasoningEfforts    []string            `json:"reasoningEfforts"`
	ReasoningMaxTokens  *ReasoningMaxTokens `json:"reasoningMaxTokens"`
	RouteIDs            []string            `json:"routeIds"`
	Upstream            compiledUpstream    `json:"upstream"`
	WeightPrecision     string              `json:"weightPrecision"`
}

type policyRequestData struct {
	EstimatedInputTokens int    `json:"estimatedInputTokens"`
	MaximumOutputTokens  int    `json:"maximumOutputTokens"`
	Model                string `json:"model"`
	Route                string `json:"route"`
}

type resolvedPolicyValues struct {
	root map[string]any
}

func policyRoutingEnabled(config *policy.Config) bool {
	return config != nil && (config.Routing.Query != nil ||
		config.Routing.AllowedCatalogNodes != nil ||
		config.Routing.MaxPreDispatchCandidates > 1)
}

func routingSelectionsForRequest(
	route Route,
	requestedModel string,
	requestedTier *schemas.BifrostServiceTier,
	includeVariants bool,
) ([]routingSelection, error) {
	snap := active.Load()
	if snap == nil {
		return nil, ErrCatalogUnavailable
	}
	providers := snap.routeModelProviders(route, requestedModel, nil)
	if len(providers) == 0 {
		return nil, ErrModelUnavailable
	}

	groups := make([][]routingSelection, 0, len(providers))
	var firstTierErr error
	var nativeTierErr error
	validatedTier := false
	native, hasNative := snap.nativeProviderForModelSelector(requestedModel, providers)
	for _, provider := range providers {
		if err := validateRequestedServiceTier(provider, requestedTier); err != nil {
			if firstTierErr == nil {
				firstTierErr = err
			}
			if hasNative && provider == native {
				nativeTierErr = err
			}
			continue
		}
		validatedTier = true
		candidates := routingDeploymentsForProvider(
			snap,
			route,
			provider,
			requestedModel,
			requestedTier,
			includeVariants,
		)
		if len(candidates) == 0 {
			continue
		}
		groups = append(groups, candidates)
	}
	if len(groups) == 0 {
		if requestedTier != nil && strings.TrimSpace(string(*requestedTier)) != "" {
			if !validatedTier {
				if nativeTierErr != nil {
					return nil, nativeTierErr
				}
				if firstTierErr != nil {
					return nil, firstTierErr
				}
			}
			return nil, APIError{
				StatusCode: 400,
				Type:       ErrorTypeInvalidRequest,
				Message:    "Model is not available: the selected deployment does not support the requested service_tier",
			}
		}
		return nil, ErrModelUnavailable
	}

	// Put each provider's default deployment before compatible variants. This
	// keeps a two-candidate fallback useful across two providers unless a policy
	// filter or sort explicitly selects a deployment variant.
	selections := make([]routingSelection, 0)
	for index := 0; ; index++ {
		added := false
		for _, group := range groups {
			if index >= len(group) {
				continue
			}
			selections = append(selections, group[index])
			added = true
		}
		if !added {
			break
		}
	}
	return selections, nil
}

// applyProviderRoutingPreference filters strict provider choices and orders
// the remaining candidates. The caller still validates provider-specific
// request fields before it selects a candidate.
func applyProviderRoutingPreference(
	selections []routingSelection,
	preference ProviderRoutingPreference,
	requestedModel string,
) ([]routingSelection, schemas.ModelProvider, bool, error) {
	snap := active.Load()
	if snap == nil {
		return nil, "", false, ErrCatalogUnavailable
	}
	only, err := snap.resolveProviderPreferences(preference.Only)
	if err != nil {
		return nil, "", false, err
	}
	if len(only) > 0 {
		allowed := make(map[schemas.ModelProvider]bool, len(only))
		for _, provider := range only {
			allowed[provider] = true
		}
		kept := selections[:0]
		for _, selection := range selections {
			if allowed[selection.provider] {
				kept = append(kept, selection)
			}
		}
		selections = kept
		if len(selections) == 0 {
			return nil, "", false, ErrModelUnavailable
		}
	}

	requestedOrder, err := snap.resolveProviderPreferences(preference.Order)
	if err != nil {
		return nil, "", false, err
	}
	providers := selectionProviders(selections)
	providers = orderedRoutingProviders(snap, requestedModel, providers, requestedOrder)
	selections = interleaveRoutingSelections(selections, providers)

	if len(providers) == 1 {
		return selections, providers[0], true, nil
	}
	for _, provider := range requestedOrder {
		if providerInList(provider, providers) {
			return selections, provider, true, nil
		}
	}
	if len(requestedOrder) == 0 {
		if native, ok := snap.nativeProviderForModelSelector(requestedModel, providers); ok {
			return selections, native, true, nil
		}
	}
	return selections, "", false, nil
}

func filterRoutingSelectionsByAllowedNodes(
	selections []routingSelection,
	config *policy.Config,
) []routingSelection {
	if len(selections) == 0 || config == nil || config.Routing.AllowedCatalogNodes == nil {
		return selections
	}
	allowed := config.Routing.AllowedCatalogNodes
	filtered := selections[:0]
	for _, selection := range selections {
		ids := candidatePolicyIDs(&ResolvedRequest{
			Provider:   selection.provider,
			Deployment: selection.deployment,
		})
		if allowed.Allows(ids.author, ids.model, ids.deployment, ids.route, ids.provider) {
			filtered = append(filtered, selection)
		}
	}
	return filtered
}

func selectionProviders(selections []routingSelection) []schemas.ModelProvider {
	seen := make(map[schemas.ModelProvider]bool, len(selections))
	providers := make([]schemas.ModelProvider, 0, len(selections))
	for _, selection := range selections {
		if seen[selection.provider] {
			continue
		}
		seen[selection.provider] = true
		providers = append(providers, selection.provider)
	}
	return providers
}

func interleaveRoutingSelections(
	selections []routingSelection,
	providers []schemas.ModelProvider,
) []routingSelection {
	groups := make(map[schemas.ModelProvider][]routingSelection, len(providers))
	for _, selection := range selections {
		groups[selection.provider] = append(groups[selection.provider], selection)
	}
	ordered := make([]routingSelection, 0, len(selections))
	for index := 0; ; index++ {
		added := false
		for _, provider := range providers {
			group := groups[provider]
			if index >= len(group) {
				continue
			}
			ordered = append(ordered, group[index])
			added = true
		}
		if !added {
			return ordered
		}
	}
}

func routingDeploymentsForProvider(
	snap *snapshot,
	route Route,
	provider schemas.ModelProvider,
	requestedModel string,
	requestedTier *schemas.BifrostServiceTier,
	includeVariants bool,
) []routingSelection {
	base, ok := DeploymentForRouteServiceTier(provider, requestedModel, route, requestedTier)
	if !ok || len(base.RouteIDs) != 1 {
		return nil
	}
	routeNode, ok := snap.graph.Routes[base.RouteIDs[0]]
	if !ok {
		return nil
	}
	_, pinned := snap.deploymentIDFor(routeNode, requestedModel)
	result := []routingSelection{{deployment: base, provider: provider}}
	if pinned || !includeVariants {
		return result
	}
	baseCompiled, ok := snap.graph.Deployments[base.ID]
	if !ok {
		return nil
	}
	baseTier := normalizedDeploymentServiceTier(provider, baseCompiled.Upstream.ServiceTier)
	for _, deploymentID := range routeNode.DeploymentIDs {
		if deploymentID == base.ID {
			continue
		}
		candidate, exists := snap.graph.Deployments[deploymentID]
		if !exists ||
			!deploymentAvailableNow(candidate) ||
			candidate.ModelID != base.ModelID ||
			candidate.Upstream.ReasoningMode != baseCompiled.Upstream.ReasoningMode {
			continue
		}
		if requestedTier == nil {
			if normalizedDeploymentServiceTier(provider, candidate.Upstream.ServiceTier) != baseTier {
				continue
			}
		} else if !deploymentMatchesRequestedTier(provider, candidate, requestedTier) {
			continue
		}
		resolved, exists := snap.deploymentFromCompiled(deploymentID, routeNode)
		if !exists {
			continue
		}
		result = append(result, routingSelection{deployment: resolved, provider: provider})
	}
	return result
}

func orderedRoutingProviders(
	snap *snapshot,
	requestedModel string,
	providers []schemas.ModelProvider,
	requestedOrder []schemas.ModelProvider,
) []schemas.ModelProvider {
	rank := make(map[schemas.ModelProvider]int, len(requestedOrder))
	for index, provider := range requestedOrder {
		rank[provider] = index
	}
	native, hasNative := snap.nativeProviderForModelSelector(requestedModel, providers)
	out := append([]schemas.ModelProvider(nil), providers...)
	sort.SliceStable(out, func(i, j int) bool {
		leftRank, leftOrdered := rank[out[i]]
		rightRank, rightOrdered := rank[out[j]]
		if leftOrdered != rightOrdered {
			return leftOrdered
		}
		if leftOrdered && leftRank != rightRank {
			return leftRank < rightRank
		}
		if hasNative && (out[i] == native) != (out[j] == native) {
			return out[i] == native
		}
		return out[i] < out[j]
	})
	return out
}

func finalizeRoutingCandidates(
	resolved []*ResolvedRequest,
	config *policy.Config,
	preference ProviderRoutingPreference,
	requestedModel string,
) ([]*ResolvedRequest, error) {
	filtered := filterRoutingPolicy(resolved, config)
	if len(filtered) == 0 {
		return nil, ErrModelUnavailable
	}

	snap := active.Load()
	if snap == nil {
		return nil, ErrCatalogUnavailable
	}
	only, err := snap.resolveProviderPreferences(preference.Only)
	if err != nil {
		return nil, err
	}
	if len(only) > 0 {
		allowed := make(map[schemas.ModelProvider]bool, len(only))
		for _, provider := range only {
			allowed[provider] = true
		}
		kept := filtered[:0]
		for _, candidate := range filtered {
			if allowed[candidate.Provider] {
				kept = append(kept, candidate)
			}
		}
		filtered = kept
		if len(filtered) == 0 {
			return nil, ErrModelUnavailable
		}
	}

	requestedOrder, err := snap.resolveProviderPreferences(preference.Order)
	if err != nil {
		return nil, err
	}
	providers := resolvedProviders(filtered)
	orderedProviders := orderedRoutingProviders(snap, requestedModel, providers, requestedOrder)
	filtered = interleaveResolvedProviders(filtered, orderedProviders)

	query := (*policy.Query)(nil)
	if config != nil {
		query = config.Routing.Query
	}
	if query != nil && len(query.OrderBy) > 0 {
		values := make(map[*ResolvedRequest]*resolvedPolicyValues, len(filtered))
		for _, candidate := range filtered {
			candidateValues, ok := newResolvedPolicyValues(candidate)
			if !ok {
				return nil, ErrCatalogUnavailable
			}
			values[candidate] = candidateValues
		}
		sort.SliceStable(filtered, func(i, j int) bool {
			return query.Less(values[filtered[i]], values[filtered[j]])
		})
	}

	matchedOrder := false
	for _, provider := range requestedOrder {
		if providerInList(provider, providers) {
			matchedOrder = true
			break
		}
	}
	_, hasNative := snap.nativeProviderForModelSelector(requestedModel, providers)
	if len(providers) > 1 && !matchedOrder && !(len(requestedOrder) == 0 && hasNative) &&
		(query == nil || len(query.OrderBy) == 0) {
		return nil, ambiguousModelError(filtered)
	}

	limit := 1
	if config != nil {
		limit = config.Routing.MaxPreDispatchCandidates
	}
	if limit < 1 {
		limit = 1
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered, nil
}

func filterRoutingPolicy(resolved []*ResolvedRequest, config *policy.Config) []*ResolvedRequest {
	if len(resolved) == 0 || config == nil {
		return resolved
	}
	allowed := config.Routing.AllowedCatalogNodes
	query := config.Routing.Query
	filtered := make([]*ResolvedRequest, 0, len(resolved))
	for _, candidate := range resolved {
		candidateValues, idsOK := newResolvedPolicyValues(candidate)
		if !idsOK {
			continue
		}
		ids := candidatePolicyIDs(candidate)
		if !allowed.Allows(ids.author, ids.model, ids.deployment, ids.route, ids.provider) ||
			!query.Matches(candidateValues) {
			continue
		}
		filtered = append(filtered, candidate)
	}
	return filtered
}

func resolvedProviders(resolved []*ResolvedRequest) []schemas.ModelProvider {
	seen := make(map[schemas.ModelProvider]bool, len(resolved))
	providers := make([]schemas.ModelProvider, 0, len(resolved))
	for _, candidate := range resolved {
		if candidate == nil || seen[candidate.Provider] {
			continue
		}
		seen[candidate.Provider] = true
		providers = append(providers, candidate.Provider)
	}
	return providers
}

func interleaveResolvedProviders(
	resolved []*ResolvedRequest,
	providers []schemas.ModelProvider,
) []*ResolvedRequest {
	groups := make(map[schemas.ModelProvider][]*ResolvedRequest, len(providers))
	for _, candidate := range resolved {
		if candidate != nil {
			groups[candidate.Provider] = append(groups[candidate.Provider], candidate)
		}
	}
	ordered := make([]*ResolvedRequest, 0, len(resolved))
	for index := 0; ; index++ {
		added := false
		for _, provider := range providers {
			group := groups[provider]
			if index >= len(group) {
				continue
			}
			ordered = append(ordered, group[index])
			added = true
		}
		if !added {
			return ordered
		}
	}
}

func ambiguousModelError(resolved []*ResolvedRequest) APIError {
	selectors := make([]string, 0)
	seen := map[string]bool{}
	for _, candidate := range resolved {
		if candidate == nil || candidate.Provider == "" || candidate.Deployment.ModelID == "" {
			continue
		}
		selector := string(candidate.Provider) + "/" + candidate.Deployment.ModelID
		if seen[selector] {
			continue
		}
		seen[selector] = true
		selectors = append(selectors, selector)
	}
	sort.Strings(selectors)
	message := ErrModelAmbiguous.Message
	if len(selectors) > 0 {
		message = "Model is ambiguous; use one of: " + strings.Join(selectors, ", ")
	}
	return APIError{StatusCode: 400, Type: ErrorTypeInvalidRequest, Message: message}
}

type policyIDs struct {
	author     string
	deployment string
	model      string
	provider   string
	route      string
}

func candidatePolicyIDs(candidate *ResolvedRequest) policyIDs {
	if candidate == nil || candidate.Deployment.snapshot == nil || len(candidate.Deployment.RouteIDs) != 1 {
		return policyIDs{}
	}
	snap := candidate.Deployment.snapshot
	model, ok := snap.graph.Models[candidate.Deployment.ModelID]
	if !ok {
		return policyIDs{}
	}
	routeID := candidate.Deployment.RouteIDs[0]
	route, ok := snap.graph.Routes[routeID]
	if !ok {
		return policyIDs{}
	}
	return policyIDs{
		author:     model.AuthorID,
		deployment: candidate.Deployment.ID,
		model:      candidate.Deployment.ModelID,
		provider:   route.ProviderID,
		route:      routeID,
	}
}

func newResolvedPolicyValues(candidate *ResolvedRequest) (*resolvedPolicyValues, bool) {
	ids := candidatePolicyIDs(candidate)
	if candidate == nil || ids.author == "" || ids.model == "" || ids.deployment == "" || ids.route == "" || ids.provider == "" {
		return nil, false
	}
	snap := candidate.Deployment.snapshot
	author, authorOK := snap.graph.Authors[ids.author]
	model, modelOK := snap.graph.Models[ids.model]
	compiledDeployment, deploymentOK := snap.graph.Deployments[ids.deployment]
	route, routeOK := snap.graph.Routes[ids.route]
	provider, providerOK := snap.graph.Providers[ids.provider]
	if !authorOK || !modelOK || !deploymentOK || !routeOK || !providerOK {
		return nil, false
	}
	deployment := candidate.Deployment
	return &resolvedPolicyValues{root: map[string]any{
		"author": map[string]any{"data": author, "id": ids.author},
		"deployment": map[string]any{
			"data": policyDeploymentData{
				Aliases:             compiledDeployment.Aliases,
				Capabilities:        deployment.Capabilities,
				ContextWindowTokens: deployment.ContextWindowTokens,
				DataHandling:        deployment.DataHandling,
				DeprecationDate:     compiledDeployment.DeprecationDate,
				InputModalities:     deployment.Capabilities.InputModalities,
				MaxOutputTokens:     deployment.MaxOutputTokens,
				ModelID:             deployment.ModelID,
				OutputModalities:    deployment.Capabilities.OutputModalities,
				Pricing:             deployment.Pricing,
				Reasoning:           deployment.Reasoning,
				ReasoningEfforts:    deployment.ReasoningEfforts,
				ReasoningMaxTokens:  deployment.ReasoningMaxTokens,
				RouteIDs:            deployment.RouteIDs,
				Upstream:            compiledDeployment.Upstream,
				WeightPrecision:     deployment.WeightPrecision,
			},
			"id": ids.deployment,
		},
		"model":    map[string]any{"data": model, "id": ids.model},
		"provider": map[string]any{"data": provider, "id": ids.provider},
		"request": policyRequestData{
			EstimatedInputTokens: candidate.InputTokenLimit(),
			MaximumOutputTokens:  candidate.OutputTokenLimit(),
			Model:                candidate.RequestedModel,
			Route:                string(candidate.Route),
		},
		"route": map[string]any{"data": route, "id": ids.route},
	}}, true
}

func (v *resolvedPolicyValues) PolicyValue(path string) (policy.Value, bool) {
	fieldType, ok := policy.FieldType(path)
	if v == nil || !ok {
		return policy.Value{}, false
	}
	current := reflect.ValueOf(any(v.root))
	for _, part := range strings.Split(path, ".") {
		current, ok = policyChild(current, part)
		if !ok {
			return policy.Value{}, false
		}
	}
	return typedPolicyValue(current, fieldType, path)
}

func policyChild(value reflect.Value, name string) (reflect.Value, bool) {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return reflect.Value{}, false
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return reflect.Value{}, false
	}
	switch value.Kind() {
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return reflect.Value{}, false
		}
		child := value.MapIndex(reflect.ValueOf(name))
		return child, child.IsValid()
	case reflect.Struct:
		typeOf := value.Type()
		for index := 0; index < value.NumField(); index++ {
			field := typeOf.Field(index)
			jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
			if jsonName == "" {
				jsonName = field.Name
			}
			if jsonName == name {
				return value.Field(index), true
			}
		}
	}
	return reflect.Value{}, false
}

func typedPolicyValue(value reflect.Value, fieldType string, path string) (policy.Value, bool) {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return policy.Value{}, false
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return policy.Value{}, false
	}
	switch fieldType {
	case "boolean":
		if value.Kind() != reflect.Bool {
			return policy.Value{}, false
		}
		return policy.Value{Type: fieldType, Boolean: value.Bool()}, true
	case "integer":
		var integer *big.Int
		switch value.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if path == "deployment.data.upstream.gpuCount" && value.Int() == 0 {
				return policy.Value{}, false
			}
			integer = big.NewInt(value.Int())
		case reflect.String:
			var valid bool
			integer, valid = new(big.Int).SetString(value.String(), 10)
			if !valid {
				return policy.Value{}, false
			}
		default:
			return policy.Value{}, false
		}
		return policy.Value{Type: fieldType, Integer: integer}, true
	case "string":
		if value.Kind() != reflect.String || value.String() == "" {
			return policy.Value{}, false
		}
		return policy.Value{Type: fieldType, String: value.String()}, true
	case "string_list":
		if value.Kind() != reflect.Slice || value.IsNil() {
			return policy.Value{}, false
		}
		stringsValue, ok := value.Interface().([]string)
		if !ok {
			return policy.Value{}, false
		}
		return policy.Value{Type: fieldType, Strings: stringsValue}, true
	default:
		return policy.Value{}, false
	}
}
