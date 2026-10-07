package catalog

import (
	"errors"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

type routingSelection struct {
	deployment Deployment
	provider   schemas.ModelProvider
	credential int
}

type policyDeploymentData struct {
	Aliases             []string            `json:"aliases"`
	Capabilities        Capabilities        `json:"capabilities"`
	FileInputs          FileInputs          `json:"fileInputs"`
	ContextWindowTokens int                 `json:"contextWindowTokens"`
	MaxInputTokens      int                 `json:"maxInputTokens"`
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
	BodyBytes int    `json:"bodyBytes"`
	Model     string `json:"model"`
	Route     string `json:"route"`
}

type resolvedPolicyValues struct {
	now    time.Time
	budget *policy.CELBudget
	root   map[string]policyNode
	fields map[string]cachedPolicyValue
	blends map[policy.BlendedPrice]cachedPolicyValue
}

type cachedPolicyValue struct {
	value policy.Value
	ok    bool
}

type policyNode struct {
	id     string
	fields any
}

func routingSelectionsForRequest(
	route Route,
	requestedModel string,
	requestedTier *schemas.BifrostServiceTier,
	config *policy.Config,
	availableCredentials map[string][]int,
) ([]routingSelection, error) {
	snap := active.Load()
	if snap == nil {
		return nil, ErrCatalogUnavailable
	}
	if requestedModel == "" {
		return routingSelectionsWithoutModel(snap, route, requestedTier, availableCredentials)
	}
	providers := snap.routeModelProviders(route, requestedModel, availableCredentials)
	providers = filterRoutingProvidersByAllowedNodes(snap, route, requestedModel, providers, config)
	if len(providers) == 0 {
		return nil, ErrModelUnavailable
	}

	groups := make([][]routingSelection, 0, len(providers))
	var firstTierErr error
	validatedTier := false
	for _, provider := range providers {
		if err := validateRequestedServiceTier(provider, requestedTier); err != nil {
			if firstTierErr == nil {
				firstTierErr = err
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
		)
		if len(candidates) == 0 {
			continue
		}
		groups = append(groups, candidates)
	}
	if len(groups) == 0 {
		if requestedTier != nil && strings.TrimSpace(string(*requestedTier)) != "" {
			if !validatedTier {
				if len(providers) == 1 && firstTierErr != nil {
					return nil, firstTierErr
				}
				if isKnownServiceTierValue(requestedTier) {
					return nil, ErrServiceTierUnavailable
				}
				if firstTierErr != nil {
					return nil, firstTierErr
				}
			}
			return nil, ErrServiceTierUnavailable
		}
		return nil, ErrModelUnavailable
	}

	selections := make([]routingSelection, 0)
	for _, group := range groups {
		selections = append(selections, group...)
	}
	return selections, nil
}

// An omitted selector leaves model selection to the intersected routing filters
// and ordering. Enumerate the catalog once, before request parsing and token work.
func routingSelectionsWithoutModel(snap *snapshot, route Route, requestedTier *schemas.BifrostServiceTier, availableCredentials map[string][]int) ([]routingSelection, error) {
	selections := make([]routingSelection, 0)
	if !isKnownServiceTierValue(requestedTier) {
		return nil, ErrUnsupportedServiceTier
	}
	for _, routeNode := range snap.graph.Routes {
		if !routeSupportsInterface(routeNode, route) {
			continue
		}
		provider := schemas.ModelProvider(routeNode.ProviderID)
		if availableCredentials != nil && len(availableCredentials[routeNode.ProviderID]) == 0 {
			continue
		}
		if err := validateRequestedServiceTier(provider, requestedTier); err != nil {
			continue
		}
		for _, id := range routeNode.DeploymentIDs {
			compiled := snap.graph.Deployments[id]
			if !deploymentAvailableNow(compiled) || deploymentIsFast(compiled) || compiled.Upstream.ReasoningMode != "" ||
				(requestedTier == nil && impliedServiceTierForDeployment(provider, compiled) != nil) ||
				(requestedTier != nil && !deploymentMatchesRequestedTier(provider, compiled, requestedTier)) {
				continue
			}
			deployment, ok := snap.deploymentFromCompiled(id, routeNode)
			if ok {
				selections = append(selections, routingSelection{deployment: deployment, provider: provider})
			}
		}
	}
	if len(selections) == 0 {
		if requestedTier != nil {
			return nil, ErrServiceTierUnavailable
		}
		return nil, ErrModelUnavailable
	}
	// Stable ties must not depend on Go map iteration or catalog serialization.
	sort.Slice(selections, func(i, j int) bool {
		if selections[i].deployment.ID != selections[j].deployment.ID {
			return selections[i].deployment.ID < selections[j].deployment.ID
		}
		return selections[i].deployment.RouteIDs[0] < selections[j].deployment.RouteIDs[0]
	})
	return selections, nil
}

// Filter exact key restrictions before request compatibility. A deployment
// that the key cannot use must not influence provider selection or error text.
func filterRoutingProvidersByAllowedNodes(
	snap *snapshot,
	route Route,
	requestedModel string,
	providers []schemas.ModelProvider,
	config *policy.Config,
) []schemas.ModelProvider {
	if snap == nil || config == nil || config.Routing.AllowedCatalogNodes == nil {
		return providers
	}
	allowed := config.Routing.AllowedCatalogNodes
	filtered := make([]schemas.ModelProvider, 0, len(providers))
	for _, provider := range providers {
		matched := false
		for _, routeNode := range snap.routes(provider, route) {
			selectedID, pinned := snap.deploymentIDFor(routeNode, requestedModel)
			selected, ok := snap.graph.Deployments[selectedID]
			if !ok {
				continue
			}
			for _, deploymentID := range routeNode.DeploymentIDs {
				if pinned && deploymentID != selectedID {
					continue
				}
				candidate, ok := snap.graph.Deployments[deploymentID]
				if !ok || candidate.ModelID != selected.ModelID {
					continue
				}
				deployment, ok := snap.deploymentFromCompiled(deploymentID, routeNode)
				if !ok {
					continue
				}
				ids := candidatePolicyIDs(&ResolvedRequest{Provider: provider, Deployment: deployment})
				if allowed.Allows(ids.author, ids.model, ids.deployment, ids.route, ids.provider) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if matched {
			filtered = append(filtered, provider)
		}
	}
	return filtered
}

// Strict provider choices are eligibility filters. Ordering is applied after
// every candidate's credential policy has been intersected.
func filterProviderSelections(selections []routingSelection, preference ProviderRoutingPreference) ([]routingSelection, error) {
	snap := active.Load()
	if snap == nil {
		return nil, ErrCatalogUnavailable
	}
	only, err := snap.resolveProviderPreferences(preference.Only)
	if err != nil {
		return nil, err
	}
	if _, err := snap.resolveProviderPreferences(preference.Order); err != nil {
		return nil, err
	}
	if len(only) == 0 {
		return selections, nil
	}
	kept := selections[:0]
	for _, selection := range selections {
		if providerInList(selection.provider, only) {
			kept = append(kept, selection)
		}
	}
	if len(kept) == 0 {
		return nil, ErrProviderSelection
	}
	return kept, nil
}

type policyRequestContext struct {
	now       time.Time
	budget    *policy.CELBudget
	model     string
	route     Route
	bodyBytes int
}

func filterRoutingSelectionsByPolicy(selections []routingSelection, config *policy.Config, context policyRequestContext) ([]routingSelection, error) {
	if len(selections) == 0 || config == nil {
		return selections, nil
	}
	allowed := config.Routing.AllowedCatalogNodes
	filtered := selections[:0]
	for _, selection := range selections {
		candidate := &ResolvedRequest{Provider: selection.provider, Deployment: selection.deployment, policyTime: context.now, policyBudget: context.budget, policyBodyBytes: context.bodyBytes, RequestedModel: context.model, Route: context.route}
		ids := candidatePolicyIDs(candidate)
		if !allowed.Allows(ids.author, ids.model, ids.deployment, ids.route, ids.provider) {
			continue
		}
		filtered = append(filtered, selection)
	}
	return filtered, nil
}

func policyEvaluationError(err error) error {
	code := "invalid_request"
	if errors.Is(err, policy.ErrPolicyWorkLimit) || errors.Is(err, policy.ErrSourceBudget) {
		code = "policy_work_limit_exceeded"
	}
	return APIError{StatusCode: 400, Type: ErrorTypeInvalidRequest, Code: code, Message: err.Error()}
}

func routingDeploymentsForProvider(
	snap *snapshot,
	route Route,
	provider schemas.ModelProvider,
	requestedModel string,
	requestedTier *schemas.BifrostServiceTier,
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
	if pinned {
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
			candidate.Upstream.ReasoningMode != baseCompiled.Upstream.ReasoningMode ||
			deploymentIsFast(candidate) != deploymentIsFast(baseCompiled) {
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

type routingCandidates struct {
	filtered                          []*ResolvedRequest
	values                            map[*ResolvedRequest]*resolvedPolicyValues
	requiredOrder, defaultOrder       *policy.Query
	requiredConflict, defaultConflict bool
	hasRequiredSort                   bool
}

// Every surviving policy participates in order agreement, including credentials
// beyond the fallback allowance. Only reachable choices need retained requests.
func (r *routingCandidates) consider(config *policy.Config, values *resolvedPolicyValues) (bool, error) {
	var query *policy.Query
	if config != nil {
		query = config.Routing.Query
	}
	if query != nil {
		matches, err := query.Matches(values)
		if err != nil {
			return false, policyEvaluationError(err)
		}
		if !matches {
			return false, nil
		}
		if len(query.OrderBy) != 0 {
			prior, conflict := &r.requiredOrder, &r.requiredConflict
			if config.Routing.SortDefault {
				prior, conflict = &r.defaultOrder, &r.defaultConflict
			}
			*conflict = *conflict || *prior != nil && !(*prior).SameOrder(query)
			*prior = query
		}
	}
	r.hasRequiredSort = r.hasRequiredSort || config.HasRequiredSort()
	return true, nil
}

func (r *routingCandidates) add(candidate *ResolvedRequest, values *resolvedPolicyValues) {
	if r.values == nil {
		r.values = make(map[*ResolvedRequest]*resolvedPolicyValues)
	}
	r.filtered = append(r.filtered, candidate)
	r.values[candidate] = values
}

func finalizeRoutingCandidates(resolved []*ResolvedRequest, config *policy.Config, preference ProviderRoutingPreference) ([][]*ResolvedRequest, error) {
	var result routingCandidates
	for _, candidate := range resolved {
		candidateConfig := candidate.policy
		if candidateConfig == nil {
			candidateConfig = config
		}
		var values *resolvedPolicyValues
		if candidateConfig != nil && candidateConfig.Routing.Query != nil {
			var ok bool
			values, ok = newResolvedPolicyValues(candidate)
			if !ok {
				continue
			}
		}
		matched, err := result.consider(candidateConfig, values)
		if err != nil {
			return nil, err
		}
		if matched {
			result.add(candidate, values)
		}
	}
	return result.finish(preference)
}

func (r *routingCandidates) finish(preference ProviderRoutingPreference) ([][]*ResolvedRequest, error) {
	query, conflict := r.requiredOrder, r.requiredConflict
	if query == nil && !r.hasRequiredSort {
		query, conflict = r.defaultOrder, r.defaultConflict
	}
	if conflict {
		return nil, APIError{StatusCode: 400, Type: ErrorTypeInvalidRequest, Code: "invalid_request", Message: "Candidate policies require different routing sort orders"}
	}
	filtered, values := r.filtered, r.values
	if query != nil {
		for _, candidate := range filtered {
			if values[candidate] == nil {
				value, ok := newResolvedPolicyValues(candidate)
				if !ok {
					return nil, ErrModelUnavailable
				}
				values[candidate] = value
			}
		}
	}
	if len(filtered) == 0 {
		return nil, ErrModelUnavailable
	}

	// An explicit sort supplies a total order; its stable deployment-ID tie
	// breaker is used only after at least one user-defined criterion.
	if query != nil && len(query.OrderBy) > 0 {
		candidates := make([]policy.Values, len(filtered))
		for i, candidate := range filtered {
			candidates[i] = values[candidate]
		}
		order, err := query.Sort(candidates)
		if err != nil {
			return nil, policyEvaluationError(err)
		}
		groups := make([][]*ResolvedRequest, 0, len(order))
		for _, index := range order {
			candidate := filtered[index]
			if len(groups) > 0 {
				last := groups[len(groups)-1]
				if last[0].Deployment.ID == candidate.Deployment.ID && last[0].Provider == candidate.Provider {
					groups[len(groups)-1] = append(last, candidate)
					continue
				}
			}
			groups = append(groups, []*ResolvedRequest{candidate})
		}
		return groups, nil
	}
	snap := active.Load()
	if snap == nil {
		return nil, ErrCatalogUnavailable
	}
	requestedOrder, err := snap.resolveProviderPreferences(preference.Order)
	if err != nil {
		return nil, err
	}
	// A provider order cannot choose between its regions or models. Keep equal
	// priorities together so ambiguity is rejected only if that group is reached.
	groups := make([][]*ResolvedRequest, len(requestedOrder)+1)
	for _, candidate := range filtered {
		rank := len(requestedOrder)
		for index, provider := range requestedOrder {
			if provider == candidate.Provider {
				rank = index
				break
			}
		}
		groups[rank] = append(groups[rank], candidate)
	}
	return groups, nil
}

func ambiguousModelError(resolved []*ResolvedRequest) APIError {
	selectors := make([]string, 0, len(resolved))
	seen := map[string]bool{}
	for _, candidate := range resolved {
		selector := candidate.Deployment.ID
		if selector != "" && !seen[selector] {
			seen[selector] = true
			selectors = append(selectors, selector)
		}
	}
	sort.Strings(selectors)
	message := ErrModelAmbiguous.Message
	// Error output stays bounded when the caller leaves the model unspecified.
	if len(selectors) <= 8 {
		message += "; matching deployments: " + strings.Join(selectors, ", ")
	}
	return APIError{Code: ErrModelAmbiguous.Code, StatusCode: ErrModelAmbiguous.StatusCode, Type: ErrModelAmbiguous.Type, Message: message}
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
	return &resolvedPolicyValues{now: candidate.policyTime, budget: candidate.policyBudget, root: map[string]policyNode{
		"author": {id: ids.author, fields: author},
		"deployment": {
			id: ids.deployment,
			fields: policyDeploymentData{
				Aliases:             compiledDeployment.Aliases,
				Capabilities:        deployment.Capabilities,
				FileInputs:          deployment.FileInputs,
				ContextWindowTokens: deployment.ContextWindowTokens,
				MaxInputTokens:      deployment.MaxInputTokens,
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
		},
		"model":    {id: ids.model, fields: model},
		"provider": {id: ids.provider, fields: provider},
		"request": {fields: policyRequestData{
			BodyBytes: candidate.policyBodyBytes,
			Model:     candidate.RequestedModel,
			Route:     string(candidate.Route),
		}},
		"route": {id: ids.route, fields: route},
	}}, true
}

func (v *resolvedPolicyValues) PolicyTime() time.Time              { return v.now }
func (v *resolvedPolicyValues) PolicyCELBudget() *policy.CELBudget { return v.budget }

func (v *resolvedPolicyValues) PolicyValue(path string) (policy.Value, bool) {
	if v == nil {
		return policy.Value{}, false
	}
	if cached, exists := v.fields[path]; exists {
		return cached.value, cached.ok
	}
	value, ok := v.resolveField(path)
	if v.fields == nil {
		v.fields = make(map[string]cachedPolicyValue)
	}
	v.fields[path] = cachedPolicyValue{value, ok}
	return value, ok
}

// A candidate view belongs to one routing pass and is immutable. Cache missing
// values too; repeated predicates and sorting must not reparse catalog prices.
func (v *resolvedPolicyValues) PolicyBlendedPrice(blend policy.BlendedPrice) (policy.Value, bool) {
	if cached, exists := v.blends[blend]; exists {
		return cached.value, cached.ok
	}
	value, ok := blend.Value(v)
	if v.blends == nil {
		v.blends = make(map[policy.BlendedPrice]cachedPolicyValue)
	}
	v.blends[blend] = cachedPolicyValue{value, ok}
	return value, ok
}

func (v *resolvedPolicyValues) resolveField(path string) (policy.Value, bool) {
	fieldType, ok := policy.FieldType(path)
	if v == nil || !ok {
		return policy.Value{}, false
	}
	parts := strings.Split(path, ".")
	node, ok := v.root[parts[0]]
	if !ok {
		return policy.Value{}, false
	}
	if len(parts) == 2 && parts[1] == "id" {
		return policy.Value{Type: fieldType, String: node.id}, true
	}
	current := reflect.ValueOf(node.fields)
	for _, part := range parts[1:] {
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
	case "decimal":
		if value.Kind() != reflect.String {
			return policy.Value{}, false
		}
		return policy.DecimalValue(value.String())
	case "integer":
		var integer *big.Int
		switch value.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if path == "deployment.upstream.gpuCount" && value.Int() == 0 {
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
