package catalog

import (
	"errors"
	"math/big"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

type routingSelection struct {
	deployment Deployment
	provider   schemas.ModelProvider
	credential int
}

type policyDeploymentData struct {
	ApprovalRequired    bool                `json:"approvalRequired"`
	Capabilities        Capabilities        `json:"capabilities"`
	NativeFileInputs    NativeFileInputs    `json:"nativeFileInputs"`
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
	now     time.Time
	budget  *policy.CELBudget
	pricing Pricing
	root    map[string]policyNode
	fields  map[string]cachedPolicyValue
	blends  map[policy.BlendedPrice]cachedPolicyValue
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
	requestedTier string,
	config *policy.Config,
	availableCredentials map[string][]int,
) ([]routingSelection, error) {
	snap := activeState()
	if snap == nil {
		return nil, ErrCatalogUnavailable
	}
	if requestedModel == "" {
		return routingSelectionsInPool(snap, route, requestedTier, availableCredentials, nil, "")
	}
	if qualifier, selector := splitQualifiedModel(requestedModel); snap.groups[selector] {
		return routingSelectionsInPool(snap, route, requestedTier, availableCredentials, qualifier, selector)
	}
	providers := snap.routeModelProviders(route, requestedModel, availableCredentials)
	providers = filterRoutingProvidersByAllowedNodes(snap, route, requestedModel, providers, config)
	if len(providers) == 0 {
		return nil, ErrModelUnavailable
	}
	selections := make([]routingSelection, 0)
	for _, provider := range providers {
		selections = append(selections, routingDeploymentsForProvider(snap, route, provider, requestedModel, requestedTier)...)
	}
	if len(selections) == 0 {
		if requestedTier != "" {
			return nil, ErrServiceTierUnavailable
		}
		return nil, ErrModelUnavailable
	}
	return selections, nil
}

// An omitted selector or a group leaves model selection to the intersected routing filters and
// ordering. The pool holds every model, or the group's models; deployments that need approval
// join it only through exact selectors. Enumerate the catalog once, before request parsing and
// token work.
func routingSelectionsInPool(snap *snapshot, route Route, requestedTier string, availableCredentials map[string][]int, qualifier []string, group string) ([]routingSelection, error) {
	tier := requestedTier
	if tier == "" {
		tier = TierStandard
	}
	selections := make([]routingSelection, 0)
	for _, routeNode := range snap.graph.Routes {
		if !routeSupportsInterface(routeNode, route) {
			continue
		}
		provider := schemas.ModelProvider(routeNode.ProviderID)
		if availableCredentials != nil && len(availableCredentials[routeNode.ProviderID]) == 0 {
			continue
		}
		for _, id := range routeNode.DeploymentIDs {
			compiled := snap.graph.Deployments[id]
			if !deploymentAvailableNow(compiled) || compiled.ApprovalRequired || compiled.Upstream.ReasoningMode != "" || compiled.Upstream.ServiceTier != tier {
				continue
			}
			if group != "" && (!slices.Contains(snap.graph.Models[compiled.ModelID].GroupIDs, group) ||
				!snap.qualifierMatches(qualifier, routeNode.ProviderID, compiled.ModelID)) {
				continue
			}
			deployment, ok := snap.deploymentFromCompiled(id, routeNode)
			if ok {
				selections = append(selections, routingSelection{deployment: deployment, provider: provider})
			}
		}
	}
	if len(selections) == 0 {
		if requestedTier != "" {
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
				if policyAllowsSelection(config, routingSelection{deployment: deployment}) {
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
	snap := activeState()
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

func filterRoutingSelectionsByPolicy(selections []routingSelection, config *policy.Config) []routingSelection {
	filtered := selections[:0]
	for _, selection := range selections {
		if policyAllowsSelection(config, selection) {
			filtered = append(filtered, selection)
		}
	}
	return filtered
}

func policyAllowsSelection(config *policy.Config, selection routingSelection) bool {
	if config == nil || config.Routing.AllowedCatalogNodes == nil {
		return true
	}
	ids := candidatePolicyIDs(&ResolvedRequest{Deployment: selection.deployment})
	return config.Routing.AllowedCatalogNodes.Allows(ids.author, ids.model, ids.deployment, ids.route, ids.provider)
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
	requestedTier string,
) []routingSelection {
	base, ok := snap.deploymentForRouteTier(provider, requestedModel, route, requestedTier)
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
	for _, deploymentID := range routeNode.DeploymentIDs {
		if deploymentID == base.ID {
			continue
		}
		candidate, exists := snap.graph.Deployments[deploymentID]
		if !exists ||
			!deploymentAvailableNow(candidate) ||
			candidate.ModelID != base.ModelID ||
			candidate.Upstream.ReasoningMode != baseCompiled.Upstream.ReasoningMode ||
			candidate.Upstream.ServiceTier != baseCompiled.Upstream.ServiceTier {
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
	filtered []*ResolvedRequest
	values   map[*ResolvedRequest]*resolvedPolicyValues
}

func policyMatches(config *policy.Config, values *resolvedPolicyValues) (bool, error) {
	if config == nil || config.Routing.Query == nil {
		return true, nil
	}
	matches, err := config.Routing.Query.Matches(values)
	if err != nil {
		return false, policyEvaluationError(err)
	}
	return matches, nil
}

func (r *routingCandidates) add(candidate *ResolvedRequest, values *resolvedPolicyValues) {
	if r.values == nil {
		r.values = make(map[*ResolvedRequest]*resolvedPolicyValues)
	}
	r.filtered = append(r.filtered, candidate)
	r.values[candidate] = values
}

// Credential policies and rules whose conditions read candidate fields cannot
// set an order, so every survivor carries the same one.
func (r *routingCandidates) finish(preference ProviderRoutingPreference) ([][]*ResolvedRequest, error) {
	filtered, values := r.filtered, r.values
	if len(filtered) == 0 {
		return nil, ErrModelUnavailable
	}
	var ordering policy.Routing
	if config := filtered[0].policy; config != nil {
		ordering = config.Routing
	}
	if ordering.Selection != nil {
		return selectRoutingTargets(filtered, ordering.Selection)
	}

	// An explicit sort supplies a total order; its stable deployment-ID tie
	// breaker is used only after at least one user-defined criterion.
	if query := ordering.Query; query != nil && len(query.OrderBy) > 0 {
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
	// A group names its newest model, so neither a price nor a provider order chooses among
	// the group's models.
	if filtered[0].RequestedModel != "" && spansModels(filtered) {
		newest, err := newestModelCandidates(filtered)
		if err != nil {
			return nil, err
		}
		filtered = newest
	}
	snap := activeState()
	if snap == nil {
		return nil, ErrCatalogUnavailable
	}
	requestedOrder, err := snap.resolveProviderPreferences(preference.Order)
	if err != nil {
		return nil, err
	}
	ranked := make([][]*ResolvedRequest, len(requestedOrder)+1)
	for _, candidate := range filtered {
		rank := len(requestedOrder)
		for index, provider := range requestedOrder {
			if provider == candidate.Provider {
				rank = index
				break
			}
		}
		ranked[rank] = append(ranked[rank], candidate)
	}
	// Within each provider rank, the default order is the cheapest deployment
	// at a 3:1 input-to-output blend, then the lower deployment ID. Neither a
	// price nor a provider order may choose a model the request did not name, so
	// such a group stays whole and is rejected as ambiguous if it is reached.
	groups := make([][]*ResolvedRequest, 0, len(filtered))
	for _, group := range ranked {
		if len(group) == 0 {
			continue
		}
		if group[0].RequestedModel == "" && spansModels(group) {
			groups = append(groups, group)
			continue
		}
		sort.SliceStable(group, func(i, j int) bool {
			return defaultOrderLess(group[i], group[j], values)
		})
		for _, candidate := range group {
			if last := len(groups) - 1; last >= 0 && groups[last][0].Deployment.ID == candidate.Deployment.ID {
				groups[last] = append(groups[last], candidate)
				continue
			}
			groups = append(groups, []*ResolvedRequest{candidate})
		}
	}
	return groups, nil
}

// defaultOrderBlend weighs input three times output, the usual ratio for a
// blended model price. A deployment without both prices sorts last.
var defaultOrderBlend = policy.BlendedPrice{InputWeight: 3, OutputWeight: 1}

func defaultOrderLess(left, right *ResolvedRequest, values map[*ResolvedRequest]*resolvedPolicyValues) bool {
	if left.Deployment.ID == right.Deployment.ID {
		return false
	}
	leftPrice, leftOK := values[left].PolicyBlendedPrice(defaultOrderBlend)
	rightPrice, rightOK := values[right].PolicyBlendedPrice(defaultOrderBlend)
	if leftOK != rightOK {
		return leftOK
	}
	if leftOK {
		if compared := leftPrice.Decimal.Cmp(rightPrice.Decimal); compared != 0 {
			return compared < 0
		}
	}
	return left.Deployment.ID < right.Deployment.ID
}

// newestModelCandidates keeps the candidates of the most recently released model. Models
// released on the same day make the request ambiguous.
func newestModelCandidates(candidates []*ResolvedRequest) ([]*ResolvedRequest, error) {
	newest := ""
	var kept []*ResolvedRequest
	for _, candidate := range candidates {
		released := candidate.Deployment.snapshot.graph.Models[candidate.Deployment.ModelID].ReleaseDate
		if released < newest {
			continue
		}
		if released > newest {
			newest, kept = released, kept[:0]
		}
		kept = append(kept, candidate)
	}
	if spansModels(kept) {
		return nil, ambiguousModelError(kept)
	}
	return kept, nil
}

func spansModels(group []*ResolvedRequest) bool {
	for _, candidate := range group[1:] {
		if candidate.Deployment.ModelID != group[0].Deployment.ModelID {
			return true
		}
	}
	return false
}

func ambiguousModelError(resolved []*ResolvedRequest) APIError {
	models := make([]string, 0, len(resolved))
	seen := map[string]bool{}
	for _, candidate := range resolved {
		model := candidate.Deployment.ModelID
		if model != "" && !seen[model] {
			seen[model] = true
			models = append(models, model)
		}
	}
	sort.Strings(models)
	message := ErrModelAmbiguous.Message
	// Error output stays bounded when many models remain.
	if len(models) <= 8 {
		message += "; matching models: " + strings.Join(models, ", ")
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
	return &resolvedPolicyValues{now: candidate.policyTime, budget: candidate.policyBudget, pricing: deployment.Pricing, root: map[string]policyNode{
		"author": {id: ids.author, fields: author},
		"deployment": {
			id: ids.deployment,
			fields: policyDeploymentData{
				Capabilities:        deployment.Capabilities,
				NativeFileInputs:    deployment.NativeFileInputs,
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
				ApprovalRequired:    deployment.ApprovalRequired,
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

func (v *resolvedPolicyValues) PolicyTokenPrice(meter string, promptTokens int64) (policy.Value, bool) {
	rates := v.pricing[meter]
	return policy.DecimalValue(rates[billing.TokenRateKey(rates, int(promptTokens))])
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
