package catalog

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
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
	ContextWindowTokens int                 `json:"contextWindowTokens"`
	MaxInputTokens      int                 `json:"maxInputTokens"`
	DataHandling        DataHandling        `json:"dataHandling"`
	InputModalities     []string            `json:"inputModalities"`
	MaxOutputTokens     int                 `json:"maxOutputTokens"`
	ModelID             string              `json:"modelId"`
	OutputModalities    []string            `json:"outputModalities"`
	Pricing             Pricing             `json:"pricing"`
	Reasoning           string              `json:"reasoning"`
	ReasoningEfforts    []string            `json:"reasoningEfforts"`
	ReasoningMaxTokens  *ReasoningMaxTokens `json:"reasoningMaxTokens"`
	RetirementDate      *string             `json:"retirementDate"`
	Upstream            compiledUpstream    `json:"upstream"`
	WeightPrecision     string              `json:"weightPrecision"`
}

type policyRequestData struct {
	BodyBytes int    `json:"bodyBytes"`
	Interface string `json:"interface"`
	Model     string `json:"model"`
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
	want variant,
	config *policy.Config,
	availableCredentials map[string][]int,
	trace *routingTrace,
) ([]routingSelection, error) {
	snap := activeState()
	if snap == nil {
		return nil, ErrCatalogUnavailable
	}
	if requestedModel == "" {
		return routingSelectionsInPool(snap, route, want, availableCredentials, nil, "", trace)
	}
	if qualifier, selector := splitQualifiedModel(requestedModel); snap.groups[selector] {
		return routingSelectionsInPool(snap, route, want, availableCredentials, qualifier, selector, trace)
	}
	providers := snap.routeModelProviders(route, requestedModel, availableCredentials, trace)
	providers = filterRoutingProvidersByAllowedNodes(snap, route, requestedModel, want, providers, config, trace)
	if len(providers) == 0 {
		if date, retired := snap.retiredOn(requestedModel, time.Now()); retired {
			return nil, modelRetired(date)
		}
		return nil, ErrModelUnavailable
	}
	selections := make([]routingSelection, 0)
	modeServed := false
	for _, provider := range providers {
		deployments := routingDeploymentsForProvider(snap, route, provider, requestedModel, want)
		_, servesMode := snap.deploymentForRoute(provider, requestedModel, route, variant{mode: want.mode})
		modeServed = modeServed || servesMode
		if trace != nil && len(deployments) == 0 {
			if servesMode {
				trace.removeProvider(provider, RemovedServiceTier)
			} else if want.mode != "" {
				trace.removeProvider(provider, RemovedReasoningMode)
			}
		}
		selections = append(selections, deployments...)
	}
	if len(selections) == 0 {
		return nil, want.unavailable(modeServed)
	}
	return selections, nil
}

// An omitted selector or a group leaves model selection to the intersected routing filters and
// ordering. The pool holds every model, or the group's models; deployments that need approval
// join it only through exact selectors. Enumerate the catalog once, before request parsing and
// token work.
//
// A trace names providers without credentials and deployments that need approval. For a group,
// it also names providers that serve the group only through another interface.
func routingSelectionsInPool(snap *snapshot, route Route, want variant, availableCredentials map[string][]int, qualifier []string, group string, trace *routingTrace) ([]routingSelection, error) {
	tier, mode := cmp.Or(want.tier, TierStandard), want.upstreamMode()
	modeServed := false
	selections := make([]routingSelection, 0)
	skipped := providerSkips{trace: trace}
	now := time.Now()
	for _, routeNode := range snap.graph.Routes {
		provider := schemas.ModelProvider(routeNode.ProviderID)
		supported := routeSupportsInterface(routeNode, route)
		credentialed := availableCredentials == nil || len(availableCredentials[routeNode.ProviderID]) > 0
		if trace == nil && (!supported || !credentialed) || trace != nil && !supported && group == "" {
			continue
		}
		for _, id := range routeNode.DeploymentIDs {
			compiled := snap.graph.Deployments[id]
			if !servesAt(compiled, routeNode, now) || compiled.Upstream.ReasoningMode != mode {
				continue
			}
			if group != "" && (!slices.Contains(snap.graph.Models[compiled.ModelID].GroupIDs, group) ||
				!snap.qualifierMatches(qualifier, routeNode.ProviderID, compiled.ModelID)) {
				continue
			}
			// The mode applies before the tier, at the Standard tier that a pool selects by default.
			if supported && credentialed && !compiled.ApprovalRequired && compiled.Upstream.ServiceTier == TierStandard {
				modeServed = true
			}
			if compiled.Upstream.ServiceTier != tier {
				continue
			}
			if !supported || !credentialed {
				skipped.add(provider, supported)
				break
			}
			if compiled.ApprovalRequired {
				if trace != nil {
					if deployment, ok := snap.deploymentFromCompiled(id, routeNode); ok {
						trace.removeSelection(routingSelection{deployment: deployment, provider: provider}, RemovedApproval, nil)
					}
				}
				continue
			}
			deployment, ok := snap.deploymentFromCompiled(id, routeNode)
			if ok {
				selections = append(selections, routingSelection{deployment: deployment, provider: provider})
			}
		}
	}
	for _, selection := range selections {
		skipped.served(selection.provider)
	}
	skipped.record()
	if len(selections) == 0 {
		return nil, want.unavailable(modeServed)
	}
	// Stable ties must not depend on Go map iteration or catalog serialization.
	sort.Slice(selections, func(i, j int) bool {
		if selections[i].deployment.ID != selections[j].deployment.ID {
			return selections[i].deployment.ID < selections[j].deployment.ID
		}
		return selections[i].deployment.RouteID < selections[j].deployment.RouteID
	})
	return selections, nil
}

// Filter exact key restrictions before request compatibility. A deployment
// that the key cannot use must not influence provider selection or error text.
func filterRoutingProvidersByAllowedNodes(
	snap *snapshot,
	route Route,
	requestedModel string,
	want variant,
	providers []schemas.ModelProvider,
	config *policy.Config,
	trace *routingTrace,
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
		} else if trace != nil {
			// Name the deployments that the provider would otherwise serve.
			deployments := routingDeploymentsForProvider(snap, route, provider, requestedModel, want)
			if len(deployments) == 0 {
				deployments = routingDeploymentsForProvider(snap, route, provider, requestedModel, variant{})
			}
			for _, selection := range deployments {
				trace.removeSelection(selection, RemovedAllowedNodes, nodesOrigin(config, selection.deployment))
			}
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

func filterRoutingSelectionsByPolicy(selections []routingSelection, config *policy.Config, trace *routingTrace) []routingSelection {
	filtered := selections[:0]
	for _, selection := range selections {
		if policyAllowsSelection(config, selection) {
			filtered = append(filtered, selection)
		} else if trace != nil {
			trace.removeSelection(selection, RemovedAllowedNodes, nodesOrigin(config, selection.deployment))
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
	want variant,
) []routingSelection {
	base, ok := snap.deploymentForRoute(provider, requestedModel, route, want)
	if !ok {
		return nil
	}
	routeNode, ok := snap.graph.Routes[base.RouteID]
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
			!servesAt(candidate, routeNode, time.Now()) ||
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
	trace    *routingTrace
}

// policyFilterFailure returns the index of the first routing filter that
// removes a candidate, or -1, and whether that filter read only stated facts.
func policyFilterFailure(config *policy.Config, values *resolvedPolicyValues) (int, bool, error) {
	if config == nil || config.Routing.Query == nil {
		return -1, true, nil
	}
	index, known, err := config.Routing.Query.FirstFailure(values)
	if err != nil {
		return index, known, policyEvaluationError(err)
	}
	return index, known, nil
}

func (r *routingCandidates) add(candidate *ResolvedRequest, values *resolvedPolicyValues) {
	if r.values == nil {
		r.values = make(map[*ResolvedRequest]*resolvedPolicyValues)
	}
	r.filtered = append(r.filtered, candidate)
	r.values[candidate] = values
}

// finish returns the candidates in routing order, grouped by deployment and
// provider. A group request keeps its newest models. Without a policy order or
// sort, candidates of several models make the request ambiguous. Otherwise
// candidates follow routing.order, then the policy sort, then the default
// order: newest model, model ID, the request's provider order, the cheapest
// blended price and deployment ID. Only the organization, folder, grant, key
// and request policies set an order or sort, never in a conditional rule, so
// every candidate carries the same ones.
func (r *routingCandidates) finish(preference ProviderRoutingPreference) ([][]*ResolvedRequest, error) {
	filtered, values := r.filtered, r.values
	if len(filtered) == 0 {
		return nil, ErrModelUnavailable
	}
	var ordering policy.Routing
	if config := filtered[0].policy; config != nil {
		ordering = config.Routing
	}
	if filtered[0].RequestedModel != "" {
		newest := newestModelCandidates(filtered)
		if r.trace != nil && len(newest) < len(filtered) {
			r.recordOlderModels(filtered, releaseDate(newest[0]))
		}
		filtered = newest
	}
	query := ordering.Query
	if query != nil && len(query.OrderBy) == 0 {
		query = nil
	}
	if len(ordering.Order) == 0 && query == nil && spansModels(filtered) {
		models := candidateModels(filtered)
		if r.trace != nil {
			r.trace.ambiguous = models
		}
		return nil, ambiguousModelError(models)
	}
	snap := activeState()
	if snap == nil {
		return nil, ErrCatalogUnavailable
	}
	requestedOrder, err := snap.resolveProviderPreferences(preference.Order)
	if err != nil {
		return nil, err
	}
	providerRank := make(map[schemas.ModelProvider]int, len(requestedOrder))
	for index, provider := range requestedOrder {
		if _, ranked := providerRank[provider]; !ranked {
			providerRank[provider] = index
		}
	}
	// Each stable sort keeps the earlier order among its own ties, so the
	// last sort applies the first key.
	sort.SliceStable(filtered, func(i, j int) bool {
		return defaultOrderLess(filtered[i], filtered[j], providerRank, values)
	})
	if query != nil {
		candidates := make([]policy.Values, len(filtered))
		for i, candidate := range filtered {
			candidates[i] = values[candidate]
		}
		indexes, err := query.Sort(candidates)
		if err != nil {
			return nil, policyEvaluationError(err)
		}
		sorted := make([]*ResolvedRequest, len(filtered))
		for i, index := range indexes {
			sorted[i] = filtered[index]
		}
		filtered = sorted
	}
	if len(ordering.Order) > 0 {
		listed := make(map[string]int, len(ordering.Order))
		for index, id := range ordering.Order {
			listed[id] = index
		}
		rank := func(candidate *ResolvedRequest) int {
			if index, found := listed[candidate.Deployment.ID]; found {
				return index
			}
			return len(ordering.Order)
		}
		sort.SliceStable(filtered, func(i, j int) bool { return rank(filtered[i]) < rank(filtered[j]) })
	}
	groups := make([][]*ResolvedRequest, 0, len(filtered))
	for _, candidate := range filtered {
		if last := len(groups) - 1; last >= 0 && groups[last][0].Deployment.ID == candidate.Deployment.ID && groups[last][0].Provider == candidate.Provider {
			groups[last] = append(groups[last], candidate)
			continue
		}
		groups = append(groups, []*ResolvedRequest{candidate})
	}
	return groups, nil
}

// defaultOrderBlend weighs input three times output, the usual ratio for a
// blended model price. A deployment without both prices sorts last.
var defaultOrderBlend = policy.BlendedPrice{InputWeight: 3, OutputWeight: 1}

// defaultOrderLess ends every routing order. Candidates of one deployment are
// equal, so they keep their credential order.
func defaultOrderLess(left, right *ResolvedRequest, providerRank map[schemas.ModelProvider]int, values map[*ResolvedRequest]*resolvedPolicyValues) bool {
	if left.Deployment.ID == right.Deployment.ID {
		return false
	}
	if left.Deployment.ModelID != right.Deployment.ModelID {
		leftReleased, rightReleased := releaseDate(left), releaseDate(right)
		if leftReleased != rightReleased {
			return leftReleased > rightReleased
		}
		return left.Deployment.ModelID < right.Deployment.ModelID
	}
	leftRank, leftRanked := providerRank[left.Provider]
	rightRank, rightRanked := providerRank[right.Provider]
	if leftRanked != rightRanked {
		return leftRanked
	}
	if leftRank != rightRank {
		return leftRank < rightRank
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

// The loader accepts only YYYY-MM-DD release dates, which sort as text.
func releaseDate(candidate *ResolvedRequest) string {
	return candidate.Deployment.snapshot.graph.Models[candidate.Deployment.ModelID].ReleaseDate
}

// newestModelCandidates keeps the candidates of the most recently released
// models. Models released on the same day all stay.
func newestModelCandidates(candidates []*ResolvedRequest) []*ResolvedRequest {
	newest := ""
	var kept []*ResolvedRequest
	for _, candidate := range candidates {
		released := releaseDate(candidate)
		if released < newest {
			continue
		}
		if released > newest {
			newest, kept = released, kept[:0]
		}
		kept = append(kept, candidate)
	}
	return kept
}

func spansModels(group []*ResolvedRequest) bool {
	for _, candidate := range group[1:] {
		if candidate.Deployment.ModelID != group[0].Deployment.ModelID {
			return true
		}
	}
	return false
}

// recordOlderModels names each deployment of a model released before newest.
func (r *routingCandidates) recordOlderModels(candidates []*ResolvedRequest, newest string) {
	type pair struct {
		provider   schemas.ModelProvider
		deployment string
	}
	seen := map[pair]bool{}
	for _, candidate := range candidates {
		key := pair{candidate.Provider, candidate.Deployment.ID}
		if releaseDate(candidate) < newest && !seen[key] {
			seen[key] = true
			r.trace.removeSelection(routingSelection{provider: candidate.Provider, deployment: candidate.Deployment}, RemovedOlderModel, nil)
		}
	}
}

func candidateModels(resolved []*ResolvedRequest) []string {
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
	return models
}

// ambiguousModelError lists every tied model: the models that the key's policy allows for the
// request, which the public model list does not show. The catalog bounds the list.
func ambiguousModelError(models []string) APIError {
	message := ErrModelAmbiguous.Message + "; matching models: " + strings.Join(models, ", ")
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
	if candidate == nil || candidate.Deployment.snapshot == nil {
		return policyIDs{}
	}
	snap := candidate.Deployment.snapshot
	model, ok := snap.graph.Models[candidate.Deployment.ModelID]
	if !ok {
		return policyIDs{}
	}
	routeID := candidate.Deployment.RouteID
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

// validatePolicyVocabulary rejects a value of a changed node that policies read but cannot name,
// because a policy that compares a field with a value outside its vocabulary fails at save. A
// deployment's values differ by route. Requests set the request fields.
func validatePolicyVocabulary(state *snapshot, changed compiledGraph) error {
	paths := make(map[string][]string)
	for _, path := range policy.VocabularyPaths() {
		root, _, _ := strings.Cut(path, ".")
		paths[root] = append(paths[root], path)
	}
	if err := validateNodeVocabulary("author", changed.Authors, paths["author"]); err != nil {
		return err
	}
	if err := validateNodeVocabulary("model", changed.Models, paths["model"]); err != nil {
		return err
	}
	if err := validateNodeVocabulary("provider", changed.Providers, paths["provider"]); err != nil {
		return err
	}
	if err := validateNodeVocabulary("route", changed.Routes, paths["route"]); err != nil {
		return err
	}
	for _, deploymentID := range slices.Sorted(maps.Keys(changed.Deployments)) {
		for _, routeID := range sortedRouteIDs(changed.Deployments[deploymentID]) {
			deployment, _ := state.deploymentFromCompiledAt(deploymentID, state.graph.Routes[routeID], time.Time{})
			values, ok := newResolvedPolicyValues(&ResolvedRequest{Deployment: deployment})
			if !ok {
				return fmt.Errorf("deployment %s route %s is not readable by policies", deploymentID, routeID)
			}
			if err := validateVocabulary("deployment "+deploymentID+" route "+routeID, values, paths["deployment"]); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateNodeVocabulary[T any](root string, nodes map[string]T, paths []string) error {
	for _, id := range slices.Sorted(maps.Keys(nodes)) {
		values := &resolvedPolicyValues{root: map[string]policyNode{root: {id: id, fields: nodes[id]}}}
		if err := validateVocabulary(root+" "+id, values, paths); err != nil {
			return err
		}
	}
	return nil
}

func validateVocabulary(owner string, values *resolvedPolicyValues, paths []string) error {
	for _, path := range paths {
		value, ok := values.resolveField(path)
		if !ok {
			continue
		}
		items := value.Strings
		if value.Type == "string" {
			items = []string{value.String}
		}
		for _, item := range items {
			if !policy.ValidFieldValue(path, item) {
				return fmt.Errorf("%s has %s %q outside the policy vocabulary", owner, path, item)
			}
		}
	}
	return nil
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
				ContextWindowTokens: deployment.ContextWindowTokens,
				MaxInputTokens:      deployment.MaxInputTokens,
				DataHandling:        deployment.DataHandling,
				InputModalities:     deployment.InputModalities,
				MaxOutputTokens:     deployment.MaxOutputTokens,
				ModelID:             deployment.ModelID,
				OutputModalities:    deployment.OutputModalities,
				Pricing:             deployment.Pricing,
				Reasoning:           deployment.Reasoning,
				ReasoningEfforts:    deployment.ReasoningEfforts,
				ReasoningMaxTokens:  deployment.ReasoningMaxTokens,
				RetirementDate:      compiledDeployment.RetirementDate,
				Upstream:            compiledDeployment.Upstream,
				ApprovalRequired:    deployment.ApprovalRequired,
				WeightPrecision:     deployment.WeightPrecision,
			},
		},
		"model":    {id: ids.model, fields: model},
		"provider": {id: ids.provider, fields: provider},
		"request": {fields: policyRequestData{
			BodyBytes: candidate.policyBodyBytes,
			Interface: candidate.Route.Interface(),
			Model:     candidate.RequestedModel,
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
	root, rest, _ := strings.Cut(path, ".")
	node, ok := v.root[root]
	if !ok {
		return policy.Value{}, false
	}
	if rest == "id" {
		return policy.Value{Type: fieldType, String: node.id}, true
	}
	current := reflect.ValueOf(node.fields)
	for name := range strings.SplitSeq(rest, ".") {
		if current, ok = policyChild(current, name); !ok {
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
		if index, ok := policyFields(value.Type())[name]; ok {
			return value.Field(index), true
		}
	}
	return reflect.Value{}, false
}

var policyFieldIndexes sync.Map // reflect.Type -> immutable map of JSON names to field indexes

// policyFields indexes the fields of a struct type by JSON name, so policies parse each type's
// tags once rather than on every read.
func policyFields(shape reflect.Type) map[string]int {
	if fields, ok := policyFieldIndexes.Load(shape); ok {
		return fields.(map[string]int)
	}
	fields := make(map[string]int, shape.NumField())
	for index := range shape.NumField() {
		field := shape.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = index
	}
	stored, _ := policyFieldIndexes.LoadOrStore(shape, fields)
	return stored.(map[string]int)
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
