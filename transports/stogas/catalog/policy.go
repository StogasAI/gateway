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
	DataHandling        policyDataHandling  `json:"dataHandling"`
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

// policyDataHandling is a deployment's data handling as policies read it, with each location's
// places: the location and every place that contains it, so that a policy can name a region.
type policyDataHandling struct {
	DataHandling     `json:",inline"`
	ProcessingWithin []string `json:"processingWithin"`
	StorageWithin    []string `json:"storageWithin"`
}

type policyRequestData struct {
	BodyBytes   int      `json:"bodyBytes"`
	HostedTools []string `json:"hostedTools"`
	Interface   string   `json:"interface"`
	Model       string   `json:"model"`
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

// routingSelectionsForRequest returns the deployments that the requested model selects at the
// variant. It returns none when the variant leaves no deployment, and the caller names the
// field.
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
	for _, provider := range providers {
		deployments := routingDeploymentsForProvider(snap, route, provider, requestedModel, want)
		if trace != nil && len(deployments) == 0 {
			if _, servesMode := snap.deploymentForRoute(provider, requestedModel, route, variant{mode: want.mode}); servesMode {
				trace.removeProvider(provider, RemovedServiceTier)
			} else if want.mode != "" {
				trace.removeProvider(provider, RemovedReasoningMode)
			}
		}
		selections = append(selections, deployments...)
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
// provider, and whether each group ties the one before it. Only policies order
// candidates: the required sort criteria, then the request's provider order,
// then the default criteria. Only the organization, folder, grant, key and
// request policies set criteria, never in a conditional rule, so every
// candidate carries the same ones. Tied candidates keep their input order,
// which keeps each deployment's credential order.
func (r *routingCandidates) finish(preference ProviderRoutingPreference) ([][]*ResolvedRequest, []bool, error) {
	filtered, values := r.filtered, r.values
	if len(filtered) == 0 {
		return nil, nil, ErrModelUnavailable
	}
	var query *policy.Query
	required := 0
	if config := filtered[0].policy; config != nil {
		query, required = config.Routing.Query, config.RequiredSorts()
	}
	if len(preference.Order) > 0 {
		snap := activeState()
		if snap == nil {
			return nil, nil, ErrCatalogUnavailable
		}
		providers, err := snap.resolveProviderPreferences(preference.Order)
		if err != nil {
			return nil, nil, err
		}
		ids := make([]string, len(providers))
		for i, provider := range providers {
			ids[i] = string(provider)
		}
		query = query.WithSort(required, policy.ProviderOrder(ids))
	}
	candidates := make([]policy.Values, len(filtered))
	for i, candidate := range filtered {
		candidates[i] = values[candidate]
	}
	indexes, ties, err := query.Sort(candidates)
	if err != nil {
		return nil, nil, policyEvaluationError(err)
	}
	groups := make([][]*ResolvedRequest, 0, len(filtered))
	groupTies := make([]bool, 0, len(filtered))
	for i, index := range indexes {
		candidate := filtered[index]
		if last := len(groups) - 1; last >= 0 && groups[last][0].Deployment.ID == candidate.Deployment.ID && groups[last][0].Provider == candidate.Provider {
			groups[last] = append(groups[last], candidate)
			continue
		}
		groups = append(groups, []*ResolvedRequest{candidate})
		groupTies = append(groupTies, ties[i])
	}
	return groups, groupTies, nil
}

// maxAmbiguousIDs bounds the IDs that an ambiguity error names, so a request
// cannot list the catalog through it.
const maxAmbiguousIDs = 3

// ambiguousError names what tied groups differ in: their models when they
// span several, otherwise their deployments. It names the first few in ID
// order and counts the rest, and returns every ID for a simulation.
func ambiguousError(groups [][]*ResolvedRequest) (APIError, []string) {
	models, deployments := map[string]bool{}, map[string]bool{}
	for _, group := range groups {
		models[group[0].Deployment.ModelID] = true
		deployments[group[0].Deployment.ID] = true
	}
	base, set := ErrDeploymentAmbiguous, deployments
	if len(models) > 1 {
		base, set = ErrModelAmbiguous, models
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	named := strings.Join(ids[:min(len(ids), maxAmbiguousIDs)], ", ")
	if more := len(ids) - maxAmbiguousIDs; more > 0 {
		named += fmt.Sprintf(" and %d more", more)
	}
	base.Message = fmt.Sprintf(base.Message, named)
	return base, ids
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
	// A hosted tool that the request lets the model call can send its content further, so the
	// policy reads the deployment's data handling joined with the tools'.
	dataHandling := candidate.EffectiveDataHandling()
	hostedTools := make([]string, len(candidate.hostedTools))
	for i, tool := range candidate.hostedTools {
		hostedTools[i] = string(tool)
	}
	return &resolvedPolicyValues{now: candidate.policyTime, budget: candidate.policyBudget, pricing: deployment.Pricing, root: map[string]policyNode{
		"author": {id: ids.author, fields: author},
		"deployment": {
			id: ids.deployment,
			fields: policyDeploymentData{
				Capabilities:        deployment.Capabilities,
				ContextWindowTokens: deployment.ContextWindowTokens,
				MaxInputTokens:      deployment.MaxInputTokens,
				DataHandling: policyDataHandling{
					DataHandling:     dataHandling,
					ProcessingWithin: deployment.Locations.Containing(dataHandling.ProcessingLocation),
					StorageWithin:    deployment.Locations.Containing(dataHandling.StorageLocation),
				},
				InputModalities:    deployment.InputModalities,
				MaxOutputTokens:    deployment.MaxOutputTokens,
				ModelID:            deployment.ModelID,
				OutputModalities:   deployment.OutputModalities,
				Pricing:            deployment.Pricing,
				Reasoning:          deployment.Reasoning,
				ReasoningEfforts:   deployment.ReasoningEfforts,
				ReasoningMaxTokens: deployment.ReasoningMaxTokens,
				RetirementDate:     compiledDeployment.RetirementDate,
				Upstream:           compiledDeployment.Upstream,
				ApprovalRequired:   deployment.ApprovalRequired,
				WeightPrecision:    deployment.WeightPrecision,
			},
		},
		"model":    {id: ids.model, fields: model},
		"provider": {id: ids.provider, fields: provider},
		"request": {fields: policyRequestData{
			BodyBytes:   candidate.policyBodyBytes,
			HostedTools: hostedTools,
			Interface:   candidate.Route.Interface(),
			Model:       candidate.RequestedModel,
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
			return value.FieldByIndex(index), true
		}
	}
	return reflect.Value{}, false
}

var policyFieldIndexes sync.Map // reflect.Type -> immutable map of JSON names to field index paths

// policyFields indexes the fields of a struct type by JSON name, so policies parse each type's
// tags once rather than on every read. The fields of an inline struct read as the struct's own.
func policyFields(shape reflect.Type) map[string][]int {
	if fields, ok := policyFieldIndexes.Load(shape); ok {
		return fields.(map[string][]int)
	}
	fields := make(map[string][]int, shape.NumField())
	for index := range shape.NumField() {
		field := shape.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if field.Anonymous && options == "inline" {
			for inner, path := range policyFields(field.Type) {
				fields[inner] = append([]int{index}, path...)
			}
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = []int{index}
	}
	stored, _ := policyFieldIndexes.LoadOrStore(shape, fields)
	return stored.(map[string][]int)
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
