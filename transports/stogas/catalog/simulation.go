package catalog

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// Removal reasons name the routing step that removed a candidate.
const (
	// The provider serves the model only through another interface.
	RemovedInterface = "interface"
	// The key has no credential for the provider.
	RemovedNoCredential = "no_credential"
	// The provider does not run the model in the requested reasoning mode.
	RemovedReasoningMode = "reasoning_mode"
	// The provider does not run the model at the requested service tier.
	RemovedServiceTier = "service_tier"
	// The deployment needs a request that names it exactly.
	RemovedApproval = "approval"
	// routing.allowedCatalogNodes excludes the deployment.
	RemovedAllowedNodes = "allowed_nodes"
	// The credential's provider account has no matching deployment.
	RemovedCredentialTarget = "credential_target"
	// The credential cannot serve requests; Code says why.
	RemovedCredential = "credential"
	// A rule's condition reads a fact the deployment does not state.
	RemovedCondition = "condition"
	// An access deny period covers the current time.
	RemovedDeny = "deny"
	// A routing filter is false, or reads a fact the deployment does not state.
	RemovedFilter = "filter"
	// A request tries at most 1 + policy.MaxFallbacks credentials of a deployment.
	RemovedPairLimit = "pair_limit"
	// The request did not send an encryption key that the pair needs, and
	// routing.missingEncryptionKeys skips such pairs. Labels names the keys.
	RemovedEncryptionKey = "encryption_key"
	// The deployment's route does not run every hosted tool that the request lists. Tools names
	// the missing ones.
	RemovedHostedTool = "hosted_tool"
)

// RemovedCandidate is a provider, a deployment, or a deployment and credential
// pair that cannot serve a simulated request.
type RemovedCandidate struct {
	Reason     string
	Provider   schemas.ModelProvider
	Deployment string
	Model      string
	// Credential is set for a pair. Origin then locates a setting in that
	// credential's policy, and otherwise in the key's policy.
	Credential *int
	Origin     *policy.Origin
	// Expression is the undecided condition or the filter that removed a pair.
	Expression string
	Unknown    bool
	Code       string
	Labels     []string
	Tools      []string
}

// SimulatedPair is one deployment and credential in routing order.
type SimulatedPair struct {
	Provider   schemas.ModelProvider
	Deployment Deployment
	Credential int
	// Retries is routing.retries in the pair's policy, which a request
	// takes when it uses the pair.
	Retries int
}

// SimulatedCriterion is one composed routing.sort criterion and the policy,
// and for a default criterion its rule, that sets it.
type SimulatedCriterion struct {
	Sort   policy.Sort
	Origin policy.Origin
}

// RoutingSimulation shows how routing treats a request that names only a
// model, a service tier, a reasoning mode and its tools. A request tries the
// first Tried pairs in order.
// Sort locates each criterion in the key's policy, which every pair shares,
// even when routing fails; Order is the origin of the first criterion.
// FallbacksOrigin locates the count in the first pair's policy.
type RoutingSimulation struct {
	Pairs           []SimulatedPair
	Tried           int
	Removed         []RemovedCandidate
	Truncated       int
	Sort            []SimulatedCriterion
	Order           *policy.Origin
	Fallbacks       int
	FallbacksOrigin *policy.Origin
	// Ambiguous lists the tied models of a model_ambiguous request, or the
	// tied deployments of a deployment_ambiguous one.
	Ambiguous []string
	Err       error
}

// SimulateRouting runs request routing up to its pair plan. It prepares no
// credential, opens no encrypted content and calls no provider. Tools are the
// types of a Responses request's tools, and toolChoice its tool_choice, which
// routing reads for the hosted tools that the request lists and lets the model
// call.
func SimulateRouting(input RequestInput, route Route, model, tier, mode string, tools []string, toolChoice json.RawMessage) *RoutingSimulation {
	trace := &routingTrace{}
	input.now, input.policyBudget, input.trace = time.Now().UTC(), policy.NewCELBudget(), trace
	activationMu.RLock()
	defer activationMu.RUnlock()
	fields := map[string]json.RawMessage{}
	if model != "" {
		fields["model"], _ = json.Marshal(model)
	}
	if tier != "" {
		fields["service_tier"], _ = json.Marshal(tier)
	}
	if mode != "" {
		fields["reasoning"], _ = json.Marshal(map[string]string{"mode": mode})
	}
	if len(tools) > 0 || len(toolChoice) > 0 {
		declared := make([]map[string]string, len(tools))
		for i, tool := range tools {
			declared[i] = map[string]string{"type": tool}
		}
		body := map[string]json.RawMessage{"tool_choice": toolChoice}
		body["tools"], _ = json.Marshal(declared)
		if len(toolChoice) == 0 {
			delete(body, "tool_choice")
		}
		use := requestHostedTools(route, body)
		input.hostedTools = &use
	}
	plan, err := planRoutes(input, route, fields)
	result := &RoutingSimulation{Removed: trace.removed, Truncated: trace.truncated, Ambiguous: trace.ambiguous, Err: err}
	// Credential policies and conditional rules set no criteria, so the key's
	// policy holds the ones that every pair uses.
	if config := input.Policy; config != nil && config.Routing.Query != nil {
		for i, origin := range config.SortOrigins() {
			result.Sort = append(result.Sort, SimulatedCriterion{Sort: config.Routing.Query.OrderBy[i], Origin: origin})
		}
	}
	if len(result.Sort) > 0 {
		result.Order = &result.Sort[0].Origin
	}
	if err != nil {
		return result
	}
	for _, choice := range plan.choices {
		pair := SimulatedPair{Provider: choice.candidate.Provider, Deployment: choice.candidate.Deployment, Credential: choice.index}
		if config := choice.candidate.policy; config != nil {
			pair.Retries = config.Routing.Retries
		}
		result.Pairs = append(result.Pairs, pair)
	}
	result.Tried, result.Fallbacks = min(plan.slots, len(plan.choices)), plan.slots-1
	if config := plan.choices[0].candidate.policy; config != nil {
		if origin, ok := config.FallbacksOrigin(); ok {
			result.FallbacksOrigin = &origin
		}
	}
	return result
}

// routingTrace records why routing removed candidates. Requests route with a
// nil trace, which records nothing.
type routingTrace struct {
	removed   []RemovedCandidate
	truncated int
	ambiguous []string
	// Credentials with one policy share the removal of the group's first one.
	groups map[pairGroup]RemovedCandidate
}

type pairGroup struct {
	provider   schemas.ModelProvider
	deployment string
	policy     *policy.Config
}

// maxRemovedCandidates bounds a simulation; Truncated counts the rest.
const maxRemovedCandidates = 1000

func (t *routingTrace) remove(entry RemovedCandidate) {
	if t == nil {
		return
	}
	if len(t.removed) == maxRemovedCandidates {
		t.truncated++
		return
	}
	t.removed = append(t.removed, entry)
}

func (t *routingTrace) removeProvider(provider schemas.ModelProvider, reason string) {
	t.remove(RemovedCandidate{Reason: reason, Provider: provider})
}

func (t *routingTrace) removeSelection(selection routingSelection, reason string, origin *policy.Origin) {
	t.remove(RemovedCandidate{Reason: reason, Provider: selection.provider, Deployment: selection.deployment.ID, Model: selection.deployment.ModelID, Origin: origin})
}

// removePair records a credential's removal. The other credentials of its
// group share the removal.
func (t *routingTrace) removePair(selection routingSelection, index int, group *policy.Config, entry RemovedCandidate) {
	if t == nil {
		return
	}
	entry.Provider, entry.Deployment, entry.Model, entry.Credential = selection.provider, selection.deployment.ID, selection.deployment.ModelID, &index
	if group != nil {
		if t.groups == nil {
			t.groups = make(map[pairGroup]RemovedCandidate)
		}
		t.groups[pairGroup{selection.provider, selection.deployment.ID, group}] = entry
	}
	t.remove(entry)
}

func (t *routingTrace) removeGrouped(selection routingSelection, index int, group *policy.Config) {
	if t != nil {
		t.removePair(selection, index, nil, t.groups[pairGroup{selection.provider, selection.deployment.ID, group}])
	}
}

// providerSkips names providers whose routes serve the requested model or
// group only where a request cannot use them: without a credential, or on
// another interface. A provider that any route serves is not named.
type providerSkips struct {
	trace   *routingTrace
	reasons map[schemas.ModelProvider]string
	kept    map[schemas.ModelProvider]bool
}

// add records a route that serves the model. A missing credential outranks
// another interface, since a credential would let a supported route serve.
func (p *providerSkips) add(provider schemas.ModelProvider, supported bool) {
	if p.trace == nil {
		return
	}
	if p.reasons == nil {
		p.reasons = make(map[schemas.ModelProvider]string)
	}
	if supported {
		p.reasons[provider] = RemovedNoCredential
	} else if p.reasons[provider] == "" {
		p.reasons[provider] = RemovedInterface
	}
}

func (p *providerSkips) served(provider schemas.ModelProvider) {
	if p.trace == nil {
		return
	}
	if p.kept == nil {
		p.kept = make(map[schemas.ModelProvider]bool)
	}
	p.kept[provider] = true
}

func (p *providerSkips) record() {
	providers := make([]schemas.ModelProvider, 0, len(p.reasons))
	for provider := range p.reasons {
		if !p.kept[provider] {
			providers = append(providers, provider)
		}
	}
	slices.Sort(providers)
	for _, provider := range providers {
		p.trace.removeProvider(provider, p.reasons[provider])
	}
}

func nodesOrigin(config *policy.Config, deployment Deployment) *policy.Origin {
	ids := candidatePolicyIDs(&ResolvedRequest{Deployment: deployment})
	if origin, ok := config.NodesOrigin(ids.author, ids.model, ids.deployment, ids.route, ids.provider); ok {
		return &origin
	}
	return nil
}
