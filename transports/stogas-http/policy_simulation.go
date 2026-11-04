package stogashttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

const policySimulationPath = "/v1/policies/simulate"

type simulationOrigin struct {
	Scope policy.Scope `json:"scope"`
	ID    string       `json:"id"`
	Rule  string       `json:"rule,omitempty"`
}

type simulationPair struct {
	Provider   schemas.ModelProvider `json:"provider"`
	Deployment string                `json:"deployment"`
	// Chain is the hash of the catalog chain that the pair calls through, as a
	// request log names each attempt's.
	Chain      string `json:"chain"`
	Model      string `json:"model"`
	Credential int    `json:"credential"`
	Retries    int    `json:"retries"`
	// ReplacedDefaults is set on each pair that the request tries, and lists
	// the settings of its matched default rules that a requirement replaces.
	ReplacedDefaults []simulationReplacedDefault `json:"replacedDefaults,omitzero"`
}

// simulationReplacedDefault is a default rule's setting that a requirement
// replaces on one pair, with the first requirement in the pair's policy chain
// that does, and how many others do too.
type simulationReplacedDefault struct {
	Setting string           `json:"setting"`
	Default simulationOrigin `json:"default"`
	By      simulationOrigin `json:"by"`
	Others  int              `json:"others,omitempty"`
}

type simulationRemoval struct {
	Reason     string                `json:"reason"`
	Provider   schemas.ModelProvider `json:"provider"`
	Deployment string                `json:"deployment,omitempty"`
	Model      string                `json:"model,omitempty"`
	Credential *int                  `json:"credential,omitempty"`
	Origin     *simulationOrigin     `json:"origin,omitempty"`
	Expression string                `json:"expression,omitempty"`
	Unknown    bool                  `json:"unknown,omitempty"`
	Code       string                `json:"code,omitempty"`
	Labels     []string              `json:"labels,omitempty"`
	Tools      []string              `json:"tools,omitempty"`
}

type simulationCredential struct {
	Mode            string `json:"mode"`
	ID              string `json:"id,omitempty"`
	EncryptionKeyID string `json:"encryptionKeyId,omitempty"`
}

type simulationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Origin locates the deny period of a schedule_denied error, or the
	// policy that fails a request without an encryption key it needs.
	Origin *simulationOrigin `json:"origin,omitempty"`
}

// policySimulation answers what a request that names only a model, a service
// tier, a reasoning mode, the types of its tools and its tool_choice, and the
// labels of the encryption keys it sends would try, and what removed every
// other candidate.
type policySimulation struct {
	Draft           string                            `json:"draft,omitempty"`
	Pairs           []simulationPair                  `json:"pairs"`
	Tried           int                               `json:"tried"`
	Fallbacks       int                               `json:"fallbacks"`
	FallbacksOrigin *simulationOrigin                 `json:"fallbacksOrigin"`
	Order           *simulationOrigin                 `json:"order"`
	Sort            []simulationCriterion             `json:"sort"`
	Removed         []simulationRemoval               `json:"removed"`
	Truncated       int                               `json:"truncated"`
	Ambiguous       []string                          `json:"ambiguous"`
	Credentials     map[string][]simulationCredential `json:"credentials"`
	Error           *simulationError                  `json:"error"`
}

// simulationCriterion is one routing.sort criterion that the key's policies
// combine, in the order that they apply, with the policy that sets it.
type simulationCriterion struct {
	Criterion policy.Sort       `json:"criterion"`
	Origin    *simulationOrigin `json:"origin"`
}

type simulationCandidate struct {
	provider schemas.ModelProvider
	index    int
}

// maxSimulatedTools bounds the tools of a simulated request, which lists types alone.
const maxSimulatedTools = 128

// simulatedTools reports whether a simulation's tools are types alone: at most 128 types, and a
// tool_choice that is a mode, or an object with its type and, for allowed_tools, the type of each
// tool that it allows.
func simulatedTools(tools []string, choice json.RawMessage) bool {
	toolType := func(value string) bool { return value != "" && len(value) <= 64 }
	if len(tools) > maxSimulatedTools || slices.ContainsFunc(tools, func(tool string) bool { return !toolType(tool) }) {
		return false
	}
	if choice == nil {
		return true
	}
	var mode string
	if json.Unmarshal(choice, &mode) == nil {
		return toolType(mode)
	}
	var object struct {
		Type  string
		Tools []struct{ Type string }
	}
	decoder := json.NewDecoder(bytes.NewReader(choice))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&object) != nil || !toolType(object.Type) || len(object.Tools) > maxSimulatedTools ||
		object.Tools != nil && object.Type != "allowed_tools" {
		return false
	}
	return !slices.ContainsFunc(object.Tools, func(tool struct{ Type string }) bool { return !toolType(tool.Type) })
}

// simulatePolicy runs routing for a key that a dashboard user can see, with a
// policy draft in place of its saved policy. It prepares no credential and
// calls no provider.
func (s *Server) simulatePolicy(ctx *requestContext) {
	credential, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return
	}
	if credential.Dashboard == nil {
		s.writeError(ctx, http.StatusForbidden, map[string]any{"error": map[string]any{"code": "permission_denied", "message": "Routing simulations need a dashboard session", "type": "permission_denied"}})
		return
	}
	fields, err := catalog.DecodeRequestBody(ctx.body, ctx.memory.admitJSON)
	if err != nil {
		if errors.Is(err, errRequestMemoryCapacity) {
			s.writeRequestMemoryCapacity(ctx)
			return
		}
		s.writeCatalogError(ctx, err)
		return
	}
	var input struct {
		Interface     string
		Model         string
		ServiceTier   string
		ReasoningMode string
		// Tools lists the type of each tool that a Responses request lists, and
		// ToolChoice is its tool_choice with only the types that routing reads.
		Tools      []string
		ToolChoice json.RawMessage
		Policy     *billing.PolicyValidationSource
		// EncryptionKeys lists the labels of the keys that the simulated
		// request sends. Without it, the request sends every registered key.
		EncryptionKeys *[]string
	}
	valid := ctx.request.URL.RawQuery == ""
	for name, raw := range fields {
		var target any
		switch name {
		case "interface":
			target = &input.Interface
		case "model":
			target = &input.Model
		case "serviceTier":
			target = &input.ServiceTier
		case "reasoningMode":
			target = &input.ReasoningMode
		case "tools":
			target = &input.Tools
		case "toolChoice":
			target = &input.ToolChoice
		case "policy":
			target = &input.Policy
		case "encryptionKeys":
			target = &input.EncryptionKeys
		default:
			valid = false
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		valid = valid && decoder.Decode(target) == nil
	}
	route, known := catalog.RouteForInterface(input.Interface)
	if input.Tools != nil || input.ToolChoice != nil {
		valid = valid && route == catalog.RouteResponses && simulatedTools(input.Tools, input.ToolChoice)
	}
	if !valid || !known ||
		input.Policy != nil && (!input.Policy.Scope.Valid() || input.Policy.ID == "" || len(input.Policy.ID) > 64 || len(input.Policy.Config) == 0) {
		s.writeError(ctx, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "invalid_request", "message": "Provide interface as chat_completions or responses, optional model, serviceTier and reasoningMode strings, for responses optional tools listing up to 128 tool types and an optional toolChoice as a mode or an object with only its types, optional encryptionKeys as a list of registered labels, and an optional policy with scope, id and config", "type": "invalid_request_error"}})
		return
	}
	if s.runtime == nil || s.runtime.Billing() == nil {
		s.writeBillingError(ctx, billing.ErrGatewayUnavailable)
		return
	}
	config, applied, err := s.runtime.Billing().SimulationConfig(ctx.request.Context(), credential.Dashboard, input.Policy)
	if errors.Is(err, billing.ErrInvalidAPIKey) || errors.Is(err, billing.ErrDashboardKeyDenied) ||
		errors.Is(err, billing.ErrGatewayUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		s.writeBillingError(ctx, err)
		return
	}
	result := policySimulation{Pairs: []simulationPair{}, Removed: []simulationRemoval{}, Sort: []simulationCriterion{}, Ambiguous: []string{}, Credentials: map[string][]simulationCredential{}}
	if input.Policy != nil {
		result.Draft = "not_applicable"
		if applied {
			result.Draft = "applied"
		}
	}
	// Requests get the same error, so it is the simulation's result.
	if err != nil {
		public := stogas.PublicBillingErrorFor(err)
		result.Error = &simulationError{Code: public.Code, Message: public.Message}
		s.writeJSON(ctx, http.StatusOK, result)
		return
	}
	ctx.claims = config.Claims
	if input.EncryptionKeys != nil {
		seen := make(map[string]bool, len(*input.EncryptionKeys))
		for _, label := range *input.EncryptionKeys {
			if seen[label] {
				s.writeError(ctx, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "invalid_request", "message": "List each encryption key label once", "type": "invalid_request_error"}})
				return
			}
			seen[label] = true
		}
		// A request that sends a key under a label that the organization
		// policy does not register fails, so the simulated one does too.
		for label := range seen {
			if _, registered := config.Config.EncryptionKeys[label]; !registered {
				public := stogas.PublicBillingErrorFor(customerkey.ErrKey)
				result.Error = &simulationError{Code: public.Code, Message: public.Message}
				s.writeJSON(ctx, http.StatusOK, result)
				return
			}
		}
	}
	for provider, selections := range config.Credentials {
		list := make([]simulationCredential, len(selections))
		for i, selection := range selections {
			list[i] = simulationCredential{Mode: selection.Mode, ID: selection.ID}
			if selection.Mode == "encrypted" && selection.Credential != nil {
				list[i].EncryptionKeyID = selection.Credential.EncryptionKeyID
			}
		}
		result.Credentials[provider] = list
	}
	now := time.Now().UTC()
	if config.Config.DeniedAt(now) {
		public := catalog.PublicError(catalog.ErrScheduleDenied)
		result.Error = &simulationError{Code: public.Code, Message: public.Message}
		if origin, ok := config.Config.DenyOrigin(now); ok {
			result.Error.Origin, _ = originFor(&origin, config.Versions, input.Policy)
		}
		s.writeJSON(ctx, http.StatusOK, result)
		return
	}
	available := map[string][]int{}
	for provider, selections := range config.Credentials {
		for index := range selections {
			available[provider] = append(available[provider], index)
		}
	}
	chains := map[simulationCandidate]*billing.PolicyVersions{}
	var budget policy.SourceBudget
	simulation := catalog.SimulateRouting(catalog.RequestInput{
		Policy:               config.Config,
		AvailableCredentials: available,
		DeploymentEligible:   stogas.CredentialDeploymentFilter(config, now),
		DeploymentChanged:    stogas.CredentialTargetChanged(config),
		CredentialPolicy: func(provider schemas.ModelProvider, index int) (catalog.RequestPolicy, error) {
			selected, err := config.SimulatedPolicyForCredential(string(provider), index, now, &budget)
			if err != nil {
				if errors.Is(err, policy.ErrSourceBudget) {
					return catalog.RequestPolicy{}, err
				}
				public := stogas.PublicBillingErrorFor(err)
				return catalog.RequestPolicy{}, errors.Join(err, catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message})
			}
			chains[simulationCandidate{provider, index}] = selected.Versions
			return catalog.RequestPolicy{Config: selected.Config}, nil
		},
		CheckRoots: func(pairs []catalog.PlannedPair) error {
			if input.EncryptionKeys == nil {
				return nil
			}
			var ids []string
			for _, pair := range pairs {
				ids = append(ids, config.RequiredRoots(string(pair.Provider), pair.Credential, pair.Policy)...)
			}
			if err := customerkey.MissingLabels(config.Config.EncryptionKeys, *input.EncryptionKeys, ids...); err != nil {
				public := stogas.PublicBillingErrorFor(err)
				return errors.Join(err, catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message})
			}
			return nil
		},
	}, route, input.Model, input.ServiceTier, input.ReasoningMode, input.Tools, input.ToolChoice)
	for _, removed := range simulation.Removed {
		versions := config.Versions
		if removed.Credential != nil {
			versions = chains[simulationCandidate{removed.Provider, *removed.Credential}]
		}
		entry := simulationRemoval{Reason: removed.Reason, Provider: removed.Provider, Deployment: removed.Deployment, Model: removed.Model,
			Credential: removed.Credential, Expression: removed.Expression, Unknown: removed.Unknown, Code: removed.Code, Labels: removed.Labels,
			Tools: removed.Tools}
		var hidden bool
		if entry.Origin, hidden = originFor(removed.Origin, versions, input.Policy); hidden {
			entry.Expression = ""
		}
		result.Removed = append(result.Removed, entry)
	}
	result.Truncated = simulation.Truncated
	// The key's policy chain sets every criterion.
	for _, criterion := range simulation.Sort {
		origin, _ := originFor(&criterion.Origin, config.Versions, input.Policy)
		result.Sort = append(result.Sort, simulationCriterion{Criterion: criterion.Sort, Origin: origin})
	}
	result.Order, _ = originFor(simulation.Order, config.Versions, input.Policy)
	if simulation.Ambiguous != nil {
		result.Ambiguous = simulation.Ambiguous
	}
	if simulation.Err != nil {
		public := catalog.PublicError(simulation.Err)
		result.Error = &simulationError{Code: public.Code, Message: public.Message}
		if missing := (*catalog.MissingKeysError)(nil); errors.As(simulation.Err, &missing) {
			result.Error.Origin, _ = originFor(&missing.Origin, chains[simulationCandidate{missing.Pair.Provider, missing.Pair.Credential}], input.Policy)
		}
		s.writeJSON(ctx, http.StatusOK, result)
		return
	}
	for i, pair := range simulation.Pairs {
		entry := simulationPair{Provider: pair.Provider, Deployment: pair.Deployment.ID, Chain: pair.Deployment.ChainHash, Model: pair.Deployment.ModelID, Credential: pair.Credential, Retries: pair.Retries}
		if i < simulation.Tried {
			chain := chains[simulationCandidate{pair.Provider, pair.Credential}]
			entry.ReplacedDefaults = []simulationReplacedDefault{}
			for _, replaced := range pair.ReplacedDefaults {
				defaults, _ := originFor(&replaced.Default, chain, input.Policy)
				by, _ := originFor(&replaced.By, chain, input.Policy)
				if defaults != nil && by != nil {
					entry.ReplacedDefaults = append(entry.ReplacedDefaults, simulationReplacedDefault{Setting: replaced.Setting, Default: *defaults, By: *by, Others: replaced.Others})
				}
			}
		}
		result.Pairs = append(result.Pairs, entry)
	}
	first := chains[simulationCandidate{simulation.Pairs[0].Provider, simulation.Pairs[0].Credential}]
	result.Tried, result.Fallbacks = simulation.Tried, simulation.Fallbacks
	result.FallbacksOrigin, _ = originFor(simulation.FallbacksOrigin, first, input.Policy)
	s.writeJSON(ctx, http.StatusOK, result)
}

// originFor names the policy that holds a setting. A key's viewer may not
// see the policies of its credentials, so originFor hides a credential
// policy's rules and reports that its expressions are hidden too, unless the
// caller sent that policy as the draft.
func originFor(origin *policy.Origin, versions *billing.PolicyVersions, draft *billing.PolicyValidationSource) (*simulationOrigin, bool) {
	if origin == nil || versions == nil || origin.Source < 0 || origin.Source >= len(*versions) {
		return nil, false
	}
	version := (*versions)[origin.Source]
	if version.Scope == policy.CredentialScope && (draft == nil || draft.Scope != version.Scope || draft.ID != version.ID) {
		return &simulationOrigin{Scope: version.Scope, ID: version.ID}, true
	}
	return &simulationOrigin{Scope: version.Scope, ID: version.ID, Rule: origin.Rule}, false
}
