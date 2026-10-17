package stogashttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
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
	Model      string                `json:"model"`
	Credential int                   `json:"credential"`
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
}

type simulationCredential struct {
	Mode            string `json:"mode"`
	ID              string `json:"id,omitempty"`
	EncryptionKeyID string `json:"encryptionKeyId,omitempty"`
}

type simulationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Origin locates the deny period of a schedule_denied error.
	Origin *simulationOrigin `json:"origin,omitempty"`
}

// policySimulation answers what a request that names only a model and a
// service tier would try, and what removed every other candidate.
type policySimulation struct {
	Draft           string                            `json:"draft,omitempty"`
	Pairs           []simulationPair                  `json:"pairs"`
	Tried           int                               `json:"tried"`
	Fallbacks       int                               `json:"fallbacks"`
	FallbacksOrigin *simulationOrigin                 `json:"fallbacksOrigin"`
	Order           *simulationOrigin                 `json:"order"`
	Removed         []simulationRemoval               `json:"removed"`
	Truncated       int                               `json:"truncated"`
	Ambiguous       []string                          `json:"ambiguous"`
	Credentials     map[string][]simulationCredential `json:"credentials"`
	Error           *simulationError                  `json:"error"`
}

type simulationCandidate struct {
	provider schemas.ModelProvider
	index    int
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
		Route       catalog.Route
		Model       string
		ServiceTier string
		Policy      *billing.PolicyValidationSource
	}
	valid := ctx.request.URL.RawQuery == ""
	for name, raw := range fields {
		var target any
		switch name {
		case "route":
			target = &input.Route
		case "model":
			target = &input.Model
		case "serviceTier":
			target = &input.ServiceTier
		case "policy":
			target = &input.Policy
		default:
			valid = false
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		valid = valid && decoder.Decode(target) == nil
	}
	if !valid || input.Route != catalog.RouteChat && input.Route != catalog.RouteResponses ||
		input.Policy != nil && (!input.Policy.Scope.Valid() || input.Policy.ID == "" || len(input.Policy.ID) > 64 || len(input.Policy.Config) == 0) {
		s.writeError(ctx, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "invalid_request", "message": "Provide route as chat-completions or responses, optional model and serviceTier strings, and an optional policy with scope, id and config", "type": "invalid_request_error"}})
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
	result := policySimulation{Pairs: []simulationPair{}, Removed: []simulationRemoval{}, Ambiguous: []string{}, Credentials: map[string][]simulationCredential{}}
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
	}, input.Route, input.Model, input.ServiceTier)
	for _, removed := range simulation.Removed {
		versions := config.Versions
		if removed.Credential != nil {
			versions = chains[simulationCandidate{removed.Provider, *removed.Credential}]
		}
		entry := simulationRemoval{Reason: removed.Reason, Provider: removed.Provider, Deployment: removed.Deployment, Model: removed.Model,
			Credential: removed.Credential, Expression: removed.Expression, Unknown: removed.Unknown, Code: removed.Code}
		var hidden bool
		if entry.Origin, hidden = originFor(removed.Origin, versions, input.Policy); hidden {
			entry.Expression = ""
		}
		result.Removed = append(result.Removed, entry)
	}
	result.Truncated = simulation.Truncated
	if simulation.Ambiguous != nil {
		result.Ambiguous = simulation.Ambiguous
	}
	if simulation.Err != nil {
		public := catalog.PublicError(simulation.Err)
		result.Error = &simulationError{Code: public.Code, Message: public.Message}
		s.writeJSON(ctx, http.StatusOK, result)
		return
	}
	for _, pair := range simulation.Pairs {
		result.Pairs = append(result.Pairs, simulationPair{Provider: pair.Provider, Deployment: pair.Deployment.ID, Model: pair.Deployment.ModelID, Credential: pair.Credential})
	}
	first := chains[simulationCandidate{simulation.Pairs[0].Provider, simulation.Pairs[0].Credential}]
	result.Tried, result.Fallbacks = simulation.Tried, simulation.Fallbacks
	result.Order, _ = originFor(simulation.Order, first, input.Policy)
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
