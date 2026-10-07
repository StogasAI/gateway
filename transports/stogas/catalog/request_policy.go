package catalog

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/inputfiles"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

type requestBodyVariant struct {
	exports   *exportconfig.Config
	body      []byte
	fields    map[string]json.RawMessage
	chat      *openaiprovider.OpenAIChatRequest
	responses *openaiprovider.OpenAIResponsesRequest
	estimate  func(Deployment) (int, error)
	summary   *redaction.Summary
	textBytes int
	files     inputfiles.Stats
}

type requestPolicyResult struct {
	value RequestPolicy
	err   error
}
type credentialCandidate struct {
	provider schemas.ModelProvider
	index    int
}
type requestVariants struct {
	base          RequestPolicy
	load          func(schemas.ModelProvider, int) (RequestPolicy, error)
	requestPolicy *policy.Request
	policies      map[credentialCandidate]requestPolicyResult
	applied       map[*policy.Config]requestPolicyResult
	fields        map[string]json.RawMessage
	route         Route
	selections    []routingSelection
	reserveBody   func(int) error
	inputBytes    int
	budget        policy.SourceBudget
}

// Routing examines metadata and complete candidate policies. No body transform,
// token count, or credential decryption is part of catalog enumeration.
func selectRequestCandidate(input RequestInput, route Route, model string, preference ProviderRoutingPreference, variants *requestVariants) (routingSelection, RequestPolicy, error) {
	var candidates routingCandidates
	credentials := make(map[*ResolvedRequest][]int, len(variants.selections))
	ranks := make(map[credentialCandidate]int)
	var firstErr error
	for _, selection := range variants.selections {
		template := ResolvedRequest{
			Route: route, RequestedModel: model, Provider: selection.provider, Deployment: selection.deployment,
			policyTime: input.now, policyBudget: input.policyBudget, policyBodyBytes: len(input.Body),
		}
		values, ok := newResolvedPolicyValues(&template)
		if !ok {
			continue
		}
		retained := 0
		indexes := []int{0}
		if input.AvailableCredentials != nil {
			indexes = input.AvailableCredentials[string(selection.provider)]
		}
		groups := make(map[*policy.Config]*ResolvedRequest)
		for rank, index := range indexes {
			ranks[credentialCandidate{selection.provider, index}] = rank
			if input.DeploymentEligible != nil && !input.DeploymentEligible(selection.provider, index, selection.deployment) {
				continue
			}
			value, err := variants.policyFor(selection.provider, index)
			if err != nil {
				if errors.Is(err, customerkey.ErrKey) || errors.Is(err, customerkey.ErrEnvelope) {
					return routingSelection{}, RequestPolicy{}, err
				}
				if errors.Is(err, policy.ErrSourceBudget) {
					return routingSelection{}, RequestPolicy{}, policyEvaluationError(err)
				}
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			original := value.Config
			if existing, found := groups[original]; found {
				if existing != nil && len(credentials[existing]) < existing.PreDispatchCandidateLimit() {
					credentials[existing] = append(credentials[existing], index)
				}
				continue
			}
			groups[original] = nil
			value.Config, err = value.Config.Activate(values)
			if err != nil {
				return routingSelection{}, RequestPolicy{}, policyEvaluationError(err)
			}
			matches, err := candidateMatchesPolicy(selection, value.Config, policyRequestContext{input.now, input.policyBudget, model, route, len(input.Body)})
			if err != nil {
				return routingSelection{}, RequestPolicy{}, err
			}
			if matches {
				matches, err = candidates.consider(value.Config, values)
				if err != nil {
					return routingSelection{}, RequestPolicy{}, err
				}
			}
			if matches && retained < policy.MaxPreDispatchCandidates {
				candidate := template
				candidate.CredentialIndex, candidate.policy = index, value.Config
				candidates.add(&candidate, values)
				groups[original] = &candidate
				credentials[&candidate] = []int{index}
				retained++
			}
		}
	}
	if len(candidates.filtered) == 0 && firstErr != nil {
		return routingSelection{}, RequestPolicy{}, firstErr
	}
	ordered, err := candidates.finish(preference)
	if err != nil {
		return routingSelection{}, RequestPolicy{}, err
	}
	firstErr = nil
	attempts, allowance := 0, 0
candidates:
	for _, group := range ordered {
		if len(group) == 0 {
			continue
		}
		for _, candidate := range group[1:] {
			if candidate.Deployment.ID != group[0].Deployment.ID || candidate.Provider != group[0].Provider {
				return routingSelection{}, RequestPolicy{}, ambiguousModelError(group)
			}
		}
		// Equal policies share routing work. Merge their remaining credential
		// choices back into the original preference order for this deployment.
		type choice struct {
			candidate *ResolvedRequest
			index     int
		}
		var choices []choice
		for _, candidate := range group {
			for _, index := range credentials[candidate] {
				choices = append(choices, choice{candidate, index})
			}
		}
		sort.Slice(choices, func(i, j int) bool {
			return ranks[credentialCandidate{choices[i].candidate.Provider, choices[i].index}] < ranks[credentialCandidate{choices[j].candidate.Provider, choices[j].index}]
		})
		for _, choice := range choices {
			candidate := choice.candidate
			if allowance == 0 || candidate.PreDispatchCandidateLimit() < allowance {
				allowance = candidate.PreDispatchCandidateLimit()
			}
			if attempts >= allowance {
				break candidates
			}
			attempts++
			if input.CheckCandidate != nil {
				if err := input.CheckCandidate(candidate.Provider, choice.index, candidate.Deployment); err != nil {
					if errors.Is(err, customerkey.ErrKey) || errors.Is(err, customerkey.ErrEnvelope) {
						return routingSelection{}, RequestPolicy{}, err
					}
					if firstErr == nil {
						firstErr = err
					}
					if attempts >= allowance {
						break candidates
					}
					continue
				}
			}
			value, _ := variants.policyFor(candidate.Provider, choice.index)
			value.Config = candidate.policy
			selected := routingSelection{provider: candidate.Provider, deployment: candidate.Deployment, credential: choice.index}
			variants.selections = []routingSelection{selected}
			return selected, value, nil
		}
	}
	if firstErr == nil {
		firstErr = ErrModelUnavailable
	}
	return routingSelection{}, RequestPolicy{}, firstErr
}

func (v *requestVariants) policyFor(provider schemas.ModelProvider, index int) (RequestPolicy, error) {
	key := credentialCandidate{provider, index}
	if v.load == nil {
		key = credentialCandidate{}
	}
	if result, ok := v.policies[key]; ok {
		return result.value, result.err
	}
	value := v.base
	var err error
	if v.load != nil {
		value, err = v.load(provider, index)
	}
	if err == nil && v.requestPolicy != nil {
		original := value.Config
		if applied, ok := v.applied[original]; ok {
			value.Config, err = applied.value.Config, applied.err
		} else {
			value.Config, err = policy.ApplyRequest(value.Config, v.requestPolicy)
			if !errors.Is(err, policy.ErrSourceBudget) {
				err = requestPolicyError(err)
			}
			if v.applied == nil {
				v.applied = make(map[*policy.Config]requestPolicyResult)
			}
			v.applied[original] = requestPolicyResult{value, err}
		}
	}
	if err == nil {
		err = v.budget.AddConfig(value.Config)
	}
	if v.policies == nil {
		v.policies = make(map[credentialCandidate]requestPolicyResult)
	}
	v.policies[key] = requestPolicyResult{value, err}
	return value, err
}

func (v *requestVariants) bodyFor(value RequestPolicy) (*requestBodyVariant, error) {
	surface := redaction.SurfaceChat
	if v.route == RouteResponses {
		surface = redaction.SurfaceResponses
	}
	return v.prepareBody(value, surface)
}

func (v *requestVariants) prepareBody(value RequestPolicy, surface redaction.Surface) (*requestBodyVariant, error) {
	exports, err := value.Config.ExportConfig()
	if err != nil {
		return nil, requestPolicyError(err)
	}
	compiled := value.RedactionPolicy
	extract := value.Config.TextExtractionEnabled()
	if value.LoadActivePlugins != nil {
		var err error
		var active *policy.ActivePlugins
		active, err = value.LoadActivePlugins(value.Config)
		if err == nil {
			compiled = active.Redaction
			extract = active.TextExtraction
			exports = active.Export
		}
		if err != nil {
			return nil, err
		}
	} else if value.Config.Activated() {
		var err error
		compiled, err = policy.CompileRedaction(value.Config)
		if err != nil {
			return nil, requestPolicyError(err)
		}
	} else if value.LoadRedactionPolicy != nil {
		var err error
		compiled, err = value.LoadRedactionPolicy()
		if errors.Is(err, customerkey.ErrKey) || errors.Is(err, customerkey.ErrEnvelope) {
			return nil, err
		}
		if err != nil || compiled == nil {
			return nil, APIError{Code: "gateway_capacity_exceeded", StatusCode: http.StatusServiceUnavailable, Type: "service_unavailable", Message: "Redaction policy is temporarily unavailable"}
		}
	} else if compiled == nil && value.Config != nil {
		var err error
		compiled, err = policy.CompileRedaction(value.Config)
		if err != nil {
			return nil, requestPolicyError(err)
		}
	}
	if v.requestPolicy != nil && value.LoadActivePlugins == nil && !value.Config.Activated() {
		requestRedaction, err := v.requestPolicy.CompileRedaction()
		if err != nil {
			return nil, requestPolicyError(err)
		}
		compiled, err = redaction.CombinePolicies([]*redaction.Policy{compiled, requestRedaction})
		if err != nil {
			return nil, requestPolicyError(err)
		}
	}
	redactor := redaction.NewWithPolicy(compiled)
	fields := copyRawRequestData(v.fields)
	var reserveExpansion func(int) error
	if v.reserveBody != nil {
		reserveExpansion = func(bytes int) error { return v.reserveBody(v.inputBytes + bytes) }
	}
	files, err := inputfiles.Process(fields, v.route == RouteResponses, extract, reserveExpansion)
	if err != nil {
		return nil, errors.Join(err, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: err.Error()})
	}
	asciiOnly := value.Config != nil && value.Config.Input != nil && value.Config.Input.ASCIIOnly
	if files.Opaque && (asciiOnly || compiled.Enabled()) {
		return nil, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Opaque attachments cannot satisfy the active input inspection policy; submit text or enable text extraction for inline UTF-8 text files"}
	}
	if asciiOnly {
		if err := redaction.ValidateASCII(fields, surface); err != nil {
			return nil, piiRedactionError(err)
		}
	}
	if err := redactor.RedactRequestFields(fields, surface, reserveExpansion); err != nil {
		return nil, piiRedactionError(err)
	}
	body, err := sonic.Marshal(fields)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	if v.reserveBody != nil {
		if err := v.reserveBody(len(body)); err != nil {
			return nil, err
		}
	}
	variant := &requestBodyVariant{exports: exports, body: body, fields: fields, summary: redactor.Summary(), textBytes: redactor.InputTextBytes()}
	variant.files = files
	if files.Opaque {
		variant.estimate = func(deployment Deployment) (int, error) { return deployment.MaxInputTokens, nil }
	} else {
		variant.estimate = requestTokenEstimator(fields, v.route, v.selections)
	}
	if v.route == RouteChat {
		variant.chat = &openaiprovider.OpenAIChatRequest{}
		err = sonic.Unmarshal(body, variant.chat)
	} else {
		variant.responses = &openaiprovider.OpenAIResponsesRequest{}
		err = sonic.Unmarshal(body, variant.responses)
	}
	if err != nil {
		return nil, ErrInvalidJSON
	}
	return variant, nil
}

func candidateMatchesPolicy(selection routingSelection, config *policy.Config, context policyRequestContext) (bool, error) {
	if config != nil && config.DeniedAt(context.now) {
		return false, APIError{Code: "schedule_denied", StatusCode: http.StatusForbidden, Type: "permission_denied", Message: "Request is not allowed at this time"}
	}
	selections := [1]routingSelection{selection}
	filtered, err := filterRoutingSelectionsByPolicy(selections[:], config, context)
	return len(filtered) != 0, err
}
