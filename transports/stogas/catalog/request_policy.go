package catalog

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

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
	// attachments are the request's attachments, where they can narrow the candidates.
	attachments []Attachment
	// hostedTools are the hosted tools that the request lets the model call, whose data
	// handling joins each candidate's.
	hostedTools []HostedTool
	// ruledOut are the deployments that the request's parameters or hosted tools ruled out.
	ruledOut []ruledOut
}

// ruledOutError gives the error of the first deployment that the request's own content ruled
// out and that an available credential reaches, or nil when the credentials reach none.
func (v *requestVariants) ruledOutError(input RequestInput, route Route) error {
	for _, out := range v.ruledOut {
		indexes := []int{0}
		if input.AvailableCredentials != nil {
			indexes = input.AvailableCredentials[string(out.selection.provider)]
		}
		for _, index := range indexes {
			if input.DeploymentEligible == nil || input.DeploymentEligible(out.selection.provider, index, route, out.selection.deployment) {
				return out.err
			}
		}
	}
	return nil
}

// pairChoice is one deployment and credential in routing order.
type pairChoice struct {
	candidate *ResolvedRequest
	index     int
}

// requestPlan hands out the request's deployment and credential pairs in routing
// order. Every pair uses one of 1 + routing.fallbacks slots, whether its provider
// is called or its local preparation fails.
type requestPlan struct {
	input    RequestInput
	variants *requestVariants
	choices  []pairChoice
	slots    int
	firstErr error
	resolve  func(routingSelection, RequestPolicy) (*ResolvedRequest, error)
}

// credentialGroup holds the credentials of a deployment that share one candidate. They share the
// policy, and a credential of Stogas never shares one with a customer's own credential, since
// only the latter reads provider file IDs.
type credentialGroup struct {
	config  *policy.Config
	managed bool
}

// capacityError marks a failed memory reservation, which every pair would repeat.
type capacityError struct{ error }

func (e capacityError) Unwrap() error { return e.error }

// stopsPlan reports errors that another pair cannot avoid. A client key that
// fails to open its content must not route the request elsewhere.
func stopsPlan(err error) bool {
	var capacity capacityError
	return errors.Is(err, customerkey.ErrKey) || errors.Is(err, customerkey.ErrEnvelope) || errors.As(err, &capacity)
}

// Routing examines metadata and complete candidate policies. No body transform,
// token count, or credential decryption is part of catalog enumeration.
func planRequest(input RequestInput, route Route, model string, preference ProviderRoutingPreference, variants *requestVariants) (*requestPlan, error) {
	const maxPairs = 1 + policy.MaxFallbacks
	trace := input.trace
	candidates := routingCandidates{trace: trace, now: input.now}
	credentials := make(map[*ResolvedRequest][]int, len(variants.selections))
	ranks := make(map[credentialCandidate]int)
	var firstErr error
	// attachmentPairs are the pairs that cannot read an attachment of the request.
	var attachmentPairs []attachmentPair
	// keep records why a pair left. A pair whose deployment cannot read an attachment counts as
	// one that cannot read it, since waiting or another policy cannot change that. Otherwise the
	// input's preference keeps one error, as in take.
	keep := func(selection routingSelection, err error) {
		if !deploymentReads(variants.attachments, selection) {
			attachmentPairs = append(attachmentPairs, attachmentPair{selection: selection})
			return
		}
		if firstErr == nil || input.prefers(err, firstErr) {
			firstErr = err
		}
	}
	// When no credential serves any candidate, the request says so. Once one
	// pair passes this check, a policy may be what removed the rest, so the
	// request keeps the general error and the simulator names each cause.
	// A removed target whose chosen Azure deployment moved to another model names that cause.
	targetRemoved, targetPassed, targetChanged := false, false, false
	// A pair whose policy skips missing encryption keys leaves before it
	// takes a place among the deployment's pairs. Its candidate stays pending
	// for later credentials that share its policy.
	var skipped []PlannedPair
	pending := make(map[*ResolvedRequest]*resolvedPolicyValues)
	skips := func(selection routingSelection, index int, config *policy.Config) bool {
		if input.CheckRoots == nil || config == nil || !config.Routing.SkipsMissingKeys() {
			return false
		}
		pair := PlannedPair{Provider: selection.provider, Credential: index, Policy: config}
		err := input.CheckRoots([]PlannedPair{pair})
		if err == nil {
			return false
		}
		skipped = append(skipped, pair)
		if trace != nil {
			entry := RemovedCandidate{Reason: RemovedEncryptionKey}
			if missing := (*customerkey.MissingError)(nil); errors.As(err, &missing) {
				entry.Labels = missing.Labels
			}
			if origin, ok := config.MissingKeysOrigin(); ok {
				entry.Origin = &origin
			}
			trace.removePair(selection, index, nil, entry)
		}
		return true
	}
	for _, selection := range variants.selections {
		template := ResolvedRequest{
			Route: route, RequestedModel: model, Provider: selection.provider, Deployment: selection.deployment,
			policyTime: input.now, policyBudget: input.policyBudget, policyBodyBytes: len(input.Body),
			hostedTools: variants.hostedTools,
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
		groups := make(map[credentialGroup]*ResolvedRequest)
		for rank, index := range indexes {
			// Credentials are tried in assignment order, so later ones cannot
			// fit within the request's pairs once they are full.
			if retained == maxPairs {
				for _, rest := range indexes[rank:] {
					trace.removePair(selection, rest, nil, RemovedCandidate{Reason: RemovedPairLimit})
				}
				break
			}
			ranks[credentialCandidate{selection.provider, index}] = rank
			if input.DeploymentEligible != nil && !input.DeploymentEligible(selection.provider, index, route, selection.deployment) {
				targetRemoved = true
				targetChanged = targetChanged || input.DeploymentChanged != nil &&
					input.DeploymentChanged(selection.provider, index, selection.deployment)
				trace.removePair(selection, index, nil, RemovedCandidate{Reason: RemovedCredentialTarget})
				continue
			}
			targetPassed = true
			value, err := variants.policyFor(selection.provider, index)
			if err != nil {
				if errors.Is(err, customerkey.ErrKey) || errors.Is(err, customerkey.ErrEnvelope) {
					return nil, err
				}
				if errors.Is(err, policy.ErrSourceBudget) {
					return nil, policyEvaluationError(err)
				}
				keep(selection, err)
				if trace != nil {
					trace.removePair(selection, index, nil, RemovedCandidate{Reason: RemovedCredential, Code: PublicError(err).Code})
				}
				continue
			}
			original := value.Config
			group := credentialGroup{original, input.CredentialBYOK != nil && !input.CredentialBYOK(selection.provider, index)}
			if existing, found := groups[group]; found {
				switch {
				case existing == nil:
					trace.removeGrouped(selection, index, original)
				case skips(selection, index, existing.policy):
				case pending[existing] != nil:
					existing.CredentialIndex = index
					candidates.add(existing, pending[existing])
					delete(pending, existing)
					credentials[existing] = []int{index}
					retained++
				case len(credentials[existing]) < maxPairs:
					credentials[existing] = append(credentials[existing], index)
				default:
					trace.removePair(selection, index, nil, RemovedCandidate{Reason: RemovedPairLimit})
				}
				continue
			}
			groups[group] = nil
			// An undecided condition or a deny period from a matched rule
			// excludes only this candidate, as an unmatched filter does.
			value.Config, err = value.Config.Activate(values)
			if errors.Is(err, policy.ErrUnknownCondition) {
				keep(selection, policyEvaluationError(err))
				if unknown := (*policy.UnknownConditionError)(nil); trace != nil && errors.As(err, &unknown) {
					trace.removePair(selection, index, original, RemovedCandidate{Reason: RemovedCondition, Origin: &unknown.Origin, Expression: unknown.Condition})
				}
				continue
			}
			if err != nil {
				return nil, policyEvaluationError(err)
			}
			if value.Config.DeniedAt(input.now) {
				keep(selection, ErrScheduleDenied)
				if trace != nil {
					origin, _ := value.Config.DenyOrigin(input.now)
					trace.removePair(selection, index, original, RemovedCandidate{Reason: RemovedDeny, Origin: &origin})
				}
				continue
			}
			if !policyAllowsSelection(value.Config, selection) {
				if trace != nil {
					trace.removePair(selection, index, original, RemovedCandidate{Reason: RemovedAllowedNodes, Origin: nodesOrigin(value.Config, selection.deployment)})
				}
				continue
			}
			failed, known, err := policyFilterFailure(value.Config, values)
			if err != nil {
				return nil, err
			}
			if failed >= 0 {
				if trace != nil {
					entry := RemovedCandidate{Reason: RemovedFilter, Expression: value.Config.Routing.Query.Filters[failed].Source, Unknown: !known}
					if origin, ok := value.Config.FilterOrigin(failed); ok {
						entry.Origin = &origin
					}
					trace.removePair(selection, index, original, entry)
				}
				continue
			}
			// A simulation sends no messages, so no pair leaves here without a record.
			if len(variants.attachments) > 0 {
				if pair := newAttachmentPair(selection, value.Config, group.managed); !pair.reads(variants.attachments) {
					attachmentPairs = append(attachmentPairs, pair)
					continue
				}
			}
			candidate := template
			candidate.CredentialIndex, candidate.policy = index, value.Config
			groups[group] = &candidate
			if skips(selection, index, value.Config) {
				pending[&candidate] = values
				continue
			}
			candidates.add(&candidate, values)
			credentials[&candidate] = []int{index}
			retained++
		}
	}
	// Sending the keys would let a skipped pair serve, so the request names
	// them when nothing else remains.
	if len(candidates.filtered) == 0 && len(skipped) > 0 {
		return nil, input.CheckRoots(skipped)
	}
	if len(candidates.filtered) == 0 && firstErr != nil {
		return nil, firstErr
	}
	if len(candidates.filtered) == 0 && len(attachmentPairs) > 0 {
		return nil, attachmentsRefusal(variants.attachments, attachmentPairs)
	}
	// Later pairs are prepared with their own checks, which read the attachments in full.
	variants.attachments = nil
	if len(candidates.filtered) == 0 && targetRemoved && !targetPassed {
		if err := variants.ruledOutError(input, route); err != nil {
			return nil, err
		}
		if targetChanged {
			return nil, ErrByokTargetChanged
		}
		return nil, ErrByokTargetUnavailable
	}
	ordered, ties, err := candidates.finish(preference)
	if err != nil {
		return nil, err
	}
	// Fallbacks cannot differ between candidates, so any one carries the count.
	plan := &requestPlan{input: input, variants: variants, slots: 1 + policy.DefaultFallbacks}
	if config := candidates.filtered[0].policy; config != nil {
		plan.slots = 1 + config.Routing.Fallbacks
	}
	// planned counts the deployments that the tried pairs come from.
	planned := 0
	for _, group := range ordered {
		// Equal policies share routing work. Merge their credential choices
		// back into the original preference order for this deployment.
		start := len(plan.choices)
		if start < plan.slots {
			planned++
		}
		for _, candidate := range group {
			for _, index := range credentials[candidate] {
				plan.choices = append(plan.choices, pairChoice{candidate, index})
			}
		}
		added := plan.choices[start:]
		sort.SliceStable(added, func(i, j int) bool {
			return ranks[credentialCandidate{added[i].candidate.Provider, added[i].index}] < ranks[credentialCandidate{added[j].candidate.Provider, added[j].index}]
		})
		// A simulation lists the pairs that the fallback count leaves untried.
		if len(plan.choices) >= plan.slots && trace == nil {
			break
		}
	}
	// A tie that reaches the tried pairs would let input order choose what
	// the policies left open. Ties among untried deployments change nothing.
	for g := 1; g <= planned && g < len(ordered); g++ {
		if !ties[g] {
			continue
		}
		first, last := g-1, g
		for first > 0 && ties[first] {
			first--
		}
		for last+1 < len(ordered) && ties[last+1] {
			last++
		}
		err, ids := ambiguousError(ordered[first : last+1])
		if trace != nil {
			trace.ambiguous = ids
		}
		return nil, err
	}
	// Unless its policy skips it, a pair that needs a root the request did
	// not send fails the request whichever tried pair it is, before any
	// provider call, so the outcome does not depend on earlier failures.
	if input.CheckRoots != nil {
		tried := plan.choices[:min(len(plan.choices), plan.slots)]
		pairs := make([]PlannedPair, len(tried))
		for i, choice := range tried {
			pairs[i] = PlannedPair{Provider: choice.candidate.Provider, Credential: choice.index, Policy: choice.candidate.policy}
		}
		if err := input.CheckRoots(pairs); err != nil {
			// A simulation names the policy that keeps the first such pair.
			for _, pair := range pairs {
				if trace == nil || pair.Policy == nil || input.CheckRoots([]PlannedPair{pair}) == nil {
					continue
				}
				if origin, ok := pair.Policy.MissingKeysOrigin(); ok {
					return nil, &MissingKeysError{error: err, Pair: pair, Origin: origin}
				}
				break
			}
			return nil, err
		}
	}
	return plan, nil
}

// MissingKeysError locates, for a simulation, the policy that fails a request
// for a pair whose encryption key the request did not send.
type MissingKeysError struct {
	error
	Pair   PlannedPair
	Origin policy.Origin
}

func (e *MissingKeysError) Unwrap() error { return e.error }

// take resolves the next pair, recording failure as the previous pair's local
// error. A pair that waits, or fails its credential check or body preparation,
// uses its slot. With no pair left, take returns the error that fail kept.
func (p *requestPlan) take(failure error) (*ResolvedRequest, error) {
	if failure != nil && stopsPlan(failure) {
		return nil, failure
	}
	p.fail(failure)
	for p.slots > 0 && len(p.choices) > 0 {
		choice := p.choices[0]
		p.choices, p.slots = p.choices[1:], p.slots-1
		candidate := choice.candidate
		if p.input.PairWaits != nil && p.slots > 0 && len(p.choices) > 0 {
			if err := p.input.PairWaits(candidate.Provider, choice.index, candidate.Deployment); err != nil {
				p.skip(err)
				continue
			}
		}
		if p.input.CheckCandidate != nil {
			if err := p.input.CheckCandidate(candidate.Provider, choice.index, candidate.Deployment); err != nil {
				if stopsPlan(err) {
					return nil, err
				}
				p.skip(err)
				continue
			}
		}
		value, _ := p.variants.policyFor(candidate.Provider, choice.index)
		value.Config = candidate.policy
		selection := routingSelection{provider: candidate.Provider, deployment: candidate.Deployment, credential: choice.index}
		p.variants.selections = []routingSelection{selection}
		resolved, err := p.resolve(selection, value)
		if err == nil {
			resolved.plan = p
			return resolved, nil
		}
		if stopsPlan(err) {
			return nil, err
		}
		p.skip(err)
	}
	switch {
	case p.firstErr != nil:
		return nil, p.firstErr
	default:
		return nil, ErrModelUnavailable
	}
}

// skip records the failure of a pair that the plan refused before its call.
func (p *requestPlan) skip(err error) {
	if p.input.PairSkipped != nil {
		p.input.PairSkipped(err)
	}
	p.fail(err)
}

// fail keeps the first local error, unless the input prefers a later one.
func (p *requestPlan) fail(err error) {
	if p.firstErr == nil || p.input.prefers(err, p.firstErr) {
		p.firstErr = err
	}
}

func (input RequestInput) prefers(err, kept error) bool {
	if input.Prefers != nil {
		return input.Prefers(err, kept)
	}
	return retriesSooner(err, kept)
}

// retriesSooner reports whether waiting ends err before other: a client that
// waits for it can then pass on that pair. An error that waiting cannot end
// never ends sooner.
func retriesSooner(err, other error) bool {
	var wait, otherWait interface{ RetryAfter() time.Duration }
	if !errors.As(err, &wait) {
		return false
	}
	return !errors.As(other, &otherWait) || wait.RetryAfter() < otherWait.RetryAfter()
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

// reserve marks a failed reservation so the plan stops instead of preparing
// another pair.
func (v *requestVariants) reserve(bytes int) error {
	if err := v.reserveBody(bytes); err != nil {
		return capacityError{err}
	}
	return nil
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
		reserveExpansion = func(bytes int) error { return v.reserve(v.inputBytes + bytes) }
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
		if err := v.reserve(len(body)); err != nil {
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
		err = variant.chat.UnmarshalJSON(body)
	} else {
		variant.responses = &openaiprovider.OpenAIResponsesRequest{}
		err = sonic.Unmarshal(body, variant.responses)
	}
	if err != nil {
		return nil, ErrInvalidJSON
	}
	return variant, nil
}
