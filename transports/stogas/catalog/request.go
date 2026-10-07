package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/inputfiles"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

const (
	ErrorTypeInvalidRequest = "invalid_request_error"
	ErrorTypeInternal       = "internal_error"
	maxProviderRoutingItems = 32
	maxProviderNameBytes    = 64
)

var (
	ErrCatalogUnavailable     = APIError{Code: "catalog_unavailable", StatusCode: http.StatusInternalServerError, Type: ErrorTypeInternal, Message: "Catalog unavailable"}
	ErrInvalidJSON            = APIError{Code: "invalid_json", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid JSON body"}
	ErrModelAmbiguous         = APIError{Code: "model_ambiguous", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Multiple deployments match; specify a deployment or a routing sort order"}
	ErrModelUnavailable       = APIError{Code: "model_unavailable", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "No deployment is available for this request. Check the model, provider credentials and routing policies."}
	ErrProviderUnavailable    = APIError{Code: "provider_unavailable", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Provider is not available"}
	ErrRouteUnavailable       = APIError{Code: "route_not_found", StatusCode: http.StatusNotFound, Type: ErrorTypeInvalidRequest, Message: "Route not found"}
	ErrUnsupportedMethod      = APIError{Code: "method_not_allowed", StatusCode: http.StatusMethodNotAllowed, Type: ErrorTypeInvalidRequest, Message: "Method is not supported for this route"}
	ErrUnsupportedRequest     = APIError{Code: "unsupported_request", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Unsupported request type"}
	ErrParameterTooLarge      = APIError{Code: "parameter_limit_exceeded", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Parameter exceeds catalog limit"}
	ErrProviderSelection      = APIError{Code: "provider_not_allowed", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Model is not available for the requested provider"}
	ErrServiceTierUnavailable = APIError{Code: "service_tier_unavailable", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Model is not available for the requested service_tier"}
	ErrUnsupportedTool        = APIError{Code: "unsupported_tool", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Tool is not supported by Stogas pricing"}
	ErrUnsupportedServiceTier = APIError{Code: "unsupported_service_tier", StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "service_tier is not supported by Stogas"}
)

type APIError struct {
	StatusCode int
	Code       string
	Type       string
	Message    string
}

func (e APIError) Error() string {
	return e.Message
}

func PublicError(err error) APIError {
	if err == nil {
		return APIError{}
	}
	var apiErr APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return APIError{StatusCode: http.StatusInternalServerError, Type: ErrorTypeInternal, Message: "Internal server error"}
}

type RequestInput struct {
	now          time.Time
	policyBudget *policy.CELBudget
	Body         []byte
	// Fields, when supplied, must come from DecodeRequestBody for this Body.
	Fields              map[string]json.RawMessage
	Method              string
	Path                string
	Policy              *policy.Config
	RedactionPolicy     *redaction.Policy
	LoadRedactionPolicy func() (*redaction.Policy, error)
	CredentialPolicy    func(schemas.ModelProvider, int) (RequestPolicy, error)
	// AvailableCredentials lists eligible assignment indexes in preference order.
	// Nil leaves provider eligibility to the caller; an empty map denies all.
	AvailableCredentials map[string][]int
	// DeploymentEligible applies cached credential target metadata without secrets.
	DeploymentEligible   func(schemas.ModelProvider, int, Deployment) bool
	CompileRequestPolicy func([]byte) (*policy.Request, error)
	// CheckCandidate prepares local credential prerequisites after metadata
	// routing. An explicit fallback allowance permits another candidate only for
	// non-cryptographic failures. Invalid encryption keys or content are terminal.
	// It runs before any redaction or tokenization and must not place a hold.
	CheckCandidate func(schemas.ModelProvider, int, Deployment) error
	// ReserveBody accounts for the transformed JSON before typed decoding and
	// tokenization. The transport keeps this reservation until the request ends.
	ReserveBody func(int) error
}

// RequestPolicy is an immutable policy prepared from the key's cached sources.
// The selected policy transforms input exactly once, after routing finishes.
type RequestPolicy struct {
	Config              *policy.Config
	RedactionPolicy     *redaction.Policy
	LoadRedactionPolicy func() (*redaction.Policy, error)
	LoadActivePlugins   func(*policy.Config) (*policy.ActivePlugins, error)
}

type ResolvedRequest struct {
	policyBodyBytes int
	policyTime      time.Time
	policyBudget    *policy.CELBudget
	Route           Route
	RequestType     schemas.RequestType
	Provider        schemas.ModelProvider
	CredentialIndex int
	RequestedModel  string
	Model           string
	Deployment      Deployment
	ExportConfig    *exportconfig.Config

	chat                 *openaiprovider.OpenAIChatRequest
	inputTokenLimit      int
	inputTokenEstimate   *int
	inputTextBytes       *int
	inputFiles           inputfiles.Stats
	outputTokenLimit     int
	pricing              requestPricingContext
	redactionSummary     *redaction.Summary
	responses            *openaiprovider.OpenAIResponsesRequest
	policy               *policy.Config
	activePolicyRules    []policy.RuleMatch
	policyCandidateLimit int
}

// ActivePolicyRules carries only matched counter names into the financial hold.
// Source indexes refer to the selected credential's immutable policy snapshot.
func (r *ResolvedRequest) ActivePolicyRules() []policy.RuleMatch {
	if r == nil {
		return nil
	}
	return r.activePolicyRules
}

// Inference retains the selected counter names, not the source graph, plugin
// dictionaries or unused credential policies that were needed for selection.
func (r *ResolvedRequest) retainPolicyDecision(config *policy.Config) {
	if config != nil {
		r.activePolicyRules = append([]policy.RuleMatch(nil), config.ActiveRules...)
		r.policyCandidateLimit = config.Routing.MaxPreDispatchCandidates
	}
}

type requestPricingContext struct {
	Route               Route
	HasWebSearchOptions bool
	SearchContextSize   string
	ToolsParseFailed    bool
	RawBody             map[string]json.RawMessage
	RawTools            []map[string]json.RawMessage
	ToolTypes           []string
}

type ProviderRoutingPreference struct {
	Only  []string
	Order []string
}

func (p ProviderRoutingPreference) Empty() bool {
	return len(p.Only) == 0 && len(p.Order) == 0
}

type requestWithSettableExtraParams interface {
	SetExtraParams(params map[string]interface{})
}

// ResolveRequest selects a deployment and credential, then redacts and counts
// the request once. Input-dependent failures never restart deployment selection.
func ResolveRequest(input RequestInput) (*ResolvedRequest, error) {
	input.now = time.Now().UTC()
	input.policyBudget = policy.NewCELBudget()
	activationMu.RLock()
	defer activationMu.RUnlock()

	route, ok, methodOK := routeForInput(input)
	if !ok {
		return nil, ErrRouteUnavailable
	}
	if !methodOK {
		return nil, ErrUnsupportedMethod
	}

	switch route {
	case RouteChat:
		return resolveChatRequests(input, route)
	case RouteResponses:
		return resolveResponsesRequests(input, route)
	default:
		return nil, ErrUnsupportedRequest
	}
}

func (r *ResolvedRequest) ToBifrost(ctx *schemas.BifrostContext) (*schemas.BifrostRequest, error) {
	if r == nil {
		return nil, ErrUnsupportedRequest
	}
	converted := false
	if ctx != nil {
		if !schemas.SetRequestModelInfo(ctx, schemas.RequestModelInfo{
			Provider:        r.Provider,
			WireModel:       r.Model,
			CanonicalModel:  r.Deployment.ModelID,
			MaxOutputTokens: r.outputTokenLimit,
		}) {
			return nil, ErrUnsupportedRequest
		}
		defer func() {
			if !converted {
				ctx.ClearValue(schemas.BifrostContextKeyRequestModelInfo)
			}
		}()
	}
	if ctx != nil && r.Provider == ProviderChutes {
		ctx.SetValue(schemas.BifrostContextKeyPassthroughExtraParams, true)
	}
	switch {
	case r.chat != nil:
		body := r.chat.ToBifrostChatRequest(ctx)
		if body == nil {
			return nil, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid chat completion request"}
		}
		body.Provider = r.Provider
		body.Model = r.Model
		body.Fallbacks = nil
		converted = true
		return &schemas.BifrostRequest{RequestType: r.RequestType, ChatRequest: body}, nil
	case r.responses != nil:
		body := r.responses.ToBifrostResponsesRequest(ctx)
		if body == nil {
			return nil, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Invalid responses request"}
		}
		body.Provider = r.Provider
		body.Model = r.Model
		body.Fallbacks = nil
		converted = true
		return &schemas.BifrostRequest{RequestType: r.RequestType, ResponsesRequest: body}, nil
	default:
		return nil, ErrUnsupportedRequest
	}
}

func (r *ResolvedRequest) PreDispatchCandidateLimit() int {
	if r == nil {
		return 1
	}
	if r.policy == nil {
		return max(1, r.policyCandidateLimit)
	}
	return max(1, r.policy.Routing.MaxPreDispatchCandidates)
}

func (r *ResolvedRequest) CatalogNodeIDsForDeployment(deployment Deployment) []string {
	if r == nil {
		return nil
	}
	ids := []string{}
	snap := deployment.snapshot
	if snap == nil {
		snap = r.Deployment.snapshot
	}
	if snap != nil {
		if model, ok := snap.graph.Models[deployment.ModelID]; ok && model.AuthorID != "" {
			ids = append(ids, "author:"+model.AuthorID)
		}
	}
	if deployment.ModelID != "" {
		ids = append(ids, "model:"+deployment.ModelID)
	}
	if deployment.ID != "" {
		ids = append(ids, "deployment:"+deployment.ID)
	}
	for _, routeID := range sortedStrings(deployment.RouteIDs) {
		if routeID != "" {
			ids = append(ids, "route:"+routeID)
			if snap != nil {
				if route, ok := snap.graph.Routes[routeID]; ok && route.ProviderID != "" {
					ids = append(ids, "provider:"+route.ProviderID)
				}
			} else if r.Provider != "" {
				ids = append(ids, "provider:"+string(r.Provider))
			}
		}
	}
	return ids
}

func (r *ResolvedRequest) CatalogIdentity() Identity {
	if r == nil || r.Deployment.snapshot == nil {
		return Identity{}
	}
	return r.Deployment.snapshot.identity
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func (r *ResolvedRequest) InputTokenLimit() int {
	if r == nil {
		return 0
	}
	return r.inputTokenLimit
}

// EstimatedInputTokens is the local buffered, context-capped estimate taken
// after redaction, before provider preparation can change the reservation.
// Opaque reasoning contributes a conservative byte-based estimate.
func (r *ResolvedRequest) EstimatedInputTokens() (int, bool) {
	if r == nil || r.inputTokenEstimate == nil {
		return 0, false
	}
	return *r.inputTokenEstimate, true
}

// InputTextBytes is decoded UTF-8 request text after redaction and before
// provider conversion. It excludes framing and opaque reasoning replay.
func (r *ResolvedRequest) InputTextBytes() (int, bool) {
	if r == nil || r.inputTextBytes == nil {
		return 0, false
	}
	return *r.inputTextBytes, true
}

func (r *ResolvedRequest) InputFiles() inputfiles.Stats {
	if r == nil {
		return inputfiles.Stats{}
	}
	return r.inputFiles
}

func (r *ResolvedRequest) OutputTokenLimit() int {
	if r == nil {
		return 0
	}
	return r.outputTokenLimit
}

func (r *ResolvedRequest) StructuredPIIRedactionSummary() *redaction.Summary {
	if r == nil {
		return nil
	}
	return r.redactionSummary
}

// SetWireModel binds the already authorized catalog deployment to the exact
// customer deployment name used on the provider request. It does not change
// the catalog deployment, pricing, or receipt identity.
func (r *ResolvedRequest) SetWireModel(model string) error {
	if r == nil {
		return ErrUnsupportedRequest
	}
	model = strings.TrimSpace(model)
	if model == "" || len(model) > 256 || strings.ContainsAny(model, "\x00\r\n") {
		return ErrModelUnavailable
	}
	r.Model = model
	return nil
}

func (r *ResolvedRequest) NormalizeMinimumOutputTokenLimit(min int) {
	if r == nil || min <= 0 || r.outputTokenLimit <= 0 || r.outputTokenLimit >= min {
		return
	}
	r.outputTokenLimit = min
	if r.chat != nil && r.chat.ChatParameters.MaxCompletionTokens != nil {
		r.chat.ChatParameters.MaxCompletionTokens = &r.outputTokenLimit
	}
	if r.responses != nil && r.responses.ResponsesParameters.MaxOutputTokens != nil {
		r.responses.ResponsesParameters.MaxOutputTokens = &r.outputTokenLimit
	}
}

func (r *ResolvedRequest) HasWebSearchOptions() bool {
	return r != nil && r.pricing.HasWebSearchOptions
}

func (r *ResolvedRequest) SearchContextSize() string {
	if r == nil {
		return ""
	}
	return r.pricing.SearchContextSize
}

func (r *ResolvedRequest) ToolsParseFailed() bool {
	return r != nil && r.pricing.ToolsParseFailed
}

func (r *ResolvedRequest) RawBody() map[string]json.RawMessage {
	if r == nil {
		return nil
	}
	return r.pricing.RawBody
}

// ReleaseInput drops preprocessing representations after the final provider body
// has been prepared. Dispatch owns its converted request; settlement and response
// validation retain independent parameter bytes, never the input attachment JSON.
// Call only after all admission and provider preparation has finished.
func (r *ResolvedRequest) ReleaseInput() {
	if r == nil {
		return
	}
	r.chat, r.responses = nil, nil
	retained := make(map[string]json.RawMessage, len(r.pricing.RawBody))
	for key, value := range r.pricing.RawBody {
		if key != "messages" && key != "input" {
			retained[strings.Clone(key)] = bytes.Clone(value)
		}
	}
	r.pricing.RawBody = retained
	for i, tool := range r.pricing.RawTools {
		retained := make(map[string]json.RawMessage, len(tool))
		for key, value := range tool {
			retained[strings.Clone(key)] = bytes.Clone(value)
		}
		r.pricing.RawTools[i] = retained
	}
	for i, kind := range r.pricing.ToolTypes {
		r.pricing.ToolTypes[i] = strings.Clone(kind)
	}
	r.pricing.SearchContextSize = strings.Clone(r.pricing.SearchContextSize)
	r.RequestedModel = strings.Clone(r.RequestedModel)
}

func (r *ResolvedRequest) RawTools() []map[string]json.RawMessage {
	if r == nil {
		return nil
	}
	return r.pricing.RawTools
}

func (r *ResolvedRequest) ToolTypes() []string {
	if r == nil {
		return nil
	}
	return r.pricing.ToolTypes
}

func (r *ResolvedRequest) SanitizeClientMetadata() {
	if r == nil {
		return
	}
	if r.chat != nil {
		r.chat.ChatParameters.Metadata = nil
	}
	if r.responses != nil {
		r.responses.ResponsesParameters.Metadata = nil
	}
}

func (r *ResolvedRequest) RequireUpstreamUsage() {
	if r == nil || r.chat == nil || !r.chat.IsStreamingRequested() {
		return
	}
	if r.chat.ChatParameters.StreamOptions == nil {
		r.chat.ChatParameters.StreamOptions = &schemas.ChatStreamOptions{}
	}
	r.chat.ChatParameters.StreamOptions.IncludeUsage = schemas.Ptr(true)
}

func (r *ResolvedRequest) ApplyProviderSamplingParameters() {
	if r == nil {
		return
	}
	if topK, ok := rawIntValue(r.pricing.RawBody["top_k"]); ok {
		if r.chat != nil {
			r.chat.ChatParameters.TopK = &topK
		} else if r.responses != nil {
			r.SetExtraParam("top_k", topK)
		}
	}
	if stopSequences, ok := rawStringListValue(r.pricing.RawBody["stop_sequences"]); ok {
		if r.chat != nil {
			r.chat.ChatParameters.Stop = stopSequences
		} else if r.responses != nil {
			r.SetExtraParam("stop", stopSequences)
		}
	}
}

func (r *ResolvedRequest) SetSpeed(speed string) {
	if r == nil {
		return
	}
	normalized := strings.ToLower(strings.TrimSpace(speed))
	if r.chat != nil {
		if normalized == "fast" {
			r.chat.ChatParameters.Speed = &normalized
		} else {
			r.chat.ChatParameters.Speed = nil
		}
	}
	if r.responses != nil {
		params := copyStringAnyMap(r.responses.ExtraParams)
		if normalized == "fast" {
			params["speed"] = normalized
		} else {
			delete(params, "speed")
		}
		r.responses.SetExtraParams(params)
	}
}

func (r *ResolvedRequest) EnsureResponsesToolMaxUses(maxUses int, toolTypes ...schemas.ResponsesToolType) {
	if r == nil || r.responses == nil || maxUses < 1 {
		return
	}
	allowed := make(map[schemas.ResponsesToolType]struct{}, len(toolTypes))
	for _, toolType := range toolTypes {
		allowed[toolType] = struct{}{}
	}
	for i := range r.responses.ResponsesParameters.Tools {
		tool := &r.responses.ResponsesParameters.Tools[i]
		if _, ok := allowed[tool.Type]; !ok {
			continue
		}
		switch tool.Type {
		case schemas.ResponsesToolTypeWebSearch:
			if tool.ResponsesToolWebSearch == nil {
				tool.ResponsesToolWebSearch = &schemas.ResponsesToolWebSearch{}
			}
			if tool.ResponsesToolWebSearch.MaxUses == nil {
				tool.ResponsesToolWebSearch.MaxUses = schemas.Ptr(maxUses)
			}
		case schemas.ResponsesToolTypeWebFetch:
			if tool.ResponsesToolWebFetch == nil {
				tool.ResponsesToolWebFetch = &schemas.ResponsesToolWebFetch{}
			}
			if tool.ResponsesToolWebFetch.MaxUses == nil {
				tool.ResponsesToolWebFetch.MaxUses = schemas.Ptr(maxUses)
			}
		}
	}
	for _, tool := range r.pricing.RawTools {
		if _, ok := allowed[rawResponsesServerToolFamily(rawjson.NormalizedStringField(tool, "type"))]; !ok {
			continue
		}
		setRawIntIfMissing(tool, "max_uses", maxUses)
	}
}

func rawResponsesServerToolFamily(rawType string) schemas.ResponsesToolType {
	rawType = strings.TrimSpace(rawType)
	switch {
	case rawType == "web_search" || strings.HasPrefix(rawType, "web_search_"):
		return schemas.ResponsesToolTypeWebSearch
	case rawType == "web_fetch" || strings.HasPrefix(rawType, "web_fetch_"):
		return schemas.ResponsesToolTypeWebFetch
	default:
		return schemas.ResponsesToolType(rawType)
	}
}

func (r *ResolvedRequest) SetExtraParam(name string, value any) {
	if r == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	if r.chat != nil {
		params := copyStringAnyMap(r.chat.ExtraParams)
		params[name] = value
		r.chat.SetExtraParams(params)
		return
	}
	if r.responses != nil {
		params := copyStringAnyMap(r.responses.ExtraParams)
		params[name] = value
		r.responses.SetExtraParams(params)
	}
}

func setRawIntIfMissing(raw map[string]json.RawMessage, name string, value int) {
	if raw == nil {
		return
	}
	if _, ok := raw[name]; ok {
		return
	}
	encoded, err := sonic.Marshal(value)
	if err != nil {
		return
	}
	raw[name] = encoded
}

func rawIntValue(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var value int
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}

func rawStringListValue(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var values []string
	if err := sonic.Unmarshal(raw, &values); err != nil {
		return nil, false
	}
	return values, true
}

func copyRawRequestData(source map[string]json.RawMessage) map[string]json.RawMessage {
	if source == nil {
		return nil
	}
	copy := make(map[string]json.RawMessage, len(source))
	for name, value := range source {
		copy[name] = value
	}
	return copy
}

func requestPolicyError(err error) error {
	if err == nil {
		return nil
	}
	status := http.StatusBadRequest
	if errors.Is(err, policy.ErrRequestPolicyDenied) {
		status = http.StatusForbidden
	}
	return APIError{StatusCode: status, Type: ErrorTypeInvalidRequest, Message: err.Error()}
}

func compileRequestPolicy(rawData map[string]json.RawMessage, input RequestInput) (*policy.Request, error) {
	raw, present := rawData["policy"]
	if !present {
		return nil, nil
	}
	delete(rawData, "policy")
	// A selected credential can supply the explicit permission. Candidate checks
	// therefore use the complete saved policy once that credential is known.
	if input.CredentialPolicy == nil && (input.Policy == nil || input.Policy.RequestPermission == 0) {
		return nil, requestPolicyError(policy.ErrRequestPolicyDenied)
	}
	compile := input.CompileRequestPolicy
	if compile == nil {
		compile = func(raw []byte) (*policy.Request, error) { return policy.CompileRequest(raw, "", nil) }
	}
	request, err := compile(raw)
	return request, requestPolicyError(err)
}

func resolveChatRequests(input RequestInput, route Route) (*ResolvedRequest, error) {
	body, rawData, config := input.Body, input.Fields, input.Policy
	redactionPolicy, loadRedactionPolicy, credentialPolicy := input.RedactionPolicy, input.LoadRedactionPolicy, input.CredentialPolicy
	var err error
	if rawData == nil {
		rawData, err = DecodeRequestBody(body, nil)
		if err != nil {
			return nil, err
		}
	}
	delete(rawData, "encryption_keys")
	requestPolicy, err := compileRequestPolicy(rawData, input)
	if err != nil {
		return nil, err
	}
	if err := dropUnknownTopLevelFields(rawData, route); err != nil {
		return nil, err
	}
	dropNoOpCompatibilityFields(rawData, route)
	if _, err := normalizeChatStopString(rawData); err != nil {
		return nil, err
	}
	if err := validateChatRawAliases(rawData); err != nil {
		return nil, err
	}
	if err := validateRawReasoningParameters(rawData, chatRawReasoningFields, true, false); err != nil {
		return nil, err
	}
	base, err := requestRoutingFields(rawData)
	if err != nil {
		return nil, err
	}
	if _, supplied := rawData["model"]; supplied && strings.TrimSpace(base.Model) == "" {
		return nil, ErrModelUnavailable
	}
	providerPreference, err := requestProviderPreference(rawData)
	if err != nil {
		return nil, err
	}
	selections, err := routingSelectionsForRequest(
		route,
		base.Model,
		base.ServiceTier,
		config,
		input.AvailableCredentials,
	)
	if err != nil {
		return nil, err
	}
	selections, err = filterRoutingSelectionsByPolicy(selections, config, policyRequestContext{input.now, input.policyBudget, base.Model, route, len(input.Body)})
	if err != nil {
		return nil, err
	}
	if len(selections) == 0 {
		if base.ServiceTier != nil {
			return nil, ErrServiceTierUnavailable
		}
		return nil, ErrModelUnavailable
	}
	selections, err = filterProviderSelections(selections, providerPreference)
	if err != nil {
		return nil, err
	}
	selections, err = filterRequestParameters(selections, rawData, route, "max_completion_tokens", "max_tokens")
	if err != nil {
		return nil, err
	}
	variants := requestVariants{
		base: RequestPolicy{Config: config, RedactionPolicy: redactionPolicy, LoadRedactionPolicy: loadRedactionPolicy},
		load: credentialPolicy, requestPolicy: requestPolicy, fields: rawData, route: route, selections: selections, reserveBody: input.ReserveBody, inputBytes: len(input.Body),
	}
	selection, candidatePolicy, err := selectRequestCandidate(input, route, base.Model, providerPreference, &variants)
	if err != nil {
		return nil, err
	}
	variant, bodyErr := variants.bodyFor(candidatePolicy)
	if bodyErr != nil {
		return nil, bodyErr
	}
	candidateRaw := copyRawRequestData(variant.fields)
	request := *variant.chat
	if request.Reasoning != nil {
		reasoning := *request.Reasoning
		request.Reasoning = &reasoning
	}
	requestType := schemas.ChatCompletionRequest
	if request.IsStreamingRequested() {
		requestType = schemas.ChatCompletionStreamRequest
	}
	resolution, resolveErr := resolveOpenAIRequest(
		variant.body,
		candidateRaw,
		route,
		requestType,
		request.Model,
		&request.Model,
		&request.ChatParameters.ServiceTier,
		func() { applyChatAliases(&request) },
		func() *int { return request.ChatParameters.MaxCompletionTokens },
		&request,
		selection,
		variant.estimate,
	)
	if resolveErr == nil && request.ChatParameters.Reasoning != nil {
		resolveErr = normalizeChatReasoning(
			request.ChatParameters.Reasoning,
			resolution.Deployment,
			resolution.outputTokenLimit,
		)
	}
	if resolveErr != nil {
		return nil, resolveErr
	}
	resolution.chat = &request
	textBytes := variant.textBytes
	resolution.inputTextBytes = &textBytes
	resolution.inputFiles = variant.files
	resolution.redactionSummary = variant.summary
	resolution.ExportConfig = variant.exports
	resolution.retainPolicyDecision(candidatePolicy.Config)
	resolution.policyTime, resolution.policyBudget = input.now, input.policyBudget
	resolution.policyBodyBytes = len(input.Body)
	return resolution, nil
}

func normalizeChatStopString(rawData map[string]json.RawMessage) (bool, error) {
	rawStop, ok := rawData["stop"]
	if !ok || len(rawStop) == 0 || string(rawStop) == "null" {
		return false, nil
	}
	var stop string
	if err := sonic.Unmarshal(rawStop, &stop); err != nil {
		var stops []string
		if err := sonic.Unmarshal(rawStop, &stops); err != nil {
			return false, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "stop must be a string or array of strings"}
		}
		return false, nil
	}
	encoded, err := sonic.Marshal([]string{stop})
	if err != nil {
		return false, ErrInvalidJSON
	}
	rawData["stop"] = encoded
	return true, nil
}

func resolveResponsesRequests(input RequestInput, route Route) (*ResolvedRequest, error) {
	body, rawData, config := input.Body, input.Fields, input.Policy
	redactionPolicy, loadRedactionPolicy, credentialPolicy := input.RedactionPolicy, input.LoadRedactionPolicy, input.CredentialPolicy
	var err error
	if rawData == nil {
		rawData, err = DecodeRequestBody(body, nil)
		if err != nil {
			return nil, err
		}
	}
	delete(rawData, "encryption_keys")
	requestPolicy, err := compileRequestPolicy(rawData, input)
	if err != nil {
		return nil, err
	}
	if err := dropUnknownTopLevelFields(rawData, route); err != nil {
		return nil, err
	}
	dropNoOpCompatibilityFields(rawData, route)
	if err := validateRawReasoningParameters(rawData, responsesRawReasoningFields, false, true); err != nil {
		return nil, err
	}
	base, err := requestRoutingFields(rawData)
	if err != nil {
		return nil, err
	}
	if _, supplied := rawData["model"]; supplied && strings.TrimSpace(base.Model) == "" {
		return nil, ErrModelUnavailable
	}
	providerPreference, err := requestProviderPreference(rawData)
	if err != nil {
		return nil, err
	}
	selections, err := routingSelectionsForRequest(
		route,
		base.Model,
		base.ServiceTier,
		config,
		input.AvailableCredentials,
	)
	if err != nil {
		return nil, err
	}
	selections, err = filterRoutingSelectionsByPolicy(selections, config, policyRequestContext{input.now, input.policyBudget, base.Model, route, len(input.Body)})
	if err != nil {
		return nil, err
	}
	if len(selections) == 0 {
		if base.ServiceTier != nil {
			return nil, ErrServiceTierUnavailable
		}
		return nil, ErrModelUnavailable
	}
	selections, err = filterProviderSelections(selections, providerPreference)
	if err != nil {
		return nil, err
	}
	selections, err = filterRequestParameters(selections, rawData, route, "max_output_tokens")
	if err != nil {
		return nil, err
	}
	variants := requestVariants{
		base: RequestPolicy{Config: config, RedactionPolicy: redactionPolicy, LoadRedactionPolicy: loadRedactionPolicy},
		load: credentialPolicy, requestPolicy: requestPolicy, fields: rawData, route: route, selections: selections, reserveBody: input.ReserveBody, inputBytes: len(input.Body),
	}
	selection, candidatePolicy, err := selectRequestCandidate(input, route, base.Model, providerPreference, &variants)
	if err != nil {
		return nil, err
	}
	variant, bodyErr := variants.bodyFor(candidatePolicy)
	if bodyErr != nil {
		return nil, bodyErr
	}
	candidateRaw := copyRawRequestData(variant.fields)
	request := *variant.responses
	if request.Reasoning != nil {
		reasoning := *request.Reasoning
		request.Reasoning = &reasoning
	}
	requestType := schemas.ResponsesRequest
	if request.IsStreamingRequested() {
		requestType = schemas.ResponsesStreamRequest
	}
	resolution, resolveErr := resolveOpenAIRequest(
		variant.body,
		candidateRaw,
		route,
		requestType,
		request.Model,
		&request.Model,
		&request.ResponsesParameters.ServiceTier,
		func() { applyResponsesAliases(candidateRaw, &request) },
		func() *int { return request.ResponsesParameters.MaxOutputTokens },
		&request,
		selection,
		variant.estimate,
	)
	if resolveErr == nil {
		resolveErr = normalizeResponsesReasoning(request.ResponsesParameters.Reasoning, resolution.Deployment, resolution.outputTokenLimit)
	}
	if resolveErr != nil {
		return nil, resolveErr
	}
	if mode := resolution.Deployment.Upstream.ReasoningMode; mode != "" {
		if request.ResponsesParameters.Reasoning == nil {
			request.ResponsesParameters.Reasoning = &schemas.ResponsesParametersReasoning{}
		}
		request.ResponsesParameters.Reasoning.Mode = &mode
	}
	resolution.responses = &request
	textBytes := variant.textBytes
	resolution.inputTextBytes = &textBytes
	resolution.inputFiles = variant.files
	resolution.redactionSummary = variant.summary
	resolution.ExportConfig = variant.exports
	resolution.retainPolicyDecision(candidatePolicy.Config)
	resolution.policyTime, resolution.policyBudget = input.now, input.policyBudget
	resolution.policyBodyBytes = len(input.Body)
	return resolution, nil
}

func piiRedactionError(err error) error {
	if errors.Is(err, redaction.ErrNonASCII) {
		return APIError{Code: "input_ascii_required", StatusCode: 400, Type: "invalid_request_error", Message: "Policy requires ASCII input text"}
	}
	if errors.Is(err, redaction.ErrMatchLimit) || errors.Is(err, redaction.ErrNestingLimit) || errors.Is(err, redaction.ErrWorkLimit) {
		return APIError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Type:       ErrorTypeInvalidRequest,
			Message:    "Request exceeds redaction limits",
		}
	}
	return err
}

// Apply catalog-known parameter constraints before credential checks, redaction,
// typed message decoding or tokenization.
func filterRequestParameters(selections []routingSelection, raw map[string]json.RawMessage, route Route, fields ...string) ([]routingSelection, error) {
	var requested *int
	for _, field := range fields {
		if value, ok := raw[field]; ok {
			count, valid := rawInteger(value)
			if !valid {
				return nil, ErrInvalidJSON
			}
			requested = &count
			break
		}
	}
	validateReasoning, err := requestReasoningValidation(raw, route)
	if err != nil {
		return nil, err
	}
	kept := selections[:0]
	var firstErr error
	for _, selection := range selections {
		outputLimit, err := effectiveOutputTokenLimit(requested, selection.deployment.MaxOutputTokens)
		if err == nil && validateReasoning != nil {
			err = validateReasoning(selection.deployment, outputLimit)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		kept = append(kept, selection)
	}
	if len(kept) == 0 {
		return nil, firstErr
	}
	// Small numeric/reasoning controls can remove every candidate without
	// traversing messages or schemas for broad feature selectors.
	selections = kept
	required, err := requestCapabilities(raw, route, sharedRequestCapabilities(selections))
	if err != nil {
		return nil, err
	}
	kept = selections[:0]
	firstErr = nil
	for _, selection := range selections {
		if err := validateRequestCapabilities(required, selection.deployment.Capabilities); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		kept = append(kept, selection)
	}
	if len(kept) == 0 {
		return nil, firstErr
	}
	return kept, nil
}

func resolveOpenAIRequest(
	body []byte,
	rawData map[string]json.RawMessage,
	route Route,
	requestType schemas.RequestType,
	requestedModel string,
	modelField *string,
	serviceTier **schemas.BifrostServiceTier,
	applyRequestAliases func(),
	requestedOutputLimit func() *int,
	extraParams requestWithSettableExtraParams,
	selection routingSelection,
	estimateTokens func(Deployment) (int, error),
) (*ResolvedRequest, error) {
	provider := selection.provider
	deployment := selection.deployment
	if _, ok := catalogRouteForRequest(provider, route); !ok {
		return nil, ErrRouteUnavailable
	}
	model := requestedModel
	var requestedServiceTier *schemas.BifrostServiceTier
	if serviceTier != nil && *serviceTier != nil {
		requestedServiceTier = *serviceTier
	}
	if err := validateRequestedServiceTier(provider, requestedServiceTier); err != nil {
		return nil, err
	}
	if !applyResolvedDeployment(provider, modelField, serviceTier, deployment) {
		return nil, ErrModelUnavailable
	}
	if applyRequestAliases != nil {
		applyRequestAliases()
	}
	outputTokenLimit, err := effectiveOutputTokenLimit(requestedOutputLimit(), deployment.MaxOutputTokens)
	if err != nil {
		return nil, err
	}

	filtered, err := filterRequestExtraParams(rawData, provider, model, route)
	if err != nil {
		return nil, err
	}
	if extraParams != nil {
		extraParams.SetExtraParams(filtered)
	}
	pricing := requestPricingContextForRaw(route, rawData)
	inputTokenEstimate, err := estimateTokens(deployment)
	if err != nil {
		return nil, err
	}
	resolved := resolvedRequest(route, requestType, provider, requestedModel, *modelField, deployment, filtered, outputTokenLimit, inputTokenEstimate, pricing)
	resolved.CredentialIndex = selection.credential
	resolved.inputTokenEstimate = &inputTokenEstimate
	return resolved, nil
}

func validateRequestedServiceTier(provider schemas.ModelProvider, requested *schemas.BifrostServiceTier) error {
	if requested == nil {
		return nil
	}
	value := strings.ToLower(strings.TrimSpace(string(*requested)))
	if value == "" {
		return nil
	}
	switch provider {
	case schemas.OpenAI:
		switch value {
		case "auto", "default", "fast", "flex", "priority":
			return nil
		case "scale", "provisioned":
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "OpenAI " + value + " service_tier is not supported by Stogas"}
		default:
			return ErrUnsupportedServiceTier
		}
	case schemas.Azure:
		switch value {
		case "auto", "default", "fast", "priority":
			return nil
		default:
			return ErrUnsupportedServiceTier
		}
	case schemas.Anthropic:
		switch value {
		case "default", "standard", "standard_only":
			return nil
		case "auto", "priority":
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Anthropic " + value + " service_tier requires an uncataloged Priority Tier contract"}
		case "flex":
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "Anthropic flex service_tier does not exist"}
		default:
			return ErrUnsupportedServiceTier
		}
	default:
		return ErrUnsupportedServiceTier
	}
}

func isKnownServiceTierValue(requested *schemas.BifrostServiceTier) bool {
	if requested == nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(string(*requested))) {
	case "", "auto", "default", "fast", "flex", "priority", "standard", "standard_only":
		return true
	default:
		return false
	}
}

func requestProviderPreference(rawData map[string]json.RawMessage) (ProviderRoutingPreference, error) {
	raw, name, ok, err := requestRoutingPreferenceRaw(rawData)
	if err != nil {
		return ProviderRoutingPreference{}, err
	}
	if !ok {
		return ProviderRoutingPreference{}, nil
	}
	var provider string
	if err := sonic.Unmarshal(raw, &provider); err == nil {
		provider = strings.TrimSpace(provider)
		if provider == "" {
			return ProviderRoutingPreference{}, providerPreferenceShapeError(name)
		}
		return ProviderRoutingPreference{Only: []string{provider}}, nil
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err != nil || object == nil {
		return ProviderRoutingPreference{}, providerPreferenceShapeError(name)
	}
	for key := range object {
		switch key {
		case "only", "order":
		default:
			return ProviderRoutingPreference{}, providerPreferenceShapeError(name)
		}
	}
	only, err := providerStringList(name, object["only"])
	if err != nil {
		return ProviderRoutingPreference{}, err
	}
	order, err := providerStringList(name, object["order"])
	if err != nil {
		return ProviderRoutingPreference{}, err
	}
	preference := ProviderRoutingPreference{Only: only, Order: order}
	if preference.Empty() {
		return ProviderRoutingPreference{}, providerPreferenceShapeError(name)
	}
	return preference, nil
}

func requestRoutingPreferenceRaw(rawData map[string]json.RawMessage) (json.RawMessage, string, bool, error) {
	providerRaw, hasProvider := rawData["provider"]
	rulesRaw, hasRules := rawData["rules"]
	if hasProvider && hasRules {
		return nil, "", false, APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "provider and rules cannot both be set"}
	}
	if hasProvider {
		return providerRaw, "provider", true, nil
	}
	if hasRules {
		return rulesRaw, "rules", true, nil
	}
	return nil, "", false, nil
}

func providerStringList(name string, raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var values []string
	if err := sonic.Unmarshal(raw, &values); err != nil || len(values) == 0 || len(values) > maxProviderRoutingItems {
		return nil, providerPreferenceShapeError(name)
	}
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" || len(normalized) > maxProviderNameBytes {
			return nil, providerPreferenceShapeError(name)
		}
		key := strings.ToLower(normalized)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, normalized)
	}
	return out, nil
}

func providerPreferenceShapeError(name string) APIError {
	if name == "" {
		name = "provider"
	}
	return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: name + " must be a non-empty string or an object with provider only/order lists"}
}

func resolvedRequest(
	route Route,
	requestType schemas.RequestType,
	provider schemas.ModelProvider,
	requestedModel string,
	model string,
	deployment Deployment,
	extraParams map[string]interface{},
	outputTokenLimit int,
	inputTokenLimit int,
	pricing requestPricingContext,
) *ResolvedRequest {
	return &ResolvedRequest{
		Route:            route,
		RequestType:      requestType,
		Provider:         provider,
		RequestedModel:   requestedModel,
		Model:            model,
		Deployment:       deployment,
		inputTokenLimit:  inputTokenLimit,
		outputTokenLimit: outputTokenLimit,
		pricing:          pricing,
	}
}

func maxInputTokenHold(contextWindowTokens int, outputTokenLimit int) int {
	if contextWindowTokens <= 0 {
		return 0
	}
	remaining := contextWindowTokens - outputTokenLimit
	if remaining < 0 {
		return 0
	}
	return remaining
}

type routingFields struct {
	Model       string
	ServiceTier *schemas.BifrostServiceTier
}

func requestRoutingFields(raw map[string]json.RawMessage) (routingFields, error) {
	var fields routingFields
	if value, ok := raw["model"]; ok {
		if err := json.Unmarshal(value, &fields.Model); err != nil {
			return fields, ErrInvalidJSON
		}
	}
	if value, ok := raw["service_tier"]; ok {
		if err := json.Unmarshal(value, &fields.ServiceTier); err != nil {
			return fields, ErrInvalidJSON
		}
	}
	return fields, nil
}

func rawStringValue(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

func requestPricingContextForRaw(route Route, rawData map[string]json.RawMessage) requestPricingContext {
	searchContextSize := ""
	hasWebSearchOptions := false
	if rawOptions, ok := rawData["web_search_options"]; ok {
		hasWebSearchOptions = true
		var options map[string]json.RawMessage
		if err := sonic.Unmarshal(rawOptions, &options); err == nil {
			searchContextSize = rawjson.NormalizedStringField(options, "search_context_size")
		}
	}
	rawTools, ok := rawData["tools"]
	if !ok {
		return requestPricingContext{Route: route, HasWebSearchOptions: hasWebSearchOptions, SearchContextSize: searchContextSize, RawBody: rawData}
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(rawTools, &tools); err != nil {
		return requestPricingContext{Route: route, HasWebSearchOptions: hasWebSearchOptions, SearchContextSize: searchContextSize, ToolsParseFailed: true, RawBody: rawData}
	}
	toolTypes := make([]string, 0, len(tools))
	if route == RouteResponses {
		var normalizedTools []schemas.ResponsesTool
		if err := sonic.Unmarshal(rawTools, &normalizedTools); err == nil {
			for _, tool := range normalizedTools {
				if tool.Type != "" {
					toolTypes = append(toolTypes, string(tool.Type))
				}
			}
		}
	} else {
		for _, tool := range tools {
			toolType := rawjson.NormalizedStringField(tool, "type")
			if toolType != "" {
				toolTypes = append(toolTypes, toolType)
			}
		}
	}
	return requestPricingContext{Route: route, HasWebSearchOptions: hasWebSearchOptions, SearchContextSize: searchContextSize, RawBody: rawData, RawTools: tools, ToolTypes: toolTypes}
}

func effectiveOutputTokenLimit(requested *int, max int) (int, error) {
	if max <= 0 {
		return 0, ErrCatalogUnavailable
	}
	if requested == nil {
		return max, nil
	}
	if *requested < 0 {
		return 0, ErrParameterTooLarge
	}
	if *requested > max {
		return 0, ErrParameterTooLarge
	}
	return *requested, nil
}

func routeForInput(input RequestInput) (Route, bool, bool) {
	normalizedPath := strings.TrimSpace(input.Path)
	normalizedMethod := strings.ToUpper(strings.TrimSpace(input.Method))
	route, ok := routeByPath[normalizedPath]
	if !ok {
		return "", false, false
	}
	spec, ok := specForRoute(route)
	if !ok {
		return "", false, false
	}
	return route, true, strings.ToUpper(spec.Method) == normalizedMethod
}

func filterRequestExtraParams(rawData map[string]json.RawMessage, provider schemas.ModelProvider, model string, route Route) (map[string]interface{}, error) {
	typedFields := typedOpenAIRequestFields(provider, route)
	if len(typedFields) == 0 {
		return nil, ErrCatalogUnavailable
	}
	// Typed request decoding ignores unknown OpenAI-compatible extension fields.
	// Keep that compatibility at the public boundary, but forward only the small
	// provider-specific allowlist below. A client extension must never become an
	// upstream parameter merely because Bifrost learns it later.
	extraParams := extractExtraParams(rawData, typedFields)
	return FilterExtraParams(provider, model, route, extraParams), nil
}

func dropUnknownTopLevelFields(rawData map[string]json.RawMessage, route Route) error {
	knownFields := KnownFields(route)
	if len(knownFields) == 0 {
		return ErrCatalogUnavailable
	}
	for name := range rawData {
		if !knownFields[name] {
			delete(rawData, name)
		}
	}
	return nil
}

// dropNoOpCompatibilityFields accepts common SDK defaults without letting
// those fields select provider storage, routing, identity, or non-text output.
// JSON null is omission for every optional top-level request field. Required
// fields remain so the normal request validator can report them accurately.
// Meaningful unsupported values remain and are rejected by route policy.
func dropNoOpCompatibilityFields(rawData map[string]json.RawMessage, route Route) {
	for name, raw := range rawData {
		if name != "model" && name != "messages" && name != "input" && rawJSONNull(raw) {
			delete(rawData, name)
		}
	}
	delete(rawData, "user")
	delete(rawData, "safety_identifier")

	switch route {
	case RouteChat:
		dropRawFieldIf(rawData, "fallbacks", rawJSONNullOrEmptyArray)
		dropRawFieldIf(rawData, "functions", rawJSONNullOrEmptyArray)
		dropRawFieldIf(rawData, "modalities", rawJSONNullOrEmptyArray)
		dropRawFieldIf(rawData, "prompt_cache_isolation_key", rawJSONNullOrEmptyString)
	case RouteResponses:
		dropRawFieldIf(rawData, "background", rawJSONFalse)
		dropRawFieldIf(rawData, "fallbacks", rawJSONNullOrEmptyArray)
		dropRawFieldIf(rawData, "previous_response_id", rawJSONNullOrEmptyString)
	}
}

func dropRawFieldIf(rawData map[string]json.RawMessage, name string, noOp func(json.RawMessage) bool) {
	if raw, ok := rawData[name]; ok && noOp(raw) {
		delete(rawData, name)
	}
}

func rawJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func rawJSONFalse(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("false"))
}

func rawJSONNullOrEmptyArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("[]"))
}

func rawJSONNullOrEmptyString(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte(`""`))
}

func extractExtraParams(rawData map[string]json.RawMessage, knownFields map[string]bool) map[string]interface{} {
	extraParams := make(map[string]interface{})
	for key, value := range rawData {
		if knownFields[key] {
			continue
		}
		var decoded any
		if err := sonic.Unmarshal(value, &decoded); err != nil {
			continue
		}
		extraParams[key] = decoded
	}
	return extraParams
}

func typedOpenAIRequestFields(provider schemas.ModelProvider, route Route) map[string]bool {
	fields := KnownFields(route)
	if provider == ProviderChutes && route == RouteChat {
		fields = copyBoolMap(fields)
		delete(fields, "repetition_penalty")
	}
	if route != RouteResponses {
		return fields
	}
	fields = copyBoolMap(fields)
	delete(fields, "cache_control")
	delete(fields, "context_management")
	delete(fields, "reasoning.effort")
	delete(fields, "task_budget")
	return fields
}

func copyBoolMap(values map[string]bool) map[string]bool {
	out := make(map[string]bool, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func copyStringAnyMap(values map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

// ReasoningEffort returns the admitted canonical reasoning effort.
func (r *ResolvedRequest) ReasoningEffort() (string, bool) {
	if r == nil || r.chat == nil || r.chat.ChatParameters.Reasoning == nil ||
		r.chat.ChatParameters.Reasoning.Effort == nil {
		return "", false
	}
	return *r.chat.ChatParameters.Reasoning.Effort, true
}

// ReasoningEnabled returns an admitted binary reasoning control.
func (r *ResolvedRequest) ReasoningEnabled() (bool, bool) {
	if r == nil || r.chat == nil || r.chat.ChatParameters.Reasoning == nil ||
		r.chat.ChatParameters.Reasoning.Enabled == nil {
		return false, false
	}
	return *r.chat.ChatParameters.Reasoning.Enabled, true
}

// PrepareChutesChatWire applies Chutes-specific output and reasoning fields.
// The resolved output limit remains the billing hold limit.
func (r *ResolvedRequest) PrepareChutesChatWire(
	defaultOutputTokens int,
	upstreamReasoningEffort string,
	thinking *bool,
) {
	if r == nil || r.chat == nil || r.Route != RouteChat {
		return
	}
	if _, maxTokensSet := rawIntValue(r.pricing.RawBody["max_tokens"]); !maxTokensSet {
		if _, maxCompletionTokensSet := rawIntValue(r.pricing.RawBody["max_completion_tokens"]); !maxCompletionTokensSet &&
			defaultOutputTokens >= 0 && defaultOutputTokens < r.outputTokenLimit {
			r.outputTokenLimit = defaultOutputTokens
			r.inputTokenLimit = min(r.Deployment.MaxInputTokens, maxInputTokenHold(r.Deployment.ContextWindowTokens, defaultOutputTokens))
		}
	}
	limit := r.outputTokenLimit
	r.chat.ChatParameters.MaxCompletionTokens = nil
	r.chat.MaxTokens = nil
	r.chat.ChatParameters.Reasoning = nil
	r.SetExtraParam("max_tokens", limit)
	if upstreamReasoningEffort != "" {
		r.SetExtraParam("reasoning_effort", upstreamReasoningEffort)
	}
	if thinking != nil {
		r.SetExtraParam("chat_template_kwargs", map[string]interface{}{
			"enable_thinking": *thinking,
			"thinking":        *thinking,
		})
	}
}

func applyChatAliases(request *openaiprovider.OpenAIChatRequest) {
	if request.ChatParameters.MaxCompletionTokens != nil {
		return
	}
	if request.MaxTokens != nil {
		request.ChatParameters.MaxCompletionTokens = request.MaxTokens
		return
	}
	if request.ExtraParams == nil {
		return
	}
	maxTokensVal, exists := request.ExtraParams["max_tokens"]
	if !exists {
		return
	}
	switch value := maxTokensVal.(type) {
	case float64:
		maxTokens := int(value)
		request.ChatParameters.MaxCompletionTokens = &maxTokens
		delete(request.ExtraParams, "max_tokens")
		request.ChatParameters.ExtraParams = request.ExtraParams
	case int:
		request.ChatParameters.MaxCompletionTokens = &value
		delete(request.ExtraParams, "max_tokens")
		request.ChatParameters.ExtraParams = request.ExtraParams
	}
}

func applyResponsesAliases(rawData map[string]json.RawMessage, request *openaiprovider.OpenAIResponsesRequest) {
	if request == nil {
		return
	}
	rawEffort, ok := rawData["reasoning.effort"]
	if !ok {
		return
	}
	if request.ResponsesParameters.Reasoning != nil && request.ResponsesParameters.Reasoning.Effort != nil {
		return
	}
	var effort string
	if err := sonic.Unmarshal(rawEffort, &effort); err != nil {
		return
	}
	if request.ResponsesParameters.Reasoning == nil {
		request.ResponsesParameters.Reasoning = &schemas.ResponsesParametersReasoning{}
	}
	request.ResponsesParameters.Reasoning.Effort = &effort
}

func validateChatTokenAliases(rawData map[string]json.RawMessage) error {
	maxTokensRaw, hasMaxTokens := rawData["max_tokens"]
	maxCompletionTokensRaw, hasMaxCompletionTokens := rawData["max_completion_tokens"]
	if !hasMaxTokens || !hasMaxCompletionTokens {
		return nil
	}
	maxTokens, ok := rawInteger(maxTokensRaw)
	if !ok {
		return nil
	}
	maxCompletionTokens, ok := rawInteger(maxCompletionTokensRaw)
	if !ok {
		return nil
	}
	if maxTokens == maxCompletionTokens {
		return nil
	}
	return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: "max_tokens conflicts with max_completion_tokens"}
}

func validateChatRawAliases(rawData map[string]json.RawMessage) error {
	if err := validateChatTokenAliases(rawData); err != nil {
		return err
	}
	reasoningRaw, hasReasoning := rawData["reasoning"]
	if !hasReasoning {
		return nil
	}
	var reasoning map[string]json.RawMessage
	if err := sonic.Unmarshal(reasoningRaw, &reasoning); err != nil {
		return nil
	}
	for _, item := range []struct {
		alias string
		field string
	}{
		{"reasoning_effort", "effort"},
		{"reasoning_max_tokens", "max_tokens"},
		{"reasoning_display", "display"},
	} {
		if _, ok := rawData[item.alias]; !ok {
			continue
		}
		if _, ok := reasoning[item.field]; ok {
			return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: item.alias + " conflicts with reasoning." + item.field}
		}
	}
	return nil
}

func rawInteger(raw json.RawMessage) (int, bool) {
	var value int
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}
