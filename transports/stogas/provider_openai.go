package stogas

import (
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

const (
	openAIAdapterRouteChat      openAIAdapterRoute = "chat-completions"
	openAIAdapterRouteResponses openAIAdapterRoute = "responses"
	maxPromptCacheBreakpoints                      = 4

	webSearchFixedContentInputTokens = 8000
	searchCallQuantity               = 1

	MeterOpenAIChatCompletionSearchModelCalls             = "openai_chat_completion_search_model_calls"
	MeterOpenAIChatCompletionSearchPreviewModelCalls      = "openai_chat_completion_search_preview_model_calls"
	MeterOpenAIResponsesWebSearchCalls                    = "openai_responses_web_search_calls"
	MeterOpenAIResponsesWebSearchPreviewCalls             = "openai_responses_web_search_preview_calls"
	MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls = "openai_responses_web_search_preview_non_reasoning_calls"

	RatePerThousandSearchContextHighCalls   = "per_1k_search_context_high_calls"
	RatePerThousandSearchContextLowCalls    = "per_1k_search_context_low_calls"
	RatePerThousandSearchContextMediumCalls = "per_1k_search_context_medium_calls"
)

type openAIAdapterRoute string

type openAIAdapterDeployment struct {
	Model               string
	ContextWindowTokens int
	Pricing             billing.Pricing
	ReasoningSupported  bool
}

type openAIAdapterContext struct {
	Route                openAIAdapterRoute
	Deployment           openAIAdapterDeployment
	OutputTokenLimit     int
	HasWebSearchOptions  bool
	SearchContextSize    string
	ToolsParseFailed     bool
	RawBody              map[string]json.RawMessage
	ToolTypes            []string
	RawTools             []map[string]json.RawMessage
	ActualWebSearchCalls int
}

var (
	errOpenAIUnsupportedTool         = errors.New("unsupported provider tool")
	errOpenAIUnsupportedParameter    = errors.New("unsupported provider parameter")
	errOpenAIUnsupportedInput        = errors.New("unsupported input modality")
	errOpenAIOutputTokenLimitTooLow  = errors.New("output token limit below provider minimum")
	errOpenAIInvalidProviderToolSpec = errors.New("invalid provider tool specification")
)

func (a OpenAIAdapter) SanitizeRequest(state *State) error {
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	ensureOpenAIResponsesHostedToolCap(state)
	return nil
}

func (a OpenAIAdapter) ValidateRequest(state *State) error {
	if err := a.DefaultAdapter.ValidateRequest(state); err != nil {
		return err
	}
	if state != nil && state.Resolution != nil {
		state.Resolution.NormalizeMinimumOutputTokenLimit(openaiprovider.MinMaxCompletionTokens)
	}
	if err := validateOpenAIPromptCaching(state); err != nil {
		return err
	}
	if err := validateOpenAIWireChatPolicy(state); err != nil {
		return err
	}
	if err := validateOpenAIWireResponsesPolicy(state); err != nil {
		return err
	}
	return openAIGuardrailError(validateOpenAIGuardrails(openAIAdapterContextForState(state)))
}

func validateOpenAIPromptCaching(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	raw := state.Resolution.RawBody()
	capabilities := state.Resolution.Deployment.Capabilities
	if err := validatePromptCacheKey(raw["prompt_cache_key"], "prompt_cache_key"); err != nil {
		return err
	}
	if rawJSONValueSet(raw["prompt_cache_key"]) && !capabilities.ImplicitPromptCaching {
		return invalidRequest("prompt caching is not supported for the selected OpenAI deployment")
	}
	if retentionRaw := raw["prompt_cache_retention"]; rawJSONValueSet(retentionRaw) {
		if !capabilities.ImplicitPromptCaching {
			return invalidRequest("prompt caching is not supported for the selected OpenAI deployment")
		}
		retention, ok := rawStringValue(retentionRaw)
		if !ok {
			return invalidRequest("prompt_cache_retention must be a string")
		}
		if retention != "in_memory" && retention != "24h" {
			return invalidRequest("prompt_cache_retention must be in_memory or 24h")
		}
	}
	optionsSet := rawJSONValueSet(raw["prompt_cache_options"])
	breakpoints, err := validatePromptCacheBreakpoints(
		rawPromptContent(state.Resolution.Route, raw),
		state.Resolution.Route,
	)
	if err != nil {
		return err
	}
	if breakpoints > maxPromptCacheBreakpoints {
		return invalidRequest("prompt_cache_breakpoint supports at most four prompt blocks")
	}
	if !optionsSet && breakpoints == 0 {
		return nil
	}
	if !capabilities.ExplicitPromptCaching {
		return invalidRequest("explicit prompt caching is not supported for the selected OpenAI deployment")
	}
	if !optionsSet {
		return nil
	}
	options, ok := rawObject(raw["prompt_cache_options"])
	if !ok {
		return invalidRequest("prompt_cache_options must be an object")
	}
	if !onlyRawKeysOptional(options, "mode", "ttl") {
		return invalidRequest("prompt_cache_options supports only mode and ttl")
	}
	if modeRaw, exists := options["mode"]; exists {
		mode, ok := rawStringValue(modeRaw)
		if !ok {
			return invalidRequest("prompt_cache_options.mode must be a string")
		}
		if mode != "implicit" && mode != "explicit" {
			return invalidRequest("prompt_cache_options.mode must be implicit or explicit")
		}
	}
	if ttlRaw, exists := options["ttl"]; exists {
		ttl, ok := rawStringValue(ttlRaw)
		if !ok {
			return invalidRequest("prompt_cache_options.ttl must be a string")
		}
		if ttl != "30m" {
			return invalidRequest("prompt_cache_options.ttl must be 30m")
		}
	}
	return nil
}

func rawPromptContent(route catalog.Route, raw map[string]json.RawMessage) json.RawMessage {
	if route == catalog.RouteChat {
		return raw["messages"]
	}
	return raw["input"]
}

func validatePromptCacheBreakpoints(raw json.RawMessage, route catalog.Route) (int, error) {
	count := 0
	err := openAIWalkRawJSON(raw, func(object map[string]json.RawMessage) error {
		breakpointRaw, exists := object["prompt_cache_breakpoint"]
		if !exists {
			return nil
		}
		blockType := rawjson.NormalizedStringField(object, "type")
		allowed := (route == catalog.RouteChat && stringInSet(blockType, "text", "refusal")) ||
			(route == catalog.RouteResponses && blockType == "input_text")
		if !allowed {
			return invalidRequest("prompt_cache_breakpoint is not supported on this prompt block")
		}
		breakpoint, ok := rawObject(breakpointRaw)
		if !ok || !onlyRawKeys(breakpoint, "mode") {
			return invalidRequest("prompt_cache_breakpoint must contain only mode")
		}
		mode, ok := rawStringValue(breakpoint["mode"])
		if !ok {
			return invalidRequest("prompt_cache_breakpoint.mode must be a string")
		}
		if mode != "explicit" {
			return invalidRequest("prompt_cache_breakpoint.mode must be explicit")
		}
		count++
		return nil
	})
	return count, err
}

func stringInSet(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// The Azure v1 data plane uses these OpenAI request schemas too. Provider
// selection and dispatch remain native Azure concerns; this layer only validates
// the shared representable wire surface before a hold is placed.
func validateOpenAIWireChatPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteChat {
		return nil
	}
	raw := state.Resolution.RawBody()
	if err := validateOpenAIChatScalarPolicy(raw); err != nil {
		return err
	}
	for _, name := range []string{"cache_control", "context_management", "stop_sequences", "task_budget", "top_k"} {
		if rawJSONValueSet(raw[name]) {
			return invalidRequest(name + " is only supported for Anthropic deployments")
		}
	}
	if err := rejectOpenAIChatCacheControls(raw); err != nil {
		return err
	}
	if err := validateOpenAIChatWebSearchOptions(raw["web_search_options"]); err != nil {
		return err
	}
	tools, err := validateChatTools(raw["tools"])
	if err != nil {
		return err
	}
	if err := validateChatToolChoice(raw["tool_choice"], tools); err != nil {
		return err
	}
	return nil
}
func validateOpenAIWireResponsesPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteResponses {
		return nil
	}
	raw := state.Resolution.RawBody()
	if err := validateOpenAIResponsesInclude(raw["include"]); err != nil {
		return err
	}
	for _, name := range []string{"cache_control", "context_management", "stop_sequences", "task_budget", "top_k"} {
		if rawJSONValueSet(raw[name]) {
			return invalidRequest(name + " is only supported for Anthropic deployments")
		}
	}
	if err := rejectOpenAIResponsesCacheControls(raw); err != nil {
		return err
	}
	return validateResponsesToolPolicy(state, raw, func(tools []schemas.ResponsesTool) error {
		if !responsesHasHostedTool(tools) {
			if _, ok := raw["max_tool_calls"]; ok {
				return invalidRequest("max_tool_calls is supported only for priced hosted Responses tools")
			}
		}
		return nil
	})
}

func validateOpenAIChatScalarPolicy(raw map[string]json.RawMessage) error {
	if rawJSONValueSet(raw["repetition_penalty"]) {
		return invalidRequest("repetition_penalty is only supported for Chutes deployments")
	}
	if rawJSONValueSet(raw["reasoning_display"]) {
		return invalidRequest("reasoning_display is only supported for Anthropic-format deployments")
	}
	if reasoning, ok := rawObject(raw["reasoning"]); ok && rawJSONValueSet(reasoning["display"]) {
		return invalidRequest("reasoning.display is only supported for Anthropic-format deployments")
	}
	if err := validateJSONBool(raw, "logprobs"); err != nil {
		return err
	}
	return validateChatPrediction(raw["prediction"])
}

func validateOpenAIResponsesInclude(raw json.RawMessage) error {
	values, err := validateStringArray(raw, "include", 0)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return invalidRequest("include must not contain duplicate values")
		}
		seen[value] = true
		if !stringInSet(value,
			"web_search_call.action.sources",
			"web_search_call.results",
			"message.output_text.logprobs",
			"reasoning.encrypted_content",
		) {
			return invalidRequest("include contains a value that is not supported by the text-only Stogas API")
		}
	}
	return nil
}

func validateOpenAIChatWebSearchOptions(raw json.RawMessage) error {
	if !rawJSONValueSet(raw) {
		return nil
	}
	options, ok := rawObject(raw)
	if !ok {
		return invalidRequest("web_search_options must be an object")
	}
	for key, value := range options {
		switch key {
		case "search_context_size":
			contextSize, ok := rawStringValue(value)
			if !ok {
				return invalidRequest("web_search_options.search_context_size must be a string")
			}
			switch contextSize {
			case "low", "medium", "high":
			default:
				return invalidRequest("web_search_options.search_context_size must be low, medium, or high")
			}
		case "user_location":
			if err := validateOpenAIChatWebSearchUserLocation(value); err != nil {
				return err
			}
		default:
			return invalidRequest("web_search_options." + key + " is not supported by Stogas API")
		}
	}
	return nil
}

func validateOpenAIChatWebSearchUserLocation(raw json.RawMessage) error {
	location, ok := rawObject(raw)
	if !ok {
		return invalidRequest("web_search_options.user_location must be an object")
	}
	for key := range location {
		if key != "type" && key != "approximate" {
			return invalidRequest("web_search_options.user_location." + key + " is not supported by Stogas API")
		}
	}
	if _, exists := location["type"]; !exists {
		return invalidRequest("web_search_options.user_location.type is required")
	}
	if _, exists := location["approximate"]; !exists {
		return invalidRequest("web_search_options.user_location.approximate is required")
	}
	for key, value := range location {
		switch key {
		case "type":
			locationType, ok := rawStringValue(value)
			if !ok {
				return invalidRequest("web_search_options.user_location.type must be a string")
			}
			if locationType != "approximate" {
				return invalidRequest(`web_search_options.user_location.type must be "approximate"`)
			}
		case "approximate":
			approximate, ok := rawObject(value)
			if !ok {
				return invalidRequest("web_search_options.user_location.approximate must be an object")
			}
			for field, fieldValue := range approximate {
				switch field {
				case "city", "country", "region", "timezone":
					if _, ok := rawStringValue(fieldValue); !ok {
						return invalidRequest("web_search_options.user_location.approximate." + field + " must be a string")
					}
				default:
					return invalidRequest("web_search_options.user_location.approximate." + field + " is not supported by Stogas API")
				}
			}
		}
	}
	return nil
}

func rawStringValue(raw json.RawMessage) (string, bool) {
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func rejectOpenAIChatCacheControls(raw map[string]json.RawMessage) error {
	if rawJSONValueSet(raw["cache_control"]) {
		return invalidRequest("cache_control is only supported for Anthropic deployments")
	}
	if rawChatCacheControlExists(raw["messages"], true) || rawChatCacheControlExists(raw["tools"], true) {
		return invalidRequest("cache_control is only supported for Anthropic deployments")
	}
	return nil
}

func rejectOpenAIResponsesCacheControls(raw map[string]json.RawMessage) error {
	if rawJSONValueSet(raw["cache_control"]) || rawResponsesCacheControlExists(raw["input"]) || rawResponsesCacheControlExists(raw["tools"]) {
		return invalidRequest("cache_control is only supported for Anthropic deployments")
	}
	return nil
}

func (a OpenAIAdapter) EstimateHold(state *State) error {
	if err := a.DefaultAdapter.EstimateHold(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	state.Hold.Meters = append(state.Hold.Meters, openAIHoldMeters(openAIAdapterContextForHold(state), state.Resolution.OutputTokenLimit(), state.Resolution.InputTokenLimit())...)
	meters, total, err := canonicalizeMeters(state.Hold.Meters, holdPricingForState(state))
	if err != nil {
		return err
	}
	state.Hold.Meters = meters
	state.Hold.EstimatedUpstreamCostUSDAtoms = total
	return nil
}

func (a OpenAIAdapter) IngestChunk(state *State, chunk *schemas.BifrostStreamChunk) error {
	if err := a.DefaultAdapter.IngestChunk(state, chunk); err != nil {
		return err
	}
	observePricedResponsesWebSearchChunk(state, chunk)
	return nil
}

func (a OpenAIAdapter) IngestResponse(state *State, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) error {
	if err := a.DefaultAdapter.IngestResponse(state, resp, bifrostErr); err != nil {
		return err
	}
	observePricedResponsesWebSearchResponse(state, resp)
	return nil
}

func (OpenAIAdapter) CalculateUpstreamCost(state *State) error {
	if state == nil {
		return nil
	}
	upstreamCostUSDAtoms, err := calculateBaseUpstreamCost(state, openAIFinalMeters(openAIAdapterContextForUpstreamCost(state)))
	if err != nil {
		return err
	}
	state.UpstreamCostUSDAtoms = upstreamCostUSDAtoms
	return nil
}

func (OpenAIAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	rawType := rawString(tool["type"])
	if rawType == "mcp" {
		return invalidRequest("Remote MCP tools are not supported because provider execution cannot be bounded or approved per request")
	}
	if openAIResponsesToolTypeSupported(rawType) {
		if openAIWebSearchToolType(rawType) {
			if state != nil && state.Resolution != nil && !responsesHostedToolChoiceAllowsCalls(state.Resolution.RawBody()) {
				return nil
			}
			if state == nil || state.Resolution == nil {
				return invalidRequest("Hosted tools are not supported for this deployment")
			}
			meterKey := openAIResponsesWebSearchCallMeter(openAIAdapterContextForState(state))
			if meterKey == "" {
				return invalidRequest("Hosted tools are not supported for this deployment")
			}
			if _, ok := effectivePricingForState(state)[meterKey]; !ok {
				return invalidRequest("Hosted tools are not supported for this deployment")
			}
		}
		return nil
	}
	return invalidRequest(openAIUnsupportedResponsesToolMessage(rawType))
}

func ensureOpenAIResponsesHostedToolCap(state *State) {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteResponses {
		return
	}
	if !responsesHostedToolChoiceAllowsCalls(state.Resolution.RawBody()) {
		return
	}
	if resolutionUsesToolType(state, schemas.ResponsesToolTypeWebSearch) || resolutionUsesToolType(state, schemas.ResponsesToolTypeWebSearchPreview) {
		state.Resolution.EnsureResponsesMaxToolCalls(responsesTopLevelMaxToolCallsOrDefault(state))
	}
}

func openAIAdapterContextForState(state *State) openAIAdapterContext {
	return openAIAdapterContextForDeployment(state, pricingDeploymentForState(state))
}

func openAIAdapterContextForHold(state *State) openAIAdapterContext {
	if state == nil || state.Resolution == nil {
		return openAIAdapterContext{}
	}
	req := openAIAdapterContextForDeployment(state, state.Resolution.Deployment)
	req.Deployment.Pricing = holdPricingForState(state)
	return req
}

func openAIAdapterContextForUpstreamCost(state *State) openAIAdapterContext {
	req := openAIAdapterContextForDeployment(state, pricingDeploymentForState(state))
	req.ActualWebSearchCalls = actualWebSearchCalls(state)
	return req
}

func openAIAdapterContextForDeployment(state *State, deployment catalog.Deployment) openAIAdapterContext {
	if state == nil || state.Resolution == nil {
		return openAIAdapterContext{}
	}
	resolution := state.Resolution
	pricing := clonePricing(deployment.Pricing)
	return openAIAdapterContext{
		Route: openAIAdapterRoute(resolution.Route),
		Deployment: openAIAdapterDeployment{
			Model:               deployment.Upstream.Model,
			ContextWindowTokens: deployment.ContextWindowTokens,
			Pricing:             pricing,
			ReasoningSupported:  deployment.ReasoningSupported,
		},
		OutputTokenLimit:     resolution.OutputTokenLimit(),
		HasWebSearchOptions:  resolution.HasWebSearchOptions(),
		SearchContextSize:    resolution.SearchContextSize(),
		ToolsParseFailed:     resolution.ToolsParseFailed(),
		RawBody:              resolution.RawBody(),
		ToolTypes:            resolution.ToolTypes(),
		RawTools:             resolution.RawTools(),
		ActualWebSearchCalls: actualWebSearchCalls(state),
	}
}

func openAIGuardrailError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errOpenAIUnsupportedTool), errors.Is(err, errOpenAIInvalidProviderToolSpec):
		return catalog.ErrUnsupportedTool
	case errors.Is(err, errOpenAIUnsupportedParameter):
		return invalidRequest("Parameter is not supported by this deployment")
	case errors.Is(err, errOpenAIUnsupportedInput):
		return invalidRequest("Input modality is not supported by Stogas billing")
	case errors.Is(err, errOpenAIOutputTokenLimitTooLow):
		return catalog.ErrParameterTooLarge
	default:
		return err
	}
}

func validateOpenAIGuardrails(req openAIAdapterContext) error {
	if err := validateOutputTokensMin16(req); err != nil {
		return err
	}
	if err := validateReasoningSupport(req); err != nil {
		return err
	}
	switch req.Route {
	case openAIAdapterRouteChat:
		if err := validateChatTextOnlyMVP(req); err != nil {
			return err
		}
		if err := validateChatNoHostedTools(req); err != nil {
			return err
		}
		if err := validateChatSearchModelWebSearchOptions(req); err != nil {
			return err
		}
	case openAIAdapterRouteResponses:
		if err := validateResponsesTextOnlyMVP(req); err != nil {
			return err
		}
		if err := validateResponsesNoUnbilledHostedTools(req); err != nil {
			return err
		}
	}
	return nil
}

func openAIResponsesToolTypeSupported(rawType string) bool {
	switch strings.TrimSpace(rawType) {
	case "function", "custom":
		return true
	default:
		return openAIWebSearchToolType(rawType)
	}
}

func openAIUnsupportedResponsesToolMessage(rawType string) string {
	rawType = strings.TrimSpace(rawType)
	normalized := strings.ReplaceAll(rawType, "-", "_")
	switch {
	case rawType == "":
		return "tools must declare a type"
	case normalized == "mcp":
		return "Remote MCP tools are not supported because provider execution cannot be bounded or approved per request"
	case strings.HasPrefix(normalized, "file_search"):
		return "file_search is not supported because hosted retrieval and file storage have separate pricing and provider state"
	case normalized == "code_interpreter" || strings.HasPrefix(normalized, "code_execution"):
		return "code execution tools are not supported because hosted containers have separate pricing and lifecycle"
	case normalized == "shell":
		return "shell is not supported because hosted execution needs a container lifecycle or provider-state continuation"
	case normalized == "local_shell" || normalized == "apply_patch":
		return rawType + " is not supported because local execution requires provider-state continuation"
	case strings.HasPrefix(normalized, "computer"):
		return "computer tools are not supported by the text-only Stogas API"
	case normalized == "image_generation":
		return "image_generation is not supported by the text-only Stogas API"
	case normalized == "tool_search" || normalized == "namespace" || normalized == "memory":
		return rawType + " is not supported until Stogas exposes the required tool-loading or provider-state lifecycle"
	default:
		return "Only function, custom, and priced hosted web search tools are supported"
	}
}

func openAIWebSearchToolType(rawType string) bool {
	switch strings.TrimSpace(rawType) {
	case "web_search", "web_search_2025_08_26", "web_search_preview", "web_search_preview_2025_03_11":
		return true
	default:
		return false
	}
}

func validateReasoningSupport(req openAIAdapterContext) error {
	if req.Deployment.ReasoningSupported {
		return nil
	}
	for _, name := range []string{"reasoning", "reasoning_effort", "reasoning_max_tokens", "reasoning_display", "reasoning.effort"} {
		if _, ok := req.RawBody[name]; ok {
			return errOpenAIUnsupportedParameter
		}
	}
	return nil
}

func openAIHoldMeters(req openAIAdapterContext, outputTokenLimit int, inputTokenLimit int) []billing.MeterEstimate {
	meters := []billing.MeterEstimate{}
	if req.Route == openAIAdapterRouteResponses {
		meters = append(meters, openAIResponsesHostedToolHoldMeters(req, outputTokenLimit, inputTokenLimit)...)
	}
	if req.Route == openAIAdapterRouteChat {
		meters = append(meters, openAIChatSearchModelHoldMeters(req, outputTokenLimit, inputTokenLimit)...)
	}
	return meters
}

func openAIFinalMeters(req openAIAdapterContext) []billing.MeterEstimate {
	meters := []billing.MeterEstimate{}
	if req.Route == openAIAdapterRouteResponses {
		meters = append(meters, openAIResponsesHostedToolFinalMeters(req)...)
	}
	if req.Route == openAIAdapterRouteChat {
		meters = append(meters, openAIChatSearchModelFinalMeters(req)...)
	}
	return meters
}

func validateOutputTokensMin16(req openAIAdapterContext) error {
	if req.OutputTokenLimit < 16 {
		return errOpenAIOutputTokenLimitTooLow
	}
	return nil
}

func validateChatTextOnlyMVP(req openAIAdapterContext) error {
	if req.Route != openAIAdapterRouteChat {
		return nil
	}
	return validateChatInput(req.RawBody["messages"])
}

func validateResponsesTextOnlyMVP(req openAIAdapterContext) error {
	if req.Route != openAIAdapterRouteResponses {
		return nil
	}
	return validateResponsesInput(req.RawBody["input"])
}

func validateChatNoHostedTools(req openAIAdapterContext) error {
	if req.Route != openAIAdapterRouteChat {
		return nil
	}
	return validateHostedTools(req)
}

func validateResponsesNoUnbilledHostedTools(req openAIAdapterContext) error {
	if req.Route != openAIAdapterRouteResponses {
		return nil
	}
	return validateHostedTools(req)
}

func validateHostedTools(req openAIAdapterContext) error {
	if req.ToolsParseFailed {
		return errOpenAIInvalidProviderToolSpec
	}
	for _, tool := range req.RawTools {
		if err := validateTool(req.Route, tool); err != nil {
			return err
		}
	}
	return nil
}

func validateChatSearchModelWebSearchOptions(req openAIAdapterContext) error {
	if req.Route != openAIAdapterRouteChat || !req.HasWebSearchOptions {
		return nil
	}
	if meterKey, _ := chatSearchMeter(req); meterKey == "" {
		return errOpenAIUnsupportedParameter
	}
	return nil
}

func openAIResponsesHostedToolHoldMeters(req openAIAdapterContext, outputTokenLimit int, inputTokenLimit int) []billing.MeterEstimate {
	meters := []billing.MeterEstimate{}
	if !responsesHostedToolChoiceAllowsCalls(req.RawBody) {
		return meters
	}
	quantity := responsesHostedToolHoldQuantity(req)
	searchKind := responsesSearchKind(req)
	if fixedContentTokens := webSearchFixedContentTokensForKind(req.Deployment.Model, searchKind); fixedContentTokens > 0 {
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, billing.MeterInputTokens, fixedContentTokens*quantity, true, billing.TokenRateHighest)
	}
	if webSearchContentTokensBilledAtModelRatesForKind(req, searchKind) && req.Deployment.ContextWindowTokens > 0 {
		remainingInputTokens := req.Deployment.ContextWindowTokens - outputTokenLimit - inputTokenLimit
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, billing.MeterInputTokens, remainingInputTokens, true, billing.TokenRateHighest)
	}
	if meterKey := responsesSearchMeterForKind(req, searchKind); meterKey != "" {
		meters = billing.AppendCallMeterCost(meters, req.Deployment.Pricing, meterKey, quantity, true)
	}
	return meters
}

func openAIResponsesHostedToolFinalMeters(req openAIAdapterContext) []billing.MeterEstimate {
	meters := []billing.MeterEstimate{}
	quantity := req.ActualWebSearchCalls
	if quantity <= 0 {
		return meters
	}
	searchKind := responsesSearchKind(req)
	if fixedContentTokens := webSearchFixedContentTokensForKind(req.Deployment.Model, searchKind); fixedContentTokens > 0 {
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, billing.MeterInputTokens, fixedContentTokens*quantity, false, billing.TokenRateStandard)
	}
	if meterKey := responsesSearchMeterForKind(req, searchKind); meterKey != "" {
		meters = billing.AppendCallMeterCost(meters, req.Deployment.Pricing, meterKey, quantity, false)
	}
	return meters
}

func openAIChatSearchModelHoldMeters(req openAIAdapterContext, _ int, _ int) []billing.MeterEstimate {
	if meterKey, rateKey := chatSearchMeter(req); meterKey != "" {
		return billing.AppendCallMeterCostWithRate(nil, req.Deployment.Pricing, meterKey, rateKey, searchCallQuantity, true)
	}
	return nil
}

func openAIChatSearchModelFinalMeters(req openAIAdapterContext) []billing.MeterEstimate {
	if meterKey, rateKey := chatSearchMeter(req); meterKey != "" {
		return billing.AppendCallMeterCostWithRate(nil, req.Deployment.Pricing, meterKey, rateKey, searchCallQuantity, false)
	}
	return nil
}

func validateChatInput(raw json.RawMessage) error {
	return openAIWalkRawJSON(raw, func(object map[string]json.RawMessage) error {
		switch rawjson.NormalizedStringField(object, "type") {
		case "file", "image_url", "input_audio":
			return errOpenAIUnsupportedInput
		default:
			return nil
		}
	})
}

func validateResponsesInput(raw json.RawMessage) error {
	return openAIWalkRawJSON(raw, func(object map[string]json.RawMessage) error {
		switch rawjson.NormalizedStringField(object, "type") {
		case "input_image", "input_audio":
			return errOpenAIUnsupportedInput
		case "input_file":
			return errOpenAIUnsupportedInput
		}
		return nil
	})
}

func openAIWalkRawJSON(raw json.RawMessage, visit func(map[string]json.RawMessage) error) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	switch trimmed[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := sonic.Unmarshal(raw, &object); err != nil {
			return errOpenAIUnsupportedInput
		}
		if err := visit(object); err != nil {
			return err
		}
		for _, child := range object {
			if err := openAIWalkRawJSON(child, visit); err != nil {
				return err
			}
		}
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return errOpenAIUnsupportedInput
		}
		for _, child := range array {
			if err := openAIWalkRawJSON(child, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTool(route openAIAdapterRoute, tool map[string]json.RawMessage) error {
	toolType := rawjson.NormalizedStringField(tool, "type")
	if route == openAIAdapterRouteResponses {
		if !openAIResponsesToolTypeSupported(toolType) {
			return errOpenAIUnsupportedTool
		}
		raw, err := sonic.Marshal(tool)
		if err != nil {
			return errOpenAIInvalidProviderToolSpec
		}
		var responsesTool schemas.ResponsesTool
		if err := sonic.Unmarshal(raw, &responsesTool); err != nil {
			return errOpenAIInvalidProviderToolSpec
		}
		switch responsesTool.Type {
		case schemas.ResponsesToolTypeFunction,
			schemas.ResponsesToolTypeCustom,
			schemas.ResponsesToolTypeWebSearch,
			schemas.ResponsesToolTypeWebSearchPreview:
			return nil
		default:
			return errOpenAIUnsupportedTool
		}
	}
	if route == openAIAdapterRouteChat {
		switch toolType {
		case "":
			return errOpenAIInvalidProviderToolSpec
		case "function":
			return nil
		default:
			return errOpenAIUnsupportedTool
		}
	}
	switch {
	case toolType == "":
		return errOpenAIInvalidProviderToolSpec
	case toolType == "function":
		return nil
	default:
		return errOpenAIUnsupportedTool
	}
}

func responsesHostedToolHoldQuantity(req openAIAdapterContext) int {
	if req.Route != openAIAdapterRouteResponses {
		return searchCallQuantity
	}
	raw, ok := req.RawBody["max_tool_calls"]
	if !ok {
		return defaultResponsesHostedToolCalls
	}
	var quantity int
	if err := sonic.Unmarshal(raw, &quantity); err != nil || quantity < searchCallQuantity {
		return defaultResponsesHostedToolCalls
	}
	return quantity
}

func chatSearchMeter(ctx openAIAdapterContext) (string, string) {
	normalized := strings.ToLower(strings.TrimSpace(ctx.Deployment.Model))
	meterKey := ""
	switch {
	case normalized == "gpt-5-search-api" || strings.HasPrefix(normalized, "gpt-5-search-api-") && hasDateSuffix(normalized):
		meterKey = MeterOpenAIChatCompletionSearchModelCalls
	case normalized == "gpt-4o-search-preview" || strings.HasPrefix(normalized, "gpt-4o-search-preview-") && hasDateSuffix(normalized):
		meterKey = MeterOpenAIChatCompletionSearchPreviewModelCalls
	case normalized == "gpt-4o-mini-search-preview" || strings.HasPrefix(normalized, "gpt-4o-mini-search-preview-") && hasDateSuffix(normalized):
		meterKey = MeterOpenAIChatCompletionSearchPreviewModelCalls
	}
	if meterKey == "" {
		return "", ""
	}
	return meterKey, searchContextRateKey(ctx.Deployment.Pricing, meterKey, ctx.SearchContextSize)
}

func responsesSearchMeter(ctx openAIAdapterContext) string {
	return responsesSearchMeterForKind(ctx, responsesSearchKind(ctx))
}

func responsesSearchMeterForKind(ctx openAIAdapterContext, kind string) string {
	switch kind {
	case "web_search_preview":
		if !ctx.Deployment.ReasoningSupported {
			return MeterOpenAIResponsesWebSearchPreviewNonReasoningCalls
		}
		return MeterOpenAIResponsesWebSearchPreviewCalls
	case "web_search":
		return MeterOpenAIResponsesWebSearchCalls
	default:
		return ""
	}
}

func responsesSearchKind(ctx openAIAdapterContext) string {
	if ctx.Route != openAIAdapterRouteResponses {
		return ""
	}
	toolTypes := effectiveResponsesToolTypes(ctx.RawBody, ctx.ToolTypes)
	usesWebSearch := usesWebSearchKind(toolTypes, "web_search")
	usesPreview := usesWebSearchKind(toolTypes, "web_search_preview")
	switch {
	case usesWebSearch && usesPreview:
		return higherCostSearchKind(ctx)
	case usesPreview:
		return "web_search_preview"
	case usesWebSearch:
		return "web_search"
	default:
		return ""
	}
}

func webSearchContentTokensBilledAtModelRatesForKind(ctx openAIAdapterContext, kind string) bool {
	if ctx.Route != openAIAdapterRouteResponses {
		return false
	}
	if kind == "web_search" && webSearchFixedContentTokensForKind(ctx.Deployment.Model, kind) == 0 {
		return true
	}
	return kind == "web_search_preview" && ctx.Deployment.ReasoningSupported
}

func webSearchFixedContentTokensForKind(model string, kind string) int {
	if kind != "web_search" {
		return 0
	}
	normalized := strings.ToLower(strings.TrimSpace(model))
	if strings.Contains(normalized, "search-preview") {
		return 0
	}
	if strings.HasPrefix(normalized, "gpt-4.1-mini") || strings.HasPrefix(normalized, "gpt-4o-mini") {
		return webSearchFixedContentInputTokens
	}
	return 0
}

func usesWebSearchKind(toolTypes []string, kind string) bool {
	for _, toolType := range toolTypes {
		if strings.EqualFold(strings.TrimSpace(toolType), kind) {
			return true
		}
	}
	return false
}

func higherCostSearchKind(ctx openAIAdapterContext) string {
	webSearchCost := searchKindEstimatedExtraCost(ctx, "web_search")
	previewCost := searchKindEstimatedExtraCost(ctx, "web_search_preview")
	if previewCost != nil && (webSearchCost == nil || previewCost.Cmp(webSearchCost) >= 0) {
		return "web_search_preview"
	}
	if webSearchCost != nil {
		return "web_search"
	}
	return ""
}

func searchKindEstimatedExtraCost(ctx openAIAdapterContext, kind string) *big.Int {
	meterKey := responsesSearchMeterForKind(ctx, kind)
	if meterKey == "" {
		return nil
	}
	call := callRate(ctx.Deployment.Pricing, meterKey)
	if call == nil {
		return nil
	}
	total := billing.CostPerThousand(searchCallQuantity, call)
	if fixedContentTokens := webSearchFixedContentTokensForKind(ctx.Deployment.Model, kind); fixedContentTokens > 0 {
		if _, inputRate, ok := billing.PricingRate(ctx.Deployment.Pricing, billing.MeterInputTokens, billing.TokenRateHighest); ok {
			total = new(big.Int).Add(total, billing.CostPerMillion(fixedContentTokens, inputRate))
		}
	}
	return total
}

func searchContextRateKey(pricing billing.Pricing, meterKey string, searchContextSize string) string {
	meter, ok := pricing[meterKey]
	if !ok {
		return billing.RatePerThousandCalls
	}
	switch strings.ToLower(strings.TrimSpace(searchContextSize)) {
	case "low":
		if _, ok := meter[RatePerThousandSearchContextLowCalls]; ok {
			return RatePerThousandSearchContextLowCalls
		}
	case "high":
		if _, ok := meter[RatePerThousandSearchContextHighCalls]; ok {
			return RatePerThousandSearchContextHighCalls
		}
	case "medium", "":
		if _, ok := meter[RatePerThousandSearchContextMediumCalls]; ok {
			return RatePerThousandSearchContextMediumCalls
		}
	}
	if _, ok := meter[billing.RatePerThousandCalls]; ok {
		return billing.RatePerThousandCalls
	}
	if _, ok := meter[RatePerThousandSearchContextHighCalls]; ok {
		return RatePerThousandSearchContextHighCalls
	}
	if _, ok := meter[RatePerThousandSearchContextMediumCalls]; ok {
		return RatePerThousandSearchContextMediumCalls
	}
	return RatePerThousandSearchContextLowCalls
}

func callRate(pricing billing.Pricing, meterKey string) *big.Int {
	meter, ok := pricing[meterKey]
	if !ok {
		return nil
	}
	rate, ok := billing.ParseRate(meter[billing.RatePerThousandCalls])
	if !ok {
		return nil
	}
	return rate
}

func hasDateSuffix(value string) bool {
	if len(value) < len("2006-01-02") {
		return false
	}
	suffix := value[len(value)-len("2006-01-02"):]
	for i, char := range suffix {
		switch i {
		case 4, 7:
			if char != '-' {
				return false
			}
		default:
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func openAIResponsesWebSearchCallMeter(ctx openAIAdapterContext) string {
	return responsesSearchMeter(ctx)
}
