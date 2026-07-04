package stogas

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"

	"github.com/bytedance/sonic"
	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	openAIAdapterRouteChat      openAIAdapterRoute = "chat-completions"
	openAIAdapterRouteResponses openAIAdapterRoute = "responses"

	webSearchFixedContentInputTokens = 8000
	searchCallQuantity               = 1

	MeterOpenAIChatCompletionSearchModelCalls        = "openai_chat_completion_search_model_calls"
	MeterOpenAIChatCompletionSearchPreviewModelCalls = "openai_chat_completion_search_preview_model_calls"
	MeterOpenAIResponsesWebSearchCalls               = "openai_responses_web_search_calls"
	MeterOpenAIResponsesWebSearchPreviewCalls        = "openai_responses_web_search_preview_calls"
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
	state.Resolution.NormalizePromptCacheRetention()
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
	if err := validateOpenAIChatCompletionPolicy(state); err != nil {
		return err
	}
	if err := validateOpenAIResponsesPolicy(state); err != nil {
		return err
	}
	return openAIGuardrailError(validateOpenAIGuardrails(openAIAdapterContextForState(state)))
}

func validateOpenAIChatCompletionPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteChat {
		return nil
	}
	raw := state.Resolution.RawBody()
	for _, name := range []string{"cache_control", "context_management", "mcp_servers", "stop_sequences", "task_budget", "top_k"} {
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
	tools, err := validateChatTools(raw["tools"], chatToolCapabilities{allowCustom: true})
	if err != nil {
		return err
	}
	if err := validateChatToolChoice(raw["tool_choice"], tools, chatToolCapabilities{allowCustom: true}); err != nil {
		return err
	}
	return nil
}

func validateOpenAIResponsesPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteResponses {
		return nil
	}
	raw := state.Resolution.RawBody()
	for _, name := range []string{"cache_control", "context_management", "stop_sequences", "task_budget", "top_k"} {
		if rawJSONValueSet(raw[name]) {
			return invalidRequest(name + " is only supported for Anthropic deployments")
		}
	}
	if err := rejectOpenAIResponsesCacheControls(raw); err != nil {
		return err
	}
	tools, err := parseResponsesTools(state, raw["tools"])
	if err != nil {
		return err
	}
	if len(tools) == 0 {
		if _, ok := raw["max_tool_calls"]; ok {
			return invalidRequest("max_tool_calls requires supported tools")
		}
		if _, ok := raw["parallel_tool_calls"]; ok {
			return invalidRequest("parallel_tool_calls requires supported tools")
		}
	}
	if err := validateResponsesToolChoice(state, raw["tool_choice"], tools); err != nil {
		return err
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
		default:
			return invalidRequest("web_search_options.user_location." + key + " is not supported by Stogas API")
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
	if openAIChatCacheControlExists(raw["messages"]) || openAIChatCacheControlExists(raw["tools"]) {
		return invalidRequest("cache_control is only supported for Anthropic deployments")
	}
	return nil
}

func openAIChatCacheControlExists(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var values []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &values); err != nil {
		return false
	}
	for _, value := range values {
		if _, ok := value["cache_control"]; ok {
			return true
		}
		contentRaw := value["content"]
		if len(contentRaw) == 0 {
			continue
		}
		trimmed := strings.TrimSpace(string(contentRaw))
		if trimmed == "" || trimmed == "null" || trimmed[0] != '[' {
			continue
		}
		var blocks []map[string]json.RawMessage
		if err := sonic.Unmarshal(contentRaw, &blocks); err != nil {
			continue
		}
		for _, block := range blocks {
			if _, ok := block["cache_control"]; ok {
				return true
			}
		}
	}
	return false
}

func rejectOpenAIResponsesCacheControls(raw map[string]json.RawMessage) error {
	if rawJSONValueSet(raw["cache_control"]) || openAIResponsesCacheControlExists(raw["input"]) || openAIResponsesCacheControlExists(raw["tools"]) {
		return invalidRequest("cache_control is only supported for Anthropic deployments")
	}
	return nil
}

func openAIResponsesCacheControlExists(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed[0] == '"' {
		return false
	}
	switch trimmed[0] {
	case '{':
		object, ok := rawObject(raw)
		if !ok {
			return false
		}
		if _, ok := object["cache_control"]; ok {
			return true
		}
		return openAIResponsesCacheControlExists(object["content"])
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return false
		}
		for _, child := range array {
			if openAIResponsesCacheControlExists(child) {
				return true
			}
		}
	}
	return false
}

func (a OpenAIAdapter) EstimateHold(state *State) error {
	if err := a.DefaultAdapter.EstimateHold(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	state.Hold.Meters = append(state.Hold.Meters, openAIHoldMeters(openAIAdapterContextForDeployment(state, state.Resolution.Deployment), state.Resolution.OutputTokenLimit(), state.Resolution.InputTokenLimit())...)
	state.Hold.MaxUSDAtoms = sumMeterAmounts(state.Hold.Meters)
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

func (OpenAIAdapter) FinalPrice(state *State) error {
	if state == nil {
		return nil
	}
	state.FinalCostUSDAtoms = baseFinalPrice(state, openAIFinalMeters(openAIAdapterContextForFinalPrice(state)))
	return nil
}

func (OpenAIAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	rawType := rawString(tool["type"])
	if openAIResponsesToolTypeSupported(rawType) {
		switch rawType {
		case "mcp":
			if err := validateOpenAIResponsesMCPToolApproval(tool); err != nil {
				return err
			}
		}
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

func validateOpenAIResponsesMCPToolApproval(tool map[string]json.RawMessage) error {
	rawApproval, ok := tool["require_approval"]
	if !ok {
		return invalidRequest(`OpenAI MCP tools require require_approval="never"`)
	}
	if rawString(rawApproval) != "never" {
		return invalidRequest(`OpenAI MCP tools require require_approval="never"`)
	}
	return nil
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

func openAIAdapterContextForFinalPrice(state *State) openAIAdapterContext {
	req := openAIAdapterContextForDeployment(state, pricingDeploymentForState(state))
	req.ActualWebSearchCalls = openAIBillableHostedToolCalls(state)
	return req
}

func openAIAdapterContextForDeployment(state *State, deployment catalog.Deployment) openAIAdapterContext {
	if state == nil || state.Resolution == nil {
		return openAIAdapterContext{}
	}
	resolution := state.Resolution
	pricing := mergePricing(catalog.ProviderPricing(resolution.Provider), deployment.Pricing)
	return openAIAdapterContext{
		Route: openAIAdapterRoute(resolution.Route),
		Deployment: openAIAdapterDeployment{
			Model:               deployment.Model,
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

func openAIBillableHostedToolCalls(state *State) int {
	actual := actualWebSearchCalls(state)
	if actual <= 0 {
		return 0
	}
	allowed := responsesTopLevelMaxToolCallsOrDefault(state)
	if allowed > 0 && actual > allowed {
		return allowed
	}
	return actual
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
	case "function", "custom", "mcp":
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
		return "Only function, custom, mcp, and priced hosted web search tools are supported"
	}
}

func openAIWebSearchToolType(rawType string) bool {
	rawType = strings.TrimSpace(rawType)
	switch {
	case rawType == "web_search", rawType == "web_search_preview":
		return true
	case strings.HasPrefix(rawType, "web_search_preview_"):
		return meaningfulToolAliasSuffix(strings.TrimPrefix(rawType, "web_search_preview_"))
	case strings.HasPrefix(rawType, "web_search_"):
		suffix := strings.TrimPrefix(rawType, "web_search_")
		return meaningfulToolAliasSuffix(suffix) && !strings.HasPrefix(suffix, "preview")
	default:
		return false
	}
}

func meaningfulToolAliasSuffix(suffix string) bool {
	return strings.Trim(suffix, "_- ") != ""
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
	if cap := responsesHostedToolHoldQuantity(req); cap > 0 && quantity > cap {
		quantity = cap
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
		switch rawStringField(object, "type") {
		case "file", "image_url", "input_audio":
			return errOpenAIUnsupportedInput
		default:
			return nil
		}
	})
}

func validateResponsesInput(raw json.RawMessage) error {
	return openAIWalkRawJSON(raw, func(object map[string]json.RawMessage) error {
		switch rawStringField(object, "type") {
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
	toolType := rawStringField(tool, "type")
	if route == openAIAdapterRouteResponses {
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
			schemas.ResponsesToolTypeMCP,
			schemas.ResponsesToolTypeWebSearch,
			schemas.ResponsesToolTypeWebSearchPreview:
			if responsesTool.Type == schemas.ResponsesToolTypeMCP {
				return validateMCPTool(tool)
			}
			return nil
		default:
			return errOpenAIUnsupportedTool
		}
	}
	if route == openAIAdapterRouteChat {
		switch toolType {
		case "":
			return errOpenAIInvalidProviderToolSpec
		case "function", "custom":
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

func validateMCPTool(tool map[string]json.RawMessage) error {
	if rawStringField(tool, "server_label") == "" || rawStringField(tool, "server_url") == "" {
		return errOpenAIInvalidProviderToolSpec
	}
	parsed, err := url.Parse(rawStringField(tool, "server_url"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return errOpenAIInvalidProviderToolSpec
	}
	var allowedTools schemas.ResponsesToolMCPAllowedTools
	if err := sonic.Unmarshal(tool["allowed_tools"], &allowedTools); err != nil {
		return errOpenAIInvalidProviderToolSpec
	}
	if len(allowedTools.ToolNames) == 0 && allowedTools.Filter == nil {
		return errOpenAIInvalidProviderToolSpec
	}
	for _, name := range allowedTools.ToolNames {
		if strings.TrimSpace(name) == "" {
			return errOpenAIInvalidProviderToolSpec
		}
	}
	if allowedTools.Filter != nil {
		if len(allowedTools.Filter.ToolNames) == 0 && (allowedTools.Filter.ReadOnly == nil || !*allowedTools.Filter.ReadOnly) {
			return errOpenAIInvalidProviderToolSpec
		}
		for _, name := range allowedTools.Filter.ToolNames {
			if strings.TrimSpace(name) == "" {
				return errOpenAIInvalidProviderToolSpec
			}
		}
	}
	if rawStringField(tool, "require_approval") != "never" {
		return errOpenAIUnsupportedTool
	}
	for key := range tool {
		switch key {
		case "type", "name", "server_label", "server_url", "server_description", "authorization", "allowed_tools", "require_approval":
		default:
			return errOpenAIUnsupportedTool
		}
	}
	return nil
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

func webSearchContentTokensBilledAtModelRates(ctx openAIAdapterContext) bool {
	return webSearchContentTokensBilledAtModelRatesForKind(ctx, responsesSearchKind(ctx))
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

func webSearchFixedContentTokens(model string, toolTypes []string) int {
	if !usesWebSearchKind(toolTypes, "web_search") {
		return 0
	}
	return webSearchFixedContentTokensForKind(model, "web_search")
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

func rawStringField(object map[string]json.RawMessage, key string) string {
	raw, ok := object[key]
	if !ok {
		return ""
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(value))
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
