package stogas

import (
	"encoding/json"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	anthropicAdapterRouteChat      anthropicAdapterRoute = "chat-completions"
	anthropicAdapterRouteResponses anthropicAdapterRoute = "responses"

	meterAnthropicWebSearchCalls = "anthropic_web_search_calls"

	opus48MaxToolOverheadTokens   = 410
	sonnet46MaxToolOverheadTokens = 589
)

type anthropicAdapterRoute string

type anthropicAdapterDeployment struct {
	Model               string
	ContextWindowTokens int
	Pricing             billing.Pricing
}

type anthropicAdapterContext struct {
	Route                 anthropicAdapterRoute
	Deployment            anthropicAdapterDeployment
	InputTokenLimit       int
	OutputTokenLimit      int
	ToolChoiceAllowsCalls bool
	ToolTypes             []string
	RawBody               map[string]json.RawMessage
	RawTools              []map[string]json.RawMessage
	ActualWebSearchCalls  int
}

func (a AnthropicAdapter) ValidateRequest(state *State) error {
	if err := a.DefaultAdapter.ValidateRequest(state); err != nil {
		return err
	}
	if err := validateAnthropicOutputTokenLimit(state); err != nil {
		return err
	}
	if err := validateAnthropicChatCompletionPolicy(state); err != nil {
		return err
	}
	return validateAnthropicResponsesPolicy(state)
}

func validateAnthropicOutputTokenLimit(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.OutputTokenLimit() != 0 {
		return nil
	}
	if anthropicRawRequestContainsCacheControl(state.Resolution.Route, state.Resolution.RawBody()) {
		return nil
	}
	return catalog.ErrParameterTooLarge
}

func validateAnthropicChatCompletionPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteChat {
		return nil
	}
	raw := state.Resolution.RawBody()
	if err := validateAnthropicParallelToolCalls(raw); err != nil {
		return err
	}
	if err := validateAnthropicSamplingIntent(raw); err != nil {
		return err
	}
	if err := rejectOpenAIOnlyParameters(raw,
		"frequency_penalty",
		"logit_bias",
		"logprobs",
		"prediction",
		"presence_penalty",
		"prompt_cache_key",
		"prompt_cache_retention",
		"seed",
		"top_logprobs",
		"verbosity",
		"web_search_options",
	); err != nil {
		return err
	}
	if err := validateAnthropicChatCacheControls(raw); err != nil {
		return err
	}
	tools, err := validateChatTools(raw["tools"], chatToolCapabilities{allowMCPToolset: true})
	if err != nil {
		return err
	}
	if err := validateChatMCPServers(raw["mcp_servers"], tools); err != nil {
		return err
	}
	if err := validateChatToolChoice(raw["tool_choice"], tools, chatToolCapabilities{allowMCPToolset: true}); err != nil {
		return err
	}
	return nil
}

func validateAnthropicResponsesPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteResponses {
		return nil
	}
	raw := state.Resolution.RawBody()
	if err := validateAnthropicParallelToolCalls(raw); err != nil {
		return err
	}
	if err := validateAnthropicSamplingIntent(raw); err != nil {
		return err
	}
	if err := rejectOpenAIOnlyParameters(raw,
		"frequency_penalty",
		"include",
		"presence_penalty",
		"prompt_cache_key",
		"prompt_cache_retention",
		"top_logprobs",
	); err != nil {
		return err
	}
	if err := validateAnthropicResponsesCacheControls(raw); err != nil {
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
	} else if responsesHasHostedTool(tools) {
		if err := validateAnthropicResponsesHostedToolCaps(state, raw, tools); err != nil {
			return err
		}
	} else if _, ok := raw["max_tool_calls"]; ok {
		return invalidRequest("max_tool_calls is only supported for Anthropic hosted tools")
	}
	if err := validateResponsesToolChoice(state, raw["tool_choice"], tools); err != nil {
		return err
	}
	return nil
}

func rejectOpenAIOnlyParameters(raw map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		if rawJSONValueSet(raw[name]) {
			return invalidRequest(name + " is only supported for OpenAI deployments")
		}
	}
	return nil
}

func validateAnthropicParallelToolCalls(raw map[string]json.RawMessage) error {
	if !rawJSONValueSet(raw["parallel_tool_calls"]) {
		return nil
	}
	return invalidRequest("parallel_tool_calls is not supported for Anthropic deployments")
}

func validateAnthropicSamplingIntent(raw map[string]json.RawMessage) error {
	if rawJSONValueSet(raw["temperature"]) && rawJSONValueSet(raw["top_p"]) {
		return invalidRequest("Anthropic deployments do not support temperature and top_p together")
	}
	if rawJSONValueSet(raw["stop"]) && rawJSONValueSet(raw["stop_sequences"]) {
		return invalidRequest("stop conflicts with stop_sequences")
	}
	return nil
}

func validateAnthropicChatCacheControls(raw map[string]json.RawMessage) error {
	if cacheControl, ok := raw["cache_control"]; ok {
		if err := validateAnthropicCacheControl(cacheControl, "cache_control"); err != nil {
			return err
		}
	}
	if err := validateAnthropicChatMessageCacheControls(raw["messages"]); err != nil {
		return err
	}
	return validateAnthropicToolCacheControls(raw["tools"])
}

func validateAnthropicChatMessageCacheControls(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var messages []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &messages); err != nil {
		return nil
	}
	for _, message := range messages {
		if _, ok := message["cache_control"]; ok {
			return invalidRequest("messages[].cache_control is not supported by Stogas API")
		}
		contentRaw := message["content"]
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
			if cacheControl, ok := block["cache_control"]; ok {
				if err := validateAnthropicCacheControl(cacheControl, "messages[].content[].cache_control"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateAnthropicResponsesCacheControls(raw map[string]json.RawMessage) error {
	if cacheControl, ok := raw["cache_control"]; ok {
		if err := validateAnthropicCacheControl(cacheControl, "cache_control"); err != nil {
			return err
		}
	}
	if err := validateAnthropicResponsesInputCacheControls(raw["input"]); err != nil {
		return err
	}
	return validateAnthropicToolCacheControls(raw["tools"])
}

func validateAnthropicResponsesInputCacheControls(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	return walkAnthropicResponsesInputCacheControls(raw, "input")
}

func walkAnthropicResponsesInputCacheControls(raw json.RawMessage, path string) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed[0] == '"' {
		return nil
	}
	switch trimmed[0] {
	case '{':
		object, ok := rawObject(raw)
		if !ok {
			return nil
		}
		if cacheControl, ok := object["cache_control"]; ok {
			switch rawString(object["type"]) {
			case "input_text", "output_text":
				if err := validateAnthropicCacheControl(cacheControl, path+".cache_control"); err != nil {
					return err
				}
			default:
				return invalidRequest(path + ".cache_control is not supported by Stogas API")
			}
		}
		if content, ok := object["content"]; ok {
			if err := walkAnthropicResponsesInputCacheControls(content, path+".content"); err != nil {
				return err
			}
		}
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return nil
		}
		for _, child := range array {
			if err := walkAnthropicResponsesInputCacheControls(child, path+"[]"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAnthropicToolCacheControls(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var tools []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &tools); err != nil {
		return nil
	}
	for _, tool := range tools {
		if cacheControl, ok := tool["cache_control"]; ok {
			if err := validateAnthropicCacheControl(cacheControl, "tools[].cache_control"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAnthropicCacheControl(raw json.RawMessage, name string) error {
	cacheControl, ok := rawObject(raw)
	if !ok {
		return invalidRequest(name + " must be an object")
	}
	if rawString(cacheControl["type"]) != "ephemeral" {
		return invalidRequest(name + ".type must be ephemeral")
	}
	if ttlRaw, ok := cacheControl["ttl"]; ok {
		switch rawString(ttlRaw) {
		case "5m", "1h":
		default:
			return invalidRequest(name + ".ttl must be 5m or 1h")
		}
	}
	return nil
}

func validateAnthropicResponsesHostedToolCaps(state *State, raw map[string]json.RawMessage, tools []schemas.ResponsesTool) error {
	if state == nil || state.Resolution == nil {
		return nil
	}
	if !responsesToolTypeExists(tools, schemas.ResponsesToolTypeWebSearch) && !responsesToolTypeExists(tools, schemas.ResponsesToolTypeWebFetch) {
		return nil
	}
	topLevelCap, hasTopLevelCap, err := rawInteger(raw["max_tool_calls"], "max_tool_calls")
	if err != nil {
		return err
	}
	for _, rawTool := range state.Resolution.RawTools() {
		rawType := rawString(rawTool["type"])
		if !anthropicResponsesWebSearchToolType(rawType) && !anthropicResponsesWebFetchToolType(rawType) {
			continue
		}
		toolCap, hasToolCap, err := rawInteger(rawTool["max_uses"], "tools[].max_uses")
		if err != nil {
			return err
		}
		if hasToolCap && (toolCap < 1 || toolCap > maxResponsesToolCalls) {
			return invalidRequest("tools[].max_uses is outside the supported range")
		}
		if hasTopLevelCap && hasToolCap && topLevelCap != toolCap {
			return invalidRequest("max_tool_calls conflicts with tools[].max_uses")
		}
	}
	return nil
}

func (a AnthropicAdapter) SanitizeRequest(state *State) error {
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	state.Resolution.ApplyProviderSamplingParameters()
	if anthropicFastDeploymentID(state.Resolution.Deployment.ID) {
		state.Resolution.SetSpeed("fast")
	} else {
		state.Resolution.SetSpeed("standard")
	}
	switch state.Resolution.Deployment.RegionID {
	case "us":
		state.Resolution.SetExtraParam("inference_geo", "us")
	case "multi-region", "":
		state.Resolution.SetExtraParam("inference_geo", "global")
	}
	ensureAnthropicResponsesHostedToolCap(state)
	return nil
}

func (a AnthropicAdapter) EstimateHold(state *State) error {
	if err := a.DefaultAdapter.EstimateHold(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	state.Hold.Meters = append(state.Hold.Meters, anthropicHoldMeters(anthropicAdapterContextForState(state))...)
	state.Hold.MaxUSDAtoms = sumMeterAmounts(state.Hold.Meters)
	return nil
}

func (a AnthropicAdapter) IngestChunk(state *State, chunk *schemas.BifrostStreamChunk) error {
	if err := a.DefaultAdapter.IngestChunk(state, chunk); err != nil {
		return err
	}
	observePricedResponsesWebSearchChunk(state, chunk)
	return nil
}

func (a AnthropicAdapter) IngestResponse(state *State, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) error {
	if err := a.DefaultAdapter.IngestResponse(state, resp, bifrostErr); err != nil {
		return err
	}
	observePricedResponsesWebSearchResponse(state, resp)
	return nil
}

func (AnthropicAdapter) FinalPrice(state *State) error {
	if state == nil {
		return nil
	}
	state.FinalCostUSDAtoms = baseFinalPrice(state, anthropicFinalMeters(anthropicAdapterContextForFinalPrice(state)))
	return nil
}

func (AnthropicAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	rawType := rawString(tool["type"])
	if anthropicResponsesToolTypeSupported(rawType) {
		if rawType == "mcp" {
			if _, ok := tool["require_approval"]; ok {
				return invalidRequest("mcp.require_approval is only supported for OpenAI Responses deployments")
			}
		}
		if anthropicResponsesWebSearchToolType(rawType) {
			if state != nil && state.Resolution != nil && !responsesHostedToolChoiceAllowsCalls(state.Resolution.RawBody()) {
				return nil
			}
			if state == nil || state.Resolution == nil {
				return invalidRequest("Hosted tools are not supported for this deployment")
			}
			if _, ok := effectivePricingForState(state)[meterAnthropicWebSearchCalls]; !ok {
				return invalidRequest("Hosted tools are not supported for this deployment")
			}
		}
		if anthropicResponsesWebFetchToolType(rawType) {
			for _, field := range []string{"allowed_callers", "allowed_domains", "blocked_domains", "citations", "response_inclusion", "use_cache"} {
				if _, ok := tool[field]; ok {
					return invalidRequest("tools[]." + field + " is not supported because it is not preserved by the current Anthropic Responses translation")
				}
			}
		}
		return nil
	}
	if anthropicResponsesCodeExecutionToolType(rawType) {
		return invalidRequest("Explicit Anthropic code_execution tools are not supported because dynamic web search/fetch auto-injects code execution when available, and standalone code execution has separate container-time pricing")
	}
	return invalidRequest("Only function, custom, mcp, web_fetch, and priced hosted web search tools are supported")
}

func ensureAnthropicResponsesHostedToolCap(state *State) {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteResponses {
		return
	}
	if !responsesHostedToolChoiceAllowsCalls(state.Resolution.RawBody()) {
		return
	}
	toolTypes := effectiveResponsesToolTypes(state.Resolution.RawBody(), state.Resolution.ToolTypes())
	if usesToolType(toolTypes, string(schemas.ResponsesToolTypeWebSearch)) {
		state.Resolution.EnsureResponsesToolMaxUses(responsesTopLevelMaxToolCallsOrDefault(state), schemas.ResponsesToolTypeWebSearch)
	}
	if usesToolType(toolTypes, string(schemas.ResponsesToolTypeWebFetch)) {
		state.Resolution.EnsureResponsesToolMaxUses(responsesTopLevelMaxToolCallsOrDefault(state), schemas.ResponsesToolTypeWebFetch)
	}
}

func anthropicAdapterContextForState(state *State) anthropicAdapterContext {
	return anthropicAdapterContextForDeployment(state, pricingDeploymentForState(state))
}

func anthropicAdapterContextForFinalPrice(state *State) anthropicAdapterContext {
	req := anthropicAdapterContextForDeployment(state, pricingDeploymentForState(state))
	req.ActualWebSearchCalls = anthropicBillableHostedToolCalls(state)
	return req
}

func anthropicAdapterContextForDeployment(state *State, deployment catalog.Deployment) anthropicAdapterContext {
	if state == nil || state.Resolution == nil {
		return anthropicAdapterContext{}
	}
	pricing := mergePricing(catalog.ProviderPricing(state.Resolution.Provider), deployment.Pricing)
	return anthropicAdapterContext{
		Route:                 anthropicAdapterRoute(state.Resolution.Route),
		Deployment:            anthropicAdapterDeployment{Model: deployment.Model, ContextWindowTokens: deployment.ContextWindowTokens, Pricing: pricing},
		InputTokenLimit:       state.Resolution.InputTokenLimit(),
		OutputTokenLimit:      state.Resolution.OutputTokenLimit(),
		ToolChoiceAllowsCalls: responsesHostedToolChoiceAllowsCalls(state.Resolution.RawBody()),
		ToolTypes:             effectiveResponsesToolTypes(state.Resolution.RawBody(), state.Resolution.ToolTypes()),
		RawBody:               state.Resolution.RawBody(),
		RawTools:              state.Resolution.RawTools(),
		ActualWebSearchCalls:  actualWebSearchCalls(state),
	}
}

func anthropicBillableHostedToolCalls(state *State) int {
	actual := actualWebSearchCalls(state)
	if actual <= 0 {
		return 0
	}
	allowed := anthropicHostedToolHoldQuantity(anthropicAdapterContextForState(state))
	if allowed > 0 && actual > allowed {
		return allowed
	}
	return actual
}

func anthropicHoldMeters(req anthropicAdapterContext) []billing.MeterEstimate {
	meters := []billing.MeterEstimate{}
	cacheWriteMeter := anthropicCacheWriteHoldMeter(req)
	if req.InputTokenLimit > 0 {
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, cacheWriteMeter, req.InputTokenLimit, true, billing.TokenRateHighest)
	}
	if overhead := anthropicToolSystemPromptHoldTokens(req.Deployment.Model, req.ToolTypes); overhead > 0 {
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, billing.MeterInputTokens, overhead, true, billing.TokenRateHighest)
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, cacheWriteMeter, overhead, true, billing.TokenRateHighest)
	}
	if req.Route == anthropicAdapterRouteResponses && req.ToolChoiceAllowsCalls && usesToolType(req.ToolTypes, "web_search") {
		meters = billing.AppendCallMeterCost(meters, req.Deployment.Pricing, meterAnthropicWebSearchCalls, anthropicHostedToolHoldQuantity(req), true)
	}
	if hostedContentTokens := anthropicHostedContentHoldTokens(req); hostedContentTokens > 0 {
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, billing.MeterInputTokens, hostedContentTokens, true, billing.TokenRateHighest)
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, cacheWriteMeter, hostedContentTokens, true, billing.TokenRateHighest)
	}
	return meters
}

func anthropicHostedContentHoldTokens(req anthropicAdapterContext) int {
	if req.Route != anthropicAdapterRouteResponses || !req.ToolChoiceAllowsCalls {
		return 0
	}
	headroom := req.Deployment.ContextWindowTokens - req.OutputTokenLimit - req.InputTokenLimit
	if headroom <= 0 {
		return 0
	}
	if usesToolType(req.ToolTypes, "web_search") {
		return headroom
	}
	if !usesToolType(req.ToolTypes, "web_fetch") {
		return 0
	}
	return anthropicWebFetchContentHoldTokens(req, headroom)
}

func anthropicWebFetchContentHoldTokens(req anthropicAdapterContext, headroom int) int {
	topLevelQuantity := anthropicResponsesTopLevelMaxToolCallsOrDefaultRaw(req.RawBody)
	total := 0
	for _, tool := range req.RawTools {
		rawType := strings.TrimSpace(rawString(tool["type"]))
		if !anthropicResponsesWebFetchToolType(rawType) {
			continue
		}
		perUse, ok := rawIntegerValue(tool["max_content_tokens"])
		if !ok || perUse < 1 {
			perUse = headroom
		}
		uses, ok := rawIntegerValue(tool["max_uses"])
		if !ok || uses < 1 {
			uses = topLevelQuantity
		}
		if perUse > headroom {
			perUse = headroom
		}
		if uses > 0 && perUse > headroom/uses {
			total = headroom
		} else {
			total += perUse * uses
		}
		if total >= headroom {
			return headroom
		}
	}
	if total == 0 {
		return headroom
	}
	return total
}

func anthropicCacheWriteHoldMeter(req anthropicAdapterContext) string {
	route := catalog.Route(req.Route)
	if !anthropicRawRequestContainsCacheControl(route, req.RawBody) && !anthropicToolCacheControlExists(req.RawTools) {
		return ""
	}
	if anthropicTopLevelCacheControlIs1h(req.RawBody) || anthropicToolCacheControlIs1h(req.RawTools) {
		return billing.MeterCacheWrite1hInputTokens
	}
	switch route {
	case catalog.RouteChat:
		if anthropicChatMessageCacheControlIs1h(req.RawBody["messages"]) {
			return billing.MeterCacheWrite1hInputTokens
		}
	case catalog.RouteResponses:
		if anthropicResponsesInputCacheControlIs1h(req.RawBody["input"]) {
			return billing.MeterCacheWrite1hInputTokens
		}
	}
	return billing.MeterCacheWrite5mInputTokens
}

func anthropicRawRequestContainsCacheControl(route catalog.Route, rawData map[string]json.RawMessage) bool {
	if rawData == nil {
		return false
	}
	if _, ok := rawData["cache_control"]; ok {
		return true
	}
	if anthropicRawArrayObjectsContainDirectKey(rawData["tools"], "cache_control") {
		return true
	}
	switch route {
	case catalog.RouteChat:
		return anthropicRawChatMessagesContainCacheControl(rawData["messages"])
	case catalog.RouteResponses:
		return anthropicRawResponsesInputContainsCacheControl(rawData["input"])
	default:
		return false
	}
}

func anthropicRawArrayObjectsContainDirectKey(raw json.RawMessage, key string) bool {
	if len(raw) == 0 {
		return false
	}
	var values []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &values); err != nil {
		return false
	}
	for _, value := range values {
		if _, ok := value[key]; ok {
			return true
		}
	}
	return false
}

func anthropicRawChatMessagesContainCacheControl(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var messages []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &messages); err != nil {
		return false
	}
	for _, message := range messages {
		contentRaw := message["content"]
		trimmed := strings.TrimSpace(string(contentRaw))
		if len(contentRaw) == 0 || trimmed == "" || trimmed[0] != '[' {
			continue
		}
		if anthropicRawArrayObjectsContainDirectKey(contentRaw, "cache_control") {
			return true
		}
	}
	return false
}

func anthropicRawResponsesInputContainsCacheControl(raw json.RawMessage) bool {
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
		return anthropicRawResponsesInputContainsCacheControl(object["content"])
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return false
		}
		for _, child := range array {
			if anthropicRawResponsesInputContainsCacheControl(child) {
				return true
			}
		}
	}
	return false
}

func anthropicTopLevelCacheControlIs1h(raw map[string]json.RawMessage) bool {
	if raw == nil {
		return false
	}
	return anthropicCacheControlTTLIs1h(raw["cache_control"])
}

func anthropicToolCacheControlIs1h(tools []map[string]json.RawMessage) bool {
	for _, tool := range tools {
		if anthropicCacheControlTTLIs1h(tool["cache_control"]) {
			return true
		}
	}
	return false
}

func anthropicToolCacheControlExists(tools []map[string]json.RawMessage) bool {
	for _, tool := range tools {
		if rawJSONValueSet(tool["cache_control"]) {
			return true
		}
	}
	return false
}

func anthropicChatMessageCacheControlIs1h(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var messages []map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &messages); err != nil {
		return false
	}
	for _, message := range messages {
		contentRaw := message["content"]
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
			if anthropicCacheControlTTLIs1h(block["cache_control"]) {
				return true
			}
		}
	}
	return false
}

func anthropicResponsesInputCacheControlIs1h(raw json.RawMessage) bool {
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
		if anthropicCacheControlTTLIs1h(object["cache_control"]) {
			return true
		}
		return anthropicResponsesInputCacheControlIs1h(object["content"])
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return false
		}
		for _, child := range array {
			if anthropicResponsesInputCacheControlIs1h(child) {
				return true
			}
		}
	}
	return false
}

func anthropicCacheControlTTLIs1h(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	cacheControl, ok := rawObject(raw)
	if !ok {
		return false
	}
	return rawString(cacheControl["ttl"]) == "1h"
}

func anthropicFinalMeters(req anthropicAdapterContext) []billing.MeterEstimate {
	if req.Route != anthropicAdapterRouteResponses || !req.ToolChoiceAllowsCalls || !usesToolType(req.ToolTypes, "web_search") || req.ActualWebSearchCalls <= 0 {
		return nil
	}
	quantity := req.ActualWebSearchCalls
	if cap := anthropicHostedToolHoldQuantity(req); cap > 0 && quantity > cap {
		quantity = cap
	}
	return billing.AppendCallMeterCost(nil, req.Deployment.Pricing, meterAnthropicWebSearchCalls, quantity, false)
}

func anthropicResponsesToolTypeSupported(rawType string) bool {
	rawType = strings.TrimSpace(rawType)
	switch rawType {
	case "function", "custom", "mcp":
		return true
	default:
		return anthropicResponsesWebSearchToolType(rawType) || anthropicResponsesWebFetchToolType(rawType)
	}
}

func anthropicResponsesWebSearchToolType(rawType string) bool {
	rawType = strings.TrimSpace(rawType)
	return rawType == "web_search" || strings.HasPrefix(rawType, "web_search_") && meaningfulToolAliasSuffix(strings.TrimPrefix(rawType, "web_search_"))
}

func anthropicResponsesWebFetchToolType(rawType string) bool {
	rawType = strings.TrimSpace(rawType)
	return rawType == "web_fetch" || strings.HasPrefix(rawType, "web_fetch_") && meaningfulToolAliasSuffix(strings.TrimPrefix(rawType, "web_fetch_"))
}

func anthropicResponsesCodeExecutionToolType(rawType string) bool {
	rawType = strings.TrimSpace(rawType)
	return rawType == "code_execution" || strings.HasPrefix(rawType, "code_execution_")
}

func anthropicFastDeploymentID(deploymentID string) bool {
	return strings.Contains(strings.ToLower(deploymentID), "-fast")
}

func anthropicHostedToolHoldQuantity(req anthropicAdapterContext) int {
	topLevelQuantity := anthropicResponsesTopLevelMaxToolCallsOrDefaultRaw(req.RawBody)
	quantity := 0
	for _, tool := range req.RawTools {
		rawType := strings.TrimSpace(rawString(tool["type"]))
		if !strings.HasPrefix(rawType, "web_search") {
			continue
		}
		value, ok := rawIntegerValue(tool["max_uses"])
		if !ok || value < 1 {
			value = topLevelQuantity
		}
		if value > quantity {
			quantity = value
		}
	}
	if quantity < 1 {
		return topLevelQuantity
	}
	return quantity
}

func anthropicToolSystemPromptHoldTokens(model string, toolTypes []string) int {
	if len(toolTypes) == 0 {
		return 0
	}
	normalized := strings.ToLower(strings.TrimSpace(model))
	switch {
	case strings.HasPrefix(normalized, "claude-opus-4-8"):
		return opus48MaxToolOverheadTokens
	case strings.HasPrefix(normalized, "claude-sonnet-4-6"):
		return sonnet46MaxToolOverheadTokens
	default:
		return sonnet46MaxToolOverheadTokens
	}
}

func anthropicResponsesTopLevelMaxToolCallsOrDefaultRaw(raw map[string]json.RawMessage) int {
	if raw == nil {
		return defaultResponsesHostedToolCalls
	}
	quantity, ok := rawIntegerValue(raw["max_tool_calls"])
	if !ok || quantity < 1 {
		return defaultResponsesHostedToolCalls
	}
	return quantity
}

func usesToolType(toolTypes []string, toolType string) bool {
	for _, candidate := range toolTypes {
		if strings.EqualFold(strings.TrimSpace(candidate), toolType) {
			return true
		}
	}
	return false
}

func rawIntegerValue(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}
