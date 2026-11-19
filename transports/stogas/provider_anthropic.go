package stogas

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/bytedance/sonic"
	anthropicprovider "github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const (
	anthropicAdapterRouteChat      anthropicAdapterRoute = "chat-completions"
	anthropicAdapterRouteResponses anthropicAdapterRoute = "responses"

	meterAnthropicWebSearchCalls = "anthropic_web_search_calls"

	// Anthropic does not publish tool-system prompt counts for Fable or Mythos.
	// Use the largest published current-model count for those families and for
	// runtime catalog drift; the catalog-wide test still requires an explicit row.
	maxAnthropicToolSystemPromptTokens = 804
)

type anthropicAdapterRoute string

type anthropicAdapterDeployment struct {
	Model           string
	MaxInputTokens  int
	MaxOutputTokens int
	Pricing         billing.Pricing
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
	// PromptCache is the lifetime of the cache entries that the gateway's marks ask for, or "".
	PromptCache string
}

// anthropicWireSupportsMidConversationSystem reports whether the model keeps a system message
// in place after the conversation starts. Anthropic documents the role on every platform that
// runs Claude, so the model alone decides, and a conversation keeps its messages on every hosting.
func anthropicWireSupportsMidConversationSystem(state *State) bool {
	return state != nil && state.Resolution != nil &&
		anthropicprovider.DefaultSupportsMidConversationSystem(schemas.Anthropic, state.Resolution.Deployment.Upstream.Model)
}

// The side of the conversation that an input item belongs to on Anthropic wire. A server tool
// result, such as a web search with its results, belongs to the assistant's turn.
const (
	claudeSystemItem = iota
	claudeUserItem
	claudeAssistantItem
	claudeServerResultItem
)

// claudeSystemPlacement checks where a system or developer message stands after the conversation
// starts on Anthropic wire, which keeps it in place as Claude requires: right after a user message,
// tool results or an assistant turn that ends in a server tool result, and last or right before
// the assistant's turn. Consecutive system messages count as one. Anywhere else it gets 400,
// because moving it or turning it into user text would change what it means.
type claudeSystemPlacement struct {
	started   bool   // a user or assistant item has come
	afterUser bool   // the last such item was on the user side or a server tool result
	pending   string // the path of a system message that waits for the assistant's turn
}

func (p *claudeSystemPlacement) next(state *State, side int, path string) error {
	if side == claudeSystemItem {
		if !p.started {
			return nil
		}
		if !anthropicWireSupportsMidConversationSystem(state) {
			return invalidRequest(path + ".role cannot be preserved after the conversation starts on this Anthropic-format deployment")
		}
		if !p.afterUser {
			return invalidRequest(path + ".role must immediately follow a user message or tool result on this Anthropic-format deployment")
		}
		p.pending = path
		return nil
	}
	if p.pending != "" && side != claudeAssistantItem && side != claudeServerResultItem {
		return invalidRequest(p.pending + ".role must be last or immediately precede an assistant turn on this Anthropic-format deployment")
	}
	p.started, p.afterUser, p.pending = true, side == claudeUserItem || side == claudeServerResultItem, ""
	return nil
}

func (a AnthropicAdapter) ValidateRequest(state *State) error {
	if err := a.DefaultAdapter.ValidateRequest(state); err != nil {
		return err
	}
	if err := validateAnthropicOutputTokenLimit(state); err != nil {
		return err
	}
	if err := validateAnthropicTaskBudget(state); err != nil {
		return err
	}
	if err := validateAnthropicContextManagement(state); err != nil {
		return err
	}
	if err := validateAnthropicChatCompletionPolicy(state); err != nil {
		return err
	}
	return validateAnthropicResponsesPolicy(state)
}

func validateAnthropicTaskBudget(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	raw := state.Resolution.RawBody()["task_budget"]
	if !rawJSONValueSet(raw) {
		return nil
	}
	// task_budget is advisory and never changes the hold, so the provider owns
	// which models accept it and its minimum.
	taskBudget, ok := rawObject(raw)
	if !ok {
		return invalidRequest("task_budget must be an object")
	}
	if !onlyRawKeysOptional(taskBudget, "type", "total", "remaining") {
		return invalidRequest("task_budget supports only type, total, and remaining")
	}
	if rawString(taskBudget["type"]) != "tokens" {
		return invalidRequest("task_budget.type must be tokens")
	}
	if _, exists, err := rawInteger(taskBudget["total"], "task_budget.total"); err != nil {
		return err
	} else if !exists {
		return invalidRequest("task_budget.total is required")
	}
	_, _, err := rawInteger(taskBudget["remaining"], "task_budget.remaining")
	return err
}

func validateAnthropicContextManagement(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	raw := state.Resolution.RawBody()["context_management"]
	if !rawJSONValueSet(raw) {
		return nil
	}
	contextManagement, ok := rawObject(raw)
	if !ok || contextManagement == nil {
		return invalidRequest("context_management must be an object")
	}
	if !onlyRawKeysOptional(contextManagement, "edits") {
		return invalidRequest("context_management supports only edits")
	}
	var rawEdits []json.RawMessage
	if err := sonic.Unmarshal(contextManagement["edits"], &rawEdits); err != nil || len(rawEdits) == 0 {
		return invalidRequest("context_management.edits must be a non-empty array")
	}
	seen := make(map[string]struct{}, len(rawEdits))
	for _, rawEdit := range rawEdits {
		edit, ok := rawObject(rawEdit)
		if !ok || edit == nil {
			return invalidRequest("context_management.edits[] must be an object")
		}
		editType := rawString(edit["type"])
		if editType == "" {
			return invalidRequest("context_management.edits[].type is required")
		}
		if _, duplicate := seen[editType]; duplicate {
			return invalidRequest("context_management edit types must be unique")
		}
		seen[editType] = struct{}{}
		switch editType {
		case string(anthropicprovider.ContextManagementEditTypeClearThinking):
			if err := validateAnthropicClearThinkingEdit(edit); err != nil {
				return err
			}
		case string(anthropicprovider.ContextManagementEditTypeClearToolUses):
			if err := validateAnthropicClearToolUsesEdit(edit); err != nil {
				return err
			}
		case string(anthropicprovider.ContextManagementEditTypeCompact):
			if err := validateAnthropicCompactEdit(edit); err != nil {
				return err
			}
		default:
			return invalidRequest("context_management.edits[].type is not supported")
		}
	}
	return nil
}

func validateAnthropicClearThinkingEdit(edit map[string]json.RawMessage) error {
	if !onlyRawKeysOptional(edit, "type", "keep") {
		return invalidRequest("clear_thinking_20251015 supports only type and keep")
	}
	keep, exists := edit["keep"]
	if !exists {
		return nil
	}
	if rawString(keep) == "all" {
		return nil
	}
	object, ok := rawObject(keep)
	if !ok || object == nil {
		return invalidRequest("clear_thinking_20251015.keep must be all or an object")
	}
	switch rawString(object["type"]) {
	case "all":
		if !onlyRawKeysOptional(object, "type") {
			return invalidRequest("clear_thinking_20251015.keep type all supports no other fields")
		}
		return nil
	case "thinking_turns":
		if !onlyRawKeysOptional(object, "type", "value") {
			return invalidRequest("clear_thinking_20251015.keep supports only type and value")
		}
		value, exists, err := rawInteger(object["value"], "clear_thinking_20251015.keep.value")
		if err != nil {
			return err
		}
		if !exists || value < 1 {
			return invalidRequest("clear_thinking_20251015.keep.value must be a positive integer")
		}
		return nil
	default:
		return invalidRequest("clear_thinking_20251015.keep.type must be all or thinking_turns")
	}
}

func validateAnthropicClearToolUsesEdit(edit map[string]json.RawMessage) error {
	if !onlyRawKeysOptional(edit, "type", "clear_at_least", "clear_tool_inputs", "exclude_tools", "keep", "trigger") {
		return invalidRequest("clear_tool_uses_20250919 contains unsupported fields")
	}
	if raw, exists := edit["clear_at_least"]; exists && !rawJSONIsNull(raw) {
		if err := validateAnthropicTypeCount(raw, "clear_tool_uses_20250919.clear_at_least", "input_tokens"); err != nil {
			return err
		}
	}
	if raw, exists := edit["clear_tool_inputs"]; exists && !rawJSONIsNull(raw) {
		var boolean bool
		if err := sonic.Unmarshal(raw, &boolean); err != nil {
			if err := validateAnthropicToolNameArray(raw, "clear_tool_uses_20250919.clear_tool_inputs"); err != nil {
				return invalidRequest("clear_tool_uses_20250919.clear_tool_inputs must be a boolean or an array of tool names")
			}
		}
	}
	if raw, exists := edit["exclude_tools"]; exists && !rawJSONIsNull(raw) {
		if err := validateAnthropicToolNameArray(raw, "clear_tool_uses_20250919.exclude_tools"); err != nil {
			return err
		}
	}
	if raw, exists := edit["keep"]; exists {
		if err := validateAnthropicTypeCount(raw, "clear_tool_uses_20250919.keep", "tool_uses"); err != nil {
			return err
		}
	}
	if raw, exists := edit["trigger"]; exists {
		if err := validateAnthropicTypeCount(raw, "clear_tool_uses_20250919.trigger", "input_tokens", "tool_uses"); err != nil {
			return err
		}
	}
	return nil
}

func validateAnthropicCompactEdit(edit map[string]json.RawMessage) error {
	if !onlyRawKeysOptional(edit, "type", "instructions", "pause_after_compaction", "trigger") {
		return invalidRequest("compact_20260112 contains unsupported fields")
	}
	if raw, exists := edit["instructions"]; exists && !rawJSONIsNull(raw) {
		var value string
		if err := sonic.Unmarshal(raw, &value); err != nil {
			return invalidRequest("compact_20260112.instructions must be a string or null")
		}
	}
	if raw, exists := edit["pause_after_compaction"]; exists {
		if err := validateRawJSONBool(raw, "compact_20260112.pause_after_compaction"); err != nil {
			return err
		}
	}
	if raw, exists := edit["trigger"]; exists && !rawJSONIsNull(raw) {
		if err := validateAnthropicTypeCount(raw, "compact_20260112.trigger", "input_tokens"); err != nil {
			return err
		}
	}
	return nil
}

func validateAnthropicTypeCount(raw json.RawMessage, name string, allowedTypes ...string) error {
	object, ok := rawObject(raw)
	if !ok || object == nil {
		return invalidRequest(name + " must be an object")
	}
	if !onlyRawKeysOptional(object, "type", "value") {
		return invalidRequest(name + " supports only type and value")
	}
	typeValue := rawString(object["type"])
	allowed := false
	for _, candidate := range allowedTypes {
		allowed = allowed || typeValue == candidate
	}
	if !allowed {
		return invalidRequest(name + ".type is not supported")
	}
	value, exists, err := rawInteger(object["value"], name+".value")
	if err != nil {
		return err
	}
	if !exists || value < 0 {
		return invalidRequest(name + ".value must be a non-negative integer")
	}
	return nil
}

func validateAnthropicToolNameArray(raw json.RawMessage, name string) error {
	var names []string
	if err := sonic.Unmarshal(raw, &names); err != nil || names == nil {
		return invalidRequest(name + " must be an array of tool names")
	}
	seen := make(map[string]struct{}, len(names))
	for _, value := range names {
		nameValue := strings.TrimSpace(value)
		if nameValue == "" || strings.ContainsAny(nameValue, "\x00\r\n") {
			return invalidRequest(name + " must contain non-empty tool names")
		}
		if _, duplicate := seen[nameValue]; duplicate {
			return invalidRequest(name + " must not contain duplicate tool names")
		}
		seen[nameValue] = struct{}{}
	}
	return nil
}

func rawJSONIsNull(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

func validateAnthropicOutputTokenLimit(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.OutputTokenLimit() != 0 {
		return nil
	}
	// A request without output only fills the cache, so it needs marks of its own or the gateway's.
	if anthropicRawRequestContainsCacheControl(state.Resolution.Route, state.Resolution.RawBody()) || gatewayPromptCache(state) != "" {
		return nil
	}
	return catalog.ErrOutputLimitTooSmall
}

func validateAnthropicChatCompletionPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteChat {
		return nil
	}
	raw := state.Resolution.RawBody()
	if err := validateAnthropicSamplingIntent(state, raw); err != nil {
		return err
	}
	if format, ok := rawObject(raw["response_format"]); ok && rawJSONValueSet(raw["response_format"]) && rawString(format["type"]) != "json_schema" {
		return invalidRequest("response_format.type must be json_schema for Anthropic-format deployments")
	}
	if rawJSONValueSet(raw["prompt_cache_retention"]) {
		return invalidRequest("prompt_cache_retention is not supported for Anthropic-format deployments")
	}
	if err := rejectAnthropicUnsupportedParameters(raw,
		"frequency_penalty",
		"logit_bias",
		"logprobs",
		"prediction",
		"presence_penalty",
		"prompt_cache_options",
		"repetition_penalty",
		"seed",
		"top_logprobs",
		"verbosity",
		"web_search_options",
	); err != nil {
		return err
	}
	if count, err := validatePromptCacheBreakpoints(raw["messages"]); err != nil {
		return err
	} else if count > 0 {
		return invalidRequest("prompt_cache_breakpoint is not supported for Anthropic-format deployments")
	}
	if err := validateAnthropicChatCacheControls(raw); err != nil {
		return err
	}
	for _, rawTool := range state.Resolution.RawTools() {
		if rawString(rawTool["type"]) == "mcp_toolset" {
			return invalidRequest("Anthropic MCP connectors are not supported because provider execution cannot be bounded per request")
		}
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

func validateAnthropicResponsesPolicy(state *State) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteResponses {
		return nil
	}
	raw := state.Resolution.RawBody()
	if streamOptions, ok := rawObject(raw["stream_options"]); ok && rawBool(streamOptions["include_obfuscation"]) {
		return invalidRequest("stream_options.include_obfuscation cannot be preserved on Anthropic-format deployments")
	}
	if err := validateAnthropicSamplingIntent(state, raw); err != nil {
		return err
	}
	if reasoning, ok := rawObject(raw["reasoning"]); ok {
		// OpenAI's summaries become Claude's summarized thinking, none omits it, and updates asks
		// for Claude's progress updates without reasoning summaries.
		switch value, _ := rawStringValue(reasoning["summary"]); value {
		case "", "auto", "concise", "detailed", "none", anthropicprovider.AnthropicThinkingDisplayUpdates:
		default:
			return invalidRequest("reasoning.summary must be auto, concise, detailed, none or updates for Anthropic-format deployments")
		}
		// Claude has no such setting: context_management's clear_thinking edit chooses which
		// earlier thinking it reads.
		if value, exists := rawStringValue(reasoning["context"]); exists && value != "auto" {
			return invalidRequest("reasoning.context must be auto for Anthropic-format deployments")
		}
	}
	if rawJSONValueSet(raw["prompt_cache_retention"]) {
		return invalidRequest("prompt_cache_retention is not supported for Anthropic-format deployments")
	}
	if err := rejectAnthropicUnsupportedParameters(raw,
		"frequency_penalty",
		"presence_penalty",
		"prompt_cache_options",
		"top_logprobs",
	); err != nil {
		return err
	}
	// Each Claude block comes back whole in a reasoning item's encrypted content.
	if err := validateResponsesInclude(raw["include"], "reasoning.encrypted_content"); err != nil {
		return err
	}
	if count, err := validatePromptCacheBreakpoints(raw["input"]); err != nil {
		return err
	} else if count > 0 {
		return invalidRequest("prompt_cache_breakpoint is not supported for Anthropic-format deployments")
	}
	if err := validateAnthropicResponsesCacheControls(raw); err != nil {
		return err
	}
	return validateResponsesToolPolicy(state, raw, func(tools []schemas.ResponsesTool) error {
		if responsesHasHostedTool(tools) {
			return validateAnthropicResponsesHostedToolCaps(state, raw, tools)
		}
		if _, ok := raw["max_tool_calls"]; ok {
			return invalidRequest("max_tool_calls is only supported for Anthropic hosted tools")
		}
		return nil
	})
}

func rejectAnthropicUnsupportedParameters(raw map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		if rawJSONValueSet(raw[name]) {
			return invalidRequest(name + " is not supported for Anthropic-format deployments")
		}
	}
	return nil
}

func validateAnthropicSamplingIntent(state *State, raw map[string]json.RawMessage) error {
	if rawJSONValueSet(raw["stop"]) && rawJSONValueSet(raw["stop_sequences"]) {
		return invalidRequest("stop conflicts with stop_sequences")
	}
	return validateStopSequenceArray(raw["stop_sequences"], "stop_sequences", maxPortableStopSequences)
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
			return invalidRequest("messages[].cache_control is not supported")
		}
		for _, block := range rawChatMessageContentBlocks(message) {
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
		// Input validation owns which blocks may carry cache_control.
		if cacheControl, ok := object["cache_control"]; ok {
			if err := validateAnthropicCacheControl(cacheControl, path+".cache_control"); err != nil {
				return err
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
	if !onlyRawKeysOptional(cacheControl, "type", "ttl") {
		return invalidRequest(name + " supports only type and ttl")
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
	effectiveTypes := catalog.EffectiveResponsesToolTypes(raw, state.Resolution.ToolTypes())
	hostedToolCount := 0
	for _, rawTool := range state.Resolution.RawTools() {
		rawType := rawString(rawTool["type"])
		if !anthropicResponsesWebSearchToolType(rawType) && !anthropicResponsesWebFetchToolType(rawType) {
			continue
		}
		if anthropicResponsesWebSearchToolType(rawType) && usesToolType(effectiveTypes, "web_search") ||
			anthropicResponsesWebFetchToolType(rawType) && usesToolType(effectiveTypes, "web_fetch") {
			hostedToolCount++
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
	if hostedToolCount > 1 {
		return invalidRequest("Anthropic Responses supports one hosted tool per request because the provider has no global tool-call cap")
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
	if state.Resolution.Deployment.Upstream.ServiceTier == catalog.TierFast {
		state.Resolution.SetSpeed("fast")
	} else {
		state.Resolution.SetSpeed("standard")
	}
	switch state.Resolution.Deployment.Upstream.InferenceGeo {
	case "us":
		state.Resolution.SetExtraParam("inference_geo", "us")
	case "global":
		state.Resolution.SetExtraParam("inference_geo", "global")
	}
	applyAnthropicResponsesToolCap(state)
	return nil
}

func (a AnthropicAdapter) EstimateHold(state *State) error {
	if err := a.DefaultAdapter.EstimateHold(state); err != nil {
		return err
	}
	return estimateAnthropicWireHold(state)
}

func estimateAnthropicWireHold(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	req := anthropicAdapterContextForState(state)
	inputTokens, outputTokens, err := anthropicTokenHoldQuantities(req)
	if err != nil {
		return err
	}
	tokenFreeMeters := make([]catalog.MeterEstimate, 0, len(state.Hold.Meters))
	for _, meter := range state.Hold.Meters {
		if !isInputTokenMeter(meter.MeterKey) && !isOutputTokenMeter(meter.MeterKey) {
			tokenFreeMeters = append(tokenFreeMeters, meter)
		}
	}
	pricing := effectivePricingForState(state)
	state.Hold.Meters = appendOutputTokenHoldCost(tokenFreeMeters, pricing, outputTokens)
	state.Hold.Meters = append(state.Hold.Meters, anthropicHoldMeters(req, inputTokens)...)
	meters, total, err := canonicalizeHoldMeters(state.Hold.Meters, pricing)
	if err != nil {
		return err
	}
	state.Hold.Meters = meters
	state.Hold.EstimatedUpstreamCostUSD = total
	state.Hold.ReservedTokens = int64(inputTokens) + int64(outputTokens)
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

func (AnthropicAdapter) CalculateUpstreamCost(state *State) error {
	if state == nil {
		return nil
	}
	if anthropicRefusalUnbilled(state) {
		settleUnbilledRefusal(state)
		return nil
	}
	upstreamCostUSD, err := calculateBaseUpstreamCost(state, anthropicFinalMeters(anthropicAdapterContextForState(state)))
	if err != nil {
		return err
	}
	state.UpstreamCostUSD = upstreamCostUSD
	return nil
}

// anthropicBilledRefusalCategories lists the refusal categories that Anthropic
// bills even when the refusal arrives before any output. Usage reported on any
// other refusal before output, including one without a category, is
// informational. The rule covers every platform that serves Claude, Azure included.
var anthropicBilledRefusalCategories = map[string]bool{
	"bio":                  true,
	"frontier_llm":         true,
	"reasoning_extraction": true,
}

// anthropicRefusalUnbilled keeps the provider billing rule separate from public
// delivery telemetry: a disconnected caller can miss output that Anthropic
// still generated and billed.
func anthropicRefusalUnbilled(state *State) bool {
	details, refused := anthropicRefusal(state.Response)
	if !refused || state.providerOutputEmitted {
		return false
	}
	return details == nil || details.Category == nil || !anthropicBilledRefusalCategories[*details.Category]
}

func settleUnbilledRefusal(state *State) {
	state.FinalMeters = nil
	state.UpstreamCostUSD = billing.ZeroChargeUSD
}

func anthropicRefusal(response *schemas.BifrostResponse) (*schemas.ResponsesStopDetails, bool) {
	if response == nil {
		return nil, false
	}
	if chat := response.ChatResponse; chat != nil {
		// Chat Completions reports a refusal as content_filter, Claude's only such stop.
		for _, choice := range chat.Choices {
			if choice.FinishReason != nil && *choice.FinishReason == "content_filter" {
				return chat.StopDetails, true
			}
		}
		return nil, false
	}
	result := response.ResponsesResponse
	if result == nil && response.ResponsesStreamResponse != nil {
		result = response.ResponsesStreamResponse.Response
	}
	if result == nil || result.StopReason == nil || *result.StopReason != "refusal" {
		return nil, false
	}
	return result.StopDetails, true
}

func (AnthropicAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	rawType := rawString(tool["type"])
	if rawType == "mcp" {
		return invalidRequest("Remote MCP tools are not supported because provider execution cannot be bounded or approved per request")
	}
	if rawType == "custom" {
		return invalidRequest("Custom tools are not supported for Anthropic-format deployments because free-form input formats are not preserved by the provider translation")
	}
	if anthropicResponsesToolTypeSupported(rawType) {
		if err := hostedToolOffered(state, rawType); err != nil {
			return err
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
		return nil
	}
	if strings.HasPrefix(rawType, "web_search_") || strings.HasPrefix(rawType, "web_fetch_") {
		return invalidRequest("Claude runs " + anthropicWebSearchVersion + " and " + anthropicWebFetchVersion + "; name one of them, web_search or web_fetch")
	}
	if strings.HasPrefix(rawType, "bash_") || strings.HasPrefix(rawType, "text_editor_") {
		return invalidRequest("Claude takes " + catalog.AnthropicBashToolType + " and " + catalog.AnthropicTextEditorToolType + "; name one of them")
	}
	if strings.HasPrefix(rawType, "computer") {
		return invalidRequest("computer tools are not supported because tool results carry only text")
	}
	if strings.HasPrefix(rawType, "memory") {
		return invalidRequest("memory tools are not supported because the instructions that Anthropic adds for them are not measured")
	}
	return invalidRequest("Only function, namespace, " + catalog.AnthropicBashToolType + ", " + catalog.AnthropicTextEditorToolType + ", web_fetch, and priced hosted web search tools are supported")
}

// Messages has no cap across tools, so a max_tool_calls that the client set becomes each hosted
// tool's max_uses. A request without one sends none.
func applyAnthropicResponsesToolCap(state *State) {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteResponses {
		return
	}
	cap, supplied := responsesExplicitMaxToolCalls(state)
	if !supplied || !responsesHostedToolChoiceAllowsCalls(state.Resolution.RawBody()) {
		return
	}
	toolTypes := catalog.EffectiveResponsesToolTypes(state.Resolution.RawBody(), state.Resolution.ToolTypes())
	if usesToolType(toolTypes, string(schemas.ResponsesToolTypeWebSearch)) {
		state.Resolution.SetResponsesToolMaxUses(cap, schemas.ResponsesToolTypeWebSearch)
	}
	if usesToolType(toolTypes, string(schemas.ResponsesToolTypeWebFetch)) {
		state.Resolution.SetResponsesToolMaxUses(cap, schemas.ResponsesToolTypeWebFetch)
	}
}

func anthropicAdapterContextForState(state *State) anthropicAdapterContext {
	return anthropicAdapterContextForDeployment(state, ExecutionDeployment(state))
}

func anthropicAdapterContextForDeployment(state *State, deployment catalog.Deployment) anthropicAdapterContext {
	if state == nil || state.Resolution == nil {
		return anthropicAdapterContext{}
	}
	pricing := clonePricing(deployment.Pricing)
	return anthropicAdapterContext{
		Route:                 anthropicAdapterRoute(state.Resolution.Route),
		Deployment:            anthropicAdapterDeployment{Model: deployment.Upstream.Model, MaxInputTokens: deployment.MaxInputTokens, MaxOutputTokens: deployment.MaxOutputTokens, Pricing: pricing},
		InputTokenLimit:       state.Resolution.InputTokenLimit(),
		OutputTokenLimit:      state.Resolution.OutputTokenLimit(),
		ToolChoiceAllowsCalls: responsesHostedToolChoiceAllowsCalls(state.Resolution.RawBody()),
		ToolTypes:             catalog.EffectiveResponsesToolTypes(state.Resolution.RawBody(), state.Resolution.ToolTypes()),
		RawBody:               state.Resolution.RawBody(),
		RawTools:              state.Resolution.RawTools(),
		ActualWebSearchCalls:  actualWebSearchCalls(state),
		PromptCache:           gatewayPromptCache(state),
	}
}

// A synchronous server-tool request runs at most ten sampling passes, and the
// hold covers one after each hosted call that it covers. Attempts after
// max_uses, which return errors, and longer loops settle above the hold.
func anthropicSamplingIterationLimit(req anthropicAdapterContext) int {
	if req.Route == anthropicAdapterRouteResponses && req.ToolChoiceAllowsCalls &&
		(usesToolType(req.ToolTypes, "web_search") || usesToolType(req.ToolTypes, "web_fetch")) {
		return 1 + min(9, anthropicHostedCallsHeld(req, anthropicResponsesHostedToolType))
	}
	return 1
}

func anthropicTokenHoldQuantities(req anthropicAdapterContext) (int, int, error) {
	if req.Deployment.MaxInputTokens <= 0 || req.InputTokenLimit < 0 || req.OutputTokenLimit < 0 {
		return 0, 0, catalog.ErrParameterTooLarge
	}
	passes := anthropicPassInputs(req)
	input := 0
	for _, read := range passes {
		if read > math.MaxInt-input {
			return 0, 0, catalog.ErrParameterTooLarge
		}
		input += read
	}
	output := req.OutputTokenLimit
	// Compaction starts when a pass reads its trigger, and the last pass reads the
	// most. Compaction reads that pass's input once more and writes a summary,
	// which usage reports apart from the output and which only the model's output
	// limit bounds.
	if trigger, ok := anthropicCompactionTrigger(req.RawBody["context_management"]); ok {
		if context := passes[len(passes)-1]; context >= trigger {
			if req.Deployment.MaxOutputTokens <= 0 || context > math.MaxInt-input ||
				req.Deployment.MaxOutputTokens > math.MaxInt-output {
				return 0, 0, catalog.ErrParameterTooLarge
			}
			input += context
			output += req.Deployment.MaxOutputTokens
		}
	}
	if input > math.MaxInt-output {
		return 0, 0, catalog.ErrParameterTooLarge
	}
	return input, output, nil
}

// anthropicPassInputs returns the input that each sampling pass reads: the first
// pass's input and the content of every hosted call before it, within the input
// limit. Anthropic bills each pass's input, so later passes read earlier results
// again. Text that the model writes between calls is short and settles.
func anthropicPassInputs(req anthropicAdapterContext) []int {
	limit := req.Deployment.MaxInputTokens
	first := min(limit, req.InputTokenLimit)
	first += min(limit-first, anthropicToolSystemPromptHoldTokens(req.Deployment.Model, req.ToolTypes))
	content := anthropicHostedContentHoldTokens(req)
	passes := make([]int, anthropicSamplingIterationLimit(req))
	for calls := range passes {
		passes[calls] = limit
		if content == 0 || calls <= (limit-first)/content {
			passes[calls] = first + calls*content
		}
	}
	return passes
}

func anthropicHoldMeters(req anthropicAdapterContext, inputTokens int) []billing.MeterEstimate {
	cacheWriteMeter := anthropicCacheWriteHoldMeter(req)
	inputMeter := highestInputHoldMeter(req.Deployment.Pricing, cacheWriteMeter)
	cacheReads := 0
	_, _, hasCacheReadRate := billing.PricingRate(req.Deployment.Pricing, billing.MeterCachedInputTokens, billing.TokenRateHighest)
	if cacheWriteMeter != "" && anthropicSamplingIterationLimit(req) > 1 {
		// Server-tool breakpoints always write with the five-minute TTL.
		inputMeter = highestInputHoldMeter(req.Deployment.Pricing, cacheWriteMeter, billing.MeterCacheWrite5mInputTokens)
	}
	if cacheWriteMeter != "" && anthropicSamplingIterationLimit(req) > 1 && hasCacheReadRate &&
		!rawJSONValueSet(req.RawBody["context_management"]) {
		// With caching, each pass reads the previous pass's input from the cache
		// and writes what is new, so the last pass's input is written once and the
		// rest is read. Expiry or a miss can settle above the hold. Context editing
		// changes the prefix, so it keeps the whole input at the write rate.
		passes := anthropicPassInputs(req)
		cacheReads = max(0, inputTokens-passes[len(passes)-1])
	}
	meters := billing.AppendTokenMeterCost(nil, req.Deployment.Pricing, inputMeter, inputTokens-cacheReads, true, billing.TokenRateHighest)
	meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, billing.MeterCachedInputTokens, cacheReads, true, billing.TokenRateHighest)
	if req.Route == anthropicAdapterRouteResponses && req.ToolChoiceAllowsCalls && usesToolType(req.ToolTypes, "web_search") {
		meters = billing.AppendCallMeterCost(meters, req.Deployment.Pricing, meterAnthropicWebSearchCalls, anthropicHostedToolHoldQuantity(req), true)
	}
	return meters
}

func anthropicContextManagementUsesCompaction(raw json.RawMessage) bool {
	_, ok := anthropicCompactionTrigger(raw)
	return ok
}

// anthropicCompactionTrigger returns the input at which the request's compaction
// starts: its trigger, or Anthropic's default of 150,000 tokens.
func anthropicCompactionTrigger(raw json.RawMessage) (int, bool) {
	contextManagement, ok := rawObject(raw)
	if !ok {
		return 0, false
	}
	var edits []map[string]json.RawMessage
	if err := sonic.Unmarshal(contextManagement["edits"], &edits); err != nil {
		return 0, false
	}
	for _, edit := range edits {
		if rawString(edit["type"]) != string(anthropicprovider.ContextManagementEditTypeCompact) {
			continue
		}
		if trigger, ok := rawObject(edit["trigger"]); ok {
			if value, ok := rawIntegerValue(trigger["value"]); ok {
				return value, true
			}
		}
		return 150000, true
	}
	return 0, false
}

// anthropicHostedContentHoldTokens is the content that one hosted call adds: a
// fetch limited by max_content_tokens adds at most that, and any other call the
// typical amount.
func anthropicHostedContentHoldTokens(req anthropicAdapterContext) int {
	if req.Route != anthropicAdapterRouteResponses || !req.ToolChoiceAllowsCalls {
		return 0
	}
	content := 0
	if usesToolType(req.ToolTypes, "web_search") {
		content = hostedCallContentTokens
	}
	if !usesToolType(req.ToolTypes, "web_fetch") {
		return content
	}
	for _, tool := range req.RawTools {
		if !anthropicResponsesWebFetchToolType(strings.TrimSpace(rawString(tool["type"]))) {
			continue
		}
		perUse, ok := rawIntegerValue(tool["max_content_tokens"])
		if !ok || perUse < 1 {
			perUse = hostedCallContentTokens
		}
		content = max(content, perUse)
	}
	return content
}

func anthropicCacheWriteHoldMeter(req anthropicAdapterContext) string {
	if req.PromptCache != "" {
		return promptCacheWriteMeter(req.PromptCache)
	}
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
		return rawChatCacheControlExists(rawData["messages"], false)
	case catalog.RouteResponses:
		return rawResponsesCacheControlExists(rawData["input"])
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
		for _, block := range rawChatMessageContentBlocks(message) {
			if anthropicCacheControlTTLIs1h(block["cache_control"]) {
				return true
			}
		}
	}
	return false
}

func anthropicResponsesInputCacheControlIs1h(raw json.RawMessage) bool {
	return rawResponsesCacheControlMatches(raw, anthropicCacheControlTTLIs1h)
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
	return billing.AppendCallMeterCost(nil, req.Deployment.Pricing, meterAnthropicWebSearchCalls, req.ActualWebSearchCalls, false)
}

// Claude runs web search and web fetch at these versions, and the unversioned names get them.
// Later versions filter results with code execution, which is closed, so a request that names
// one is refused: a request never runs another version than the one it names.
const (
	anthropicWebSearchVersion = string(anthropicprovider.AnthropicToolTypeWebSearch20250305)
	anthropicWebFetchVersion  = string(anthropicprovider.AnthropicToolTypeWebFetch20250910)
)

func anthropicResponsesToolTypeSupported(rawType string) bool {
	rawType = strings.TrimSpace(rawType)
	switch rawType {
	case "function", "namespace", catalog.AnthropicBashToolType, catalog.AnthropicTextEditorToolType:
		return true
	default:
		return anthropicResponsesWebSearchToolType(rawType) || anthropicResponsesWebFetchToolType(rawType)
	}
}

func anthropicResponsesWebSearchToolType(rawType string) bool {
	switch strings.TrimSpace(rawType) {
	case "web_search", anthropicWebSearchVersion:
		return true
	default:
		return false
	}
}

func anthropicResponsesWebFetchToolType(rawType string) bool {
	switch strings.TrimSpace(rawType) {
	case "web_fetch", anthropicWebFetchVersion:
		return true
	default:
		return false
	}
}

func anthropicHostedToolHoldQuantity(req anthropicAdapterContext) int {
	return anthropicHostedCallsHeld(req, func(rawType string) bool { return strings.HasPrefix(rawType, "web_search") })
}

// anthropicHostedCallsHeld is the number of calls that the hold covers for the
// hosted tools that match: the largest cap among them, or ten for one without.
func anthropicHostedCallsHeld(req anthropicAdapterContext, hosted func(rawType string) bool) int {
	topLevelQuantity := anthropicResponsesTopLevelMaxToolCallsOrDefaultRaw(req.RawBody)
	quantity := 0
	for _, tool := range req.RawTools {
		if !hosted(strings.TrimSpace(rawString(tool["type"]))) {
			continue
		}
		value, ok := rawIntegerValue(tool["max_uses"])
		if !ok || value < 1 {
			value = topLevelQuantity
		}
		quantity = max(quantity, value)
	}
	if quantity < 1 {
		return topLevelQuantity
	}
	return quantity
}

func anthropicResponsesHostedToolType(rawType string) bool {
	return strings.HasPrefix(rawType, "web_search") || anthropicResponsesWebFetchToolType(rawType)
}

func anthropicToolSystemPromptHoldTokens(model string, toolTypes []string) int {
	if len(toolTypes) == 0 {
		return 0
	}
	if tokens, known := anthropicToolSystemPromptTokensForModel(model); known {
		return tokens
	}
	return maxAnthropicToolSystemPromptTokens
}

func anthropicToolSystemPromptTokensForModel(model string) (int, bool) {
	normalized := strings.ToLower(strings.TrimSpace(model))
	// Bedrock names Claude as an inference profile, such as global.anthropic.claude-fable-5-1.
	if _, name, profile := strings.Cut(normalized, "anthropic."); profile {
		normalized = name
	}
	normalized = strings.ReplaceAll(normalized, ".", "-")
	switch {
	case strings.HasPrefix(normalized, "claude-opus-5-5"):
		return 286, true
	case strings.HasPrefix(normalized, "claude-opus-5"):
		return 406, true
	case strings.HasPrefix(normalized, "claude-opus-4-8"):
		return 410, true
	case strings.HasPrefix(normalized, "claude-opus-4-7"):
		return 804, true
	case strings.HasPrefix(normalized, "claude-opus-4-6"):
		return 589, true
	case strings.HasPrefix(normalized, "claude-opus-4-5"):
		return 588, true
	case strings.HasPrefix(normalized, "claude-opus-4-1"):
		return 315, true
	case strings.HasPrefix(normalized, "claude-sonnet-5-5"):
		return 286, true
	case strings.HasPrefix(normalized, "claude-sonnet-5"):
		return 474, true
	case strings.HasPrefix(normalized, "claude-sonnet-4-6"):
		return 589, true
	case strings.HasPrefix(normalized, "claude-sonnet-4-5"):
		return 588, true
	case strings.HasPrefix(normalized, "claude-haiku-5-5"):
		return 406, true
	case strings.HasPrefix(normalized, "claude-haiku-4-5"):
		return 588, true
	case strings.HasPrefix(normalized, "claude-haiku-3-5"):
		return 355, true
	case strings.HasPrefix(normalized, "claude-fable-5"),
		strings.HasPrefix(normalized, "claude-mythos-5"),
		strings.HasPrefix(normalized, "claude-mythos-preview"):
		return maxAnthropicToolSystemPromptTokens, true
	default:
		return 0, false
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
