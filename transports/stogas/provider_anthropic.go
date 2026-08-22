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
	SamplingIterations    int
}

func anthropicWireSupportsMidConversationSystem(state *State) bool {
	return state != nil && state.Resolution != nil &&
		anthropicprovider.SupportsMidConversationSystem(
			state.Resolution.Provider,
			state.Resolution.Deployment.Upstream.Model,
		)
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
	model := state.Resolution.Deployment.Upstream.Model
	if !anthropicprovider.IsOpus47Plus(model) && !anthropicprovider.IsFableFamily(model) {
		return invalidRequest("task_budget is not supported for this Anthropic model")
	}
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
	total, exists, err := rawInteger(taskBudget["total"], "task_budget.total")
	if err != nil {
		return err
	}
	if !exists {
		return invalidRequest("task_budget.total is required")
	}
	if total < 20_000 {
		return invalidRequest("task_budget.total is below the provider minimum")
	}
	remaining, exists, err := rawInteger(taskBudget["remaining"], "task_budget.remaining")
	if err != nil {
		return err
	}
	if exists && (remaining < 0 || remaining > total) {
		return invalidRequest("task_budget.remaining must be between zero and task_budget.total")
	}
	return nil
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
	for index, rawEdit := range rawEdits {
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
			if !anthropicModelSupportsCompaction(state.Resolution.Deployment.Upstream.Model) {
				return invalidRequest("compact_20260112 is not supported for this Anthropic model")
			}
			if err := validateAnthropicCompactEdit(edit); err != nil {
				return err
			}
		default:
			return invalidRequest("context_management.edits[].type is not supported")
		}
		if index > 0 && editType == string(anthropicprovider.ContextManagementEditTypeClearThinking) {
			return invalidRequest("clear_thinking_20251015 must be the first context management edit")
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
		if err := validateAnthropicTypeCount(raw, "clear_tool_uses_20250919.clear_at_least", 0, "input_tokens"); err != nil {
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
		if err := validateAnthropicTypeCount(raw, "clear_tool_uses_20250919.keep", 0, "tool_uses"); err != nil {
			return err
		}
	}
	if raw, exists := edit["trigger"]; exists {
		if err := validateAnthropicTypeCount(raw, "clear_tool_uses_20250919.trigger", 0, "input_tokens", "tool_uses"); err != nil {
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
		if err := validateAnthropicTypeCount(raw, "compact_20260112.trigger", 50_000, "input_tokens"); err != nil {
			return err
		}
	}
	return nil
}

func validateAnthropicTypeCount(raw json.RawMessage, name string, minimum int, allowedTypes ...string) error {
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
	if !exists || value < minimum {
		return invalidRequest(name + ".value is below the provider minimum")
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

func anthropicModelSupportsCompaction(model string) bool {
	normalized := strings.ToLower(strings.TrimSpace(model))
	for _, prefix := range []string{
		"claude-fable-5",
		"claude-mythos-5",
		"claude-mythos-preview",
		"claude-opus-4-6",
		"claude-opus-4-7",
		"claude-opus-4-8",
		"claude-opus-5",
		"claude-sonnet-4-6",
		"claude-sonnet-5",
	} {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}

func rawJSONIsNull(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
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
	if err := validateAnthropicSamplingIntent(state, raw); err != nil {
		return err
	}
	if format, ok := rawObject(raw["response_format"]); ok && rawJSONValueSet(raw["response_format"]) && rawString(format["type"]) != "json_schema" {
		return invalidRequest("response_format.type must be json_schema for Anthropic-format deployments")
	}
	if rawJSONValueSet(raw["prompt_cache_key"]) {
		return invalidRequest("prompt_cache_key is not supported for Anthropic-format deployments")
	}
	if rawJSONValueSet(raw["prompt_cache_retention"]) {
		return invalidRequest("prompt_cache_retention is not supported for Anthropic-format deployments")
	}
	if err := rejectOpenAIOnlyParameters(raw,
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
	if count, err := validatePromptCacheBreakpoints(raw["messages"], catalog.RouteChat); err != nil {
		return err
	} else if count > 0 {
		return invalidRequest("prompt_cache_breakpoint is only supported for OpenAI deployments")
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
	if streamOptions, ok := rawObject(raw["stream_options"]); ok && rawJSONValueSet(streamOptions["include_obfuscation"]) {
		return invalidRequest("stream_options.include_obfuscation cannot be preserved on Anthropic-format deployments")
	}
	if err := validateAnthropicParallelToolCalls(raw); err != nil {
		return err
	}
	if err := validateAnthropicSamplingIntent(state, raw); err != nil {
		return err
	}
	if reasoning, ok := rawObject(raw["reasoning"]); ok {
		for _, name := range []string{"summary", "generate_summary"} {
			if value, exists := rawStringValue(reasoning[name]); exists && value != "auto" {
				return invalidRequest("reasoning." + name + " must be auto for Anthropic-format deployments")
			}
		}
	}
	if rawJSONValueSet(raw["prompt_cache_key"]) {
		return invalidRequest("prompt_cache_key is not supported for Anthropic-format deployments")
	}
	if rawJSONValueSet(raw["prompt_cache_retention"]) {
		return invalidRequest("prompt_cache_retention is not supported for Anthropic-format deployments")
	}
	if err := rejectOpenAIOnlyParameters(raw,
		"frequency_penalty",
		"include",
		"presence_penalty",
		"prompt_cache_options",
		"top_logprobs",
	); err != nil {
		return err
	}
	if count, err := validatePromptCacheBreakpoints(raw["input"], catalog.RouteResponses); err != nil {
		return err
	} else if count > 0 {
		return invalidRequest("prompt_cache_breakpoint is only supported for OpenAI deployments")
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
			return invalidRequest("messages[].cache_control is not supported by Stogas API")
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
	effectiveTypes := effectiveResponsesToolTypes(raw, state.Resolution.ToolTypes())
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
	if strings.EqualFold(strings.TrimSpace(state.Resolution.Deployment.Upstream.Speed), "fast") {
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
	ensureAnthropicResponsesHostedToolCap(state)
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
	req.SamplingIterations = anthropicSamplingIterationLimit(req)
	if req.SamplingIterations < 1 {
		return catalog.ErrParameterTooLarge
	}
	scaledOutputTokens, ok := multiplyAnthropicTokenLimit(req.OutputTokenLimit, req.SamplingIterations)
	if !ok {
		return catalog.ErrParameterTooLarge
	}
	tokenFreeMeters := make([]catalog.MeterEstimate, 0, len(state.Hold.Meters))
	for _, meter := range state.Hold.Meters {
		if !isInputTokenMeter(meter.MeterKey) && !isOutputTokenMeter(meter.MeterKey) {
			tokenFreeMeters = append(tokenFreeMeters, meter)
		}
	}
	pricing := effectivePricingForState(state)
	state.Hold.Meters = appendOutputTokenHoldCost(tokenFreeMeters, pricing, scaledOutputTokens)
	state.Hold.Meters = append(state.Hold.Meters, anthropicHoldMeters(req)...)
	meters, total, err := canonicalizeMeters(state.Hold.Meters, pricing)
	if err != nil {
		return err
	}
	state.Hold.Meters = meters
	state.Hold.MaxUSDAtoms = total
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
	price, err := baseFinalPrice(state, anthropicFinalMeters(anthropicAdapterContextForFinalPrice(state)))
	if err != nil {
		return err
	}
	state.FinalCostUSDAtoms = price
	return nil
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
	return invalidRequest("Only function, web_fetch, and priced hosted web search tools are supported")
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
	req.ActualWebSearchCalls = actualWebSearchCalls(state)
	return req
}

func anthropicAdapterContextForDeployment(state *State, deployment catalog.Deployment) anthropicAdapterContext {
	if state == nil || state.Resolution == nil {
		return anthropicAdapterContext{}
	}
	pricing := clonePricing(deployment.Pricing)
	return anthropicAdapterContext{
		Route:                 anthropicAdapterRoute(state.Resolution.Route),
		Deployment:            anthropicAdapterDeployment{Model: deployment.Upstream.Model, ContextWindowTokens: deployment.ContextWindowTokens, Pricing: pricing},
		InputTokenLimit:       state.Resolution.InputTokenLimit(),
		OutputTokenLimit:      state.Resolution.OutputTokenLimit(),
		ToolChoiceAllowsCalls: responsesHostedToolChoiceAllowsCalls(state.Resolution.RawBody()),
		ToolTypes:             effectiveResponsesToolTypes(state.Resolution.RawBody(), state.Resolution.ToolTypes()),
		RawBody:               state.Resolution.RawBody(),
		RawTools:              state.Resolution.RawTools(),
		ActualWebSearchCalls:  actualWebSearchCalls(state),
	}
}

func anthropicHoldMeters(req anthropicAdapterContext) []billing.MeterEstimate {
	meters := []billing.MeterEstimate{}
	cacheWriteMeter := anthropicCacheWriteHoldMeter(req)
	inputMeter := highestInputHoldMeter(req.Deployment.Pricing, cacheWriteMeter)
	iterations := req.SamplingIterations
	if iterations < 1 {
		iterations = 1
	}
	if quantity, ok := multiplyAnthropicTokenLimit(req.InputTokenLimit, iterations); ok && quantity > 0 {
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, inputMeter, quantity, true, billing.TokenRateHighest)
	}
	if overhead := anthropicToolSystemPromptHoldTokens(req.Deployment.Model, req.ToolTypes); overhead > 0 {
		if quantity, ok := multiplyAnthropicTokenLimit(overhead, iterations); ok {
			meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, inputMeter, quantity, true, billing.TokenRateHighest)
		}
	}
	if req.Route == anthropicAdapterRouteResponses && req.ToolChoiceAllowsCalls && usesToolType(req.ToolTypes, "web_search") {
		meters = billing.AppendCallMeterCost(meters, req.Deployment.Pricing, meterAnthropicWebSearchCalls, anthropicHostedToolHoldQuantity(req), true)
	}
	if hostedContentTokens := anthropicHostedContentHoldTokens(req); hostedContentTokens > 0 {
		if quantity, ok := multiplyAnthropicTokenLimit(hostedContentTokens, iterations); ok {
			meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, inputMeter, quantity, true, billing.TokenRateHighest)
		}
	}
	return meters
}

func anthropicSamplingIterationLimit(req anthropicAdapterContext) int {
	iterations := 1
	if req.Route == anthropicAdapterRouteResponses && req.ToolChoiceAllowsCalls {
		for _, tool := range req.RawTools {
			rawType := strings.TrimSpace(rawString(tool["type"]))
			if !anthropicResponsesWebSearchToolType(rawType) && !anthropicResponsesWebFetchToolType(rawType) {
				continue
			}
			if anthropicResponsesWebSearchToolType(rawType) && !usesToolType(req.ToolTypes, "web_search") ||
				anthropicResponsesWebFetchToolType(rawType) && !usesToolType(req.ToolTypes, "web_fetch") {
				continue
			}
			uses, ok := rawIntegerValue(tool["max_uses"])
			if !ok || uses < 1 {
				uses = anthropicResponsesTopLevelMaxToolCallsOrDefaultRaw(req.RawBody)
			}
			if uses > math.MaxInt-iterations {
				return 0
			}
			iterations += uses
		}
	}
	if anthropicContextManagementUsesCompaction(req.RawBody["context_management"]) {
		if iterations > math.MaxInt/2 {
			return 0
		}
		iterations *= 2
	}
	return iterations
}

func anthropicContextManagementUsesCompaction(raw json.RawMessage) bool {
	contextManagement, ok := rawObject(raw)
	if !ok {
		return false
	}
	var edits []map[string]json.RawMessage
	if err := sonic.Unmarshal(contextManagement["edits"], &edits); err != nil {
		return false
	}
	for _, edit := range edits {
		if rawString(edit["type"]) == string(anthropicprovider.ContextManagementEditTypeCompact) {
			return true
		}
	}
	return false
}

func multiplyAnthropicTokenLimit(quantity int, multiplier int) (int, bool) {
	if quantity < 0 || multiplier < 1 || quantity > math.MaxInt/multiplier {
		return 0, false
	}
	return quantity * multiplier, true
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

func anthropicResponsesToolTypeSupported(rawType string) bool {
	rawType = strings.TrimSpace(rawType)
	switch rawType {
	case "function":
		return true
	default:
		return anthropicResponsesWebSearchToolType(rawType) || anthropicResponsesWebFetchToolType(rawType)
	}
}

func anthropicResponsesWebSearchToolType(rawType string) bool {
	switch strings.TrimSpace(rawType) {
	case "web_search", "web_search_20250305", "web_search_20260209", "web_search_20260318":
		return true
	default:
		return false
	}
}

func anthropicResponsesWebFetchToolType(rawType string) bool {
	switch strings.TrimSpace(rawType) {
	case "web_fetch", "web_fetch_20250910", "web_fetch_20260209", "web_fetch_20260309", "web_fetch_20260318":
		return true
	default:
		return false
	}
}

func anthropicResponsesCodeExecutionToolType(rawType string) bool {
	rawType = strings.TrimSpace(rawType)
	return rawType == "code_execution" || strings.HasPrefix(rawType, "code_execution_")
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
	if tokens, known := anthropicToolSystemPromptTokensForModel(model); known {
		return tokens
	}
	return maxAnthropicToolSystemPromptTokens
}

func anthropicToolSystemPromptTokensForModel(model string) (int, bool) {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(model)), ".", "-")
	switch {
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
	case strings.HasPrefix(normalized, "claude-sonnet-5"):
		return 474, true
	case strings.HasPrefix(normalized, "claude-sonnet-4-6"):
		return 589, true
	case strings.HasPrefix(normalized, "claude-sonnet-4-5"):
		return 588, true
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
