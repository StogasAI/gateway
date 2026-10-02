package catalog

import (
	"encoding/json"
	"fmt"

	"github.com/maximhq/bifrost/transports/stogas/rawjson"
	"github.com/maximhq/bifrost/transports/stogas/tokenizer"
)

const (
	openAIInputHoldTextBufferBps = 10300

	openAIInputHoldBaseTokens      = 64
	openAIInputHoldMessageTokens   = 12
	openAIInputHoldBlockTokens     = 8
	openAIInputHoldToolTokens      = 32
	openAIInputHoldToolEventTokens = 16

	anthropicInputHoldTextBufferBps = 11500

	anthropicInputHoldBaseTokens         = 128
	anthropicInputHoldMessageTokens      = 20
	anthropicInputHoldBlockTokens        = 12
	anthropicInputHoldToolTokens         = 48
	anthropicInputHoldToolEventTokens    = 24
	anthropicInputHoldToolPreambleTokens = 512
)

// The catalog selects one supported local estimator explicitly. Decode its
// family once with the model; request handling never infers it from names,
// authors, or hosting providers.
type tokenizationStrategy string

const (
	tokenizationOpenAI    tokenizationStrategy = "openai"
	tokenizationAnthropic tokenizationStrategy = "anthropic"
	tokenizationDeepSeek  tokenizationStrategy = "deepseek"
	tokenizationQwen3     tokenizationStrategy = "qwen3"
	tokenizationQwen35    tokenizationStrategy = "qwen35"
	tokenizationGemma     tokenizationStrategy = "gemma"
	tokenizationMiniMax   tokenizationStrategy = "minimax"
	tokenizationTekken    tokenizationStrategy = "tekken"
	tokenizationKimi      tokenizationStrategy = "kimi"
	tokenizationGLM       tokenizationStrategy = "glm"
)

func (strategy tokenizationStrategy) valid() bool {
	if strategy == tokenizationOpenAI || strategy == tokenizationAnthropic {
		return true
	}
	encoding, _ := publishedTokenization(strategy)
	return encoding != ""
}

func publishedTokenization(strategy tokenizationStrategy) (string, int) {
	switch strategy {
	case tokenizationDeepSeek:
		return "deepseek", 10300
	case tokenizationQwen3:
		return "qwen3", 10300
	case tokenizationQwen35:
		return "qwen35", 10300
	case tokenizationGemma:
		return "gemma", 10300
	case tokenizationMiniMax:
		return "minimax", 10300
	case tokenizationTekken:
		return "mistral", 10300
	case tokenizationKimi:
		return "kimi", 10300
	// GLM's 16-KiB artificial boundaries missed up to 2 of 35 whitespace
	// tokens in the calibration search. Seven percent covers that observation.
	case tokenizationGLM:
		return "glm", 10700
	default:
		return "", 0
	}
}

type inputHoldStats struct {
	TextFields           []string
	OpaqueReasoningBytes int

	Messages        int
	ContentBlocks   int
	ToolDefinitions int
	ToolEvents      int
}

// estimateInputHold reserves funds; it is not a request-admission token
// limit. The selected provider remains authoritative for its tokenizer and
// context window, including future one- and two-million-token deployments.
func estimateInputHold(stats inputHoldStats, strategy tokenizationStrategy, maxInputTokens int) (int, error) {
	if maxInputTokens < 0 {
		maxInputTokens = 0
	}
	// Provider reasoning envelopes are opaque, not text for the model tokenizer.
	// Reserve one token per encoded byte, in addition to visible text and framing.
	// This is a deliberately conservative empirical estimate, not a token bound
	// guaranteed by the provider's undocumented encrypted representation.
	visibleLimit := maxInputTokens
	if maxInputTokens > 0 {
		if stats.OpaqueReasoningBytes >= maxInputTokens {
			return maxInputTokens, nil
		}
		visibleLimit -= stats.OpaqueReasoningBytes
	}
	var estimate int
	var err error
	switch strategy {
	case tokenizationOpenAI:
		estimate, err = openAIInputTokenHold(stats, visibleLimit)
	case tokenizationAnthropic:
		estimate, err = anthropicInputTokenHold(stats, visibleLimit)
	default:
		encoding, buffer := publishedTokenization(strategy)
		if encoding == "" {
			return 0, fmt.Errorf("unsupported catalog tokenization strategy")
		}
		estimate, err = vocabularyInputTokenHold(stats, visibleLimit, encoding, buffer, true)
		if strategy == tokenizationMiniMax {
			// The pinned M3 template has a 176-token empty-user prompt,
			// exceeding the shared 148-token base/message allowance by 28.
			estimate += 28
		}
	}
	if err != nil {
		return 0, APIError{StatusCode: 400, Type: ErrorTypeInvalidRequest, Message: "Input text cannot be tokenized: " + err.Error()}
	}
	estimate += stats.OpaqueReasoningBytes
	if maxInputTokens > 0 && estimate > maxInputTokens {
		return maxInputTokens, nil
	}
	return estimate, nil
}

// One request can have several deployments, but its input text is immutable
// during selection. Parse it once and tokenize once per strategy. Context
// caps are applied separately so deployment variants cannot multiply scanning.
func requestTokenEstimator(rawData map[string]json.RawMessage, route Route, selections []routingSelection) func(Deployment) (int, error) {
	stats := requestInputHoldStats(rawData, route)
	maxContext := 0
	for _, selection := range selections {
		context := selection.deployment.ContextWindowTokens
		if context <= 0 {
			maxContext = 0
			break
		}
		maxContext = max(maxContext, context)
	}
	estimates := make(map[tokenizationStrategy]int)
	return func(deployment Deployment) (int, error) {
		if deployment.snapshot == nil {
			return 0, ErrModelUnavailable
		}
		model, ok := deployment.snapshot.graph.Models[deployment.ModelID]
		if !ok {
			return 0, ErrModelUnavailable
		}
		strategy := model.TokenizerFamily
		estimate, ok := estimates[strategy]
		if !ok {
			var err error
			estimate, err = estimateInputHold(stats, strategy, maxContext)
			if err != nil {
				return 0, err
			}
			estimates[strategy] = estimate
		}
		if context := deployment.ContextWindowTokens; context > 0 && estimate > context {
			return context, nil
		}
		return estimate, nil
	}
}

func requestInputHoldStats(rawData map[string]json.RawMessage, route Route) inputHoldStats {
	stats := inputHoldStats{}
	appendTopLevelTextFields(&stats, rawData, "instructions", "system", "developer")
	collectMessageList(rawData["messages"], &stats)
	collectResponsesInput(rawData["input"], &stats)
	appendToolDefinitions(rawData["tools"], &stats)
	appendCompactJSONText(rawData["response_format"], &stats)
	appendCompactJSONText(rawData["functions"], &stats)
	appendCompactJSONText(rawData["context_management"], &stats)
	appendCompactJSONText(rawData["task_budget"], &stats)
	appendCompactJSONText(rawData["stop_sequences"], &stats)
	if route == RouteResponses {
		appendCompactJSONText(rawData["text"], &stats)
	}
	return stats
}

func openAIInputTokenHold(stats inputHoldStats, maxTokens int) (int, error) {
	return vocabularyInputTokenHold(stats, maxTokens, tokenizer.O200kBase, openAIInputHoldTextBufferBps, false)
}

func vocabularyInputTokenHold(stats inputHoldStats, maxTokens int, encoding string, buffer int, extendedFraming bool) (int, error) {
	codec, err := tokenizer.Get(encoding)
	if err != nil {
		return 0, err
	}
	textTokens := 0
	for _, text := range stats.TextFields {
		if text == "" {
			continue
		}
		count, err := codec.CountAtMost(text, maxTokens-textTokens)
		if err != nil {
			return 0, err
		}
		textTokens += count
		if maxTokens > 0 && textTokens >= maxTokens {
			return maxTokens, nil
		}
	}
	return ceilMulDiv(textTokens, buffer, 10000) + inputHoldFraming(stats, extendedFraming), nil
}

func anthropicInputTokenHold(stats inputHoldStats, maxTokens int) (int, error) {
	textHold := 0
	for _, text := range stats.TextFields {
		if text == "" {
			continue
		}
		count, err := tokenizer.Claude().CountAtMost(text, maxTokens-textHold)
		if err != nil {
			return 0, err
		}
		textHold += ceilMulDiv(count, anthropicInputHoldTextBufferBps, 10000) + 8
		if maxTokens > 0 && textHold >= maxTokens {
			return maxTokens, nil
		}
	}
	return textHold + inputHoldFraming(stats, true), nil
}

func inputHoldFraming(stats inputHoldStats, anthropic bool) int {
	if !anthropic {
		return openAIInputHoldBaseTokens +
			openAIInputHoldMessageTokens*stats.Messages +
			openAIInputHoldBlockTokens*stats.ContentBlocks +
			openAIInputHoldToolTokens*stats.ToolDefinitions +
			openAIInputHoldToolEventTokens*stats.ToolEvents
	}
	tokens := anthropicInputHoldBaseTokens +
		anthropicInputHoldMessageTokens*stats.Messages +
		anthropicInputHoldBlockTokens*stats.ContentBlocks +
		anthropicInputHoldToolTokens*stats.ToolDefinitions +
		anthropicInputHoldToolEventTokens*stats.ToolEvents
	if stats.ToolDefinitions > 0 {
		tokens += anthropicInputHoldToolPreambleTokens
	}
	return tokens
}

func appendTopLevelTextFields(stats *inputHoldStats, rawData map[string]json.RawMessage, keys ...string) {
	for _, key := range keys {
		appendStringValue(rawData[key], stats)
	}
}

func collectMessageList(raw json.RawMessage, stats *inputHoldStats) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	messages, err := rawjson.Array(raw)
	if err != nil {
		collectTextLike(raw, stats)
		return
	}
	for _, message := range messages {
		stats.Messages++
		collectMessageObject(message, stats)
	}
}

func collectResponsesInput(raw json.RawMessage, stats *inputHoldStats) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	if appendStringValue(raw, stats) {
		stats.Messages++
		stats.ContentBlocks++
		return
	}
	items, err := rawjson.Array(raw)
	if err != nil {
		collectMessageObject(raw, stats)
		return
	}
	for _, item := range items {
		stats.Messages++
		if inputItemLooksLikeContentBlock(item) {
			stats.ContentBlocks++
		}
		collectMessageObject(item, stats)
	}
}

func collectMessageObject(raw json.RawMessage, stats *inputHoldStats) {
	object, err := rawjson.Object(raw)
	if err != nil {
		collectTextLike(raw, stats)
		return
	}
	if rawStringValue(object["type"]) == "reasoning" {
		collectReasoningObject(object, "encrypted_content", stats)
		return
	}
	if rawStringValue(object["role"]) == "tool" {
		stats.ToolEvents++
	}
	if objectType := rawStringValue(object["type"]); objectType == "function_call" || objectType == "function_call_output" || objectType == "tool_call" || objectType == "tool_result" {
		stats.ToolEvents++
	}
	if rawToolCalls, ok := object["tool_calls"]; ok {
		stats.ToolEvents += rawArrayLen(rawToolCalls)
		collectTextLike(rawToolCalls, stats)
	}
	if rawContent, ok := object["content"]; ok {
		collectContent(rawContent, stats)
	}
	for key, value := range object {
		switch key {
		case "content", "role", "type", "tool_calls", "tools", "response_format", "metadata":
			continue
		case "reasoning":
			// Anthropic history repeats the visible summary beside signed details.
			// The authenticated envelope supplies the actual thinking input.
			if _, signed := object["reasoning_details"]; !signed {
				collectTextLike(value, stats)
			}
		case "reasoning_details":
			collectReasoningDetails(value, stats)
		default:
			collectTextLike(value, stats)
		}
	}
}

func collectContent(raw json.RawMessage, stats *inputHoldStats) {
	if appendStringValue(raw, stats) {
		stats.ContentBlocks++
		return
	}
	if blocks, err := rawjson.Array(raw); err == nil {
		for _, block := range blocks {
			stats.ContentBlocks++
			if object, err := rawjson.Object(block); err == nil {
				switch rawStringValue(object["type"]) {
				case "thinking":
					collectReasoningObject(object, "signature", stats)
					continue
				case "redacted_thinking":
					collectReasoningObject(object, "data", stats)
					continue
				}
				collectTextObject(object, stats)
				continue
			}
			collectTextLike(block, stats)
		}
		return
	}
	collectTextLike(raw, stats)
}

func collectReasoningDetails(raw json.RawMessage, stats *inputHoldStats) {
	details, err := rawjson.Array(raw)
	if err != nil {
		collectTextLike(raw, stats)
		return
	}
	for _, rawDetail := range details {
		detail, err := rawjson.Object(rawDetail)
		if err != nil {
			collectTextLike(rawDetail, stats)
			continue
		}
		field := "signature"
		if rawStringValue(detail["type"]) == "reasoning.encrypted" && rawStringValue(detail["data"]) != "" {
			field = "data"
		}
		collectReasoningObject(detail, field, stats)
	}
}

// Called only at declared reasoning positions. A similarly named property in
// a tool argument or schema remains ordinary input text.
func collectReasoningObject(object map[string]json.RawMessage, opaqueField string, stats *inputHoldStats) {
	if opaque := rawStringValue(object[opaqueField]); opaque != "" {
		stats.OpaqueReasoningBytes += len(opaque)
		return
	}
	for field, value := range object {
		switch field {
		case "id", "type", "index", "format", opaqueField:
			// Message/block framing is counted separately.
		default:
			collectTextLike(value, stats)
		}
	}
}

func collectTextLike(raw json.RawMessage, stats *inputHoldStats) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	if appendStringValue(raw, stats) {
		return
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err == nil {
		collectTextObject(object, stats)
		return
	}
	if array, err := rawjson.Array(raw); err == nil {
		for _, child := range array {
			collectTextLike(child, stats)
		}
	}
}

func collectTextObject(object map[string]json.RawMessage, stats *inputHoldStats) {
	for childKey, child := range object {
		if childKey != "authorization_token" && childKey != "metadata" {
			collectTextLike(child, stats)
		}
	}
}

func appendToolDefinitions(raw json.RawMessage, stats *inputHoldStats) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	if tools, err := rawjson.Array(raw); err == nil {
		for _, tool := range tools {
			stats.ToolDefinitions++
			appendCompactJSONText(tool, stats)
		}
		return
	}
	stats.ToolDefinitions++
	appendCompactJSONText(raw, stats)
}

func appendCompactJSONText(raw json.RawMessage, stats *inputHoldStats) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return
	}
	// encoding/json sorts object keys. The reservation must not change when a
	// client writes the same tool schema in a different key order.
	encoded, err := json.Marshal(value)
	if err != nil {
		return
	}
	appendText(string(encoded), stats)
}

func appendStringValue(raw json.RawMessage, stats *inputHoldStats) bool {
	value := rawStringValue(raw)
	if value == "" {
		return false
	}
	appendText(value, stats)
	return true
}

func appendText(text string, stats *inputHoldStats) {
	stats.TextFields = append(stats.TextFields, text)
}

func inputItemLooksLikeContentBlock(raw json.RawMessage) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return false
	}
	switch rawStringValue(object["type"]) {
	case "input_text", "output_text":
		return true
	default:
		return false
	}
}

func rawArrayLen(raw json.RawMessage) int {
	array, err := rawjson.Array(raw)
	if err != nil {
		return 0
	}
	return len(array)
}

func ceilMulDiv(value int, multiplier int, divisor int) int {
	if value <= 0 {
		return 0
	}
	return (value*multiplier + divisor - 1) / divisor
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}
