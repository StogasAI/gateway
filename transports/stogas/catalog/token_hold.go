package catalog

import (
	"encoding/json"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	tiktoken "github.com/tiktoken-go/tokenizer"
)

const (
	openAIInputHoldTextBufferBps = 10300

	openAIInputHoldBaseTokens      = 64
	openAIInputHoldMessageTokens   = 12
	openAIInputHoldBlockTokens     = 8
	openAIInputHoldToolTokens      = 32
	openAIInputHoldToolEventTokens = 16

	anthropicInputHoldTextBufferBps = 13000

	anthropicInputHoldBaseTokens      = 128
	anthropicInputHoldMessageTokens   = 20
	anthropicInputHoldBlockTokens     = 12
	anthropicInputHoldToolTokens      = 48
	anthropicInputHoldToolEventTokens = 24
)

var openAITokenizerCache sync.Map

type inputHoldStats struct {
	TextFields []string
	TextBytes  int

	Messages        int
	ContentBlocks   int
	ToolDefinitions int
	ToolEvents      int

	AnthropicStrict bool
}

func inputTokenHoldEstimate(body []byte, rawData map[string]json.RawMessage, provider schemas.ModelProvider, model string, route Route, maxInputTokens int) int {
	stats := requestInputHoldStats(rawData, route)
	if maxInputTokens < 0 {
		maxInputTokens = 0
	}
	if maxInputTokens > 0 && stats.TextBytes >= maxInputTokens {
		return maxInputTokens
	}
	estimate := 0
	switch provider {
	case schemas.OpenAI:
		estimate = openAIInputTokenHold(model, stats)
	case schemas.Anthropic:
		estimate = anthropicInputTokenHold(stats)
	default:
		estimate = ceilMulDiv(len(body), 130, 100)
	}
	if estimate <= 0 && len(body) > 0 {
		estimate = 1
	}
	if maxInputTokens > 0 && estimate > maxInputTokens {
		return maxInputTokens
	}
	return estimate
}

func requestInputHoldStats(rawData map[string]json.RawMessage, route Route) inputHoldStats {
	stats := inputHoldStats{}
	appendTopLevelTextFields(&stats, rawData, "instructions", "system", "developer")
	collectMessageList(rawData["messages"], &stats)
	collectResponsesInput(rawData["input"], &stats)
	appendToolDefinitions(rawData["tools"], &stats)
	appendCompactJSONText(rawData["response_format"], &stats)
	appendCompactJSONText(rawData["functions"], &stats)
	if route == RouteResponses {
		appendCompactJSONText(rawData["text"], &stats)
	}
	return stats
}

func openAIInputTokenHold(model string, stats inputHoldStats) int {
	codec, ok := openAITokenizerForModel(model)
	textTokens := 0
	for _, text := range stats.TextFields {
		if text == "" {
			continue
		}
		if ok {
			count, err := codec.Count(text)
			if err == nil {
				textTokens += count
				continue
			}
		}
		textTokens += len(text)
	}
	return ceilMulDiv(textTokens, openAIInputHoldTextBufferBps, 10000) +
		openAIInputHoldBaseTokens +
		openAIInputHoldMessageTokens*stats.Messages +
		openAIInputHoldBlockTokens*stats.ContentBlocks +
		openAIInputHoldToolTokens*stats.ToolDefinitions +
		openAIInputHoldToolEventTokens*stats.ToolEvents
}

func anthropicInputTokenHold(stats inputHoldStats) int {
	textHold := 0
	for _, text := range stats.TextFields {
		if text == "" {
			continue
		}
		estimate := anthropicWeightedTextEstimate(text, stats.AnthropicStrict || anthropicTextNeedsStrictFloor(text))
		textHold += ceilMulDiv(estimate, anthropicInputHoldTextBufferBps, 10000) + 8
	}
	if stats.AnthropicStrict {
		textHold = maxInt(textHold, ceilMulDiv(stats.TextBytes, 85, 100))
	}
	return textHold +
		anthropicInputHoldBaseTokens +
		anthropicInputHoldMessageTokens*stats.Messages +
		anthropicInputHoldBlockTokens*stats.ContentBlocks +
		anthropicInputHoldToolTokens*stats.ToolDefinitions +
		anthropicInputHoldToolEventTokens*stats.ToolEvents
}

func openAITokenizerForModel(model string) (tiktoken.Codec, bool) {
	encoding, ok := openAIEncodingForModel(model)
	if !ok {
		return nil, false
	}
	if cached, ok := openAITokenizerCache.Load(encoding); ok {
		codec, ok := cached.(tiktoken.Codec)
		return codec, ok
	}
	codec, err := tiktoken.Get(encoding)
	if err != nil {
		return nil, false
	}
	openAITokenizerCache.Store(encoding, codec)
	return codec, true
}

func openAIEncodingForModel(model string) (tiktoken.Encoding, bool) {
	normalized := strings.ToLower(strings.TrimSpace(model))
	switch {
	case normalized == "":
		return "", false
	case strings.HasPrefix(normalized, "gpt-5"),
		strings.HasPrefix(normalized, "gpt-4.1"),
		strings.HasPrefix(normalized, "gpt-4o"),
		strings.HasPrefix(normalized, "o1"),
		strings.HasPrefix(normalized, "o3"),
		strings.HasPrefix(normalized, "o4"):
		return tiktoken.O200kBase, true
	case strings.HasPrefix(normalized, "gpt-4"),
		strings.HasPrefix(normalized, "gpt-3.5"),
		strings.HasPrefix(normalized, "gpt-35"):
		return tiktoken.Cl100kBase, true
	default:
		return "", false
	}
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
	var messages []json.RawMessage
	if err := sonic.Unmarshal(raw, &messages); err != nil {
		collectTextLike(raw, "", stats)
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
	var items []json.RawMessage
	if err := sonic.Unmarshal(raw, &items); err != nil {
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
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err != nil {
		collectTextLike(raw, "", stats)
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
	}
	if rawContent, ok := object["content"]; ok {
		collectContent(rawContent, stats)
	}
	for key, value := range object {
		switch key {
		case "content", "role", "type", "tool_calls", "tools", "response_format", "metadata":
			continue
		default:
			collectTextLike(value, key, stats)
		}
	}
}

func collectContent(raw json.RawMessage, stats *inputHoldStats) {
	if appendStringValue(raw, stats) {
		stats.ContentBlocks++
		return
	}
	var blocks []json.RawMessage
	if err := sonic.Unmarshal(raw, &blocks); err == nil {
		for _, block := range blocks {
			stats.ContentBlocks++
			collectTextLike(block, "", stats)
		}
		return
	}
	collectTextLike(raw, "content", stats)
}

func collectTextLike(raw json.RawMessage, key string, stats *inputHoldStats) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	if isTextBearingKey(key) && appendStringValue(raw, stats) {
		return
	}
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err == nil {
		for childKey, child := range object {
			if childKey == "authorization_token" || childKey == "metadata" {
				continue
			}
			collectTextLike(child, childKey, stats)
		}
		return
	}
	var array []json.RawMessage
	if err := sonic.Unmarshal(raw, &array); err == nil {
		for _, child := range array {
			collectTextLike(child, key, stats)
		}
	}
}

func isTextBearingKey(key string) bool {
	switch key {
	case "arguments", "content", "description", "developer", "instructions", "input", "name", "output", "summary", "system", "text":
		return true
	default:
		return false
	}
}

func appendToolDefinitions(raw json.RawMessage, stats *inputHoldStats) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	var tools []json.RawMessage
	if err := sonic.Unmarshal(raw, &tools); err == nil {
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
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return
	}
	encoded, err := sonic.Marshal(value)
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
	stats.TextBytes += len(text)
	if anthropicTextNeedsStrictFloor(text) {
		stats.AnthropicStrict = true
	}
}

func inputItemLooksLikeContentBlock(raw json.RawMessage) bool {
	var object map[string]json.RawMessage
	if err := sonic.Unmarshal(raw, &object); err != nil {
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
	var array []json.RawMessage
	if err := sonic.Unmarshal(raw, &array); err != nil {
		return 0
	}
	return len(array)
}

func anthropicWeightedTextEstimate(text string, strict bool) int {
	bytes := len(text)
	asciiRunes, cjkRunes, emojiRunes, otherNonASCIIRunes := classifyRunes(text)
	byBytes := ceilMulDiv(bytes, 100, 235)
	byClass := ceilMulDiv(asciiRunes, 100, 255) +
		ceilMulDiv(cjkRunes, 135, 100) +
		emojiRunes*4 +
		ceilMulDiv(otherNonASCIIRunes, 180, 100)
	if strict {
		return maxInt(maxInt(byBytes, byClass), ceilMulDiv(bytes, 75, 100))
	}
	return maxInt(byBytes, byClass)
}

func classifyRunes(text string) (ascii int, cjk int, emoji int, otherNonASCII int) {
	for _, r := range text {
		switch {
		case r < utf8.RuneSelf:
			ascii++
		case isCJKLikeRune(r):
			cjk++
		case isEmojiLikeRune(r):
			emoji++
		default:
			otherNonASCII++
		}
	}
	return ascii, cjk, emoji, otherNonASCII
}

func anthropicTextNeedsStrictFloor(text string) bool {
	if len(text) < 32 {
		return false
	}
	asciiLetters := 0
	digits := 0
	hex := 0
	base64 := 0
	spaces := 0
	symbols := 0
	nonASCII := 0
	for _, r := range text {
		switch {
		case r >= utf8.RuneSelf:
			nonASCII++
		case unicode.IsSpace(r):
			spaces++
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			asciiLetters++
			if (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
				hex++
			}
			base64++
		case r >= '0' && r <= '9':
			digits++
			hex++
			base64++
		case r == '+' || r == '/' || r == '=' || r == '-' || r == '_':
			symbols++
			base64++
		default:
			symbols++
		}
	}
	runes := utf8.RuneCountInString(text)
	if runes == 0 {
		return false
	}
	if nonASCII*5 >= runes {
		return true
	}
	if len(text) >= 64 && (hex+digits)*5 >= runes*4 && spaces == 0 {
		return true
	}
	if len(text) >= 64 && base64*10 >= runes*9 && spaces == 0 {
		return true
	}
	if len(text) >= 64 && spaces*20 <= runes && (symbols+digits)*10 >= runes*3 {
		return true
	}
	return false
}

func isCJKLikeRune(r rune) bool {
	return (r >= 0x3040 && r <= 0x30ff) ||
		(r >= 0x3400 && r <= 0x4dbf) ||
		(r >= 0x4e00 && r <= 0x9fff) ||
		(r >= 0xac00 && r <= 0xd7af)
}

func isEmojiLikeRune(r rune) bool {
	return (r >= 0x1f000 && r <= 0x1faff) ||
		(r >= 0x2600 && r <= 0x27bf)
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
