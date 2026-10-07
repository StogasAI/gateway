package catalog

import (
	"encoding/json"

	"github.com/maximhq/bifrost/transports/stogas/rawjson"
	"github.com/maximhq/bifrost/transports/stogas/tokenizer"
)

// Framing allowances are separate from universal text estimation. They retain
// the existing measured template allowances using the model's canonical author;
// the hosting provider never chooses the text estimator.
const (
	openAIInputHoldBaseTokens      = 64
	openAIInputHoldMessageTokens   = 12
	openAIInputHoldBlockTokens     = 8
	openAIInputHoldToolTokens      = 32
	openAIInputHoldToolEventTokens = 16

	extendedInputHoldBaseTokens         = 128
	extendedInputHoldMessageTokens      = 20
	extendedInputHoldBlockTokens        = 12
	extendedInputHoldToolTokens         = 48
	extendedInputHoldToolEventTokens    = 24
	extendedInputHoldToolPreambleTokens = 512
)

type inputHoldStats struct {
	TextFields           []string
	OpaqueReasoningBytes int

	Messages        int
	ContentBlocks   int
	ToolDefinitions int
	ToolEvents      int
}

// estimateInputContent counts visible text once, independent of the candidate
// model, and adds opaque reasoning separately. The limit only clips the hold;
// it never rejects, truncates or modifies the submitted content.
func estimateInputContent(stats inputHoldStats, limit int) (int, error) {
	// Provider reasoning envelopes are not text for the model tokenizer.
	// One token per encoded byte remains an empirical allowance, not a bound
	// guaranteed by the provider's undocumented encrypted representation.
	estimate := stats.OpaqueReasoningBytes
	if limit > 0 && estimate >= limit {
		return limit, nil
	}
	for _, text := range stats.TextFields {
		remaining := 0
		if limit > 0 {
			remaining = limit - estimate
		}
		count, err := tokenizer.EstimateAtMost(text, remaining)
		if err != nil {
			return 0, APIError{StatusCode: 400, Type: ErrorTypeInvalidRequest, Message: "Input text cannot be estimated: " + err.Error()}
		}
		estimate += count
		if limit > 0 && estimate >= limit {
			return limit, nil
		}
	}
	return estimate, nil
}

// Each immutable post-redaction body shares one content estimate across all
// routing candidates. Candidate-specific framing and input ceilings are cheap
// additions; a small candidate's ceiling must not cap a later larger candidate.
func requestTokenEstimator(rawData map[string]json.RawMessage, route Route, selections []routingSelection) func(Deployment) (int, error) {
	stats := requestInputHoldStats(rawData, route)
	maxInput := 0
	for _, selection := range selections {
		limit := selection.deployment.MaxInputTokens
		if limit <= 0 {
			maxInput = 0
			break
		}
		maxInput = max(maxInput, limit)
	}
	var content int
	var contentErr error
	counted := false
	return func(deployment Deployment) (int, error) {
		if deployment.snapshot == nil {
			return 0, ErrModelUnavailable
		}
		model, ok := deployment.snapshot.graph.Models[deployment.ModelID]
		if !ok {
			return 0, ErrModelUnavailable
		}
		if !counted {
			content, contentErr = estimateInputContent(stats, maxInput)
			counted = true
		}
		if contentErr != nil {
			return 0, contentErr
		}
		estimate := content + inputHoldFraming(stats, model.AuthorID)
		if limit := deployment.MaxInputTokens; limit > 0 {
			estimate = min(estimate, limit)
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

func inputHoldFraming(stats inputHoldStats, author string) int {
	if author == "openai" {
		return openAIInputHoldBaseTokens +
			openAIInputHoldMessageTokens*stats.Messages +
			openAIInputHoldBlockTokens*stats.ContentBlocks +
			openAIInputHoldToolTokens*stats.ToolDefinitions +
			openAIInputHoldToolEventTokens*stats.ToolEvents
	}
	tokens := extendedInputHoldBaseTokens +
		extendedInputHoldMessageTokens*stats.Messages +
		extendedInputHoldBlockTokens*stats.ContentBlocks +
		extendedInputHoldToolTokens*stats.ToolDefinitions +
		extendedInputHoldToolEventTokens*stats.ToolEvents
	if stats.ToolDefinitions > 0 {
		tokens += extendedInputHoldToolPreambleTokens
	}
	if author == "minimax" {
		// The pinned M3 template has a 176-token empty-user prompt,
		// exceeding the shared 148-token base/message allowance by 28.
		tokens += 28
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
