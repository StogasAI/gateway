package catalog

import (
	"encoding/json"

	"github.com/maximhq/bifrost/core/schemas"
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

	// OpenAI adds its own instructions for each of these tools, which the request does not show.
	// Input tokens beside the same request without the tool, equal on gpt-5.5, gpt-5.6-luna,
	// gpt-6-astra and gpt-6.1-sol (live, November 12, 2026): 237 for shell, 520 more once it lists
	// a skill, and 623 for apply_patch.
	openAIShellToolTokens      = 237
	openAIShellSkillsTokens    = 520
	openAIApplyPatchToolTokens = 623
	// The computer tool adds 811 on gpt-5.6-luna and gpt-6.2-sol alike (capture openai/computer-use).
	openAIComputerToolTokens = 811
	// File search adds 1,483 on gpt-6-luna, also under tool_choice none, before any search
	// (capture openai/file-search).
	openAIFileSearchToolTokens = 1483

	// Anthropic documents what its bash and text editor tools add to the input: 325 and 974
	// tokens on Claude Opus 4.7 and later, and less on earlier models. No live count confirms them.
	anthropicBashToolTokens       = 325
	anthropicTextEditorToolTokens = 974
)

type inputHoldStats struct {
	TextFields []string
	// OpaqueBytes are the bytes of provider ciphertext that the provider reads as text: encrypted
	// reasoning and Claude's encrypted search results.
	OpaqueBytes int

	Messages        int
	ContentBlocks   int
	ToolDefinitions int
	ToolEvents      int
	// ToolPromptTokens is what the provider's own instructions for the declared tools add.
	ToolPromptTokens int
}

// estimateInputContent counts visible text once, independent of the candidate
// model, and adds opaque reasoning separately. The limit only clips the hold;
// it never rejects, truncates or modifies the submitted content.
func estimateInputContent(stats inputHoldStats, limit int) (int, error) {
	// Provider ciphertext is not text for the model tokenizer. One token per
	// encoded byte remains an empirical allowance, not a bound guaranteed by
	// the provider's undocumented encrypted representation.
	estimate := stats.OpaqueBytes
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
//
// fileTexts are the texts of the text files that stay files, which the provider reads as prompt
// text.
func requestTokenEstimator(rawData map[string]json.RawMessage, fileTexts []string, route Route, selections []routingSelection) func(Deployment) (int, error) {
	stats := requestInputHoldStats(rawData, route)
	stats.TextFields = append(stats.TextFields, fileTexts...)
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
		return stats.ToolPromptTokens + openAIInputHoldBaseTokens +
			openAIInputHoldMessageTokens*stats.Messages +
			openAIInputHoldBlockTokens*stats.ContentBlocks +
			openAIInputHoldToolTokens*stats.ToolDefinitions +
			openAIInputHoldToolEventTokens*stats.ToolEvents
	}
	tokens := stats.ToolPromptTokens + extendedInputHoldBaseTokens +
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
	itemType := rawStringValue(object["type"])
	switch itemType {
	case "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output", "tool_call", "tool_result",
		"shell_call", "shell_call_output", "apply_patch_call", "apply_patch_call_output", "computer_call", "computer_call_output",
		"web_search_call", "web_fetch_call", "file_search_call", "tool_search_call", "tool_search_output",
		"mcp_list_tools", "mcp_call", "mcp_approval_request", "mcp_approval_response":
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
		case "content", "role", "type", "tool_calls", "response_format", "metadata":
			continue
		case "tools":
			// The tools that a tool search loaded, or that an MCP server listed, reach the model as
			// the request's own tools do.
			appendToolDefinitions(value, stats)
		case "reasoning":
			// Anthropic history repeats the visible summary beside signed details.
			// The authenticated envelope supplies the actual thinking input.
			if _, signed := object["reasoning_details"]; !signed {
				collectTextLike(value, stats)
			}
		case "reasoning_details":
			collectReasoningDetails(value, stats)
		case "action":
			if itemType == "web_search_call" {
				collectSearchAction(value, stats)
			} else {
				collectTextLike(value, stats)
			}
		default:
			collectTextLike(value, stats)
		}
	}
}

// collectSearchAction counts the action of a web search that a reply returned. Claude reads each
// result's encrypted content as the page text that it holds.
func collectSearchAction(raw json.RawMessage, stats *inputHoldStats) {
	action, err := rawjson.Object(raw)
	if err != nil {
		collectTextLike(raw, stats)
		return
	}
	for key, value := range action {
		sources, err := rawjson.Array(value)
		if key != "sources" || err != nil {
			collectTextLike(value, stats)
			continue
		}
		for _, sourceRaw := range sources {
			source, err := rawjson.Object(sourceRaw)
			if err != nil {
				collectTextLike(sourceRaw, stats)
				continue
			}
			for field, value := range source {
				if opaque := rawStringValue(value); field == "encrypted_content" && opaque != "" {
					stats.OpaqueBytes += len(opaque)
					continue
				}
				collectTextLike(value, stats)
			}
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
		stats.OpaqueBytes += len(opaque)
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
			if !appendNamespaceToolDefinitions(tool, stats) {
				stats.ToolDefinitions++
				stats.ToolPromptTokens += toolPromptTokens(tool)
				appendCompactJSONText(tool, stats)
			}
		}
		return
	}
	stats.ToolDefinitions++
	appendCompactJSONText(raw, stats)
}

// toolPromptTokens is what the provider's own instructions for a tool add to the input.
func toolPromptTokens(raw json.RawMessage) int {
	tool, err := rawjson.Object(raw)
	if err != nil {
		return 0
	}
	switch schemas.ResponsesToolType(rawStringValue(tool["type"])) {
	case AnthropicBashToolType:
		return anthropicBashToolTokens
	case AnthropicTextEditorToolType:
		return anthropicTextEditorToolTokens
	case schemas.ResponsesToolTypeShell:
		tokens := openAIShellToolTokens
		if environment, err := rawjson.Object(tool["environment"]); err == nil && rawArrayLen(environment["skills"]) > 0 {
			tokens += openAIShellSkillsTokens
		}
		return tokens
	case schemas.ResponsesToolTypeApplyPatch:
		return openAIApplyPatchToolTokens
	case schemas.ResponsesToolTypeComputer:
		return openAIComputerToolTokens
	case schemas.ResponsesToolTypeFileSearch:
		return openAIFileSearchToolTokens
	}
	return 0
}

// appendNamespaceToolDefinitions counts each tool of a namespace as a tool with the namespace's
// name and description, as an interface without namespaces gets it, and reports whether the tool
// is a namespace.
func appendNamespaceToolDefinitions(raw json.RawMessage, stats *inputHoldStats) bool {
	namespace, err := rawjson.Object(raw)
	if err != nil || CanonicalResponsesToolType(rawStringValue(namespace["type"])) != schemas.ResponsesToolTypeNamespace {
		return false
	}
	members, err := rawjson.Array(namespace["tools"])
	if err != nil {
		return false
	}
	for _, member := range members {
		stats.ToolDefinitions++
		appendCompactJSONText(member, stats)
		appendStringValue(namespace["name"], stats)
		appendStringValue(namespace["description"], stats)
	}
	return true
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
