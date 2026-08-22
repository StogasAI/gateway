package stogas

import (
	"bytes"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func validateProviderChatMessage(state *State, message *schemas.ChatMessage) error {
	if message == nil || message.Role != schemas.ChatMessageRoleAssistant || message.ChatToolMessage != nil || message.Name != nil {
		return ErrProviderResponseMalformed
	}
	if validateProviderChatContent(message.Content) != nil {
		return ErrProviderResponseMalformed
	}
	if assistant := message.ChatAssistantMessage; assistant != nil {
		if assistant.Audio != nil || validateProviderReasoningDetails(assistant.ReasoningDetails) != nil ||
			assistant.Reasoning != nil && len(assistant.ReasoningDetails) == 0 ||
			!validOptionalProviderText(assistant.Refusal, maxProviderResponseBodySize, false) ||
			!validOptionalProviderText(assistant.Reasoning, maxProviderResponseBodySize, true) ||
			assistant.Refusal != nil && providerChatContentPresent(message.Content) ||
			!providerReasoningMatchesDetails(assistant.Reasoning, assistant.ReasoningDetails) ||
			validateProviderChatAnnotations(state, assistant.Annotations) != nil {
			return ErrProviderResponseMalformed
		}
		if err := validateProviderChatToolCalls(state, assistant.ToolCalls, false); err != nil {
			return err
		}
	}
	return nil
}

func validateProviderChatDelta(state *State, delta *schemas.ChatStreamResponseChoiceDelta) error {
	if delta == nil || delta.Audio != nil || rawProviderExtensionSet(delta.ExtraContent) ||
		validateProviderReasoningDetails(delta.ReasoningDetails) != nil ||
		delta.Reasoning != nil && len(delta.ReasoningDetails) == 0 ||
		!validOptionalProviderText(delta.Content, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(delta.Refusal, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(delta.Reasoning, maxProviderResponseBodySize, true) ||
		delta.Content != nil && delta.Refusal != nil ||
		!providerReasoningMatchesDetails(delta.Reasoning, delta.ReasoningDetails) ||
		validateProviderChatAnnotations(state, delta.Annotations) != nil {
		return ErrProviderResponseMalformed
	}
	if delta.Role != nil && *delta.Role != string(schemas.ChatMessageRoleAssistant) {
		return ErrProviderResponseMalformed
	}
	return validateProviderChatToolCalls(state, delta.ToolCalls, true)
}

func validateProviderReasoningDetails(details []schemas.ChatReasoningDetails) error {
	if len(details) > maxProviderResponseItems {
		return ErrProviderResponseMalformed
	}
	seen := make(map[int]struct{}, len(details))
	for _, detail := range details {
		if detail.Index < 0 || detail.Index >= maxProviderResponseItems {
			return ErrProviderResponseMalformed
		}
		if _, duplicate := seen[detail.Index]; duplicate {
			return ErrProviderResponseMalformed
		}
		seen[detail.Index] = struct{}{}
		if detail.ID != nil && !validProviderResponseID(*detail.ID) {
			return ErrProviderResponseMalformed
		}
		switch detail.Type {
		case schemas.BifrostReasoningDetailsTypeSummary:
			if detail.Summary == nil || !validProviderText(*detail.Summary, maxProviderResponseBodySize, true) ||
				detail.Text != nil || detail.Signature != nil || detail.Data != nil {
				return ErrProviderResponseMalformed
			}
		case schemas.BifrostReasoningDetailsTypeEncrypted:
			if detail.Data == nil || !validProviderText(*detail.Data, maxProviderResponseBodySize, false) ||
				detail.Summary != nil || detail.Text != nil || detail.Signature != nil {
				return ErrProviderResponseMalformed
			}
		case schemas.BifrostReasoningDetailsTypeText:
			if detail.Text == nil && detail.Signature == nil ||
				!validOptionalProviderText(detail.Text, maxProviderResponseBodySize, true) ||
				!validOptionalProviderText(detail.Signature, maxProviderResponseBodySize, false) ||
				detail.Summary != nil || detail.Data != nil {
				return ErrProviderResponseMalformed
			}
		default:
			return ErrProviderResponseMalformed
		}
	}
	return nil
}

func providerReasoningMatchesDetails(reasoning *string, details []schemas.ChatReasoningDetails) bool {
	if reasoning == nil {
		return true
	}
	var text strings.Builder
	found := false
	for _, detail := range details {
		if detail.Type == schemas.BifrostReasoningDetailsTypeText && detail.Text != nil {
			found = true
			_, _ = text.WriteString(*detail.Text)
		}
	}
	return found && text.String() == *reasoning
}

func validateProviderChatToolCalls(state *State, calls []schemas.ChatAssistantMessageToolCall, streaming bool) error {
	if len(calls) > maxClientTools {
		return ErrProviderResponseMalformed
	}
	seen := make(map[uint16]struct{}, len(calls))
	seenIDs := make(map[string]struct{}, len(calls))
	for position, call := range calls {
		if !streaming && call.Index != 0 {
			return ErrProviderResponseMalformed
		}
		index := call.Index
		if !streaming {
			index = uint16(position)
		}
		if int(index) >= maxClientTools {
			return ErrProviderResponseMalformed
		}
		if _, duplicate := seen[index]; duplicate {
			return ErrProviderResponseMalformed
		}
		seen[index] = struct{}{}
		if call.Type != nil && *call.Type != "function" {
			return ErrProviderResponseMalformed
		}
		if rawProviderExtensionSet(call.ExtraContent) {
			return ErrProviderResponseMalformed
		}
		id := ""
		if call.ID != nil {
			id = *call.ID
			if !validProviderResponseID(id) {
				return ErrProviderResponseMalformed
			}
			if _, duplicate := seenIDs[id]; duplicate {
				return ErrProviderResponseMalformed
			}
			seenIDs[id] = struct{}{}
		}
		name := ""
		if call.Function.Name != nil {
			name = *call.Function.Name
			if !validClientToolName(name) || !providerChatToolNameAllowed(state, name) {
				return ErrProviderResponseMalformed
			}
		}
		if !streaming && (call.Type == nil || id == "" || name == "") {
			return ErrProviderResponseMalformed
		}
		if !streaming && !catalog.ValidateJSONObjectText(call.Function.Arguments) {
			return ErrProviderResponseMalformed
		}
		if state == nil {
			if streaming && (call.Type == nil || id == "" || name == "") {
				return ErrProviderResponseMalformed
			}
			continue
		}
		if state.chatToolCalls == nil {
			state.chatToolCalls = make(map[uint16]providerChatToolCall)
		}
		if state.chatToolCallIDs == nil {
			state.chatToolCallIDs = make(map[string]uint16)
		}
		if id != "" {
			if prior, duplicate := state.chatToolCallIDs[id]; duplicate && prior != index {
				return ErrProviderResponseMalformed
			}
			state.chatToolCallIDs[id] = index
		}
		observed, exists := state.chatToolCalls[index]
		if streaming && !exists && (call.Type == nil || id == "" || name == "") {
			return ErrProviderResponseMalformed
		}
		if observed.id != "" && id != "" && observed.id != id || observed.name != "" && name != "" && observed.name != name {
			return ErrProviderResponseMalformed
		}
		if observed.id == "" {
			observed.id = id
		}
		if observed.name == "" {
			observed.name = name
		}
		if observed.arguments == nil {
			observed.arguments = &bytes.Buffer{}
		}
		if !appendProviderBuffer(observed.arguments, call.Function.Arguments) {
			return ErrProviderResponseMalformed
		}
		state.chatToolCalls[index] = observed
	}
	return nil
}

func validateProviderChatContent(content *schemas.ChatMessageContent) error {
	if content == nil {
		return nil
	}
	if content.ContentStr != nil && content.ContentBlocks != nil {
		return ErrProviderResponseMalformed
	}
	if content.ContentStr != nil {
		if !validProviderText(*content.ContentStr, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
		return nil
	}
	if content.ContentBlocks == nil {
		return nil
	}
	if len(content.ContentBlocks) > maxProviderResponseItems {
		return ErrProviderResponseMalformed
	}
	for _, block := range content.ContentBlocks {
		if block.CacheControl != nil || block.Citations != nil ||
			block.PromptCacheBreakpoint != nil || block.CachePoint != nil {
			return ErrProviderResponseMalformed
		}
		switch block.Type {
		case schemas.ChatContentBlockTypeText:
			if block.Text == nil || !validProviderText(*block.Text, maxProviderResponseBodySize, true) ||
				block.Refusal != nil || block.ImageURLStruct != nil || block.InputAudio != nil || block.File != nil {
				return ErrProviderResponseMalformed
			}
		case schemas.ChatContentBlockTypeRefusal:
			if block.Refusal == nil || !validProviderText(*block.Refusal, maxProviderResponseBodySize, true) ||
				block.Text != nil || block.ImageURLStruct != nil || block.InputAudio != nil || block.File != nil {
				return ErrProviderResponseMalformed
			}
		default:
			return ErrProviderResponseMalformed
		}
	}
	return nil
}

func providerChatContentPresent(content *schemas.ChatMessageContent) bool {
	if content == nil {
		return false
	}
	return content.ContentStr != nil && *content.ContentStr != "" || len(content.ContentBlocks) != 0
}

func validateProviderChatAnnotations(state *State, annotations []schemas.ChatAssistantMessageAnnotation) error {
	if len(annotations) == 0 {
		return nil
	}
	if len(annotations) > maxProviderResponseItems || state == nil || state.Resolution == nil ||
		!state.Resolution.HasWebSearchOptions() {
		return ErrProviderResponseMalformed
	}
	for _, annotation := range annotations {
		citation := annotation.URLCitation
		if annotation.Type != "url_citation" || citation.StartIndex < 0 || citation.EndIndex < citation.StartIndex ||
			citation.URL == nil || !validProviderHTTPURL(*citation.URL) || citation.Sources != nil ||
			citation.Type != nil && *citation.Type != "url_citation" ||
			!validProviderText(citation.Title, 64*1024, true) ||
			!validOptionalProviderText(citation.Text, 1024*1024, true) {
			return ErrProviderResponseMalformed
		}
	}
	return nil
}

func validateProviderChatLogProbs(logProbs *schemas.BifrostLogProbs) error {
	if logProbs == nil {
		return nil
	}
	if logProbs.TextCompletionLogProb != nil || len(logProbs.Content) > maxProviderResponseItems ||
		len(logProbs.Refusal) > maxProviderResponseItems {
		return ErrProviderResponseMalformed
	}
	for _, value := range logProbs.Content {
		if !validProviderLogProb(value.Token, value.LogProb, value.Bytes) || len(value.TopLogProbs) > 20 {
			return ErrProviderResponseMalformed
		}
		for _, top := range value.TopLogProbs {
			if !validProviderLogProb(top.Token, top.LogProb, top.Bytes) {
				return ErrProviderResponseMalformed
			}
		}
	}
	for _, value := range logProbs.Refusal {
		if !validProviderLogProb(value.Token, value.LogProb, value.Bytes) {
			return ErrProviderResponseMalformed
		}
	}
	return nil
}

func validateProviderChatToolCompletion(state *State, finishReason string) error {
	if !validProviderFinishReason(state, finishReason) {
		return ErrProviderResponseMalformed
	}
	toolCalls := 0
	if state != nil {
		toolCalls = len(state.chatToolCalls)
		for index := 0; index < toolCalls; index++ {
			call, ok := state.chatToolCalls[uint16(index)]
			if !ok {
				return ErrProviderResponseMalformed
			}
			if call.id == "" || call.name == "" || call.arguments == nil ||
				!catalog.ValidateJSONObjectText(call.arguments.String()) {
				return ErrProviderResponseMalformed
			}
		}
		if providerChatToolCallRequired(state) && toolCalls == 0 {
			return ErrProviderResponseMalformed
		}
		if state.Resolution != nil {
			if raw, ok := state.Resolution.RawBody()["parallel_tool_calls"]; ok && !rawBool(raw) && toolCalls > 1 {
				return ErrProviderResponseMalformed
			}
		}
	}
	if (finishReason == string(schemas.BifrostFinishReasonToolCalls)) != (toolCalls > 0) {
		return ErrProviderResponseMalformed
	}
	return nil
}

func providerChatToolCallRequired(state *State) bool {
	if state == nil || state.Resolution == nil {
		return false
	}
	choice := state.Resolution.RawBody()["tool_choice"]
	if value, ok := rawStringValue(choice); ok {
		return value == "required"
	}
	_, selected := rawObject(choice)
	return selected
}

func validProviderFinishReason(state *State, value string) bool {
	switch value {
	case string(schemas.BifrostFinishReasonStop),
		string(schemas.BifrostFinishReasonLength),
		string(schemas.BifrostFinishReasonToolCalls),
		"content_filter":
		return true
	case "compaction":
		return state != nil && state.Resolution != nil &&
			(state.Resolution.Provider == schemas.Anthropic || state.Resolution.Provider == schemas.Azure) &&
			anthropicContextManagementUsesCompaction(state.Resolution.RawBody()["context_management"])
	default:
		return false
	}
}

func providerChatToolNameAllowed(state *State, name string) bool {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteChat {
		return false
	}
	declared := false
	for _, tool := range state.Resolution.RawTools() {
		if rawString(tool["type"]) != "function" {
			continue
		}
		function, ok := rawObject(tool["function"])
		if ok && rawString(function["name"]) == name {
			declared = true
			break
		}
	}
	if !declared {
		return false
	}
	choice := state.Resolution.RawBody()["tool_choice"]
	if selected, ok := rawStringValue(choice); ok {
		return selected != "none"
	}
	object, ok := rawObject(choice)
	if !ok {
		return true
	}
	function, ok := rawObject(object["function"])
	return !ok || rawString(function["name"]) == name
}
