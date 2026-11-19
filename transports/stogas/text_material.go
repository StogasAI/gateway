package stogas

import "github.com/maximhq/bifrost/core/schemas"

// Text material is independent of billing usage. Keep exact UTF-8 byte counts;
// presentation divides by four. Summaries and ciphertext cannot measure reasoning.
type textMaterial struct {
	output, reasoning int
	visible, opaque   int
}

func (m *textMaterial) add(other textMaterial, sign int) {
	m.output += sign * other.output
	m.reasoning += sign * other.reasoning
	m.visible += sign * other.visible
	m.opaque += sign * other.opaque
}

func textBytes(text *string) int {
	return len(stringValue(text))
}

func stringValue(text *string) string {
	if text == nil {
		return ""
	}
	return *text
}

// textSource names one text of a response, which its pieces continue: the content, a refusal or
// a tool call of a Chat choice, or a part, a tool value or a patch's path of a Responses item.
type textSource struct {
	kind       textSourceKind
	item, part int
}

type textSourceKind uint8

const (
	chatContent textSourceKind = iota
	chatRefusal
	chatCall
	responsesPart
	responsesValue
	responsesPath
)

// chatOutputText visits the output text of a Chat choice: the content and refusals that a person
// reads, the reply, and the arguments of its tool calls.
func chatOutputText(choice *schemas.BifrostResponseChoice, visit func(source textSource, text string, reply bool)) {
	if stream := choice.ChatStreamResponseChoice; stream != nil && stream.Delta != nil {
		delta := stream.Delta
		visit(textSource{kind: chatContent, part: -1}, stringValue(delta.Content), true)
		visit(textSource{kind: chatRefusal, part: -1}, stringValue(delta.Refusal), true)
		for _, call := range delta.ToolCalls {
			visit(textSource{kind: chatCall, item: int(call.Index)}, call.Function.Arguments, false)
		}
	}
	if unary := choice.ChatNonStreamResponseChoice; unary != nil && unary.Message != nil {
		message := unary.Message
		if content := message.Content; content != nil {
			visit(textSource{kind: chatContent, part: -1}, stringValue(content.ContentStr), true)
			for i, block := range content.ContentBlocks {
				visit(textSource{kind: chatContent, part: i}, stringValue(block.Text), true)
				visit(textSource{kind: chatRefusal, part: i}, stringValue(block.Refusal), true)
			}
		}
		if assistant := message.ChatAssistantMessage; assistant != nil {
			visit(textSource{kind: chatRefusal, part: -1}, stringValue(assistant.Refusal), true)
			for i, call := range assistant.ToolCalls {
				visit(textSource{kind: chatCall, item: i}, call.Function.Arguments, false)
			}
		}
	}
}

// responsesItemOutputText visits the output text of the Responses item at index: the text and
// refusals of a message, the reply, and the values of a tool call.
func responsesItemOutputText(index int, item *schemas.ResponsesMessage, visit func(source textSource, text string, reply bool)) {
	if item == nil || item.Type == nil {
		return
	}
	if item.Content != nil {
		for i, block := range item.Content.ContentBlocks {
			source := textSource{kind: responsesPart, item: index, part: i}
			switch block.Type {
			case schemas.ResponsesOutputMessageContentTypeText:
				visit(source, stringValue(block.Text), true)
			case schemas.ResponsesOutputMessageContentTypeRefusal:
				if block.ResponsesOutputMessageContentRefusal != nil {
					visit(source, block.Refusal, true)
				}
			}
		}
	}
	tool := item.ResponsesToolMessage
	if tool == nil {
		return
	}
	source := textSource{kind: responsesValue, item: index}
	switch *item.Type {
	case schemas.ResponsesMessageTypeFunctionCall:
		visit(source, stringValue(tool.Arguments), false)
	case schemas.ResponsesMessageTypeCustomToolCall:
		if tool.ResponsesCustomToolCall != nil {
			visit(source, tool.ResponsesCustomToolCall.Input, false)
		}
	case schemas.ResponsesMessageTypeShellCall:
		for i, command := range providerShellCommands(item) {
			visit(textSource{kind: responsesValue, item: index, part: i}, command, false)
		}
	case schemas.ResponsesMessageTypeApplyPatchCall:
		if call := tool.ResponsesApplyPatchCall; call != nil && call.Operation != nil {
			visit(textSource{kind: responsesPath, item: index}, call.Operation.Path, false)
			visit(source, stringValue(call.Operation.Diff), false)
		}
	}
}

// responsesOutputDelta reports whether a Responses stream event's delta continues output text,
// and whether that text is the reply.
func responsesOutputDelta(eventType schemas.ResponsesStreamResponseType) (output, reply bool) {
	switch eventType {
	case schemas.ResponsesStreamResponseTypeOutputTextDelta, schemas.ResponsesStreamResponseTypeRefusalDelta:
		return true, true
	case schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta,
		schemas.ResponsesStreamResponseTypeCustomToolCallInputDelta,
		schemas.ResponsesStreamResponseTypeShellCallCommandDelta,
		schemas.ResponsesStreamResponseTypeApplyPatchCallOperationDiffDelta:
		return true, false
	}
	return false, false
}

// keepClientStopText keeps the text material that a stopped client had received, before text
// that arrives after it stopped counts. Only the goroutine that observes text calls it.
func (s *State) keepClientStopText() {
	if s.clientStopTextTaken {
		return
	}
	if s.ClientStopped().IsZero() {
		return
	}
	s.clientStopText, s.clientStopTextObserved, s.clientStopTextTaken = s.textMaterial, s.textMaterialObserved, true
}

// clientStopTextMaterial is the text material that a client which stopped early had received:
// everything observed when no text arrived after it stopped.
func (s *State) clientStopTextMaterial() (textMaterial, bool) {
	if s.clientStopTextTaken {
		return s.clientStopText, s.clientStopTextObserved
	}
	return s.textMaterial, s.textMaterialObserved
}

func (s *State) observeChatTextMaterial(response *schemas.BifrostChatResponse) {
	if response == nil || len(response.Choices) == 0 {
		return
	}
	s.keepClientStopText()
	var material textMaterial
	for i := range response.Choices {
		choice := &response.Choices[i]
		chatOutputText(choice, func(_ textSource, text string, _ bool) { material.output += len(text) })
		var details []schemas.ChatReasoningDetails
		var reasoning *string
		if stream := choice.ChatStreamResponseChoice; stream != nil && stream.Delta != nil {
			details, reasoning = stream.Delta.ReasoningDetails, stream.Delta.Reasoning
		}
		if unary := choice.ChatNonStreamResponseChoice; unary != nil && unary.Message != nil && unary.Message.ChatAssistantMessage != nil {
			assistant := unary.Message.ChatAssistantMessage
			details, reasoning = assistant.ReasoningDetails, assistant.Reasoning
		}
		// The reasoning string repeats the text of its details, then holds Claude's thinking
		// that has no detail (validateProviderChatMessage), so the longer of the two counts.
		detailText := 0
		for _, detail := range details {
			switch detail.Type {
			case schemas.BifrostReasoningDetailsTypeText:
				if detail.Text != nil {
					detailText += len(*detail.Text)
					material.visible = 1
				}
			case schemas.BifrostReasoningDetailsTypeSummary, schemas.BifrostReasoningDetailsTypeEncrypted:
				material.opaque = 1
			}
		}
		if textBytes(reasoning) > 0 {
			material.visible = 1
		}
		material.reasoning += max(detailText, textBytes(reasoning))
	}
	s.textMaterial.add(material, 1)
	s.textMaterialObserved = true
}

func responsesItemTextMaterial(item *schemas.ResponsesMessage) textMaterial {
	var material textMaterial
	if item == nil || item.Type == nil {
		return material
	}
	responsesItemOutputText(0, item, func(_ textSource, text string, _ bool) { material.output += len(text) })
	if item.Content != nil {
		for _, block := range item.Content.ContentBlocks {
			if block.Type == schemas.ResponsesOutputMessageContentTypeReasoning {
				material.reasoning += textBytes(block.Text)
				material.visible = 1
			}
		}
	}
	if item.ResponsesReasoning != nil && (len(item.ResponsesReasoning.Summary) > 0 || item.ResponsesReasoning.EncryptedContent != nil) {
		material.opaque = 1
	}
	return material
}

func (s *State) observeResponsesTextMaterial(response *schemas.BifrostResponsesResponse) {
	if response == nil {
		return
	}
	s.keepClientStopText()
	s.textMaterial = textMaterial{}
	for i := range response.Output {
		s.textMaterial.add(responsesItemTextMaterial(&response.Output[i]), 1)
	}
	s.textMaterialObserved = true
	s.responsesTextMaterial = nil
}

func (s *State) observeResponsesStreamTextMaterial(event *schemas.BifrostResponsesStreamResponse) {
	if event == nil {
		return
	}
	s.keepClientStopText()
	if event.Type == schemas.ResponsesStreamResponseTypeCompleted || event.Type == schemas.ResponsesStreamResponseTypeIncomplete {
		// The validated terminal snapshot replaces accumulated deltas, so echoes
		// and item-done snapshots never count the same text twice.
		s.observeResponsesTextMaterial(event.Response)
		return
	}
	if event.OutputIndex == nil {
		return
	}
	index := *event.OutputIndex
	previous := s.responsesTextMaterial[index]
	current := previous
	switch output, _ := responsesOutputDelta(event.Type); {
	case output:
		current.output += textBytes(event.Delta)
	case event.Type == schemas.ResponsesStreamResponseTypeOutputItemAdded, event.Type == schemas.ResponsesStreamResponseTypeOutputItemDone:
		current = responsesItemTextMaterial(event.Item)
	case event.Type == schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded,
		event.Type == schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta:
		current.opaque = 1
	case event.Type == schemas.ResponsesStreamResponseTypeReasoningTextDelta:
		current.reasoning += textBytes(event.Delta)
		current.visible = 1
	case event.Type == schemas.ResponsesStreamResponseTypeContentPartAdded:
		if event.Part != nil && event.Part.Type == schemas.ResponsesOutputMessageContentTypeReasoning {
			current.visible = 1
		}
	default:
		return
	}
	if s.responsesTextMaterial == nil {
		s.responsesTextMaterial = make(map[int]textMaterial)
	}
	s.responsesTextMaterial[index] = current
	s.textMaterial.add(previous, -1)
	s.textMaterial.add(current, 1)
	s.textMaterialObserved = true
}

func (s *State) reasoningTextBytes() (int, bool) {
	return s.reasoningBytes(s.textMaterial, s.textMaterialObserved)
}

func (s *State) reasoningBytes(material textMaterial, observed bool) (int, bool) {
	if !observed || material.opaque > 0 {
		return 0, false
	}
	// Native Claude thinking is summarized even when core labels it text.
	if responsesUsesAnthropicWire(s) && (material.visible > 0 || s.Resolution.Deployment.ReasoningSupported) {
		return 0, false
	}
	if material.visible > 0 {
		return material.reasoning, true
	}
	if s.Resolution != nil && !s.Resolution.Deployment.ReasoningSupported {
		return 0, true
	}
	return 0, false
}
