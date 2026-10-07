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
	if text == nil {
		return 0
	}
	return len(*text)
}

func (s *State) observeChatTextMaterial(response *schemas.BifrostChatResponse) {
	if response == nil || len(response.Choices) == 0 {
		return
	}
	var material textMaterial
	for _, choice := range response.Choices {
		var details []schemas.ChatReasoningDetails
		var calls []schemas.ChatAssistantMessageToolCall
		if stream := choice.ChatStreamResponseChoice; stream != nil && stream.Delta != nil {
			delta := stream.Delta
			material.output += textBytes(delta.Content) + textBytes(delta.Refusal)
			details, calls = delta.ReasoningDetails, delta.ToolCalls
		}
		if unary := choice.ChatNonStreamResponseChoice; unary != nil && unary.Message != nil {
			message := unary.Message
			if content := message.Content; content != nil {
				material.output += textBytes(content.ContentStr)
				for _, block := range content.ContentBlocks {
					material.output += textBytes(block.Text) + textBytes(block.Refusal)
				}
			}
			if assistant := message.ChatAssistantMessage; assistant != nil {
				material.output += textBytes(assistant.Refusal)
				details, calls = assistant.ReasoningDetails, assistant.ToolCalls
			}
		}
		for _, call := range calls {
			material.output += len(call.Function.Arguments)
		}
		// The convenience reasoning string repeats reasoning.text details.
		for _, detail := range details {
			switch detail.Type {
			case schemas.BifrostReasoningDetailsTypeText:
				if detail.Text != nil {
					material.reasoning += len(*detail.Text)
					material.visible = 1
				}
			case schemas.BifrostReasoningDetailsTypeSummary, schemas.BifrostReasoningDetailsTypeEncrypted:
				material.opaque = 1
			}
		}
	}
	s.textMaterial.add(material, 1)
	s.textMaterialObserved = true
}

func responsesItemTextMaterial(item *schemas.ResponsesMessage) textMaterial {
	var material textMaterial
	if item == nil || item.Type == nil {
		return material
	}
	if item.Content != nil {
		for _, block := range item.Content.ContentBlocks {
			switch block.Type {
			case schemas.ResponsesOutputMessageContentTypeText:
				material.output += textBytes(block.Text)
			case schemas.ResponsesOutputMessageContentTypeRefusal:
				if block.ResponsesOutputMessageContentRefusal != nil {
					material.output += len(block.Refusal)
				}
			case schemas.ResponsesOutputMessageContentTypeReasoning:
				if block.Text != nil {
					material.reasoning += len(*block.Text)
					material.visible = 1
				}
				if block.EncryptedContent != nil {
					material.opaque = 1
				}
			}
		}
	}
	if item.ResponsesReasoning != nil && (len(item.ResponsesReasoning.Summary) > 0 || item.ResponsesReasoning.EncryptedContent != nil) {
		material.opaque = 1
	}
	if tool := item.ResponsesToolMessage; tool != nil {
		switch *item.Type {
		case schemas.ResponsesMessageTypeFunctionCall:
			material.output += textBytes(tool.Arguments)
		case schemas.ResponsesMessageTypeCustomToolCall:
			if tool.ResponsesCustomToolCall != nil {
				material.output += len(tool.ResponsesCustomToolCall.Input)
			}
		case schemas.ResponsesMessageTypeCodeInterpreterCall:
			if tool.ResponsesCodeInterpreterToolCall != nil {
				material.output += textBytes(tool.Code)
			}
		}
	}
	return material
}

func (s *State) observeResponsesTextMaterial(response *schemas.BifrostResponsesResponse) {
	if response == nil {
		return
	}
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
	switch event.Type {
	case schemas.ResponsesStreamResponseTypeOutputItemAdded, schemas.ResponsesStreamResponseTypeOutputItemDone:
		current = responsesItemTextMaterial(event.Item)
	case schemas.ResponsesStreamResponseTypeOutputTextDelta:
		current.output += textBytes(event.Delta)
	case schemas.ResponsesStreamResponseTypeRefusalDelta,
		schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta,
		schemas.ResponsesStreamResponseTypeCustomToolCallInputDelta,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDelta:
		current.output += textBytes(event.Delta)
	case schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta:
		// Core uses these events for both summaries and raw content blocks.
		// SummaryIndex identifies summaries; ContentIndex identifies content.
		if event.SummaryIndex != nil {
			current.opaque = 1
		} else if event.ContentIndex != nil {
			current.reasoning += textBytes(event.Delta)
			current.visible = 1
		}
	case schemas.ResponsesStreamResponseTypeContentPartAdded:
		if event.Part != nil && event.Part.Type == schemas.ResponsesOutputMessageContentTypeReasoning {
			if event.Part.Text != nil {
				current.visible = 1
			}
			if event.Part.EncryptedContent != nil {
				current.opaque = 1
			}
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
	if !s.textMaterialObserved || s.textMaterial.opaque > 0 {
		return 0, false
	}
	// Native Claude thinking is summarized even when core labels it text.
	if responsesUsesAnthropicWire(s) && (s.textMaterial.visible > 0 || s.Resolution.Deployment.ReasoningSupported) {
		return 0, false
	}
	if s.textMaterial.visible > 0 {
		return s.textMaterial.reasoning, true
	}
	if s.Resolution != nil && !s.Resolution.Deployment.ReasoningSupported {
		return 0, true
	}
	return 0, false
}
