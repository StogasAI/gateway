package stogas

import (
	"encoding/json"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestChatTextMaterialSeparatesReasoningAndToolArguments(t *testing.T) {
	var response schemas.BifrostChatResponse
	if err := json.Unmarshal([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"café","reasoning":"推理","reasoning_details":[{"index":0,"type":"reasoning.text","text":"推理"}],"tool_calls":[{"type":"function","function":{"name":"lookup","arguments":"{}"}}]}}]}`), &response); err != nil {
		t.Fatal(err)
	}
	state := chatResponseValidationState()
	state.Resolution.Deployment.ReasoningSupported = true
	state.observeChatTextMaterial(&response)
	meters := metersForState(state)
	if meters[billing.MeterOutputTextBytes].Quantity != "7" || meters[billing.MeterReasoningTextBytes].Quantity != "6" {
		t.Fatalf("UTF-8 content/arguments and reasoning must be counted once: %#v", meters)
	}
	if _, exists := meters[billing.MeterInputTextBytes]; exists {
		t.Fatal("output must not invent input material")
	}
	for _, provider := range []schemas.ModelProvider{schemas.Anthropic, schemas.Azure} {
		state.Resolution.Provider = provider
		state.Resolution.Deployment.Upstream.ModelFormat = "Anthropic"
		if _, known := state.reasoningTextBytes(); known {
			t.Fatalf("%s native thinking summary counted as complete reasoning", provider)
		}
	}
}

func TestTextMaterialUnknownAndKnownEmpty(t *testing.T) {
	for _, kind := range []schemas.BifrostReasoningDetailsType{schemas.BifrostReasoningDetailsTypeSummary, schemas.BifrostReasoningDetailsTypeEncrypted} {
		state := chatResponseValidationState()
		response := validUnaryChatProviderResponse()
		response.Choices[0].Message.ChatAssistantMessage = &schemas.ChatAssistantMessage{
			ReasoningDetails: []schemas.ChatReasoningDetails{
				{Type: schemas.BifrostReasoningDetailsTypeText, Text: schemas.Ptr("visible")},
				{Type: kind, Summary: schemas.Ptr("summary"), Data: schemas.Ptr("ciphertext")},
			},
		}
		state.observeChatTextMaterial(response)
		if _, known := state.reasoningTextBytes(); known {
			t.Fatalf("%s must leave reasoning unknown", kind)
		}
		if _, present := metersForState(state)[billing.MeterReasoningTextBytes]; present {
			t.Fatal("unknown reasoning must not become zero")
		}
	}
	state := chatResponseValidationState()
	if _, known := state.reasoningTextBytes(); known {
		t.Fatal("no response must remain unknown")
	}
	state.observeChatTextMaterial(validUnaryChatProviderResponse())
	if bytes, known := state.reasoningTextBytes(); !known || bytes != 0 {
		t.Fatalf("nonreasoning response = %d, %v; want known zero", bytes, known)
	}
	state.Resolution.Deployment.ReasoningSupported = true
	if _, known := state.reasoningTextBytes(); known {
		t.Fatal("absence of reasoning text on a reasoning model must remain unknown")
	}
}

func TestResponsesTextMaterialReplacesStreamSnapshots(t *testing.T) {
	state := responsesValidationState()
	index := 0
	item := &schemas.ResponsesMessage{
		Type: schemas.Ptr(schemas.ResponsesMessageTypeMessage),
		Content: &schemas.ResponsesMessageContent{ContentBlocks: []schemas.ResponsesMessageContentBlock{
			{Type: schemas.ResponsesOutputMessageContentTypeText, Text: schemas.Ptr("café")},
		}},
	}
	state.observeResponsesStreamTextMaterial(&schemas.BifrostResponsesStreamResponse{
		Type: schemas.ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: &index,
		Item: &schemas.ResponsesMessage{Type: item.Type},
	})
	for _, delta := range []string{"caf", "é"} {
		state.observeResponsesStreamTextMaterial(&schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeOutputTextDelta, OutputIndex: &index, Delta: &delta,
		})
	}
	if state.textMaterial.output != 5 {
		t.Fatalf("partial stream bytes = %d, want 5", state.textMaterial.output)
	}
	state.observeResponsesStreamTextMaterial(&schemas.BifrostResponsesStreamResponse{
		Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &index, Item: item,
	})
	terminal := &schemas.BifrostResponsesResponse{Output: []schemas.ResponsesMessage{*item}}
	for _, status := range []schemas.ResponsesStreamResponseType{schemas.ResponsesStreamResponseTypeCompleted, schemas.ResponsesStreamResponseTypeIncomplete} {
		state.observeResponsesStreamTextMaterial(&schemas.BifrostResponsesStreamResponse{Type: status, Response: terminal})
		if state.textMaterial.output != 5 || state.responsesTextMaterial != nil {
			t.Fatalf("snapshot double-counted text or retained item counters: %#v", state.textMaterial)
		}
	}
	unary := responsesValidationState()
	unary.observeResponsesTextMaterial(terminal)
	if unary.textMaterial != state.textMaterial {
		t.Fatal("unary and streamed text material differ")
	}
}

func TestResponsesReasoningContentAndSummaries(t *testing.T) {
	state := responsesValidationState()
	state.Resolution.Deployment.ReasoningSupported = true
	index := 0
	state.observeResponsesStreamTextMaterial(&schemas.BifrostResponsesStreamResponse{
		Type:        schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		OutputIndex: &index, ContentIndex: &index, Delta: schemas.Ptr("推理"),
	})
	if bytes, known := state.reasoningTextBytes(); !known || bytes != 6 {
		t.Fatalf("raw content bytes = %d, %v", bytes, known)
	}
	state.observeResponsesStreamTextMaterial(&schemas.BifrostResponsesStreamResponse{
		Type:        schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		OutputIndex: &index, SummaryIndex: &index, Delta: schemas.Ptr("summary"),
	})
	if _, known := state.reasoningTextBytes(); known {
		t.Fatal("summary must leave reasoning unknown")
	}
	state.observeResponsesTextMaterial(&schemas.BifrostResponsesResponse{Output: []schemas.ResponsesMessage{{
		Type:               schemas.Ptr(schemas.ResponsesMessageTypeReasoning),
		ResponsesReasoning: &schemas.ResponsesReasoning{EncryptedContent: schemas.Ptr("ciphertext")},
	}}})
	if _, known := state.reasoningTextBytes(); known || state.textMaterial.output != 0 {
		t.Fatal("encrypted reasoning must not contribute standard text units")
	}
}

func TestTextMaterialOnlyObservesAcceptedProviderOutput(t *testing.T) {
	state := chatResponseValidationState()
	response := validUnaryChatProviderResponse()
	response.Choices[0].Message.Content = &schemas.ChatMessageContent{ContentStr: schemas.Ptr("café")}
	response.Object = "invalid"
	adapter := DefaultAdapter{}
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ChatResponse: response}, nil); err == nil {
		t.Fatal("invalid response accepted")
	}
	if state.textMaterialObserved {
		t.Fatal("invalid response contributed text material")
	}
	response.Object = "chat.completion"
	if err := adapter.IngestResponse(state, &schemas.BifrostResponse{ChatResponse: response}, nil); err != nil {
		t.Fatal(err)
	}
	if metersForState(state)[billing.MeterOutputTextBytes].Quantity != "5" {
		t.Fatal("accepted output not counted")
	}
}

func TestResponsesGeneratedToolTextAndRefusals(t *testing.T) {
	for _, test := range []struct {
		name, body string
		bytes      int
	}{
		{"function arguments", `{"type":"function_call","arguments":"{\"q\":\"é\"}"}`, 10},
		{"custom input", `{"type":"custom_tool_call","input":"café"}`, 5},
		{"generated code", `{"type":"code_interpreter_call","code":"print('é')"}`, 11},
		{"refusal", `{"type":"message","content":[{"type":"refusal","refusal":"Non."}]}`, 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			var item schemas.ResponsesMessage
			if err := json.Unmarshal([]byte(test.body), &item); err != nil {
				t.Fatal(err)
			}
			if got := responsesItemTextMaterial(&item); got.output != test.bytes || got.reasoning != 0 {
				t.Fatalf("material = %#v, want %d output bytes", got, test.bytes)
			}
		})
	}
}

func TestChatStreamingTextMaterialRetainsPrefixAfterError(t *testing.T) {
	state := chatResponseValidationState()
	adapter := DefaultAdapter{}
	for index, text := range []string{"caf", "é"} {
		chunk := validChatProviderChunk("chat_stream", false)
		if index > 0 {
			chunk.Choices[0].Delta.Role = nil
		}
		chunk.Choices[0].Delta.Content = &text
		if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
			t.Fatal(err)
		}
	}
	if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostError: &schemas.BifrostError{}}); err != nil {
		t.Fatal(err)
	}
	if metersForState(state)[billing.MeterOutputTextBytes].Quantity != "5" {
		t.Fatal("stream error lost observed UTF-8 text")
	}
}
