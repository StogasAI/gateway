package gemini

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// TestStreamReasoningDetailsKeepOneIndex streams thought text over two chunks, then a function call
// with a signature and a closing text signature, as Agent Platform does, with the role in every
// chunk. Clients join a stream's reasoning details by index, so the thought text keeps one index
// and each signature gets its own, and only the first delta carries the role.
func TestStreamReasoningDetailsKeepOneIndex(t *testing.T) {
	chunks := []string{
		`{"candidates":[{"content":{"role":"model","parts":[{"text":"Plan ","thought":true},{"text":"the call.","thought":true}]}}]}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"text":" Then answer.","thought":true}]}}]}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"id":"call_1","name":"get_weather","args":{"city":"Paris"}},"thoughtSignature":"AQID"}]}}]}`,
		`{"candidates":[{"content":{"role":"model","parts":[{"text":"","thoughtSignature":"BAUG"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":1,"totalTokenCount":4}}`,
	}
	state := NewGeminiStreamState()
	type detail struct {
		index           int
		kind, text, sig string
	}
	var got []detail
	roles := 0
	for _, raw := range chunks {
		response := &GenerateContentResponse{}
		if err := json.Unmarshal([]byte(raw), response); err != nil {
			t.Fatal(err)
		}
		converted, bifrostErr, _ := response.ToBifrostChatCompletionStream(state)
		if bifrostErr != nil {
			t.Fatal(bifrostErr.Error.Message)
		}
		for _, chunk := range converted {
			if chunk.Choices[0].ChatStreamResponseChoice.Delta.Role != nil {
				roles++
			}
			for _, d := range chunk.Choices[0].ChatStreamResponseChoice.Delta.ReasoningDetails {
				entry := detail{index: d.Index, kind: string(d.Type)}
				if d.Text != nil {
					entry.text = *d.Text
				}
				if d.Signature != nil {
					entry.sig = *d.Signature
				}
				got = append(got, entry)
			}
		}
	}
	want := []detail{
		{0, "reasoning.text", "Plan the call.", ""},
		{0, "reasoning.text", " Then answer.", ""},
		{1, "reasoning.encrypted", "", "AQID"},
		{2, "reasoning.encrypted", "", "BAUG"},
	}
	if len(got) != len(want) || roles != 1 {
		t.Fatalf("details = %+v, %d deltas with the role", got, roles)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("detail %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestTextSignatureGoesBackOnTheLastTextPart converts an assistant message whose text Gemini signed
// back to Gemini: the signature that names no tool call returns on the message's last text part,
// and the signature of a function call stays on the call.
func TestTextSignatureGoesBackOnTheLastTextPart(t *testing.T) {
	text, call := []byte{1, 2, 3}, []byte{4, 5, 6}
	request, err := ToGeminiChatCompletionRequest(nil, &schemas.BifrostChatRequest{
		Model: "gemini-3.8-flash",
		Input: []schemas.ChatMessage{
			{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Hi.")}},
			{
				Role: schemas.ChatMessageRoleAssistant,
				Content: &schemas.ChatMessageContent{ContentBlocks: []schemas.ChatContentBlock{
					{Type: schemas.ChatContentBlockTypeText, Text: schemas.Ptr("Hello.")},
					{Type: schemas.ChatContentBlockTypeText, Text: schemas.Ptr("Ask me anything.")},
				}},
				ChatAssistantMessage: &schemas.ChatAssistantMessage{
					ReasoningDetails: []schemas.ChatReasoningDetails{
						{Index: 0, Type: schemas.BifrostReasoningDetailsTypeSummary, Summary: schemas.Ptr("Greet.")},
						{Index: 1, Type: schemas.BifrostReasoningDetailsTypeEncrypted, Signature: schemas.Ptr(base64.StdEncoding.EncodeToString(text))},
						{Index: 2, Type: schemas.BifrostReasoningDetailsTypeEncrypted, ID: schemas.Ptr("tool_call_call_1"), Signature: schemas.Ptr(base64.StdEncoding.EncodeToString(call))},
					},
					ToolCalls: []schemas.ChatAssistantMessageToolCall{{
						ID:       schemas.Ptr("call_1"),
						Type:     schemas.Ptr("function"),
						Function: schemas.ChatAssistantMessageToolCallFunction{Name: schemas.Ptr("get_weather"), Arguments: `{"city":"Paris"}`},
					}},
				},
			},
			{Role: schemas.ChatMessageRoleTool, ChatToolMessage: &schemas.ChatToolMessage{ToolCallID: schemas.Ptr("call_1")}, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Sunny.")}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := request.Contents[1].Parts
	if len(parts) != 3 || parts[0].ThoughtSignature != nil || string(parts[1].ThoughtSignature) != string(text) ||
		parts[2].FunctionCall == nil || string(parts[2].ThoughtSignature) != string(call) {
		encoded, _ := json.Marshal(parts)
		t.Fatalf("model parts = %s", encoded)
	}
}
