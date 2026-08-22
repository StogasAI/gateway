package openai

import (
	"encoding/json"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestOpenAIMessageHistoryCodecPreservesNeutralFieldsAndOmitsStreamIndex(t *testing.T) {
	input := []byte(`{"role":"assistant","content":null,"reasoning":"thought","reasoning_details":[{"index":0,"type":"reasoning.text","text":"thought","signature":"sig"}],"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]}`)
	var message OpenAIMessage
	if err := json.Unmarshal(input, &message); err != nil {
		t.Fatalf("unmarshal assistant history: %v", err)
	}
	if message.OpenAIChatAssistantMessage == nil || message.OpenAIChatAssistantMessage.Reasoning == nil || *message.OpenAIChatAssistantMessage.Reasoning != "thought" || len(message.OpenAIChatAssistantMessage.ReasoningDetails) != 1 || len(message.OpenAIChatAssistantMessage.ToolCalls) != 1 {
		t.Fatalf("assistant history fields were not preserved: %#v", message.OpenAIChatAssistantMessage)
	}
	message.OpenAIChatAssistantMessage.ToolCalls[0].Index = 7
	wire, err := json.Marshal(message)
	if err != nil {
		t.Fatalf("marshal assistant history: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("decode assistant wire: %v", err)
	}
	if decoded["role"] != string(schemas.ChatMessageRoleAssistant) || decoded["reasoning_content"] != "thought" {
		t.Fatalf("common assistant fields changed: %#v", decoded)
	}
	if _, exists := decoded["reasoning_details"]; exists {
		t.Fatalf("neutral reasoning_details leaked to OpenAI wire: %s", wire)
	}
	toolCalls, ok := decoded["tool_calls"].([]any)
	if !ok || len(toolCalls) != 1 {
		t.Fatalf("tool calls changed: %#v", decoded["tool_calls"])
	}
	toolCall, ok := toolCalls[0].(map[string]any)
	if !ok || toolCall["id"] != "call_1" || toolCall["type"] != "function" {
		t.Fatalf("tool call changed: %#v", toolCalls[0])
	}
	if _, exists := toolCall["index"]; exists {
		t.Fatalf("stream-only tool-call index leaked to request wire: %s", wire)
	}
}
