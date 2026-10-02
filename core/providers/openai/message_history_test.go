package openai

import (
	"encoding/json"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestOpenAIMessageHistoryCodecPreservesNeutralFieldsAndOmitsStreamIndex(t *testing.T) {
	input := []byte(`{"role":"assistant","content":null,"reasoning":"thought","reasoning_details":[{"index":0,"type":"reasoning.text","text":"thought","signature":"sig"}],"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"},"extra_content":{"google":{"thought_signature":"sig"}}}]}`)
	var message OpenAIMessage
	if err := json.Unmarshal(input, &message); err != nil {
		t.Fatalf("unmarshal assistant history: %v", err)
	}
	neutral := ConvertOpenAIMessagesToBifrostMessages([]OpenAIMessage{message})
	if len(neutral) != 1 || neutral[0].ChatAssistantMessage == nil || neutral[0].Reasoning == nil || *neutral[0].Reasoning != "thought" || len(neutral[0].ReasoningDetails) != 1 || len(neutral[0].ToolCalls) != 1 {
		t.Fatalf("assistant history fields were not preserved: %#v", neutral)
	}
	neutral[0].ToolCalls[0].Index = 7
	message = ConvertBifrostMessagesToOpenAIMessages(neutral)[0]
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
	if extra, ok := toolCall["extra_content"].(map[string]any); !ok || extra["google"].(map[string]any)["thought_signature"] != "sig" {
		t.Fatalf("provider tool-call metadata was lost: %s", wire)
	}

	if _, exists := toolCall["index"]; exists {
		t.Fatalf("stream-only tool-call index leaked to request wire: %s", wire)
	}
}
