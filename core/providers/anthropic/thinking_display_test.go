package anthropic

import (
	"encoding/json"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestThinkingDisplayPreservesProviderDefaultAndExplicitChoices(t *testing.T) {
	for _, model := range []string{"claude-opus-4-7", "claude-opus-4-8", "claude-sonnet-4-6"} {
		for _, display := range []string{"", "omitted", "summarized"} {
			t.Run(model+"/"+display, func(t *testing.T) {
				reasoning := &schemas.ChatReasoning{Effort: schemas.Ptr("high")}
				responseReasoning := &schemas.ResponsesParametersReasoning{Effort: schemas.Ptr("high")}
				thinking := map[string]any{"type": "adaptive"}
				if display != "" {
					reasoning.Display = &display
					thinking["display"] = display
					summary := "auto"
					if display == "omitted" {
						summary = "none"
					}
					responseReasoning.Summary = &summary
				}
				chat, err := ToAnthropicChatRequest(testCtx(), chatReq(model, reasoning, schemas.Ptr(8192)))
				if err != nil {
					t.Fatal(err)
				}
				nativeRequest := chatReq(model, nil, schemas.Ptr(8192))
				nativeRequest.Params.ExtraParams = map[string]any{"thinking": thinking}
				native, err := ToAnthropicChatRequest(testCtx(), nativeRequest)
				if err != nil {
					t.Fatal(err)
				}
				responses, err := ToAnthropicResponsesRequest(testCtx(), &schemas.BifrostResponsesRequest{
					Provider: schemas.Anthropic, Model: model,
					Params: &schemas.ResponsesParameters{Reasoning: responseReasoning, MaxOutputTokens: schemas.Ptr(8192)},
				})
				if err != nil {
					t.Fatal(err)
				}
				for name, request := range map[string]*AnthropicMessageRequest{"chat": chat, "native": native, "responses": responses} {
					body, err := json.Marshal(request)
					if err != nil {
						t.Fatal(err)
					}
					var wire struct{ Thinking map[string]any }
					if err := json.Unmarshal(body, &wire); err != nil {
						t.Fatal(err)
					}
					if wire.Thinking["type"] != "adaptive" {
						t.Fatalf("%s thinking mode changed: %s", name, body)
					}
					got, present := wire.Thinking["display"]
					if display == "" && present || display != "" && got != display {
						t.Errorf("%s display = %v (present %v), want %q", name, got, present, display)
					}
				}
			})
		}
	}
}
