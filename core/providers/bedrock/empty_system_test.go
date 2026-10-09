package bedrock

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestChatConversionPreservesUserAfterEmptySystemMessage(t *testing.T) {
	for _, role := range []string{"system", "developer"} {
		for _, content := range []string{"", `,"content":null`, `,"content":"instruction"`} {
			t.Run(role+content, func(t *testing.T) {
				var messages []schemas.ChatMessage
				if err := json.Unmarshal([]byte(fmt.Sprintf(`[{"role":%q%s},{"role":"user","content":"hello"}]`, role, content)), &messages); err != nil {
					t.Fatal(err)
				}
				ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				request, err := ToBedrockChatCompletionRequest(ctx, &schemas.BifrostChatRequest{
					Provider: schemas.Bedrock, Model: "anthropic.claude-sonnet-4-6", Input: messages,
				})
				if err != nil {
					t.Fatal(err)
				}
				if len(request.Messages) != 1 || len(request.Messages[0].Content) != 1 || request.Messages[0].Content[0].Text == nil || *request.Messages[0].Content[0].Text != "hello" {
					t.Fatalf("user content changed: %#v", request.Messages)
				}
				if content == `,"content":"instruction"` {
					if len(request.System) != 1 || request.System[0].Text == nil || *request.System[0].Text != "instruction" {
						t.Fatalf("system content lost: %#v", request.System)
					}
				} else if len(request.System) != 0 {
					t.Fatalf("empty system content emitted: %#v", request.System)
				}
			})
		}
	}
}
