package stogas

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/providers/anthropic"
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
)

// cutToolCallRequest is the recorded request of the capture as a client sends it to the gateway.
func cutToolCallRequest(t *testing.T, recorded providerExchange) string {
	model := `"provider:openai gpt-5.5"`
	if recorded.Request.Path == "/v1/chat/completions" {
		model = `"route:openai-chat-completions gpt-5.5"`
	}
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(recorded.Request.Body, &body); err != nil {
		t.Fatal(err)
	}
	body["model"] = json.RawMessage(model)
	delete(body, "store")
	request, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(request)
}

// OpenAI keeps a function call that the output limit cut, with its unfinished arguments (capture
// openai/tool-call-cut-at-output-limit). The client gets the reply as the provider ended it,
// because the reason tells it to raise the limit, where an error would have it send the same
// request again.
func TestReplyCutInsideAFunctionCallPasses(t *testing.T) {
	capture := providerCapture(t, "openai/tool-call-cut-at-output-limit")

	t.Run("chat whole", func(t *testing.T) {
		recorded := exchange(t, capture, "chat whole")
		state := resolvedChatValidationState(t, cutToolCallRequest(t, recorded))
		reply := &schemas.BifrostChatResponse{}
		if err := sonic.Unmarshal(recorded.Response.Body, reply); err != nil {
			t.Fatal(err)
		}
		if err := validateProviderChatResponse(state, reply, false); err != nil {
			t.Fatalf("recorded reply refused: %v", err)
		}
		if state.chatFinishReason != "length" || len(state.chatToolCalls) != 1 {
			t.Fatalf("finish %q with %d calls", state.chatFinishReason, len(state.chatToolCalls))
		}
	})

	t.Run("chat stream", func(t *testing.T) {
		recorded := exchange(t, capture, "chat stream")
		state := resolvedChatValidationState(t, cutToolCallRequest(t, recorded))
		for _, data := range recorded.Response.Events {
			chunk := &schemas.BifrostChatResponse{}
			if err := sonic.Unmarshal(data, chunk); err != nil {
				t.Fatal(err)
			}
			if err := validateProviderChatResponse(state, chunk, true); err != nil {
				t.Fatalf("recorded chunk %s refused: %v", data, err)
			}
		}
		if state.chatFinishReason != "length" || len(state.chatToolCalls) != 1 {
			t.Fatalf("finish %q with %d calls", state.chatFinishReason, len(state.chatToolCalls))
		}
	})

	t.Run("responses whole", func(t *testing.T) {
		recorded := exchange(t, capture, "responses whole")
		state := resolvedResponseValidationState(t, cutToolCallRequest(t, recorded))
		if err := validateProviderResponsesResponse(state, recorded.responsesReply(t)); err != nil {
			t.Fatalf("recorded reply refused: %v", err)
		}
	})

	t.Run("responses stream", func(t *testing.T) {
		recorded := exchange(t, capture, "responses stream")
		state := resolvedResponseValidationState(t, cutToolCallRequest(t, recorded))
		if err := replayLocalToolStream(state, recorded.responsesStream(t)); err != nil {
			t.Fatalf("recorded stream refused: %v", err)
		}
	})
}

// A call that the provider finished must hold a JSON object, and a reply that ends for another
// reason than a cut holds no unfinished call.
func TestFinishedFunctionCallNeedsAJSONObject(t *testing.T) {
	capture := providerCapture(t, "openai/tool-call-cut-at-output-limit")
	recorded := exchange(t, capture, "chat whole")
	for _, reason := range []string{"tool_calls", "stop"} {
		state := resolvedChatValidationState(t, cutToolCallRequest(t, recorded))
		reply := &schemas.BifrostChatResponse{}
		if err := sonic.Unmarshal(recorded.Response.Body, reply); err != nil {
			t.Fatal(err)
		}
		reply.Choices[0].FinishReason = schemas.Ptr(reason)
		if err := validateProviderChatResponse(state, reply, false); err == nil {
			t.Fatalf("finish reason %s accepted unfinished arguments", reason)
		}
	}

	whole := exchange(t, capture, "responses whole")
	state := resolvedResponseValidationState(t, cutToolCallRequest(t, whole))
	reply := whole.responsesReply(t)
	for index := range reply.Output {
		if reply.Output[index].Status != nil {
			reply.Output[index].Status = schemas.Ptr("completed")
		}
	}
	if err := validateProviderResponsesResponse(state, reply); err == nil {
		t.Fatal("a completed call accepted unfinished arguments")
	}
}

const (
	claudeCutToolCallChat      = `{"model":"anthropic-claude-sonnet-4-6","messages":[{"role":"user","content":"write it"}],"tools":[{"type":"function","function":{"name":"write_file","parameters":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}}}}}],"max_completion_tokens":40,"stream":true}`
	claudeCutToolCallResponses = `{"model":"anthropic-claude-sonnet-4-6","input":"write it","tools":[{"type":"function","name":"write_file","parameters":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}}}}],"max_output_tokens":40,"stream":true}`
)

// Claude's cut call reaches the client the same way on both interfaces. The stream is Bedrock's
// (capture aws/eager-input-streaming), which reports the output limit without closing the call's
// block. The stop reason decides the outcome: the same unfinished arguments in a reply that
// Claude ended by itself fail it, because a finished call holds a JSON object.
func TestClaudeReplyCutInsideAToolCall(t *testing.T) {
	recorded := exchange(t, providerCapture(t, "aws/eager-input-streaming"), "stream cut inside the call")
	for _, test := range []struct {
		name, stopReason, finishReason string
		passes                         bool
	}{
		{"cut at the output limit", "max_tokens", "length", true},
		{"ended by Claude", "tool_use", "tool_calls", false},
	} {
		events := make([]anthropic.AnthropicStreamEvent, len(recorded.Response.Events))
		arguments := ""
		for index, data := range recorded.Response.Events {
			if err := json.Unmarshal(data, &events[index]); err != nil {
				t.Fatal(err)
			}
			if message := events[index].Message; message != nil {
				// The test catalog serves another Claude model than the recording used.
				message.Model = "claude-sonnet-4-6"
			}
			if delta := events[index].Delta; delta != nil && delta.StopReason != nil {
				*delta.StopReason = anthropic.AnthropicStopReason(test.stopReason)
			} else if delta != nil && delta.PartialJSON != nil {
				arguments += *delta.PartialJSON
			}
		}

		t.Run(test.name+" responses", func(t *testing.T) {
			_, ctx, state := providerBody(t, "/v1/responses", claudeCutToolCallResponses)
			streamState := anthropic.AcquireAnthropicResponsesStreamState()
			defer anthropic.ReleaseAnthropicResponsesStreamState(streamState)
			sequence := 0
			var terminal *schemas.BifrostResponsesStreamResponse
			var refused error
		replay:
			for index := range events {
				chunks, bifrostErr, _ := events[index].ToBifrostResponsesStream(ctx, sequence, streamState)
				if bifrostErr != nil {
					t.Fatalf("convert %s: %v", events[index].Type, bifrostErr.Error)
				}
				for _, chunk := range chunks {
					terminal = chunk
					if refused = state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: chunk}); refused != nil {
						break replay
					}
				}
				sequence += len(chunks)
			}
			if !test.passes {
				// The call's item ends as the stream closes its block; the terminal event shows that Claude ended the reply.
				if refused == nil || terminal.Type != schemas.ResponsesStreamResponseTypeCompleted {
					t.Fatalf("unfinished arguments in a reply that Claude ended: %v at %s", refused, terminal.Type)
				}
				return
			}
			if refused != nil {
				t.Fatalf("%s refused: %v", terminal.Type, refused)
			}
			if terminal.Type != schemas.ResponsesStreamResponseTypeIncomplete || len(terminal.Response.Output) != 1 {
				t.Fatalf("terminal event = %s with %d items", terminal.Type, len(terminal.Response.Output))
			}
			item := terminal.Response.Output[0]
			if item.Status == nil || *item.Status != "incomplete" || item.ResponsesToolMessage == nil ||
				*item.ResponsesToolMessage.Arguments != arguments {
				t.Fatalf("call item = %+v", item)
			}
		})

		t.Run(test.name+" chat", func(t *testing.T) {
			ctx, cancel := schemas.NewBifrostContextWithCancel(context.Background())
			defer cancel()
			state := resolvedChatValidationState(t, claudeCutToolCallChat)
			streamState := anthropic.NewAnthropicStreamState()
			var refused error
			for index := range events {
				chunk, bifrostErr, _ := events[index].ToBifrostChatCompletionStream(ctx, "", streamState)
				if bifrostErr != nil {
					t.Fatalf("convert %s: %v", events[index].Type, bifrostErr.Error)
				}
				if chunk == nil {
					continue
				}
				// The provider's stream loop names the message on every chunk.
				chunk.ID, chunk.Model = "msg_01cut", "claude-sonnet-4-6"
				if refused = state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); refused != nil {
					break
				}
			}
			if refused == nil {
				// The provider's stream loop ends the stream with the stop reason as Chat's finish reason.
				usage := &schemas.BifrostLLMUsage{PromptTokens: 12, CompletionTokens: 40, TotalTokens: 52}
				last := providerutils.CreateBifrostChatCompletionChunkResponse("msg_01cut", usage, &test.finishReason, len(events), "claude-sonnet-4-6", 0)
				refused = state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: last})
			}
			if !test.passes {
				if refused == nil {
					t.Fatal("unfinished arguments passed in a reply that Claude ended")
				}
				return
			}
			if refused != nil {
				t.Fatalf("cut reply refused: %v", refused)
			}
			if state.chatFinishReason != "length" || len(state.chatToolCalls) != 1 {
				t.Fatalf("finish %q with %d calls", state.chatFinishReason, len(state.chatToolCalls))
			}
		})
	}
}
