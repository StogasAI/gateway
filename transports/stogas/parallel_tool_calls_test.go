package stogas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog/catalogtest"
)

// TestOneToolCallReachesTheClient replays recorded replies that call several tools in one turn,
// from models that ignore parallel_tool_calls false or have no such setting. A client that asks
// for one call gets the first, and every other client gets every call.
func TestOneToolCallReachesTheClient(t *testing.T) {
	catalogtest.UseFallback(t)
	calls := func(reply *schemas.BifrostChatResponse) int {
		return len(reply.Choices[0].Message.ChatAssistantMessage.ToolCalls)
	}
	t.Run("Kimi K3 on Bedrock", func(t *testing.T) {
		// Bedrock took parallel_tool_calls false and answered with two calls (capture
		// aws/chat-completions-tools).
		recorded := exchange(t, providerCapture(t, "aws/chat-completions-tools"), "parallel_tool_calls false")
		state, err := resolveAWSChatState(t, awsChatRequest(t, recorded))
		if err != nil {
			t.Fatal(err)
		}
		reply := &schemas.BifrostChatResponse{}
		if err := sonic.Unmarshal(recorded.Response.Body, reply); err != nil {
			t.Fatal(err)
		}
		if calls(reply) != 2 {
			t.Fatalf("the recording holds %d calls, want 2", calls(reply))
		}
		if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ChatResponse: reply}, nil); err != nil {
			t.Fatal(err)
		}
		if calls(reply) != 1 {
			t.Fatalf("the client got %d calls", calls(reply))
		}
	})
	t.Run("Gemini", func(t *testing.T) {
		// Gemini has no setting for one call per turn (capture google-cloud/generate-content-tools).
		recorded := exchange(t, providerCapture(t, "google-cloud/generate-content-tools"), "tools at mode AUTO")
		if got := calls(geminiClientReply(t, geminiAsk+`}`, recorded)); got != 2 {
			t.Fatalf("the client got %d calls without parallel_tool_calls, want 2", got)
		}
		if got := calls(geminiClientReply(t, geminiAsk+`,"parallel_tool_calls":false}`, recorded)); got != 1 {
			t.Fatalf("the client got %d calls with parallel_tool_calls false", got)
		}
	})
	t.Run("Gemma 4 on Google Cloud", func(t *testing.T) {
		// Gemma 4 took parallel_tool_calls false and called the tool for each of five cities, in a
		// reply and in a stream that sends every call at index 0 (capture
		// google-cloud/chat-completions-fields).
		recorded := providerCapture(t, "google-cloud/chat-completions-fields")
		model := "google/gemma-4-26b-a4b-it-maas"
		// The contract asks until a reply calls several tools, so the last run that it recorded did.
		last := func(label string) providerExchange {
			var found providerExchange
			for run := 1; ; run++ {
				next, ok := recorded[fmt.Sprintf("%s %s, run %d", model, label, run)]
				if !ok {
					break
				}
				found = next
			}
			if found.Name == "" {
				t.Fatalf("the capture has no run of %q", label)
			}
			return found
		}
		t.Run("reply", func(t *testing.T) {
			sent := last("five cities with parallel_tool_calls false")
			reply := googleChatReply(t, sent)
			if reply == nil || calls(reply) < 2 {
				t.Fatal("the recording holds no reply with several calls")
			}
			first := *reply.Choices[0].Message.ChatAssistantMessage.ToolCalls[0].ID
			state, err := resolveGoogleState(t, geminiChatPath, googleChatRequest(t, sent))
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{ChatResponse: reply}, nil); err != nil {
				t.Fatal(err)
			}
			if calls(reply) != 1 || *reply.Choices[0].Message.ChatAssistantMessage.ToolCalls[0].ID != first {
				t.Fatalf("the client got %d calls", calls(reply))
			}
		})
		t.Run("stream", func(t *testing.T) {
			sent := last("five cities streamed with parallel_tool_calls false")
			for _, one := range []bool{true, false} {
				request := map[string]json.RawMessage{}
				if err := json.Unmarshal([]byte(googleChatRequest(t, sent)), &request); err != nil {
					t.Fatal(err)
				}
				if !one {
					delete(request, "parallel_tool_calls")
				}
				body, _ := json.Marshal(request)
				state, err := resolveGoogleState(t, geminiChatPath, string(body))
				if err != nil {
					t.Fatal(err)
				}
				// The client joins deltas by index.
				type call struct{ id, name, arguments string }
				got := map[uint16]*call{}
				for _, chunk := range chatStreamThroughCore(t, model, sent.Response.Events) {
					if err := state.Adapter.IngestChunk(state, chunk); err != nil {
						t.Fatal(err)
					}
					for _, choice := range chunk.BifrostChatResponse.Choices {
						if choice.ChatStreamResponseChoice == nil || choice.Delta == nil {
							continue
						}
						for _, delta := range choice.Delta.ToolCalls {
							joined := got[delta.Index]
							if joined == nil {
								joined = &call{}
								got[delta.Index] = joined
							}
							if delta.ID != nil {
								joined.id += *delta.ID
							}
							if delta.Function.Name != nil {
								joined.name += *delta.Function.Name
							}
							joined.arguments += delta.Function.Arguments
						}
					}
				}
				want := 5
				if one {
					want = 1
				}
				if len(got) != want {
					t.Fatalf("parallel_tool_calls false %t: the client got %d calls", one, len(got))
				}
				cities := map[string]bool{}
				for index, joined := range got {
					var arguments struct{ City string }
					if joined.name != "get_weather" || json.Unmarshal([]byte(joined.arguments), &arguments) != nil || arguments.City == "" {
						t.Fatalf("call %d: %q with arguments %q", index, joined.name, joined.arguments)
					}
					cities[arguments.City] = true
				}
				if len(cities) != want {
					t.Fatalf("the calls name %d cities, want %d", len(cities), want)
				}
			}
		})
	})
}

// chatStreamThroughCore serves recorded Chat Completions events to core's OpenAI provider and
// returns the chunks that core makes of them, as a provider's stream reaches the gateway.
func chatStreamThroughCore(t *testing.T, model string, events []json.RawMessage) []*schemas.BifrostStreamChunk {
	t.Helper()
	var body bytes.Buffer
	for _, event := range events {
		// An event of the capture spans several lines, and an SSE data line ends at the first.
		body.WriteString("data: ")
		if err := json.Compact(&body, event); err != nil {
			t.Fatal(err)
		}
		body.WriteString("\n\n")
	}
	body.WriteString("data: [DONE]\n\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write(body.Bytes())
	}))
	t.Cleanup(server.Close)
	key := schemas.Key{
		ID: "test", Name: "test", Value: *schemas.NewSecretVar("test-key"),
		Models: schemas.WhiteList{"*"}, Weight: 1, Enabled: schemas.Ptr(true),
	}
	client, err := bifrost.Init(t.Context(), schemas.BifrostConfig{
		Account: &account{
			keys:            map[schemas.ModelProvider]schemas.Key{schemas.OpenAI: key},
			providerConfigs: map[schemas.ModelProvider]schemas.ProviderConfig{schemas.OpenAI: newProviderConfig(server.URL, true, false)},
		},
		InitialPoolSize: 1,
		Logger:          bifrost.NewDefaultLogger(schemas.LogLevelError),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Shutdown)
	ctx, cancel := schemas.NewBifrostContextWithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stream, streamErr := client.ChatCompletionStreamRequest(ctx, &schemas.BifrostChatRequest{
		Provider: schemas.OpenAI, Model: model,
		Input: []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("hello")}}},
	})
	if streamErr != nil {
		t.Fatalf("stream: %v", streamErr.Error)
	}
	var chunks []*schemas.BifrostStreamChunk
	for chunk := range stream {
		if chunk.BifrostError != nil {
			t.Fatalf("stream error: %v", chunk.BifrostError.Error)
		}
		if chunk.BifrostChatResponse != nil {
			chunks = append(chunks, chunk)
		}
	}
	return chunks
}
