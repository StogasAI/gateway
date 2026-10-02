package stogas

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// Each supported native wire must retain the no-replay boundary through the
// real dispatcher, including its retry loop and configured fallback route.
func TestSupportedProviderAmbiguousStreamsDoNotReplay(t *testing.T) {
	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic, schemas.Azure} {
		for _, responses := range []bool{false, true} {
			for _, failure := range []string{"non-SSE success", "closed after headers"} {
				t.Run(fmt.Sprintf("%s/responses=%t/%s", provider, responses, failure), func(t *testing.T) {
					var calls atomic.Int32
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						calls.Add(1)
						if failure == "non-SSE success" {
							w.Header().Set("Content-Type", "application/json")
							_, _ = fmt.Fprint(w, `{"error":{"message":"generation interrupted"}}`)
							return
						}
						w.Header().Set("Content-Type", "text/event-stream")
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
						panic(http.ErrAbortHandler)
					}))
					t.Cleanup(server.Close)
					config := newProviderConfig(server.URL, true, false)
					config.NetworkConfig.MaxRetries = 2
					config.NetworkConfig.RetryBackoffInitial = time.Millisecond
					config.NetworkConfig.RetryBackoffMax = time.Millisecond
					key := schemas.Key{
						ID: "test", Name: "test", Value: *schemas.NewSecretVar("test-key"),
						Models: schemas.WhiteList{"*"}, Weight: 1, Enabled: schemas.Ptr(true),
					}
					model := "gpt-5"
					if provider == schemas.Anthropic {
						model = "claude-sonnet-4-6"
					}
					if provider == schemas.Azure {
						key.AzureKeyConfig = &schemas.AzureKeyConfig{Endpoint: *schemas.NewSecretVar(server.URL)}
					}
					client, err := bifrost.Init(t.Context(), schemas.BifrostConfig{
						Account: &account{
							keys:            map[schemas.ModelProvider]schemas.Key{provider: key},
							providerConfigs: map[schemas.ModelProvider]schemas.ProviderConfig{provider: config},
						},
						InitialPoolSize: 1,
						Logger:          bifrost.NewDefaultLogger(schemas.LogLevelError),
					})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(client.Shutdown)
					ctx, cancel := schemas.NewBifrostContextWithTimeout(t.Context(), 3*time.Second)
					defer cancel()
					fallbacks := []schemas.Fallback{{Provider: provider, Model: "fallback-model"}}
					var stream chan *schemas.BifrostStreamChunk
					var streamErr *schemas.BifrostError
					if responses {
						stream, streamErr = client.ResponsesStreamRequest(ctx, &schemas.BifrostResponsesRequest{
							Provider: provider, Model: model, Fallbacks: fallbacks,
							Input:  []schemas.ResponsesMessage{{Role: schemas.Ptr(schemas.ResponsesInputMessageRoleUser), Content: &schemas.ResponsesMessageContent{ContentStr: schemas.Ptr("hello")}}},
							Params: &schemas.ResponsesParameters{MaxOutputTokens: schemas.Ptr(16)},
						})
					} else {
						stream, streamErr = client.ChatCompletionStreamRequest(ctx, &schemas.BifrostChatRequest{
							Provider: provider, Model: model, Fallbacks: fallbacks,
							Input:  []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("hello")}}},
							Params: &schemas.ChatParameters{MaxCompletionTokens: schemas.Ptr(16)},
						})
					}
					for stream != nil {
						select {
						case chunk, ok := <-stream:
							if !ok {
								stream = nil
								continue
							}
							if chunk.BifrostError != nil {
								streamErr = chunk.BifrostError
							}
						case <-ctx.Done():
							t.Fatal("failed provider stream did not close")
						}
					}
					if calls.Load() != 1 {
						t.Fatalf("ambiguous provider execution was retried or never dispatched: calls=%d", calls.Load())
					}
					if streamErr == nil || !streamErr.IsBifrostError || streamErr.AllowFallbacks == nil || *streamErr.AllowFallbacks {
						t.Fatalf("ambiguous stream did not return a terminal error that blocks replay: %#v", streamErr)
					}
				})
			}
		}
	}
}
