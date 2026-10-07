package stogas

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

// Local provider sockets exercise the real Bifrost dispatch, provider codecs,
// stream conversion and OTLP delivery. Chutes uses its post-decryption OpenAI
// adapter here; its attestation and encrypted transport have separate tests.
func TestProviderContentReachesExport(t *testing.T) {
	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Azure, schemas.Anthropic, catalog.ProviderChutes} {
		for _, responses := range []bool{false, true} {
			if provider == catalog.ProviderChutes && responses {
				continue
			}
			for _, streaming := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/responses=%t/stream=%t", provider, responses, streaming), func(t *testing.T) {
					wire, want := exportProviderWire(provider, responses, streaming)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						io.Copy(io.Discard, r.Body)
						w.Header().Set("Content-Type", "application/json")
						if streaming {
							w.Header().Set("Content-Type", "text/event-stream")
						}
						io.WriteString(w, wire)
					}))
					defer upstream.Close()
					config := newProviderConfig(upstream.URL, true, false)
					config.NetworkConfig.MaxRetries = 0
					key := schemas.Key{ID: "test", Name: "test", Value: *schemas.NewSecretVar("test-key"), Models: schemas.WhiteList{"*"}, Weight: 1, Enabled: schemas.Ptr(true)}
					if provider == schemas.Azure {
						key.AzureKeyConfig = &schemas.AzureKeyConfig{Endpoint: *schemas.NewSecretVar(upstream.URL)}
					}
					if provider == catalog.ProviderChutes {
						config.CustomProviderConfig = &schemas.CustomProviderConfig{BaseProviderType: schemas.OpenAI, AllowedRequests: &schemas.AllowedRequests{ChatCompletion: true, ChatCompletionStream: true}}
					}
					client, err := bifrost.Init(t.Context(), schemas.BifrostConfig{
						Account:         &account{keys: map[schemas.ModelProvider]schemas.Key{provider: key}, providerConfigs: map[schemas.ModelProvider]schemas.ProviderConfig{provider: config}},
						InitialPoolSize: 1, Logger: bifrost.NewDefaultLogger(schemas.LogLevelError),
					})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Shutdown()

					received := make(chan ptrace.Traces, 1)
					receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						raw, err := io.ReadAll(r.Body)
						request := ptraceotlp.NewExportRequest()
						if err != nil {
							t.Error(err)
						}
						if err := request.UnmarshalJSON(raw); err != nil {
							t.Error(err)
						}
						received <- request.Traces()
						w.Header().Set("Content-Type", "application/json")
						io.WriteString(w, `{}`)
					}))
					defer receiver.Close()
					engine := exporter.New(t.Context(), exporter.Options{Local: true})
					defer engine.Close()
					capture := engine.Start("org", t.Name(), &exportconfig.Config{Destinations: []exportconfig.Destination{{URL: receiver.URL, Content: "both", MaxRetries: schemas.Ptr(0)}}})
					defer capture.Discard()
					ctx, cancel := schemas.NewBifrostContextWithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					var stream chan *schemas.BifrostStreamChunk
					var callErr *schemas.BifrostError
					if responses {
						req := &schemas.BifrostResponsesRequest{Provider: provider, Model: "gpt-5", Input: []schemas.ResponsesMessage{{Role: schemas.Ptr(schemas.ResponsesInputMessageRoleUser), Content: &schemas.ResponsesMessageContent{ContentStr: schemas.Ptr("prompt")}}}, Params: &schemas.ResponsesParameters{MaxOutputTokens: schemas.Ptr(1024)}}
						capture.Input(&schemas.BifrostRequest{ResponsesRequest: req})
						if streaming {
							stream, callErr = client.ResponsesStreamRequest(ctx, req)
						} else {
							var result *schemas.BifrostResponsesResponse
							result, callErr = client.ResponsesRequest(ctx, req)
							capture.Response(&schemas.BifrostResponse{ResponsesResponse: result})
						}
					} else {
						req := &schemas.BifrostChatRequest{Provider: provider, Model: "gpt-5", Input: []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("prompt")}}}, Params: &schemas.ChatParameters{MaxCompletionTokens: schemas.Ptr(1024)}}
						capture.Input(&schemas.BifrostRequest{ChatRequest: req})
						if streaming {
							stream, callErr = client.ChatCompletionStreamRequest(ctx, req)
						} else {
							var result *schemas.BifrostChatResponse
							result, callErr = client.ChatCompletionRequest(ctx, req)
							capture.Response(&schemas.BifrostResponse{ChatResponse: result})
						}
					}
					if callErr != nil {
						t.Fatalf("provider request: %v", callErr)
					}
					for stream != nil {
						select {
						case chunk, ok := <-stream:
							if !ok {
								stream = nil
								continue
							}
							if chunk.BifrostError != nil {
								t.Fatalf("provider stream: %v", chunk.BifrostError)
							}
							capture.Chunk(chunk)
						case <-ctx.Done():
							t.Fatal("provider stream did not close")
						}
					}
					capture.Finish(exporter.Record{RequestID: t.Name(), Provider: string(provider), Model: "gpt-5", RequestType: "chat_completion", StartedAt: time.Now().Add(-time.Second), EndedAt: time.Now(), Outcome: "success"})
					select {
					case traces := <-received:
						if traces.SpanCount() != 1 {
							t.Fatalf("span count %d", traces.SpanCount())
						}
						span := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
						content, _ := span.Attributes().Get("gen_ai.output.messages")
						var messages []struct {
							Parts []map[string]any `json:"parts"`
						}
						if err := json.Unmarshal([]byte(content.Str()), &messages); err != nil {
							t.Fatal(err)
						}
						if len(messages) != 1 {
							t.Fatalf("output choices: %s", content.Str())
						}
						parts, _ := json.Marshal(messages[0].Parts)
						if string(parts) != want {
							t.Fatalf("parts %s; want %s", parts, want)
						}
						omitted, _ := span.Attributes().Get("stogas.output.omitted")
						if omitted.Bool() != (provider == schemas.Anthropic) {
							t.Fatalf("omitted=%v", omitted.Bool())
						}
					case <-time.After(5 * time.Second):
						t.Fatal("export did not arrive")
					}
				})
			}
		}
	}
}

func exportProviderWire(provider schemas.ModelProvider, responses, streaming bool) (string, string) {
	const standardParts = `[{"content":"thinking","type":"reasoning"},{"content":"answer","type":"text"},{"arguments":{"city":"Paris"},"id":"call_1","name":"weather","type":"tool_call"}]`
	if provider == schemas.Anthropic {
		const unary = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"thinking","thinking":"thinking","signature":"private-signature"},{"type":"text","text":"answer"},{"type":"tool_use","id":"call_1","name":"weather","input":{"city":"Paris"}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":5,"output_tokens":8}}`
		if !streaming {
			want := standardParts
			if !responses {
				// Bifrost's buffered Chat conversion appends a newline to thinking.
				want = strings.Replace(want, `"thinking"`, `"thinking\n"`, 1)
			}
			return unary, want
		}
		return exportSSE([]string{
			`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"stop_reason":null,"usage":{"input_tokens":5,"output_tokens":0}}}`,
			`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"thinking"}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"private-signature"}}`,
			`{"type":"content_block_stop","index":0}`,
			`{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
			`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"answer"}}`,
			`{"type":"content_block_stop","index":1}`,
			`{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"call_1","name":"weather","input":{}}}`,
			`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"Paris\"}"}}`,
			`{"type":"content_block_stop","index":2}`,
			`{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":8}}`,
			`{"type":"message_stop"}`,
		}), standardParts
	}
	if responses {
		const unary = `{"id":"resp_1","object":"response","created_at":1700000000,"status":"completed","model":"gpt-5","output":[{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"answer","annotations":[]}]},{"id":"ct_1","type":"custom_tool_call","call_id":"call_1","name":"freeform","input":"123"}],"usage":{"input_tokens":5,"output_tokens":8,"total_tokens":13}}`
		const want = `[{"content":"thinking","type":"reasoning"},{"content":"answer","type":"text"},{"arguments":"123","id":"call_1","name":"freeform","type":"tool_call"}]`
		if !streaming {
			return unary, want
		}
		return exportSSE([]string{
			`{"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":{"id":"rs_1","type":"reasoning","summary":[]}}`,
			`{"type":"response.reasoning_summary_text.delta","sequence_number":2,"output_index":0,"summary_index":0,"delta":"thinking"}`,
			`{"type":"response.completed","sequence_number":3,"response":` + unary + `}`,
		}), want
	}
	reasoning := `"reasoning_details":[{"type":"reasoning.text","index":0,"text":"thinking"}]`
	if provider == schemas.Azure {
		reasoning = `"reasoning":"thinking"`
	}
	if provider == catalog.ProviderChutes {
		reasoning = `"reasoning_content":"thinking"`
	}
	message := `{"role":"assistant","content":"answer",` + reasoning + `,"tool_calls":[{"index":0,"type":"function","id":"call_1","function":{"name":"weather","arguments":"{\"city\":\"Paris\"}"}}]}`
	if !streaming {
		return `{"id":"chat_1","object":"chat.completion","created":1700000000,"model":"gpt-5","choices":[{"index":0,"message":` + message + `,"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":8,"total_tokens":13}}`, standardParts
	}
	return exportSSE([]string{
		`{"id":"chat_1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-5","choices":[{"index":0,"delta":` + message + `,"finish_reason":null}]}`,
		`{"id":"chat_1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-5","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":8,"total_tokens":13}}`,
		`[DONE]`,
	}), standardParts
}

func exportSSE(events []string) string {
	var body strings.Builder
	for _, event := range events {
		var typed struct {
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(event), &typed) == nil && typed.Type != "" {
			fmt.Fprintf(&body, "event: %s\n", typed.Type)
		}
		fmt.Fprintf(&body, "data: %s\n\n", event)
	}
	return body.String()
}
