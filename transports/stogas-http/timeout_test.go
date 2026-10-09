package stogashttp

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestResponseDeadlinePreservesProviderLifetimeAndFinalUsage(t *testing.T) {
	for _, test := range []struct {
		name      string
		delta     *schemas.ChatStreamResponseChoiceDelta
		total     time.Duration
		completed bool
		wantTime  time.Duration
	}{
		{name: "keepalives only", wantTime: 5 * time.Minute},
		{name: "empty delta", delta: &schemas.ChatStreamResponseChoiceDelta{}, wantTime: 5 * time.Minute},
		{name: "reasoning renews idle", delta: &schemas.ChatStreamResponseChoiceDelta{Reasoning: schemas.Ptr("thinking"), ReasoningDetails: []schemas.ChatReasoningDetails{{Type: schemas.BifrostReasoningDetailsTypeText, Text: schemas.Ptr("thinking")}}}, wantTime: 9 * time.Minute},
		{name: "text cannot renew total", delta: &schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("hello")}, total: 6 * time.Minute, wantTime: 6 * time.Minute},
		{name: "completion stops idle", delta: &schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("done")}, completed: true, wantTime: 4 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := &Server{}
				ctx := newTestRequest(t)
				total := test.total
				if total == 0 {
					total = time.Hour
				}
				request, cancelRequest := schemas.NewBifrostContextWithTimeout(t.Context(), time.Hour)
				var defaults *policy.Timeouts
				ctx.responseWait = newResponseDeadline(time.Now(), total, defaults.OutputIdle())
				ctx.responseWait.startOutput()
				cancel := func() { ctx.responseWait.stop(); cancelRequest() }
				defer cancel()
				state := &stogas.State{Adapter: stogas.DefaultAdapter{}, Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}}
				provider := make(chan *schemas.BifrostStreamChunk)
				releaseProvider := make(chan struct{})
				release := sync.OnceFunc(func() { close(releaseProvider) })
				defer release()
				finished := make(chan struct{})
				reader := server.startSSEStream(ctx, request, state, provider, true, false, cancel, func() { close(finished) })
				defer reader.Close()
				startedAt := time.Now()
				go func() {
					defer close(provider)
					chunk := func(delta *schemas.ChatStreamResponseChoiceDelta, complete bool) *schemas.BifrostStreamChunk {
						response := &schemas.BifrostChatResponse{ID: "timeout_probe", Object: "chat.completion.chunk", Choices: []schemas.BifrostResponseChoice{{ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: delta}}}}
						if complete {
							response.Choices[0].FinishReason = schemas.Ptr("stop")
							response.Usage = &schemas.BifrostLLMUsage{PromptTokens: 7, CompletionTokens: 3, TotalTokens: 10}
						}
						return &schemas.BifrostStreamChunk{BifrostChatResponse: response}
					}
					provider <- chunk(&schemas.ChatStreamResponseChoiceDelta{Role: schemas.Ptr("assistant")}, false)
					if test.delta != nil {
						time.Sleep(4 * time.Minute)
						provider <- chunk(test.delta, test.completed)
					}
					if !test.completed {
						<-releaseProvider
						provider <- chunk(&schemas.ChatStreamResponseChoiceDelta{}, true)
					}
				}()
				body, err := io.ReadAll(reader)
				if err != nil || time.Since(startedAt) != test.wantTime {
					t.Fatalf("response after %s, want %s: %v, %s", time.Since(startedAt), test.wantTime, err, body)
				}
				if test.completed {
					if !strings.Contains(string(body), "data: [DONE]") || strings.Contains(string(body), `"error"`) {
						t.Fatalf("completion became a timeout: %s", body)
					}
					time.Sleep(10 * time.Minute)
					if ctx.responseWait.timedOut() {
						t.Fatal("completed request retained a live output timer")
					}
				} else {
					if payload := requireSSEErrorPayload(t, string(body)); payload["code"] != "request_timeout" {
						t.Fatalf("timeout lost its public code: %v", payload)
					}
					if request.Err() != nil {
						t.Fatal("caller timeout canceled dispatched provider work")
					}
					select {
					case <-finished:
						t.Fatal("timeout released provider ownership before teardown")
					default:
					}
					release()
				}
				<-finished
				if state.Signals == nil || state.Signals.PromptTokens() != 7 || state.Signals.CompletionTokens() != 3 {
					t.Fatal("caller timeout lost the final usage block")
				}
			})
		})
	}
}

func TestRequestTimeoutIncludesPreparationAndRejectsExpiredAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source, err := policy.CompileSource([]byte(`{"timeouts":{"totalSeconds":5}}`))
		if err != nil {
			t.Fatal(err)
		}
		config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
		if err != nil {
			t.Fatal(err)
		}
		resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}]}`), Policy: config})
		if err != nil {
			t.Fatal(err)
		}
		startedAt := time.Now()
		time.Sleep(3 * time.Second)
		ctx := newTestRequest(t)
		request, state, cancel, err := newRequestContext(ctx, startedAt, resolution, apiCredential{}, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()
		deadline, _ := request.Deadline()
		if deadline != startedAt.Add(billing.GatewayRequestLifetime) || state.RequestLifetime != billing.GatewayRequestLifetime {
			t.Fatal("caller policy shortened the provider deadline or hold duration")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if !ctx.responseWait.timedOut() || request.Err() != nil || ctx.responseWait.startOutput() {
			t.Fatal("expired preparation permitted dispatch or canceled the provider lifetime")
		}
		request, state, cancel, err = newRequestContext(newTestRequest(t), startedAt, resolution, apiCredential{}, nil, "")
		if !errors.Is(err, context.DeadlineExceeded) || request != nil || state != nil || cancel != nil {
			t.Fatal("expired preparation created an inference context")
		}
	})
}

func TestOutputTimeoutPreservesUsageOnProviderStartupFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := newTestRequest(t)
		request, cancel := schemas.NewBifrostContextWithCancel(t.Context())
		defer cancel()
		ctx.responseWait = newResponseDeadline(time.Now(), time.Hour, time.Second)
		ctx.responseWait.startOutput()
		time.Sleep(time.Second)
		synctest.Wait()
		if request.Err() != nil {
			t.Fatal("caller timeout canceled the upstream request")
		}
		state := &stogas.State{Resolution: &catalog.ResolvedRequest{Route: catalog.RouteChat}}
		failure := &schemas.BifrostError{Type: schemas.Ptr(schemas.RequestCancelled), Error: &schemas.ErrorField{Message: "provider canceled"}, ExtraFields: schemas.BifrostErrorExtraFields{BilledUsage: &schemas.BifrostLLMUsage{PromptTokens: 7, CompletionTokens: 3, TotalTokens: 10}}}
		(&Server{}).failStreamStart(ctx, request, state, stogas.DefaultAdapter{}, failure, cancel)
		if response := testResponse(ctx); response.Code != 504 || !strings.Contains(response.Body.String(), `"request_timeout"`) {
			t.Fatalf("output timeout became a provider cancellation: %d %s", response.Code, response.Body.String())
		}
		signals, ok := state.Signals.(*stogas.StandardSignals)
		if !ok || signals.PromptTokens() != 7 || signals.CompletionTokens() != 3 {
			t.Fatal("timeout discarded the provider's billable usage")
		}
	})
}

func TestClientObservationFinishesBeforeSettlement(t *testing.T) {
	for _, disconnectFirst := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx := newTestRequest(t)
			client, disconnect := context.WithCancel(ctx.request.Context())
			defer disconnect()
			ctx.request = ctx.request.WithContext(client)
			provider, state, cleanup, err := newRequestContext(ctx, time.Now(), &catalog.ResolvedRequest{Route: catalog.RouteChat}, apiCredential{}, nil, "")
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			if disconnectFirst {
				disconnect()
			}
			ctx.finishClientWait()
			if cancelled, _ := state.ClientStatus(); cancelled != disconnectFirst {
				t.Fatalf("client observation still pending at settlement: cancelled=%v", cancelled)
			}
			if provider.Err() != nil || ctx.responseWait.waiting() {
				t.Fatal("ending caller observation canceled provider work or permitted another attempt")
			}
			disconnect()
			synctest.Wait()
			ctx.finishClientWait()
			if cancelled, _ := state.ClientStatus(); cancelled != disconnectFirst {
				t.Fatal("HTTP handler completion became a client disconnect")
			}
		})
	}
}
