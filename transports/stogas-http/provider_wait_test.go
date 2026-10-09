package stogashttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
)

type providerWaitRecorder struct {
	*sessionDeadlineRecorder
	mu   sync.Mutex
	fail bool
}

func (w *providerWaitRecorder) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ResponseRecorder.Write(data)
}

func (w *providerWaitRecorder) FlushError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail {
		return io.ErrClosedPipe
	}
	w.Flush()
	return nil
}

func TestEncryptedProviderWaitPreservesStatusAndTransfersPendingWork(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, outcome := range []string{"response", "cancel", "write-failure", "timeout"} {
			t.Run(fmt.Sprintf("streaming=%v/%s", streaming, outcome), func(t *testing.T) {
				fixture := newSessionHTTPFixture(t, func(*requestContext) { t.Fatal("unexpected inference") }, true)
				wire, decoder := fixture.request(t, []byte(`{"method":"POST","path":"/v1/responses","headers":{}}`), []byte(`{}`))
				input, _, err := channel.Accept(fixture.server.sessions, bytes.NewReader(wire))
				if err != nil {
					t.Fatal(err)
				}
				defer input.Close()
				if _, err := io.Copy(io.Discard, input); err != nil {
					t.Fatal(err)
				}
				synctest.Test(t, func(t *testing.T) {
					outer := &providerWaitRecorder{sessionDeadlineRecorder: &sessionDeadlineRecorder{httptest.NewRecorder()}}
					writer := newSessionResponse(outer, input, false)
					if err := writer.acknowledge(); err != nil {
						t.Fatal(err)
					}
					client, disconnect := context.WithCancel(t.Context())
					defer disconnect()
					ctx := &requestContext{writer: writer, request: httptest.NewRequestWithContext(client, http.MethodPost, "/v1/responses", nil)}
					wait := time.Hour
					if outcome == "timeout" {
						wait = 3 * responseKeepaliveInterval
					}
					ctx.responseWait = newResponseDeadline(time.Now(), wait, time.Hour)
					defer ctx.responseWait.stop()
					state := &stogas.State{}
					finish := make(chan struct{})
					returned := make(chan struct{})
					settled := make(chan struct{})
					go func() {
						response := `{"error":"later rejection"}`
						expected := &schemas.BifrostError{StatusCode: schemas.Ptr(http.StatusTooManyRequests)}
						value, failure, pending := awaitProviderResult(ctx, state.MarkClientStopped, func() (string, *schemas.BifrostError) {
							<-finish
							return response, expected
						}, streaming)
						if pending != nil {
							go func() {
								result := <-pending
								if result.response != response || result.failure != expected {
									t.Error("pending result was lost")
								}
								close(settled)
							}()
						} else {
							if value != response || failure != expected {
								t.Error("provider rejection was changed")
							}
							close(settled)
						}
						if outcome == "response" {
							writer.Header().Set("Content-Type", "application/json")
							writer.Header().Set("Retry-After", "7")
							writer.WriteHeader(http.StatusTooManyRequests)
							_, _ = writer.Write([]byte(response))
							_ = writer.finish()
						} else if outcome == "timeout" {
							(&Server{}).writeBifrostError(ctx, requestTimeoutError())
							_ = writer.finish()
						}
						close(returned)
					}()
					time.Sleep(2 * responseKeepaliveInterval)
					synctest.Wait()
					outer.mu.Lock()
					controlRecords := bytes.NewReader(bytes.Clone(outer.Body.Bytes()))
					outer.Body.Reset()
					outer.fail = outcome == "write-failure"
					outer.mu.Unlock()
					for range 3 {
						kind, payload, err := readSessionRecord(t, controlRecords, decoder)
						if err != nil || kind != channel.Keepalive || len(payload) != 0 {
							t.Fatalf("keepalive = %v, %v", kind, err)
						}
					}
					if controlRecords.Len() != 0 {
						t.Fatal("quiet wait committed inner headers or body")
					}
					switch outcome {
					case "response":
						close(finish)
					case "cancel":
						disconnect()
					default:
						time.Sleep(responseKeepaliveInterval)
					}
					<-returned
					synctest.Wait()
					if stopped, _ := state.ClientStatus(); stopped != (outcome == "cancel" || outcome == "write-failure") {
						t.Fatal("client stop recorded incorrectly")
					}
					before := bytes.Clone(outer.Body.Bytes())
					if outcome != "response" {
						select {
						case <-settled:
							t.Fatal("provider ownership ended before completion")
						default:
						}
						close(finish)
					}
					<-settled
					if !bytes.Equal(before, outer.Body.Bytes()) {
						t.Fatal("detached provider wrote to a completed response")
					}
					if outcome == "response" || outcome == "timeout" {
						metadata, body := readSessionResponse(t, outer.Result(), decoder)
						if outcome == "response" {
							if metadata.Status != 429 || metadata.Headers["Retry-After"] != "7" || string(body) != `{"error":"later rejection"}` {
								t.Fatal("keepalive changed late JSON error")
							}
						} else if metadata.Status != 504 || !bytes.Contains(body, []byte(`"request_timeout"`)) {
							t.Fatal("timeout lost encrypted status or error")
						}
					}
				})
			})
		}
	}
}

func TestOrdinaryUnaryWaitLeavesHTTPResponseUncommitted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writer := httptest.NewRecorder()
		ctx := &requestContext{writer: writer, request: httptest.NewRequest(http.MethodPost, "/v1/responses", nil)}
		result, failure, pending := awaitProviderResult(ctx, func() { t.Fatal("unexpected cancellation") }, func() (string, *schemas.BifrostError) {
			time.Sleep(2 * responseKeepaliveInterval)
			if writer.Flushed || writer.Body.Len() != 0 || len(writer.Header()) != 0 {
				t.Fatal("ordinary JSON response gained progress framing")
			}
			return "failure", nil
		}, false)
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = writer.Write([]byte(result))
		if pending != nil || failure != nil || writer.Result().StatusCode != 429 || writer.Body.String() != "failure" {
			t.Fatal("ordinary HTTP status or response changed")
		}
	})
}

func TestEncryptedUnaryWaitPreservesHandlerPanicBoundary(t *testing.T) {
	ctx := &requestContext{writer: &sessionResponse{}, request: httptest.NewRequest(http.MethodPost, "/v1/responses", nil)}
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Fatal("provider panic did not reach the handler's recovery boundary")
		}
	}()
	_, _, _ = awaitProviderResult(ctx, func() {}, func() (string, *schemas.BifrostError) {
		panic(http.ErrAbortHandler)
	}, false)
}

func TestRequestContextDisconnectPolicyAndCleanup(t *testing.T) {
	for _, finished := range []bool{false, true} {
		t.Run(fmt.Sprintf("finished=%v", finished), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := newTestRequest(t)
				client, disconnect := context.WithCancel(t.Context())
				defer disconnect()
				ctx.request = ctx.request.WithContext(client)
				provider, state, cleanup, err := newRequestContext(ctx, time.Now(), testResolution(), apiCredential{}, nil, "")
				if err != nil {
					t.Fatal(err)
				}
				defer cleanup()
				if finished {
					cleanup()
				}
				disconnect()
				synctest.Wait()
				if stopped, _ := state.ClientStatus(); stopped != !finished {
					t.Fatal("completion or disconnect was recorded incorrectly")
				}
				if (provider.Err() != nil) != finished {
					t.Fatal("client disconnect canceled provider work")
				}
			})
		})
	}
}

func TestClientDisconnectDrainsFinalUsage(t *testing.T) {
	server := &Server{}
	ctx := newTestRequest(t)
	provider, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	state := &stogas.State{Resolution: testResolution(), Adapter: stogas.DefaultAdapter{}}
	stream := make(chan *schemas.BifrostStreamChunk, 1)
	var closeOnce sync.Once
	closeStream := func() { closeOnce.Do(func() { close(stream) }) }
	defer closeStream()
	finished := make(chan struct{})
	reader := server.startSSEStream(ctx, provider, state, stream, true, false, cancel, func() { close(finished) })
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-provider.Done():
		t.Fatal("client disconnect ended the billing read")
	default:
	}
	stream <- &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
		ID: "chatcmpl_cancel", Object: "chat.completion.chunk", Model: "gpt-5.5",
		Choices: []schemas.BifrostResponseChoice{{Index: 0, FinishReason: schemas.Ptr("stop"), ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &schemas.ChatStreamResponseChoiceDelta{}}}},
		Usage:   &schemas.BifrostLLMUsage{PromptTokens: 17, CompletionTokens: 23, TotalTokens: 40},
	}}
	closeStream()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancelled provider stream did not finish")
	}
	if state.Signals == nil || state.Signals.PromptTokens() != 17 || state.Signals.CompletionTokens() != 23 {
		t.Fatalf("lost final usage after disconnect: %#v", state.Signals)
	}
	if stopped, _ := state.ClientStatus(); !stopped || state.BifrostError != nil {
		t.Fatalf("client disconnect changed provider outcome: %#v", state.BifrostError)
	}
}
