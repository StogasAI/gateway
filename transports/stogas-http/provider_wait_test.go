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

func TestEncryptedProviderWaitKeepsStatusAndOwnsProviderUntilReturn(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, outcome := range []string{"response", "cancel", "write-failure"} {
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
					requestLifetime, disconnect := context.WithCancel(t.Context())
					defer disconnect()
					providerContext, cancelProvider := context.WithCancel(t.Context())
					defer cancelProvider()
					ctx := &requestContext{writer: writer, request: httptest.NewRequestWithContext(requestLifetime, http.MethodPost, "/v1/responses", nil)}
					finish := make(chan struct{})
					returned := make(chan struct{})
					go func() {
						response := `{"error":"later rejection"}`
						if streaming {
							expected := &schemas.BifrostError{StatusCode: schemas.Ptr(http.StatusTooManyRequests)}
							stream, failure := awaitProviderStream(ctx, cancelProvider, func() (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
								<-finish
								return nil, expected
							})
							if stream != nil || failure != expected || ctx.pendingStream != nil {
								t.Error("stream startup did not preserve the provider rejection")
							}
						} else {
							_, failure := awaitProviderResult(ctx, cancelProvider, func() (string, *schemas.BifrostError) {
								<-finish
								return response, nil
							})
							if failure != nil {
								t.Error("unexpected provider failure")
							}
						}
						writer.Header().Set("Content-Type", "application/json")
						writer.Header().Set("Retry-After", "7")
						writer.WriteHeader(http.StatusTooManyRequests)
						_, _ = writer.Write([]byte(response))
						_ = writer.finish()
						close(returned)
					}()
					time.Sleep(2 * responseKeepaliveInterval)
					synctest.Wait()
					outer.mu.Lock()
					controlRecords := bytes.NewReader(bytes.Clone(outer.Body.Bytes()))
					outer.Body.Reset()
					outer.fail = outcome == "write-failure"
					outer.mu.Unlock()
					for range 3 { // Initial receipt and two quiet-response keepalives.
						kind, payload, err := readSessionRecord(t, controlRecords, decoder)
						if err != nil || kind != channel.Keepalive || len(payload) != 0 {
							t.Fatalf("keepalive = %v, %v", kind, err)
						}
					}
					if controlRecords.Len() != 0 || writer.started {
						t.Fatal("quiet wait committed inner headers or body")
					}
					if outcome == "cancel" {
						disconnect()
					} else if outcome == "write-failure" {
						time.Sleep(responseKeepaliveInterval)
					}
					synctest.Wait()
					if (providerContext.Err() != nil) != (outcome != "response") {
						t.Fatal("downstream failure did not cancel provider work")
					}
					select {
					case <-returned:
						t.Fatal("provider wait released work before the provider returned")
					default:
					}
					close(finish)
					<-returned
					if outcome != "write-failure" {
						metadata, body := readSessionResponse(t, outer.Result(), decoder)
						if metadata.Status != 429 || metadata.Headers["Retry-After"] != "7" || string(body) != `{"error":"later rejection"}` {
							t.Fatal("keepalive changed late JSON error")
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
		result, failure := awaitProviderResult(ctx, func() { t.Fatal("unexpected cancellation") }, func() (string, *schemas.BifrostError) {
			time.Sleep(2 * responseKeepaliveInterval)
			if writer.Flushed || writer.Body.Len() != 0 || len(writer.Header()) != 0 {
				t.Fatal("ordinary JSON response gained progress framing")
			}
			return "failure", nil
		})
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = writer.Write([]byte(result))
		if failure != nil || writer.Result().StatusCode != 429 || writer.Body.String() != "failure" {
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
	_, _ = awaitProviderResult(ctx, func() {}, func() (string, *schemas.BifrostError) {
		panic(http.ErrAbortHandler)
	})
}
