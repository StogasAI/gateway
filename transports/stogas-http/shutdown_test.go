package stogashttp

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/valyala/fasthttp"
)

func TestBlockedSSESendEndsWhenRequestContextCloses(t *testing.T) {
	server := &Server{}
	requestCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)
	drain := newRequestDrain()
	if !drain.begin() {
		t.Fatal("request drain rejected work before draining")
	}
	state := &stogas.State{}
	responseCtx := &fasthttp.RequestCtx{}

	server.writeSSEStream(responseCtx, requestCtx, state, stream, true, false, cancel, drain.end)
	t.Cleanup(func() {
		cancel()
		_ = responseCtx.Response.CloseBodyStream()
		close(stream)
	})

	sendChunk := func(id string) {
		t.Helper()
		select {
		case stream <- &schemas.BifrostStreamChunk{
			BifrostChatResponse: &schemas.BifrostChatResponse{
				ID:      id,
				Object:  "chat.completion.chunk",
				Model:   "gpt-5",
				Choices: []schemas.BifrostResponseChoice{},
			},
		}:
		case <-time.After(time.Second):
			t.Fatalf("timed out sending stream chunk %q", id)
		}
	}

	sendChunk("first")
	sendChunk("second")
	idle := drain.start()
	select {
	case <-idle:
		t.Fatal("request completed while the downstream SSE queue was blocked")
	default:
	}

	cancel()
	select {
	case <-idle:
	case <-time.After(time.Second):
		t.Fatal("request context did not release the blocked SSE send")
	}
	if state.BifrostError == nil || state.BifrostError.Error == nil || state.BifrostError.Error.Code == nil || *state.BifrostError.Error.Code != "request_timeout" {
		t.Fatalf("request context did not mark the final stream state: %#v", state.BifrostError)
	}
}

func TestServerShutdownContextBoundsActiveBodyStream(t *testing.T) {
	body := newBlockingResponseBody()
	fastHTTPServer := &fasthttp.Server{Handler: func(ctx *fasthttp.RequestCtx) {
		ctx.Response.SetBodyStream(body, -1)
	}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- fastHTTPServer.Serve(listener)
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	shutdownCtx, cancelShutdown := context.WithCancel(t.Context())
	t.Cleanup(func() {
		cancelShutdown()
		body.releaseBody()
		_ = conn.Close()
		_ = listener.Close()
	})
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: gateway.test\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("response body stream did not start")
	}

	server := &Server{server: fastHTTPServer}
	shutdownDone := make(chan struct{})
	go func() {
		server.shutdownWithContext(shutdownCtx)
		close(shutdownDone)
	}()

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("fasthttp Serve returned an error during shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not close the listener")
	}
	select {
	case <-shutdownDone:
		t.Fatal("shutdown completed while the response body stream was active")
	default:
	}

	cancelShutdown()
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not stop waiting when its context ended")
	}
}

type blockingResponseBody struct {
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	releaseOnce sync.Once
}

func newBlockingResponseBody() *blockingResponseBody {
	return &blockingResponseBody{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *blockingResponseBody) Read([]byte) (int, error) {
	b.startedOnce.Do(func() { close(b.started) })
	<-b.release
	return 0, io.EOF
}

func (b *blockingResponseBody) releaseBody() {
	b.releaseOnce.Do(func() { close(b.release) })
}
