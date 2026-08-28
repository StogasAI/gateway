package utils

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

// newTestServer creates an in-memory fasthttp server that responds after the given delay.
// Returns a client configured to talk to it and a cleanup function.
func newTestServer(t *testing.T, delay time.Duration, statusCode int) (*fasthttp.Client, func()) {
	t.Helper()
	ln := fasthttputil.NewInmemoryListener()

	server := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			if delay > 0 {
				time.Sleep(delay)
			}
			ctx.SetStatusCode(statusCode)
			ctx.SetBody([]byte(`{"ok":true}`))
		},
	}

	go server.Serve(ln) //nolint:errcheck

	client := &fasthttp.Client{
		Dial: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	cleanup := func() {
		ln.Close()
	}

	return client, cleanup
}

type recordingContextTransport struct {
	called   bool
	deadline time.Time
}

func (t *recordingContextTransport) RoundTrip(*fasthttp.HostClient, *fasthttp.Request, *fasthttp.Response) (bool, error) {
	return false, errors.New("context-aware request path was not used")
}

func (t *recordingContextTransport) DoRequestWithContext(ctx context.Context, _ *fasthttp.Request, response *fasthttp.Response) error {
	t.called = true
	t.deadline, _ = ctx.Deadline()
	response.SetStatusCode(fasthttp.StatusOK)
	return nil
}

func TestMakeRequestWithContext_SuccessReturnsNoopWait(t *testing.T) {
	client, cleanup := newTestServer(t, 0, 200)
	defer cleanup()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://test/")

	latency, bifrostErr, wait := MakeRequestWithContext(context.Background(), client, req, resp)
	defer wait()

	if bifrostErr != nil {
		t.Fatalf("expected no error, got: %v", bifrostErr.Error.Message)
	}
	if latency <= 0 {
		t.Fatal("expected positive latency")
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode())
	}
}

func TestMakeRequestWithContextPassesContextToCustomTransport(t *testing.T) {
	transport := &recordingContextTransport{}
	client := &fasthttp.Client{Transport: transport}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	wantDeadline, _ := ctx.Deadline()
	_, bifrostErr, wait := MakeRequestWithContext(ctx, client, req, resp)
	wait()
	if bifrostErr != nil {
		t.Fatalf("MakeRequestWithContext returned error: %v", bifrostErr)
	}
	if !transport.called || !transport.deadline.Equal(wantDeadline) {
		t.Fatalf("custom transport context = called:%t deadline:%s, want %s", transport.called, transport.deadline, wantDeadline)
	}
}

func TestMakeRequestWithContext_DeadlineExceededReturnsTimeoutError(t *testing.T) {
	// Server takes 500ms to respond
	client, cleanup := newTestServer(t, 500*time.Millisecond, 200)
	defer cleanup()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	req.SetRequestURI("http://test/")

	// Deadline exceeded almost immediately
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, bifrostErr, wait := MakeRequestWithContext(ctx, client, req, resp)

	// Should get a timeout error with 504 status
	if bifrostErr == nil {
		t.Fatal("expected timeout error")
	}
	if bifrostErr.Error.Type == nil || *bifrostErr.Error.Type != schemas.RequestTimedOut {
		t.Fatalf("expected RequestTimedOut error type, got: %v", bifrostErr.Error.Type)
	}
	if bifrostErr.StatusCode == nil || *bifrostErr.StatusCode != 504 {
		t.Fatalf("expected status 504, got: %v", bifrostErr.StatusCode)
	}

	// wait() should block until the goroutine finishes, then we can safely release
	start := time.Now()
	wait()
	elapsed := time.Since(start)

	// The wait should have taken roughly the remaining server delay (~490ms)
	if elapsed < 200*time.Millisecond {
		t.Fatalf("wait() returned too quickly (%v), expected it to block until goroutine finishes", elapsed)
	}

	// Now safe to release
	fasthttp.ReleaseRequest(req)
	fasthttp.ReleaseResponse(resp)
}

func TestDoStreamingRequestHonorsDeadlineBeforeResponseHeaders(t *testing.T) {
	client, cleanup := newTestServer(t, 500*time.Millisecond, 200)
	defer cleanup()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://test/")
	resp.StreamBody = true

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	err := DoStreamingRequest(ctx, client, req, resp)
	if !errors.Is(err, fasthttp.ErrTimeout) {
		t.Fatalf("DoStreamingRequest error = %v, want fasthttp timeout", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("streaming header deadline took %s, want a bounded wait", elapsed)
	}
}

func TestDoStreamingRequestPassesContextToCustomTransport(t *testing.T) {
	transport := &recordingContextTransport{}
	client := &fasthttp.Client{Transport: transport}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	wantDeadline, _ := ctx.Deadline()
	if err := DoStreamingRequest(ctx, client, req, resp); err != nil {
		t.Fatalf("DoStreamingRequest returned error: %v", err)
	}
	if !transport.called || !transport.deadline.Equal(wantDeadline) {
		t.Fatalf("custom transport context = called:%t deadline:%s, want %s", transport.called, transport.deadline, wantDeadline)
	}
}

func TestDoStreamingRequestKeepsDeadlineOnStreamedBody(t *testing.T) {
	ln := fasthttputil.NewInmemoryListener()
	server := &fasthttp.Server{Handler: func(ctx *fasthttp.RequestCtx) {
		ctx.SetBodyStreamWriter(func(writer *bufio.Writer) {
			_, _ = writer.WriteString("first\n")
			_ = writer.Flush()
			time.Sleep(500 * time.Millisecond)
			_, _ = writer.WriteString("late\n")
		})
	}}
	go server.Serve(ln) //nolint:errcheck
	defer ln.Close()

	client := &fasthttp.Client{
		Dial: func(string) (net.Conn, error) { return ln.Dial() },
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://test/")
	resp.StreamBody = true

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if err := DoStreamingRequest(ctx, client, req, resp); err != nil {
		t.Fatalf("DoStreamingRequest returned error before streamed body: %v", err)
	}
	reader := bufio.NewReader(resp.BodyStream())
	if first, err := reader.ReadString('\n'); err != nil || first != "first\n" {
		t.Fatalf("first streamed body read = %q, %v", first, err)
	}
	startedAt := time.Now()
	_, err := reader.ReadString('\n')
	var networkError net.Error
	if !errors.Is(err, fasthttp.ErrTimeout) && !errors.Is(err, fasthttputil.ErrTimeout) &&
		(!errors.As(err, &networkError) || !networkError.Timeout()) {
		t.Fatalf("stalled streamed body error = %v, want network timeout", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("streamed body deadline took %s, want a bounded wait", elapsed)
	}
}

func TestMakeRequestWithContext_ContextCancelReturnsCancelledError(t *testing.T) {
	// Server takes 500ms to respond
	client, cleanup := newTestServer(t, 500*time.Millisecond, 200)
	defer cleanup()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	req.SetRequestURI("http://test/")

	// Cancel context explicitly (not deadline)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	_, bifrostErr, wait := MakeRequestWithContext(ctx, client, req, resp)

	// Should get a cancellation error with 499 status
	if bifrostErr == nil {
		t.Fatal("expected cancellation error")
	}
	if bifrostErr.Error.Type == nil || *bifrostErr.Error.Type != schemas.RequestCancelled {
		t.Fatalf("expected RequestCancelled error type, got: %v", bifrostErr.Error.Type)
	}
	if bifrostErr.StatusCode == nil || *bifrostErr.StatusCode != 499 {
		t.Fatalf("expected status 499, got: %v", bifrostErr.StatusCode)
	}

	// wait() should block until the goroutine finishes
	start := time.Now()
	wait()
	elapsed := time.Since(start)

	if elapsed < 200*time.Millisecond {
		t.Fatalf("wait() returned too quickly (%v), expected it to block until goroutine finishes", elapsed)
	}

	fasthttp.ReleaseRequest(req)
	fasthttp.ReleaseResponse(resp)
}

func TestMakeRequestWithContext_WaitPreventsDataRace(t *testing.T) {
	// This test verifies the fix for the data race. Under -race, accessing resp
	// while client.Do is still writing to it would be flagged. The wait function
	// ensures we don't release until the goroutine is done.
	//
	// Run with: go test -race -run TestMakeRequestWithContext_WaitPreventsDataRace

	// Server responds after 200ms
	client, cleanup := newTestServer(t, 200*time.Millisecond, 200)
	defer cleanup()

	for range 10 {
		func() {
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			req.SetRequestURI("http://test/")

			// Cancel context after 5ms — well before server responds
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()

			_, _, wait := MakeRequestWithContext(ctx, client, req, resp)

			// Simulate the real caller pattern: defer wait() before defer Release.
			// Go defers are LIFO, so wait() runs first, then Release.
			// This is the pattern that prevents the data race.
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)
			defer wait()
		}()
	}
}

func TestMakeRequestWithContext_SuccessWaitDoesNotBlock(t *testing.T) {
	client, cleanup := newTestServer(t, 0, 200)
	defer cleanup()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://test/")

	_, _, wait := MakeRequestWithContext(context.Background(), client, req, resp)

	// On the success path, wait should be a noop that returns immediately
	start := time.Now()
	wait()
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("wait() on success path should be a noop and return immediately")
	}
}

func TestMakeRequestWithContext_ConcurrentRequestsWithCancellation(t *testing.T) {
	// Simulate the production scenario: multiple concurrent requests where some
	// contexts cancel while the HTTP call is in-flight. Under -race, this would
	// detect the original bug where deferred Release races with client.Do.
	client, cleanup := newTestServer(t, 100*time.Millisecond, 200)
	defer cleanup()

	const numRequests = 20
	var completed atomic.Int32

	done := make(chan struct{})
	for range numRequests {
		go func() {
			defer func() {
				if completed.Add(1) == numRequests {
					close(done)
				}
			}()

			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			req.SetRequestURI("http://test/")

			// Half the requests cancel early, half complete normally
			var ctx context.Context
			var cancel context.CancelFunc
			if completed.Load()%2 == 0 {
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Millisecond)
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			}

			_, _, wait := MakeRequestWithContext(ctx, client, req, resp)
			// Correct pattern: wait before release
			wait()
			cancel()
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}()
	}

	select {
	case <-done:
		// All requests completed
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for requests, only %d/%d completed", completed.Load(), numRequests)
	}
}

func TestNewBifrostTimeoutError(t *testing.T) {
	err := NewBifrostTimeoutError("test timeout", context.DeadlineExceeded)

	if !err.IsBifrostError {
		t.Fatal("expected IsBifrostError to be true")
	}
	if err.AllowFallbacks == nil || *err.AllowFallbacks {
		t.Fatal("ambiguous provider timeouts must block fallbacks")
	}
	if err.StatusCode == nil || *err.StatusCode != 504 {
		t.Fatalf("expected StatusCode 504, got %v", err.StatusCode)
	}
	if err.Error.Type == nil || *err.Error.Type != schemas.RequestTimedOut {
		t.Fatalf("expected RequestTimedOut type, got %v", err.Error.Type)
	}
	if err.Error.Message != "test timeout" {
		t.Fatalf("expected 'test timeout', got %s", err.Error.Message)
	}
	// Note: ExtraFields.Provider is populated by bifrost.go's dispatcher via
	// PopulateExtraFields, not by NewBifrostTimeoutError — the constructor has
	// no provider context.
}

func TestMakeRequestWithContext_ClientError(t *testing.T) {
	// Test that client errors still return noop wait function
	client := &fasthttp.Client{
		Dial: func(addr string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "nonexistent.invalid"}}
		},
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://nonexistent.invalid/")

	_, bifrostErr, wait := MakeRequestWithContext(context.Background(), client, req, resp)
	defer wait()

	if bifrostErr == nil {
		t.Fatal("expected error for nonexistent host")
	}
	// Upstream connectivity failures (DNS/OpError) should surface as 502 Bad Gateway,
	// not the default 400 — see NewBifrostUpstreamConnectionError.
	if bifrostErr.StatusCode == nil || *bifrostErr.StatusCode != 502 {
		t.Fatalf("expected StatusCode 502, got %v", bifrostErr.StatusCode)
	}
	if bifrostErr.Error.Type == nil || *bifrostErr.Error.Type != schemas.ProviderConnectionFailed {
		t.Fatalf("expected ProviderConnectionFailed type, got %v", bifrostErr.Error.Type)
	}
	// wait should be noop since the goroutine completed (with error)
	start := time.Now()
	wait()
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("wait() should be noop on error path")
	}
}

func TestNewBifrostUpstreamConnectionError(t *testing.T) {
	err := NewBifrostUpstreamConnectionError("upstream dropped connection", context.DeadlineExceeded)

	if err.IsBifrostError {
		t.Fatal("expected IsBifrostError to be false (upstream is at fault)")
	}
	if err.StatusCode == nil || *err.StatusCode != 502 {
		t.Fatalf("expected StatusCode 502, got %v", err.StatusCode)
	}
	if err.Error.Type == nil || *err.Error.Type != schemas.ProviderConnectionFailed {
		t.Fatalf("expected ProviderConnectionFailed type, got %v", err.Error.Type)
	}
	if err.Error.Message != "upstream dropped connection" {
		t.Fatalf("expected 'upstream dropped connection', got %s", err.Error.Message)
	}
}

func TestMakeRequestWithContext_DeferOrderingPattern(t *testing.T) {
	// Verify the exact defer pattern used by callers works correctly under -race.
	// This mirrors the real provider code pattern.
	client, cleanup := newTestServer(t, 150*time.Millisecond, 200)
	defer cleanup()

	// Track the order of operations
	var order []string
	var orderDone = make(chan struct{})

	go func() {
		defer close(orderDone)

		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		req.SetRequestURI("http://test/")

		// Mimic the real provider pattern with defer ordering:
		// These defers run in reverse order (LIFO)
		defer func() {
			fasthttp.ReleaseRequest(req)
			order = append(order, "release-req")
		}()
		defer func() {
			fasthttp.ReleaseResponse(resp)
			order = append(order, "release-resp")
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, _, wait := MakeRequestWithContext(ctx, client, req, resp)
		// This defer runs FIRST (last declared = first to run)
		defer func() {
			wait()
			order = append(order, "wait-done")
		}()
	}()

	select {
	case <-orderDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	// Verify order: wait must complete before any release
	if len(order) != 3 {
		t.Fatalf("expected 3 operations, got %d: %v", len(order), order)
	}
	if order[0] != "wait-done" {
		t.Fatalf("expected wait-done first, got: %v", order)
	}
	if order[1] != "release-resp" {
		t.Fatalf("expected release-resp second, got: %v", order)
	}
	if order[2] != "release-req" {
		t.Fatalf("expected release-req third, got: %v", order)
	}
}
