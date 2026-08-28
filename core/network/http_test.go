package network

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

// TestStaleConnectionRetryIfErr validates the error-matching logic of
// StaleConnectionRetryIfErr for different error types and attempt counts.
func TestStaleConnectionRetryIfErr(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		attempts  int
		wantReset bool
		wantRetry bool
	}{
		{
			name:      "retries on whitespace error (first attempt)",
			err:       fmt.Errorf(`error when reading response headers: cannot find whitespace in the first line of response "217\r\ndata: ..."`),
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "retries on connection reset by peer",
			err:       fmt.Errorf("read tcp 10.0.0.1:54321->10.0.0.2:443: read: connection reset by peer"),
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "retries on io.EOF (server closed connection)",
			err:       io.EOF,
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "retries on wrapped io.EOF",
			err:       fmt.Errorf("read response: %w", io.EOF),
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "retries on unexpected EOF",
			err:       io.ErrUnexpectedEOF,
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "retries on wrapped unexpected EOF",
			err:       fmt.Errorf("read response: %w", io.ErrUnexpectedEOF),
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "retries on broken pipe (write to closed connection)",
			err:       fmt.Errorf("write tcp 10.0.0.1:53374->10.0.0.2:30000: write: broken pipe"),
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "retries on use of closed network connection",
			err:       fmt.Errorf("read tcp 10.0.0.1:53374->10.0.0.2:443: use of closed network connection"),
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "retries on server closed connection",
			err:       fmt.Errorf("server closed connection before returning the first response byte"),
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			// fasthttp.ErrConnectionClosed is treated as retryable: it means the server
			// closed an idle keep-alive connection before sending any response byte (a
			// stale connection). In fasthttp v1.68.0 the callback actually receives raw
			// io.EOF — the sentinel is only produced AFTER the retry loop (client.go:1413) —
			// but we match it explicitly to stay correct if a future version surfaces it.
			name:      "retries on fasthttp.ErrConnectionClosed sentinel",
			err:       fasthttp.ErrConnectionClosed,
			attempts:  1,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "retries on second stale-connection attempt",
			err:       io.EOF,
			attempts:  2,
			wantReset: true,
			wantRetry: true,
		},
		{
			name:      "does not retry after max stale-connection attempts",
			err:       io.EOF,
			attempts:  4,
			wantReset: false,
			wantRetry: false,
		},
		{
			name:      "does not retry on nil error",
			err:       nil,
			attempts:  1,
			wantReset: false,
			wantRetry: false,
		},
		{
			name:      "does not retry on unrelated error",
			err:       fmt.Errorf("dial tcp: lookup api.example.com: no such host"),
			attempts:  1,
			wantReset: false,
			wantRetry: false,
		},
		{
			name:      "does not retry on timeout",
			err:       fasthttp.ErrTimeout,
			attempts:  1,
			wantReset: false,
			wantRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(request)
			request.Header.SetMethod(http.MethodGet)
			resetTimeout, retry := StaleConnectionRetryIfErr(request, tt.attempts, tt.err)
			if resetTimeout != tt.wantReset {
				t.Errorf("resetTimeout = %v, want %v", resetTimeout, tt.wantReset)
			}
			if retry != tt.wantRetry {
				t.Errorf("retry = %v, want %v", retry, tt.wantRetry)
			}
		})
	}
}

func TestStaleConnectionRetryIfErrDoesNotReplayPost(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "wrapped EOF", err: fmt.Errorf("read response: %w", io.EOF)},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF},
		{name: "connection reset", err: fmt.Errorf("read: connection reset by peer")},
		{name: "broken pipe", err: fmt.Errorf("write: broken pipe")},
		{name: "closed connection", err: fmt.Errorf("use of closed network connection")},
		{name: "no response byte", err: fmt.Errorf("server closed connection before returning the first response byte")},
		{name: "stale response bytes", err: fmt.Errorf("cannot find whitespace in the first line of response")},
		{name: "fasthttp closed sentinel", err: fasthttp.ErrConnectionClosed},
		{name: "timeout", err: fasthttp.ErrTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(request)
			request.Header.SetMethod(http.MethodPost)

			resetTimeout, retry := StaleConnectionRetryIfErr(request, 1, tt.err)
			if resetTimeout || retry {
				t.Fatalf("POST must not be retried after %v", tt.err)
			}
		})
	}
}

func TestFasthttpClientDoesNotReplayPostAfterProviderReceivesBody(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		if _, err := io.Copy(io.Discard, request.Body); err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		received.Add(1)
		// Close the connection after the full request arrived but before any
		// response. The client cannot know whether inference already started.
		panic(http.ErrAbortHandler)
	}))
	defer server.Close()

	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)
	request.Header.SetMethod(http.MethodPost)
	request.SetRequestURI(server.URL)
	request.SetBodyString(`{"model":"test","input":"hello"}`)

	client := &fasthttp.Client{RetryIfErr: StaleConnectionRetryIfErr}
	if err := client.DoTimeout(request, response, 2*time.Second); err == nil {
		t.Fatal("expected an ambiguous response-read failure")
	}
	if got := received.Load(); got != 1 {
		t.Fatalf("provider received %d POST requests, want exactly 1", got)
	}
}

// TestMaxConnDurationForcesReconnection verifies that MaxConnDuration causes
// fasthttp to close and replace connections after the configured lifetime,
// preventing stale long-lived connections from accumulating during sustained
// back-to-back request traffic.
//
// Uses the server's ConnState callback to reliably count new TCP connections
// (r.RemoteAddr is unreliable because the OS can reuse ephemeral ports).
func TestMaxConnDurationForcesReconnection(t *testing.T) {
	const maxConnDuration = 150 * time.Millisecond

	// Track new connections via ConnState (fires once per new TCP accept)
	var newConnCount atomic.Int32

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnCount.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	t.Run("with_MaxConnDuration_connection_is_recycled", func(t *testing.T) {
		newConnCount.Store(0)

		client := &fasthttp.Client{
			MaxConnsPerHost: 1,
			MaxConnDuration: maxConnDuration,
		}
		defer client.CloseIdleConnections()

		// First request: establishes connection A
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI(server.URL)
		req.Header.SetMethod(http.MethodPost)
		req.SetBodyString(`{"test": 1}`)

		if err := client.Do(req, resp); err != nil {
			t.Fatalf("First request failed: %v", err)
		}
		_ = resp.Body()

		connsAfterFirst := newConnCount.Load()
		t.Logf("After first request: %d new connections", connsAfterFirst)

		// Wait for MaxConnDuration to expire.
		t.Logf("Waiting %v for MaxConnDuration to expire...", maxConnDuration+50*time.Millisecond)
		time.Sleep(maxConnDuration + 50*time.Millisecond)

		// Second request: reuses connection A but sends Connection: close
		// (fasthttp's MaxConnDuration sets Connection: close on expired conns,
		// telling the server to close the connection after the response)
		req2 := fasthttp.AcquireRequest()
		resp2 := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req2)
		defer fasthttp.ReleaseResponse(resp2)

		req2.SetRequestURI(server.URL)
		req2.Header.SetMethod(http.MethodPost)
		req2.SetBodyString(`{"test": 2}`)

		if err := client.Do(req2, resp2); err != nil {
			t.Fatalf("Second request failed: %v", err)
		}
		_ = resp2.Body()

		// Third request: connection A is now closed by server → must create connection B
		req3 := fasthttp.AcquireRequest()
		resp3 := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req3)
		defer fasthttp.ReleaseResponse(resp3)

		req3.SetRequestURI(server.URL)
		req3.Header.SetMethod(http.MethodPost)
		req3.SetBodyString(`{"test": 3}`)

		if err := client.Do(req3, resp3); err != nil {
			t.Fatalf("Third request failed: %v", err)
		}

		connsAfterThird := newConnCount.Load()
		if connsAfterThird < 2 {
			t.Errorf("expected at least 2 new connections after MaxConnDuration recycling, got %d", connsAfterThird)
		} else {
			t.Logf("Connection recycled: %d total new connections", connsAfterThird)
		}
	})

	t.Run("without_MaxConnDuration_connection_is_reused", func(t *testing.T) {
		newConnCount.Store(0)

		client := &fasthttp.Client{
			MaxConnsPerHost: 1,
			// No MaxConnDuration — connections live forever
		}
		defer client.CloseIdleConnections()

		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI(server.URL)
		req.Header.SetMethod(http.MethodPost)
		req.SetBodyString(`{"test": 1}`)

		if err := client.Do(req, resp); err != nil {
			t.Fatalf("First request failed: %v", err)
		}
		_ = resp.Body()

		// Wait same duration as above
		time.Sleep(maxConnDuration + 50*time.Millisecond)

		req2 := fasthttp.AcquireRequest()
		resp2 := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req2)
		defer fasthttp.ReleaseResponse(resp2)

		req2.SetRequestURI(server.URL)
		req2.Header.SetMethod(http.MethodPost)
		req2.SetBodyString(`{"test": 2}`)

		if err := client.Do(req2, resp2); err != nil {
			t.Fatalf("Second request failed: %v", err)
		}

		totalConns := newConnCount.Load()
		// Without MaxConnDuration, the same connection should be reused
		if totalConns != 1 {
			t.Errorf("expected one reused connection without MaxConnDuration, got %d", totalConns)
		}
	})
}

// TestMaxConnWaitTimeoutAlignedWithReadTimeout verifies that when the connection
// pool is exhausted, requests wait for MaxConnWaitTimeout (aligned with ReadTimeout)
// before failing, not the old hardcoded 10s.
func TestMaxConnWaitTimeoutAlignedWithReadTimeout(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var startedOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedOnce.Do(func() { close(firstStarted) })
		<-releaseFirst
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	const maxConnWait = 200 * time.Millisecond
	client := &fasthttp.Client{
		MaxConnsPerHost:    1,
		MaxConnWaitTimeout: maxConnWait,
		ReadTimeout:        2 * time.Second,
		WriteTimeout:       2 * time.Second,
	}
	defer client.CloseIdleConnections()

	// Hold the first request until the second request exhausts its bounded wait.
	var wg sync.WaitGroup
	firstReqErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI(server.URL)
		req.Header.SetMethod(http.MethodPost)
		req.SetBodyString(`{"slot": "occupied"}`)

		firstReqErr <- client.Do(req, resp)
	}()

	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		close(releaseFirst)
		wg.Wait()
		t.Fatal("first request did not occupy the connection pool")
	}

	// The second request must wait for MaxConnWaitTimeout and then fail.
	start := time.Now()
	req2 := fasthttp.AcquireRequest()
	resp2 := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req2)
	defer fasthttp.ReleaseResponse(resp2)

	req2.SetRequestURI(server.URL)
	req2.Header.SetMethod(http.MethodPost)
	req2.SetBodyString(`{"waiting": true}`)

	err := client.Do(req2, resp2)
	elapsed := time.Since(start)

	close(releaseFirst)
	wg.Wait()

	if firstErr := <-firstReqErr; firstErr != nil {
		t.Fatalf("first request failed; pool-exhaustion scenario was not exercised: %v", firstErr)
	}

	if !errors.Is(err, fasthttp.ErrNoFreeConns) {
		t.Fatalf("second request error = %v, want %v", err, fasthttp.ErrNoFreeConns)
	}

	if elapsed < maxConnWait/2 || elapsed > 2*time.Second {
		t.Errorf("expected pool wait near %v, got %v", maxConnWait, elapsed)
	}
}

// TestDefaultClientConfigValues verifies that DefaultClientConfig contains
// the expected values for connection pool settings.
func TestDefaultClientConfigValues(t *testing.T) {
	if DefaultClientConfig.ReadTimeout != 60*time.Second {
		t.Errorf("ReadTimeout = %v, want 60s", DefaultClientConfig.ReadTimeout)
	}
	if DefaultClientConfig.WriteTimeout != 60*time.Second {
		t.Errorf("WriteTimeout = %v, want 60s", DefaultClientConfig.WriteTimeout)
	}
	if DefaultClientConfig.MaxIdleConnDuration != 30*time.Second {
		t.Errorf("MaxIdleConnDuration = %v, want 30s", DefaultClientConfig.MaxIdleConnDuration)
	}
	if DefaultClientConfig.MaxConnDuration != 300*time.Second {
		t.Errorf("MaxConnDuration = %v, want 300s", DefaultClientConfig.MaxConnDuration)
	}
	if DefaultClientConfig.MaxConnsPerHost != 200 {
		t.Errorf("MaxConnsPerHost = %d, want 200", DefaultClientConfig.MaxConnsPerHost)
	}
	// Verify the provider-level constant matches
	if schemas.DefaultMaxConnDurationInSeconds != 300 {
		t.Errorf("DefaultMaxConnDurationInSeconds = %d, want 300", schemas.DefaultMaxConnDurationInSeconds)
	}
}

// TestCreateFasthttpClientPoolSettings verifies that the HTTPClientFactory
// creates fasthttp clients with the correct pool settings including
// MaxConnDuration, MaxConnWaitTimeout, and FIFO ConnPoolStrategy.
func TestCreateFasthttpClientPoolSettings(t *testing.T) {
	factory := NewHTTPClientFactory(nil, nil)
	client := factory.GetFasthttpClient(ClientPurposeInference)

	if client.MaxConnDuration != DefaultClientConfig.MaxConnDuration {
		t.Errorf("MaxConnDuration = %v, want %v", client.MaxConnDuration, DefaultClientConfig.MaxConnDuration)
	}
	if client.MaxConnWaitTimeout != DefaultClientConfig.ReadTimeout {
		t.Errorf("MaxConnWaitTimeout = %v, want %v (aligned with ReadTimeout)", client.MaxConnWaitTimeout, DefaultClientConfig.ReadTimeout)
	}
	if client.ConnPoolStrategy != fasthttp.FIFO {
		t.Errorf("ConnPoolStrategy = %v, want FIFO (%v)", client.ConnPoolStrategy, fasthttp.FIFO)
	}
	if client.MaxIdleConnDuration != DefaultClientConfig.MaxIdleConnDuration {
		t.Errorf("MaxIdleConnDuration = %v, want %v", client.MaxIdleConnDuration, DefaultClientConfig.MaxIdleConnDuration)
	}
	if client.MaxConnsPerHost != DefaultClientConfig.MaxConnsPerHost {
		t.Errorf("MaxConnsPerHost = %d, want %d", client.MaxConnsPerHost, DefaultClientConfig.MaxConnsPerHost)
	}
}
