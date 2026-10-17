package stogashttp

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
)

// testRun binds one pair whose provider request is ready.
func testRun(server *Server, ctx *requestContext, request *schemas.BifrostContext, state *stogas.State, cancel context.CancelFunc) *providerRun {
	pair := &providerPair{Pair: state.Pair, ctx: schemas.NewBifrostContext(request, schemas.NoDeadline), request: &schemas.BifrostRequest{}}
	return &providerRun{server: server, client: ctx, request: request, state: state, cancel: cancel, pair: pair, attempted: pair}
}

func TestFailureActionFor(t *testing.T) {
	failure := func(status int, code string) *schemas.BifrostError {
		failure := &schemas.BifrostError{Error: &schemas.ErrorField{Message: "provider failure"}}
		if status != 0 {
			failure.StatusCode = schemas.Ptr(status)
		}
		if code != "" {
			failure.Error.Code = schemas.Ptr(code)
		}
		return failure
	}
	ours := failure(http.StatusInternalServerError, "")
	ours.AllowFallbacks = schemas.Ptr(false)
	billed := failure(http.StatusServiceUnavailable, "")
	billed.ExtraFields.BilledUsage = &schemas.BifrostLLMUsage{PromptTokens: 3}
	cancelled := failure(0, "")
	cancelled.Type = schemas.Ptr(schemas.RequestCancelled)
	timedOut := failure(0, "")
	timedOut.Type = schemas.Ptr(schemas.RequestTimedOut)
	unreachable := failure(0, "")
	unreachable.Type = schemas.Ptr(schemas.ProviderConnectionFailed)
	failedResponse := &requestMemoryLease{}
	failedResponse.responseFailed.Store(true)
	for _, test := range []struct {
		name    string
		failure *schemas.BifrostError
		headers map[string]string
		memory  *requestMemoryLease
		want    failureAction
	}{
		{name: "rate limit", failure: failure(http.StatusTooManyRequests, ""), want: retryPair},
		{name: "conflict", failure: failure(http.StatusConflict, ""), want: retryPair},
		{name: "server error", failure: failure(http.StatusInternalServerError, ""), want: retryPair},
		{name: "unavailable", failure: failure(http.StatusServiceUnavailable, ""), want: retryPair},
		{name: "overloaded", failure: failure(529, ""), want: retryPair},
		{name: "timeout", failure: timedOut, want: retryPair},
		{name: "connection", failure: unreachable, want: retryPair},
		{name: "invalid response", failure: failure(http.StatusBadGateway, "upstream_protocol_error"), want: retryPair},
		{name: "quota", failure: failure(http.StatusTooManyRequests, "insufficient_quota"), want: nextPair},
		{name: "authentication", failure: failure(http.StatusUnauthorized, ""), want: nextPair},
		{name: "permission", failure: failure(http.StatusForbidden, ""), want: nextPair},
		{name: "deployment gone", failure: failure(http.StatusNotFound, ""), want: nextPair},
		{name: "invalid request", failure: failure(http.StatusBadRequest, ""), want: stopRun},
		{name: "context length", failure: failure(http.StatusBadRequest, "context_length_exceeded"), want: stopRun},
		{name: "content filter", failure: failure(http.StatusBadRequest, "content_filter"), want: stopRun},
		{name: "cancelled", failure: cancelled, want: stopRun},
		{name: "our failure", failure: ours, want: stopRun},
		{name: "billed usage", failure: billed, want: stopRun},
		{name: "response memory", failure: failure(http.StatusServiceUnavailable, ""), memory: failedResponse, want: stopRun},
		{name: "provider asks for a retry", failure: failure(http.StatusBadRequest, ""), headers: map[string]string{"x-should-retry": "true"}, want: retryPair},
		{name: "provider refuses a retry", failure: failure(http.StatusInternalServerError, ""), headers: map[string]string{"X-Should-Retry": "false"}, want: nextPair},
		{name: "provider refuses a retry of a credential", failure: failure(http.StatusUnauthorized, ""), headers: map[string]string{"x-should-retry": "false"}, want: nextPair},
		{name: "provider asks to retry billed usage", failure: billed, headers: map[string]string{"x-should-retry": "true"}, want: stopRun},
		{name: "provider asks to retry our failure", failure: ours, headers: map[string]string{"x-should-retry": "true"}, want: stopRun},
	} {
		if got := failureActionFor(test.failure, retryAfterContext(test.headers), test.memory); got != test.want {
			t.Errorf("%s: action = %d, want %d", test.name, got, test.want)
		}
	}
}

func retryAfterContext(headers map[string]string) *schemas.BifrostContext {
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	if headers != nil {
		ctx.SetValue(schemas.BifrostContextKeyProviderResponseHeaders, headers)
	}
	return ctx
}

func TestRetryWaitBacksOffAndHonorsRetryAfter(t *testing.T) {
	for _, test := range []struct {
		name     string
		retries  int
		headers  map[string]string
		min, max time.Duration
	}{
		{name: "first retry", min: 375 * time.Millisecond, max: 500 * time.Millisecond},
		{name: "third retry", retries: 2, min: 1500 * time.Millisecond, max: 2 * time.Second},
		{name: "longest backoff", retries: 10, min: 6 * time.Second, max: retryMaxWait},
		{name: "provider asks for longer", headers: map[string]string{"Retry-After": "3"}, min: 3 * time.Second, max: 3 * time.Second},
		{name: "provider asks for less", retries: 2, headers: map[string]string{"retry-after-ms": "10"}, min: 1500 * time.Millisecond, max: 2 * time.Second},
		{name: "provider asks past the limit", headers: map[string]string{"Retry-After": "30"}, min: 30 * time.Second, max: 30 * time.Second},
	} {
		ctx := retryAfterContext(test.headers)
		for range 100 {
			if wait := retryWait(test.retries, ctx); wait < test.min || wait > test.max {
				t.Fatalf("%s: wait = %s, want %s to %s", test.name, wait, test.min, test.max)
			}
		}
	}
}

func TestProviderRetryAfter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, test := range []struct {
			name    string
			headers map[string]string
			want    time.Duration
			ok      bool
		}{
			{name: "milliseconds", headers: map[string]string{"retry-after-ms": "1500.5"}, want: 1500500 * time.Microsecond, ok: true},
			{name: "milliseconds first", headers: map[string]string{"Retry-After-Ms": "250", "Retry-After": "9"}, want: 250 * time.Millisecond, ok: true},
			{name: "invalid milliseconds", headers: map[string]string{"retry-after-ms": "soon", "retry-after": "2.5"}, want: 2500 * time.Millisecond, ok: true},
			{name: "date", headers: map[string]string{"Retry-After": time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)}, want: 5 * time.Second, ok: true},
			{name: "past date", headers: map[string]string{"Retry-After": time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat)}, ok: true},
			{name: "huge", headers: map[string]string{"Retry-After": "1e300"}, want: math.MaxInt64, ok: true},
			{name: "infinite", headers: map[string]string{"Retry-After": "Inf"}, want: math.MaxInt64, ok: true},
			{name: "negative", headers: map[string]string{"Retry-After": "-1"}},
			{name: "not a number", headers: map[string]string{"Retry-After": "NaN"}},
			{name: "words", headers: map[string]string{"Retry-After": "soon"}},
			{name: "absent"},
		} {
			wait, ok := providerRetryAfter(retryAfterContext(test.headers))
			if wait != test.want || ok != test.ok {
				t.Errorf("%s: wait = %s, %t, want %s, %t", test.name, wait, ok, test.want, test.ok)
			}
		}
	})
}

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	for wait, want := range map[time.Duration]string{
		0:                                "0",
		time.Nanosecond:                  "1",
		time.Second:                      "1",
		time.Second + time.Millisecond:   "2",
		time.Duration(math.MaxInt64):     "9223372037",
		90*time.Second + time.Nanosecond: "91",
	} {
		if got := retryAfterSeconds(wait); got != want {
			t.Errorf("retryAfterSeconds(%s) = %q, want %q", wait, got, want)
		}
	}
}

func TestResponseDeadlineGivesEachCallAnIdleWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		wait := newResponseDeadline(time.Now(), time.Minute)
		defer wait.stop()
		if !wait.startOutput(10*time.Second) || wait.remaining() != 10*time.Second {
			t.Fatalf("first call window = %s", wait.remaining())
		}
		time.Sleep(8 * time.Second)
		// A fallback's policy can set another idle window, which output renews.
		if !wait.startOutput(20*time.Second) || wait.remaining() != 20*time.Second {
			t.Fatalf("fallback window = %s", wait.remaining())
		}
		time.Sleep(15 * time.Second)
		wait.observe(time.Now())
		if wait.remaining() != 20*time.Second {
			t.Fatalf("renewed fallback window = %s", wait.remaining())
		}
		time.Sleep(25 * time.Second)
		if !wait.timedOut() {
			t.Fatal("a silent call outlived its idle window")
		}
		wait = newResponseDeadline(time.Now(), time.Minute)
		for range 6 {
			time.Sleep(9 * time.Second)
			if !wait.startOutput(10 * time.Second) {
				t.Fatal("a call within the total deadline did not start")
			}
		}
		if wait.remaining() != 6*time.Second {
			t.Fatalf("window past the total deadline = %s", wait.remaining())
		}
		time.Sleep(6 * time.Second)
		synctest.Wait()
		if !wait.timedOut() || wait.startOutput(10*time.Second) {
			t.Fatal("a call started after the total deadline")
		}
		wait = newResponseDeadline(time.Now(), time.Minute)
		wait.stop()
		if wait.startOutput(10*time.Second) || wait.timedOut() || wait.remaining() != 0 {
			t.Fatal("a caller that left became a timeout or kept a window")
		}
	})
}

func TestProviderPanicReachesTheOwner(t *testing.T) {
	ctx := &requestContext{writer: &sessionResponse{}, request: httptest.NewRequest(http.MethodPost, "/v1/responses", nil)}
	request, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	run := testRun(&Server{}, ctx, request, &stogas.State{Pair: stogas.Pair{Resolution: testResolution()}}, cancel)
	calls := 0
	result, pending := runProvider(ctx, run, func(*schemas.BifrostContext, *schemas.BifrostRequest) (string, *schemas.BifrostError) {
		calls++
		panic(http.ErrAbortHandler)
	}, false)
	if pending != nil || result.panic != http.ErrAbortHandler || calls != 1 {
		t.Fatalf("panic = %v, calls = %d", result.panic, calls)
	}
	if result.failure == nil || *result.failure.StatusCode != http.StatusInternalServerError || failureActionFor(result.failure, result.ctx, nil) != stopRun {
		t.Fatal("a provider panic can start another call")
	}
}
