package stogashttp

import (
	"context"
	"maps"
	"math"
	"math/rand/v2"
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
		{name: "model retired", failure: failure(http.StatusGone, ""), want: nextPair},
		{name: "model decommissioned", failure: failure(http.StatusBadRequest, "model_decommissioned"), want: nextPair},
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
		{name: "provider asks for longer", headers: map[string]string{"Retry-After": "3"}, min: 3 * time.Second, max: 4 * time.Second},
		{name: "provider asks for less", retries: 2, headers: map[string]string{"retry-after-ms": "10"}, min: 1500 * time.Millisecond, max: 2 * time.Second},
		{name: "provider asks for nearly the limit", headers: map[string]string{"retry-after-ms": "7500"}, min: 7500 * time.Millisecond, max: retryMaxWait},
		{name: "provider asks for the limit", headers: map[string]string{"Retry-After": "8"}, min: retryMaxWait, max: retryMaxWait},
		{name: "provider asks past the limit", headers: map[string]string{"Retry-After": "30"}, min: 30 * time.Second, max: 30 * time.Second},
		{name: "provider asks for too long to represent", headers: map[string]string{"Retry-After": "1e300"}, min: math.MaxInt64, max: math.MaxInt64},
	} {
		ctx := retryAfterContext(test.headers)
		least, most := time.Duration(math.MaxInt64), time.Duration(0)
		for range 100 {
			wait := retryWait(test.retries, ctx)
			if wait < test.min || wait > test.max {
				t.Fatalf("%s: wait = %s, want %s to %s", test.name, wait, test.min, test.max)
			}
			least, most = min(least, wait), max(most, wait)
		}
		// Spread waits vary: 100 within a tenth of their range has chance below 10⁻²⁵.
		if test.max > test.min && most-least < (test.max-test.min)/10 {
			t.Fatalf("%s: waits from %s to %s, not spread over %s to %s", test.name, least, most, test.min, test.max)
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

func TestSpreadRetryAfterRoundsUpAndSpreads(t *testing.T) {
	for wait, want := range map[time.Duration][]string{
		0:                                {"1", "2"},
		time.Nanosecond:                  {"1", "2"},
		time.Second:                      {"1", "2"},
		time.Second + time.Millisecond:   {"2", "3"},
		59 * time.Second:                 {"59", "60"},
		59*time.Second + time.Nanosecond: {"60"},
		90*time.Second + time.Nanosecond: {"91"},
		time.Duration(math.MaxInt64):     {"9223372037"},
	} {
		seen := map[string]bool{}
		// Each value of a spread is missed by all 64 draws with chance 2⁻⁶⁴.
		for range 64 {
			seen[spreadRetryAfter(wait)] = true
		}
		if !maps.Equal(seen, map[string]bool{want[0]: true, want[len(want)-1]: true}) {
			t.Errorf("spreadRetryAfter(%s) = %v, want %v", wait, seen, want)
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

// Every combination of failure, retry budget, wait and remaining time takes
// the step that the retry rules state, and asks for a wait only to retry.
func TestNextStepCoversEveryCombination(t *testing.T) {
	waits := []time.Duration{0, retryInitialWait, retryMaxWait - 1, retryMaxWait, retryMaxWait + 1, time.Hour}
	remaining := []time.Duration{0, retryInitialWait, retryMaxWait, retryMaxWait + time.Second, time.Hour}
	for _, action := range []failureAction{stopRun, nextPair, retryPair} {
		for retries := 0; retries <= 3; retries++ {
			for used := 0; used <= retries+1; used++ {
				for _, wait := range waits {
					for _, left := range remaining {
						for _, hasNext := range []bool{false, true} {
							asked := false
							step, got := nextStep(action, used, retries, func() time.Duration { asked = true; return wait }, left, hasNext)
							retry := action == retryPair && used < retries && wait <= retryMaxWait && wait < left
							want := stepStop
							switch {
							case retry:
								want = stepRetry
							case action != stopRun && hasNext:
								want = stepAdvance
							}
							if step != want {
								t.Fatalf("action=%d used=%d/%d wait=%s left=%s next=%v: step %d, want %d", action, used, retries, wait, left, hasNext, step, want)
							}
							if (step == stepRetry) != (got > 0 || wait == 0 && retry) || step != stepRetry && got != 0 {
								t.Fatalf("step %d returned wait %s", step, got)
							}
							// The wait, which can be random, is drawn only when a retry is possible.
							if asked != (action == retryPair && used < retries) {
								t.Fatalf("wait drawn=%v for action=%d used=%d/%d", asked, action, used, retries)
							}
						}
					}
				}
			}
		}
	}
}

// A run over a plan of up to three pairs, each with its own retries, never
// calls a pair more than once plus its retries, never uses more pairs than the
// plan holds, never retries past the caller's wait, and ends at a final failure.
func TestRunStepsStayWithinThePlan(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 7))
	actions := []failureAction{stopRun, nextPair, retryPair}
	for trial := range 20000 {
		pairs := 1 + rng.IntN(3)
		budgets := make([]int, pairs)
		for i := range budgets {
			budgets[i] = rng.IntN(4)
		}
		left := time.Duration(rng.IntN(40)) * time.Second
		pair, used, calls := 0, 0, make([]int, pairs)
		for {
			calls[pair]++
			action := actions[rng.IntN(len(actions))]
			wait := time.Duration(rng.IntN(12)) * time.Second
			step, slept := nextStep(action, used, budgets[pair], func() time.Duration { return wait }, left, pair+1 < pairs)
			if step == stepRetry {
				if action != retryPair || slept > retryMaxWait || slept >= left {
					t.Fatalf("trial %d: retried after action %d with wait %s of %s", trial, action, slept, left)
				}
				used++
				left -= slept
				continue
			}
			if action == stopRun && step != stepStop {
				t.Fatalf("trial %d: a final failure did not end the run", trial)
			}
			if step == stepStop {
				break
			}
			pair, used = pair+1, 0
		}
		for i, count := range calls {
			if count > 1+budgets[i] {
				t.Fatalf("trial %d: pair %d called %d times with %d retries", trial, i, count, budgets[i])
			}
		}
	}
}
