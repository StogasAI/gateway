package stogashttp

import (
	"context"
	"encoding/json"
	"maps"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
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
		{name: "workspace that refuses the deployment's inference geo", failure: anthropicRefusal(http.StatusBadRequest, "inference_geo 'global' is not allowed for this workspace. Allowed values: ['us']"), headers: map[string]string{"x-should-retry": "false"}, want: nextPair},
		{name: "account spend limit", failure: anthropicRefusal(http.StatusBadRequest, "You have reached your specified workspace API usage limits. You will regain access on 2026-12-01 at 00:00 UTC."), want: nextPair},
		{name: "spend cap", failure: anthropicRefusal(http.StatusTooManyRequests, "You have reached your API usage limits: your organization has crossed its monthly API usage threshold."), want: nextPair},
		{name: "context length", failure: failure(http.StatusBadRequest, "context_length_exceeded"), want: nextPair},
		{name: "prompt longer than the deployment's window", failure: anthropicRefusal(http.StatusBadRequest, "prompt is too long: 215000 tokens > 200000 maximum"), want: nextPair},
		{name: "body larger than the provider takes", failure: failure(http.StatusRequestEntityTooLarge, ""), want: nextPair},
		{name: "image the provider cannot read", failure: failure(http.StatusBadRequest, "image_too_large"), want: nextPair},
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
		{name: "another model version served", failure: servedModelChangedError(), want: nextPair},
		{name: "provider asks to retry another model version", failure: servedModelChangedError(), headers: map[string]string{"x-should-retry": "true"}, want: nextPair},
	} {
		if got := failureActionFor(test.failure, retryAfterContext(test.headers), test.memory); got != test.want {
			t.Errorf("%s: action = %d, want %d", test.name, got, test.want)
		}
	}
}

// anthropicRefusal is an Anthropic error that only its message ties to the key's account.
func anthropicRefusal(status int, message string) *schemas.BifrostError {
	errorType := "invalid_request_error"
	if status == http.StatusTooManyRequests {
		errorType = "rate_limit_error"
	}
	return &schemas.BifrostError{StatusCode: schemas.Ptr(status), Error: &schemas.ErrorField{Type: schemas.Ptr(errorType), Message: message}}
}

func TestAzureReplyThatNamesAnotherVersionFailsItsCall(t *testing.T) {
	binding := billing.AzureBinding{ID: "binding-1", ModelName: "gpt-5.6-sol", ModelVersion: "2026-07-09"}
	authorization := &billing.Authorization{AzureBinding: &binding, UpstreamByok: "byok-1"}
	// Without a runtime the server stops and rechecks nothing, which the stogas tests cover.
	server := &Server{}
	discarded := 0
	discard := func() { discarded++ }
	for _, headers := range []map[string]string{
		{"X-Ms-Served-Model": "gpt-5.6-sol-2026-07-09"},
		{"x-ms-served-model": "GPT-5.6-sol-2026-07-09"},
		// A reply that names no version, or none at all, is no evidence.
		{"x-ms-served-model": "gpt-5.6-sol"},
		nil,
	} {
		if failure := server.checkAzureReply(retryAfterContext(headers), authorization, nil, discard); failure != nil || discarded != 0 {
			t.Fatalf("headers %v: failure = %v, discarded %d", headers, failure, discarded)
		}
	}
	changed := retryAfterContext(map[string]string{"x-ms-served-model": "gpt-5.6-sol-2026-10-28"})
	failure := server.checkAzureReply(changed, authorization, nil, discard)
	if failure == nil || discarded != 1 || failureActionFor(failure, changed, nil) != nextPair {
		t.Fatalf("a reply from another version: failure = %v, discarded %d", failure, discarded)
	}
	status, payload := publicBifrostError(failure)
	body := payload["error"].(map[string]any)
	if status != http.StatusBadRequest || body["code"] != billing.ErrByokTargetChanged.Code || body["message"] != billing.ErrByokTargetChanged.Message {
		t.Fatalf("caller error = %d %v", status, body)
	}
	if billing.NormalizeUpstreamStatus(failure) != "model_unavailable" {
		t.Fatalf("logged upstream status = %s", billing.NormalizeUpstreamStatus(failure))
	}
	// A provider failure stays the call's failure.
	gone := &schemas.BifrostError{StatusCode: schemas.Ptr(http.StatusNotFound), Error: &schemas.ErrorField{Message: "DeploymentNotFound"}}
	if server.checkAzureReply(changed, authorization, gone, discard) != gone || discarded != 1 {
		t.Fatal("a provider failure was replaced")
	}
}

func TestDiscardedStreamStopsItsProvider(t *testing.T) {
	attempt, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	stream := make(chan *schemas.BifrostStreamChunk)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		defer close(stream)
		for {
			select {
			case stream <- &schemas.BifrostStreamChunk{}:
			case <-attempt.Done():
				return
			}
		}
	}()
	discardProviderResponse(attempt, stream)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the discarded stream's provider kept running")
	}
	// A unary reply needs nothing.
	discardProviderResponse(attempt, &schemas.BifrostResponse{})
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

// waitRefusal is a billing refusal that ends after wait.
type waitRefusal struct {
	*billing.RequestError
	wait time.Duration
}

func (e waitRefusal) Unwrap() error             { return e.RequestError }
func (e waitRefusal) RetryAfter() time.Duration { return e.wait }

// When no pair serves a request, the caller gets the failure that ended the
// run, else the first failure, unless a later one passes sooner by waiting. A
// pair counts with its latest failure, and a model that is gone yields to any
// other failure.
func TestRunReportsTheFailureThatPassesSoonest(t *testing.T) {
	type failure struct {
		pair    int
		status  int
		code    string
		headers map[string]string
		after   time.Duration // since the previous failure
		local   error         // a failure before a provider call
		unsent  bool          // the provider failure came before the call was sent
	}
	wait := func(seconds string) map[string]string { return map[string]string{"retry-after": seconds} }
	noRetry := map[string]string{"x-should-retry": "false"}
	for _, test := range []struct {
		name        string
		failures    []failure
		status      int
		code        string
		retryAfter  []string // the values that Retry-After can take; none when empty
		shouldRetry string
		gateway     bool // the request records the answer as its gateway error
	}{
		{name: "a wait passes a credential failure", failures: []failure{{status: 429, headers: wait("30")}, {pair: 1, status: 401}},
			status: 429, code: "upstream_rate_limit_error", retryAfter: []string{"30", "31"}},
		{name: "a later wait passes an earlier credential failure", failures: []failure{{status: 401}, {pair: 1, status: 429, headers: wait("30")}},
			status: 429, code: "upstream_rate_limit_error", retryAfter: []string{"30", "31"}},
		{name: "an overload passes a retired model", failures: []failure{{status: 503}, {pair: 1, status: 410}}, status: 503},
		{name: "a dropped connection passes a missing deployment", failures: []failure{{code: schemas.ProviderConnectionFailed}, {pair: 1, status: 404}}, status: 502},
		{name: "a server error passes before a long wait", failures: []failure{{status: 500}, {pair: 1, status: 429, headers: wait("30")}}, status: 500},
		{name: "the shorter wait", failures: []failure{{status: 429, headers: wait("30")}, {pair: 1, status: 429, headers: wait("2")}},
			status: 429, code: "upstream_rate_limit_error", retryAfter: []string{"2", "3"}},
		{name: "the shorter wait first", failures: []failure{{status: 429, headers: wait("2")}, {pair: 1, status: 529, headers: wait("30")}},
			status: 429, code: "upstream_rate_limit_error", retryAfter: []string{"2", "3"}},
		{name: "time on later pairs shortens the wait", failures: []failure{{status: 429, headers: wait("20")}, {pair: 1, status: 401, after: 8 * time.Second}},
			status: 429, code: "upstream_rate_limit_error", retryAfter: []string{"12", "13"}},
		{name: "a wait that ended passes now", failures: []failure{{status: 429, headers: wait("2")}, {pair: 1, status: 500, after: 5 * time.Second}},
			status: 429, code: "upstream_rate_limit_error"},
		{name: "the first of two credential failures", failures: []failure{{status: 401}, {pair: 1, status: 403}},
			status: 424, code: "upstream_authentication_failed", shouldRetry: "false"},
		{name: "a missing deployment yields", failures: []failure{{status: 404}, {pair: 1, status: 401}},
			status: 424, code: "upstream_authentication_failed", shouldRetry: "false"},
		{name: "a retired model yields", failures: []failure{{status: 410}, {pair: 1, status: 403}},
			status: 424, code: "upstream_access_denied", shouldRetry: "false"},
		{name: "every deployment gone", failures: []failure{{status: 404}, {pair: 1, status: 410}}, status: 404, shouldRetry: "false"},
		{name: "a gone model yields although its provider asks for a retry", failures: []failure{{status: 404, headers: map[string]string{"x-should-retry": "true"}}, {pair: 1, status: 401}},
			status: 424, code: "upstream_authentication_failed", shouldRetry: "false"},
		{name: "a later gone model yields although its provider asks for a retry", failures: []failure{{status: 401}, {pair: 1, status: 404, headers: map[string]string{"x-should-retry": "true"}}},
			status: 424, code: "upstream_authentication_failed", shouldRetry: "false"},
		{name: "a wait over a minute passes no other failure", failures: []failure{{status: 401}, {pair: 1, status: 429, headers: wait("300")}},
			status: 424, code: "upstream_authentication_failed", shouldRetry: "false"},
		{name: "an invalid request ends the run", failures: []failure{{status: 429, headers: wait("30")}, {pair: 1, status: 400}}, status: 400},
		{name: "a content filter ends the run", failures: []failure{{status: 429, headers: wait("30")}, {pair: 1, status: 400, code: "content_filter"}}, status: 400, code: "content_filter"},
		{name: "every window too small", failures: []failure{{status: 400, code: "context_length_exceeded"}, {pair: 1, status: 413}},
			status: 400, code: "context_length_exceeded", shouldRetry: "false"},
		{name: "a pair's latest failure", failures: []failure{{status: 503}, {status: 429, headers: wait("30"), after: time.Second}, {pair: 1, status: 401}},
			status: 429, code: "upstream_rate_limit_error", retryAfter: []string{"30", "31"}},
		{name: "a provider that refuses retries", failures: []failure{{status: 500, headers: noRetry}, {pair: 1, status: 401}}, status: 500, shouldRetry: "false"},
		{name: "a wait over a minute", failures: []failure{{status: 429, headers: wait("300")}},
			status: 429, code: "upstream_rate_limit_error", retryAfter: []string{"300"}, shouldRetry: "false"},
		{name: "a provider that asks for a retry", failures: []failure{{status: 400, headers: map[string]string{"x-should-retry": "true"}}}, status: 400, shouldRetry: "true"},
		{name: "an unsent call's wait over a minute", failures: []failure{{status: 429, headers: wait("300"), unsent: true}},
			status: 429, code: "upstream_rate_limit_error", retryAfter: []string{"300"}, shouldRetry: "false"},
		{name: "a refusal with a wait after a call", failures: []failure{{status: 401}, {pair: 1, local: billingFailure{waitRefusal{billing.ErrRateLimit, 300 * time.Millisecond}}}},
			status: 429, code: "rate_limit_exceeded", retryAfter: []string{"1", "2"}, gateway: true},
		{name: "gateway capacity after a call", failures: []failure{{status: 401}, {pair: -1, local: errRequestMemoryCapacity}},
			status: 503, code: "gateway_capacity_exceeded", retryAfter: []string{"1", "2"}, gateway: true},
		{name: "a refusal before a call keeps its place", failures: []failure{{local: billingFailure{billing.ErrInsufficientBalance}}, {pair: 1, status: 401}},
			status: 402, code: "insufficient_balance", gateway: true},
		{name: "the caller left", failures: []failure{{local: billingFailure{waitRefusal{billing.ErrRateLimit, time.Second}}}, {pair: 1, status: 401}, {pair: -1, local: context.Canceled}},
			status: 429, code: "rate_limit_exceeded", retryAfter: []string{"1", "2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := newTestRequest(t)
				run := &providerRun{client: ctx}
				for _, f := range test.failures {
					time.Sleep(f.after)
					if f.local != nil {
						run.local = f.local
						run.noteLocal(f.local, f.pair)
						continue
					}
					failure := &schemas.BifrostError{Error: &schemas.ErrorField{Message: "provider failure"}}
					if f.status != 0 {
						failure.StatusCode = schemas.Ptr(f.status)
					}
					if f.code != "" {
						failure.Error.Code = schemas.Ptr(f.code)
					}
					attempt := retryAfterContext(f.headers)
					if f.unsent {
						run.local = &unsentCall{failure: failure, ctx: attempt}
						run.noteLocal(run.local, f.pair)
						continue
					}
					run.last, run.lastCtx = failure, attempt
					run.note(callFailure(failure, attempt, failureActionFor(failure, attempt, nil), f.pair))
				}
				if run.reportsLocal() != test.gateway {
					t.Fatalf("gateway error = %v", run.reportsLocal())
				}
				(&Server{}).writeErrorResponse(ctx, run.response())
				response := testResponse(ctx)
				body := map[string]map[string]any{}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				code, _ := body["error"]["code"].(string)
				if response.Code != test.status || test.code != "" && code != test.code {
					t.Fatalf("answer = %d %q, want %d %q", response.Code, code, test.status, test.code)
				}
				if after := response.Header().Get("Retry-After"); after != "" && !slices.Contains(test.retryAfter, after) || after == "" && len(test.retryAfter) > 0 {
					t.Fatalf("Retry-After = %q, want one of %v", after, test.retryAfter)
				}
				if got := response.Header().Get("X-Should-Retry"); got != test.shouldRetry {
					t.Fatalf("X-Should-Retry = %q, want %q", got, test.shouldRetry)
				}
			})
		})
	}
}

// The choice does not depend on how the failures arrive: against a reference
// that compares every pair's latest failure at once, the incremental choice
// picks the same failure.
func TestRunReportMatchesAReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(11, 5))
	for trial := range 20000 {
		run := &providerRun{}
		var latest []*runFailure
		at := time.Unix(0, 0)
		for pair, count := 0, 1+rng.IntN(6); count > 0; count-- {
			if rng.IntN(3) == 0 {
				pair++
			}
			at = at.Add(time.Duration(rng.IntN(4)) * time.Second)
			f := &runFailure{pair: pair, at: at, passes: rng.IntN(2) == 0, gone: rng.IntN(3) == 0, ends: count == 1 && rng.IntN(4) == 0}
			if f.passes && rng.IntN(2) == 0 {
				f.until = at.Add(time.Duration(rng.IntN(6)) * time.Second)
			}
			if n := len(latest); n > 0 && latest[n-1].pair == pair {
				latest[n-1] = f
			} else {
				latest = append(latest, f)
			}
			run.note(f)
		}
		if got, want := run.reported(), referenceReport(latest); got != want {
			t.Fatalf("trial %d: reported %+v, want %+v", trial, *got, *want)
		}
	}
}

// referenceReport applies the rule to every pair's latest failure in order.
func referenceReport(failures []*runFailure) *runFailure {
	if last := failures[len(failures)-1]; last.ends {
		return last
	}
	var kept *runFailure
	for _, f := range failures {
		switch {
		case kept == nil:
			kept = f
		case f.gone != kept.gone:
			if kept.gone {
				kept = f
			}
		case f.passes && !kept.passes:
			kept = f
		case f.passes && kept.passes:
			// Each wait ends when it ends, or now if it already did.
			ready := func(g *runFailure) time.Time {
				if g.until.After(f.at) {
					return g.until
				}
				return f.at
			}
			if ready(f).Before(ready(kept)) {
				kept = f
			}
		}
	}
	return kept
}

// A call's output window ends with the call: until the next call starts, the
// caller waits within the total deadline.
func TestFailedCallEndsItsOutputWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		wait := newResponseDeadline(time.Now(), time.Minute)
		defer wait.stop()
		wait.startOutput(10 * time.Second)
		time.Sleep(9900 * time.Millisecond)
		wait.endOutput()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if wait.timedOut() || wait.remaining() != 48100*time.Millisecond || !wait.startOutput(10*time.Second) {
			t.Fatalf("between calls: timed out %v, remaining %s", wait.timedOut(), wait.remaining())
		}
		// A window that ran out timed the caller out.
		time.Sleep(10 * time.Second)
		wait.endOutput()
		if !wait.timedOut() || wait.startOutput(10*time.Second) {
			t.Fatal("an expired window ended without a timeout")
		}
	})
}
