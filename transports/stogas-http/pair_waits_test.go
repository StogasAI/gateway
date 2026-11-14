package stogashttp

import (
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/maximhq/bifrost/core/network"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// refused is the refusal of a pair that waits, for a request that does not
// test it.
func refused(waits *pairWaits, key pairKey) error {
	_, err := waits.refusal(key)
	return err
}

// A recorded wait refuses its pair with what remains of it and answers as the
// provider's failure did, until it ends or the pair serves.
func TestPairWaitRefusesUntilItEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var waits pairWaits
		key := pairKey{"credential", "deployment"}
		answer := catalog.APIError{Code: "upstream_rate_limit_error", StatusCode: 429, Type: "rate_limit_error", Message: "slow down"}
		waits.set(key, time.Now().Add(30*time.Second), answer)
		time.Sleep(10 * time.Second)
		_, err := waits.refusal(key)
		response := catalogErrorResponse(err)
		if err == nil || response.status != 429 || response.code() != "upstream_rate_limit_error" ||
			(response.retryAfter != "20" && response.retryAfter != "21") || response.final {
			t.Fatalf("refusal %v answers %d %q after %q", err, response.status, response.code(), response.retryAfter)
		}
		if refused(&waits, pairKey{"credential", "other"}) != nil || refused(&waits, pairKey{"other", "deployment"}) != nil {
			t.Fatal("a wait refused another pair")
		}
		time.Sleep(20 * time.Second)
		if refused(&waits, key) != nil || len(waits.waiting) != 0 {
			t.Fatal("an ended wait still refused its pair")
		}
		waits.set(key, time.Now().Add(time.Minute), answer)
		waits.clear(key)
		if refused(&waits, key) != nil {
			t.Fatal("a pair that served still waited")
		}
	})
}

// A full table makes room only from waits that ended.
func TestPairWaitsStayBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var waits pairWaits
		for i := range maxPairWaits {
			waits.set(pairKey{fmt.Sprint(i), "d"}, time.Now().Add(time.Duration(i%2+1)*time.Minute), catalog.APIError{})
		}
		late := pairKey{"late", "d"}
		waits.set(late, time.Now().Add(time.Hour), catalog.APIError{})
		waits.failed(late, false)
		if refused(&waits, late) != nil || len(waits.waiting) != maxPairWaits {
			t.Fatalf("a full table took a new wait: %d", len(waits.waiting))
		}
		// An existing pair's wait still changes.
		waits.set(pairKey{"0", "d"}, time.Now().Add(time.Hour), catalog.APIError{})
		time.Sleep(90 * time.Second)
		waits.set(late, time.Now().Add(time.Hour), catalog.APIError{})
		if refused(&waits, late) == nil || len(waits.waiting) != maxPairWaits/2+2 {
			t.Fatalf("ended waits were kept: %d", len(waits.waiting))
		}
	})
}

// Only a call on a customer's credential whose provider asks for longer than a
// retry waits records the pair's wait, even when the call ended its request. A
// request that the pair would serve meanwhile gets the provider's rate limit,
// or its lack of capacity.
func TestFailedCallRecordsItsPairsWait(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		code    string
		headers map[string]string
		mode    string
		answer  string // the refusal's code while the pair waits; none when no wait is recorded
	}{
		{name: "a long rate limit", status: 429, headers: map[string]string{"retry-after": "30"}, mode: "stored", answer: "upstream_rate_limit_error"},
		{name: "a long overload", status: 529, headers: map[string]string{"retry-after": "30"}, mode: "encrypted", answer: "upstream_capacity_unavailable"},
		{name: "a long unavailability", status: 503, headers: map[string]string{"retry-after": "30"}, mode: "stored", answer: "upstream_capacity_unavailable"},
		{name: "a provider that refuses retries", status: 429, headers: map[string]string{"retry-after": "30", "x-should-retry": "false"}, mode: "stored", answer: "upstream_rate_limit_error"},
		{name: "a wait that a retry covers", status: 429, headers: map[string]string{"retry-after": "8"}, mode: "stored"},
		{name: "no wait", status: 503, mode: "stored"},
		{name: "an exhausted quota", status: 429, code: "insufficient_quota", headers: map[string]string{"retry-after": "30"}, mode: "stored"},
		{name: "Stogas's own credential", status: 429, headers: map[string]string{"retry-after": "30"}, mode: "managed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{}
			resolution := &catalog.ResolvedRequest{Provider: schemas.OpenAI, CredentialIndex: 0, Deployment: catalog.Deployment{ID: "openai-gpt-5.6-sol"}}
			run := &providerRun{server: server, client: newTestRequest(t), state: &stogas.State{},
				keyConfig: &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{"openai": {{Mode: test.mode, ID: "byok"}}}},
				pair:      &providerPair{Pair: stogas.Pair{Resolution: resolution}},
			}
			failure := &schemas.BifrostError{StatusCode: schemas.Ptr(test.status), Error: &schemas.ErrorField{Message: "provider failure"}}
			if test.code != "" {
				failure.Error.Code = schemas.Ptr(test.code)
			}
			attempt := retryAfterContext(test.headers)
			run.action = failureActionFor(failure, attempt, nil)
			key := pairKey{"byok", "openai-gpt-5.6-sol"}
			run.pair.wait, _ = pairWaitKey(run.keyConfig, resolution.Provider, resolution.CredentialIndex, resolution.Deployment.ID)
			run.recordWait(callFailure(run.state, failure, attempt, run.action, 0, 1, "openai-gpt-5.6-sol"), failure)
			answer := ""
			if refusal := refused(&server.pairWaits, key); refusal != nil {
				answer = catalogErrorResponse(refusal).code()
			}
			if answer != test.answer {
				t.Fatalf("answer = %q, want %q", answer, test.answer)
			}
			run.clearWait()
			if refused(&server.pairWaits, key) != nil {
				t.Fatal("serving kept the wait")
			}
		})
	}
}

// A refused pair counts like a call: its wait passes a later credential
// failure, and the caller gets what remains of it.
func TestWaitingPairRanksLikeItsCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var waits pairWaits
		key := pairKey{"credential", "deployment"}
		waits.set(key, time.Now().Add(30*time.Second), catalog.APIError{Code: "upstream_rate_limit_error", StatusCode: 429, Type: "rate_limit_error", Message: "slow down"})
		time.Sleep(5 * time.Second)
		ctx := newTestRequest(t)
		run := &providerRun{client: ctx}
		run.noteLocal(refused(&waits, key), -1)
		failure := &schemas.BifrostError{StatusCode: schemas.Ptr(401), Error: &schemas.ErrorField{Message: "bad key"}}
		run.last, run.lastCtx = failure, retryAfterContext(nil)
		run.note(callFailure(run.state, failure, run.lastCtx, nextPair, 1, 2, "deployment"))
		response := run.response()
		var refusal interface{ RetryAfter() time.Duration }
		if response.status != 429 || response.retryAfter != "25" && response.retryAfter != "26" || response.final ||
			!errors.As(refused(&waits, key), &refusal) {
			t.Fatalf("answer %d after %q, final %v", response.status, response.retryAfter, response.final)
		}
	})
}

// Three failed calls in a row make their pair wait 30 seconds. One request
// then tests the pair while the others still pass over it, and each failed
// test starts a wait that is 30 seconds longer, up to five minutes.
func TestFailedCallsMakeTheirPairWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var waits pairWaits
		key := pairKey{"credential", "deployment"}
		after := func() string {
			t.Helper()
			tests, err := waits.refusal(key)
			if tests || err == nil {
				t.Fatalf("the pair did not wait: tests %v, %v", tests, err)
			}
			response := catalogErrorResponse(err)
			if response.status != 503 || response.code() != "upstream_capacity_unavailable" || response.final {
				t.Fatalf("a waiting pair answers %d %q, final %v", response.status, response.code(), response.final)
			}
			return response.retryAfter
		}
		tests := func() {
			t.Helper()
			if tests, err := waits.refusal(key); !tests || err != nil {
				t.Fatalf("no request tests the pair: %v", err)
			}
		}

		// Failures more than a minute apart, or with an answer between them,
		// are not one row.
		waits.failed(key, false)
		waits.failed(key, false)
		time.Sleep(61 * time.Second)
		waits.failed(key, false)
		waits.failed(key, false)
		waits.answered(key)
		waits.failed(key, false)
		waits.failed(key, false)
		if refused(&waits, key) != nil {
			t.Fatal("two failures in a row made the pair wait")
		}
		waits.failed(key, false)
		if wait := after(); wait != "30" && wait != "31" {
			t.Fatalf("the first wait lasts %q", wait)
		}
		// A call from before the wait, or a last pair's during it, changes nothing.
		time.Sleep(10 * time.Second)
		waits.failed(key, false)
		waits.failed(key, true)
		if wait := after(); wait != "20" && wait != "21" {
			t.Fatalf("a failure during the wait changed it to %q", wait)
		}

		// One request tests the pair. Until its call returns, the others pass
		// over the pair for as long as the wait lasted.
		time.Sleep(20 * time.Second)
		tests()
		if wait := after(); wait != "30" && wait != "31" {
			t.Fatalf("during a test the others wait %q", wait)
		}
		// A request that does not make its call returns the test.
		waits.release(key)
		tests()
		// A call that started before the wait says nothing about the test.
		waits.failed(key, false)
		after()
		waits.failed(key, true)
		if wait := after(); wait != "60" && wait != "61" {
			t.Fatalf("the second wait lasts %q", wait)
		}
		// A second test of the same wait that fails later does not start another.
		waits.failed(key, true)
		if entry := waits.waiting[key]; entry.opened != 2 {
			t.Fatalf("the pair waited %d times in a row", entry.opened)
		}
		for n := 3; n <= 12; n++ {
			time.Sleep(time.Until(waits.waiting[key].closed))
			tests()
			waits.failed(key, true)
			want := min(time.Duration(n)*30*time.Second, 5*time.Minute)
			if got := time.Until(waits.waiting[key].closed); got != want {
				t.Fatalf("wait %d lasts %v, want %v", n, got, want)
			}
		}

		// A provider's wait and the pair's own are apart: the later one answers,
		// and an answer that the provider computed ends only the pair's own.
		waits.set(key, time.Now().Add(time.Second), stableAnswer("upstream_rate_limit_error"))
		if _, err := waits.refusal(key); catalogErrorResponse(err).status != 503 {
			t.Fatalf("a provider's shorter wait answers instead of the pair's: %v", err)
		}
		waits.set(key, time.Now().Add(10*time.Minute), stableAnswer("upstream_rate_limit_error"))
		if _, err := waits.refusal(key); catalogErrorResponse(err).status != 429 {
			t.Fatalf("the provider's longer wait does not answer: %v", err)
		}
		waits.answered(key)
		if _, err := waits.refusal(key); err == nil || catalogErrorResponse(err).status != 429 || waits.waiting[key].opened != 0 {
			t.Fatalf("an answer ended the provider's wait or kept the pair's: %v", err)
		}
		time.Sleep(10 * time.Minute)
		if refused(&waits, key) != nil || len(waits.waiting) != 0 {
			t.Fatal("an ended wait stayed")
		}

		// A pair that serves its test starts again.
		for range pairFailureLimit {
			waits.failed(key, false)
		}
		time.Sleep(30 * time.Second)
		tests()
		waits.clear(key)
		waits.failed(key, false)
		if refused(&waits, key) != nil {
			t.Fatal("a pair that served kept its failures")
		}
	})
}

// A failed call counts for its pair only when it reached no provider or its
// outcome is unknown. Another failure shows that the provider answers, and a
// call on Stogas's own credential records nothing.
func TestFailedCallCountsWithoutTheProvidersAnswer(t *testing.T) {
	unsent := &schemas.BifrostError{Error: &schemas.ErrorField{Message: "connection refused"}}
	unsent.Error.Error = &network.NotSentError{Err: errors.New("dial tcp: connection refused")}
	status := func(code int) *schemas.BifrostError {
		return &schemas.BifrostError{StatusCode: schemas.Ptr(code), Error: &schemas.ErrorField{Message: "provider failure"}}
	}
	key := pairKey{"byok", "openai-gpt-5.6-sol"}
	for _, test := range []struct {
		name     string
		failures []*schemas.BifrostError
		unsent   bool // the calls reached no provider
		managed  bool
		waits    bool
	}{
		{name: "server errors", failures: []*schemas.BifrostError{status(500), status(502), status(529)}, waits: true},
		{name: "calls that the provider never received", failures: []*schemas.BifrostError{unsent, unsent, unsent}, waits: true},
		{name: "a transport that proves nothing was sent", failures: []*schemas.BifrostError{status(503), status(503), status(503)}, unsent: true, waits: true},
		{name: "a refusal between server errors", failures: []*schemas.BifrostError{status(500), status(500), status(400), status(500)}},
		{name: "a rate limit between server errors", failures: []*schemas.BifrostError{status(500), status(500), status(429), status(500)}},
		{name: "a refusal before any call", failures: []*schemas.BifrostError{status(500), status(500), status(400), status(500)}, unsent: true, waits: true},
		{name: "refusals", failures: []*schemas.BifrostError{status(401), status(404), status(429), status(400)}},
		{name: "Stogas's own credential", failures: []*schemas.BifrostError{status(500), status(500), status(500)}, managed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{}
			run := &providerRun{server: server, pair: &providerPair{}}
			if !test.managed {
				run.pair.wait = key
			}
			for _, failure := range test.failures {
				run.recordOutcome(failure, retryAfterContext(map[string]string{"date": "now"}), !test.unsent)
			}
			if waits := refused(&server.pairWaits, key) != nil; waits != test.waits {
				t.Fatalf("the pair waits: %v, want %v", waits, test.waits)
			}
		})
	}
}

// The request that tests a pair decides the test with its call. A request that
// ends before that call returns the test, so that the next request makes it.
func TestRunReturnsATestThatItDoesNotMake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &Server{}
		waits := &server.pairWaits
		key, other := pairKey{"byok", "first"}, pairKey{"byok", "second"}
		for _, pair := range []pairKey{key, other} {
			for range pairFailureLimit {
				waits.failed(pair, false)
			}
		}
		time.Sleep(30 * time.Second)
		take := func(pair pairKey) bool {
			tests, _ := waits.refusal(pair)
			return tests
		}
		// The plan let the run test both pairs, and the run bound the first.
		if !take(key) || !take(other) {
			t.Fatal("no request tests the pairs")
		}
		run := &providerRun{server: server, pair: &providerPair{wait: key, tests: true}, tests: []pairKey{other}}
		run.releaseTests()
		if take(key) || !take(other) {
			t.Fatal("the run kept the test of a pair that it did not bind, or returned its bound pair's")
		}
		// A call that reached no provider for the gateway's own reasons decides nothing.
		run.recordOutcome(&schemas.BifrostError{StatusCode: schemas.Ptr(400), Error: &schemas.ErrorField{Message: "invalid"}}, retryAfterContext(nil), false)
		if run.pair.tests || !take(key) {
			t.Fatal("a call that decided nothing kept the test")
		}
		// A failed test starts the next wait, and a served one ends the memory.
		run.pair.tests = true
		run.recordOutcome(&schemas.BifrostError{StatusCode: schemas.Ptr(500), Error: &schemas.ErrorField{Message: "failed"}}, retryAfterContext(nil), true)
		if got := time.Until(waits.waiting[key].closed); got != time.Minute {
			t.Fatalf("a failed test starts a wait of %v", got)
		}
		time.Sleep(time.Minute)
		run.pair.tests = take(key)
		run.clearWait()
		if _, waiting := waits.waiting[key]; waiting || run.pair.tests {
			t.Fatal("a served test kept the pair's memory")
		}
	})
}
