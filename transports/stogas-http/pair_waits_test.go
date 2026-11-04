package stogashttp

import (
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// A recorded wait refuses its pair with what remains of it and answers as the
// provider's failure did, until it ends or the pair serves.
func TestPairWaitRefusesUntilItEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var waits pairWaits
		key := pairKey{"credential", "deployment"}
		answer := catalog.APIError{Code: "upstream_rate_limit_error", StatusCode: 429, Type: "rate_limit_error", Message: "slow down"}
		waits.set(key, pairWait{until: time.Now().Add(30 * time.Second), answer: answer})
		time.Sleep(10 * time.Second)
		err := waits.refusal(key)
		response := catalogErrorResponse(err)
		if err == nil || response.status != 429 || response.code() != "upstream_rate_limit_error" ||
			(response.retryAfter != "20" && response.retryAfter != "21") || response.final {
			t.Fatalf("refusal %v answers %d %q after %q", err, response.status, response.code(), response.retryAfter)
		}
		if waits.refusal(pairKey{"credential", "other"}) != nil || waits.refusal(pairKey{"other", "deployment"}) != nil {
			t.Fatal("a wait refused another pair")
		}
		time.Sleep(20 * time.Second)
		if waits.refusal(key) != nil || len(waits.waiting) != 0 {
			t.Fatal("an ended wait still refused its pair")
		}
		waits.set(key, pairWait{until: time.Now().Add(time.Minute), answer: answer})
		waits.clear(key)
		if waits.refusal(key) != nil {
			t.Fatal("a pair that served still waited")
		}
	})
}

// A full table makes room only from waits that ended.
func TestPairWaitsStayBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var waits pairWaits
		for i := range maxPairWaits {
			waits.set(pairKey{fmt.Sprint(i), "d"}, pairWait{until: time.Now().Add(time.Duration(i%2+1) * time.Minute)})
		}
		late := pairKey{"late", "d"}
		waits.set(late, pairWait{until: time.Now().Add(time.Hour)})
		if waits.refusal(late) != nil || len(waits.waiting) != maxPairWaits {
			t.Fatalf("a full table took a new wait: %d", len(waits.waiting))
		}
		// An existing pair's wait still changes.
		waits.set(pairKey{"0", "d"}, pairWait{until: time.Now().Add(time.Hour)})
		time.Sleep(90 * time.Second)
		waits.set(late, pairWait{until: time.Now().Add(time.Hour)})
		if waits.refusal(late) == nil || len(waits.waiting) != maxPairWaits/2+2 {
			t.Fatalf("ended waits were kept: %d", len(waits.waiting))
		}
	})
}

// Only a sent call on a customer's credential whose provider asks for longer
// than a retry waits, and that a wait can pass, records the pair's wait.
func TestFailedCallRecordsItsPairsWait(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		code    string
		headers map[string]string
		mode    string
		record  bool
	}{
		{name: "a long rate limit", status: 429, headers: map[string]string{"retry-after": "30"}, mode: "stored", record: true},
		{name: "a long overload", status: 529, headers: map[string]string{"retry-after": "30"}, mode: "encrypted", record: true},
		{name: "a wait that a retry covers", status: 429, headers: map[string]string{"retry-after": "8"}, mode: "stored"},
		{name: "no wait", status: 503, mode: "stored"},
		{name: "a provider that refuses retries", status: 429, headers: map[string]string{"retry-after": "30", "x-should-retry": "false"}, mode: "stored"},
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
			run.recordWait(callFailure(failure, attempt, run.action, 0))
			key := pairKey{"byok", "openai-gpt-5.6-sol"}
			if recorded := server.pairWaits.refusal(key) != nil; recorded != test.record {
				t.Fatalf("recorded = %v", recorded)
			}
			run.clearWait()
			if server.pairWaits.refusal(key) != nil {
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
		waits.set(key, pairWait{until: time.Now().Add(30 * time.Second), answer: catalog.APIError{Code: "upstream_rate_limit_error", StatusCode: 429, Type: "rate_limit_error", Message: "slow down"}})
		time.Sleep(5 * time.Second)
		ctx := newTestRequest(t)
		run := &providerRun{client: ctx}
		run.noteLocal(waits.refusal(key), -1)
		failure := &schemas.BifrostError{StatusCode: schemas.Ptr(401), Error: &schemas.ErrorField{Message: "bad key"}}
		run.last, run.lastCtx = failure, retryAfterContext(nil)
		run.note(callFailure(failure, run.lastCtx, nextPair, 1))
		response := run.response()
		var refusal interface{ RetryAfter() time.Duration }
		if response.status != 429 || response.retryAfter != "25" && response.retryAfter != "26" || response.final ||
			!errors.As(waits.refusal(key), &refusal) {
			t.Fatalf("answer %d after %q, final %v", response.status, response.retryAfter, response.final)
		}
	})
}
