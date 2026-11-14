package stogashttp

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// pairWaits remembers, on this gateway, each customer credential and
// deployment that a request should pass over for a time, for one of two
// reasons.
//
// The provider asked callers to wait longer than a retry waits. A call during
// the wait is refused, and providers count refused calls against the limit
// (OpenAI) or say that earlier retries fail (Anthropic).
//
// Three calls in a row failed without an answer that the provider computed: it
// never received them, or their outcome is unknown. A request never follows
// such a call with another, so during an outage every request that starts on
// the pair fails. The pair then waits 30 seconds, after which one request
// tests it: a call that serves, or that the provider refuses for its own
// reasons, ends the memory, and a test that fails as before starts a wait of
// 30 seconds more than the last, up to 5 minutes. The counts and times are
// those of Envoy's outlier detection and LiteLLM's allowed failures.
//
// During a wait, a request passes over the pair while another remains, and the
// pair uses its place, so no request reaches past its policy's fallbacks. A
// pair that is the request's last still gets its call, since a smaller request
// can pass a token limit that refused a larger one and a failing provider may
// have recovered. Stogas's own credentials have no entry: one customer's
// failures must never change another's routing, and their transport keeps its
// own waits.
type pairWaits struct {
	mu      sync.Mutex
	waiting map[pairKey]pairWait
}

type pairKey struct{ credential, deployment string }

type pairWait struct {
	until  time.Time        // when the wait that the provider asked for ends
	answer catalog.APIError // what a request that the pair would serve gets during it

	failures int       // failed calls in a row since the provider last answered
	failedAt time.Time // when the latest of them failed
	opened   int       // waits in a row that those failures started
	closed   time.Time // when the latest such wait ends
	test     time.Time // until when one request tests the pair after it
}

const (
	// maxPairWaits bounds the memory. A full table records nothing new until
	// an entry ends, which costs only the calls that it would have saved.
	maxPairWaits = 4096
	// pairFailureLimit is how many calls in a row fail before the pair waits.
	// With one call in a hundred failing by chance, three in a row happen
	// once in a million calls.
	pairFailureLimit = 3
	// pairFailureWindow is the longest time between two failures of one row.
	pairFailureWindow = time.Minute
	// pairFailureWait is the first wait, and each wait after a failed test is
	// this much longer, up to pairFailureMaxWait.
	pairFailureWait    = 30 * time.Second
	pairFailureMaxWait = 5 * time.Minute
)

// waitingPair is a pair that the plan passed over during its wait.
type waitingPair struct{ until time.Time }

func (w waitingPair) Error() string { return "the pair waits before its next call" }

func (w waitingPair) RetryAfter() time.Duration { return time.Until(w.until) }

func pairWaitKey(keyConfig *billing.KeyConfigSnapshot, provider schemas.ModelProvider, index int, deployment string) (pairKey, bool) {
	credential := keyConfig.CustomerCredentialID(string(provider), index)
	return pairKey{credential, deployment}, credential != ""
}

// ended reports an entry that changes nothing any more.
func (wait pairWait) ended(now time.Time) bool {
	return !wait.until.After(now) && wait.opened == 0 &&
		(wait.failures == 0 || now.Sub(wait.failedAt) > pairFailureWindow)
}

// update changes the entry of key, which it makes when the table has room.
func (w *pairWaits) update(key pairKey, change func(*pairWait, time.Time)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	wait, ok := w.waiting[key]
	if !ok && len(w.waiting) >= maxPairWaits {
		for other, recorded := range w.waiting {
			// A pair that no request tested for the longest wait starts again.
			if recorded.ended(now) || !recorded.until.After(now) && recorded.opened > 0 &&
				now.Sub(recorded.closed) > pairFailureMaxWait && !recorded.test.After(now) {
				delete(w.waiting, other)
			}
		}
		if len(w.waiting) >= maxPairWaits {
			return
		}
	}
	change(&wait, now)
	if w.waiting == nil {
		w.waiting = make(map[pairKey]pairWait)
	}
	w.waiting[key] = wait
}

// set records the wait that a provider asked for.
func (w *pairWaits) set(key pairKey, until time.Time, answer catalog.APIError) {
	w.update(key, func(wait *pairWait, _ time.Time) { wait.until, wait.answer = until, answer })
}

// failed records a call that failed without an answer that the provider
// computed. tested says that the call tested the pair after a wait.
func (w *pairWaits) failed(key pairKey, tested bool) {
	w.update(key, func(wait *pairWait, now time.Time) {
		switch {
		case wait.opened > 0 && (!tested || wait.closed.After(now)):
			// A call from before the wait, or a last pair's during it, says
			// nothing new, and an earlier test already started the next wait.
			return
		case wait.opened == 0:
			if now.Sub(wait.failedAt) > pairFailureWindow {
				wait.failures = 0
			}
			wait.failures, wait.failedAt = wait.failures+1, now
			if wait.failures < pairFailureLimit {
				return
			}
		}
		wait.opened++
		wait.closed, wait.test = now.Add(failureWait(wait.opened)), time.Time{}
	})
}

// unavailablePair answers a request that a pair would serve while it waits
// after failed calls.
var unavailablePair = stableAnswer("upstream_capacity_unavailable")

func stableAnswer(code string) catalog.APIError {
	status, errorType, code, message, _ := publicStableGatewayError(&schemas.BifrostError{Error: &schemas.ErrorField{Code: &code}})
	return catalog.APIError{Code: code, StatusCode: status, Type: errorType, Message: message}
}

// answered forgets what the pair's failed calls started: the provider served
// a call, or refused one for its own reasons. A wait that the provider asked
// for stays.
func (w *pairWaits) answered(key pairKey) {
	w.mu.Lock()
	defer w.mu.Unlock()
	wait, ok := w.waiting[key]
	if !ok {
		return
	}
	wait.failures, wait.opened, wait.closed, wait.test = 0, 0, time.Time{}, time.Time{}
	if wait.ended(time.Now()) {
		delete(w.waiting, key)
	} else {
		w.waiting[key] = wait
	}
}

// clear forgets the pair, which served.
func (w *pairWaits) clear(key pairKey) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.waiting, key)
}

// release returns a test that its request did not make, so that the next
// request tests the pair.
func (w *pairWaits) release(key pairKey) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if wait, ok := w.waiting[key]; ok && wait.opened > 0 {
		wait.test = time.Time{}
		w.waiting[key] = wait
	}
}

// refusal is the error of a pair that still waits, or nil. It answers as the
// provider's failure did, with what remains of the wait. After a wait that
// failed calls started, the first request tests the pair, which tests reports,
// and the others pass over it until that call returns or as long as the wait
// lasted.
func (w *pairWaits) refusal(key pairKey) (tests bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	wait, ok := w.waiting[key]
	if !ok {
		return false, nil
	}
	now := time.Now()
	// The pair serves again when both waits have ended, so the later one answers.
	switch {
	case wait.until.After(now) && !wait.until.Before(wait.closed) && !wait.until.Before(wait.test):
		return false, errors.Join(waitingPair{wait.until}, wait.answer)
	case wait.closed.After(now):
		return false, errors.Join(waitingPair{wait.closed}, unavailablePair)
	case wait.test.After(now):
		return false, errors.Join(waitingPair{wait.test}, unavailablePair)
	case wait.opened == 0:
		if wait.ended(now) {
			delete(w.waiting, key)
		}
		return false, nil
	}
	wait.test = now.Add(failureWait(wait.opened))
	w.waiting[key] = wait
	return true, nil
}

// failureWait is the wait that failed calls start for the nth time in a row.
func failureWait(n int) time.Duration {
	return min(time.Duration(n)*pairFailureWait, pairFailureMaxWait)
}

// recordOutcome records whether the bound pair's failed call got an answer
// that the provider computed. A call that reached no provider counts only as
// a failure, since its error can be the gateway's own.
func (r *providerRun) recordOutcome(failure *schemas.BifrostError, attempt *schemas.BifrostContext, sent bool) {
	pair := r.pair
	if pair.wait.credential == "" {
		return
	}
	tested := pair.tests
	pair.tests = false
	switch {
	case requestNotSent(failure) || outcomeUnknown(failure, attempt):
		r.server.pairWaits.failed(pair.wait, tested)
	case sent:
		r.server.pairWaits.answered(pair.wait)
	case tested:
		r.server.pairWaits.release(pair.wait)
	}
}

// recordWait records the bound pair's failed call when its provider asked for
// a wait longer than a retry waits, after which the pair can serve again. A
// request that the pair would serve meanwhile gets the refusal that its rate
// limit or lack of capacity calls for, since the provider never sees it.
func (r *providerRun) recordWait(f *runFailure, failure *schemas.BifrostError) {
	if f.until.Sub(f.at) <= retryMaxWait || r.pair.wait.credential == "" {
		return
	}
	code := "upstream_capacity_unavailable"
	if status, _ := publicBifrostError(failure); status == http.StatusTooManyRequests {
		code = "upstream_rate_limit_error"
	}
	r.server.pairWaits.set(r.pair.wait, f.until, stableAnswer(code))
}

// clearWait forgets the wait of the bound pair, which served.
func (r *providerRun) clearWait() {
	if r.pair != nil && r.pair.wait.credential != "" {
		r.pair.tests = false
		r.server.pairWaits.clear(r.pair.wait)
	}
}

// releaseTests returns the tests of pairs that the run did not bind.
func (r *providerRun) releaseTests() {
	for _, key := range r.tests {
		r.server.pairWaits.release(key)
	}
	r.tests = nil
}
