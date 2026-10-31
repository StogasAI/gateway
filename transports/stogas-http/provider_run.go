package stogashttp

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
)

// A retry waits like the OpenAI and Anthropic SDKs: half a second, doubled
// for each retry, less up to a quarter, or longer when the provider asks. A
// provider that asks for more than retryMaxWait gets the next pair instead.
const (
	retryInitialWait = 500 * time.Millisecond
	retryMaxWait     = 8 * time.Second
)

// providerRun takes one inference request through its deployment and
// credential pairs: up to three pairs, and up to three retries on each. Every
// provider call is an attempt in the request log.
//
// Only the request's owner uses a run: the handler, then the stream writer or
// the detached unary owner. A provider call runs in its own goroutine, and the
// owner touches neither the run nor its state until the call returns.
type providerRun struct {
	server  *Server
	client  *requestContext
	request *schemas.BifrostContext
	state   *stogas.State
	cancel  context.CancelFunc

	// The plan and what it needs stay until no other pair can follow.
	plan                *catalog.ResolvedRequest
	credential          apiCredential
	keyConfig           *billing.KeyConfigSnapshot
	policyMemory        *requestMemoryLease
	policyBytes         int64
	preparation         *requestMemoryLease
	prepared            *billing.PreparedCredential
	bodyBytes           int
	startedAt           time.Time
	finishPreprocessing func()

	// pair is bound for calls, held has the hold, called made the last logged
	// call, and attempted is the last pair whose preparation started.
	pair, held, called, attempted *providerPair
	retries                       int // calls after the first on the bound pair
	attempts                      int // logged calls before the current one
	last                          *schemas.BifrostError
	lastCtx                       *schemas.BifrostContext
	local                         error // the latest failure before a provider call
}

// providerPair keeps a pair's state and its context, which holds the prepared
// provider request and credential. Each call gets its own child context.
type providerPair struct {
	stogas.Pair
	ctx     *schemas.BifrostContext
	request *schemas.BifrostRequest
}

type providerCall[T any] func(*schemas.BifrostContext, *schemas.BifrostRequest) (T, *schemas.BifrostError)

// billingFailure marks an error that the billing renderer describes.
type billingFailure struct{ error }

func (f billingFailure) Unwrap() error { return f.error }

// unsentCall is a provider call that never reached a provider: its transport
// proved so, or core failed before the call. It is not an attempt, and the
// next pair can still serve the request.
type unsentCall struct {
	failure *schemas.BifrostError
	ctx     *schemas.BifrostContext
}

func (c *unsentCall) Error() string { return bifrostErrorMessage(c.failure) }

// bind prepares resolution for the next provider call. Its state replaces the
// previous pair's; after a failure it stays there for the next bind or the end
// of the run.
func (r *providerRun) bind(resolution *catalog.ResolvedRequest) error {
	next := &providerPair{ctx: schemas.NewBifrostContext(r.request, schemas.NoDeadline)}
	previous := r.attempted
	r.attempted = next
	r.retire(previous)
	r.state.Pair = stogas.NewPair(resolution, stogas.AdapterFor(resolution.Provider))
	r.state.PreparedCredential, r.prepared = r.prepared, nil
	err := r.prepare(next, resolution)
	r.state.PreparedCredential.Clear()
	r.state.PreparedCredential = nil
	next.Pair = r.state.Pair
	if next.Authorization != nil {
		previous, r.held = r.held, next
		r.retire(previous)
	}
	if err != nil {
		return err
	}
	previous, r.pair, r.retries = r.pair, next, 0
	r.retire(previous)
	return nil
}

func (r *providerRun) prepare(pair *providerPair, resolution *catalog.ResolvedRequest) error {
	state := r.state
	if r.keyConfig.Claims != nil {
		state.Export = r.server.exports.Start(resolution.ExportConfig)
	}
	resolution.ExportConfig = nil
	selected, err := r.keyConfig.PolicyForCredential(string(resolution.Provider), resolution.CredentialIndex, r.credential.EncryptionKeys, r.startedAt, nil)
	if err != nil {
		return billingFailure{err}
	}
	state.PolicyVersions = selected.Versions
	if r.held == nil {
		r.client.policyVersions = selected.Versions
	}
	if err := state.Adapter.ValidateRequest(state); err != nil {
		return err
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		return err
	}
	if err := state.Adapter.EstimateHold(state); err != nil {
		return err
	}
	request, err := resolution.ToBifrost(pair.ctx)
	if err != nil {
		return err
	}
	if err := stogas.PrepareProviderRequest(pair.ctx, state, request); err != nil {
		return err
	}
	// Database and provider waits are not preprocessing.
	r.finishPreprocessing()
	if err := r.waitError(); err != nil {
		return err
	}
	var previous *billing.Authorization
	if r.held != nil {
		previous = r.held.Authorization
	}
	err = stogas.AuthorizeState(r.request, r.client.request.Context(), r.server.runtime.Billing(), state, r.keyConfig, r.credential.EncryptionKeys, previous)
	if previous == nil && state.Authorization != nil {
		r.server.recordAdmission(r.client)
		r.client.markPaid()
	}
	// A request without a hold costs nothing, so its export never copies it.
	if state.Authorization != nil {
		state.Export.Input(resolution.RawBody(), resolution.Route == catalog.RouteResponses)
	}
	if err != nil {
		return billingFailure{err}
	}
	if err := r.server.runtime.ApplyUpstreamCredentials(pair.ctx, state); err != nil {
		return billingFailure{err}
	}
	if resolution.Provider == schemas.Azure {
		// The credential names the Azure deployment that the body addresses.
		if request, err = resolution.ToBifrost(pair.ctx); err != nil {
			return err
		}
		if err := stogas.PrepareProviderRequest(pair.ctx, state, request); err != nil {
			return err
		}
	}
	resolution.ReleaseInput()
	pair.request = request
	return nil
}

// bindFrom binds the first pair, or the next one that prepares.
func (r *providerRun) bindFrom(first *catalog.ResolvedRequest) bool {
	err := r.bind(first)
	r.finishPreprocessing()
	if err == nil {
		return true
	}
	r.local = err
	return !stopsRequest(err) && r.advance(err)
}

// advance binds the next pair that prepares. failure is the local error that
// stopped the previous pair, or nil after a provider failure.
func (r *providerRun) advance(failure error) bool {
	for {
		if err := r.waitError(); err != nil {
			r.local = err
			return false
		}
		r.finishPreprocessing = r.server.preprocessing.begin(r.bodyBytes)
		resolution, err := r.plan.NextPair(failure)
		if err == nil {
			err = r.accountPolicyMemory()
		}
		if err == nil {
			err = r.bind(resolution)
		}
		r.finishPreprocessing()
		if err == nil {
			return true
		}
		r.local = err
		if resolution == nil || stopsRequest(err) {
			return false
		}
		failure = err
	}
}

// accountPolicyMemory charges the policy content that resolving pairs loaded.
func (r *providerRun) accountPolicyMemory() error {
	bytes := r.keyConfig.MemoryBytes()
	if grown := bytes - r.policyBytes; grown > 0 {
		if !r.policyMemory.grow(int(grown)) {
			return errRequestMemoryCapacity
		}
		r.policyBytes = bytes
	}
	return nil
}

// stopsRequest reports a failure before a provider call that no other pair
// avoids. Billing refusals of one pair, catalog checks and request preparation
// leave the next pair.
func stopsRequest(err error) bool {
	var refusal billingFailure
	if errors.As(err, &refusal) {
		return !billing.PairRefused(refusal.error)
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		errors.Is(err, errRequestMemoryCapacity) || errors.Is(err, customerkey.ErrKey) || errors.Is(err, customerkey.ErrEnvelope)
}

// failed records a failed call on the bound pair. It reports false for a call
// that reached no provider.
func (r *providerRun) failed(failure *schemas.BifrostError, attempt *schemas.BifrostContext) bool {
	defer attempt.Cancel()
	count := r.state.ProviderAttemptCount()
	if count > r.attempts && chutese2ee.NotSent(attempt) {
		r.state.MarkProviderNotSent()
		count--
	}
	if count <= r.attempts {
		r.local = &unsentCall{failure, attempt}
		return false
	}
	// Chutes calls again inside its transport when the provider proves that it
	// did not run an invocation. Those calls use the pair's retries.
	r.retries += count - r.attempts - 1
	previous := r.called
	r.called, r.last, r.lastCtx = r.pair, failure, attempt
	r.retire(previous)
	return true
}

// next decides what follows a failed call: another call on the bound pair
// after the returned wait, a call on the next pair, or the end of the run.
func (r *providerRun) next(failure *schemas.BifrostError, attempt *schemas.BifrostContext) (time.Duration, bool) {
	if !r.failed(failure, attempt) {
		return 0, r.advance(r.local)
	}
	if !r.waiting() {
		return 0, false
	}
	step, wait := nextStep(failureActionFor(failure, attempt, r.client.memory), r.retries, r.pair.Resolution.Retries(),
		func() time.Duration { return retryWait(r.retries, attempt) }, r.client.responseWait.remaining(), r.plan.HasNextPair())
	switch step {
	case stepRetry:
		r.retries++
		return wait, true
	case stepAdvance:
		return 0, r.advance(nil)
	default:
		return 0, false
	}
}

type runStep uint8

const (
	stepStop runStep = iota
	stepRetry
	stepAdvance
)

// nextStep decides what follows a failed provider call. The bound pair runs
// again while its retries last and its wait fits both the longest retry wait
// and the time the caller still waits; otherwise any failure but a final one
// passes to the next pair, while one remains.
func nextStep(action failureAction, used, retries int, wait func() time.Duration, remaining time.Duration, hasNext bool) (runStep, time.Duration) {
	if action == retryPair && used < retries {
		if wait := wait(); wait <= retryMaxWait && wait < remaining {
			return stepRetry, wait
		}
	}
	if action != stopRun && hasNext {
		return stepAdvance, 0
	}
	return stepStop, 0
}

type failureAction uint8

const (
	stopRun failureAction = iota
	nextPair
	retryPair // or the next pair when the bound one cannot retry
)

// failureActionFor classifies a provider failure as the OpenAI and Anthropic
// SDKs do: the provider's x-should-retry decides whether the call may run
// again, and without it a timeout, a 409, a 429 or a server error can. A
// credential or deployment failure can pass on another pair. Billed usage and
// failures of our own end the request.
func failureActionFor(failure *schemas.BifrostError, attempt *schemas.BifrostContext, memory *requestMemoryLease) failureAction {
	if failure == nil || failure.AllowFallbacks != nil && !*failure.AllowFallbacks || failure.ExtraFields.BilledUsage != nil ||
		memory != nil && memory.responseFailed.Load() {
		return stopRun
	}
	action := statusFailureAction(failure)
	switch providerResponseHeader(attempt, "x-should-retry") {
	case "true":
		return retryPair
	case "false":
		if action == retryPair {
			// The header speaks for this provider account, not for other pairs.
			return nextPair
		}
	}
	return action
}

func statusFailureAction(failure *schemas.BifrostError) failureAction {
	if failure.StatusCode != nil && *failure.StatusCode == http.StatusConflict {
		return retryPair
	}
	switch billing.NormalizeUpstreamStatus(failure) {
	case "connection_error", "timeout", "rate_limited", "provider_unavailable", "provider_overloaded", "provider_error", "invalid_response":
		return retryPair
	case "authentication_error", "permission_error", "over_budget", "model_unavailable", "model_retired":
		return nextPair
	default:
		return stopRun
	}
}

func retryWait(retries int, attempt *schemas.BifrostContext) time.Duration {
	wait := time.Duration(float64(min(retryInitialWait<<retries, retryMaxWait)) * (1 - 0.25*rand.Float64()))
	if after, ok := providerRetryAfter(attempt); ok && after > wait {
		if after >= retryMaxWait {
			return after
		}
		// Calls that a provider refused together get the same wait, often in
		// whole seconds, and would otherwise retry together. A random part of
		// a second spreads them and never makes a wait too long to retry.
		return min(after+rand.N(time.Second), retryMaxWait)
	}
	return wait
}

// waitError reports why the caller no longer waits for the response.
func (r *providerRun) waitError() error {
	if err := r.client.inferenceWaitError(); err != nil {
		return err
	}
	if cancelled, _ := r.state.ClientStatus(); cancelled || !r.client.responseWait.waiting() {
		return context.Canceled
	}
	return nil
}

func (r *providerRun) waiting() bool { return r.waitError() == nil }

// pause waits out a retry's backoff, then reports whether the call may start
// and, if so, gives it an output idle window of idle.
func (r *providerRun) pause(wait, idle time.Duration) bool {
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.request.Done():
			return false
		case <-r.client.request.Context().Done():
			return false
		case <-r.client.responseWait.done():
			return false
		}
	}
	return r.request.Err() == nil && r.waiting() && r.client.responseWait.startOutput(idle)
}

// startProviderCall calls the bound pair after wait, and not before its
// authorization lets the request start. A call that the caller stopped waiting
// for does not start and returns a result without called.
func startProviderCall[T any](r *providerRun, wait time.Duration, call providerCall[T]) <-chan providerResult[T] {
	if !r.plan.HasNextPair() {
		r.releasePlan()
	}
	var limited time.Duration
	if authorization := r.pair.Authorization; authorization != nil {
		limited = time.Until(authorization.StartAt)
		wait = max(wait, limited)
	}
	r.attempts = r.state.ProviderAttemptCount()
	attempt := schemas.NewBifrostContext(r.pair.ctx, schemas.NoDeadline)
	if r.pair.Resolution.Provider == catalog.ProviderChutes {
		chutese2ee.SetInvocationBudget(attempt, 1+r.pair.Resolution.Retries()-r.retries, r.waiting)
	}
	request, state, idle := r.pair.request, r.state, r.pair.Resolution.RequestTimeouts().OutputIdle()
	server, provider := r.server, r.pair.Resolution.Provider
	ready := make(chan providerResult[T], 1)
	go func() {
		result := providerResult[T]{ctx: attempt}
		defer func() {
			// A detached call must still settle after a provider panic.
			if result.panic = recover(); result.panic != nil {
				result.failure = &schemas.BifrostError{
					StatusCode: schemas.Ptr(http.StatusInternalServerError), AllowFallbacks: schemas.Ptr(false),
					Error: &schemas.ErrorField{Message: "Provider request failed"},
				}
			}
			ready <- result
		}()
		paused := time.Now()
		resumed := r.pause(wait, idle)
		if limited > 0 {
			// The log shows only the part of the pause that the rate caused, up to
			// when the caller stopped waiting.
			state.RateLimitWait += min(limited, time.Since(paused))
		}
		if !resumed {
			return
		}
		state.MarkProviderStarted()
		result.called = true
		if server != nil {
			defer server.providerCalls.begin(provider, time.Now())()
		}
		result.response, result.failure = call(attempt, request)
		if server != nil {
			server.providers.observe(provider, result.failure)
		}
	}()
	return ready
}

// runProvider calls the bound pair, and the pairs after it, until a call
// succeeds or the run ends, while the caller waits. It returns the pending
// call when the caller stops waiting or a plain stream needs its first
// keepalive. Encrypted responses get keepalive records meanwhile.
func runProvider[T any](ctx *requestContext, r *providerRun, call providerCall[T], streaming bool) (providerResult[T], <-chan providerResult[T]) {
	var keepalive <-chan time.Time
	if _, encrypted := ctx.writer.(*sessionResponse); encrypted || streaming {
		ticker := time.NewTicker(responseKeepaliveInterval)
		defer ticker.Stop()
		keepalive = ticker.C
	}
	ready := startProviderCall(r, 0, call)
	for {
		result, pending := awaitProviderResult(ctx, r.state.MarkClientStopped, ready, keepalive)
		switch {
		case pending != nil, result.called && result.failure == nil:
			return result, pending
		case result.panic != nil:
			r.failed(result.failure, result.ctx)
			return result, nil
		case !result.called:
			r.stopped()
			return result, nil
		}
		delay, again := r.next(result.failure, result.ctx)
		if !again {
			return result, nil
		}
		ready = startProviderCall(r, delay, call)
	}
}

// stopped records a call that did not start because the caller stopped
// waiting or the request ran out of time.
func (r *providerRun) stopped() {
	if r.local = r.waitError(); r.local == nil {
		r.local = context.DeadlineExceeded
	}
}

// releasePlan drops what only later pairs need.
func (r *providerRun) releasePlan() {
	r.plan.ReleasePlan()
	r.plan = nil
	r.keyConfig = nil
	r.credential.EncryptionKeys.Clear()
	r.prepared.Clear()
	r.prepared = nil
	r.policyMemory.release()
	r.preparation.release()
}

// retire releases a pair that no reference keeps.
func (r *providerRun) retire(p *providerPair) {
	if p == nil || p == r.pair || p == r.held || p == r.called || p == r.attempted {
		return
	}
	p.Export.Discard()
	p.ctx.Cancel()
}

// commit keeps the bound pair after its call succeeded.
func (r *providerRun) commit() {
	r.releasePlan()
	previous := [...]*providerPair{r.held, r.called, r.attempted}
	r.held, r.called, r.attempted, r.last, r.lastCtx = r.pair, r.pair, r.pair, nil, nil
	for _, p := range previous {
		r.retire(p)
	}
}

// end binds the pair whose outcome the request reports: the last logged call,
// else the pair with the hold. It returns that call's failure and context, or
// nil when no call reached a provider and r.local has the failure.
func (r *providerRun) end() (*schemas.BifrostError, *schemas.BifrostContext) {
	r.releasePlan()
	final := r.called
	if final == nil {
		final = r.held
	}
	if final == nil {
		final = r.attempted
	}
	if final.request == nil {
		// Its preparation failed before it released the input.
		final.Resolution.ReleaseInput()
	}
	previous := [...]*providerPair{r.pair, r.held, r.called, r.attempted}
	r.pair, r.held, r.called, r.attempted = final, final, final, final
	for _, p := range previous {
		r.retire(p)
	}
	r.state.Pair = final.Pair
	if r.last != nil {
		return r.last, r.lastCtx
	}
	if r.state.ProcessingError == nil && !cancelledLocally(r.local) {
		response := localErrorResponse(r.local)
		code, _ := response.payload["error"].(map[string]any)["code"].(string)
		r.state.ProcessingError = &schemas.BifrostError{StatusCode: &response.status, Error: &schemas.ErrorField{Code: &code}}
	}
	return nil, nil
}

// cancelledLocally reports a failure that says only that the caller left.
func cancelledLocally(err error) bool {
	var unsent *unsentCall
	if errors.As(err, &unsent) {
		return billing.NormalizeUpstreamStatus(unsent.failure) == "cancelled"
	}
	return errors.Is(err, context.Canceled)
}
