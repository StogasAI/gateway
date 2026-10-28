package stogashttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
)

func providerFailure(status int, errorType string, ours bool) *schemas.BifrostError {
	failure := &schemas.BifrostError{IsBifrostError: ours, Error: &schemas.ErrorField{Message: "provider failure"}}
	if status != 0 {
		failure.StatusCode = schemas.Ptr(status)
	}
	if errorType != "" {
		failure.Error.Type = schemas.Ptr(errorType)
	}
	return failure
}

// Unanswered calls count until any provider answers. The monitor needs two
// providers unanswered, so one provider's outage is not this gateway's fault.
func TestProviderReachCountsUnansweredProvidersUntilAnAnswer(t *testing.T) {
	var reach providerReach
	if diagnostics := reach.diagnostics(); diagnostics != (providerReachDiagnostics{}) {
		t.Fatalf("new reach = %+v", diagnostics)
	}
	reach.observe(schemas.OpenAI, providerFailure(http.StatusBadGateway, schemas.ProviderConnectionFailed, false))
	first := reach.diagnostics()
	if first.Unanswered != 1 || first.UnansweredProviders != 1 || first.UnansweredSince == nil || !first.UnansweredSince.Equal(*first.LastUnansweredAt) {
		t.Fatalf("after a connection failure: %+v", first)
	}
	time.Sleep(2 * time.Millisecond)
	// Timeouts are unanswered too: a dropped connection times out instead of
	// failing. Cancellations and this gateway's own failures change nothing.
	reach.observe(schemas.Anthropic, providerFailure(http.StatusGatewayTimeout, schemas.RequestTimedOut, true))
	reach.observe(schemas.OpenAI, providerFailure(0, schemas.RequestCancelled, false))
	reach.observe(schemas.Gemini, providerFailure(http.StatusInternalServerError, "", true))
	reach.observe(schemas.Gemini, providerFailure(0, "", false))
	second := reach.diagnostics()
	if second.Unanswered != 2 || second.UnansweredProviders != 2 || !second.UnansweredSince.Equal(*first.UnansweredSince) ||
		!second.LastUnansweredAt.After(*first.LastUnansweredAt) {
		t.Fatalf("after a timeout: %+v", second)
	}
	// A provider's error status is an answer: its endpoint was reached.
	reach.observe(schemas.Gemini, providerFailure(http.StatusUnauthorized, "", false))
	answered := reach.diagnostics()
	if answered.Unanswered != 2 || answered.UnansweredProviders != 0 || answered.UnansweredSince != nil ||
		!answered.LastUnansweredAt.Equal(*second.LastUnansweredAt) {
		t.Fatalf("after an error status: %+v", answered)
	}
	reach.observe(schemas.OpenAI, providerFailure(http.StatusBadGateway, schemas.ProviderConnectionFailed, false))
	reach.observe(schemas.OpenAI, nil)
	if succeeded := reach.diagnostics(); succeeded.Unanswered != 3 || succeeded.UnansweredProviders != 0 || succeeded.UnansweredSince != nil {
		t.Fatalf("after a success: %+v", succeeded)
	}
}

func TestProviderCallsReportTheirReach(t *testing.T) {
	ctx := &requestContext{writer: &sessionResponse{}, request: httptest.NewRequest(http.MethodPost, "/v1/responses", nil)}
	request, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	server := &Server{}
	run := testRun(server, ctx, request, &stogas.State{Pair: stogas.Pair{Resolution: testResolution()}}, cancel)
	result := <-startProviderCall(run, 0, func(*schemas.BifrostContext, *schemas.BifrostRequest) (string, *schemas.BifrostError) {
		return "", providerFailure(http.StatusBadGateway, schemas.ProviderConnectionFailed, false)
	})
	if !result.called || server.providers.diagnostics().UnansweredProviders != 1 {
		t.Fatalf("called = %t, reach = %+v", result.called, server.providers.diagnostics())
	}
	// A panic is this gateway's failure, not a provider's answer.
	result = <-startProviderCall(run, 0, func(*schemas.BifrostContext, *schemas.BifrostRequest) (string, *schemas.BifrostError) {
		panic(http.ErrAbortHandler)
	})
	if result.panic == nil || server.providers.diagnostics().UnansweredSince == nil {
		t.Fatalf("panic = %v, reach = %+v", result.panic, server.providers.diagnostics())
	}
	result = <-startProviderCall(run, 0, func(*schemas.BifrostContext, *schemas.BifrostRequest) (string, *schemas.BifrostError) {
		return "response", nil
	})
	if result.failure != nil || server.providers.diagnostics().UnansweredSince != nil {
		t.Fatalf("failure = %v, reach = %+v", result.failure, server.providers.diagnostics())
	}
}

// The peak covers the last one to two minutes and calls that started earlier
// and still run, so a monitor that reads once a minute sees every saturation.
func TestProviderCallsReportRecentPeakPerProvider(t *testing.T) {
	var calls providerCalls
	start := time.Date(2026, 10, 28, 12, 0, 10, 0, time.UTC)
	if got := calls.diagnostics(start); got != (providerCallDiagnostics{Workers: stogas.ProviderWorkers}) {
		t.Fatalf("no calls = %+v", got)
	}
	var ends []func()
	for range 3 {
		ends = append(ends, calls.begin(schemas.OpenAI, start))
	}
	long := calls.begin(schemas.Anthropic, start)
	ends = append(ends, calls.begin(schemas.Anthropic, start))
	for _, end := range ends {
		end()
	}
	want := providerCallDiagnostics{Workers: stogas.ProviderWorkers, RecentPeak: 3, RecentPeakProvider: string(schemas.OpenAI)}
	if got := calls.diagnostics(start); got != want {
		t.Fatalf("after a burst = %+v, want %+v", got, want)
	}
	// The next minute still reports the last minute's peak.
	if got := calls.diagnostics(start.Add(time.Minute)); got != want {
		t.Fatalf("a minute later = %+v, want %+v", got, want)
	}
	// After that only the call that still runs counts.
	want = providerCallDiagnostics{Workers: stogas.ProviderWorkers, RecentPeak: 1, RecentPeakProvider: string(schemas.Anthropic)}
	if got := calls.diagnostics(start.Add(2 * time.Minute)); got != want {
		t.Fatalf("two minutes later = %+v, want %+v", got, want)
	}
	long()
	if got := calls.diagnostics(start.Add(5 * time.Minute)); got != (providerCallDiagnostics{Workers: stogas.ProviderWorkers}) {
		t.Fatalf("after every call ended = %+v", got)
	}
}

// A call counts while core runs or queues it, and a panic still ends it.
func TestStartProviderCallCountsRunningCalls(t *testing.T) {
	ctx := &requestContext{writer: &sessionResponse{}, request: httptest.NewRequest(http.MethodPost, "/v1/responses", nil)}
	request, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	server := &Server{}
	release := make(chan struct{})
	running := make(chan struct{})
	run := testRun(server, ctx, request, &stogas.State{Pair: stogas.Pair{Resolution: testResolution()}}, cancel)
	ready := startProviderCall(run, 0, func(*schemas.BifrostContext, *schemas.BifrostRequest) (string, *schemas.BifrostError) {
		close(running)
		<-release
		panic("provider")
	})
	<-running
	if got := server.providerCalls.diagnostics(time.Now()); got.RecentPeak != 1 {
		t.Fatalf("while running = %+v", got)
	}
	close(release)
	if result := <-ready; result.panic == nil {
		t.Fatal("the panic was not reported")
	}
	server.providerCalls.mu.Lock()
	defer server.providerCalls.mu.Unlock()
	for provider, calls := range server.providerCalls.running {
		if calls != 0 {
			t.Fatalf("%s still counts %d calls", provider, calls)
		}
	}
}
