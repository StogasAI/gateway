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
