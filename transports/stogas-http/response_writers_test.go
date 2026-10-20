package stogashttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

type retryableBillingTestError struct{ delay time.Duration }

func (e retryableBillingTestError) Error() string             { return billing.ErrRateLimit.Error() }
func (e retryableBillingTestError) Unwrap() error             { return billing.ErrRateLimit }
func (e retryableBillingTestError) RetryAfter() time.Duration { return e.delay }

func TestBillingFailureRetryAfterSurvivesWrapping(t *testing.T) {
	for _, tc := range []struct {
		delay time.Duration
		want  string
	}{{25 * time.Millisecond, "1"}, {time.Second, "1"}, {time.Second + time.Nanosecond, "2"}, {2 * time.Second, "2"}} {
		t.Run(tc.delay.String(), func(t *testing.T) {
			ctx := newTestRequest(t)
			s := &Server{}
			s.writeBillingError(ctx, fmt.Errorf("internal detail: %w", retryableBillingTestError{tc.delay}))
			if testResponse(ctx).Code != 429 || string(ctx.writer.Header().Get("Retry-After")) != tc.want {
				t.Fatalf("response = %s", testResponse(ctx).Body.Bytes())
			}
			var body struct {
				Error struct{ Code, Type, Message string }
			}
			if err := json.Unmarshal(testResponse(ctx).Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code != "rate_limit_exceeded" || body.Error.Type != "rate_limit_error" || body.Error.Message != billing.ErrRateLimit.Message {
				t.Fatalf("wrong public error: %s", testResponse(ctx).Body.Bytes())
			}
		})
	}
}

func TestWriteProviderErrorTellsClientsWhenToRetry(t *testing.T) {
	for _, tc := range []struct {
		name, providerRetryAfter  string
		err                       *schemas.BifrostError
		wantRetryAfter, wantRetry string
	}{
		{"rate limit", "7", testBifrostError(http.StatusTooManyRequests, "slow down", "rate_limit_error", ""), "7", ""},
		{"overload until a past date", "Wed, 21 Oct 2015 07:28:00 GMT", testBifrostError(529, "overloaded", "overloaded_error", ""), "0", ""},
		{"invalid delay", "soon", testBifrostError(http.StatusServiceUnavailable, "unavailable", "", ""), "", ""},
		{"request error", "7", testBifrostError(http.StatusBadRequest, "bad request", "invalid_request_error", ""), "", ""},
		{"rejected credential", "7", testBifrostError(http.StatusUnauthorized, "bad key", "authentication_error", ""), "", "false"},
		{"exhausted quota", "7", testBifrostError(http.StatusTooManyRequests, "quota", "", "insufficient_quota"), "", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newTestRequest(t)
			bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			bifrostCtx.SetValue(schemas.BifrostContextKeyProviderResponseHeaders, map[string]string{"Retry-After": tc.providerRetryAfter})
			(&Server{}).writeProviderError(ctx, bifrostCtx, tc.err)
			header := ctx.writer.Header()
			if header.Get("Retry-After") != tc.wantRetryAfter || header.Get("X-Should-Retry") != tc.wantRetry {
				t.Fatalf("Retry-After = %q, X-Should-Retry = %q", header.Get("Retry-After"), header.Get("X-Should-Retry"))
			}
		})
	}
}

func TestPublicBifrostErrorKeepsProviderLimitAndPolicyDetails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      *schemas.BifrostError
		wantCode any
	}{
		{"prompt too long", testBifrostError(http.StatusBadRequest, "prompt is too long: 215000 tokens > 200000 maximum", "invalid_request_error", ""), nil},
		{"OpenAI cyber policy on 403", testBifrostError(http.StatusForbidden, "Request blocked by cyber policy.", "", "cyber_policy"), "cyber_policy"},
		{"OpenAI cyber policy inside a stream", testBifrostError(0, "Request blocked by cyber policy.", "", "cyber_policy"), "cyber_policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, payload := publicBifrostError(tc.err)
			errorObject := publicErrorObject(t, payload)
			if status != http.StatusBadRequest || errorObject["code"] != tc.wantCode || errorObject["message"] != tc.err.Error.Message {
				t.Fatalf("status = %d, error = %#v", status, errorObject)
			}
		})
	}
}
