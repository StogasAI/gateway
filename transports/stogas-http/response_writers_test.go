package stogashttp

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
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

func TestBillingRefusalsTellClientsWhenToRetry(t *testing.T) {
	for _, tc := range []struct {
		name, retry string
		err         error
		want        []string
	}{
		{"hold-back", "", retryableBillingTestError{25 * time.Millisecond}, []string{"1", "2"}},
		{"one second", "", retryableBillingTestError{time.Second}, []string{"1", "2"}},
		{"just over a second", "", retryableBillingTestError{time.Second + time.Nanosecond}, []string{"2", "3"}},
		{"under a minute", "", retryableBillingTestError{59 * time.Second}, []string{"59", "60"}},
		{"a minute", "", retryableBillingTestError{59*time.Second + time.Millisecond}, []string{"60"}},
		{"over a minute", "false", retryableBillingTestError{90 * time.Second}, []string{"90"}},
		{"no wait", "false", billing.ErrRateLimit, []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[string]bool{}
			// Each wait of a spread is missed by all 64 draws with chance 2⁻⁶⁴.
			for range 64 {
				ctx := newTestRequest(t)
				s := &Server{}
				s.writeBillingError(ctx, fmt.Errorf("internal detail: %w", tc.err))
				header := ctx.writer.Header()
				if testResponse(ctx).Code != 429 || header.Get("X-Should-Retry") != tc.retry {
					t.Fatalf("response = %d %s, X-Should-Retry = %q", testResponse(ctx).Code, testResponse(ctx).Body.Bytes(), header.Get("X-Should-Retry"))
				}
				seen[header.Get("Retry-After")] = true
				var body struct {
					Error struct{ Code, Type, Message string }
				}
				if err := json.Unmarshal(testResponse(ctx).Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Error.Code != "rate_limit_exceeded" || body.Error.Type != "rate_limit_error" || body.Error.Message != billing.ErrRateLimit.Message {
					t.Fatalf("wrong public error: %s", testResponse(ctx).Body.Bytes())
				}
			}
			want := map[string]bool{}
			for _, value := range tc.want {
				want[value] = true
			}
			if !maps.Equal(seen, want) {
				t.Fatalf("Retry-After values = %v, want %v", seen, tc.want)
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
