package stogashttp

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

type retryableBillingTestError struct{ delay time.Duration }

func (e retryableBillingTestError) Error() string             { return billing.ErrAbuseRateLimit.Error() }
func (e retryableBillingTestError) Unwrap() error             { return billing.ErrAbuseRateLimit }
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
			if body.Error.Code != "abuse_rate_limited" || body.Error.Type != "rate_limit_error" || body.Error.Message != billing.ErrAbuseRateLimit.Message {
				t.Fatalf("wrong public error: %s", testResponse(ctx).Body.Bytes())
			}
		})
	}
}
