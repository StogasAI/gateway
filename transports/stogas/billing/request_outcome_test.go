package billing

import "testing"

// The cases follow the outcome that Analytics shows, branch by branch.
func TestRequestOutcome(t *testing.T) {
	attempts := func(statuses ...string) []ProviderAttempt {
		result := make([]ProviderAttempt, len(statuses))
		for i, status := range statuses {
			result[i].Status = status
		}
		return result
	}
	failure := &EventError{Code: "insufficient_balance", Status: 402}
	for _, tc := range []struct {
		name  string
		event RequestEvent
		want  string
	}{
		{"served", RequestEvent{ProviderAttempts: attempts("success")}, "success"},
		{"served after a fallback", RequestEvent{ProviderAttempts: attempts("rate_limited", "success")}, "success"},
		{"every call failed", RequestEvent{ProviderAttempts: attempts("rate_limited", "provider_unavailable")}, "failed"},
		{"the last call failed after one succeeded", RequestEvent{ProviderAttempts: attempts("success", "timeout")}, "failed"},
		{"rejected before any call", RequestEvent{GatewayError: failure, ProviderAttempts: []ProviderAttempt{}}, "rejected"},
		{"rejected, counted with others", RequestEvent{GatewayError: failure, RequestCount: 94}, "rejected"},
		{"the gateway failed after the provider succeeded", RequestEvent{GatewayError: failure, ProviderAttempts: attempts("success")}, "failed"},
		{"the gateway refused the next candidate", RequestEvent{GatewayError: failure, ProviderAttempts: attempts("rate_limited")}, "failed"},
		// A gateway error comes before the caller's own stop.
		{"rejected and cancelled", RequestEvent{GatewayError: failure, Cancelled: true}, "rejected"},
		{"failed and cancelled", RequestEvent{GatewayError: failure, Cancelled: true, ProviderAttempts: attempts("cancelled")}, "failed"},
		{"the caller stopped a call", RequestEvent{Cancelled: true, ProviderAttempts: attempts("cancelled")}, "cancelled"},
		{"the caller stopped after the provider finished", RequestEvent{Cancelled: true, ProviderAttempts: attempts("success")}, "cancelled"},
		{"the caller stopped before any call", RequestEvent{Cancelled: true}, "cancelled"},
		{"no call and no error", RequestEvent{}, "unknown"},
		{"a call without a result", RequestEvent{ProviderAttempts: attempts("")}, "unknown"},
		{"a call whose result is unknown", RequestEvent{ProviderAttempts: attempts("success", "unknown")}, "unknown"},
		{"an error without a code is no gateway error", RequestEvent{GatewayError: &EventError{}, ProviderAttempts: attempts("success")}, "success"},
		{"a call that the provider cancelled", RequestEvent{ProviderAttempts: attempts("cancelled")}, "failed"},
	} {
		if got := tc.event.Outcome(); got != tc.want {
			t.Errorf("%s: outcome = %s, want %s", tc.name, got, tc.want)
		}
	}
}
