package billing

import (
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestTerminalBackoffUsesFinalOutcomeAndKeepsEventFacts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		event     RequestEvent
		clears    bool
		unchanged bool
	}{
		{"success", RequestEvent{ProviderAttempts: []ProviderAttempt{{Status: "success"}}}, true, false},
		{"recovered retry", RequestEvent{ProviderAttempts: []ProviderAttempt{{Status: "provider_error"}, {Status: "success"}}}, true, false},
		{"failed after output", RequestEvent{ProviderAttempts: []ProviderAttempt{{Status: "success"}, {Status: "provider_error", OutputObserved: true}}}, false, false},
		{"processing failed", RequestEvent{GatewayError: &EventError{Code: "internal_error", Status: 500}, ProviderAttempts: []ProviderAttempt{{Status: "success"}}}, false, false},
		{"local error", RequestEvent{GatewayError: &EventError{Code: "gateway_capacity_exceeded", Status: 503}, ProviderAttempts: []ProviderAttempt{{Status: "success"}}}, false, false},
		{"no dispatch", RequestEvent{}, false, false},
		{"client cancelled", RequestEvent{Cancelled: true, ProviderAttempts: []ProviderAttempt{{Status: "provider_error"}}}, false, true},
		{"cancelled after success", RequestEvent{Cancelled: true, ProviderAttempts: []ProviderAttempt{{Status: "success"}}}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{}
			started := time.Now().Add(-time.Second)
			a := &Authorization{KeyID: "key", OrganizationID: "org", dashboardAdmissionIdentity: "dashboard:actor:session", admissionStartedAt: started}
			identities := []string{"key:key", "dashboard:actor:session"}
			for _, key := range identities {
				s.callerFailures.record(key, started.Add(-time.Second))
			}
			before := tc.event
			before.ProviderAttempts = append([]ProviderAttempt(nil), tc.event.ProviderAttempts...)
			s.recordRequestOutcome(a, tc.event)
			if !reflect.DeepEqual(before, tc.event) {
				t.Fatal("backoff changed logged outcome")
			}
			for _, key := range identities {
				shard := &s.callerFailures.shards[localAdmissionShard(key)]
				entry, exists := shard.entries[key]
				if tc.clears && exists || !tc.clears && !exists {
					t.Fatalf("%s: unexpected cache state", key)
				}
				if tc.unchanged && !entry.lastFailedAt.Equal(started.Add(-time.Second)) {
					t.Fatal("cancellation changed failure state")
				}
				if !tc.clears && entry.failures != 1 {
					t.Fatalf("%s failures: %d", key, entry.failures)
				}
			}
		})
	}
	for _, status := range []string{"authentication_error", "permission_error", "over_budget", "rate_limited", "timeout", "connection_error", "provider_unavailable", "provider_overloaded", "provider_error", "invalid_response", "invalid_request", "model_unavailable", "context_length_exceeded", "request_too_large", "invalid_image", "content_filter", "unknown"} {
		s := &Service{}
		s.recordRequestOutcome(&Authorization{KeyID: "key", OrganizationID: "org"}, RequestEvent{ProviderAttempts: []ProviderAttempt{{Status: status}}})
		if len(s.callerFailures.shards[localAdmissionShard("key:key")].entries) != 1 {
			t.Fatalf("%s did not back off", status)
		}
	}
}

func TestFailureBackoffConcurrentAndOutOfOrderCompletions(t *testing.T) {
	var c callerFailureCache
	now := time.Unix(1700000000, 0)
	var workers sync.WaitGroup
	for i := range 200 {
		workers.Go(func() {
			c.record("org", now.Add(time.Duration(i)*time.Millisecond))
			c.get("org", now)
			c.succeeded("org", now.Add(-time.Second))
		})
	}
	workers.Wait()
	latest := now.Add(199 * time.Millisecond)
	if got := c.get("org", latest); got != 2*time.Second {
		t.Fatalf("concurrent completion shortened cooldown: %s", got)
	}
	c.record("org", now)
	if got := c.get("org", latest); got != 2*time.Second {
		t.Fatalf("old completion shortened cooldown: %s", got)
	}
	if got := c.get("org", latest.Add(2*time.Second)); got != 0 {
		t.Fatalf("cooldown did not end: %s", got)
	}
	c.succeeded("org", latest.Add(-time.Nanosecond))
	if c.get("org", latest) == 0 {
		t.Fatal("older success erased failure")
	}
	c.succeeded("org", latest)
	if c.get("org", latest) != 0 {
		t.Fatal("newer success did not clear failure")
	}
	c.record("org", latest)
	if c.get("org", latest) != 25*time.Millisecond {
		t.Fatal("recovered request retained failure streak")
	}
}

func TestFailureCooldownBoundaryAndBoundedState(t *testing.T) {
	var c callerFailureCache
	now := time.Unix(1700000000, 0)
	c.record("key", now)
	c.record("key", now.Add(25*time.Millisecond-time.Nanosecond))
	if c.get("key", now.Add(25*time.Millisecond-time.Nanosecond)) != 50*time.Millisecond {
		t.Fatal("overlapping failure did not escalate")
	}
	now = now.Add(75*time.Millisecond - time.Nanosecond)
	c.record("key", now)
	if c.get("key", now) != 25*time.Millisecond {
		t.Fatal("exact cooldown boundary retained failure streak")
	}
	for i := 0; i < localAdmissionShards*localAdmissionEntriesPerShard*2; i++ {
		c.record(string(rune(i+1)), now)
	}
	for i := range c.shards {
		if len(c.shards[i].entries) > localAdmissionEntriesPerShard {
			t.Fatal("unbounded failure identities")
		}
	}
}

func TestLocalRateOutOfOrderArrivalDoesNotMintTokens(t *testing.T) {
	var limiter localRequestLimiter
	now := time.Unix(1700000000, 0)
	for range localRequestBurst {
		if limiter.allow("org", now) != 0 {
			t.Fatal("initial burst missing")
		}
	}
	if limiter.allow("org", now.Add(-time.Second)) <= 0 {
		t.Fatal("older arrival admitted")
	}
	if limiter.allow("org", now) <= 0 {
		t.Fatal("older arrival minted refill credit")
	}
	if limiter.allow("org", now.Add(time.Second)) != 0 {
		t.Fatal("normal refill failed")
	}
}

func TestFailureCooldownUnderContinuousTraffic(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rate  int
		fails bool
	}{
		{"periodic upstream outage", 2, true},
		{"busy upstream outage", 20, true},
		{"healthy organization allowance", 60, false},
		{"runaway failed requests", 10000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var failures callerFailureCache
			var rate localRequestLimiter
			start := time.Unix(1700000000, 0)
			admitted := 0
			for i := range tc.rate * 10 {
				now := start.Add(time.Duration(i) * time.Second / time.Duration(tc.rate))
				if failures.get("org", now) > 0 || rate.allow("org", now) > 0 {
					continue
				}
				admitted++
				if tc.fails {
					failures.record("org", now)
				}
			}
			if tc.rate <= 60 && admitted != tc.rate*10 {
				t.Fatalf("periodic application admitted %d/%d", admitted, tc.rate*10)
			}
			if tc.rate == 10000 && (admitted == 0 || admitted > 400) {
				t.Fatalf("runaway failure admission = %d, want 1..400", admitted)
			}
			if failures.get("other-org", start) != 0 {
				t.Fatal("one organization's failures blocked another")
			}
		})
	}
}

func TestRejectedRetryFloodCannotExtendCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Service{}
		claims := &APIKeyClaims{KeyID: "key", OrganizationID: "org"}
		s.RecordCallerFailure(claims, nil, 503, "provider_unavailable")
		for range 1000 {
			if s.callerBackoff(claims, nil, time.Now()) == nil {
				t.Fatal("cooldown allowed an early retry")
			}
			s.RecordCallerFailure(claims, nil, 429, ErrAbuseRateLimit.Code)
		}
		time.Sleep(25 * time.Millisecond)
		if s.callerBackoff(claims, nil, time.Now()) != nil {
			t.Fatal("rejected retries prolonged cooldown")
		}
		s.RecordCallerFailure(claims, nil, 503, "provider_unavailable")
		if delay := s.callerFailures.get("key:key", time.Now()); delay != 25*time.Millisecond {
			t.Fatalf("retry after cooldown retained penalty: %s", delay)
		}
	})
}
