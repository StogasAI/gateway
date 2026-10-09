package billing

import (
	"sync"
	"sync/atomic"
	"time"
)

// A local overload response is distinct from a saved request/concurrency quota.
// RetryAfter also survives public error wrapping and encrypted HTTP responses.
type retryAfterError struct {
	delay time.Duration
}

func (e *retryAfterError) Error() string             { return ErrAbuseRateLimit.Error() }
func (e *retryAfterError) Unwrap() error             { return ErrAbuseRateLimit }
func (e *retryAfterError) StatusCode() int           { return 429 }
func (e *retryAfterError) RetryAfter() time.Duration { return e.delay }

// RecordCallerFailure accepts only locally verified identities. Failed work,
// including dependency failures, consumes the same brief per-key backoff.
// Sibling keys never inherit it; aggregate organization admission is separate.
// Cancellation and rejected retries do not extend a cooldown.
func (s *Service) RecordCallerFailure(claims *APIKeyClaims, dashboard *DashboardCredential, status int, code string) {
	if s == nil || status < 400 || status == 408 || status == 499 || code == ErrAbuseRateLimit.Code {
		return
	}
	now := time.Now()
	if claims != nil && claims.KeyID != "" && claims.OrganizationID != "" {
		s.callerFailures.record("key:"+claims.KeyID, now)
	}
	if dashboard != nil {
		s.callerFailures.record(dashboardAdmissionKey(dashboard), now)
	}
}

func (s *Service) callerBackoff(claims *APIKeyClaims, dashboard *DashboardCredential, now time.Time) error {
	var delay time.Duration
	if claims != nil {
		delay = s.callerFailures.get("key:"+claims.KeyID, now)
	}
	if dashboard != nil {
		actorDelay := s.callerFailures.get(dashboardAdmissionKey(dashboard), now)
		delay = max(delay, actorDelay)
	}
	if delay > 0 {
		return &retryAfterError{delay: delay}
	}
	return nil
}

func (s *Service) recordRequestSuccess(keyID, dashboardIdentity string, started time.Time) {
	s.callerFailures.succeeded("key:"+keyID, started)
	if dashboardIdentity != "" {
		s.callerFailures.succeeded(dashboardIdentity, started)
	}
}

// A successful hold is not a successful request: clearing here would let
// repeated provider failures erase their own backoff before each dispatch.
func (s *Service) recordRequestOutcome(authorization *Authorization, event RequestEvent) {
	if event.Cancelled {
		return
	}
	if event.GatewayError == nil && len(event.ProviderAttempts) > 0 && event.ProviderAttempts[len(event.ProviderAttempts)-1].Status == "success" {
		s.recordRequestSuccess(authorization.KeyID, authorization.dashboardAdmissionIdentity, authorization.admissionStartedAt)
		return
	}
	now := time.Now()
	if authorization.KeyID != "" && authorization.OrganizationID != "" {
		s.callerFailures.record("key:"+authorization.KeyID, now)
	}
	if authorization.dashboardAdmissionIdentity != "" {
		s.callerFailures.record(authorization.dashboardAdmissionIdentity, now)
	}
}

type callerFailureEntry struct {
	blockedUntil time.Time
	failures     uint8
	lastFailedAt time.Time
}

type callerFailureShard struct {
	mu      sync.Mutex
	entries map[string]callerFailureEntry
}

type callerFailureCache struct {
	hits    atomic.Uint64
	lookups atomic.Uint64
	shards  [localAdmissionShards]callerFailureShard
}

func (c *callerFailureCache) get(
	key string,
	now time.Time,
) time.Duration {
	if c == nil || key == "" {
		return 0
	}
	c.lookups.Add(1)
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, ok := shard.entries[key]
	if !ok || !now.Before(entry.blockedUntil) {
		return 0
	}
	c.hits.Add(1)
	return entry.blockedUntil.Sub(now)
}

func (c *callerFailureCache) record(key string, now time.Time) {
	if c == nil || key == "" {
		return
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]callerFailureEntry)
	}

	entry := shard.entries[key]
	// Concurrent completions can acquire the shard lock out of timestamp
	// order. An older completion must not shorten the latest cooldown.
	if now.Before(entry.lastFailedAt) {
		now = entry.lastFailedAt
	}
	// Only overlapping failure bursts escalate. Once the advertised cooldown
	// ends, a new failure starts fresh without requiring a successful request.
	// Rejected retries only read this state and cannot prolong the penalty.
	if !now.Before(entry.blockedUntil) {
		entry.failures = 1
	} else if entry.failures < 16 {
		entry.failures++
	}
	delay := 25 * time.Millisecond
	for attempt := uint8(1); attempt < entry.failures && delay < 2*time.Second; attempt++ {
		delay *= 2
	}
	if delay > 2*time.Second {
		delay = 2 * time.Second
	}
	entry.blockedUntil = now.Add(delay)
	entry.lastFailedAt = now
	if _, exists := shard.entries[key]; !exists {
		evictCallerFailureEntry(shard.entries)
	}
	shard.entries[key] = entry
}

// A successful request ends an earlier failure streak. An older request
// completing late must not erase failures recorded since that request started.
func (c *callerFailureCache) succeeded(key string, started time.Time) {
	if c == nil || key == "" {
		return
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if entry, ok := shard.entries[key]; ok && !entry.lastFailedAt.After(started) {
		delete(shard.entries, key)
	}
}

func evictCallerFailureEntry(entries map[string]callerFailureEntry) {
	if len(entries) < localAdmissionEntriesPerShard {
		return
	}
	for key := range entries {
		delete(entries, key)
		return
	}
}
