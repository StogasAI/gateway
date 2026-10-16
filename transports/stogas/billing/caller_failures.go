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

// callerAdmissionKey names the credential that caller backoff applies to: the
// verified API key secret, or the dashboard actor's session. Sibling keys, a
// key's replaced secret and other sessions never share it; aggregate
// organization admission is separate.
func callerAdmissionKey(claims *APIKeyClaims, dashboard *DashboardCredential) string {
	if dashboard != nil {
		return dashboardAdmissionKey(dashboard)
	}
	if claims != nil {
		return claims.admissionKey
	}
	return ""
}

// A secret that PostgreSQL refused, because its key was deleted, left its grant
// or got a new secret, keeps its valid signature. Its holder could otherwise
// spend the organization's local request allowance again after every brief
// cooldown, so this gateway refuses the secret for a minute without asking
// PostgreSQL.
const refusedAPIKeyDuration = time.Minute

// RecordCallerFailure accepts only locally verified identities. Failed work,
// including dependency failures, consumes the same brief backoff. Cancellation
// and rejected retries do not extend a cooldown.
func (s *Service) RecordCallerFailure(claims *APIKeyClaims, dashboard *DashboardCredential, status int, code string) {
	if s == nil || status < 400 || status == 408 || status == 499 || code == ErrAbuseRateLimit.Code {
		return
	}
	if dashboard == nil && claims != nil {
		for _, refusal := range []*RequestError{ErrInvalidAPIKey, ErrAPIKeyOldSecret} {
			if code == refusal.Code {
				s.callerFailures.refuse(claims.admissionKey, refusal, time.Now())
				return
			}
		}
	}
	s.callerFailures.record(callerAdmissionKey(claims, dashboard), time.Now())
}

func (s *Service) callerBackoff(admissionKey string, now time.Time) error {
	if delay := s.callerFailures.get(admissionKey, now); delay > 0 {
		return &retryAfterError{delay: delay}
	}
	return nil
}

// A successful hold is not a successful request: clearing here would let
// repeated provider failures erase their own backoff before each dispatch.
func (s *Service) recordRequestOutcome(authorization *Authorization, event RequestEvent) {
	if event.Cancelled {
		return
	}
	if event.GatewayError == nil && len(event.ProviderAttempts) > 0 && event.ProviderAttempts[len(event.ProviderAttempts)-1].Status == "success" {
		s.callerFailures.succeeded(authorization.admissionKey, authorization.admissionStartedAt)
		return
	}
	s.callerFailures.record(authorization.admissionKey, time.Now())
}

type callerFailureEntry struct {
	blockedUntil time.Time
	failures     uint8
	lastFailedAt time.Time
	refusal      *RequestError
	refusedUntil time.Time
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

// refuse remembers PostgreSQL's refusal of a secret. Requests refused from
// memory do not extend it, so a key that becomes valid again, such as one
// returned to its grant, works within the minute.
func (c *callerFailureCache) refuse(key string, refusal *RequestError, now time.Time) {
	if c == nil || key == "" {
		return
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]callerFailureEntry)
	}
	entry, exists := shard.entries[key]
	if now.Before(entry.refusedUntil) {
		return
	}
	entry.refusal = refusal
	entry.refusedUntil = now.Add(refusedAPIKeyDuration)
	if !exists {
		evictCallerFailureEntry(shard.entries)
	}
	shard.entries[key] = entry
}

func (c *callerFailureCache) refused(key string, now time.Time) error {
	if c == nil || key == "" {
		return nil
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if entry, ok := shard.entries[key]; ok && now.Before(entry.refusedUntil) {
		return entry.refusal
	}
	return nil
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
