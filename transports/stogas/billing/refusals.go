package billing

import (
	"sync"
	"sync/atomic"
	"time"
)

// retryAfterError tells the caller when a refusal ends. RetryAfter survives
// public error wrapping and encrypted HTTP responses.
type retryAfterError struct {
	*RequestError
	delay time.Duration
}

func (e *retryAfterError) Unwrap() error             { return e.RequestError }
func (e *retryAfterError) RetryAfter() time.Duration { return e.delay }

const (
	// After PostgreSQL refuses a credential's request, this gateway refuses the
	// credential's next requests from memory for this long. The pause stays the
	// same however often PostgreSQL refuses, so a client that retries keeps the
	// full rate that its limits allow.
	refusalHoldBack = 25 * time.Millisecond
	// A secret that PostgreSQL refused, because its key was deleted, left its
	// grant or got a new secret, keeps its valid signature. This gateway refuses
	// the secret for a minute without asking PostgreSQL, so its holder cannot
	// spend the organization's local request allowance.
	refusedAPIKeyDuration = time.Minute
)

// callerAdmissionKey names the credential that refusals apply to: the verified
// API key secret, or the dashboard actor's session. Sibling keys, a key's
// replaced secret and other sessions never share it; aggregate organization
// admission is separate.
func callerAdmissionKey(claims *APIKeyClaims, dashboard *DashboardCredential) string {
	if dashboard != nil {
		return dashboardAdmissionKey(dashboard)
	}
	if claims != nil {
		return claims.admissionKey
	}
	return ""
}

// RecordRefusal remembers a verified credential's request that PostgreSQL
// refused. The transport reports a request once, after its last pair, and
// only if no pair was admitted, so a refusal that another pair passes holds
// nothing back. Other rejections cost no database call and hold nothing back.
func (s *Service) RecordRefusal(claims *APIKeyClaims, dashboard *DashboardCredential, code string) {
	if s == nil || !refusalCodes[code] {
		return
	}
	if dashboard == nil && claims != nil {
		for _, refusal := range []*RequestError{ErrInvalidAPIKey, ErrAPIKeyOldSecret} {
			if code == refusal.Code {
				s.refusals.record(claims.admissionKey, refusal, refusedAPIKeyDuration, time.Now())
				return
			}
		}
	}
	s.refusals.record(callerAdmissionKey(claims, dashboard), nil, refusalHoldBack, time.Now())
}

type refusal struct {
	until time.Time
	// err is the refusal that memory repeats, or nil for the generic hold-back,
	// since other refusals can depend on the request.
	err *RequestError
}

type refusalShard struct {
	mu      sync.Mutex
	entries map[string]refusal
}

type refusalCache struct {
	hits    atomic.Uint64
	lookups atomic.Uint64
	shards  [localAdmissionShards]refusalShard
}

func (c *refusalCache) get(key string, now time.Time) error {
	if key == "" {
		return nil
	}
	c.lookups.Add(1)
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	entry := shard.entries[key]
	shard.mu.Unlock()
	if !now.Before(entry.until) {
		return nil
	}
	c.hits.Add(1)
	if entry.err != nil {
		return entry.err
	}
	return &retryAfterError{ErrRateLimit, entry.until.Sub(now)}
}

// record keeps a current refusal until it ends, so requests that memory or a
// concurrent statement refused cannot extend it.
func (c *refusalCache) record(key string, err *RequestError, duration time.Duration, now time.Time) {
	if key == "" {
		return
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, exists := shard.entries[key]
	if exists && now.Before(entry.until) {
		return
	}
	if shard.entries == nil {
		shard.entries = make(map[string]refusal)
	}
	if !exists && len(shard.entries) >= localAdmissionEntriesPerShard {
		for other := range shard.entries {
			delete(shard.entries, other)
			break
		}
	}
	shard.entries[key] = refusal{now.Add(duration), err}
}
