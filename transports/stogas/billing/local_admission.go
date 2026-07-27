package billing

import (
	"math"
	"sync"
	"time"
)

const (
	localAdmissionShards          = 64
	localAdmissionEntriesPerShard = 512
	localRequestRatePerSecond     = 120
	localRequestBurst             = 120
	localAuthorizationConcurrency = 8
)

type localRequestEntry struct {
	tokens    float64
	updatedAt time.Time
}

type localRequestShard struct {
	mu      sync.Mutex
	entries map[string]localRequestEntry
}

// localRequestLimiter is a coarse per-process shield. PostgreSQL remains the
// authoritative fleet-wide token bucket.
type localRequestLimiter struct {
	shards [localAdmissionShards]localRequestShard
}

func (l *localRequestLimiter) allow(keyID string, now time.Time) time.Duration {
	if l == nil || keyID == "" {
		return time.Second
	}
	shard := &l.shards[localAdmissionShard(keyID)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]localRequestEntry)
	}

	entry, ok := shard.entries[keyID]
	if !ok {
		evictLocalAdmissionEntry(shard.entries)
		shard.entries[keyID] = localRequestEntry{
			tokens:    localRequestBurst - 1,
			updatedAt: now,
		}
		return 0
	}

	elapsed := now.Sub(entry.updatedAt).Seconds()
	if elapsed > 0 {
		entry.tokens = math.Min(localRequestBurst, entry.tokens+elapsed*localRequestRatePerSecond)
	}
	entry.updatedAt = now
	if entry.tokens >= 1 {
		entry.tokens--
		shard.entries[keyID] = entry
		return 0
	}
	shard.entries[keyID] = entry
	return time.Duration(math.Ceil((1 - entry.tokens) / localRequestRatePerSecond * float64(time.Second)))
}

type localAuthorizationShard struct {
	mu       sync.Mutex
	inFlight map[string]uint8
}

// localAuthorizationLimiter prevents one key's first uncached burst from
// occupying the process's entire database pool.
type localAuthorizationLimiter struct {
	shards [localAdmissionShards]localAuthorizationShard
}

func (l *localAuthorizationLimiter) acquire(keyID string) (func(), bool) {
	if l == nil || keyID == "" {
		return nil, false
	}
	shard := &l.shards[localAdmissionShard(keyID)]
	shard.mu.Lock()
	if shard.inFlight == nil {
		shard.inFlight = make(map[string]uint8)
	}
	if shard.inFlight[keyID] >= localAuthorizationConcurrency {
		shard.mu.Unlock()
		return nil, false
	}
	shard.inFlight[keyID]++
	shard.mu.Unlock()

	return func() {
		shard.mu.Lock()
		if shard.inFlight[keyID] <= 1 {
			delete(shard.inFlight, keyID)
		} else {
			shard.inFlight[keyID]--
		}
		shard.mu.Unlock()
	}, true
}

type authorizationRejectionEntry struct {
	blockedUntil time.Time
	failures     uint8
	lastFailedAt time.Time
	result       string
}

type authorizationRejectionShard struct {
	mu      sync.Mutex
	entries map[string]authorizationRejectionEntry
}

type authorizationRejectionCache struct {
	shards [localAdmissionShards]authorizationRejectionShard
}

type rejectionPolicy struct {
	decay   time.Duration
	initial time.Duration
	maximum time.Duration
}

func (c *authorizationRejectionCache) get(
	key string,
	now time.Time,
) (string, time.Duration, bool) {
	if c == nil || key == "" {
		return "", 0, false
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, ok := shard.entries[key]
	if !ok || !now.Before(entry.blockedUntil) {
		return "", 0, false
	}
	return entry.result, entry.blockedUntil.Sub(now), true
}

func (c *authorizationRejectionCache) record(key string, result string, now time.Time) {
	policy, ok := authorizationRejectionPolicy(result)
	if c == nil || key == "" || !ok {
		return
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]authorizationRejectionEntry)
	}

	entry := shard.entries[key]
	if entry.result != result || now.Sub(entry.lastFailedAt) > policy.decay {
		entry.failures = 1
	} else if entry.failures < 16 {
		entry.failures++
	}
	delay := policy.initial
	for attempt := uint8(1); attempt < entry.failures && delay < policy.maximum; attempt++ {
		delay *= 2
	}
	if delay > policy.maximum {
		delay = policy.maximum
	}
	entry.blockedUntil = now.Add(delay)
	entry.lastFailedAt = now
	entry.result = result
	if _, exists := shard.entries[key]; !exists {
		evictAuthorizationRejectionEntry(shard.entries)
	}
	shard.entries[key] = entry
}

func (c *authorizationRejectionCache) clear(key string) {
	if c == nil || key == "" {
		return
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	delete(shard.entries, key)
	shard.mu.Unlock()
}

func authorizationRejectionPolicy(result string) (rejectionPolicy, bool) {
	switch result {
	case "key_rate_limited":
		return rejectionPolicy{
			decay:   10 * time.Second,
			initial: 25 * time.Millisecond,
			maximum: time.Second,
		}, true
	case "insufficient_balance", "key_spend_limit":
		return rejectionPolicy{
			decay:   30 * time.Second,
			initial: 250 * time.Millisecond,
			maximum: 2 * time.Second,
		}, true
	case "dashboard_forbidden", "invalid_key", "key_disabled", "key_expired":
		return rejectionPolicy{
			decay:   time.Minute,
			initial: time.Second,
			maximum: 10 * time.Second,
		}, true
	default:
		return rejectionPolicy{}, false
	}
}

func localAdmissionShard(value string) uint64 {
	const (
		offset = uint64(14695981039346656037)
		prime  = uint64(1099511628211)
	)
	hash := offset
	for index := 0; index < len(value); index++ {
		hash ^= uint64(value[index])
		hash *= prime
	}
	return hash % localAdmissionShards
}

func evictLocalAdmissionEntry(entries map[string]localRequestEntry) {
	if len(entries) < localAdmissionEntriesPerShard {
		return
	}
	for key := range entries {
		delete(entries, key)
		return
	}
}

func evictAuthorizationRejectionEntry(entries map[string]authorizationRejectionEntry) {
	if len(entries) < localAdmissionEntriesPerShard {
		return
	}
	for key := range entries {
		delete(entries, key)
		return
	}
}
