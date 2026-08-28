package billing

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	localAdmissionShards               = 64
	localAdmissionEntriesPerShard      = 512
	localRequestRatePerSecond          = 120
	localRequestBurst                  = 120
	localAuthorizationPoolShareDivisor = int32(4)
)

type LocalAdmissionDiagnostics struct {
	APIKeyCacheEntries                       int        `json:"apiKeyCacheEntries"`
	APIKeyCacheHits                          uint64     `json:"apiKeyCacheHits"`
	APIKeyCacheLookups                       uint64     `json:"apiKeyCacheLookups"`
	AuthorizationActiveIdentities            int64      `json:"authorizationActiveIdentities"`
	AuthorizationAttempts                    uint64     `json:"authorizationAttempts"`
	AuthorizationConcurrencyLimitPerIdentity int32      `json:"authorizationConcurrencyLimitPerIdentity"`
	AuthorizationInFlight                    int64      `json:"authorizationInFlight"`
	AuthorizationLastRejectedAt              *time.Time `json:"authorizationLastRejectedAt,omitempty"`
	AuthorizationPeakInFlight                int64      `json:"authorizationPeakInFlight"`
	AuthorizationRejected                    uint64     `json:"authorizationRejected"`
	RejectionCacheHits                       uint64     `json:"rejectionCacheHits"`
	RejectionCacheLookups                    uint64     `json:"rejectionCacheLookups"`
	RequestAttempts                          uint64     `json:"requestAttempts"`
	RequestBurst                             int        `json:"requestBurst"`
	RequestLastRejectedAt                    *time.Time `json:"requestLastRejectedAt,omitempty"`
	RequestRatePerSecond                     int        `json:"requestRatePerSecond"`
	RequestRejected                          uint64     `json:"requestRejected"`
}

type verifiedAPIKeyShard struct {
	mu      sync.Mutex
	entries map[string]APIKeyClaims
}

// verifiedAPIKeyCache saves only immutable claims from valid signed keys.
// PostgreSQL still checks every request-time permission, limit, and balance.
type verifiedAPIKeyCache struct {
	hits    atomic.Uint64
	lookups atomic.Uint64
	shards  [localAdmissionShards]verifiedAPIKeyShard
}

func (c *verifiedAPIKeyCache) get(key string) (*APIKeyClaims, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	c.lookups.Add(1)
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	claims, ok := shard.entries[key]
	shard.mu.Unlock()
	if !ok {
		return nil, false
	}
	c.hits.Add(1)
	return cloneAPIKeyClaims(claims), true
}

func (c *verifiedAPIKeyCache) put(key string, claims *APIKeyClaims) {
	if c == nil || key == "" || claims == nil {
		return
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]APIKeyClaims)
	}
	if _, exists := shard.entries[key]; !exists {
		evictVerifiedAPIKeyEntry(shard.entries)
	}
	shard.entries[key] = *cloneAPIKeyClaims(*claims)
}

func (c *verifiedAPIKeyCache) entryCount() int {
	if c == nil {
		return 0
	}
	total := 0
	for index := range c.shards {
		shard := &c.shards[index]
		shard.mu.Lock()
		total += len(shard.entries)
		shard.mu.Unlock()
	}
	return total
}

func cloneAPIKeyClaims(claims APIKeyClaims) *APIKeyClaims {
	copy := claims
	if claims.GrantID != nil {
		grantID := *claims.GrantID
		copy.GrantID = &grantID
	}
	return &copy
}

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
	attempts       atomic.Uint64
	lastRejectedAt atomic.Int64
	rejected       atomic.Uint64
	shards         [localAdmissionShards]localRequestShard
}

func (l *localRequestLimiter) allow(identity string, now time.Time) time.Duration {
	if l == nil || identity == "" {
		return time.Second
	}
	l.attempts.Add(1)
	shard := &l.shards[localAdmissionShard(identity)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]localRequestEntry)
	}

	entry, ok := shard.entries[identity]
	if !ok {
		evictLocalAdmissionEntry(shard.entries)
		shard.entries[identity] = localRequestEntry{
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
		shard.entries[identity] = entry
		return 0
	}
	shard.entries[identity] = entry
	l.rejected.Add(1)
	l.lastRejectedAt.Store(now.UTC().UnixMilli())
	return time.Duration(math.Ceil((1 - entry.tokens) / localRequestRatePerSecond * float64(time.Second)))
}

type localAuthorizationShard struct {
	mu       sync.Mutex
	inFlight map[string]int32
}

// localAuthorizationLimiter prevents one signed API credential or dashboard
// actor/session from occupying the process's entire database pool.
type localAuthorizationLimiter struct {
	limit            int32
	activeIdentities atomic.Int64
	attempts         atomic.Uint64
	inFlight         atomic.Int64
	peakInFlight     atomic.Int64
	lastRejectedAt   atomic.Int64
	rejected         atomic.Uint64
	shards           [localAdmissionShards]localAuthorizationShard
}

func newLocalAuthorizationLimiter(poolMaxConns int32) *localAuthorizationLimiter {
	return &localAuthorizationLimiter{limit: localAuthorizationLimit(poolMaxConns)}
}

func localAuthorizationLimit(poolMaxConns int32) int32 {
	if poolMaxConns <= 0 {
		return 0
	}
	return 1 + (poolMaxConns-1)/localAuthorizationPoolShareDivisor
}

func (l *localAuthorizationLimiter) acquire(identity string) (func(), bool) {
	if l == nil || identity == "" || l.limit <= 0 {
		return nil, false
	}
	l.attempts.Add(1)
	shard := &l.shards[localAdmissionShard(identity)]
	shard.mu.Lock()
	if shard.inFlight == nil {
		shard.inFlight = make(map[string]int32)
	}
	if shard.inFlight[identity] >= l.limit {
		shard.mu.Unlock()
		l.rejected.Add(1)
		l.lastRejectedAt.Store(time.Now().UTC().UnixMilli())
		return nil, false
	}
	first := shard.inFlight[identity] == 0
	shard.inFlight[identity]++
	shard.mu.Unlock()
	if first {
		l.activeIdentities.Add(1)
	}
	l.recordInFlight(l.inFlight.Add(1))

	return func() {
		shard.mu.Lock()
		last := shard.inFlight[identity] <= 1
		if last {
			delete(shard.inFlight, identity)
		} else {
			shard.inFlight[identity]--
		}
		shard.mu.Unlock()
		if last {
			l.activeIdentities.Add(-1)
		}
		l.inFlight.Add(-1)
	}, true
}

func (l *localAuthorizationLimiter) recordInFlight(value int64) {
	for {
		peak := l.peakInFlight.Load()
		if value <= peak || l.peakInFlight.CompareAndSwap(peak, value) {
			return
		}
	}
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
	hits    atomic.Uint64
	lookups atomic.Uint64
	shards  [localAdmissionShards]authorizationRejectionShard
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
	c.lookups.Add(1)
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, ok := shard.entries[key]
	if !ok || !now.Before(entry.blockedUntil) {
		return "", 0, false
	}
	c.hits.Add(1)
	return entry.result, entry.blockedUntil.Sub(now), true
}

func localAdmissionDiagnostics(
	requests *localRequestLimiter,
	authorizations *localAuthorizationLimiter,
	rejections *authorizationRejectionCache,
	apiKeys *verifiedAPIKeyCache,
) LocalAdmissionDiagnostics {
	result := LocalAdmissionDiagnostics{
		RequestBurst:         localRequestBurst,
		RequestRatePerSecond: localRequestRatePerSecond,
	}
	if requests != nil {
		result.RequestAttempts = requests.attempts.Load()
		result.RequestLastRejectedAt = localAdmissionTime(requests.lastRejectedAt.Load())
		result.RequestRejected = requests.rejected.Load()
	}
	if authorizations != nil {
		result.AuthorizationActiveIdentities = authorizations.activeIdentities.Load()
		result.AuthorizationAttempts = authorizations.attempts.Load()
		result.AuthorizationConcurrencyLimitPerIdentity = authorizations.limit
		result.AuthorizationInFlight = authorizations.inFlight.Load()
		result.AuthorizationLastRejectedAt = localAdmissionTime(authorizations.lastRejectedAt.Load())
		result.AuthorizationPeakInFlight = authorizations.peakInFlight.Load()
		result.AuthorizationRejected = authorizations.rejected.Load()
	}
	if rejections != nil {
		result.RejectionCacheHits = rejections.hits.Load()
		result.RejectionCacheLookups = rejections.lookups.Load()
	}
	if apiKeys != nil {
		result.APIKeyCacheEntries = apiKeys.entryCount()
		result.APIKeyCacheHits = apiKeys.hits.Load()
		result.APIKeyCacheLookups = apiKeys.lookups.Load()
	}
	return result
}

func localAdmissionTime(unixMilliseconds int64) *time.Time {
	if unixMilliseconds <= 0 {
		return nil
	}
	value := time.UnixMilli(unixMilliseconds).UTC()
	return &value
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
	case "dashboard_forbidden", "grant_disabled", "invalid_key", "key_disabled", "key_expired":
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

func evictVerifiedAPIKeyEntry(entries map[string]APIKeyClaims) {
	if len(entries) < localAdmissionEntriesPerShard {
		return
	}
	for key := range entries {
		delete(entries, key)
		return
	}
}
