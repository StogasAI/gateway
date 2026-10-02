package billing

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	localAdmissionShards          = 64
	localAdmissionEntriesPerShard = 512
	localRequestRatePerSecond     = 120
	localRequestBurst             = 120
)

type LocalAdmissionDiagnostics struct {
	APIKeyCacheEntries        int        `json:"apiKeyCacheEntries"`
	APIKeyCacheHits           uint64     `json:"apiKeyCacheHits"`
	APIKeyCacheLookups        uint64     `json:"apiKeyCacheLookups"`
	AuthorizationAttempts     uint64     `json:"authorizationAttempts"`
	AuthorizationInFlight     int64      `json:"authorizationInFlight"`
	AuthorizationPeakInFlight int64      `json:"authorizationPeakInFlight"`
	RejectionCacheHits        uint64     `json:"rejectionCacheHits"`
	RejectionCacheLookups     uint64     `json:"rejectionCacheLookups"`
	RequestAttempts           uint64     `json:"requestAttempts"`
	RequestBurst              int        `json:"requestBurst"`
	RequestLastRejectedAt     *time.Time `json:"requestLastRejectedAt,omitempty"`
	RequestRatePerSecond      int        `json:"requestRatePerSecond"`
	RequestRejected           uint64     `json:"requestRejected"`
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
	if now.After(entry.updatedAt) {
		entry.updatedAt = now
	}
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

// Authorization work waits in pgxpool under its existing query deadline. The
// request memory and organization rate gates bound admission before this point.
type authorizationActivity struct {
	attempts     atomic.Uint64
	inFlight     atomic.Int64
	peakInFlight atomic.Int64
}

func (l *authorizationActivity) start() func() {
	l.attempts.Add(1)
	l.recordInFlight(l.inFlight.Add(1))
	return sync.OnceFunc(func() { l.inFlight.Add(-1) })
}

func (l *authorizationActivity) recordInFlight(value int64) {
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

func (c *authorizationRejectionCache) get(
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

func localAdmissionDiagnostics(
	requests *localRequestLimiter,
	authorizations *authorizationActivity,
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
		result.AuthorizationAttempts = authorizations.attempts.Load()
		result.AuthorizationInFlight = authorizations.inFlight.Load()
		result.AuthorizationPeakInFlight = authorizations.peakInFlight.Load()
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

func (c *authorizationRejectionCache) record(key string, now time.Time) {
	if c == nil || key == "" {
		return
	}
	shard := &c.shards[localAdmissionShard(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]authorizationRejectionEntry)
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
		evictAuthorizationRejectionEntry(shard.entries)
	}
	shard.entries[key] = entry
}

// A successful request ends an earlier failure streak. An older request
// completing late must not erase failures recorded since that request started.
func (c *authorizationRejectionCache) succeeded(key string, started time.Time) {
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
