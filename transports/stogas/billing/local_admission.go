package billing

import (
	"context"
	"errors"
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
	APIKeyCacheEntries        int    `json:"apiKeyCacheEntries"`
	APIKeyCacheHits           uint64 `json:"apiKeyCacheHits"`
	APIKeyCacheLookups        uint64 `json:"apiKeyCacheLookups"`
	AuthorizationAttempts     uint64 `json:"authorizationAttempts"`
	AuthorizationInFlight     int64  `json:"authorizationInFlight"`
	AuthorizationPeakInFlight int64  `json:"authorizationPeakInFlight"`
	// Authorizations that waited for an earlier one of their organization in
	// this gateway, those that PostgreSQL found it busy for, and those that
	// waited until their deadline.
	OrganizationWaits     uint64     `json:"organizationWaits"`
	OrganizationBusy      uint64     `json:"organizationBusy"`
	OrganizationTimeouts  uint64     `json:"organizationTimeouts"`
	RejectionCacheHits    uint64     `json:"rejectionCacheHits"`
	RejectionCacheLookups uint64     `json:"rejectionCacheLookups"`
	RequestAttempts       uint64     `json:"requestAttempts"`
	RequestBurst          int        `json:"requestBurst"`
	RequestLastRejectedAt *time.Time `json:"requestLastRejectedAt,omitempty"`
	RequestRatePerSecond  int        `json:"requestRatePerSecond"`
	RequestRejected       uint64     `json:"requestRejected"`
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

// Authorization work waits for its organization slot and in pgxpool under its
// query deadline. The request memory and organization rate gates bound
// admission before this point.
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

// organizationSlots runs one authorization at a time for each organization.
// An organization's authorizations wait for each other on its rows, so running
// more at once would only take more of the pool and of the database's shared
// connections from every other organization. The rest wait in order, holding
// nothing. PostgreSQL bounds them across gateways in the same way.
type organizationSlots struct {
	waits    atomic.Uint64
	busy     atomic.Uint64
	timeouts atomic.Uint64
	shards   [localAdmissionShards]organizationSlotShard
}

type organizationSlotShard struct {
	mu    sync.Mutex
	slots map[string]*organizationSlot
}

// An entry lasts while its holder or a waiter needs it, so authorization
// admission bounds the map.
type organizationSlot struct {
	held  chan struct{}
	users int
}

// take waits for the organization's slot until ctx ends. Release is safe to
// call more than once.
func (o *organizationSlots) take(ctx context.Context, organizationID string) (func(), error) {
	shard := &o.shards[localAdmissionShard(organizationID)]
	shard.mu.Lock()
	slot := shard.slots[organizationID]
	if slot == nil {
		if shard.slots == nil {
			shard.slots = make(map[string]*organizationSlot)
		}
		slot = &organizationSlot{held: make(chan struct{}, 1)}
		shard.slots[organizationID] = slot
	}
	slot.users++
	shard.mu.Unlock()
	leave := func() {
		shard.mu.Lock()
		if slot.users--; slot.users == 0 {
			delete(shard.slots, organizationID)
		}
		shard.mu.Unlock()
	}
	select {
	case slot.held <- struct{}{}:
	default:
		o.waits.Add(1)
		select {
		case slot.held <- struct{}{}:
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				o.timeouts.Add(1)
			}
			leave()
			return nil, ctx.Err()
		}
	}
	return sync.OnceFunc(func() {
		<-slot.held
		leave()
	}), nil
}

func localAdmissionDiagnostics(
	requests *localRequestLimiter,
	authorizations *authorizationActivity,
	organizations *organizationSlots,
	rejections *callerFailureCache,
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
	if organizations != nil {
		result.OrganizationWaits = organizations.waits.Load()
		result.OrganizationBusy = organizations.busy.Load()
		result.OrganizationTimeouts = organizations.timeouts.Load()
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
