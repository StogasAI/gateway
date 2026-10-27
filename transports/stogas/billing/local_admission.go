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
)

// localRequestLimit is a token bucket that refills ratePerSecond and admits
// burst requests at once when full.
type localRequestLimit struct{ ratePerSecond, burst float64 }

// PostgreSQL admits an organization's requests at its platform rate R, 120 a
// second unless the organization has a rate of its own, and 3R at once as they
// wait up to two seconds to start. Each gateway admits a credential's requests
// at up to 2R a second, in bursts of up to 3R, and an organization's at up to
// 4R and 6R, so a gateway that receives every request of an organization
// refuses none that PostgreSQL would admit, apart from a few sent while
// PostgreSQL's refusal of an earlier one was on its way back. Two credentials
// at their limit fill their organization's, so one runaway credential takes at
// most half of it.
const defaultPlatformRequestsPerSecond = 120

func credentialRequestLimit(rate float64) localRequestLimit {
	return localRequestLimit{2 * rate, 3 * rate}
}

func organizationRequestLimit(rate float64) localRequestLimit {
	return localRequestLimit{4 * rate, 6 * rate}
}

// organizationRates holds the platform rate of each organization whose latest
// authorization on this gateway reported one above the default, so its local
// limits rise with it. Every other organization keeps the default's limits: a
// lower rate needs no lower local limits, because PostgreSQL refuses requests
// above it before it locks or writes anything, as it does for any flood.
type organizationRates struct {
	shards [localAdmissionShards]struct {
		mu      sync.Mutex
		entries map[string]float64
	}
}

func (r *organizationRates) rate(organizationID string) float64 {
	if organizationID == "" {
		return defaultPlatformRequestsPerSecond
	}
	shard := &r.shards[localAdmissionShard(organizationID)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if rate, ok := shard.entries[organizationID]; ok {
		return rate
	}
	return defaultPlatformRequestsPerSecond
}

// learn records the rate an authorization reported. Results that do not read
// the rate report none.
func (r *organizationRates) learn(organizationID string, rate *int32) {
	if organizationID == "" || rate == nil || *rate < 1 {
		return
	}
	shard := &r.shards[localAdmissionShard(organizationID)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if *rate <= defaultPlatformRequestsPerSecond {
		delete(shard.entries, organizationID)
		return
	}
	if shard.entries == nil {
		shard.entries = make(map[string]float64)
	}
	if _, ok := shard.entries[organizationID]; !ok {
		evictLocalAdmissionEntry(shard.entries)
	}
	shard.entries[organizationID] = float64(*rate)
}

func (r *organizationRates) count() int {
	total := 0
	for index := range r.shards {
		shard := &r.shards[index]
		shard.mu.Lock()
		total += len(shard.entries)
		shard.mu.Unlock()
	}
	return total
}

type LocalAdmissionDiagnostics struct {
	APIKeyCacheEntries        int    `json:"apiKeyCacheEntries"`
	APIKeyCacheHits           uint64 `json:"apiKeyCacheHits"`
	APIKeyCacheLookups        uint64 `json:"apiKeyCacheLookups"`
	AuthorizationAttempts     uint64 `json:"authorizationAttempts"`
	AuthorizationInFlight     int64  `json:"authorizationInFlight"`
	AuthorizationPeakInFlight int64  `json:"authorizationPeakInFlight"`
	// Authorization statements that failed, from a connection, PostgreSQL or
	// the statement itself, and when the last one failed. FailingSince is when
	// the first failed after PostgreSQL last answered one, and stays empty
	// while the latest was answered.
	AuthorizationFailures     uint64     `json:"authorizationFailures"`
	AuthorizationLastFailedAt *time.Time `json:"authorizationLastFailedAt,omitempty"`
	AuthorizationFailingSince *time.Time `json:"authorizationFailingSince,omitempty"`
	// Authorizations that waited for an earlier one of their organization in
	// this gateway, statements that PostgreSQL found it busy for, and
	// authorizations that waited until their deadline. Batches are statements
	// that authorized more than one request.
	OrganizationWaits           uint64     `json:"organizationWaits"`
	OrganizationBusy            uint64     `json:"organizationBusy"`
	OrganizationTimeouts        uint64     `json:"organizationTimeouts"`
	OrganizationLastTimeoutAt   *time.Time `json:"organizationLastTimeoutAt,omitempty"`
	OrganizationBatches         uint64     `json:"organizationBatches"`
	OrganizationBatchedRequests uint64     `json:"organizationBatchedRequests"`
	OrganizationLargestBatch    int64      `json:"organizationLargestBatch"`
	RejectionCacheHits          uint64     `json:"rejectionCacheHits"`
	RejectionCacheLookups       uint64     `json:"rejectionCacheLookups"`
	// The limits of organizations with the default platform rate, and how many
	// organizations this gateway knows a higher rate for.
	CredentialRequests   LocalRequestDiagnostics `json:"credentialRequests"`
	OrganizationRequests LocalRequestDiagnostics `json:"organizationRequests"`
	OwnRateOrganizations int                     `json:"ownRateOrganizations"`
}

type LocalRequestDiagnostics struct {
	Attempts       uint64     `json:"attempts"`
	Burst          int        `json:"burst"`
	LastRejectedAt *time.Time `json:"lastRejectedAt,omitempty"`
	RatePerSecond  int        `json:"ratePerSecond"`
	Rejected       uint64     `json:"rejected"`
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

func (l *localRequestLimiter) allow(identity string, now time.Time, limit localRequestLimit) time.Duration {
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
			tokens:    limit.burst - 1,
			updatedAt: now,
		}
		return 0
	}

	elapsed := now.Sub(entry.updatedAt).Seconds()
	if elapsed > 0 {
		entry.tokens = math.Min(limit.burst, entry.tokens+elapsed*limit.ratePerSecond)
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
	return time.Duration(math.Ceil((1 - entry.tokens) / limit.ratePerSecond * float64(time.Second)))
}

// refund returns the token of a request that allow admitted.
func (l *localRequestLimiter) refund(identity string, limit localRequestLimit) {
	shard := &l.shards[localAdmissionShard(identity)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if entry, ok := shard.entries[identity]; ok {
		entry.tokens = math.Min(limit.burst, entry.tokens+1)
		shard.entries[identity] = entry
	}
}

func (l *localRequestLimiter) diagnostics(limit localRequestLimit) LocalRequestDiagnostics {
	result := LocalRequestDiagnostics{Burst: int(limit.burst), RatePerSecond: int(limit.ratePerSecond)}
	if l != nil {
		result.Attempts = l.attempts.Load()
		result.LastRejectedAt = localAdmissionTime(l.lastRejectedAt.Load())
		result.Rejected = l.rejected.Load()
	}
	return result
}

// admitCredential charges a verified credential's local allowance. Its
// organization sets the limit; a credential whose organization is not known
// yet gets the default's.
func (s *Service) admitCredential(credential string, organizationID string, now time.Time) error {
	limit := credentialRequestLimit(s.organizationRates.rate(organizationID))
	if retryAfter := s.credentialRequests.allow(credential, now, limit); retryAfter > 0 {
		return &retryAfterError{ErrRateLimit, retryAfter}
	}
	return nil
}

// admitOrganization charges the organization's local allowance for a request
// that its credential's admitted. A refusal returns the credential's token, so
// other credentials' requests cost a credential nothing.
func (s *Service) admitOrganization(credential string, organizationID string, now time.Time) error {
	rate := s.organizationRates.rate(organizationID)
	if retryAfter := s.organizationRequests.allow(organizationID, now, organizationRequestLimit(rate)); retryAfter > 0 {
		s.credentialRequests.refund(credential, credentialRequestLimit(rate))
		return &retryAfterError{ErrRateLimit, retryAfter}
	}
	return nil
}

// Authorization work waits in its organization's queue under its deadline.
// The local allowances bound admission before this point.
type authorizationActivity struct {
	attempts     atomic.Uint64
	inFlight     atomic.Int64
	peakInFlight atomic.Int64
	failures     atomic.Uint64
	// Unix milliseconds, zero when unset.
	lastFailedAt, failingSince atomic.Int64
}

// answered records a statement that PostgreSQL answered, whatever its results.
func (l *authorizationActivity) answered() {
	l.failingSince.Store(0)
}

// failed records a statement that PostgreSQL did not answer. A batch that one
// request's error rolled back runs again one by one and is not a failure.
func (l *authorizationActivity) failed() {
	now := time.Now().UTC().UnixMilli()
	l.failures.Add(1)
	l.lastFailedAt.Store(now)
	l.failingSince.CompareAndSwap(0, now)
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

func (s *Service) localAdmissionDiagnostics() LocalAdmissionDiagnostics {
	queues := &s.organizationQueues
	return LocalAdmissionDiagnostics{
		APIKeyCacheEntries:          s.apiKeys.entryCount(),
		APIKeyCacheHits:             s.apiKeys.hits.Load(),
		APIKeyCacheLookups:          s.apiKeys.lookups.Load(),
		AuthorizationAttempts:       s.authorizations.attempts.Load(),
		AuthorizationInFlight:       s.authorizations.inFlight.Load(),
		AuthorizationPeakInFlight:   s.authorizations.peakInFlight.Load(),
		AuthorizationFailures:       s.authorizations.failures.Load(),
		AuthorizationLastFailedAt:   localAdmissionTime(s.authorizations.lastFailedAt.Load()),
		AuthorizationFailingSince:   localAdmissionTime(s.authorizations.failingSince.Load()),
		OrganizationWaits:           queues.waits.Load(),
		OrganizationBusy:            queues.busy.Load(),
		OrganizationTimeouts:        queues.timeouts.Load(),
		OrganizationLastTimeoutAt:   localAdmissionTime(queues.lastTimeoutAt.Load()),
		OrganizationBatches:         queues.batches.Load(),
		OrganizationBatchedRequests: queues.batched.Load(),
		OrganizationLargestBatch:    queues.largestBatch.Load(),
		RejectionCacheHits:          s.refusals.hits.Load(),
		RejectionCacheLookups:       s.refusals.lookups.Load(),
		CredentialRequests:          s.credentialRequests.diagnostics(credentialRequestLimit(defaultPlatformRequestsPerSecond)),
		OrganizationRequests:        s.organizationRequests.diagnostics(organizationRequestLimit(defaultPlatformRequestsPerSecond)),
		OwnRateOrganizations:        s.organizationRates.count(),
	}
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

func evictLocalAdmissionEntry[V any](entries map[string]V) {
	if len(entries) < localAdmissionEntriesPerShard {
		return
	}
	for key := range entries {
		delete(entries, key)
		return
	}
}
