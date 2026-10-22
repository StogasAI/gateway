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

// Each gateway admits a credential's requests at up to 240 a second, in bursts
// of up to 360, and an organization's at up to 480 and 720. PostgreSQL admits
// an organization's requests at 120 a second, and 360 at once as they wait up
// to two seconds to start, so a gateway that receives every request of an
// organization refuses none that PostgreSQL would admit, apart from a few sent
// while PostgreSQL's refusal of an earlier one was on its way back. Two
// credentials at their limit fill their organization's, so one runaway
// credential takes at most half of it.
var (
	credentialRequestLimit   = localRequestLimit{240, 360}
	organizationRequestLimit = localRequestLimit{480, 720}
)

type LocalAdmissionDiagnostics struct {
	APIKeyCacheEntries        int    `json:"apiKeyCacheEntries"`
	APIKeyCacheHits           uint64 `json:"apiKeyCacheHits"`
	APIKeyCacheLookups        uint64 `json:"apiKeyCacheLookups"`
	AuthorizationAttempts     uint64 `json:"authorizationAttempts"`
	AuthorizationInFlight     int64  `json:"authorizationInFlight"`
	AuthorizationPeakInFlight int64  `json:"authorizationPeakInFlight"`
	// Authorizations that waited for an earlier one of their organization in
	// this gateway, statements that PostgreSQL found it busy for, and
	// authorizations that waited until their deadline. Batches are statements
	// that authorized more than one request.
	OrganizationWaits           uint64                  `json:"organizationWaits"`
	OrganizationBusy            uint64                  `json:"organizationBusy"`
	OrganizationTimeouts        uint64                  `json:"organizationTimeouts"`
	OrganizationLastTimeoutAt   *time.Time              `json:"organizationLastTimeoutAt,omitempty"`
	OrganizationBatches         uint64                  `json:"organizationBatches"`
	OrganizationBatchedRequests uint64                  `json:"organizationBatchedRequests"`
	OrganizationLargestBatch    int64                   `json:"organizationLargestBatch"`
	RejectionCacheHits          uint64                  `json:"rejectionCacheHits"`
	RejectionCacheLookups       uint64                  `json:"rejectionCacheLookups"`
	CredentialRequests          LocalRequestDiagnostics `json:"credentialRequests"`
	OrganizationRequests        LocalRequestDiagnostics `json:"organizationRequests"`
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

// admitCredential charges a verified credential's local allowance.
func (s *Service) admitCredential(credential string, now time.Time) error {
	if retryAfter := s.credentialRequests.allow(credential, now, credentialRequestLimit); retryAfter > 0 {
		return &retryAfterError{ErrRateLimit, retryAfter}
	}
	return nil
}

// admitOrganization charges the organization's local allowance for a request
// that its credential's admitted. A refusal returns the credential's token, so
// other credentials' requests cost a credential nothing.
func (s *Service) admitOrganization(credential string, organizationID string, now time.Time) error {
	if retryAfter := s.organizationRequests.allow(organizationID, now, organizationRequestLimit); retryAfter > 0 {
		s.credentialRequests.refund(credential, credentialRequestLimit)
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
		OrganizationWaits:           queues.waits.Load(),
		OrganizationBusy:            queues.busy.Load(),
		OrganizationTimeouts:        queues.timeouts.Load(),
		OrganizationLastTimeoutAt:   localAdmissionTime(queues.lastTimeoutAt.Load()),
		OrganizationBatches:         queues.batches.Load(),
		OrganizationBatchedRequests: queues.batched.Load(),
		OrganizationLargestBatch:    queues.largestBatch.Load(),
		RejectionCacheHits:          s.refusals.hits.Load(),
		RejectionCacheLookups:       s.refusals.lookups.Load(),
		CredentialRequests:          s.credentialRequests.diagnostics(credentialRequestLimit),
		OrganizationRequests:        s.organizationRequests.diagnostics(organizationRequestLimit),
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

func evictLocalAdmissionEntry(entries map[string]localRequestEntry) {
	if len(entries) < localAdmissionEntriesPerShard {
		return
	}
	for key := range entries {
		delete(entries, key)
		return
	}
}
