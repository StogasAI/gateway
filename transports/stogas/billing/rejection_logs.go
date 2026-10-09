package billing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

const (
	rejectionLogWindow          = time.Second
	rejectionLogIndividualLimit = 5
	rejectionLogCapacity        = 4096
	rejectionLogPerKeyCapacity  = 32
	rejectionLogBatchSize       = 256
	rejectionLogDeliveryTimeout = requestLogAppendWaitTimeout
)

// Rejections never retain credentials, bodies, provider text, or arbitrary labels.
// A sealed batch stays immutable so an ambiguous write can safely be replayed.
type RejectionInput struct {
	PolicyVersions *PolicyVersions
	Claims         *APIKeyClaims
	RequestID      string
	RequestType    string
	Code           string
	StatusCode     int
	CreatedAt      time.Time
	NodeID         string
	GatewayVersion string
}

type rejectionLogKey struct {
	keyID, requestType, code string
	status                   int
	window                   int64
	versions                 [32]byte
}

type RejectionLogDiagnostics struct {
	PendingGroups    int        `json:"pendingGroups"`
	OldestPendingAt  *time.Time `json:"oldestPendingAt,omitempty"`
	RecordedRequests uint64     `json:"recordedRequests"`
	StoredRequests   uint64     `json:"storedRequests"`
	DroppedRequests  uint64     `json:"droppedRequests"`
	DeliveryFailures uint64     `json:"deliveryFailures"`
	LastDroppedAt    *time.Time `json:"lastDroppedAt,omitempty"`
}

type rejectionLogRequest struct {
	id, at string
}

type rejectionLogGroup struct {
	// RequestEvent counts only repeats beyond the individual allowance.
	RequestEvent
	individual []rejectionLogRequest
	queuedAt   time.Time
}

type rejectionLogBuffer struct {
	deliveryBlocked atomic.Bool
	mu              sync.Mutex
	groups          map[rejectionLogKey]*rejectionLogGroup
	perKey          map[string]int
	pending         []RequestEvent
	pendingAt       time.Time
	pendingGroups   int
	diagnostics     RejectionLogDiagnostics
	stop            chan struct{}
	done            chan struct{}
	closed          bool
}

// NewRejectionEvent gives authenticated pre-authorization failures the same
// customer-visible representation in telemetry and optional content exports.
func NewRejectionEvent(input RejectionInput) RequestEvent {
	at := input.CreatedAt.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	stamp := at.Format("2006-01-02T15:04:05.000Z")
	zero := ZeroChargeUSD
	return RequestEvent{
		SchemaVersion: RequestLogSchemaVersion,
		RequestID:     input.RequestID, CreatedAt: stamp, LastRequestAt: stamp, RequestCount: 1,
		PolicyVersions: input.PolicyVersions,
		StogasAPIKeyID: input.Claims.KeyID, StogasOrganizationID: input.Claims.OrganizationID,
		StogasUserID: input.Claims.ResponsibleID, StogasGrantID: input.Claims.GrantID,
		RequestType:      input.RequestType,
		GatewayError:     &EventError{Code: NormalizeStogasErrorCode(input.Code, input.StatusCode), Status: input.StatusCode},
		ProviderAttempts: []ProviderAttempt{},
		Usage: RequestUsage{Meters: EventMeters{}, UpstreamCostUSD: ZeroChargeUSD, BilledCostUSD: ZeroChargeUSD,
			CacheReadSavingsUSD: &zero, CacheWriteOverheadUSD: &zero},
		NodeID: input.NodeID, GatewayVersion: input.GatewayVersion,
	}
}

func (s *Service) RecordRejection(input RejectionInput) {
	if s == nil || input.Claims == nil || input.RequestID == "" || input.StatusCode < 400 || input.StatusCode > 599 {
		return
	}
	input.Code = NormalizeStogasErrorCode(input.Code, input.StatusCode)
	switch input.RequestType {
	case "chat_completion_request", "chat_completion_stream", "responses_request", "responses_stream":
	default:
		input.RequestType = "unknown"
	}
	b := &s.rejectionLogs
	b.mu.Lock()
	defer b.mu.Unlock()
	b.diagnostics.RecordedRequests++
	if b.closed {
		b.recordDropped(1)
		return
	}
	if b.groups == nil {
		b.groups = make(map[rejectionLogKey]*rejectionLogGroup)
		b.perKey = make(map[string]int)
		b.stop, b.done = make(chan struct{}), make(chan struct{})
		go s.runRejectionLogs()
	}
	at := input.CreatedAt.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var versions [32]byte
	if input.PolicyVersions != nil {
		raw, _ := json.Marshal(input.PolicyVersions)
		versions = sha256.Sum256(raw)
	}
	key := rejectionLogKey{input.Claims.KeyID, input.RequestType, input.Code, input.StatusCode, at.Truncate(rejectionLogWindow).Unix(), versions}
	stamp := at.Format("2006-01-02T15:04:05.000Z")
	group := b.groups[key]
	if group == nil {
		if len(b.groups) >= rejectionLogCapacity || b.perKey[input.Claims.KeyID] >= rejectionLogPerKeyCapacity {
			b.recordDropped(1)
			return
		}
		group = &rejectionLogGroup{queuedAt: time.Now().UTC(), RequestEvent: NewRejectionEvent(input)}
		group.RequestCount = 0
		b.groups[key] = group
		b.perKey[input.Claims.KeyID]++
	}
	if len(group.individual) < rejectionLogIndividualLimit {
		group.individual = append(group.individual, rejectionLogRequest{input.RequestID, stamp})
		return
	}
	if group.RequestCount == ^uint32(0) {
		b.recordDropped(1)
		return
	}
	if group.RequestCount == 0 {
		group.RequestID, group.CreatedAt, group.LastRequestAt = input.RequestID, stamp, stamp
	}
	group.RequestCount++
	if stamp > group.LastRequestAt {
		group.LastRequestAt = stamp
	}
	if stamp < group.CreatedAt {
		group.CreatedAt = stamp
	}
}

func (b *rejectionLogBuffer) recordDropped(count uint64) {
	b.diagnostics.DroppedRequests += count
	now := time.Now().UTC()
	b.diagnostics.LastDroppedAt = &now
}

func (b *rejectionLogBuffer) snapshot() RejectionLogDiagnostics {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := b.diagnostics
	result.PendingGroups = len(b.groups) + b.pendingGroups
	oldest := b.pendingAt
	for _, group := range b.groups {
		if oldest.IsZero() || group.queuedAt.Before(oldest) {
			oldest = group.queuedAt
		}
	}
	if !oldest.IsZero() {
		result.OldestPendingAt = &oldest
	}
	return result
}

func (b *rejectionLogBuffer) nextBatch(now time.Time, closing bool) []RequestEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pending) > 0 {
		return b.pending
	}
	for key, group := range b.groups {
		if !closing && key.window >= now.Truncate(rejectionLogWindow).Unix() {
			continue
		}
		rows := len(group.individual)
		if group.RequestCount > 0 {
			rows++
		}
		if len(b.pending)+rows > rejectionLogBatchSize {
			break
		}
		for _, request := range group.individual {
			event := group.RequestEvent
			event.RequestID, event.CreatedAt, event.LastRequestAt = request.id, request.at, request.at
			event.RequestCount = 1
			b.pending = append(b.pending, event)
		}
		if group.RequestCount > 0 {
			b.pending = append(b.pending, group.RequestEvent)
		}
		b.pendingGroups++
		if b.pendingAt.IsZero() || group.queuedAt.Before(b.pendingAt) {
			b.pendingAt = group.queuedAt
		}
		delete(b.groups, key)
		b.perKey[key.keyID]--
		if b.perKey[key.keyID] == 0 {
			delete(b.perKey, key.keyID)
		}
		if len(b.pending) == rejectionLogBatchSize {
			break
		}
	}
	return b.pending
}

func (s *Service) runRejectionLogs() {
	b := &s.rejectionLogs
	defer close(b.done)
	ticker := time.NewTicker(rejectionLogWindow)
	defer ticker.Stop()
	closing := false
	for {
		if !closing {
			select {
			case <-ticker.C:
			case <-b.stop:
				closing = true
			}
		}
		for {
			batch := b.nextBatch(time.Now(), closing)
			if len(batch) == 0 {
				b.mu.Lock()
				if len(b.groups) == 0 && len(b.pending) == 0 {
					b.deliveryBlocked.Store(false)
				}
				b.mu.Unlock()
				break
			}
			ctx, cancel := context.WithTimeout(context.Background(), rejectionLogDeliveryTimeout)
			err := s.deliverRejectionLogs(ctx, batch)
			cancel()
			b.mu.Lock()
			if err == nil {
				for _, event := range batch {
					b.diagnostics.StoredRequests += uint64(event.RequestCount)
				}
				b.pending = nil
				b.pendingAt, b.pendingGroups = time.Time{}, 0
			} else {
				b.diagnostics.DeliveryFailures++
				b.deliveryBlocked.Store(true)
			}
			b.mu.Unlock()
			if err != nil {
				break
			}
		}
		if closing {
			b.mu.Lock()
			for _, event := range b.pending {
				b.recordDropped(uint64(event.RequestCount))
			}
			for _, group := range b.groups {
				b.recordDropped(uint64(len(group.individual)) + uint64(group.RequestCount))
			}
			b.pending, b.groups, b.perKey = nil, nil, nil
			b.pendingAt, b.pendingGroups = time.Time{}, 0
			b.mu.Unlock()
			return
		}
	}
}

func (s *Service) closeRejectionLogs() {
	b := &s.rejectionLogs
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		if b.stop != nil {
			close(b.stop)
		}
	}
	done := b.done
	b.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (s *Service) deliverRejectionLogs(ctx context.Context, events []RequestEvent) error {
	return s.requestLogs.appendGatewayRequests(ctx, events)
}
