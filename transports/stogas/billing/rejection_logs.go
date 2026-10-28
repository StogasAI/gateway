package billing

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"
)

const (
	// Groups cover UTC minutes, the dashboard's smallest chart interval, so
	// chart totals stay exact while a repeating rejection adds at most six
	// rows a minute on each gateway.
	rejectionLogWindow = time.Minute
	// Individual rows and the counts of ended windows leave on the next tick.
	rejectionLogInterval        = time.Second
	rejectionLogIndividualLimit = 5
	rejectionLogCapacity        = 4096
	rejectionLogPerKeyCapacity  = 32
	// One organization may hold a sixteenth of the groups, and only its first
	// rejectionLogPerKeyCapacity groups send individual rows; the rest send
	// their count alone. So one organization's rejections add at most 416 rows
	// a minute on each gateway instead of 24,576, and cannot fill the buffer
	// that every organization's rejections share.
	rejectionLogPerOrganizationCapacity = 256
	rejectionLogBatchSize               = settlementMaxRejections
)

// Rejections never retain credentials, bodies, provider text, or arbitrary labels.
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
	Transport      string
}

type rejectionLogKey struct {
	keyID, requestType, code, transport string
	status                              int
	window                              int64
	versions                            [32]byte
}

type RejectionLogDiagnostics struct {
	PendingGroups    int        `json:"pendingGroups"`
	OldestPendingAt  *time.Time `json:"oldestPendingAt,omitempty"`
	RecordedRequests uint64     `json:"recordedRequests"`
	StoredRequests   uint64     `json:"storedRequests"`
	DroppedRequests  uint64     `json:"droppedRequests"`
	LastDroppedAt    *time.Time `json:"lastDroppedAt,omitempty"`
}

type rejectionLogRequest struct {
	id, at string
}

type rejectionLogGroup struct {
	// RequestEvent counts only repeats beyond the individual allowance.
	RequestEvent
	// The export of the first repeat, whose request ID the count keeps. It
	// leaves with the count.
	export RejectionExport
	// Individual rows not yet handed to settlement, and how many the window
	// has recorded. They leave at once; only the count waits for the window
	// to end.
	individual []rejectionLogRequest
	recorded   int
	// When the oldest row in individual arrived.
	queuedAt time.Time
}

type rejectionLogBuffer struct {
	mu              sync.Mutex
	groups          map[rejectionLogKey]*rejectionLogGroup
	perKey          map[string]int
	perOrganization map[string]int
	// The batch being settled.
	pendingAt     time.Time
	pendingGroups int
	diagnostics   RejectionLogDiagnostics
	stop          chan struct{}
	done          chan struct{}
	closed        bool
}

// NewRejectionEvent gives authenticated pre-authorization failures the same
// customer-visible representation in telemetry and optional content exports.
// Rejections share records, so none keeps a request's session ID or metadata.
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
		APIKeyID:       input.Claims.KeyID, OrganizationID: input.Claims.OrganizationID,
		MemberID: input.Claims.ResponsibleID, GrantID: input.Claims.GrantID,
		RequestType: input.RequestType, Metadata: map[string]string{}, Transport: input.Transport,
		GatewayError:     &EventError{Code: NormalizeStogasErrorCode(input.Code, input.StatusCode), Status: input.StatusCode},
		ProviderAttempts: []ProviderAttempt{},
		Usage: RequestUsage{Meters: EventMeters{}, UpstreamCostUSD: ZeroChargeUSD, BilledCostUSD: ZeroChargeUSD,
			TaxUSD: ZeroChargeUSD, CacheReadSavingsUSD: &zero, CacheWriteOverheadUSD: &zero},
		NodeID: input.NodeID, GatewayVersion: input.GatewayVersion,
	}
}

// RejectionExport is a rejected request's export. It leaves with the row that
// holds the rejection, so a caller cannot make the gateway send more records
// than the request log shows. Finish or Discard runs once, outside the
// buffer's lock.
type RejectionExport interface {
	Finish(row RequestEvent)
	Discard()
}

type countExport struct {
	export RejectionExport
	row    RequestEvent
}

// RecordRejection reports whether the rejection keeps a row of its own, with
// its request ID. Later ones in its group only add to the group's count, and
// a full buffer drops them. An export leaves at once with a row of its own.
// The first repeat's leaves with the count when the minute ends; the other
// repeats' are discarded, as are dropped rejections'.
func (s *Service) RecordRejection(input RejectionInput, export RejectionExport) bool {
	kept, row := s.recordRejection(input, &export)
	if export != nil {
		if row != nil {
			export.Finish(*row)
		} else {
			export.Discard()
		}
	}
	return kept
}

// recordRejection returns the rejection's own row when it keeps one and has
// an export, and clears the export when its group holds it for the count.
func (s *Service) recordRejection(input RejectionInput, export *RejectionExport) (bool, *RequestEvent) {
	if s == nil || input.Claims == nil || input.RequestID == "" || input.StatusCode < 400 || input.StatusCode > 599 {
		return false, nil
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
		return false, nil
	}
	if b.groups == nil {
		b.groups = make(map[rejectionLogKey]*rejectionLogGroup)
		b.perKey, b.perOrganization = make(map[string]int), make(map[string]int)
		b.stop, b.done = make(chan struct{}), make(chan struct{})
		go s.runRejectionLogs()
	}
	now := time.Now().UTC()
	at := input.CreatedAt.UTC()
	if at.IsZero() {
		at = now
	}
	var versions [32]byte
	if input.PolicyVersions != nil {
		raw, _ := json.Marshal(input.PolicyVersions)
		versions = sha256.Sum256(raw)
	}
	key := rejectionLogKey{input.Claims.KeyID, input.RequestType, input.Code, input.Transport, input.StatusCode, at.Truncate(rejectionLogWindow).Unix(), versions}
	stamp := at.Format("2006-01-02T15:04:05.000Z")
	group := b.groups[key]
	if group == nil {
		organization := b.perOrganization[input.Claims.OrganizationID]
		if len(b.groups) >= rejectionLogCapacity || b.perKey[input.Claims.KeyID] >= rejectionLogPerKeyCapacity ||
			organization >= rejectionLogPerOrganizationCapacity {
			b.recordDropped(1)
			return false, nil
		}
		group = &rejectionLogGroup{RequestEvent: NewRejectionEvent(input)}
		group.RequestCount = 0
		if organization >= rejectionLogPerKeyCapacity {
			group.recorded = rejectionLogIndividualLimit
		}
		b.groups[key] = group
		b.perKey[input.Claims.KeyID]++
		b.perOrganization[input.Claims.OrganizationID]++
	}
	if group.recorded < rejectionLogIndividualLimit {
		group.recorded++
		if len(group.individual) == 0 {
			group.queuedAt = now
		}
		group.individual = append(group.individual, rejectionLogRequest{input.RequestID, stamp})
		if *export == nil {
			return true, nil
		}
		// The row that nextBatch sends.
		row := group.RequestEvent
		row.RequestID, row.CreatedAt, row.LastRequestAt, row.RequestCount = input.RequestID, stamp, stamp, 1
		return true, &row
	}
	if group.RequestCount == ^uint32(0) {
		b.recordDropped(1)
		return false, nil
	}
	if group.RequestCount == 0 {
		group.RequestID, group.CreatedAt, group.LastRequestAt = input.RequestID, stamp, stamp
		group.export, *export = *export, nil
	}
	group.RequestCount++
	if stamp > group.LastRequestAt {
		group.LastRequestAt = stamp
	}
	if stamp < group.CreatedAt {
		group.CreatedAt = stamp
	}
	return false, nil
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
	now := time.Now()
	oldest := b.pendingAt
	for key, group := range b.groups {
		if at := group.readyAt(key, now); !at.IsZero() && (oldest.IsZero() || at.Before(oldest)) {
			oldest = at
		}
	}
	if !oldest.IsZero() {
		result.OldestPendingAt = &oldest
	}
	return result
}

// readyAt reports when the group's oldest row that waits for settlement could
// first be sent, or zero when none waits. A count waits for its window to end.
// A group opened after its window ended holds individual rows until it leaves,
// so its age follows their arrival.
func (g *rejectionLogGroup) readyAt(key rejectionLogKey, now time.Time) time.Time {
	if len(g.individual) > 0 {
		return g.queuedAt
	}
	if ended := time.Unix(key.window, 0).Add(rejectionLogWindow); g.RequestCount > 0 && !ended.After(now) {
		return ended
	}
	return time.Time{}
}

// nextBatch returns the rows to settle and the exports of its counts.
func (b *rejectionLogBuffer) nextBatch(now time.Time, closing bool) ([]RequestEvent, []countExport) {
	b.mu.Lock()
	defer b.mu.Unlock()
	current := now.Truncate(rejectionLogWindow).Unix()
	var batch []RequestEvent
	var exports []countExport
	for key, group := range b.groups {
		ended := closing || key.window < current
		rows := len(group.individual)
		if ended && group.RequestCount > 0 {
			rows++
		}
		if rows > 0 && len(batch)+rows > rejectionLogBatchSize {
			break
		}
		if at := group.readyAt(key, now); !at.IsZero() && (b.pendingAt.IsZero() || at.Before(b.pendingAt)) {
			b.pendingAt = at
		}
		for _, request := range group.individual {
			event := group.RequestEvent
			event.RequestID, event.CreatedAt, event.LastRequestAt = request.id, request.at, request.at
			event.RequestCount = 1
			batch = append(batch, event)
		}
		group.individual = nil
		if !ended {
			continue
		}
		if group.RequestCount > 0 {
			batch = append(batch, group.RequestEvent)
			if group.export != nil {
				exports = append(exports, countExport{group.export, group.RequestEvent})
			}
		}
		if rows > 0 {
			b.pendingGroups++
		}
		delete(b.groups, key)
		releaseGroup(b.perKey, key.keyID)
		releaseGroup(b.perOrganization, group.OrganizationID)
		if len(batch) == rejectionLogBatchSize {
			break
		}
	}
	return batch, exports
}

func releaseGroup(counts map[string]int, id string) {
	if counts[id]--; counts[id] == 0 {
		delete(counts, id)
	}
}

func (s *Service) runRejectionLogs() {
	b := &s.rejectionLogs
	defer close(b.done)
	ticker := time.NewTicker(rejectionLogInterval)
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
			batch, exports := b.nextBatch(time.Now(), closing)
			if len(batch) == 0 {
				break
			}
			// Exports follow the rows that settlement receives, as a row of
			// its own leaves with its request.
			for _, count := range exports {
				count.export.Finish(count.row)
			}
			stored := s.settleRejections(batch)
			b.mu.Lock()
			for i, event := range batch {
				if stored[i] {
					b.diagnostics.StoredRequests += uint64(event.RequestCount)
				} else {
					b.recordDropped(uint64(event.RequestCount))
				}
			}
			b.pendingAt, b.pendingGroups = time.Time{}, 0
			b.mu.Unlock()
		}
		if closing {
			return
		}
	}
}

// CloseRejectionLogs refuses new rejections and sends the exports of the
// counts, which can no longer change, so that they leave before the exporter
// closes. DrainFinalizations stores the rows.
func (s *Service) CloseRejectionLogs() {
	if s != nil {
		s.stopRejectionLogs()
	}
}

// stopRejectionLogs refuses new rejections, sends the counts' exports, and
// returns a channel that closes once every buffered rejection is settled, or
// nil when none were recorded.
func (s *Service) stopRejectionLogs() <-chan struct{} {
	b := &s.rejectionLogs
	var exports []countExport
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		for _, group := range b.groups {
			if group.export != nil {
				exports = append(exports, countExport{group.export, group.RequestEvent})
				group.export = nil
			}
		}
		if b.stop != nil {
			close(b.stop)
		}
	}
	done := b.done
	b.mu.Unlock()
	for _, count := range exports {
		count.export.Finish(count.row)
	}
	return done
}
