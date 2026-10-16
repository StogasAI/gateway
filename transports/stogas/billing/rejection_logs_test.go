package billing

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func rejectionFixture() RejectionInput {
	return RejectionInput{
		Claims:    &APIKeyClaims{KeyID: uuid.Must(uuid.NewV7()).String(), OrganizationID: uuid.Must(uuid.NewV7()).String(), ResponsibleID: uuid.Must(uuid.NewV7()).String()},
		RequestID: uuid.Must(uuid.NewV7()).String(), RequestType: "chat_completion_request",
		Code: "insufficient_balance", StatusCode: 402, CreatedAt: time.Now().UTC().Truncate(time.Second), GatewayVersion: "dev",
	}
}

// rejectionRows returns every rejection the database received, in order.
func rejectionRows(db *fakeSettlementDatabase) []json.RawMessage {
	var rows []json.RawMessage
	for _, call := range db.recorded() {
		rows = append(rows, call.rejections...)
	}
	return rows
}

func TestRejectionLogsCountConcurrentRequestsAndKeepKeysReasonsAndWindowsSeparate(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	input := rejectionFixture()
	// A future minute stays open until the drain, whenever the sender ticks.
	input.CreatedAt = input.CreatedAt.Add(time.Hour).Truncate(rejectionLogWindow)
	var callers sync.WaitGroup
	for i := range 100 {
		callers.Go(func() {
			copy := input
			copy.RequestID = uuid.Must(uuid.NewV7()).String()
			copy.CreatedAt = input.CreatedAt.Add(time.Duration(i) * time.Millisecond)
			service.RecordRejection(copy)
		})
	}
	callers.Wait()
	other := input
	other.Code, other.StatusCode = "key_rate_limited", 429
	service.RecordRejection(other)
	other = rejectionFixture()
	service.RecordRejection(other)
	other = input
	other.CreatedAt = input.CreatedAt.Add(rejectionLogWindow)
	other.RequestID = uuid.Must(uuid.NewV7()).String()
	service.RecordRejection(other)
	drainSettlements(t, service)
	rows := rejectionRows(db)
	if len(rows) != rejectionLogIndividualLimit+4 {
		t.Fatalf("stored %d rows, want first individual rejections, repeats, and three other groups", len(rows))
	}
	var total uint32
	for _, raw := range rows {
		var row RequestEvent
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Fatal(err)
		}
		total += row.RequestCount
		if row.RequestCount == 100-rejectionLogIndividualLimit {
			if row.CreatedAt < input.CreatedAt.Format("2006-01-02T15:04:05.000Z") || row.LastRequestAt > input.CreatedAt.Add(99*time.Millisecond).Format("2006-01-02T15:04:05.000Z") || row.CreatedAt > row.LastRequestAt {
				t.Fatalf("incorrect first/last timestamps: %s %s", row.CreatedAt, row.LastRequestAt)
			}
		}
		if len(row.ProviderAttempts) != 0 || row.Usage.BilledCostUSD != "0" {
			t.Fatalf("rejection became billable: %+v", row)
		}
	}
	if total != 103 {
		t.Fatalf("count = %d, want 103", total)
	}
	if got := service.Diagnostics().RejectionLogs; got.RecordedRequests != 103 || got.StoredRequests != 103 || got.PendingGroups != 0 || got.DroppedRequests != 0 || got.OldestPendingAt != nil {
		t.Fatalf("diagnostics: %+v", got)
	}
}

func TestRejectionLogsKeepFirstRequestsIndividualAndBoundDeliveryBatches(t *testing.T) {
	type savedRow struct {
		ID    string `json:"request_id"`
		Count uint32 `json:"request_count"`
		First string `json:"created_at"`
		Last  string `json:"last_request_at"`
	}
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	want := map[string]savedRow{}
	var total uint64
	// Enough distinct keys to cross the batch limit, including both sides of
	// the grouping threshold and a large burst. Every saved ID is predictable.
	counts := []int{1, rejectionLogIndividualLimit, rejectionLogIndividualLimit + 1, rejectionLogIndividualLimit + 2, 100}
	for range rejectionLogBatchSize / rejectionLogIndividualLimit {
		counts = append(counts, rejectionLogIndividualLimit)
	}
	for _, count := range counts {
		input := rejectionFixture()
		input.CreatedAt = input.CreatedAt.Add(time.Hour)
		var repeat savedRow
		for i := range count {
			copy := input
			copy.RequestID = uuid.Must(uuid.NewV7()).String()
			copy.CreatedAt = input.CreatedAt.Add(time.Duration(i) * time.Millisecond)
			stamp := copy.CreatedAt.Format("2006-01-02T15:04:05.000Z")
			if i < rejectionLogIndividualLimit {
				want[copy.RequestID] = savedRow{copy.RequestID, 1, stamp, stamp}
			} else {
				if repeat.Count == 0 {
					repeat.ID, repeat.First = copy.RequestID, stamp
				}
				repeat.Count++
				repeat.Last = stamp
			}
			service.RecordRejection(copy)
			total++
		}
		if repeat.Count > 0 {
			want[repeat.ID] = repeat
		}
	}
	before := service.Diagnostics().RejectionLogs
	if before.PendingGroups != len(counts) || before.OldestPendingAt != nil && before.OldestPendingAt.After(time.Now()) {
		t.Fatalf("pending age must use queue arrival, not the request timestamp: %+v", before)
	}
	drainSettlements(t, service)
	for _, call := range db.recorded() {
		if len(call.rejections) > rejectionLogBatchSize {
			t.Fatalf("settlement call exceeds its rejection limit: %d", len(call.rejections))
		}
	}
	rows := rejectionRows(db)
	if len(rows) != len(want) {
		t.Fatalf("stored %d rows, want %d", len(rows), len(want))
	}
	for _, raw := range rows {
		var row savedRow
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Fatal(err)
		}
		if expected, ok := want[row.ID]; !ok || expected != row {
			t.Fatalf("unexpected row: %+v, want %+v", row, expected)
		}
		delete(want, row.ID)
	}
	if got := service.Diagnostics().RejectionLogs; got.StoredRequests != total || got.RecordedRequests != total || got.DroppedRequests != 0 || got.OldestPendingAt != nil {
		t.Fatalf("delivery accounting: %+v", got)
	}
}

func TestRejectionLogsNeverAcceptSuccessfulRequests(t *testing.T) {
	service := &Service{}
	input := rejectionFixture()
	for status := 200; status < 400; status++ {
		input.StatusCode = status
		service.RecordRejection(input)
	}
	service.Close()
	if got := service.Diagnostics().RejectionLogs; got.RecordedRequests != 0 || got.PendingGroups != 0 {
		t.Fatalf("successful requests entered rejection grouping: %+v", got)
	}
}

// A batch whose connection broke may have committed. It runs again unchanged:
// analytics keeps one row per request ID, so a repeat stores nothing new.
func TestRejectionLogsFlushWhenTrafficStopsAndRetryTheSameBatchUntilStored(t *testing.T) {
	var calls atomic.Int32
	failing := make(chan struct{})
	recovered := make(chan struct{})
	db := newFakeSettlementDatabase(t, func(call settlementCall) settlementReply {
		switch calls.Add(1) {
		case 1:
			return settlementReply{drop: true}
		case 2:
			close(failing)
			<-recovered
		}
		return settleAll(call)
	})
	service := db.service
	service.RecordRejection(rejectionFixture())
	select {
	case <-failing:
	case <-time.After(5 * time.Second):
		t.Fatal("quiet rejection was not flushed and retried")
	}
	if got := service.Diagnostics().RejectionLogs; got.OldestPendingAt == nil || got.PendingGroups != 1 {
		t.Fatalf("failed delivery lost its pending age: %+v", got)
	}
	if !service.FinalizationReady() {
		t.Fatal("failed rejection delivery closed inference admission")
	}
	close(recovered)
	drainSettlements(t, service)
	recorded := db.recorded()
	if len(recorded) != 2 || recorded[0].arrays != recorded[1].arrays {
		t.Fatalf("retry changed the batch: %+v", recorded)
	}
	if got := service.Diagnostics().RejectionLogs; got.StoredRequests != 1 || got.DroppedRequests != 0 || got.PendingGroups != 0 || got.OldestPendingAt != nil {
		t.Fatalf("recovery did not store the retained rejection: %+v", got)
	}
}

func TestRejectionLogsBoundMemoryAndDiscardUntrustedLabels(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	input := rejectionFixture()
	input.CreatedAt = time.Now().Add(time.Hour).Truncate(rejectionLogWindow)
	input.Code, input.RequestType = "secret-provider-message", "secret-client-path"
	service.RecordRejection(input)
	service.rejectionLogs.mu.Lock()
	for _, row := range service.rejectionLogs.groups {
		encoded, _ := json.Marshal(row)
		if strings.Contains(string(encoded), "secret") || row.RequestType != "unknown" || row.GatewayError == nil || row.GatewayError.Code != "insufficient_balance" {
			t.Errorf("untrusted labels escaped: %s", encoded)
		}
	}
	service.rejectionLogs.mu.Unlock()
	for i := 1; i <= rejectionLogPerKeyCapacity; i++ {
		copy := input
		copy.CreatedAt = input.CreatedAt.Add(time.Duration(i) * rejectionLogWindow)
		service.RecordRejection(copy)
	}
	if got := service.Diagnostics().RejectionLogs; got.PendingGroups != rejectionLogPerKeyCapacity || got.DroppedRequests != 1 {
		t.Fatalf("per-key cap: %+v", got)
	}
	for i := rejectionLogPerKeyCapacity; i <= rejectionLogCapacity; i++ {
		copy := input
		claims := *input.Claims
		claims.KeyID, claims.OrganizationID = uuid.Must(uuid.NewV7()).String(), uuid.Must(uuid.NewV7()).String()
		copy.Claims = &claims
		service.RecordRejection(copy)
	}
	if got := service.Diagnostics().RejectionLogs; got.PendingGroups != rejectionLogCapacity || got.DroppedRequests != 2 {
		t.Fatalf("process cap: %+v", got)
	}
	drainSettlements(t, service)
	service.RecordRejection(input)
	if got := service.Diagnostics().RejectionLogs; got.PendingGroups != 0 || got.DroppedRequests != 3 || got.StoredRequests != got.RecordedRequests-3 {
		t.Fatalf("shutdown loss accounting: %+v", got)
	}
}

// An organization with many keys can neither fill the buffer that every
// organization shares nor add individual rows for every key.
func TestRejectionLogsBoundEachOrganization(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	input := rejectionFixture()
	input.CreatedAt = time.Now().Add(time.Hour).Truncate(rejectionLogWindow)
	for range rejectionLogPerOrganizationCapacity + 1 {
		copy := input
		claims := *input.Claims
		claims.KeyID = uuid.Must(uuid.NewV7()).String()
		copy.Claims = &claims
		for range 2 {
			copy.RequestID = uuid.Must(uuid.NewV7()).String()
			service.RecordRejection(copy)
		}
	}
	other := rejectionFixture()
	other.CreatedAt = input.CreatedAt
	service.RecordRejection(other)
	if got := service.Diagnostics().RejectionLogs; got.PendingGroups != rejectionLogPerOrganizationCapacity+1 || got.DroppedRequests != 2 {
		t.Fatalf("organization cap: %+v", got)
	}
	drainSettlements(t, service)
	var individual, counted int
	for _, raw := range rejectionRows(db) {
		var row struct {
			Organization string `json:"stogas_organization_id"`
			Count        uint32 `json:"request_count"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Fatal(err)
		}
		switch {
		case row.Organization == other.Claims.OrganizationID:
		case row.Count == 1:
			individual++
		case row.Count == 2:
			counted++
		default:
			t.Fatalf("unexpected row count %d", row.Count)
		}
	}
	if individual != 2*rejectionLogPerKeyCapacity || counted != rejectionLogPerOrganizationCapacity-rejectionLogPerKeyCapacity {
		t.Fatalf("got %d individual rows and %d count rows", individual, counted)
	}
}

func TestRejectionGroupsKeepDifferentPolicyVersionsSeparate(t *testing.T) {
	s := newFakeSettlementDatabase(t, settleAll).service
	// A future window stays open until the end of the test.
	at := time.Now().Add(time.Hour)
	for i := 1; i <= 2; i++ {
		s.RecordRejection(RejectionInput{Claims: &APIKeyClaims{KeyID: "key"}, RequestID: fmt.Sprint(i), Code: "policy_denied", StatusCode: 403, CreatedAt: at, PolicyVersions: &PolicyVersions{{Scope: "organization", ID: "org", Revision: i}, {Scope: "key", ID: "key", Revision: i}}})
	}
	s.rejectionLogs.mu.Lock()
	defer s.rejectionLogs.mu.Unlock()
	if len(s.rejectionLogs.groups) != 2 {
		t.Fatal("different saved policies were counted as one rejection group")
	}
}

// A repeating rejection adds its individual rows at once and one count when
// its minute ends, whatever the traffic within the minute.
func TestRejectionLogsSendIndividualRowsAtOnceAndCountsWhenTheMinuteEnds(t *testing.T) {
	service := &Service{}
	b := &service.rejectionLogs
	// Existing maps keep RecordRejection from starting the sender, so the test
	// takes each batch itself.
	b.groups, b.perKey, b.perOrganization = map[rejectionLogKey]*rejectionLogGroup{}, map[string]int{}, map[string]int{}
	input := rejectionFixture()
	record := func(at time.Time) {
		copy := input
		copy.RequestID, copy.CreatedAt = uuid.Must(uuid.NewV7()).String(), at
		service.RecordRejection(copy)
	}
	settled := func() { b.pendingAt, b.pendingGroups = time.Time{}, 0 }
	stamp := func(at time.Time) string { return at.Format("2006-01-02T15:04:05.000Z") }

	minute := time.Now().UTC().Add(time.Hour).Truncate(rejectionLogWindow)
	for i := range rejectionLogIndividualLimit + 2 {
		record(minute.Add(time.Duration(i) * time.Second))
	}
	if got := b.snapshot(); got.OldestPendingAt == nil || got.OldestPendingAt.After(time.Now()) {
		t.Fatalf("waiting individual rows must report their arrival: %+v", got)
	}
	if batch := b.nextBatch(minute.Add(10*time.Second), false); len(batch) != rejectionLogIndividualLimit {
		t.Fatalf("sent %d rows inside the minute, want the %d individual rows", len(batch), rejectionLogIndividualLimit)
	}
	settled()
	record(minute.Add(30 * time.Second))
	if got := b.snapshot(); got.OldestPendingAt != nil || got.PendingGroups != 1 {
		t.Fatalf("a count inside its minute must not look delayed: %+v", got)
	}
	if batch := b.nextBatch(minute.Add(59*time.Second), false); len(batch) != 0 {
		t.Fatalf("sent %d rows before the minute ended", len(batch))
	}
	batch := b.nextBatch(minute.Add(rejectionLogWindow), false)
	if len(batch) != 1 || batch[0].RequestCount != 3 || batch[0].CreatedAt != stamp(minute.Add(5*time.Second)) || batch[0].LastRequestAt != stamp(minute.Add(30*time.Second)) {
		t.Fatalf("count row: %+v", batch)
	}
	settled()
	if len(b.groups) != 0 || len(b.perKey) != 0 {
		t.Fatal("an ended group kept its place")
	}

	// A rejection for a minute that has already ended ages from its arrival.
	started := time.Now()
	past := started.UTC().Add(-time.Hour).Truncate(rejectionLogWindow)
	for range rejectionLogIndividualLimit + 1 {
		record(past)
	}
	if got := b.snapshot(); got.OldestPendingAt == nil || got.OldestPendingAt.Before(started) {
		t.Fatalf("a late rejection must age from its arrival, not its minute: %+v", got)
	}
	if batch := b.nextBatch(time.Now(), false); len(batch) != rejectionLogIndividualLimit+1 {
		t.Fatalf("an ended minute sent %d rows, want its individual rows and count together", len(batch))
	}
}
