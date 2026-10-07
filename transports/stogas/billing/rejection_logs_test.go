package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

func rejectionTestClient(t *testing.T, handler http.HandlerFunc) *RequestLogClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewRequestLogClient(RequestLogConfig{TinybirdHost: server.URL, TinybirdToken: "test", AllowInsecurePrivateNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	client.fallback.circuitOpenDuration = time.Millisecond
	return client
}

func TestRejectionLogsCountConcurrentRequestsAndKeepKeysReasonsAndWindowsSeparate(t *testing.T) {
	var rows []RequestEvent
	var mu sync.Mutex
	client := rejectionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		mu.Lock()
		for _, line := range lines {
			var row RequestEvent
			// Ingestion serializes nested bags; inspect only the public scalar fields.
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(line), &fields); err != nil {
				t.Error(err)
				continue
			}
			for _, field := range []string{"provider_attempts", "meters", "plugins", "performance", "cancelled", "error", "policy_versions"} {
				delete(fields, field)
			}
			encoded, _ := json.Marshal(fields)
			if err := json.Unmarshal(encoded, &row); err != nil {
				t.Error(err)
			}
			rows = append(rows, row)
		}
		mu.Unlock()
		fmt.Fprintf(w, `{"successful_rows":%d,"quarantined_rows":0}`, len(lines))
	})
	service := &Service{requestLogs: client}
	input := rejectionFixture()
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
	other.CreatedAt = input.CreatedAt.Add(time.Second)
	other.RequestID = uuid.Must(uuid.NewV7()).String()
	service.RecordRejection(other)
	service.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(rows) != rejectionLogIndividualLimit+4 {
		t.Fatalf("stored %d rows, want first individual rejections, repeats, and three other groups", len(rows))
	}
	var total uint32
	for _, row := range rows {
		total += row.RequestCount
		if row.RequestCount == 100-rejectionLogIndividualLimit {
			if row.CreatedAt < input.CreatedAt.Format("2006-01-02T15:04:05.000Z") || row.LastRequestAt > input.CreatedAt.Add(99*time.Millisecond).Format("2006-01-02T15:04:05.000Z") || row.CreatedAt > row.LastRequestAt {
				t.Fatalf("incorrect first/last timestamps: %s %s", row.CreatedAt, row.LastRequestAt)
			}
		}
		if len(row.ProviderAttempts) != 0 || row.BilledCostUSD != "0" {
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
	var rows []savedRow
	client := rejectionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		if len(lines) > rejectionLogBatchSize {
			t.Errorf("delivery batch exceeds its row limit: %d", len(lines))
		}
		for _, line := range lines {
			var row savedRow
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Error(err)
			}
			rows = append(rows, row)
		}
		fmt.Fprintf(w, `{"successful_rows":%d,"quarantined_rows":0}`, len(lines))
	})
	service := &Service{requestLogs: client}
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
	if before.PendingGroups != len(counts) || before.OldestPendingAt == nil || before.OldestPendingAt.After(time.Now()) {
		t.Fatalf("pending age must use queue arrival, not the request timestamp: %+v", before)
	}
	service.Close()
	if len(rows) != len(want) {
		t.Fatalf("stored %d rows, want %d", len(rows), len(want))
	}
	for _, row := range rows {
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

func TestRejectionLogsFlushWhenTrafficStopsAndReplayAnAmbiguousBatchUnchanged(t *testing.T) {
	bodies := make(chan string, 4)
	client := rejectionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		bodies <- string(body)
		// Simulate an accepted write whose acknowledgement did not prove delivery.
		w.Write([]byte(`{"successful_rows":0,"quarantined_rows":0}`))
	})
	service := &Service{requestLogs: client}
	input := rejectionFixture()
	service.RecordRejection(input)
	var first string
	select {
	case first = <-bodies:
	case <-time.After(3 * time.Second):
		t.Fatal("quiet rejection was not flushed")
	}
	select {
	case second := <-bodies:
		if first != second {
			t.Fatal("delivery retry changed the batch identity or count")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unconfirmed batch was not retried")
	}
	if got := service.Diagnostics().RejectionLogs; got.OldestPendingAt == nil || got.PendingGroups != 1 {
		t.Fatalf("failed delivery lost its pending age: %+v", got)
	}
	if service.FinalizationReady() {
		t.Fatal("failed rejection delivery left inference admission open")
	}
	service.Close()
	if got := service.Diagnostics().RejectionLogs; got.StoredRequests != 0 || got.DroppedRequests != 1 || got.DeliveryFailures < 2 {
		t.Fatalf("ambiguous delivery was treated as committed: %+v", got)
	}
}

func TestRejectionLogsBoundMemoryAndDiscardUntrustedLabels(t *testing.T) {
	service := &Service{}
	input := rejectionFixture()
	input.CreatedAt = time.Now().Add(time.Hour).Truncate(time.Second)
	input.Code, input.RequestType = "secret-provider-message", "secret-client-path"
	service.RecordRejection(input)
	service.rejectionLogs.mu.Lock()
	for _, row := range service.rejectionLogs.groups {
		encoded, _ := json.Marshal(row)
		if strings.Contains(string(encoded), "secret") || row.RequestType != "unknown" || row.Error == nil || row.Error.Code != "insufficient_balance" {
			t.Errorf("untrusted labels escaped: %s", encoded)
		}
	}
	service.rejectionLogs.mu.Unlock()
	for i := 1; i <= rejectionLogPerKeyCapacity; i++ {
		copy := input
		copy.CreatedAt = input.CreatedAt.Add(time.Duration(i) * time.Second)
		service.RecordRejection(copy)
	}
	if got := service.Diagnostics().RejectionLogs; got.PendingGroups != rejectionLogPerKeyCapacity || got.DroppedRequests != 1 {
		t.Fatalf("per-key cap: %+v", got)
	}
	for i := rejectionLogPerKeyCapacity; i <= rejectionLogCapacity; i++ {
		copy := input
		claims := *input.Claims
		claims.KeyID = uuid.Must(uuid.NewV7()).String()
		copy.Claims = &claims
		service.RecordRejection(copy)
	}
	if got := service.Diagnostics().RejectionLogs; got.PendingGroups != rejectionLogCapacity || got.DroppedRequests != 2 {
		t.Fatalf("process cap: %+v", got)
	}
	service.Close()
	service.RecordRejection(input)
	if got := service.Diagnostics().RejectionLogs; got.PendingGroups != 0 || got.RecordedRequests != got.DroppedRequests {
		t.Fatalf("shutdown loss accounting: %+v", got)
	}
}

func TestRejectionDeliveryRecoveryReopensAdmissionAfterRetainedGroupsDrain(t *testing.T) {
	var recovered atomic.Bool
	client := rejectionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !recovered.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		rows := len(strings.Split(strings.TrimSpace(string(body)), "\n"))
		fmt.Fprintf(w, `{"successful_rows":%d,"quarantined_rows":0}`, rows)
	})
	service := &Service{requestLogs: client}
	defer service.Close()
	service.RecordRejection(rejectionFixture())
	deadline := time.Now().Add(5 * time.Second)
	for !service.rejectionLogs.deliveryBlocked.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if service.FinalizationReady() {
		t.Fatal("failed rejection delivery did not close admission")
	}
	recovered.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := service.DrainFinalizations(ctx); err != nil {
		t.Fatal(err)
	}
	if got := service.Diagnostics().RejectionLogs; !service.FinalizationReady() || got.StoredRequests != 1 || got.DroppedRequests != 0 || got.PendingGroups != 0 {
		t.Fatalf("recovery did not drain retained rejections: %+v", got)
	}
}

func TestRejectionGroupsKeepDifferentPolicyVersionsSeparate(t *testing.T) {
	s := &Service{}
	defer s.closeRejectionLogs()
	at := time.Now()
	for i := 1; i <= 2; i++ {
		s.RecordRejection(RejectionInput{Claims: &APIKeyClaims{KeyID: "key"}, RequestID: fmt.Sprint(i), Code: "policy_denied", StatusCode: 403, CreatedAt: at, PolicyVersions: &PolicyVersions{{Scope: "organization", ID: "org", Revision: i}, {Scope: "key", ID: "key", Revision: i}}})
	}
	s.rejectionLogs.mu.Lock()
	defer s.rejectionLogs.mu.Unlock()
	if len(s.rejectionLogs.groups) != 2 {
		t.Fatal("different saved policies were counted as one rejection group")
	}
}
