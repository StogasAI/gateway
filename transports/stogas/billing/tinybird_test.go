package billing

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTinybirdAppendMicrobatchesConcurrentEvents(t *testing.T) {
	const eventCount = 32

	var requests atomic.Int32
	var rows atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.URL.Query().Get("name"); got != tinybirdGatewayRequestsDatasource {
			t.Errorf("datasource = %q, want %q", got, tinybirdGatewayRequestsDatasource)
		}
		if got := r.URL.Query().Get("wait"); got != "true" {
			t.Errorf("wait query = %q, want true", got)
		}
		if got := r.Header.Get("authorization"); got != "Bearer gateway-requests-token" {
			t.Errorf("authorization header = %q", got)
		}
		if got := r.Header.Get("content-type"); got != "application/x-ndjson" {
			t.Errorf("content-type = %q, want application/x-ndjson", got)
		}

		scanner := bufio.NewScanner(r.Body)
		batchRows := 0
		for scanner.Scan() {
			payload := tinybirdGatewayRequestEventPayload{}
			if err := json.Unmarshal(scanner.Bytes(), &payload); err != nil {
				t.Errorf("decode NDJSON row: %v", err)
				continue
			}
			if payload.RequestID == "" {
				t.Error("batched request row has no request_id")
			}
			batchRows++
		}
		if err := scanner.Err(); err != nil {
			t.Errorf("scan NDJSON body: %v", err)
		}
		rows.Add(int32(batchRows))
		_, _ = fmt.Fprintf(w, `{"successful_rows":%d,"quarantined_rows":0}`, batchRows)
	}))
	defer server.Close()

	client := newTestTinybirdClient(t, server.URL)
	client.batchWindow = 100 * time.Millisecond

	start := make(chan struct{})
	errs := make(chan error, eventCount)
	var wg sync.WaitGroup
	for i := 0; i < eventCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			event := testGatewayRequestEvent()
			event.RequestID = fmt.Sprintf("request-%d", index)
			errs <- client.AppendGatewayRequest(context.Background(), event)
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("AppendGatewayRequest returned error: %v", err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("Tinybird requests = %d, want one microbatch", got)
	}
	if got := rows.Load(); got != eventCount {
		t.Fatalf("Tinybird rows = %d, want %d", got, eventCount)
	}
}

func TestTinybirdBatchRequiresExactCommittedRowCount(t *testing.T) {
	const eventCount = 3

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"successful_rows":2,"quarantined_rows":0}`))
	}))
	defer server.Close()

	client := newTestTinybirdClient(t, server.URL)
	client.batchWindow = 100 * time.Millisecond

	start := make(chan struct{})
	errs := make(chan error, eventCount)
	var wg sync.WaitGroup
	for i := 0; i < eventCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			event := testGatewayRequestEvent()
			event.RequestID = fmt.Sprintf("request-%d", index)
			errs <- client.AppendGatewayRequest(context.Background(), event)
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err == nil || !strings.Contains(err.Error(), "expected_rows=3 successful_rows=2") {
			t.Fatalf("AppendGatewayRequest error = %v, want exact batch acknowledgement failure", err)
		}
	}
}

func TestTinybirdCallerCancellationDoesNotCancelSharedBatch(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseRequest) })
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows := 0
		scanner := bufio.NewScanner(r.Body)
		for scanner.Scan() {
			rows++
		}
		if err := scanner.Err(); err != nil {
			t.Errorf("scan NDJSON body: %v", err)
		}
		close(requestStarted)
		<-releaseRequest
		_, _ = fmt.Fprintf(w, `{"successful_rows":%d,"quarantined_rows":0}`, rows)
	}))
	defer server.Close()
	defer release()

	client := newTestTinybirdClient(t, server.URL)
	client.batchWindow = 100 * time.Millisecond

	cancelledCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelledResult := make(chan error, 1)
	committedResult := make(chan error, 1)
	start := make(chan struct{})
	go func() {
		<-start
		cancelledResult <- client.AppendGatewayRequest(cancelledCtx, testGatewayRequestEvent())
	}()
	go func() {
		<-start
		event := testGatewayRequestEvent()
		event.RequestID = "request-2"
		committedResult <- client.AppendGatewayRequest(context.Background(), event)
	}()
	close(start)

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("Tinybird batch did not start")
	}
	cancel()
	cancelledErr := <-cancelledResult
	release()
	if cancelledErr == nil || !strings.Contains(cancelledErr.Error(), "context canceled") {
		t.Fatalf("cancelled AppendGatewayRequest error = %v, want context cancellation", cancelledErr)
	}
	if err := <-committedResult; err != nil {
		t.Fatalf("remaining AppendGatewayRequest returned error: %v", err)
	}
}

func TestTinybirdBatchDispatchDoesNotExceedFleetRequestBudget(t *testing.T) {
	const (
		fleetNodes             = 8
		datasourceRequestLimit = 100
	)
	perNodeRollingSecond := int(time.Second/tinybirdMinRequestInterval) + 1
	if requestsPerSecond := perNodeRollingSecond * fleetNodes; requestsPerSecond >= datasourceRequestLimit {
		t.Fatalf(
			"fleet request budget = %d requests/second, want below %d",
			requestsPerSecond,
			datasourceRequestLimit,
		)
	}

	var mu sync.Mutex
	var dispatched []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		dispatched = append(dispatched, time.Now())
		mu.Unlock()
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	client := newTestTinybirdClient(t, server.URL)
	client.batchWindow = time.Millisecond
	client.minRequestInterval = 30 * time.Millisecond
	client.maxBatchRows = 1

	start := make(chan struct{})
	errs := make(chan error, 3)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			event := testGatewayRequestEvent()
			event.RequestID = fmt.Sprintf("request-%d", index)
			errs <- client.AppendGatewayRequest(context.Background(), event)
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("AppendGatewayRequest returned error: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dispatched) != 3 {
		t.Fatalf("Tinybird requests = %d, want 3 size-limited batches", len(dispatched))
	}
	for index := 1; index < len(dispatched); index++ {
		if spacing := dispatched[index].Sub(dispatched[index-1]); spacing < 25*time.Millisecond {
			t.Fatalf("batch spacing = %s, want rate-limited dispatches", spacing)
		}
	}
}

func TestTinybirdAppendRejectsOversizedEventBeforeAdmission(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := newTestTinybirdClient(t, server.URL)
	event := testGatewayRequestEvent()
	event.Pricing = map[string]any{"oversized": strings.Repeat("x", tinybirdMaxEventBytes)}

	err := client.AppendGatewayRequest(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "encoded event") {
		t.Fatalf("AppendGatewayRequest error = %v, want encoded event size rejection", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("Tinybird requests = %d, want no request for oversized event", got)
	}
}

func TestTinybirdCloseFlushesPendingBatchAndRejectsNewEvents(t *testing.T) {
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	client := NewTinybirdClient(server.URL, "gateway-requests-token")
	client.batchWindow = time.Hour

	line, err := json.Marshal(tinybirdGatewayRequestEvent(testGatewayRequestEvent()))
	if err != nil {
		t.Fatalf("marshal Tinybird event: %v", err)
	}
	appendRequest := tinybirdAppendRequest{
		line:   append(line, '\n'),
		result: make(chan error, 1),
	}
	client.startOnce.Do(func() {
		client.workerWG.Add(1)
		go client.run()
	})
	client.queue <- appendRequest
	client.Close()

	select {
	case <-requests:
	default:
		t.Fatal("Close did not flush the pending Tinybird batch")
	}
	if err := <-appendRequest.result; err != nil {
		t.Fatalf("pending AppendGatewayRequest returned error: %v", err)
	}
	if err := client.AppendGatewayRequest(context.Background(), testGatewayRequestEvent()); err == nil ||
		!strings.Contains(err.Error(), "client is closed") {
		t.Fatalf("AppendGatewayRequest after Close error = %v, want closed client error", err)
	}
}

func newTestTinybirdClient(t *testing.T, host string) *TinybirdClient {
	t.Helper()
	client := NewTinybirdClient(host, "gateway-requests-token")
	client.batchWindow = time.Millisecond
	client.minRequestInterval = time.Millisecond
	t.Cleanup(client.Close)
	return client
}
