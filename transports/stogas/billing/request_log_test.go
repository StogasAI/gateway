package billing

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func queueTestClient(t *testing.T, queueURL, tinybirdURL string) *RequestLogClient {
	t.Helper()
	config := RequestLogConfig{QueueURL: queueURL, QueueToken: "producer-token"}
	if tinybirdURL != "" {
		config.TinybirdHost = tinybirdURL
		config.TinybirdToken = "analytics-token"
	}
	client, err := NewRequestLogClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.batchWindow = time.Millisecond
	client.minRequestInterval = time.Millisecond
	t.Cleanup(client.Close)
	return client
}

func TestFinalizationDurablyQueuesCanonicalMicrobatchWithoutDatabase(t *testing.T) {
	const count = 32
	var calls atomic.Int32
	var records []requestLogRecord
	var mutex sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer producer-token" {
			t.Error("producer authorization missing")
		}
		scanner := bufio.NewScanner(r.Body)
		rows := 0
		for scanner.Scan() {
			var record requestLogRecord
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				t.Error(err)
			}
			mutex.Lock()
			records = append(records, record)
			mutex.Unlock()
			rows++
		}
		if err := scanner.Err(); err != nil {
			t.Error(err)
		}
		fmt.Fprintf(w, `{"accepted_rows":%d}`, rows)
	}))
	defer server.Close()
	client := queueTestClient(t, server.URL, "")
	client.batchWindow = 50 * time.Millisecond
	service := &Service{requestLogs: client}
	// A database access here would fail: the accepted queue owns settlement.
	var tasks sync.WaitGroup
	for range count {
		tasks.Add(1)
		go func() {
			defer tasks.Done()
			authorization := testAuthorization()
			event := testGatewayRequestEvent()
			if err := service.FinalizeRequest(context.Background(), authorization, event, nil); err != nil {
				t.Error(err)
			}
		}()
	}
	tasks.Wait()
	service.Close()
	if calls.Load() != 1 || len(records) != count {
		t.Fatalf("calls=%d rows=%d", calls.Load(), len(records))
	}
	expected := createHoldParamsHash(testAuthorization().ProviderKey, testAuthorization().ProductKey, testAuthorization().UpstreamTargetJSON)
	for _, record := range records {
		if record.HoldParamsHash != expected || record.RequestID != testAuthorization().RequestID {
			t.Fatal("durable record lost its reservation binding")
		}
		if record.BilledCostUSD != record.UpstreamCostUSD {
			t.Fatal("managed charge changed")
		}
	}
}

func TestQueueFailureFallsBackWithExactImmutableEvidence(t *testing.T) {
	for _, acknowledgement := range []string{"unavailable", `{"accepted_rows":0}`, `{"accepted_rows":1} {}`, `{"accepted_rows":"1"}`} {
		t.Run(acknowledgement, func(t *testing.T) {
			var primaryCalls, fallbackCalls atomic.Int32
			var queued requestLogRecord
			var stored tinybirdGatewayRequestEventPayload
			primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				primaryCalls.Add(1)
				if err := json.NewDecoder(r.Body).Decode(&queued); err != nil {
					t.Error(err)
				}
				if acknowledgement == "unavailable" {
					w.WriteHeader(503)
					return
				}
				io.WriteString(w, acknowledgement)
			}))
			defer primary.Close()
			fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fallbackCalls.Add(1)
				if err := json.NewDecoder(r.Body).Decode(&stored); err != nil {
					t.Error(err)
				}
				io.WriteString(w, `{"successful_rows":1,"quarantined_rows":0}`)
			}))
			defer fallback.Close()
			client := queueTestClient(t, primary.URL, fallback.URL)
			event := testGatewayRequestEvent()
			event.holdParamsHash = strings.Repeat("a", 64)
			for range 2 {
				destination, err := client.AppendGatewayRequest(context.Background(), event)
				if err != nil || destination != LogTinybird {
					t.Fatalf("destination=%d err=%v", destination, err)
				}
			}
			if primaryCalls.Load() != 1 || fallbackCalls.Load() != 2 {
				t.Fatal("queue circuit blocked the independent fallback")
			}
			if queued.RequestID != stored.RequestID || queued.HoldParamsHash != stored.HoldParamsHash || queued.BilledCostUSD != stored.BilledCostUSD {
				t.Fatal("fallback changed durable financial evidence")
			}
		})
	}
}

func TestQueueRecoveryStopsTinybirdFallback(t *testing.T) {
	var unavailable atomic.Bool
	unavailable.Store(true)
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable.Load() {
			w.WriteHeader(503)
			return
		}
		io.WriteString(w, `{"accepted_rows":1}`)
	}))
	defer primary.Close()
	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls.Add(1)
		io.WriteString(w, `{"successful_rows":1,"quarantined_rows":0}`)
	}))
	defer fallback.Close()
	client := queueTestClient(t, primary.URL, fallback.URL)
	client.primary.circuitOpenDuration = time.Millisecond
	destination, err := client.AppendGatewayRequest(context.Background(), testGatewayRequestEvent())
	if err != nil || destination != LogTinybird {
		t.Fatalf("initial destination=%d err=%v", destination, err)
	}
	unavailable.Store(false)
	time.Sleep(2 * time.Millisecond)
	destination, err = client.AppendGatewayRequest(context.Background(), testGatewayRequestEvent())
	if err != nil || destination != LogQueue || fallbackCalls.Load() != 1 {
		t.Fatalf("recovered destination=%d err=%v", destination, err)
	}
}

func TestFinalizationBackpressureRetainsEveryAcceptedRequestUntilAllDrain(t *testing.T) {
	const count = 64
	var mode, accepted atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() == 0 || (mode.Load() == 1 && !accepted.CompareAndSwap(0, -1)) {
			w.WriteHeader(503)
			return
		}
		rows := 0
		scanner := bufio.NewScanner(r.Body)
		for scanner.Scan() {
			rows++
		}
		if accepted.Load() == -1 {
			accepted.Store(int32(rows))
		} else {
			accepted.Add(int32(rows))
		}
		fmt.Fprintf(w, `{"accepted_rows":%d}`, rows)
	}))
	defer primary.Close()
	client := queueTestClient(t, primary.URL, "")
	client.primary.circuitOpenDuration = time.Millisecond
	service := &Service{requestLogs: client}
	defer service.Close()
	authorizations := make([]*Authorization, count)
	for i := range authorizations {
		release, err := service.reserveFinalization()
		if err != nil {
			t.Fatal(err)
		}
		authorizations[i] = testAuthorization()
		authorizations[i].releaseFinalization = release
	}
	var retained, released atomic.Int32
	retain := func(size int) (func(), bool) {
		if size <= 0 || size > requestLogMaxEventBytes+2048 {
			t.Errorf("unexpected retained size %d", size)
		}
		retained.Add(1)
		return func() { released.Add(1) }, true
	}
	for _, authorization := range authorizations {
		if err := service.FinalizeRequest(context.Background(), authorization, testGatewayRequestEvent(), retain); err != nil {
			t.Fatal(err)
		}
	}
	if service.FinalizationReady() || retained.Load() != count || released.Load() != 0 {
		t.Fatal("failed finalizations were not retained behind the gate")
	}
	if _, err := service.reserveFinalization(); !errors.Is(err, ErrGatewayUnavailable) {
		t.Fatal("new inference admission crossed a failed finalization")
	}
	mode.Store(1)
	deadline := time.Now().Add(5 * time.Second)
	for service.finalizations.pending.Load() == count && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if pending := service.finalizations.pending.Load(); pending <= 0 || pending >= count || service.FinalizationReady() {
		t.Fatalf("partial recovery opened admission: pending=%d", pending)
	}
	mode.Store(2)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := service.DrainFinalizations(ctx); err != nil {
		t.Fatal(err)
	}
	if !service.FinalizationReady() || retained.Load() != released.Load() || accepted.Load() != count {
		t.Fatalf("recovery ready=%t retained=%d released=%d accepted=%d", service.FinalizationReady(), retained.Load(), released.Load(), accepted.Load())
	}
	release, err := service.reserveFinalization()
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestFinalizationSurvivesHoldExpiryAndOnlyShutdownReleasesUndeliveredMemory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		service := &Service{}
		authorization := testAuthorization()
		var err error
		authorization.releaseFinalization, err = service.reserveFinalization()
		if err != nil {
			t.Fatal(err)
		}
		var released atomic.Int32
		if err := service.FinalizeRequest(context.Background(), authorization, testGatewayRequestEvent(), func(int) (func(), bool) {
			return func() { released.Add(1) }, true
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		if service.FinalizationReady() || released.Load() != 0 || service.finalizations.pending.Load() != 1 {
			t.Fatal("elapsed hold expiry discarded execution evidence")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := service.DrainFinalizations(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown drain=%v", err)
		}
		service.Close()
		if released.Load() != 1 || service.finalizations.abandoned.Load() != 1 || service.finalizations.pending.Load() != 0 {
			t.Fatal("shutdown did not account for retained memory")
		}
	})
}

func TestFinalizationCapacityIsReservedBeforeAuthorizationAndReleasedOnce(t *testing.T) {
	service := &Service{}
	defer service.Close()
	releases := make([]func(), finalizationCapacity)
	for i := range releases {
		var err error
		releases[i], err = service.reserveFinalization()
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.reserveFinalization(); !errors.Is(err, ErrGatewayUnavailable) || service.FinalizationReady() {
		t.Fatal("exhausted capacity admitted another hold")
	}
	releases[0]()
	releases[0]()
	release, err := service.reserveFinalization()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.reserveFinalization(); !errors.Is(err, ErrGatewayUnavailable) {
		t.Fatal("double release created capacity")
	}
	release()
	for _, release := range releases[1:] {
		release()
	}
	if !service.FinalizationReady() {
		t.Fatal("capacity did not recover")
	}
}

func TestFailedMemoryTransferKeepsRequestOwnerUntilShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		service := &Service{}
		authorization := testAuthorization()
		var err error
		authorization.releaseFinalization, err = service.reserveFinalization()
		if err != nil {
			t.Fatal(err)
		}
		finished := make(chan error, 1)
		go func() {
			finished <- service.FinalizeRequest(context.Background(), authorization, testGatewayRequestEvent(), func(int) (func(), bool) { return nil, false })
		}()
		synctest.Wait()
		select {
		case <-finished:
			t.Fatal("failed memory transfer released the original request owner")
		default:
		}
		if service.FinalizationReady() || service.finalizations.pending.Load() != 1 {
			t.Fatal("inline finalization did not close admission")
		}
		service.Close()
		synctest.Wait()
		if err := <-finished; err != nil || service.finalizations.pending.Load() != 0 || service.finalizations.abandoned.Load() != 1 {
			t.Fatalf("shutdown lost retained request accounting: %v", err)
		}
	})
}

// The database endpoint really refuses connections; successful durable delivery
// must not retain a retry or gate admission on a second settlement owner.
func TestTinybirdDeliveryCompletesFinalizationDuringDatabaseOutage(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		t.Run(fmt.Sprintf("delayed=%t", delayed), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			listener.Close()
			pool, err := pgxpool.New(context.Background(), "postgres://unused:unused@"+address+"/unused?sslmode=disable&connect_timeout=1")
			if err != nil {
				t.Fatal(err)
			}
			var stored atomic.Bool
			stored.Store(!delayed)
			var fallbackCalls atomic.Int32
			primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
			defer primary.Close()
			fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fallbackCalls.Add(1)
				if !stored.Load() {
					w.WriteHeader(503)
					return
				}
				fmt.Fprint(w, `{"successful_rows":1,"quarantined_rows":0}`)
			}))
			defer fallback.Close()
			client := queueTestClient(t, primary.URL, fallback.URL)
			client.primary.circuitOpenDuration = time.Millisecond
			client.fallback.circuitOpenDuration = time.Millisecond
			service := &Service{requestLogs: client, db: &GatewayDB{pool: pool}, settleHoldQuery: "select 1"}
			defer service.Close()
			authorization := testAuthorization()
			authorization.releaseFinalization, err = service.reserveFinalization()
			if err != nil {
				t.Fatal(err)
			}
			if err := service.FinalizeRequest(context.Background(), authorization, testGatewayRequestEvent(), nil); err != nil {
				t.Fatal(err)
			}
			if delayed {
				if service.FinalizationReady() {
					t.Fatal("undelivered log did not close admission")
				}
				stored.Store(true)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := service.DrainFinalizations(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if !service.FinalizationReady() || service.finalizations.pending.Load() != 0 || service.finalizations.reserved != 0 {
				t.Fatal("database outage retained a durably stored log")
			}
			calls := fallbackCalls.Load()
			time.Sleep(50 * time.Millisecond)
			if fallbackCalls.Load() != calls {
				t.Fatal("confirmed fallback was written again")
			}
		})
	}
}
