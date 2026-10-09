package billing

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

func TestTinybirdRequiresAuthenticatedHybridTLS(t *testing.T) {
	for _, mode := range []string{"hybrid", "classical", "tls12", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
			if mode == "classical" || mode == "tls12" {
				server.TLS.CurvePreferences = []tls.CurveID{tls.X25519}
			}
			if mode == "tls12" {
				server.TLS.MinVersion = tls.VersionTLS12
				server.TLS.MaxVersion = tls.VersionTLS12
			}
			server.StartTLS()
			defer server.Close()
			client, err := NewRequestLogClient(RequestLogConfig{TinybirdHost: server.URL, TinybirdToken: "fixture", AllowInsecurePrivateNetwork: false})
			if err != nil {
				t.Fatal(err)
			}
			transport := client.fallback.client.Transport.(*http.Transport)
			defer transport.CloseIdleConnections()
			if mode != "untrusted" {
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				transport.TLSClientConfig.RootCAs = roots
			}
			response, err := client.fallback.client.Get(server.URL)
			if response != nil {
				response.Body.Close()
			}
			if (err == nil) != (mode == "hybrid") {
				t.Fatalf("TLS mode %s accepted=%v", mode, err == nil)
			}
		})
	}
}

func TestRedactionProjectionPreservesUnrecordedZeroAndMaximum(t *testing.T) {
	for _, metrics := range []*plugins.StogasStructuredPIIRedactionMetrics{nil, {}, {ItemsRedacted: ^uint32(0), DurationUS: 125}} {
		event := testGatewayRequestEvent()
		event.Plugins = plugins.Metrics{StogasStructuredPIIRedaction: metrics}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var restored RequestEvent
		if err := json.Unmarshal(encoded, &restored); err != nil {
			t.Fatal(err)
		}
		payload := tinybirdGatewayRequestEvent(restored)
		if metrics == nil {
			if payload.AnalyticsRedactedItems != nil {
				t.Fatal("unrecorded redaction became a zero count")
			}
		} else if payload.AnalyticsRedactedItems == nil || *payload.AnalyticsRedactedItems != metrics.ItemsRedacted {
			t.Fatalf("redaction count changed: got %v, want %d", payload.AnalyticsRedactedItems, metrics.ItemsRedacted)
		}
	}
}

func TestTokenUsageSurvivesSerializationAndAnalyticsProjection(t *testing.T) {
	for _, quantity := range []*uint64{nil, new(uint64), func() *uint64 { n := uint64(1_000_000_000_000); return &n }()} {
		event := testGatewayRequestEvent()
		event.Usage.Meters = EventMeters{}
		if quantity != nil {
			event.Usage.Meters[MeterTotalTokens] = EventMeter{Quantity: fmt.Sprint(*quantity)}
		}
		encoded, err := encodeGatewayRequestEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := decodeGatewayRequestEvent(encoded)
		if err != nil {
			t.Fatal(err)
		}
		payload := tinybirdGatewayRequestEvent(restored)
		if quantity == nil {
			if payload.AnalyticsTotalTokens != nil {
				t.Fatal("unknown usage became a known value")
			}
		} else if payload.AnalyticsTotalTokens == nil || *payload.AnalyticsTotalTokens != *quantity {
			t.Fatalf("token usage changed: got %v, want %d", payload.AnalyticsTotalTokens, *quantity)
		}
	}
}

func TestNormalizeTinybirdHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	for _, test := range []struct {
		allowInsecurePrivateNetwork bool
		name                        string
		host                        string
		want                        string
		wantErr                     bool
	}{
		{name: "HTTPS origin", host: "https://api.tinybird.co/", want: "https://api.tinybird.co"},
		{name: "loopback HTTP", host: server.URL, want: server.URL},
		{name: "remote HTTP", host: "http://tinybird.example", wantErr: true},
		{name: "private HTTP", host: "http://10.0.2.2:7181", wantErr: true},
		{
			name:                        "explicit local private HTTP",
			host:                        "http://10.0.2.2:7181",
			allowInsecurePrivateNetwork: true,
			want:                        "http://10.0.2.2:7181",
		},
		{
			name:                        "private hostname remains blocked",
			host:                        "http://tinybird.internal",
			allowInsecurePrivateNetwork: true,
			wantErr:                     true,
		},
		{name: "credentials", host: "https://token@tinybird.example", wantErr: true},
		{name: "path", host: "https://tinybird.example/private", wantErr: true},
		{name: "query", host: "https://tinybird.example?token=value", wantErr: true},
		{name: "empty query", host: "https://tinybird.example?", wantErr: true},
		{name: "fragment", host: "https://tinybird.example#fragment", wantErr: true},
		{name: "missing scheme", host: "tinybird.example", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeTinybirdHost(test.host, test.allowInsecurePrivateNetwork)
			if test.wantErr {
				if err == nil {
					t.Fatalf("NormalizeTinybirdHost(%q) = %q, want error", test.host, got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("NormalizeTinybirdHost(%q) = %q, %v; want %q", test.host, got, err, test.want)
			}
		})
	}
}

func TestRequestLogClientRefusesRedirects(t *testing.T) {
	var redirectedRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer destination.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	_, err := newTestRequestLogClient(t, server.URL).AppendGatewayRequest(context.Background(), testGatewayRequestEvent())
	if err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Fatalf("AppendGatewayRequest error = %v, want redirect status rejection", err)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("redirect destination requests = %d, want 0", got)
	}
}

func TestTinybirdAppendMicrobatchesConcurrentEvents(t *testing.T) {
	const eventCount = 32

	var requests atomic.Int32
	var rows atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.URL.Query().Get("name"); got != "gateway_requests" {
			t.Errorf("datasource = %q, want %q", got, "gateway_requests")
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

	client := newTestRequestLogClient(t, server.URL)
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
			_, err := client.AppendGatewayRequest(context.Background(), event)
			errs <- err
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

	client := newTestRequestLogClient(t, server.URL)
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
			_, err := client.AppendGatewayRequest(context.Background(), event)
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err == nil || !strings.Contains(err.Error(), "did not commit every request log row") {
			t.Fatalf("AppendGatewayRequest error = %v, want exact batch acknowledgement failure", err)
		}
	}
}

func TestTinybirdCircuitSkipsRequestsUntilTheProbeWindow(t *testing.T) {
	var requests atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	client := newTestRequestLogClient(t, server.URL)
	client.fallback.circuitOpenDuration = time.Hour
	if _, err := client.AppendGatewayRequest(context.Background(), testGatewayRequestEvent()); err == nil {
		t.Fatal("first Tinybird failure did not open the circuit")
	}
	if _, err := client.AppendGatewayRequest(context.Background(), testGatewayRequestEvent()); err == nil ||
		!strings.Contains(err.Error(), "circuit is open") {
		t.Fatalf("second Tinybird append error = %v, want open circuit", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("Tinybird requests while circuit open = %d, want 1 initial request", got)
	}
	if diagnostics := client.Diagnostics(); !diagnostics.Fallback.CircuitOpen || diagnostics.Fallback.ShortCircuits != 1 {
		t.Fatalf("Tinybird circuit diagnostics = %#v", diagnostics)
	}

	client.fallback.circuitOpenUntil.Store(time.Now().Add(-time.Second).UnixNano())
	fail.Store(false)
	if _, err := client.AppendGatewayRequest(context.Background(), testGatewayRequestEvent()); err != nil {
		t.Fatalf("Tinybird recovery probe returned error: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("Tinybird requests after recovery probe = %d, want 2", got)
	}
	if diagnostics := client.Diagnostics(); diagnostics.Fallback.CircuitOpen {
		t.Fatalf("Tinybird circuit remained open after recovery: %#v", diagnostics)
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

	client := newTestRequestLogClient(t, server.URL)
	client.batchWindow = 100 * time.Millisecond

	cancelledCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelledResult := make(chan error, 1)
	committedResult := make(chan error, 1)
	start := make(chan struct{})
	go func() {
		<-start
		_, err := client.AppendGatewayRequest(cancelledCtx, testGatewayRequestEvent())
		cancelledResult <- err
	}()
	go func() {
		<-start
		event := testGatewayRequestEvent()
		event.RequestID = "request-2"
		_, err := client.AppendGatewayRequest(context.Background(), event)
		committedResult <- err
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
	perNodeRollingSecond := int(time.Second/requestLogMinRequestInterval) + 1
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

	client := newTestRequestLogClient(t, server.URL)
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
			_, err := client.AppendGatewayRequest(context.Background(), event)
			errs <- err
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

	client := newTestRequestLogClient(t, server.URL)
	event := testGatewayRequestEvent()
	event.Usage.Meters = EventMeters{"oversized": PricedMeter("1", strings.Repeat("x", requestLogMaxEventBytes), "1", "1")}

	_, err := client.AppendGatewayRequest(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "request log is") {
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

	client, err := NewRequestLogClient(RequestLogConfig{TinybirdHost: server.URL, TinybirdToken: "gateway-requests-token", AllowInsecurePrivateNetwork: false})
	if err != nil {
		t.Fatalf("NewRequestLogClient returned error: %v", err)
	}
	client.batchWindow = time.Hour

	line, err := json.Marshal(testGatewayRequestEvent())
	if err != nil {
		t.Fatalf("marshal Tinybird event: %v", err)
	}
	appendRequest := requestLogAppendRequest{
		line:   append(line, '\n'),
		result: make(chan logDelivery, 1),
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
	if result := <-appendRequest.result; result.err != nil {
		t.Fatalf("pending AppendGatewayRequest returned error: %v", result.err)
	}
	if _, err := client.AppendGatewayRequest(context.Background(), testGatewayRequestEvent()); err == nil ||
		!strings.Contains(err.Error(), "client is closed") {
		t.Fatalf("AppendGatewayRequest after Close error = %v, want closed client error", err)
	}
}

func newTestRequestLogClient(t *testing.T, host string) *RequestLogClient {
	t.Helper()
	client, err := NewRequestLogClient(RequestLogConfig{TinybirdHost: host, TinybirdToken: "gateway-requests-token", AllowInsecurePrivateNetwork: false})
	if err != nil {
		t.Fatalf("NewRequestLogClient returned error: %v", err)
	}
	client.batchWindow = time.Millisecond
	client.minRequestInterval = time.Millisecond
	t.Cleanup(client.Close)
	return client
}

func TestPolicyVersionsSurviveSerializationAndTinybirdEncoding(t *testing.T) {
	event := testGatewayRequestEvent()
	event.PolicyVersions = &PolicyVersions{{Scope: "organization", ID: "org", Revision: 3}, {Scope: "grant", ID: "grant", Revision: 4}, {Scope: "key", ID: "key", Revision: 8}}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var restored RequestEvent
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	payload := tinybirdGatewayRequestEvent(restored)
	var versions PolicyVersions
	if err := json.Unmarshal([]byte(payload.PolicyVersions), &versions); err != nil {
		t.Fatal(err)
	}
	if len(versions) != 3 || versions[0].Revision != 3 || versions[1].Revision != 4 || versions[2].Revision != 8 {
		t.Fatalf("wrong recorded snapshot: %#v", versions)
	}
	event.PolicyVersions = nil
	if tinybirdGatewayRequestEvent(event).PolicyVersions != "null" {
		t.Fatal("unknown snapshot was invented")
	}
}
