package exporter

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
)

type testLease struct {
	mu    sync.Mutex
	used  int
	limit int
}

func (l *testLease) Grow(n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > l.limit-l.used {
		return false
	}
	l.used += n
	return true
}
func (l *testLease) Release() {
	l.mu.Lock()
	l.used = 0
	l.mu.Unlock()
}

// Each lease, including each connection's, gets the same limit.
func testOptions(local bool, limit int) Options {
	return Options{Local: local, NewLease: func() Lease { return &testLease{limit: limit} }}
}

// budgetLease spends one budget shared by every lease.
type budgetLease struct {
	mu     sync.Mutex
	spent  *atomic.Int64
	budget int64
	used   int64
}

func (l *budgetLease) Grow(n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.spent.Add(int64(n)) > l.budget {
		l.spent.Add(-int64(n))
		return false
	}
	l.used += int64(n)
	return true
}
func (l *budgetLease) Release() {
	l.mu.Lock()
	l.spent.Add(-l.used)
	l.used = 0
	l.mu.Unlock()
}
func testRecord(id string) map[string]any {
	return map[string]any{"request_id": id, "billed_cost_usd": "0.001", "meters": map[string]any{}}
}
func testMetadata() json.RawMessage {
	return json.RawMessage(`{"billed_cost_usd":"0.001","meters":{}}`)
}
func testConfig(url string) *exportconfig.Config {
	return &exportconfig.Config{Destinations: []exportconfig.Destination{{URL: url}}}
}
func await(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition timed out")
}

func TestFullJSONDeliveryAndDetachedOwnership(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			received := make(chan map[string]json.RawMessage, 2)
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/webhook" || r.Header.Get("Authorization") != "Bearer destination-secret" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Idempotency-Key") != "record" {
					t.Error("wrong method/path/headers")
				}
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if strings.Contains(string(raw), "destination-secret") {
					t.Error("delivery credential in payload")
				}
				var record map[string]json.RawMessage
				if err := json.Unmarshal(raw, &record); err != nil {
					t.Error(err)
				}
				received <- record
				w.WriteHeader(http.StatusAccepted)
				io.WriteString(w, "accepted")
			}))
			defer receiver.Close()
			e := New(context.Background(), testOptions(true, 16<<20))
			defer e.Close()
			config := testConfig(receiver.URL + "/webhook")
			config.Destinations[0].Headers = map[string]string{"Authorization": "Bearer destination-secret"}
			config.Destinations = append(config.Destinations, config.Destinations[0])
			c := e.Start(config, "id", Trace{})
			config.Destinations[0].Headers["Authorization"] = "changed"
			message, _ := json.Marshal(strings.Repeat("large prompt 世界 ", 65536))
			body := map[string]json.RawMessage{"input": message, "temperature": json.RawMessage(`0.25`), "tools": json.RawMessage(`[{"type":"custom","name":"freeform"}]`)}
			c.Input(body, true)
			expectedInput, _ := json.Marshal(body)
			clear(message)
			responses := []string{`{"type":"response.output_item.added","item":{"type":"reasoning","encrypted_content":"opaque"}}`, `{"type":"response.completed","response":{"output":[{"type":"custom_tool_call","input":"123","name":"freeform"},{"type":"reasoning","summary":[],"encrypted_content":"opaque"}],"usage":{"output_tokens":0}}}`}
			for _, response := range responses {
				raw := []byte(response)
				if streaming {
					c.Event(raw)
				} else {
					c.Response(raw)
				}
				clear(raw)
			}
			c.Finish("record", "success", testRecord("record"), testMetadata())
			e.Close()
			if d := e.Diagnostics(); d.Delivered != 2 || d.ReservedBytes != 0 || d.PendingDeliveries != 0 {
				t.Fatalf("diagnostics: %+v", d)
			}
			for range 2 {
				got := <-received
				var input, want any
				json.Unmarshal(got["request"], &input)
				json.Unmarshal(expectedInput, &want)
				if !reflect.DeepEqual(input, want) {
					t.Fatal("full input changed or truncated")
				}
				if string(got["stogas"]) != string(testMetadata()) {
					t.Fatal("metadata changed")
				}
				if streaming {
					var events []json.RawMessage
					if err := json.Unmarshal(got["events"], &events); err != nil {
						t.Fatal(err)
					}
					if len(events) != len(responses) {
						t.Fatal("missing stream events")
					}
					for i := range events {
						if string(events[i]) != responses[i] {
							t.Fatal("event changed or reordered")
						}
					}
				} else if string(got["response"]) != responses[1] {
					t.Fatal("full response changed")
				}
			}
		})
	}
}

// A destination without content gets the request record and metadata, and
// a capture copies content only while some destination sends it.
func TestDestinationsWithoutContent(t *testing.T) {
	var mu sync.Mutex
	received := map[string]map[string]json.RawMessage{}
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var record map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
			t.Error(err)
		}
		mu.Lock()
		received[r.URL.Path] = record
		mu.Unlock()
	}))
	defer receiver.Close()
	off := exportconfig.Content{}
	withoutContent := exportconfig.Destination{URL: receiver.URL + "/metadata", Content: &off}
	checkMetadataOnly := func() {
		t.Helper()
		got := received["/metadata"]
		keys := make([]string, 0, len(got))
		for key := range got {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"billed_cost_usd", "meters", "request_id", "stogas"}) || string(got["stogas"]) != string(testMetadata()) {
			t.Fatalf("record without content = %s", got)
		}
	}
	for _, streaming := range []bool{false, true} {
		clear(received)
		e := New(context.Background(), testOptions(true, 16<<20))
		c := e.Start(&exportconfig.Config{Destinations: []exportconfig.Destination{{URL: receiver.URL + "/content"}, withoutContent}}, "id", Trace{})
		c.Input(map[string]json.RawMessage{"input": json.RawMessage(`"prompt"`)}, true)
		output, field := `{"output":"answer"}`, "response"
		if streaming {
			c.Event([]byte(output))
			field = "events"
		} else {
			c.Response([]byte(output))
		}
		c.Finish("record", "success", testRecord("record"), testMetadata())
		e.Close()
		if e.Diagnostics().Delivered != 2 {
			t.Fatalf("diagnostics = %+v", e.Diagnostics())
		}
		full := received["/content"]
		if string(full["request"]) != `{"input":"prompt"}` || strings.Trim(string(full[field]), "[]") != output {
			t.Fatalf("record with content = %s", full)
		}
		checkMetadataOnly()
	}
	clear(received)
	e := New(context.Background(), testOptions(true, 16<<20))
	c := e.Start(&exportconfig.Config{Destinations: []exportconfig.Destination{withoutContent}}, "id", Trace{})
	reserved := e.Diagnostics().ReservedBytes
	c.Input(map[string]json.RawMessage{"input": json.RawMessage(`"` + strings.Repeat("prompt ", 4096) + `"`)}, true)
	c.Response([]byte(`{"output":"answer"}`))
	if c.Active() || e.Diagnostics().ReservedBytes != reserved {
		t.Fatalf("capture without content destinations copied content: %+v", e.Diagnostics())
	}
	c.Finish("record", "success", testRecord("record"), testMetadata())
	e.Close()
	checkMetadataOnly()
}

func TestMemoryPressureDropsWholeCapture(t *testing.T) {
	var received atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer receiver.Close()
	e := New(context.Background(), testOptions(true, 8192+deliveryStateBytes))
	defer e.Close()
	c := e.Start(testConfig(receiver.URL), "id", Trace{})
	c.Input(map[string]json.RawMessage{"model": json.RawMessage(`"model"`)}, false)
	c.Event([]byte(`{"delta":"hello"}`))
	c.Event([]byte(`{"delta":"` + strings.Repeat("x", 8192) + `"}`))
	c.Finish("dropped", "success", testRecord("dropped"), testMetadata())
	e.Close()
	if d := e.Diagnostics(); received.Load() != 0 || d.MemoryDropped != 1 || d.ReservedBytes != 0 {
		t.Fatalf("partial export or leak: %+v", d)
	}
}

// A capture dropped at the start keeps the request record's export section,
// which receivers need to find the records that never arrived.
func TestMemoryPressureAtStartKeepsExportCoverage(t *testing.T) {
	e := New(context.Background(), testOptions(true, deliveryStateBytes))
	defer e.Close()
	c := e.Start(testConfig("http://127.0.0.1:1"), "id", Trace{})
	if c == nil || c.Active() || *c.Duration() != 0 {
		t.Fatalf("dropped capture = %+v, want an inactive capture with zero duration", c)
	}
	c.Input(map[string]json.RawMessage{"model": json.RawMessage(`"model"`)}, false)
	c.Finish("dropped", "success", testRecord("dropped"), testMetadata())
	if d := e.Diagnostics(); d.MemoryDropped != 1 || d.ReservedBytes != 0 || d.PendingDeliveries != 0 {
		t.Fatalf("diagnostics = %+v, want one memory drop and nothing retained", d)
	}
}

func TestConnectionsSpendSharedMemoryUntilClosed(t *testing.T) {
	var received atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		received.Add(1)
	}))
	defer receiver.Close()
	var spent atomic.Int64
	export := func(budget int64) Diagnostics {
		e := New(context.Background(), Options{Local: true, NewLease: func() Lease { return &budgetLease{spent: &spent, budget: budget} }})
		e.Start(testConfig(receiver.URL), "id", Trace{}).Finish("id", "success", testRecord("id"), testMetadata())
		await(t, func() bool { return e.Diagnostics().PendingDeliveries == 0 })
		// The finished record is released; only the idle connection stays charged.
		if budget > connectionBytes && spent.Load() != connectionBytes {
			t.Fatalf("idle connection charge = %d", spent.Load())
		}
		e.Close()
		if spent.Load() != 0 {
			t.Fatalf("closed exporter kept %d bytes", spent.Load())
		}
		return e.Diagnostics()
	}
	// The record fits, but its connection does not.
	if d := export(16384 + deliveryStateBytes); received.Load() != 0 || d.MemoryDropped != 1 || d.Failed != 0 {
		t.Fatalf("connection opened without memory: %+v", d)
	}
	if d := export(1 << 20); received.Load() != 1 || d.Delivered != 1 {
		t.Fatalf("charged connection did not deliver: %+v", d)
	}
}

// Only OTLP's transient statuses and network failures earn the one retry.
func TestRetryPolicyAndNoRedirect(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	t.Run("cases", func(t *testing.T) { retryCases(t, target.URL) })
	if redirected.Load() != 0 {
		t.Fatal("followed credential-bearing redirect")
	}
}

func retryCases(t *testing.T, target string) {
	for _, tc := range []struct {
		first, second     int
		retryAfter        string
		attempts          int32
		delivered         bool
		dropConnectionFor bool
	}{
		{first: 200, attempts: 1, delivered: true},
		{first: 204, attempts: 1, delivered: true},
		{first: 302, attempts: 1},
		{first: 400, attempts: 1},
		{first: 401, attempts: 1},
		{first: 500, attempts: 1},
		{first: 429, second: 202, retryAfter: "0", attempts: 2, delivered: true},
		{first: 503, second: 503, retryAfter: "0", attempts: 2},
		{first: 502, second: 200, retryAfter: time.Now().UTC().Format(http.TimeFormat), attempts: 2, delivered: true},
		// A receiver delay past the delivery window ends the record without waiting.
		{first: 504, retryAfter: "120", attempts: 1},
		{dropConnectionFor: true, second: 200, attempts: 2, delivered: true},
	} {
		t.Run(fmt.Sprintf("%d-%d-%v", tc.first, tc.second, tc.dropConnectionFor), func(t *testing.T) {
			t.Parallel()
			var attempts atomic.Int32
			var keys sync.Map
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				keys.Store(r.Header.Get("Idempotency-Key"), true)
				status := tc.second
				if attempts.Add(1) == 1 {
					if tc.dropConnectionFor {
						conn, _, _ := w.(http.Hijacker).Hijack()
						conn.Close()
						return
					}
					status = tc.first
				}
				w.Header().Set("Location", target)
				w.Header().Set("Retry-After", tc.retryAfter)
				w.WriteHeader(status)
			}))
			defer receiver.Close()
			e := New(context.Background(), testOptions(true, connectionBytes))
			e.Start(testConfig(receiver.URL), "id", Trace{}).Finish("id", "success", testRecord("id"), testMetadata())
			await(t, func() bool { return e.Diagnostics().PendingDeliveries == 0 })
			e.Close()
			d := e.Diagnostics()
			if attempts.Load() != tc.attempts || d.Retried != uint64(tc.attempts-1) || (d.Delivered == 1) != tc.delivered || (d.Failed == 1) == tc.delivered || d.ReservedBytes != 0 {
				t.Fatalf("attempts %d, diagnostics %+v", attempts.Load(), d)
			}
			if _, ok := keys.Load("id"); !ok {
				t.Fatal("missing idempotency key")
			}
		})
	}
}

func TestSlowReceiverDoesNotDelayOtherDestinations(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer fast.Close()
	e := New(context.Background(), testOptions(true, 1<<20))
	defer e.Close()
	defer close(release)
	for i := range 4 * maxConnsPerHost {
		e.Start(testConfig(slow.URL), "id", Trace{}).Finish(fmt.Sprint("slow", i), "success", testRecord("slow"), testMetadata())
	}
	for i := range 20 {
		e.Start(testConfig(fast.URL), "id", Trace{}).Finish(fmt.Sprint("fast", i), "success", testRecord("fast"), testMetadata())
	}
	// Wait for the exporter's own count: the receiver sees a request before its response is recorded.
	await(t, func() bool { return e.Diagnostics().Delivered == 20 })
	if d := e.Diagnostics(); d.PendingDeliveries != 4*maxConnsPerHost {
		t.Fatalf("slow receiver blocked others: %+v", d)
	}
}

// Inference reclaims finished records immediately, including during an upload.
func TestReclaimReleasesOldestRecordsFirst(t *testing.T) {
	uploading := make(chan struct{}, 8)
	done := make(chan struct{})
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadFull(r.Body, make([]byte, 1024))
		uploading <- struct{}{}
		<-done
	}))
	defer receiver.Close()
	e := New(context.Background(), testOptions(true, 64<<20))
	defer e.Close()
	defer close(done)
	reserved := make([]int64, 3)
	for i := range reserved {
		before := e.Diagnostics().ReservedBytes
		c := e.Start(testConfig(receiver.URL), "id", Trace{})
		c.Input(map[string]json.RawMessage{"input": json.RawMessage(`"` + strings.Repeat("x", 16<<20) + `"`)}, true)
		c.Finish(fmt.Sprint(i), "success", testRecord(fmt.Sprint(i)), testMetadata())
		reserved[i] = e.Diagnostics().ReservedBytes - before
		<-uploading
	}
	if freed := e.Reclaim(1); freed != reserved[0] || e.Diagnostics().ReservedBytes != reserved[1]+reserved[2] {
		t.Fatalf("reclaimed %d of %v, diagnostics %+v", freed, reserved, e.Diagnostics())
	}
	if freed := e.Reclaim(reserved[1] + 1); freed != reserved[1]+reserved[2] || e.Diagnostics().ReservedBytes != 0 {
		t.Fatalf("reclaimed %d, diagnostics %+v", freed, e.Diagnostics())
	}
	await(t, func() bool { return e.Diagnostics().PendingDeliveries == 0 })
	if d := e.Diagnostics(); d.MemoryDropped != 3 || d.Failed != 0 || d.Delivered != 0 || e.Reclaim(1) != 0 {
		t.Fatalf("reclaimed deliveries: %+v", d)
	}
}

func TestConcurrentDeliveryAndShutdownRelease(t *testing.T) {
	release := make(chan struct{})
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer receiver.Close()
	defer close(release)
	e := New(context.Background(), testOptions(true, connectionBytes))
	config := testConfig(receiver.URL)
	var workers sync.WaitGroup
	for w := range 6 {
		workers.Add(1)
		go func(w int) {
			defer workers.Done()
			for i := range 120 {
				e.Start(config, "id", Trace{}).Finish(fmt.Sprint(w, i), "success", testRecord(fmt.Sprint(w, i)), testMetadata())
			}
		}(w)
	}
	workers.Wait()
	e.cancel()
	for range 3 {
		workers.Add(1)
		go func() { defer workers.Done(); e.Close() }()
	}
	workers.Wait()
	if d := e.Diagnostics(); d.PendingDeliveries != 0 || d.ReservedBytes != 0 || d.Failed != 720 || e.Start(config, "id", Trace{}).Active() {
		t.Fatalf("shutdown leak: %+v", d)
	}
}

func TestHTTPSCertificateValidationAndPublicNetworkBoundary(t *testing.T) {
	var received atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
	}))
	defer receiver.Close()
	for _, tc := range []struct{ local, trust, want bool }{{true, true, true}, {true, false, false}, {false, true, false}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			e := New(context.Background(), testOptions(tc.local, 16<<20))
			defer e.Close()
			if tc.trust {
				roots := x509.NewCertPool()
				roots.AddCert(receiver.Certificate())
				e.client.transport.TLSClientConfig.RootCAs = roots
			}
			e.Start(testConfig(receiver.URL), "id", Trace{}).Finish("id", "success", testRecord("id"), testMetadata())
			await(t, func() bool { return e.Diagnostics().PendingDeliveries == 0 })
			if (e.Diagnostics().Delivered == 1) != tc.want {
				t.Fatalf("TLS delivery %+v", e.Diagnostics())
			}
		})
	}
	if received.Load() != 1 {
		t.Fatalf("invalid TLS/private request reached receiver: %d", received.Load())
	}
}

func TestHTTPEarlyRejectionReleasesRequestBody(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%v", http2), func(t *testing.T) {
			receiver := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if (r.ProtoMajor == 2) != http2 {
					t.Error("wrong HTTP protocol")
				}
				// Reject credentials before reading a potentially large upload.
				w.WriteHeader(http.StatusUnauthorized)
			}))
			receiver.EnableHTTP2 = http2
			receiver.StartTLS()
			defer receiver.Close()
			e := New(context.Background(), testOptions(true, 1))
			defer e.Close()
			roots := x509.NewCertPool()
			roots.AddCert(receiver.Certificate())
			e.client.transport.TLSClientConfig.RootCAs = roots
			for range 32 {
				body := []byte(strings.Repeat("x", 2<<20))
				r := &record{ctx: context.Background(), cancel: func() {}, requestID: "id", reservation: &reservation{engine: e, lease: &testLease{}}}
				r.payloads[formJSONContent] = payload{parts: [][]byte{body}, size: int64(len(body))}
				result := e.client.send(context.Background(), destination{Destination: testConfig(receiver.URL).Destinations[0], content: true}, r)
				// The last delivery can erase the payload while the transport still reads.
				r.release()
				if result.delivered || result.retryable {
					t.Fatal("authentication rejection accepted or retried")
				}
			}
		})
	}
}

// Receivers are customer controlled. Their responses must not hold memory,
// stretch delivery past its lifetime, or follow requests elsewhere.
func TestHostileReceiverResponsesStayBounded(t *testing.T) {
	for _, tc := range []struct {
		name      string
		respond   func(http.ResponseWriter)
		attempts  int32
		delivered bool
	}{
		{name: "endless body", attempts: 1, delivered: true, respond: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusOK)
			for range 1 << 12 {
				if _, err := w.Write(make([]byte, 1<<10)); err != nil {
					return
				}
			}
		}},
		{name: "oversized headers", attempts: maxAttempts, respond: func(w http.ResponseWriter) {
			w.Header().Set("X-Large", strings.Repeat("x", 2*responseLimit))
			w.WriteHeader(http.StatusOK)
		}},
		// A wait longer than the delivery's lifetime ends it, as one past the lifetime does,
		// and never wraps around to retry at once.
		{name: "overflowing Retry-After", attempts: 1, respond: func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "99999999999999999999")
			w.WriteHeader(http.StatusServiceUnavailable)
		}},
		{name: "Retry-After past lifetime", attempts: 1, respond: func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusTooManyRequests)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var attempts atomic.Int32
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				attempts.Add(1)
				tc.respond(w)
			}))
			defer receiver.Close()
			e := New(context.Background(), testOptions(true, connectionBytes))
			defer e.Close()
			e.Start(testConfig(receiver.URL), "id", Trace{}).Finish("id", "success", testRecord("id"), testMetadata())
			await(t, func() bool { return e.Diagnostics().PendingDeliveries == 0 })
			if d := e.Diagnostics(); attempts.Load() != tc.attempts || (d.Delivered == 1) != tc.delivered || d.ReservedBytes != 0 {
				t.Fatalf("attempts %d, diagnostics %+v", attempts.Load(), d)
			}
		})
	}
}

func TestHostedDeliveryRejectsLoopbackHostnames(t *testing.T) {
	var received atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer receiver.Close()
	e := New(context.Background(), testOptions(false, connectionBytes))
	defer e.Close()
	roots := x509.NewCertPool()
	roots.AddCert(receiver.Certificate())
	e.client.transport.TLSClientConfig.RootCAs = roots
	url := strings.Replace(receiver.URL, "127.0.0.1", "localhost", 1)
	e.Start(testConfig(url), "id", Trace{}).Finish("id", "success", testRecord("id"), testMetadata())
	await(t, func() bool { return e.Diagnostics().PendingDeliveries == 0 })
	if received.Load() != 0 || e.Diagnostics().Delivered != 0 {
		t.Fatal("hosted delivery reached a loopback receiver through its hostname")
	}
}

// A retry must not wait on an HTTP/2 connection that stopped answering.
func TestDeliveryChecksItsHTTP2Connections(t *testing.T) {
	client := newDeliveryClient(false, testOptions(false, 1<<20).NewLease)
	defer client.close()
	if client.transport.HTTP2 == nil || client.transport.HTTP2.SendPingTimeout == 0 {
		t.Fatal("export delivery does not check its HTTP/2 connections")
	}
}

// A held export keeps admission for its destinations and response alone
// until it leaves, then sends what its capture would have sent. Delivery
// state is admitted again when it leaves, so memory pressure or a closed
// exporter then drops it whole.
func TestHeldExportKeepsOnlyWhatItSendsLater(t *testing.T) {
	received := make(chan map[string]json.RawMessage, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Idempotency-Key") != "first-repeat" || r.Header.Get("Authorization") != "Bearer receiver" {
			t.Error("wrong headers")
		}
		var record map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
			t.Error(err)
		}
		received <- record
	}))
	defer receiver.Close()
	config := testConfig(receiver.URL)
	config.Destinations[0].Headers = map[string]string{"Authorization": "Bearer receiver"}
	response := []byte(`{"error":{"message":"Add credit to continue.","type":"insufficient_balance","code":"insufficient_balance","param":null}}`)
	kept := int64(len(response) + len(receiver.URL) + len("Authorization") + len("Bearer receiver"))
	started := kept - int64(len(response)) + deliveryStateBytes
	spent := &atomic.Int64{}
	budget := func(bytes int64) Options {
		return Options{Local: true, NewLease: func() Lease { return &budgetLease{spent: spent, budget: bytes} }}
	}
	hold := func(e *Engine) *Held {
		t.Helper()
		c := e.Start(config, "id", Trace{})
		c.Response(response)
		held := c.Hold()
		if held == nil || c.Active() {
			t.Fatal("holding must end the capture and keep its export")
		}
		if got := e.Diagnostics().ReservedBytes; got != kept {
			t.Fatalf("a held export reserves %d bytes, want %d", got, kept)
		}
		return held
	}

	e := New(context.Background(), budget(1<<30))
	defer e.Close()
	hold(e).Finish("first-repeat", "success", map[string]any{"request_id": "first-repeat", "request_count": 6}, testMetadata())
	record := <-received
	if string(record["request_count"]) != "6" || string(record["request"]) != "null" || string(record["response"]) != string(response) || string(record["stogas"]) != string(testMetadata()) {
		t.Fatalf("held record: %s", record)
	}
	await(t, func() bool { d := e.Diagnostics(); return d.Delivered == 1 && d.ReservedBytes == 0 })
	hold(e).Discard()
	if d := e.Diagnostics(); d.ReservedBytes != 0 {
		t.Fatalf("a discarded export kept memory: %+v", d)
	}
	if e.Start(&exportconfig.Config{}, "id", Trace{}).Hold() != nil {
		t.Fatal("a capture without destinations holds nothing")
	}

	// Another capture takes the memory that delivery state needs.
	spent.Store(0)
	pressed := New(context.Background(), budget(kept+started+deliveryStateBytes/2))
	defer pressed.Close()
	held := hold(pressed)
	other := pressed.Start(config, "id", Trace{})
	held.Finish("first-repeat", "success", testRecord("first-repeat"), testMetadata())
	if d := pressed.Diagnostics(); d.MemoryDropped != 1 || d.ReservedBytes != started || d.PendingDeliveries != 0 {
		t.Fatalf("memory pressure: %+v", d)
	}
	other.Discard()

	closed := New(context.Background(), testOptions(true, 1<<20))
	held = hold(closed)
	closed.Close()
	held.Finish("first-repeat", "success", testRecord("first-repeat"), testMetadata())
	if d := closed.Diagnostics(); d.Failed != 1 || d.ReservedBytes != 0 {
		t.Fatalf("closed exporter: %+v", d)
	}
}

// requestAt finds a request ID whose sample position is inside [low, high).
func requestAt(t *testing.T, low, high float64) string {
	t.Helper()
	for i := range 100_000 {
		id := fmt.Sprintf("01a14a2c-7ee1-7ad7-bbf6-%012x", i)
		if position := exportconfig.Position(id); position >= low && position < high {
			return id
		}
	}
	t.Fatalf("no request ID between %v and %v", low, high)
	return ""
}

// Each destination gets the records that its sample chooses for the way the
// request ended: all of them, a share, some outcomes, or a share per outcome.
// Its content chooses in the same way which of them carry bodies.
func TestSampleChoosesRecordsByRequestAndOutcome(t *testing.T) {
	var mu sync.Mutex
	received := map[string]map[string]bool{}
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var record map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
			t.Error(err)
		}
		_, content := record["request"]
		key := r.Header.Get("Idempotency-Key")
		want := r.URL.Path != "/mixed"
		if r.URL.Path == "/failure-bodies" {
			// The ID ends in the request's number, which sets its outcome below.
			number, err := strconv.ParseInt(key[len(key)-12:], 16, 64)
			if err != nil {
				t.Error(err)
			}
			outcome := exportconfig.Outcomes[number%int64(len(exportconfig.Outcomes))]
			want = outcome == "failed" || outcome == "rejected"
		}
		if content != want {
			t.Errorf("%s got content for %s: %v", r.URL.Path, key, content)
		}
		mu.Lock()
		defer mu.Unlock()
		if received[r.URL.Path] == nil {
			received[r.URL.Path] = map[string]bool{}
		}
		if received[r.URL.Path][key] {
			t.Errorf("%s got %s twice", r.URL.Path, key)
		}
		received[r.URL.Path][key] = true
	}))
	defer receiver.Close()
	off := exportconfig.Content{}
	samples := map[string]*exportconfig.Sample{
		"/every":    nil,
		"/tenth":    {0.1, 0.1, 0.1, 0.1, 0.1},
		"/failures": {0, 1, 0, 1, 0},
		"/mixed":    {0.2, 1, 0, 0, 0.5},
		// Every record, with bodies for failures and rejections only.
		"/failure-bodies": nil,
	}
	config := &exportconfig.Config{}
	for path, sample := range samples {
		d := exportconfig.Destination{URL: receiver.URL + path, Sample: sample}
		switch path {
		case "/mixed":
			d.Content = &off
		case "/failure-bodies":
			d.Content = &exportconfig.Content{0, 1, 0, 1, 0}
		}
		config.Destinations = append(config.Destinations, d)
	}
	e := New(context.Background(), testOptions(true, 64<<20))
	want := map[string]map[string]bool{}
	deliveries := 0
	for i := range 240 {
		outcome := exportconfig.Outcomes[i%len(exportconfig.Outcomes)]
		id := fmt.Sprintf("01a14a2c-7ee1-7ad7-bbf6-%012x", i)
		position := exportconfig.Position(id)
		for _, d := range config.Destinations {
			path := strings.TrimPrefix(d.URL, receiver.URL)
			if want[path] == nil {
				want[path] = map[string]bool{}
			}
			if position < d.Rate(outcome) {
				want[path][id], deliveries = true, deliveries+1
			}
		}
		c := e.Start(config, id, Trace{})
		c.Input(map[string]json.RawMessage{"input": json.RawMessage(`"prompt"`)}, true)
		c.Response([]byte(`{"output":"answer"}`))
		if !c.Due(outcome) {
			t.Fatalf("%s %s: the record is due, because one destination gets every record", id, outcome)
		}
		c.Finish(id, outcome, testRecord(id), testMetadata())
	}
	e.Close()
	if !reflect.DeepEqual(received, want) {
		for path := range samples {
			t.Errorf("%s got %d records, want %d", path, len(received[path]), len(want[path]))
		}
		t.FailNow()
	}
	if len(want["/tenth"]) == 0 || len(want["/tenth"]) == 240 || len(want["/failures"]) != 96 || len(want["/every"]) != 240 {
		t.Fatalf("the test's requests do not exercise the samples: %d, %d, %d", len(want["/tenth"]), len(want["/failures"]), len(want["/every"]))
	}
	if d := e.Diagnostics(); d.Delivered != uint64(deliveries) || d.Failed != 0 || d.MemoryDropped != 0 || d.ReservedBytes != 0 || d.PendingDeliveries != 0 {
		t.Fatalf("diagnostics = %+v, want %d deliveries and nothing else", d, deliveries)
	}
}

// A request whose position no destination's sample reaches has no capture, so
// it copies nothing and its record says nothing of export. A capture that
// started ends without a record when the request's outcome is not one that a
// destination gets, and counts as neither a failure nor a drop.
func TestRecordsThatNoDestinationGetsCostNothing(t *testing.T) {
	var received atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer receiver.Close()
	e := New(context.Background(), testOptions(true, 16<<20))
	defer e.Close()
	off := exportconfig.Content{}
	inside, outside := requestAt(t, 0, 0.1), requestAt(t, 0.3, 1)
	tenth := &exportconfig.Config{Destinations: []exportconfig.Destination{{URL: receiver.URL, Sample: &exportconfig.Sample{0.1, 0.1, 0.1, 0.1, 0.1}}}}

	c := e.Start(tenth, outside, Trace{})
	if c != nil || c.Active() || c.Duration() != nil || c.Hold() != nil || e.Diagnostics().ReservedBytes != 0 {
		t.Fatalf("a request outside every sample started a capture: %+v", e.Diagnostics())
	}
	for _, outcome := range exportconfig.Outcomes {
		if c.Due(outcome) {
			t.Fatalf("a request outside every sample is due a %s record", outcome)
		}
	}
	// The calls of a request's whole life are safe without a capture.
	c.Input(map[string]json.RawMessage{"input": json.RawMessage(`"prompt"`)}, true)
	c.Event([]byte(`{}`))
	c.Finish(outside, "success", testRecord(outside), testMetadata())
	c.Discard()

	// The highest rate of any outcome decides whether the request starts a capture.
	successes := &exportconfig.Config{Destinations: []exportconfig.Destination{{URL: receiver.URL, Sample: &exportconfig.Sample{0.3, 0, 0, 0, 0}}}}
	if e.Start(successes, outside, Trace{}) != nil {
		t.Fatal("a request outside the highest rate started a capture")
	}
	c = e.Start(successes, inside, Trace{})
	c.Input(map[string]json.RawMessage{"input": json.RawMessage(`"prompt"`)}, true)
	c.Response([]byte(`{"error":{}}`))
	if !c.Active() || !c.Due("success") || c.Due("failed") || c.Due("rejected") || c.Due("cancelled") || c.Due("unknown") || c.Due("") {
		t.Fatal("the capture is due only the outcome that its destination gets")
	}
	c.Finish(inside, "failed", testRecord(inside), testMetadata())
	if d := e.Diagnostics(); d.ReservedBytes != 0 || d.PendingDeliveries != 0 || d.Failed != 0 || d.MemoryDropped != 0 || c.Active() {
		t.Fatalf("an outcome that no destination gets left something behind: %+v", d)
	}

	// Content is copied only for a destination that can get it. Here the one that sends
	// content samples a tenth, and the request is outside it.
	mixed := &exportconfig.Config{Destinations: []exportconfig.Destination{
		{URL: receiver.URL + "/content", Sample: &exportconfig.Sample{0.1, 0.1, 0.1, 0.1, 0.1}},
		{URL: receiver.URL + "/metadata", Content: &off},
	}}
	c = e.Start(mixed, outside, Trace{})
	reserved := e.Diagnostics().ReservedBytes
	c.Input(map[string]json.RawMessage{"input": json.RawMessage(`"` + strings.Repeat("prompt ", 4096) + `"`)}, true)
	if c == nil || c.Active() || e.Diagnostics().ReservedBytes != reserved || reserved >= 2*deliveryStateBytes {
		t.Fatalf("a request outside the content destination's sample copied content or reserved its delivery: %+v", e.Diagnostics())
	}
	c.Finish(outside, "success", testRecord(outside), testMetadata())
	if both := e.Start(mixed, inside, Trace{}); !both.Active() {
		t.Fatal("a request inside the content destination's sample copies content")
	} else {
		both.Finish(inside, "success", testRecord(inside), testMetadata())
	}
	await(t, func() bool { return e.Diagnostics().Delivered == 3 })
	if d := e.Diagnostics(); received.Load() != 3 || d.ReservedBytes != 0 || d.Failed != 0 {
		t.Fatalf("diagnostics = %+v, received %d", d, received.Load())
	}

	// A capture that memory refused still says whether its record was due, so that the
	// request record marks only records that a destination should hold.
	pressed := New(context.Background(), testOptions(true, deliveryStateBytes))
	defer pressed.Close()
	failures := &exportconfig.Config{Destinations: []exportconfig.Destination{
		{URL: receiver.URL, Sample: &exportconfig.Sample{0, 1, 0, 1, 0}},
		{URL: receiver.URL + "/tenth", Sample: &exportconfig.Sample{0.1, 0.1, 0.1, 0.1, 0.1}},
	}}
	c = pressed.Start(failures, outside, Trace{})
	if c == nil || c.held() || !c.Due("failed") || !c.Due("rejected") || c.Due("success") || *c.Duration() != 0 {
		t.Fatalf("dropped capture = %+v", c)
	}
	// Only the destination that the request reaches counts as dropped.
	if d := pressed.Diagnostics(); d.MemoryDropped != 1 || d.ReservedBytes != 0 {
		t.Fatalf("diagnostics = %+v", d)
	}
}

// A rejection's export waits for the record that holds it, and leaves only for
// the destinations that get rejections.
func TestHeldExportFollowsTheSample(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path+" "+r.Header.Get("Idempotency-Key"))
		mu.Unlock()
	}))
	defer receiver.Close()
	inside, outside := requestAt(t, 0, 0.5), requestAt(t, 0.5, 1)
	config := &exportconfig.Config{Destinations: []exportconfig.Destination{
		{URL: receiver.URL + "/successes", Sample: &exportconfig.Sample{1, 0, 0, 0, 0}},
		{URL: receiver.URL + "/rejections", Sample: &exportconfig.Sample{0, 0, 0, 0.5, 0}},
	}}
	e := New(context.Background(), testOptions(true, 16<<20))
	for _, id := range []string{inside, outside} {
		c := e.Start(config, id, Trace{})
		c.Response([]byte(`{"error":{}}`))
		held := c.Hold()
		if held == nil {
			t.Fatal("the capture holds its export")
		}
		held.Finish(id, "rejected", testRecord(id), testMetadata())
		held.Finish(id, "rejected", testRecord(id), testMetadata())
	}
	e.Close()
	if d := e.Diagnostics(); !slices.Equal(paths, []string{"/rejections " + inside}) || d.Delivered != 1 || d.Failed != 0 || d.MemoryDropped != 0 || d.ReservedBytes != 0 {
		t.Fatalf("deliveries = %v, diagnostics = %+v", paths, d)
	}
}

// A remote MCP tool's credentials reach the provider but never an export, including a token
// in the server URL's user information, path or query.
func TestCapturedInputOmitsToolCredentials(t *testing.T) {
	e := New(context.Background(), testOptions(true, 16<<20))
	defer e.Close()
	c := e.Start(testConfig("https://example.com/webhook"), "id", Trace{})
	defer c.Discard()
	tools := json.RawMessage(`[{"type":"mcp","server_label":"wiki","server_url":"https://user:pass@mcp.example.com:8443/s/path-secret/mcp?api_key=query-secret#x","authorization":"token-secret","headers":{"X-Api-Key":"header-secret"}},{"type":"mcp","server_label":"odd","server_url":"not a url"},{"type":"function","name":"lookup"}]`)
	body := map[string]json.RawMessage{"input": json.RawMessage(`"hi"`), "tools": tools}
	c.Input(body, true)
	if string(body["tools"]) != string(tools) {
		t.Fatal("capture changed the request that the provider receives")
	}
	var captured struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(c.request, &captured); err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"type": "mcp", "server_label": "wiki", "server_url": "https://mcp.example.com:8443", "authorization": "[omitted]", "headers": map[string]any{"X-Api-Key": "[omitted]"}},
		{"type": "mcp", "server_label": "odd", "server_url": "[omitted]"},
		{"type": "function", "name": "lookup"},
	}
	if !reflect.DeepEqual(captured.Tools, want) {
		t.Fatalf("captured tools = %#v", captured.Tools)
	}

	plain := json.RawMessage(`[{"type":"function","name":"lookup"}]`)
	if got, ok := omitToolCredentials(plain); !ok || string(got) != string(plain) {
		t.Fatalf("tools without credentials changed: %s", got)
	}
	if _, ok := omitToolCredentials(json.RawMessage(`{"type":"mcp","authorization":"token-secret"}`)); ok {
		t.Fatal("unreadable tools were kept")
	}
}
