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
func testOptions(local bool, limit int) Options {
	return Options{Local: local, NewLease: func() Lease { return &testLease{limit: limit} }}
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
			c := e.Start(config)
			config.Destinations[0].Headers["Authorization"] = "changed"
			message, _ := json.Marshal(strings.Repeat("large prompt 世界 ", 65536))
			body := map[string]json.RawMessage{"input": message, "temperature": json.RawMessage(`0.25`), "tools": json.RawMessage(`[{"type":"custom","name":"freeform"}]`)}
			c.Input(body)
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
			c.Finish("record", testRecord("record"), testMetadata())
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

func TestMemoryPressureDropsWholeCapture(t *testing.T) {
	var received atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer receiver.Close()
	e := New(context.Background(), testOptions(true, 8192+deliveryStateBytes))
	defer e.Close()
	c := e.Start(testConfig(receiver.URL))
	c.Input(map[string]json.RawMessage{"model": json.RawMessage(`"model"`)})
	c.Event([]byte(`{"delta":"hello"}`))
	c.Event([]byte(`{"delta":"` + strings.Repeat("x", 8192) + `"}`))
	c.Finish("dropped", testRecord("dropped"), testMetadata())
	e.Close()
	if d := e.Diagnostics(); received.Load() != 0 || d.MemoryDropped != 1 || d.ReservedBytes != 0 {
		t.Fatalf("partial export or leak: %+v", d)
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
			e := New(context.Background(), testOptions(true, 16384+deliveryStateBytes))
			e.Start(testConfig(receiver.URL)).Finish("id", testRecord("id"), testMetadata())
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
	var fastReceived atomic.Int32
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fastReceived.Add(1) }))
	defer fast.Close()
	e := New(context.Background(), testOptions(true, 1<<20))
	defer e.Close()
	defer close(release)
	for i := range 4 * maxConnsPerHost {
		e.Start(testConfig(slow.URL)).Finish(fmt.Sprint("slow", i), testRecord("slow"), testMetadata())
	}
	for i := range 20 {
		e.Start(testConfig(fast.URL)).Finish(fmt.Sprint("fast", i), testRecord("fast"), testMetadata())
	}
	await(t, func() bool { return fastReceived.Load() == 20 })
	if d := e.Diagnostics(); d.PendingDeliveries != 4*maxConnsPerHost || d.Delivered != 20 {
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
		c := e.Start(testConfig(receiver.URL))
		c.Input(map[string]json.RawMessage{"input": json.RawMessage(`"` + strings.Repeat("x", 16<<20) + `"`)})
		c.Finish(fmt.Sprint(i), testRecord(fmt.Sprint(i)), testMetadata())
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
	e := New(context.Background(), testOptions(true, 16384+deliveryStateBytes))
	config := testConfig(receiver.URL)
	var workers sync.WaitGroup
	for w := range 6 {
		workers.Add(1)
		go func(w int) {
			defer workers.Done()
			for i := range 120 {
				e.Start(config).Finish(fmt.Sprint(w, i), testRecord(fmt.Sprint(w, i)), testMetadata())
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
	if d := e.Diagnostics(); d.PendingDeliveries != 0 || d.ReservedBytes != 0 || d.Failed != 720 || e.Start(config) != nil {
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
			e.Start(testConfig(receiver.URL)).Finish("id", testRecord("id"), testMetadata())
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
				payload := []byte(strings.Repeat("x", 2<<20))
				r := &record{ctx: context.Background(), cancel: func() {}, requestID: "id", size: int64(len(payload)), parts: [][]byte{payload}, reservation: &reservation{engine: e, lease: &testLease{}}}
				result := e.client.send(context.Background(), testConfig(receiver.URL).Destinations[0], r)
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
		{name: "overflowing Retry-After", attempts: maxAttempts, respond: func(w http.ResponseWriter) {
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
			e := New(context.Background(), testOptions(true, 16384+deliveryStateBytes))
			defer e.Close()
			e.Start(testConfig(receiver.URL)).Finish("id", testRecord("id"), testMetadata())
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
	e := New(context.Background(), testOptions(false, 16384+deliveryStateBytes))
	defer e.Close()
	roots := x509.NewCertPool()
	roots.AddCert(receiver.Certificate())
	e.client.transport.TLSClientConfig.RootCAs = roots
	url := strings.Replace(receiver.URL, "127.0.0.1", "localhost", 1)
	e.Start(testConfig(url)).Finish("id", testRecord("id"), testMetadata())
	await(t, func() bool { return e.Diagnostics().PendingDeliveries == 0 })
	if received.Load() != 0 || e.Diagnostics().Delivered != 0 {
		t.Fatal("hosted delivery reached a loopback receiver through its hostname")
	}
}
