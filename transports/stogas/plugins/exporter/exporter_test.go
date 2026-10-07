package exporter

import (
	"compress/gzip"
	"context"
	"crypto/x509"
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

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

func testRecord(id string) Record {
	return Record{RequestID: id, Model: "model", Provider: "openai", RequestType: "chat_completion", StartedAt: time.Unix(1700000000, 0), EndedAt: time.Unix(1700000001, 0), Outcome: "success", CostUSD: "0.001", InputTokens: ptr(int64(7)), OutputTokens: ptr(int64(3)), Metadata: `{"request_id":"` + id + `"}`}
}
func ptr[T any](v T) *T { return &v }
func testConfig(url string) *exportconfig.Config {
	return &exportconfig.Config{Destinations: []exportconfig.Destination{{URL: url, Content: "both", MaxRetries: ptr(0)}}}
}
func oneSpan(t *testing.T, traces ptrace.Traces) ptrace.Span {
	t.Helper()
	if traces.SpanCount() != 1 {
		t.Fatalf("span count %d", traces.SpanCount())
	}
	return traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
}
func attribute(span ptrace.Span, name string) string {
	v, _ := span.Attributes().Get(name)
	return v.AsString()
}
func input(c *Capture, value string) {
	c.Input(&schemas.BifrostRequest{ChatRequest: &schemas.BifrostChatRequest{Input: []schemas.ChatMessage{{Role: "user", Content: &schemas.ChatMessageContent{ContentStr: ptr(value)}}}}})
}
func delta(c *Capture, content string) {
	c.Chunk(&schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{Index: 0, ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &schemas.ChatStreamResponseChoiceDelta{Content: ptr(content)}}}}}})
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

func TestHTTPBatchInteroperability(t *testing.T) {
	for _, encoding := range []string{"json", "protobuf"} {
		t.Run(encoding, func(t *testing.T) {
			var mu sync.Mutex
			var received []ptrace.Traces
			var bodyJSON []byte
			receiver := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/custom/v1/traces" || r.Header.Get("Authorization") != "Bearer customer-secret" {
					t.Error("wrong destination URL/method/auth")
				}
				if encoding == "protobuf" && r.ProtoMajor != 2 {
					t.Error("protobuf TLS export did not negotiate HTTP/2")
				}
				raw := readExportBody(t, r)
				request := ptraceotlp.NewExportRequest()
				var err error
				if encoding == "json" {
					if r.Header.Get("Content-Type") != "application/json" {
						t.Error("content type")
					}
					err = request.UnmarshalJSON(raw)
				} else {
					if r.Header.Get("Content-Type") != "application/x-protobuf" {
						t.Error("content type")
					}
					err = request.UnmarshalProto(raw)
				}
				if err != nil {
					t.Error(err)
				}
				mu.Lock()
				received = append(received, request.Traces())
				bodyJSON, _ = request.MarshalJSON()
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{}`)
			}))
			if encoding == "protobuf" {
				receiver.EnableHTTP2 = true
				receiver.StartTLS()
			} else {
				receiver.Start()
			}
			defer receiver.Close()
			engine := New(context.Background(), Options{Local: true})
			defer engine.Close()
			if encoding == "protobuf" {
				roots := x509.NewCertPool()
				roots.AddCert(receiver.Certificate())
				engine.client.transport.TLSClientConfig.RootCAs = roots
			}
			config := testConfig(receiver.URL + "/custom/v1/traces")
			config.Destinations[0].Encoding = encoding
			config.Destinations[0].Headers = map[string]string{"Authorization": "Bearer customer-secret"}
			for i := range 3 {
				c := engine.Start("org", fmt.Sprint(i), config)
				input(c, "Hello 世界")
				delta(c, "Good ")
				delta(c, "day")
				c.Finish(testRecord(fmt.Sprint(i)))
			}
			await(t, func() bool { return engine.Diagnostics().Delivered == 3 })
			mu.Lock()
			defer mu.Unlock()
			if len(received) != 1 || received[0].SpanCount() != 3 {
				t.Fatalf("expected one batch with three spans: %d batches", len(received))
			}
			span := received[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
			if got := attribute(span, "gen_ai.output.messages"); got != `[{"role":"assistant","parts":[{"content":"Good day","type":"text"}],"finish_reason":"unknown"}]` {
				t.Fatalf("output %s", got)
			}
			if got := attribute(span, "gen_ai.input.messages"); got != `[{"role":"user","parts":[{"content":"Hello 世界","type":"text"}]}]` {
				t.Fatalf("input %s", got)
			}
			if !span.StartTimestamp().AsTime().Equal(testRecord("").StartedAt) || !span.EndTimestamp().AsTime().Equal(testRecord("").EndedAt) {
				t.Fatal("timestamps")
			}
			var wire struct {
				ResourceSpans []struct {
					ScopeSpans []struct {
						Spans []struct {
							TraceID string `json:"traceId"`
							SpanID  string `json:"spanId"`
							Start   string `json:"startTimeUnixNano"`
						} `json:"spans"`
					} `json:"scopeSpans"`
				} `json:"resourceSpans"`
			}
			if json.Unmarshal(bodyJSON, &wire) != nil {
				t.Fatal("JSON")
			}
			s := wire.ResourceSpans[0].ScopeSpans[0].Spans[0]
			if len(s.TraceID) != 32 || len(s.SpanID) != 16 || s.Start != "1700000000000000000" {
				t.Fatalf("invalid OTLP JSON identifiers/timestamp: %+v", s)
			}
			if strings.Contains(string(bodyJSON), "customer-secret") {
				t.Fatal("credential escaped into trace")
			}
			await(t, func() bool { return engine.Diagnostics().ReservedBytes == 0 })
		})
	}
}

func TestDeliveryAcknowledgementsAndRetries(t *testing.T) {
	for _, tc := range []struct {
		name, format        string
		status              int
		body, contentType   string
		retries             int
		wantAttempts        int
		delivered, rejected uint64
	}{
		{"webhook204", "webhook", 204, "", "", 3, 1, 1, 0},
		{"webhookCustomBody", "webhook", 202, `accepted`, "text/plain", 3, 1, 1, 0},
		{"otlpPartial", "otlp", 200, `{"partialSuccess":{"rejectedSpans":"1","errorMessage":"reject"}}`, "application/json", 3, 1, 0, 1},
		{"otlpWarning", "otlp", 200, `{"partialSuccess":{"errorMessage":"warning"}}`, "application/json", 3, 1, 1, 0},
		{"otlpWrongBody", "otlp", 200, `accepted`, "text/plain", 3, 1, 0, 0},
		{"authentication", "otlp", 401, `secret raw response`, "text/plain", 3, 1, 0, 0},
		{"server500NotRetryable", "otlp", 500, ``, "", 3, 1, 0, 0},
		{"retryDisabled", "otlp", 503, ``, "", 0, 1, 0, 0},
		{"threeRetries", "otlp", 503, ``, "", 3, 4, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			var first []byte
			var mu sync.Mutex
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw := readExportBody(t, r)
				mu.Lock()
				if first == nil {
					first = raw
				} else if string(first) != string(raw) {
					t.Error("retry payload changed")
				}
				mu.Unlock()
				attempts.Add(1)
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer receiver.Close()
			engine := New(context.Background(), Options{Local: true})
			defer engine.Close()
			config := testConfig(receiver.URL)
			config.Destinations[0].Format = tc.format
			config.Destinations[0].MaxRetries = ptr(tc.retries)
			c := engine.Start("org", "id", config)
			input(c, "test")
			c.Finish(testRecord("id"))
			await(t, func() bool { return engine.Diagnostics().PendingRecords == 0 })
			d := engine.Diagnostics()
			if int(attempts.Load()) != tc.wantAttempts || d.Delivered != tc.delivered || d.Rejected != tc.rejected || d.ReservedBytes != 0 {
				t.Fatalf("attempts=%d diagnostics=%+v", attempts.Load(), d)
			}
		})
	}
}

func TestIsolationFilteringSamplingAndMemory(t *testing.T) {
	var mu sync.Mutex
	var counts []int
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := readExportBody(t, r)
		request := ptraceotlp.NewExportRequest()
		if err := request.UnmarshalJSON(raw); err != nil {
			t.Error(err)
		}
		mu.Lock()
		counts = append(counts, request.Traces().SpanCount())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	defer receiver.Close()
	e := New(context.Background(), Options{Local: true})
	defer e.Close()
	config := testConfig(receiver.URL)
	config.Destinations[0].Content = "none"
	for _, org := range []string{"one", "two"} {
		c := e.Start(org, "id", config)
		input(c, strings.Repeat("x", 1<<20))
		if c.input.used != 0 {
			t.Fatal("metadata-only captured input")
		}
		c.Finish(testRecord("id"))
	}
	await(t, func() bool { return e.Diagnostics().Delivered == 2 })
	mu.Lock()
	if len(counts) != 2 || counts[0] != 1 || counts[1] != 1 {
		t.Errorf("cross-tenant batch: %v", counts)
	}
	mu.Unlock()
	config.Destinations[0].SampleRate = ptr(0.0)
	if c := e.Start("one", "id", config); c != nil {
		t.Fatal("zero sampling allocated capture")
	}
	config.Destinations[0].SampleRate = nil
	config.Destinations[0].Outcomes = []string{"failure"}
	c := e.Start("one", "id", config)
	c.Finish(testRecord("id"))
	if e.Diagnostics().PendingRecords != 0 {
		t.Fatal("success escaped failure filter")
	}
	await(t, func() bool { return e.Diagnostics().ReservedBytes == 0 })
	r := e.reserve()
	if !r.grow(memoryLimit) {
		t.Fatal("cannot fill empty budget")
	}
	if e.Start("one", "id", config) != nil {
		t.Fatal("capture admitted over memory limit")
	}
	r.release()
	if d := e.Diagnostics(); d.ReservedBytes != 0 {
		t.Fatalf("leaked reservation %+v", d)
	}
}

func TestCaptureLimitsToolsAndResponsesSnapshots(t *testing.T) {
	e := New(context.Background(), Options{})
	defer e.Close()
	config := testConfig("https://example.com/v1/traces")
	config.Destinations[0].MaxCaptureBytes = ptr(1024)
	c := e.Start("org", "id", config)
	defer c.Discard()
	input(c, strings.Repeat("世界", 2000))
	raw, _, truncated := c.input.encode(1024)
	if !truncated || !json.Valid([]byte(raw)) || c.input.used > 1024 {
		t.Fatalf("limit/UTF8: %s", raw)
	}
	for _, args := range []string{`{"city":`, `"Paris"}`} {
		c.Chunk(&schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &schemas.ChatStreamResponseChoiceDelta{ToolCalls: []schemas.ChatAssistantMessageToolCall{{Index: 0, Function: schemas.ChatAssistantMessageToolCallFunction{Arguments: args}}}}}}}}})
	}
	raw, _, _ = c.output.encode(1024)
	if !strings.Contains(raw, `"arguments":{"city":"Paris"}`) {
		t.Fatalf("tool arguments not assembled: %s", raw)
	}
	c.Discard()
	c = e.Start("org", "responses", testConfig("https://example.com/v1/traces"))
	defer c.Discard()
	for _, s := range []string{`{"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}}`, `{"type":"response.output_text.delta","output_index":0,"delta":"hello"}`, `{"type":"response.output_item.done","output_index":0,"item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}}`, `{"type":"response.completed","response":{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}]}}`} {
		var r schemas.BifrostResponsesStreamResponse
		if err := json.Unmarshal([]byte(s), &r); err != nil {
			t.Fatal(err)
		}
		c.responseChunk(&r)
	}
	raw, _, _ = c.output.encode(4096)
	if raw != `[{"role":"assistant","parts":[{"content":"hello","type":"text"}],"finish_reason":"stop"}]` {
		t.Fatalf("repeated terminal content: %s", raw)
	}
}

func TestNetworkPolicyRedirectAndShutdown(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	for _, local := range []bool{false, true} {
		e := New(context.Background(), Options{Local: local})
		config := testConfig(redirect.URL)
		c := e.Start("org", "id", config)
		c.Finish(testRecord("id"))
		e.Close()
		if d := e.Diagnostics(); d.Delivered != 0 || d.PendingRecords != 0 || d.ReservedBytes != 0 {
			t.Fatalf("shutdown leaked/redirect followed: %+v", d)
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("credential-bearing redirect followed")
	}
}

func TestResponsesTerminalOnlyAndChoiceProjection(t *testing.T) {
	e := New(context.Background(), Options{})
	defer e.Close()
	c := e.Start("org", "id", testConfig("https://example.com/v1/traces"))
	defer c.Discard()
	for _, raw := range []string{
		`{"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}}`,
		`{"type":"response.output_item.done","output_index":0,"item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello "},{"type":"output_text","text":"world"}]}}`,
		`{"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","call_id":"call_1","name":"weather","arguments":"{\"city\":\"Paris\"}"}}`,
		`{"type":"response.completed","response":{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello world"}]},{"type":"function_call","call_id":"call_1","name":"weather","arguments":"{\"city\":\"Paris\"}"}]}}`,
	} {
		var chunk schemas.BifrostResponsesStreamResponse
		if err := json.Unmarshal([]byte(raw), &chunk); err != nil {
			t.Fatal(err)
		}
		c.responseChunk(&chunk)
	}
	raw, _, truncated := c.output.encode(65536)
	const want = `[{"role":"assistant","parts":[{"content":"hello world","type":"text"},{"arguments":{"city":"Paris"},"id":"call_1","name":"weather","type":"tool_call"}],"finish_reason":"tool_call"}]`
	if raw != want || truncated {
		t.Fatalf("output %s truncated=%v", raw, truncated)
	}
}

func TestHTTPSCertificateValidationAndPublicNetworkBoundary(t *testing.T) {
	var received atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(200)
	}))
	defer receiver.Close()
	for _, tc := range []struct{ local, trust, want bool }{{true, true, true}, {true, false, false}, {false, true, false}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			e := New(context.Background(), Options{Local: tc.local})
			defer e.Close()
			if tc.trust {
				roots := x509.NewCertPool()
				roots.AddCert(receiver.Certificate())
				e.client.transport.TLSClientConfig.RootCAs = roots
			}
			cfg := testConfig(receiver.URL)
			cfg.Destinations[0].Encoding = "protobuf"
			c := e.Start("org", "id", cfg)
			c.Finish(testRecord("id"))
			e.Close()
			if (e.Diagnostics().Delivered == 1) != tc.want {
				t.Fatalf("TLS delivery %+v", e.Diagnostics())
			}
		})
	}
	if received.Load() != 1 {
		t.Fatalf("invalid TLS/private request reached receiver: %d", received.Load())
	}
}

func TestFailureFiltersAndIndependentCaptureViews(t *testing.T) {
	e := New(context.Background(), Options{})
	defer e.Close()
	cfg := testConfig("https://example.com/v1/traces")
	d := &cfg.Destinations[0]
	d.Outcomes = []string{"failure"}
	d.ErrorStatusRanges = []exportconfig.StatusRange{{Min: 500, Max: 504}}
	d.ErrorCodes = []string{"upstream_protocol_error"}
	for _, tc := range []struct {
		outcome string
		status  int
		code    string
		want    bool
	}{
		{"success", 0, "", false}, {"cancelled", 0, "", false}, {"failure", 502, "upstream_protocol_error", true}, {"failure", 429, "upstream_protocol_error", false}, {"failure", 502, "other", false},
	} {
		if got := d.Match(tc.outcome, tc.status, tc.code); got != tc.want {
			t.Fatalf("filter %+v => %v", tc, got)
		}
	}
	c := e.Start("org", "id", cfg)
	defer c.Discard()
	input(c, "prompt")
	delta(c, "answer")
	for _, view := range []string{"none", "input", "output", "both"} {
		d.Content = view
		trace, _ := c.trace(testRecord("id"), *d, 65536)
		s := oneSpan(t, trace)
		_, in := s.Attributes().Get("gen_ai.input.messages")
		_, out := s.Attributes().Get("gen_ai.output.messages")
		if in != (view == "input" || view == "both") || out != (view == "output" || view == "both") {
			t.Fatalf("view %s", view)
		}
	}
}

func TestConcurrentQueuePressureAndShutdownRelease(t *testing.T) {
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
	e := New(context.Background(), Options{Local: true})
	cfg := testConfig(receiver.URL)
	cfg.Destinations[0].Content = "none"
	var workers sync.WaitGroup
	for w := range 6 {
		workers.Add(1)
		go func(w int) {
			defer workers.Done()
			for i := range 120 {
				id := fmt.Sprintf("%d-%d", w, i)
				c := e.Start("org", id, cfg)
				c.Finish(testRecord(id))
			}
		}(w)
	}
	workers.Wait()
	before := e.Diagnostics()
	if before.PendingRecords > maxPendingRecords || before.ReservedBytes > memoryLimit || before.Dropped == 0 {
		t.Fatalf("unbounded pressure: %+v", before)
	}
	// Cancellation must release every batch, including records not yet dispatched.
	e.cancel()
	e.Close()
	if d := e.Diagnostics(); d.PendingRecords != 0 || d.ReservedBytes != 0 {
		t.Fatalf("shutdown leak: %+v", d)
	}
}

func TestBatchByteLimitAndRetryAfterExpiry(t *testing.T) {
	var count atomic.Int32
	var largest atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := readExportBody(t, r)
		if int64(len(raw)) > largest.Load() {
			largest.Store(int64(len(raw)))
		}
		if len(raw) > maxBatchBytes {
			t.Errorf("oversized batch %d", len(raw))
		}
		count.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(429)
	}))
	defer receiver.Close()
	e := New(context.Background(), Options{Local: true})
	defer e.Close()
	cfg := testConfig(receiver.URL)
	cfg.Destinations[0].MaxCaptureBytes = ptr(exportconfig.MaxCaptureBytes)
	cfg.Destinations[0].MaxRetries = ptr(3)
	for i := range 2 {
		id := fmt.Sprint(i)
		c := e.Start("org", id, cfg)
		input(c, strings.Repeat("\x01", 200000))
		delta(c, strings.Repeat("\"", 200000))
		c.Finish(testRecord(id))
	}
	await(t, func() bool { return e.Diagnostics().PendingRecords == 0 })
	d := e.Diagnostics()
	if count.Load() != 2 || largest.Load() == 0 || d.Retried != 0 || d.Dropped != 2 || d.Truncated != 2 || d.ReservedBytes != 0 {
		t.Fatalf("expiry/encoding limits: requests=%d bytes=%d diagnostics=%+v", count.Load(), largest.Load(), d)
	}
}

func readExportBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	var reader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return nil
		}
		defer gz.Close()
		reader = gz
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxBatchBytes+1))
	if err != nil {
		t.Error(err)
	}
	return raw
}

func TestRetryBackoffDoesNotBlockHealthyDestination(t *testing.T) {
	var failed atomic.Int32
	sick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		failed.Add(1)
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer sick.Close()
	var delivered atomic.Bool
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		delivered.Store(true)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	defer healthy.Close()
	e := New(context.Background(), Options{Local: true})
	defer func() { e.cancel(); e.Close() }()
	config := testConfig(sick.URL)
	config.Destinations[0].MaxRetries = ptr(3)
	for i := range deliveryWorkers {
		id := fmt.Sprint(i)
		c := e.Start(id, id, config) // separate destination groups fill all workers
		c.Finish(testRecord(id))
	}
	await(t, func() bool { return failed.Load() == deliveryWorkers })
	start := time.Now()
	c := e.Start("healthy", "healthy", testConfig(healthy.URL))
	c.Finish(testRecord("healthy"))
	await(t, delivered.Load)
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Fatalf("healthy destination waited behind backoff: %v", elapsed)
	}
}

func TestMetadataOnlyPreservesUnknownUsageAndGenerationSettings(t *testing.T) {
	e := New(context.Background(), Options{Local: true})
	defer e.Close()
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Destinations[0].Content = "none"
	c := e.Start("org", "metadata", cfg)
	defer c.Discard()
	temperature := 0.25
	c.Input(&schemas.BifrostRequest{ChatRequest: &schemas.BifrostChatRequest{Params: &schemas.ChatParameters{Temperature: &temperature, MaxCompletionTokens: ptr(1024)}, Input: []schemas.ChatMessage{{Role: "user", Content: &schemas.ChatMessageContent{ContentStr: ptr("private prompt")}}}}})
	temperature = 0.75 // captured scalars must not borrow the request graph
	r := testRecord("metadata")
	r.InputTokens = nil
	r.OutputTokens = ptr(int64(0))
	r.CachedInputTokens = ptr(int64(4))
	r.ReasoningTokens = ptr(int64(2))
	r.TimeToFirstTokenMS = ptr(uint32(30))
	r.FinishReason = "tool_calls"
	traces, _ := c.trace(r, cfg.Destinations[0], 65536)
	s := oneSpan(t, traces)
	if _, ok := s.Attributes().Get("gen_ai.usage.input_tokens"); ok {
		t.Fatal("unknown usage reported as zero")
	}
	for key, want := range map[string]int64{"gen_ai.usage.output_tokens": 0, "gen_ai.usage.cache_read.input_tokens": 4, "gen_ai.usage.reasoning.output_tokens": 2, "gen_ai.request.max_tokens": 1024, "stogas.performance.ttft_ms": 30} {
		got, ok := s.Attributes().Get(key)
		if !ok || got.Int() != want {
			t.Fatalf("%s = %v", key, got.AsRaw())
		}
	}
	got, _ := s.Attributes().Get("gen_ai.request.temperature")
	if got.Double() != 0.25 {
		t.Fatal("borrowed parameter")
	}
	cost, _ := s.Attributes().Get("llm.cost.total")
	if cost.Double() != 0.001 {
		t.Fatal("consumer cost")
	}
	reasons, _ := s.Attributes().Get("gen_ai.response.finish_reasons")
	if reasons.Slice().At(0).Str() != "tool_call" {
		t.Fatal("finish reason")
	}
	raw, _ := ptraceotlp.NewExportRequestFromTraces(traces).MarshalJSON()
	if strings.Contains(string(raw), "private prompt") || c.input.used != 0 {
		t.Fatal("metadata-only request retained content")
	}
}

func TestFullBatchCompressionAndCredentialIsolation(t *testing.T) {
	var mu sync.Mutex
	counts := map[string]int{}
	var wireBytes, decodedBytes int
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Error("protobuf was not compressed")
		}
		wire := r.ContentLength
		raw := readExportBody(t, r)
		request := ptraceotlp.NewExportRequest()
		if err := request.UnmarshalProto(raw); err != nil {
			t.Error(err)
		}
		if request.Traces().ResourceSpans().Len() != 1 {
			t.Error("duplicated resource envelope")
		}
		mu.Lock()
		counts[r.Header.Get("Authorization")] += request.Traces().SpanCount()
		wireBytes += int(wire)
		decodedBytes += len(raw)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer receiver.Close()
	e := New(context.Background(), Options{Local: true})
	defer e.Close()
	cfg := testConfig(receiver.URL)
	cfg.Destinations[0].Encoding = "protobuf"
	for _, key := range []string{"Bearer A", "Bearer B"} {
		cfg.Destinations[0].Headers = map[string]string{"Authorization": key}
		for i := range maxBatchRecords {
			id := fmt.Sprint(key, i)
			c := e.Start("org", id, cfg)
			input(c, strings.Repeat("A useful request with repeatable instructions. ", 40))
			c.Finish(testRecord(id))
		}
	}
	await(t, func() bool { return e.Diagnostics().PendingRecords == 0 })
	mu.Lock()
	defer mu.Unlock()
	if counts["Bearer A"] != 64 || counts["Bearer B"] != 64 {
		t.Fatalf("credential isolation: %v, %+v", counts, e.Diagnostics())
	}
	if wireBytes >= decodedBytes {
		t.Fatal("compression increased traffic")
	}
	t.Logf("protobuf batches: %d bytes over HTTP, %d bytes decoded", wireBytes, decodedBytes)
}

func TestLostAcknowledgementReplaysIdenticalBatch(t *testing.T) {
	var mu sync.Mutex
	var first []byte
	var attempts int
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := readExportBody(t, r)
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts == 1 {
			first = raw
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		if string(raw) != string(first) {
			t.Error("ambiguous delivery changed span IDs or payload")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	defer receiver.Close()
	e := New(context.Background(), Options{Local: true})
	defer e.Close()
	cfg := testConfig(receiver.URL)
	cfg.Destinations[0].MaxRetries = ptr(1)
	c := e.Start("org", "lost-ack", cfg)
	input(c, "accepted before disconnect")
	c.Finish(testRecord("lost-ack"))
	await(t, func() bool { return e.Diagnostics().PendingRecords == 0 })
	mu.Lock()
	defer mu.Unlock()
	if attempts != 2 || e.Diagnostics().Delivered != 1 || e.Diagnostics().Retried != 1 {
		t.Fatalf("ambiguous retry: attempts=%d diagnostics=%+v", attempts, e.Diagnostics())
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
			client := newDeliveryClient(true)
			defer client.close()
			roots := x509.NewCertPool()
			roots.AddCert(receiver.Certificate())
			client.transport.TLSClientConfig.RootCAs = roots
			for range 32 {
				payload := []byte(strings.Repeat("x", maxBatchBytes))
				accepted, _, retry, _ := client.send(context.Background(), testConfig(receiver.URL).Destinations[0], payload, 1, false)
				// Engine can erase and release the payload immediately after send.
				clear(payload)
				if accepted || retry {
					t.Fatal("authentication rejection accepted or retried")
				}
			}
		})
	}
}
