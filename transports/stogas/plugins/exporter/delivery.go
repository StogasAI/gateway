package exporter

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/network"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

const responseLimit = 64 << 10

type deliveryClient struct {
	client    *http.Client
	transport *http.Transport
	local     bool
}

func newDeliveryClient(local bool) deliveryClient {
	safeDial := network.SSRFSafeDialContext(deliveryTimeout)
	dial := func(ctx context.Context, networkName, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip, err := netip.ParseAddr(host)
		if local && err == nil && ip.IsLoopback() {
			return (&net.Dialer{Timeout: deliveryTimeout}).DialContext(ctx, networkName, address)
		}
		return safeDial(ctx, networkName, address)
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, MaxIdleConns: deliveryWorkers, MaxIdleConnsPerHost: deliveryWorkers, MaxConnsPerHost: deliveryWorkers, IdleConnTimeout: deliveryAge, TLSHandshakeTimeout: deliveryTimeout, ResponseHeaderTimeout: deliveryTimeout, MaxResponseHeaderBytes: responseLimit, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: deliveryTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return deliveryClient{client: client, transport: transport, local: local}
}
func (c deliveryClient) close() { c.transport.CloseIdleConnections() }

// HTTP transports may still read a request body after Do returns an error.
// Close detaches it under the read lock so send can release its payload safely.
type deliveryBody struct {
	mu     sync.Mutex
	reader *bytes.Reader
}

func (b *deliveryBody) Read(dst []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(dst)
}
func (b *deliveryBody) Close() error {
	b.mu.Lock()
	b.reader = nil
	b.mu.Unlock()
	return nil
}

type delivery struct {
	jobs                  []*job
	payload               []byte
	compressed            bool
	deadline, nextAttempt time.Time
	attempt               int
	finished              bool
}

// prepare merges the shared resource/scope once and encodes an immutable retry
// payload. OTLP Protobuf receivers support gzip; JSON and webhooks stay plain.
func (b *delivery) prepare(e *Engine) bool {
	target := b.jobs[0].target
	traces := ptrace.NewTraces()
	for _, j := range b.jobs {
		rs := j.traces.ResourceSpans().At(0)
		if traces.ResourceSpans().Len() > 0 {
			previous := traces.ResourceSpans().At(traces.ResourceSpans().Len() - 1)
			if previous.Resource().Attributes().Equal(rs.Resource().Attributes()) {
				rs.ScopeSpans().At(0).Spans().MoveAndAppendTo(previous.ScopeSpans().At(0).Spans())
				continue
			}
		}
		rs.MoveTo(traces.ResourceSpans().AppendEmpty())
	}
	request := ptraceotlp.NewExportRequestFromTraces(traces)
	var err error
	if target.Encoding == "protobuf" {
		b.payload, err = request.MarshalProto()
	} else {
		b.payload, err = request.MarshalJSON()
	}
	if err != nil || len(b.payload) > maxBatchBytes {
		return false
	}
	scratch := e.reserve()
	defer scratch.release()
	// BestSpeed uses about 1.2 MiB of encoder state; account scratch separately.
	if target.Encoding == "protobuf" && scratch.grow(2<<20) {
		var packed bytes.Buffer
		writer, _ := gzip.NewWriterLevel(&packed, gzip.BestSpeed)
		_, writeErr := writer.Write(b.payload)
		closeErr := writer.Close()
		if writeErr == nil && closeErr == nil && packed.Len() < len(b.payload) {
			clear(b.payload)
			b.payload, b.compressed = packed.Bytes(), true
		} else {
			clear(packed.Bytes())
		}
	}
	return true
}
func (e *Engine) deliver(b *delivery) {
	b.finished = true
	if !time.Now().Before(b.deadline) || e.ctx.Err() != nil {
		e.dropped.Add(uint64(len(b.jobs)))
		return
	}
	if b.attempt == 0 && !b.prepare(e) {
		e.dropped.Add(uint64(len(b.jobs)))
		return
	}
	if b.attempt > 0 {
		e.retried.Add(1)
	}
	target := b.jobs[0].target
	ctx, cancel := context.WithDeadline(e.ctx, b.deadline)
	accepted, rejected, retry, wait := e.client.send(ctx, target, b.payload, len(b.jobs), b.compressed)
	cancel()
	if accepted {
		e.delivered.Add(uint64(len(b.jobs) - rejected))
		e.rejected.Add(uint64(rejected))
		return
	}
	if !retry || b.attempt >= target.Retries() || e.ctx.Err() != nil {
		e.dropped.Add(uint64(len(b.jobs)))
		return
	}
	if wait == 0 {
		wait = time.Duration(1<<b.attempt)*time.Second + time.Duration(rand.Int64N(int64(250*time.Millisecond)))
	}
	b.nextAttempt = time.Now().Add(wait)
	if !b.nextAttempt.Before(b.deadline) {
		e.dropped.Add(uint64(len(b.jobs)))
		return
	}
	b.attempt++
	b.finished = false
}
func (c deliveryClient) send(ctx context.Context, d exportconfig.Destination, payload []byte, count int, compressed bool) (accepted bool, rejected int, retry bool, wait time.Duration) {
	requestBody := &deliveryBody{reader: bytes.NewReader(payload)}
	defer requestBody.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, requestBody)
	if err != nil || (!c.local && req.URL.Scheme != "https") {
		return
	}
	req.ContentLength = int64(len(payload))
	for key, v := range d.Headers {
		req.Header.Set(key, v)
	}
	contentType := "application/json"
	if d.Encoding == "protobuf" {
		contentType = "application/x-protobuf"
	}
	req.Header.Set("Content-Type", contentType)
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", contentType)
	}
	response, err := c.client.Do(req)
	if err != nil {
		return false, 0, !errors.Is(err, context.Canceled), 0
	}
	defer func() {
		// Bound draining while allowing ordinary small acknowledgements to reuse TLS.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, responseLimit))
		response.Body.Close()
	}()
	if response.StatusCode == 429 || response.StatusCode == 502 || response.StatusCode == 503 || response.StatusCode == 504 {
		return false, 0, true, retryAfter(response.Header.Get("Retry-After"), time.Now())
	}
	if d.Format == "webhook" {
		// Generic HTTP webhooks acknowledge with any 2xx; their body is unrelated
		// to OTLP's ExportTraceServiceResponse and is never interpreted or logged.
		return response.StatusCode >= 200 && response.StatusCode < 300, 0, false, 0
	}
	if response.StatusCode != http.StatusOK {
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil {
		return false, 0, !errors.Is(err, context.Canceled), 0
	}
	if len(body) > responseLimit {
		return
	}
	defer clear(body)
	reply := ptraceotlp.NewExportResponse()
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	switch mediaType {
	case "application/x-protobuf":
		err = reply.UnmarshalProto(body)
	case "application/json":
		err = reply.UnmarshalJSON(body)
	default:
		return
	}
	if err != nil {
		return
	}
	rejected = int(reply.PartialSuccess().RejectedSpans())
	if rejected < 0 || rejected > count {
		return false, 0, false, 0
	}
	return true, rejected, false, 0
}
func retryAfter(raw string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseUint(raw, 10, 32); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(raw); err == nil && date.After(now) {
		return date.Sub(now)
	}
	return 0
}
