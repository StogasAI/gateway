package exporter

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/network"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
)

const (
	responseLimit = 64 << 10
	// Kong HTTP Log's retry time, OpenTelemetry's maximum export time and
	// APISIX's buffer duration all bound in-memory delivery to one minute.
	deliveryWindow = time.Minute
	// OpenTelemetry's default export timeout and Kong HTTP Log's default timeout.
	// It bounds connecting, TLS and waiting for response headers; large uploads
	// are bounded by the delivery window instead.
	attemptTimeout = 10 * time.Second
	// Fluent Bit's default retry limit. OTLP's retryable statuses decide whether
	// the second attempt is used.
	maxAttempts = 2
	// OpenTelemetry's initial retry interval and Fluent Bit's backoff base,
	// randomized by half in either direction as OpenTelemetry does.
	retryDelay = 5 * time.Second
	// An organization may start 120 requests a second on each gateway, and
	// rejected requests are exported too. HTTP/1.1 carries one delivery per
	// connection, so 32 connections keep up while a receiver answers within
	// about 270 ms, as one on another continent does. HTTP/2 multiplexes
	// deliveries within each connection. Connections open only on demand.
	maxConnsPerHost = 32
	// Idle connections stay charged until they close. This keeps one request's
	// whole fan-out, eight hosts at the per-host limit, ready for reuse.
	maxIdleConns  = exportconfig.MaxDestinations * maxConnsPerHost
	shutdownDrain = 5 * time.Second
	// Go 1.27 measured about 13 KiB per delivery waiting for an HTTP/1.1
	// connection and 19 KiB per HTTP/2 stream, mostly goroutine stacks.
	deliveryStateBytes = 20 << 10
	// Go 1.27 measured about 40 KiB per idle HTTP/1.1 connection and 55 KiB per
	// HTTP/2 connection, including TLS buffers and goroutine stacks.
	connectionBytes = 64 << 10
)

var (
	errRecordReleased   = errors.New("export record released")
	errConnectionMemory = errors.New("export connection memory unavailable")
)

type deliveryClient struct {
	client    *http.Client
	transport *http.Transport
	local     bool
}

// Each open connection spends the shared budget, so receivers cannot hold
// memory that admission does not see.
func newDeliveryClient(local bool, newLease func() Lease) deliveryClient {
	safeDial := network.SSRFSafeDialContext(attemptTimeout)
	dial := func(ctx context.Context, networkName, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		lease := newLease()
		if !lease.Grow(connectionBytes) {
			lease.Release()
			return nil, errConnectionMemory
		}
		var conn net.Conn
		if ip, parseErr := netip.ParseAddr(host); local && parseErr == nil && ip.IsLoopback() {
			conn, err = (&net.Dialer{Timeout: attemptTimeout}).DialContext(ctx, networkName, address)
		} else {
			conn, err = safeDial(ctx, networkName, address)
		}
		if err != nil {
			lease.Release()
			return nil, err
		}
		return &chargedConn{Conn: conn, release: sync.OnceFunc(lease.Release)}, nil
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, MaxIdleConns: maxIdleConns, MaxIdleConnsPerHost: maxConnsPerHost, MaxConnsPerHost: maxConnsPerHost, IdleConnTimeout: deliveryWindow, TLSHandshakeTimeout: attemptTimeout, ResponseHeaderTimeout: attemptTimeout, MaxResponseHeaderBytes: responseLimit, DisableCompression: true}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return deliveryClient{client: client, transport: transport, local: local}
}
func (c deliveryClient) close() { c.transport.CloseIdleConnections() }

type chargedConn struct {
	net.Conn
	release func()
}

func (c *chargedConn) Close() error {
	c.release()
	return c.Conn.Close()
}

// HTTP transports may still read a request body after Do returns. Every read
// takes the record lock, so releasing the record erases the payload safely.
type deliveryBody struct {
	record       *record
	part, offset int
}

func (b *deliveryBody) Read(dst []byte) (int, error) {
	r := b.record
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.parts == nil {
		return 0, errRecordReleased
	}
	n := 0
	for b.part < len(r.parts) && n < len(dst) {
		copied := copy(dst[n:], r.parts[b.part][b.offset:])
		n += copied
		b.offset += copied
		if b.offset == len(r.parts[b.part]) {
			b.part++
			b.offset = 0
		}
	}
	if n == 0 && b.part == len(r.parts) {
		return 0, io.EOF
	}
	return n, nil
}
func (b *deliveryBody) Close() error { return nil }

type attempt struct {
	delivered, retryable, memoryDropped bool
	retryAfter                          *time.Duration
}

func (c deliveryClient) send(ctx context.Context, d exportconfig.Destination, r *record) attempt {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, &deliveryBody{record: r})
	if err != nil || (!c.local && req.URL.Scheme != "https") {
		return attempt{}
	}
	req.ContentLength = r.size
	// The key lets receivers drop retried duplicates and lets net/http replay a
	// request whose reused connection closed before the receiver saw it.
	req.GetBody = func() (io.ReadCloser, error) { return &deliveryBody{record: r}, nil }
	for key, value := range d.Headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", r.requestID)
	response, err := c.client.Do(req)
	if errors.Is(err, errConnectionMemory) {
		return attempt{memoryDropped: true}
	}
	if err != nil {
		return attempt{retryable: ctx.Err() == nil}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, responseLimit))
	switch response.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return attempt{retryable: true, retryAfter: retryAfter(response.Header.Get("Retry-After"))}
	}
	return attempt{delivered: response.StatusCode >= 200 && response.StatusCode < 300}
}

// retryAfter accepts delay seconds or an HTTP date, as RFC 9110 defines.
func retryAfter(value string) *time.Duration {
	var delay time.Duration
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil {
		delay = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(value); err == nil {
		delay = max(0, time.Until(at))
	} else {
		return nil
	}
	return &delay
}
