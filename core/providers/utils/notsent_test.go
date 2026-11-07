package utils

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/network"
	"github.com/valyala/fasthttp"
)

// refusedAddress is a local address that nothing listens on.
func refusedAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := ln.Addr().String()
	ln.Close()
	return address
}

// A POST never goes out on a pooled connection that the upstream closed while
// it sat idle: the transport passes over it, so the request is neither lost
// nor left with an unknown outcome.
func TestContextTransport_PooledConnClosedWhileIdleIsPassedOver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var accepted, served atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				httpReq, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, httpReq.Body)
				served.Add(1)
				// The upstream's keep-alive ends right after its response.
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
			}()
		}
	}()

	client := ConfigureDialer(&fasthttp.Client{ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}, true)
	target := "http://" + ln.Addr().String()
	for i := 1; i <= 2; i++ {
		req, resp := newSilentStreamingRequest(target)
		err := client.Do(req, resp)
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
		if err != nil {
			t.Fatalf("POST %d failed: %v", i, err)
		}
		if i == 1 {
			// Let the close reach the pooled socket.
			time.Sleep(100 * time.Millisecond)
		}
	}
	if accepted.Load() != 2 || served.Load() != 2 {
		t.Fatalf("upstream accepted %d connections and served %d requests, want 2 and 2", accepted.Load(), served.Load())
	}
}

// A request that never reached the upstream says so; one that the upstream
// read before the connection died does not, whatever the method.
func TestContextTransport_ReportsWhetherTheRequestWasSent(t *testing.T) {
	client := ConfigureDialer(&fasthttp.Client{ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}, true)

	req, resp := newSilentStreamingRequest("http://" + refusedAddress(t))
	err := DoRequestWithContext(context.Background(), client, req, resp)
	fasthttp.ReleaseRequest(req)
	fasthttp.ReleaseResponse(resp)
	if err == nil || !network.RequestNotSent(err) {
		t.Fatalf("refused connection: err = %v, want a NotSentError", err)
	}

	upstream := newClosingUpstream(t)
	req, resp = newSilentStreamingRequest(upstream.URL())
	err = DoRequestWithContext(context.Background(), client, req, resp)
	fasthttp.ReleaseRequest(req)
	fasthttp.ReleaseResponse(resp)
	if err == nil || network.RequestNotSent(err) {
		t.Fatalf("closed after the upstream read the request: err = %v, want an error that may follow a run", err)
	}

	sending, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, resp = fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	req.SetRequestURI("http://" + stalledUpstream(t, cancel) + "/v1/chat/completions")
	req.Header.SetMethod(http.MethodPost)
	req.SetBody(make([]byte, stalledBodySize))
	err = DoRequestWithContext(sending, client, req, resp)
	fasthttp.ReleaseRequest(req)
	fasthttp.ReleaseResponse(resp)
	if !errors.Is(err, context.Canceled) || network.RequestNotSent(err) {
		t.Fatalf("request whose context ended while it was sent: err = %v, want the context's error alone", err)
	}

	// Go reports a dial that timed out as a deadline, which is still the
	// transport's own failure before anything was sent. The dialer takes its
	// timeout from ReadTimeout.
	slowDial := ConfigureDialer(&fasthttp.Client{ReadTimeout: time.Nanosecond, WriteTimeout: 2 * time.Second}, true)
	req, resp = newSilentStreamingRequest("http://" + refusedAddress(t))
	err = DoRequestWithContext(context.Background(), slowDial, req, resp)
	fasthttp.ReleaseRequest(req)
	fasthttp.ReleaseResponse(resp)
	if !errors.Is(err, context.DeadlineExceeded) || !network.RequestNotSent(err) {
		t.Fatalf("dial timeout: err = %v, want a NotSentError that wraps the timeout", err)
	}
}

// net/http requests, which Bedrock sends, say the same.
func TestDoHTTPRequest_ReportsWhetherTheRequestWasSent(t *testing.T) {
	post := func(target string) error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(`{"model":"m"}`))
		if err != nil {
			t.Fatalf("NewRequestWithContext: %v", err)
		}
		resp, err := DoHTTPRequest(&http.Client{Timeout: 2 * time.Second}, req)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := post("http://" + refusedAddress(t)); err == nil || !network.RequestNotSent(err) {
		t.Fatalf("refused connection: err = %v, want a NotSentError", err)
	}
	if err := post(newClosingUpstream(t).URL()); err == nil || network.RequestNotSent(err) {
		t.Fatalf("closed after the upstream read the request: err = %v, want an error that may follow a run", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+refusedAddress(t), strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	slowDial := &http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: time.Nanosecond}).DialContext}}
	if _, err := DoHTTPRequest(slowDial, req); !errors.Is(err, context.DeadlineExceeded) || !network.RequestNotSent(err) {
		t.Fatalf("dial timeout: err = %v, want a NotSentError that wraps the timeout", err)
	}
	sending, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err = http.NewRequestWithContext(sending, http.MethodPost, "http://"+stalledUpstream(t, cancel), bytes.NewReader(make([]byte, stalledBodySize)))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	if _, err := DoHTTPRequest(&http.Client{}, req); !errors.Is(err, context.Canceled) || network.RequestNotSent(err) {
		t.Fatalf("request whose context ended while it was sent: err = %v, want the context's error alone", err)
	}
}

// stalledBodySize is more than the socket buffers of a stalled upstream hold.
const stalledBodySize = 64 << 20

// stalledUpstream accepts one connection, calls read once the request's
// headers arrived, and reads nothing more, so that the client is still
// sending a body of stalledBodySize bytes.
func stalledUpstream(t *testing.T, read func()) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	held := make(chan struct{})
	t.Cleanup(func() {
		close(held)
		ln.Close()
	})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
			read()
		}
		<-held
	}()
	return ln.Addr().String()
}
