package billing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const requestLogMaxResponseBytes = 64 * 1024

type requestLogSink struct {
	client              *http.Client
	endpoint            string
	token               string
	queue               bool
	accessClientID      string
	accessClientSecret  string
	circuitOpenDuration time.Duration
	circuitOpenUntil    atomic.Int64
	failures            atomic.Uint64
	shortCircuits       atomic.Uint64
}

type RequestLogSinkDiagnostics struct {
	CircuitOpen   bool   `json:"circuitOpen"`
	Failures      uint64 `json:"failures"`
	ShortCircuits uint64 `json:"shortCircuits"`
}

func newRequestLogSink(endpoint, token string, allowPrivateHTTP, queue bool) (*requestLogSink, error) {
	endpoint, token = strings.TrimSpace(endpoint), strings.TrimSpace(token)
	if endpoint == "" && token == "" {
		return nil, nil
	}
	if endpoint == "" || token == "" {
		return nil, errors.New("configure request log endpoint and token together")
	}
	parsed, err := normalizeLogEndpoint(endpoint, allowPrivateHTTP)
	if err != nil {
		return nil, err
	}
	if !queue {
		if parsed.Path != "" && parsed.Path != "/" {
			return nil, errors.New("Tinybird requires a clean HTTPS origin")
		}
		parsed.Path = "/v0/events"
		parsed.RawQuery = "name=gateway_requests&wait=true"
	}
	return &requestLogSink{
		endpoint: parsed.String(), token: token, queue: queue,
		circuitOpenDuration: requestLogCircuitOpenDuration,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}},
				TLSHandshakeTimeout: 10 * time.Second,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
			Timeout:       requestLogAppendTimeout,
		},
	}, nil
}

func normalizeLogEndpoint(endpoint string, allowPrivateHTTP bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return nil, errors.New("request log endpoint requires a clean HTTPS URL")
	}
	allowsHTTP := parsed.Hostname() == "localhost"
	if address := net.ParseIP(parsed.Hostname()); address != nil {
		allowsHTTP = address.IsLoopback() || (allowPrivateHTTP && (address.IsPrivate() || address.IsLinkLocalUnicast()))
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && allowsHTTP) {
		return nil, errors.New("request log endpoint requires HTTPS")
	}
	return parsed, nil
}

func NormalizeTinybirdHost(host string, allowPrivateHTTP bool) (string, error) {
	parsed, err := normalizeLogEndpoint(host, allowPrivateHTTP)
	if err != nil {
		return "", err
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("Tinybird requires a clean HTTPS origin")
	}
	parsed.Path = ""
	return parsed.String(), nil
}

func (sink *requestLogSink) append(body []byte, rows int) error {
	if time.Now().UnixNano() < sink.circuitOpenUntil.Load() {
		sink.shortCircuits.Add(1)
		return errors.New("request log destination circuit is open")
	}
	// One batch worker owns calls to both destinations, so recovery needs no
	// separate probe lock or per-request circuit admission state.
	err := sink.send(body, rows)
	if err != nil {
		sink.failures.Add(1)
		sink.circuitOpenUntil.Store(time.Now().Add(sink.circuitOpenDuration).UnixNano())
	} else {
		sink.circuitOpenUntil.Store(0)
	}
	return err
}

func (sink *requestLogSink) send(body []byte, rows int) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestLogAppendTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sink.endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid request log destination")
	}
	request.Header.Set("authorization", "Bearer "+sink.token)
	request.Header.Set("content-type", "application/x-ndjson")
	if sink.accessClientID != "" {
		request.Header.Set("cf-access-client-id", sink.accessClientID)
		request.Header.Set("cf-access-client-secret", sink.accessClientSecret)
	}
	response, err := sink.client.Do(request)
	if err != nil {
		return errors.New("request log delivery failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("request log destination status %d", response.StatusCode)
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, requestLogMaxResponseBytes+1))
	if err != nil || len(body) > requestLogMaxResponseBytes {
		return errors.New("invalid request log acknowledgement")
	}
	var result struct {
		AcceptedRows    int `json:"accepted_rows"`
		SuccessfulRows  int `json:"successful_rows"`
		QuarantinedRows int `json:"quarantined_rows"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&result); err != nil {
		return errors.New("invalid request log acknowledgement")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request log acknowledgement contains trailing data")
	}
	if sink.queue {
		if result.AcceptedRows != rows {
			return errors.New("request log queue did not confirm every row")
		}
	} else if result.SuccessfulRows != rows || result.QuarantinedRows != 0 {
		return errors.New("Tinybird did not commit every request log row")
	}
	return nil
}

func (sink *requestLogSink) close() {
	if sink != nil {
		sink.client.CloseIdleConnections()
	}
}

func (sink *requestLogSink) diagnostics() *RequestLogSinkDiagnostics {
	if sink == nil {
		return nil
	}
	return &RequestLogSinkDiagnostics{
		CircuitOpen: time.Now().UnixNano() < sink.circuitOpenUntil.Load(),
		Failures:    sink.failures.Load(), ShortCircuits: sink.shortCircuits.Load(),
	}
}
