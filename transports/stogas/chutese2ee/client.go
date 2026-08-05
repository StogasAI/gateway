package chutese2ee

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maximumSafeReadAttempts = 3

const productionAPIBaseURL = "https://api.chutes.ai"

type apiClient struct {
	apiKey     string
	baseURL    *url.URL
	client     *http.Client
	ownsClient bool
}

func newAPIClient(apiKey, rawBaseURL string, requireProductionOrigin, requirePostQuantumTLS bool) (*apiClient, error) {
	if err := validateChutesAPIKey(apiKey); err != nil {
		return nil, errors.New("Chutes API key is required")
	}
	baseURL, err := url.Parse(strings.TrimRight(strings.TrimSpace(rawBaseURL), "/"))
	if err != nil || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("invalid Chutes E2EE API base URL")
	}
	if baseURL.Path != "" && baseURL.Path != "/" {
		return nil, errors.New("Chutes E2EE API base URL must not contain a path")
	}
	if requireProductionOrigin && baseURL.String() != productionAPIBaseURL {
		return nil, errors.New("confidential Chutes E2EE traffic must use the fixed Chutes API origin")
	}
	if baseURL.Scheme != "https" && !(baseURL.Scheme == "http" && !requirePostQuantumTLS) {
		return nil, errors.New("Chutes E2EE API base URL must use HTTPS")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if requirePostQuantumTLS {
		tlsConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	}
	transport := &http.Transport{
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           128,
		MaxIdleConnsPerHost:    128,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig:        tlsConfig,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   transportTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not permitted")
		},
	}
	return &apiClient{apiKey: apiKey, baseURL: baseURL, client: client, ownsClient: true}, nil
}

func (c *apiClient) withAPIKey(apiKey string) (*apiClient, error) {
	if c == nil || c.baseURL == nil || c.client == nil {
		return nil, errCredentialUnavailable
	}
	if err := validateChutesAPIKey(apiKey); err != nil {
		return nil, err
	}
	return &apiClient{
		apiKey:  apiKey,
		baseURL: c.baseURL,
		client:  c.client,
	}, nil
}

func (c *apiClient) close() {
	if c == nil {
		return
	}
	c.apiKey = ""
	if c.ownsClient && c.client != nil {
		if transport, ok := c.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
}

func (c *apiClient) requestJSON(ctx context.Context, method, path string, requestBody io.Reader, maximum int64, output any) (int, time.Duration, error) {
	started := time.Now()
	reference, err := url.Parse(path)
	if err != nil || reference.IsAbs() || reference.Host != "" || !strings.HasPrefix(reference.Path, "/") {
		return 0, time.Since(started), errors.New("invalid Chutes API path")
	}
	requestURL := c.baseURL.ResolveReference(reference)
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), requestBody)
	if err != nil {
		return 0, time.Since(started), err
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Accept", "application/json")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return 0, time.Since(started), err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return response.StatusCode, time.Since(started), err
	}
	if int64(len(body)) > maximum {
		return response.StatusCode, time.Since(started), errors.New("Chutes response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, time.Since(started), &httpStatusError{
			Operation:  method + " " + path,
			StatusCode: response.StatusCode,
			RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
		}
	}
	if err := json.Unmarshal(body, output); err != nil {
		return response.StatusCode, time.Since(started), fmt.Errorf("decode Chutes response: %w", err)
	}
	return response.StatusCode, time.Since(started), nil
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil && when.After(now) {
		return when.Sub(now)
	}
	return 0
}

func retryableChutesRead(err error, retryNotFound bool) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusRequestTimeout,
			http.StatusTooEarly,
			http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		case http.StatusNotFound:
			return retryNotFound
		default:
			return false
		}
	}
	var networkError net.Error
	return errors.As(err, &networkError) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func chutesReadRetryDelay(err error, attempt int, maximum time.Duration) (time.Duration, bool) {
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && statusErr.RetryAfter > 0 {
		if statusErr.RetryAfter > maximum {
			return 0, false
		}
		return statusErr.RetryAfter, true
	}
	delay := 100 * time.Millisecond
	for index := 0; index < attempt && delay < maximum; index++ {
		delay *= 2
	}
	if delay > maximum {
		delay = maximum
	}
	half := delay / 2
	if half <= 0 {
		return delay, true
	}
	jitter, randomErr := rand.Int(rand.Reader, big.NewInt(int64(half)+1))
	if randomErr != nil {
		return delay, true
	}
	return half + time.Duration(jitter.Int64()), true
}

func waitForChutesRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
