package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tinybirdGatewayRequestsDatasource = "gateway_requests"
	tinybirdAppendTimeout             = 10 * time.Second
	tinybirdAppendWaitTimeout         = tinybirdAppendTimeout + time.Second
	tinybirdCircuitOpenDuration       = 30 * time.Second
	// Coalesce briefly after idle, but cap steady-state dispatches independently.
	// Eight nodes therefore use at most 32 of the datasource's 100 requests/second.
	tinybirdBatchWindow        = 50 * time.Millisecond
	tinybirdMinRequestInterval = 250 * time.Millisecond
	tinybirdMaxEventBytes      = 64 * 1024
	tinybirdMaxResponseBytes   = 64 * 1024
	// Stay below Tinybird's smallest (10 MB) Events API request limit.
	tinybirdMaxBatchBytes = 8 * 1024 * 1024
	tinybirdMaxBatchRows  = 4096
	tinybirdQueueCapacity = 2048
)

var errTinybirdCircuitOpen = errors.New("append tinybird event: circuit is open")

type TinybirdClient struct {
	client              *http.Client
	host                string
	token               string
	batchWindow         time.Duration
	minRequestInterval  time.Duration
	maxBatchBytes       int
	maxBatchRows        int
	circuitOpenDuration time.Duration
	queue               chan tinybirdAppendRequest
	stop                chan struct{}
	startOnce           sync.Once
	workerWG            sync.WaitGroup
	mu                  sync.RWMutex
	closed              bool
	batches             atomic.Uint64
	batchFailures       atomic.Uint64
	circuitOpenUntil    atomic.Int64
	rows                atomic.Uint64
	shortCircuits       atomic.Uint64
}

type TinybirdDiagnostics struct {
	BatchFailures uint64 `json:"batchFailures"`
	Batches       uint64 `json:"batches"`
	CircuitOpen   bool   `json:"circuitOpen"`
	Closed        bool   `json:"closed"`
	QueueCapacity int    `json:"queueCapacity"`
	QueueDepth    int    `json:"queueDepth"`
	Rows          uint64 `json:"rows"`
	ShortCircuits uint64 `json:"shortCircuits"`
}

type tinybirdAppendRequest struct {
	line   []byte
	result chan error
}

type ProviderAttempt struct {
	Provider              string  `json:"provider"`
	Status                string  `json:"status"`
	StatusCode            *int    `json:"status_code"`
	LatencyMS             uint32  `json:"latency_ms"`
	ProviderFirstOutputMS *uint32 `json:"provider_first_output_ms"`
	ProviderRequestID     string  `json:"provider_request_id"`
	FinishReason          string  `json:"finish_reason"`
	UpstreamByok          string  `json:"upstream_byok"`
}

type RequestEvent struct {
	RequestID               string            `json:"request_id"`
	CreatedAt               string            `json:"created_at"`
	StogasAPIKeyID          string            `json:"stogas_api_key_id"`
	StogasProvisioningKeyID *string           `json:"stogas_provisioning_key_id"`
	StogasUserID            string            `json:"stogas_user_id"`
	StogasOrganizationID    string            `json:"stogas_organization_id"`
	StogasWorkspaceID       string            `json:"stogas_workspace_id"`
	RequestType             string            `json:"request_type"`
	Cancelled               bool              `json:"cancelled"`
	ClientStopMS            *uint32           `json:"client_stop_ms"`
	CatalogDigest           string            `json:"catalog_digest"`
	ProviderAttempts        []ProviderAttempt `json:"provider_attempts"`
	StogasProcessingSuccess bool              `json:"stogas_processing_success"`
	StogasBillingStatus     string            `json:"stogas_billing_status"`
	NodeID                  string            `json:"node_id"`
	TotalTimeMS             uint32            `json:"total_time_ms"`
	UpstreamCostUSDAtoms    string            `json:"upstream_cost_usd_atoms"`
	BilledCostUSDAtoms      string            `json:"billed_cost_usd_atoms"`
	Pricing                 EventPricing      `json:"pricing"`
	GatewayVersion          string            `json:"gateway_version"`
	CatalogNodeIDs          []string          `json:"catalog_node_ids"`
	analyticsQuantities     map[string]uint64
}

type EventMeter struct {
	Quantity     string `json:"quantity"`
	RateKey      string `json:"rateKey"`
	RateUSDAtoms string `json:"rateUsdAtoms"`
	USDAtoms     string `json:"usdAtoms"`
}

type EventPricing map[string]EventMeter

type tinybirdEventsResponse struct {
	QuarantinedRows int `json:"quarantined_rows"`
	SuccessfulRows  int `json:"successful_rows"`
}

func NewTinybirdClient(host string, token string, allowInsecurePrivateNetwork bool) (*TinybirdClient, error) {
	host = strings.TrimSpace(host)
	token = strings.TrimSpace(token)
	if host == "" && token == "" {
		return nil, nil
	}
	if host == "" || token == "" {
		return nil, errors.New("configure Tinybird host and token together")
	}
	normalizedHost, err := NormalizeTinybirdHost(host, allowInsecurePrivateNetwork)
	if err != nil {
		return nil, err
	}
	return &TinybirdClient{
		client: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: tinybirdAppendTimeout,
		},
		host:                normalizedHost,
		token:               token,
		batchWindow:         tinybirdBatchWindow,
		minRequestInterval:  tinybirdMinRequestInterval,
		maxBatchBytes:       tinybirdMaxBatchBytes,
		maxBatchRows:        tinybirdMaxBatchRows,
		circuitOpenDuration: tinybirdCircuitOpenDuration,
		queue:               make(chan tinybirdAppendRequest, tinybirdQueueCapacity),
		stop:                make(chan struct{}),
	}, nil
}

func NormalizeTinybirdHost(host string, allowInsecurePrivateNetwork bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(host))
	if err != nil || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid Tinybird host: expected a clean HTTPS origin")
	}
	if parsed.RawPath != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("invalid Tinybird host: expected a clean HTTPS origin")
	}
	allowsHTTP := parsed.Hostname() == "localhost"
	if address := net.ParseIP(parsed.Hostname()); address != nil {
		allowsHTTP = address.IsLoopback() ||
			(allowInsecurePrivateNetwork && (address.IsPrivate() || address.IsLinkLocalUnicast()))
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && allowsHTTP) {
		return "", errors.New("invalid Tinybird host: expected a clean HTTPS origin")
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func (c *TinybirdClient) AppendGatewayRequest(ctx context.Context, event RequestEvent) error {
	if c == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("append tinybird event: %w", err)
	}
	if c.circuitOpen(time.Now()) {
		c.shortCircuits.Add(1)
		return errTinybirdCircuitOpen
	}

	line, err := json.Marshal(tinybirdGatewayRequestEvent(event))
	if err != nil {
		return fmt.Errorf("marshal tinybird event: %w", err)
	}
	line = append(line, '\n')
	if len(line) > tinybirdMaxEventBytes {
		return fmt.Errorf("append tinybird event: encoded event is %d bytes, limit is %d", len(line), tinybirdMaxEventBytes)
	}

	appendRequest := tinybirdAppendRequest{
		line:   line,
		result: make(chan error, 1),
	}

	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return fmt.Errorf("append tinybird event: client is closed")
	}
	c.startOnce.Do(func() {
		c.workerWG.Add(1)
		go c.run()
	})
	select {
	case c.queue <- appendRequest:
		c.mu.RUnlock()
	default:
		c.mu.RUnlock()
		return fmt.Errorf("append tinybird event: microbatch queue is full")
	}

	waitTimer := time.NewTimer(tinybirdAppendWaitTimeout)
	defer waitTimer.Stop()
	select {
	case err := <-appendRequest.result:
		return err
	case <-ctx.Done():
		return fmt.Errorf("append tinybird event: %w", ctx.Err())
	case <-waitTimer.C:
		return fmt.Errorf("append tinybird event: timed out waiting for microbatch acknowledgement")
	}
}

func (c *TinybirdClient) Close() {
	if c == nil {
		return
	}

	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.stop)
	}
	c.mu.Unlock()
	c.workerWG.Wait()
	c.client.CloseIdleConnections()
}

func (c *TinybirdClient) run() {
	defer c.workerWG.Done()

	var pending *tinybirdAppendRequest
	var lastDispatch time.Time
	closing := false
	for {
		first, ok := c.nextBatchRequest(pending, closing)
		pending = nil
		if !ok {
			if closing {
				return
			}
			closing = true
			continue
		}

		batch, next, stopped := c.collectBatch(first, closing, lastDispatch)
		pending = next
		closing = closing || stopped
		var err error
		if c.circuitOpen(time.Now()) {
			c.shortCircuits.Add(uint64(len(batch)))
			err = errTinybirdCircuitOpen
		} else {
			c.waitForDispatch(lastDispatch)
			lastDispatch = time.Now()
			err = c.appendBatch(batch)
			if err != nil {
				c.openCircuit(time.Now())
			} else {
				c.circuitOpenUntil.Store(0)
			}
		}
		c.batches.Add(1)
		c.rows.Add(uint64(len(batch)))
		if err != nil {
			c.batchFailures.Add(1)
		}
		for _, appendRequest := range batch {
			appendRequest.result <- err
		}
	}
}

func (c *TinybirdClient) Diagnostics() *TinybirdDiagnostics {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	return &TinybirdDiagnostics{
		BatchFailures: c.batchFailures.Load(),
		Batches:       c.batches.Load(),
		CircuitOpen:   c.circuitOpen(time.Now()),
		Closed:        closed,
		QueueCapacity: cap(c.queue),
		QueueDepth:    len(c.queue),
		Rows:          c.rows.Load(),
		ShortCircuits: c.shortCircuits.Load(),
	}
}

func (c *TinybirdClient) circuitOpen(now time.Time) bool {
	return now.UnixNano() < c.circuitOpenUntil.Load()
}

func (c *TinybirdClient) openCircuit(now time.Time) {
	duration := c.circuitOpenDuration
	if duration <= 0 {
		duration = tinybirdCircuitOpenDuration
	}
	c.circuitOpenUntil.Store(now.Add(duration).UnixNano())
}

func (c *TinybirdClient) nextBatchRequest(pending *tinybirdAppendRequest, closing bool) (tinybirdAppendRequest, bool) {
	if pending != nil {
		return *pending, true
	}
	if closing {
		select {
		case appendRequest := <-c.queue:
			return appendRequest, true
		default:
			return tinybirdAppendRequest{}, false
		}
	}

	select {
	case appendRequest := <-c.queue:
		return appendRequest, true
	case <-c.stop:
		return tinybirdAppendRequest{}, false
	}
}

func (c *TinybirdClient) collectBatch(
	first tinybirdAppendRequest,
	closing bool,
	lastDispatch time.Time,
) ([]tinybirdAppendRequest, *tinybirdAppendRequest, bool) {
	batch := make([]tinybirdAppendRequest, 1, min(c.maxBatchRows, len(c.queue)+1))
	batch[0] = first
	batchBytes := len(first.line)

	if closing {
		batch, _, pending := c.drainBatch(batch, batchBytes)
		return batch, pending, true
	}

	flushAt := time.Now().Add(c.batchWindow)
	nextAllowed := lastDispatch.Add(c.minRequestInterval)
	if nextAllowed.After(flushAt) {
		flushAt = nextAllowed
	}
	timer := time.NewTimer(max(time.Until(flushAt), 0))
	defer timer.Stop()

	for c.batchHasCapacity(batch, batchBytes) {
		select {
		case appendRequest := <-c.queue:
			if !c.batchCanAppend(batch, batchBytes, appendRequest) {
				select {
				case <-timer.C:
					return batch, &appendRequest, false
				case <-c.stop:
					return batch, &appendRequest, true
				}
			}
			batch = append(batch, appendRequest)
			batchBytes += len(appendRequest.line)
		case <-timer.C:
			return batch, nil, false
		case <-c.stop:
			batch, _, pending := c.drainBatch(batch, batchBytes)
			return batch, pending, true
		}
	}

	select {
	case <-timer.C:
		return batch, nil, false
	case <-c.stop:
		return batch, nil, true
	}
}

func (c *TinybirdClient) drainBatch(
	batch []tinybirdAppendRequest,
	batchBytes int,
) ([]tinybirdAppendRequest, int, *tinybirdAppendRequest) {
	for c.batchHasCapacity(batch, batchBytes) {
		select {
		case appendRequest := <-c.queue:
			if !c.batchCanAppend(batch, batchBytes, appendRequest) {
				return batch, batchBytes, &appendRequest
			}
			batch = append(batch, appendRequest)
			batchBytes += len(appendRequest.line)
		default:
			return batch, batchBytes, nil
		}
	}
	return batch, batchBytes, nil
}

func (c *TinybirdClient) batchHasCapacity(batch []tinybirdAppendRequest, batchBytes int) bool {
	return len(batch) < c.maxBatchRows && batchBytes < c.maxBatchBytes
}

func (c *TinybirdClient) batchCanAppend(
	batch []tinybirdAppendRequest,
	batchBytes int,
	appendRequest tinybirdAppendRequest,
) bool {
	return len(batch) < c.maxBatchRows && batchBytes+len(appendRequest.line) <= c.maxBatchBytes
}

func (c *TinybirdClient) waitForDispatch(lastDispatch time.Time) {
	if lastDispatch.IsZero() {
		return
	}
	delay := time.Until(lastDispatch.Add(c.minRequestInterval))
	if delay > 0 {
		time.Sleep(delay)
	}
}

func (c *TinybirdClient) appendBatch(batch []tinybirdAppendRequest) error {
	bodySize := 0
	for _, appendRequest := range batch {
		bodySize += len(appendRequest.line)
	}
	body := bytes.NewBuffer(make([]byte, 0, bodySize))
	for _, appendRequest := range batch {
		_, _ = body.Write(appendRequest.line)
	}

	endpoint, err := url.Parse(c.host + "/v0/events")
	if err != nil {
		return fmt.Errorf("parse tinybird host: %w", err)
	}
	query := endpoint.Query()
	query.Set("name", tinybirdGatewayRequestsDatasource)
	query.Set("wait", "true")
	endpoint.RawQuery = query.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), tinybirdAppendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), body)
	if err != nil {
		return fmt.Errorf("create tinybird batch request: %w", err)
	}
	req.Header.Set("authorization", "Bearer "+c.token)
	req.Header.Set("content-type", "application/x-ndjson")

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("append tinybird batch: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("append tinybird batch: status %d", res.StatusCode)
	}
	responseBody, err := io.ReadAll(io.LimitReader(res.Body, tinybirdMaxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read tinybird batch acknowledgement: %w", err)
	}
	if len(responseBody) > tinybirdMaxResponseBytes {
		return fmt.Errorf("tinybird batch acknowledgement exceeded %d bytes", tinybirdMaxResponseBytes)
	}
	result := tinybirdEventsResponse{}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("decode tinybird batch acknowledgement: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("decode tinybird batch acknowledgement: trailing data")
	}
	if result.SuccessfulRows != len(batch) || result.QuarantinedRows != 0 {
		return fmt.Errorf(
			"append tinybird batch not committed: expected_rows=%d successful_rows=%d quarantined_rows=%d",
			len(batch),
			result.SuccessfulRows,
			result.QuarantinedRows,
		)
	}
	return nil
}

type tinybirdGatewayRequestEventPayload struct {
	RequestID                    string   `json:"request_id"`
	CreatedAt                    string   `json:"created_at"`
	StogasAPIKeyID               string   `json:"stogas_api_key_id"`
	StogasProvisioningKeyID      *string  `json:"stogas_provisioning_key_id"`
	StogasUserID                 string   `json:"stogas_user_id"`
	StogasOrganizationID         string   `json:"stogas_organization_id"`
	StogasWorkspaceID            string   `json:"stogas_workspace_id"`
	RequestType                  string   `json:"request_type"`
	Cancelled                    uint8    `json:"cancelled"`
	ClientStopMS                 *uint32  `json:"client_stop_ms"`
	CatalogDigest                string   `json:"catalog_digest"`
	ProviderAttempts             string   `json:"provider_attempts"`
	AnalyticsProviderStatus      string   `json:"analytics_provider_status"`
	AnalyticsProviderLatencyMS   uint32   `json:"analytics_provider_latency_ms"`
	AnalyticsTimeToFirstOutputMS *uint32  `json:"analytics_time_to_first_output_ms"`
	AnalyticsProviders           []string `json:"analytics_providers"`
	AnalyticsProviderStatuses    []string `json:"analytics_provider_statuses"`
	StogasProcessingSuccess      uint8    `json:"stogas_processing_success"`
	StogasBillingStatus          string   `json:"stogas_billing_status"`
	NodeID                       string   `json:"node_id"`
	TotalTimeMS                  uint32   `json:"total_time_ms"`
	UpstreamCostUSDAtoms         string   `json:"upstream_cost_usd_atoms"`
	BilledCostUSDAtoms           string   `json:"billed_cost_usd_atoms"`
	AnalyticsUpstreamByok        []string `json:"analytics_upstream_byok"`
	Pricing                      string   `json:"pricing"`
	AnalyticsInputTokens         uint64   `json:"analytics_input_tokens"`
	AnalyticsCachedInputTokens   uint64   `json:"analytics_cached_input_tokens"`
	AnalyticsCacheWriteTokens    uint64   `json:"analytics_cache_write_input_tokens"`
	AnalyticsOutputTokens        uint64   `json:"analytics_output_tokens"`
	AnalyticsReasoningTokens     uint64   `json:"analytics_reasoning_tokens"`
	GatewayVersion               string   `json:"gateway_version"`
	CatalogNodeIDs               string   `json:"catalog_node_ids"`
}

func tinybirdGatewayRequestEvent(event RequestEvent) tinybirdGatewayRequestEventPayload {
	attemptsJSON := mustJSONString(event.ProviderAttempts, "[]")
	pricingJSON := mustJSONString(event.Pricing, "{}")
	catalogNodeIDsJSON := mustJSONString(event.CatalogNodeIDs, "[]")
	processed := uint8(0)
	if event.StogasProcessingSuccess {
		processed = 1
	}
	cancelled := uint8(0)
	if event.Cancelled {
		cancelled = 1
	}
	providerStatus := ""
	providerLatencyMS, timeToFirstOutputMS := event.ProviderTiming()
	upstreamByok := make([]string, 0, len(event.ProviderAttempts))
	providers := make([]string, 0, len(event.ProviderAttempts))
	providerStatuses := make([]string, 0, len(event.ProviderAttempts))
	if finalAttempt, ok := event.FinalProviderAttempt(); ok {
		providerStatus = finalAttempt.Status
	}
	for _, attempt := range event.ProviderAttempts {
		if provider := strings.TrimSpace(attempt.Provider); provider != "" {
			providers = append(providers, provider)
		}
		if status := strings.TrimSpace(attempt.Status); status != "" {
			providerStatuses = append(providerStatuses, status)
		}
		if attempt.StatusCode != nil && *attempt.StatusCode >= 100 && *attempt.StatusCode <= 599 {
			providerStatuses = append(providerStatuses, strconv.Itoa(*attempt.StatusCode))
		}
		if byokID := strings.TrimSpace(attempt.UpstreamByok); byokID != "" {
			upstreamByok = append(upstreamByok, byokID)
		}
	}
	cacheWriteTokens :=
		event.analyticsPricingQuantity(MeterCacheWriteInputTokens) +
			event.analyticsPricingQuantity(MeterCacheWrite5mInputTokens) +
			event.analyticsPricingQuantity(MeterCacheWrite1hInputTokens)
	return tinybirdGatewayRequestEventPayload{
		AnalyticsCachedInputTokens:   event.analyticsPricingQuantity(MeterCachedInputTokens),
		AnalyticsCacheWriteTokens:    cacheWriteTokens,
		AnalyticsInputTokens:         event.analyticsPricingQuantity(MeterInputTokens),
		AnalyticsOutputTokens:        event.analyticsPricingQuantity(MeterOutputTokens),
		AnalyticsProviderLatencyMS:   providerLatencyMS,
		AnalyticsProviderStatus:      providerStatus,
		AnalyticsProviders:           providers,
		AnalyticsProviderStatuses:    providerStatuses,
		AnalyticsReasoningTokens:     event.analyticsPricingQuantity(MeterReasoningTokens),
		AnalyticsTimeToFirstOutputMS: timeToFirstOutputMS,
		AnalyticsUpstreamByok:        upstreamByok,
		Cancelled:                    cancelled,
		ClientStopMS:                 event.ClientStopMS,
		CatalogDigest:                strings.TrimSpace(event.CatalogDigest),
		CreatedAt:                    event.CreatedAt,
		Pricing:                      pricingJSON,
		ProviderAttempts:             attemptsJSON,
		NodeID:                       strings.ToLower(strings.TrimSpace(event.NodeID)),
		GatewayVersion:               strings.TrimSpace(event.GatewayVersion),
		RequestID:                    event.RequestID,
		RequestType:                  event.RequestType,
		CatalogNodeIDs:               catalogNodeIDsJSON,
		StogasAPIKeyID:               event.StogasAPIKeyID,
		StogasProvisioningKeyID:      event.StogasProvisioningKeyID,
		StogasBillingStatus:          event.StogasBillingStatus,
		StogasOrganizationID:         event.StogasOrganizationID,
		StogasProcessingSuccess:      processed,
		StogasUserID:                 event.StogasUserID,
		StogasWorkspaceID:            event.StogasWorkspaceID,
		UpstreamCostUSDAtoms:         event.UpstreamCostUSDAtoms,
		BilledCostUSDAtoms:           event.BilledCostUSDAtoms,
		TotalTimeMS:                  event.TotalTimeMS,
	}
}

func saturatingUint32(value uint64) uint32 {
	const maximum = ^uint32(0)
	if value > uint64(maximum) {
		return maximum
	}
	return uint32(value)
}

func (event RequestEvent) analyticsPricingQuantity(meter string) uint64 {
	return event.analyticsQuantities[meter]
}

func mustJSONString(value any, fallback string) string {
	if value == nil {
		return fallback
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fallback
	}
	return string(encoded)
}
