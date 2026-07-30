package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tinybirdGatewayRequestsDatasource = "gateway_requests"
	tinybirdAppendTimeout             = 10 * time.Second
	tinybirdAppendWaitTimeout         = tinybirdAppendTimeout + time.Second
	// Coalesce briefly after idle, but cap steady-state dispatches independently.
	// Eight nodes therefore use at most 32 of the datasource's 100 requests/second.
	tinybirdBatchWindow        = 50 * time.Millisecond
	tinybirdMinRequestInterval = 250 * time.Millisecond
	tinybirdMaxEventBytes      = 64 * 1024
	// Stay below Tinybird's smallest (10 MB) Events API request limit.
	tinybirdMaxBatchBytes = 8 * 1024 * 1024
	tinybirdMaxBatchRows  = 4096
	tinybirdQueueCapacity = 2048
)

type TinybirdClient struct {
	client             *http.Client
	host               string
	token              string
	batchWindow        time.Duration
	minRequestInterval time.Duration
	maxBatchBytes      int
	maxBatchRows       int
	queue              chan tinybirdAppendRequest
	stop               chan struct{}
	startOnce          sync.Once
	workerWG           sync.WaitGroup
	mu                 sync.RWMutex
	closed             bool
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
	UpstreamCredential    string  `json:"upstream_credential"`
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
	CatalogDigest           string            `json:"catalog_digest"`
	CatalogSequence         uint64            `json:"catalog_sequence"`
	ProviderAttempts        []ProviderAttempt `json:"provider_attempts"`
	StogasProcessingSuccess bool              `json:"stogas_processing_success"`
	StogasBillingStatus     string            `json:"stogas_billing_status"`
	GatewayNodeID           string            `json:"gateway_node_id"`
	TotalTimeMS             uint32            `json:"total_time_ms"`
	UpstreamCostUSDAtoms    string            `json:"upstream_cost_usd_atoms"`
	BilledCostUSDAtoms      string            `json:"billed_cost_usd_atoms"`
	Pricing                 map[string]any    `json:"pricing"`
	GatewayVersion          string            `json:"gateway_version"`
	ResolvedCatalogNodeIDs  []string          `json:"resolved_catalog_node_ids"`
}

type tinybirdEventsResponse struct {
	QuarantinedRows int `json:"quarantined_rows"`
	SuccessfulRows  int `json:"successful_rows"`
}

func NewTinybirdClient(host string, token string) *TinybirdClient {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	token = strings.TrimSpace(token)
	if host == "" || token == "" {
		return nil
	}
	return &TinybirdClient{
		client:             &http.Client{Timeout: tinybirdAppendTimeout},
		host:               host,
		token:              token,
		batchWindow:        tinybirdBatchWindow,
		minRequestInterval: tinybirdMinRequestInterval,
		maxBatchBytes:      tinybirdMaxBatchBytes,
		maxBatchRows:       tinybirdMaxBatchRows,
		queue:              make(chan tinybirdAppendRequest, tinybirdQueueCapacity),
		stop:               make(chan struct{}),
	}
}

func (c *TinybirdClient) AppendGatewayRequest(ctx context.Context, event RequestEvent) error {
	if c == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("append tinybird event: %w", err)
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
		c.waitForDispatch(lastDispatch)
		lastDispatch = time.Now()
		err := c.appendBatch(batch)
		for _, appendRequest := range batch {
			appendRequest.result <- err
		}
	}
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
	result := tinybirdEventsResponse{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode tinybird batch acknowledgement: %w", err)
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
	CatalogDigest                string   `json:"catalog_digest"`
	CatalogSequence              uint64   `json:"catalog_sequence"`
	ProviderAttempts             string   `json:"provider_attempts"`
	AnalyticsProviderStatus      string   `json:"analytics_provider_status"`
	AnalyticsProviderLatencyMS   uint32   `json:"analytics_provider_latency_ms"`
	AnalyticsTimeToFirstOutputMS *uint32  `json:"analytics_time_to_first_output_ms"`
	StogasProcessingSuccess      uint8    `json:"stogas_processing_success"`
	StogasBillingStatus          string   `json:"stogas_billing_status"`
	GatewayNodeID                string   `json:"gateway_node_id"`
	TotalTimeMS                  uint32   `json:"total_time_ms"`
	UpstreamCostUSDAtoms         string   `json:"upstream_cost_usd_atoms"`
	BilledCostUSDAtoms           string   `json:"billed_cost_usd_atoms"`
	AnalyticsUpstreamCredentials []string `json:"analytics_upstream_credentials"`
	Pricing                      string   `json:"pricing"`
	AnalyticsInputTokens         uint64   `json:"analytics_input_tokens"`
	AnalyticsCachedInputTokens   uint64   `json:"analytics_cached_input_tokens"`
	AnalyticsCacheWriteTokens    uint64   `json:"analytics_cache_write_input_tokens"`
	AnalyticsOutputTokens        uint64   `json:"analytics_output_tokens"`
	AnalyticsReasoningTokens     uint64   `json:"analytics_reasoning_tokens"`
	GatewayVersion               string   `json:"gateway_version"`
	ResolvedCatalogNodeIDs       string   `json:"resolved_catalog_node_ids"`
}

func tinybirdGatewayRequestEvent(event RequestEvent) tinybirdGatewayRequestEventPayload {
	attemptsJSON := mustJSONString(event.ProviderAttempts, "[]")
	pricingJSON := mustJSONString(event.Pricing, "{}")
	resolvedCatalogNodeIDsJSON := mustJSONString(event.ResolvedCatalogNodeIDs, "[]")
	processed := uint8(0)
	if event.StogasProcessingSuccess {
		processed = 1
	}
	cancelled := uint8(0)
	if event.Cancelled {
		cancelled = 1
	}
	providerStatus := ""
	var providerLatencyMS uint32
	var timeToFirstOutputMS *uint32
	upstreamCredentials := make([]string, 0, len(event.ProviderAttempts))
	if len(event.ProviderAttempts) > 0 {
		providerStatus = event.ProviderAttempts[0].Status
		providerLatencyMS = event.ProviderAttempts[0].LatencyMS
		timeToFirstOutputMS = event.ProviderAttempts[0].ProviderFirstOutputMS
	}
	for _, attempt := range event.ProviderAttempts {
		if credential := strings.TrimSpace(attempt.UpstreamCredential); credential != "" {
			upstreamCredentials = append(upstreamCredentials, credential)
		}
	}
	cacheWriteTokens :=
		analyticsPricingQuantity(event.Pricing, MeterCacheWriteInputTokens) +
			analyticsPricingQuantity(event.Pricing, MeterCacheWrite5mInputTokens) +
			analyticsPricingQuantity(event.Pricing, MeterCacheWrite1hInputTokens)
	return tinybirdGatewayRequestEventPayload{
		AnalyticsCachedInputTokens:   analyticsPricingQuantity(event.Pricing, MeterCachedInputTokens),
		AnalyticsCacheWriteTokens:    cacheWriteTokens,
		AnalyticsInputTokens:         analyticsPricingQuantity(event.Pricing, MeterInputTokens),
		AnalyticsOutputTokens:        analyticsPricingQuantity(event.Pricing, MeterOutputTokens),
		AnalyticsProviderLatencyMS:   providerLatencyMS,
		AnalyticsProviderStatus:      providerStatus,
		AnalyticsReasoningTokens:     analyticsPricingQuantity(event.Pricing, MeterReasoningTokens),
		AnalyticsTimeToFirstOutputMS: timeToFirstOutputMS,
		AnalyticsUpstreamCredentials: upstreamCredentials,
		Cancelled:                    cancelled,
		CatalogDigest:                strings.TrimSpace(event.CatalogDigest),
		CatalogSequence:              event.CatalogSequence,
		CreatedAt:                    event.CreatedAt,
		Pricing:                      pricingJSON,
		ProviderAttempts:             attemptsJSON,
		GatewayNodeID:                strings.ToLower(strings.TrimSpace(event.GatewayNodeID)),
		GatewayVersion:               strings.TrimSpace(event.GatewayVersion),
		RequestID:                    event.RequestID,
		RequestType:                  event.RequestType,
		ResolvedCatalogNodeIDs:       resolvedCatalogNodeIDsJSON,
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

func analyticsPricingQuantity(pricing map[string]any, meter string) uint64 {
	entry, ok := pricing[meter].(map[string]any)
	if !ok {
		return 0
	}
	quantity, err := strconv.ParseUint(strings.TrimSpace(fmt.Sprint(entry["quantity"])), 10, 64)
	if err != nil {
		return 0
	}
	return quantity
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
