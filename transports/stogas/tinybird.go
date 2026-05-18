package stogas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const tinybirdGatewayRequestsDatasource = "gateway_requests"

type TinybirdClient struct {
	client *http.Client
	host   string
	token  string
}

type ProviderAttempt struct {
	Provider       string  `json:"provider"`
	Status         string  `json:"status"`
	StatusCode     *int    `json:"status_code"`
	LatencyMS      uint32  `json:"latency_ms"`
	ProviderTTFBMS *uint32 `json:"provider_ttfb_ms"`
	IsBYOK         bool    `json:"is_byok"`
}

type GatewayRequestEvent struct {
	RequestID                    string            `json:"request_id"`
	CreatedAt                    string            `json:"created_at"`
	StogasAPIKeyID               string            `json:"stogas_api_key_id"`
	RequestType                  string            `json:"request_type"`
	ProviderAttempts             []ProviderAttempt `json:"provider_attempts"`
	StogasProcessingSuccess      bool              `json:"stogas_processing_success"`
	StogasBillingStatus          string            `json:"stogas_billing_status"`
	UpstreamProviderFinishReason string            `json:"upstream_provider_finish_reason"`
	ProviderRequestID            string            `json:"provider_request_id"`
	TotalTimeMS                  uint32            `json:"total_time_ms"`
	UpstreamProviderTimeMS       uint32            `json:"upstream_provider_time_ms"`
	TTFBMS                       uint32            `json:"ttfb_ms"`
	TotalCostUSDAtoms            string            `json:"total_cost_usd_atoms"`
	Metrics                      map[string]any    `json:"metrics"`
}

func NewTinybirdClient(host string, token string) *TinybirdClient {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	token = strings.TrimSpace(token)
	if host == "" || token == "" {
		return nil
	}
	return &TinybirdClient{
		client: &http.Client{Timeout: 2 * time.Second},
		host:   host,
		token:  token,
	}
}

func (c *TinybirdClient) AppendGatewayRequest(ctx context.Context, event GatewayRequestEvent) error {
	if c == nil {
		return nil
	}
	body, err := json.Marshal(tinybirdGatewayRequestEvent(event))
	if err != nil {
		return fmt.Errorf("marshal tinybird event: %w", err)
	}
	body = append(body, '\n')

	endpoint, err := url.Parse(c.host + "/v0/events")
	if err != nil {
		return fmt.Errorf("parse tinybird host: %w", err)
	}
	query := endpoint.Query()
	query.Set("name", tinybirdGatewayRequestsDatasource)
	query.Set("wait", "true")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create tinybird request: %w", err)
	}
	req.Header.Set("authorization", "Bearer "+c.token)
	req.Header.Set("content-type", "application/x-ndjson")

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("append tinybird event: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("append tinybird event: status %d", res.StatusCode)
	}
	return nil
}

type tinybirdGatewayRequestEventPayload struct {
	RequestID                    string `json:"request_id"`
	CreatedAt                    string `json:"created_at"`
	StogasAPIKeyID               string `json:"stogas_api_key_id"`
	RequestType                  string `json:"request_type"`
	ProviderAttempts             string `json:"provider_attempts"`
	StogasProcessingSuccess      uint8  `json:"stogas_processing_success"`
	StogasBillingStatus          string `json:"stogas_billing_status"`
	UpstreamProviderFinishReason string `json:"upstream_provider_finish_reason"`
	ProviderRequestID            string `json:"provider_request_id"`
	TotalTimeMS                  uint32 `json:"total_time_ms"`
	UpstreamProviderTimeMS       uint32 `json:"upstream_provider_time_ms"`
	TTFBMS                       uint32 `json:"ttfb_ms"`
	TotalCostUSDAtoms            string `json:"total_cost_usd_atoms"`
	Metrics                      string `json:"metrics"`
}

func tinybirdGatewayRequestEvent(event GatewayRequestEvent) tinybirdGatewayRequestEventPayload {
	attemptsJSON := mustJSONString(event.ProviderAttempts, "[]")
	metricsJSON := mustJSONString(event.Metrics, "{}")
	processed := uint8(0)
	if event.StogasProcessingSuccess {
		processed = 1
	}
	return tinybirdGatewayRequestEventPayload{
		CreatedAt:                    event.CreatedAt,
		Metrics:                      metricsJSON,
		ProviderAttempts:             attemptsJSON,
		ProviderRequestID:            event.ProviderRequestID,
		RequestID:                    event.RequestID,
		RequestType:                  event.RequestType,
		StogasAPIKeyID:               event.StogasAPIKeyID,
		StogasBillingStatus:          event.StogasBillingStatus,
		StogasProcessingSuccess:      processed,
		TotalCostUSDAtoms:            event.TotalCostUSDAtoms,
		TotalTimeMS:                  event.TotalTimeMS,
		TTFBMS:                       event.TTFBMS,
		UpstreamProviderFinishReason: event.UpstreamProviderFinishReason,
		UpstreamProviderTimeMS:       event.UpstreamProviderTimeMS,
	}
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
