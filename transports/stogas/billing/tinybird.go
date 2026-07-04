package billing

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
const tinybirdAppendTimeout = 10 * time.Second

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

type RequestEvent struct {
	RequestID                    string            `json:"request_id"`
	CreatedAt                    string            `json:"created_at"`
	StogasAPIKeyID               string            `json:"stogas_api_key_id"`
	StogasUserID                 string            `json:"stogas_user_id"`
	StogasOrganizationID         string            `json:"stogas_organization_id"`
	StogasWorkspaceID            string            `json:"stogas_workspace_id"`
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
	Pricing                      map[string]any    `json:"pricing"`
	ReleaseMeasurement           string            `json:"release_measurement"`
	ResolvedCatalogNodeIDs       []string          `json:"resolved_catalog_node_ids"`
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
		client: &http.Client{Timeout: tinybirdAppendTimeout},
		host:   host,
		token:  token,
	}
}

func (c *TinybirdClient) AppendGatewayRequest(ctx context.Context, event RequestEvent) error {
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
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("append tinybird event: status %d", res.StatusCode)
	}
	result := tinybirdEventsResponse{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode tinybird event acknowledgement: %w", err)
	}
	if result.SuccessfulRows != 1 || result.QuarantinedRows != 0 {
		return fmt.Errorf("append tinybird event not committed: successful_rows=%d quarantined_rows=%d", result.SuccessfulRows, result.QuarantinedRows)
	}
	return nil
}

type tinybirdGatewayRequestEventPayload struct {
	RequestID                    string `json:"request_id"`
	CreatedAt                    string `json:"created_at"`
	StogasAPIKeyID               string `json:"stogas_api_key_id"`
	StogasUserID                 string `json:"stogas_user_id"`
	StogasOrganizationID         string `json:"stogas_organization_id"`
	StogasWorkspaceID            string `json:"stogas_workspace_id"`
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
	Pricing                      string `json:"pricing"`
	ReleaseMeasurement           string `json:"release_measurement"`
	ResolvedCatalogNodeIDs       string `json:"resolved_catalog_node_ids"`
}

func tinybirdGatewayRequestEvent(event RequestEvent) tinybirdGatewayRequestEventPayload {
	attemptsJSON := mustJSONString(event.ProviderAttempts, "[]")
	pricing := canonicalPricing(event.Pricing)
	pricingJSON := mustJSONString(pricing, "{}")
	resolvedCatalogNodeIDsJSON := mustJSONString(event.ResolvedCatalogNodeIDs, "[]")
	processed := uint8(0)
	if event.StogasProcessingSuccess {
		processed = 1
	}
	return tinybirdGatewayRequestEventPayload{
		CreatedAt:                    event.CreatedAt,
		Pricing:                      pricingJSON,
		ProviderAttempts:             attemptsJSON,
		ProviderRequestID:            event.ProviderRequestID,
		ReleaseMeasurement:           strings.ToLower(strings.TrimSpace(event.ReleaseMeasurement)),
		RequestID:                    event.RequestID,
		RequestType:                  event.RequestType,
		ResolvedCatalogNodeIDs:       resolvedCatalogNodeIDsJSON,
		StogasAPIKeyID:               event.StogasAPIKeyID,
		StogasBillingStatus:          event.StogasBillingStatus,
		StogasOrganizationID:         event.StogasOrganizationID,
		StogasProcessingSuccess:      processed,
		StogasUserID:                 event.StogasUserID,
		StogasWorkspaceID:            event.StogasWorkspaceID,
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
