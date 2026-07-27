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
	Provider              string  `json:"provider"`
	Status                string  `json:"status"`
	StatusCode            *int    `json:"status_code"`
	LatencyMS             uint32  `json:"latency_ms"`
	ProviderFirstOutputMS *uint32 `json:"provider_first_output_ms"`
	IsBYOK                bool    `json:"is_byok"`
}

type RequestEvent struct {
	RequestID                    string            `json:"request_id"`
	CreatedAt                    string            `json:"created_at"`
	StogasAPIKeyID               string            `json:"stogas_api_key_id"`
	StogasProvisioningKeyID      *string           `json:"stogas_provisioning_key_id"`
	StogasUserID                 string            `json:"stogas_user_id"`
	StogasOrganizationID         string            `json:"stogas_organization_id"`
	StogasWorkspaceID            string            `json:"stogas_workspace_id"`
	RequestType                  string            `json:"request_type"`
	ProviderAttempts             []ProviderAttempt `json:"provider_attempts"`
	StogasProcessingSuccess      bool              `json:"stogas_processing_success"`
	StogasBillingStatus          string            `json:"stogas_billing_status"`
	UpstreamProviderFinishReason string            `json:"upstream_provider_finish_reason"`
	ProviderRequestID            string            `json:"provider_request_id"`
	GatewayNodeID                string            `json:"gateway_node_id"`
	TotalTimeMS                  uint32            `json:"total_time_ms"`
	UpstreamProviderTimeMS       uint32            `json:"upstream_provider_time_ms"`
	TTFBMS                       uint32            `json:"ttfb_ms"`
	TotalCostUSDAtoms            string            `json:"total_cost_usd_atoms"`
	Pricing                      map[string]any    `json:"pricing"`
	GatewayVersion               string            `json:"gateway_version"`
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
	RequestID                    string  `json:"request_id"`
	CreatedAt                    string  `json:"created_at"`
	StogasAPIKeyID               string  `json:"stogas_api_key_id"`
	StogasProvisioningKeyID      *string `json:"stogas_provisioning_key_id"`
	StogasUserID                 string  `json:"stogas_user_id"`
	StogasOrganizationID         string  `json:"stogas_organization_id"`
	StogasWorkspaceID            string  `json:"stogas_workspace_id"`
	RequestType                  string  `json:"request_type"`
	ProviderAttempts             string  `json:"provider_attempts"`
	AnalyticsProviderStatus      string  `json:"analytics_provider_status"`
	StogasProcessingSuccess      uint8   `json:"stogas_processing_success"`
	StogasBillingStatus          string  `json:"stogas_billing_status"`
	UpstreamProviderFinishReason string  `json:"upstream_provider_finish_reason"`
	ProviderRequestID            string  `json:"provider_request_id"`
	GatewayNodeID                string  `json:"gateway_node_id"`
	TotalTimeMS                  uint32  `json:"total_time_ms"`
	UpstreamProviderTimeMS       uint32  `json:"upstream_provider_time_ms"`
	TTFBMS                       uint32  `json:"ttfb_ms"`
	TotalCostUSDAtoms            string  `json:"total_cost_usd_atoms"`
	Pricing                      string  `json:"pricing"`
	AnalyticsInputTokens         uint64  `json:"analytics_input_tokens"`
	AnalyticsCachedInputTokens   uint64  `json:"analytics_cached_input_tokens"`
	AnalyticsCacheWriteTokens    uint64  `json:"analytics_cache_write_input_tokens"`
	AnalyticsOutputTokens        uint64  `json:"analytics_output_tokens"`
	AnalyticsReasoningTokens     uint64  `json:"analytics_reasoning_tokens"`
	AnalyticsTimeToFirstOutputMS uint32  `json:"analytics_time_to_first_output_ms"`
	GatewayVersion               string  `json:"gateway_version"`
	ResolvedCatalogNodeIDs       string  `json:"resolved_catalog_node_ids"`
}

func tinybirdGatewayRequestEvent(event RequestEvent) tinybirdGatewayRequestEventPayload {
	attemptsJSON := mustJSONString(event.ProviderAttempts, "[]")
	pricing := clonePricing(event.Pricing)
	pricingJSON := mustJSONString(pricing, "{}")
	resolvedCatalogNodeIDsJSON := mustJSONString(event.ResolvedCatalogNodeIDs, "[]")
	processed := uint8(0)
	if event.StogasProcessingSuccess {
		processed = 1
	}
	providerStatus := ""
	if len(event.ProviderAttempts) > 0 {
		providerStatus = event.ProviderAttempts[0].Status
	}
	cacheWriteTokens :=
		analyticsMeterQuantity(pricing, MeterCacheWrite5mInputTokens) +
			analyticsMeterQuantity(pricing, MeterCacheWrite1hInputTokens)
	timeToFirstOutputMS := uint32(0)
	if len(event.ProviderAttempts) > 0 && event.ProviderAttempts[0].ProviderFirstOutputMS != nil {
		timeToFirstOutputMS = *event.ProviderAttempts[0].ProviderFirstOutputMS
	}
	return tinybirdGatewayRequestEventPayload{
		AnalyticsCachedInputTokens:   analyticsMeterQuantity(pricing, MeterCachedInputTokens),
		AnalyticsCacheWriteTokens:    cacheWriteTokens,
		AnalyticsInputTokens:         analyticsMeterQuantity(pricing, MeterInputTokens),
		AnalyticsOutputTokens:        analyticsMeterQuantity(pricing, MeterOutputTokens),
		AnalyticsProviderStatus:      providerStatus,
		AnalyticsReasoningTokens:     analyticsMeterQuantity(pricing, MeterReasoningTokens),
		AnalyticsTimeToFirstOutputMS: timeToFirstOutputMS,
		CreatedAt:                    event.CreatedAt,
		Pricing:                      pricingJSON,
		ProviderAttempts:             attemptsJSON,
		ProviderRequestID:            event.ProviderRequestID,
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
		TotalCostUSDAtoms:            event.TotalCostUSDAtoms,
		TotalTimeMS:                  event.TotalTimeMS,
		TTFBMS:                       event.TTFBMS,
		UpstreamProviderFinishReason: event.UpstreamProviderFinishReason,
		UpstreamProviderTimeMS:       event.UpstreamProviderTimeMS,
	}
}

func analyticsMeterQuantity(pricing map[string]any, meter string) uint64 {
	entry, ok := pricing[meter].(map[string]any)
	if !ok {
		return 0
	}
	quantity, err := strconv.ParseUint(fmt.Sprint(entry["quantity"]), 10, 64)
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
