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

type GatewayRequestEvent struct {
	RequestID                    string `json:"request_id"`
	CreatedAt                    string `json:"created_at"`
	OrganizationID               string `json:"organization_id"`
	WorkspaceID                  string `json:"workspace_id"`
	StogasAPIKeyID               string `json:"stogas_api_key_id"`
	RequestType                  string `json:"request_type"`
	UpstreamProvider             string `json:"upstream_provider"`
	Model                        string `json:"model"`
	StogasStatus                 string `json:"stogas_status"`
	UpstreamStatus               string `json:"upstream_status"`
	StogasBillingStatus          string `json:"stogas_billing_status"`
	StogasBillingRecordStatus    string `json:"stogas_billing_record_status"`
	UpstreamProviderFinishReason string `json:"upstream_provider_finish_reason"`
	TotalTimeMS                  uint32 `json:"total_time_ms"`
	UpstreamProviderTimeMS       uint32 `json:"upstream_provider_time_ms"`
	TTFBMS                       uint32 `json:"ttfb_ms"`
	UpstreamProviderTTFBMS       uint32 `json:"upstream_provider_ttfb_ms"`
	UpstreamProviderRequestID    string `json:"upstream_provider_request_id"`
	TotalCostUSDAtoms            string `json:"total_cost_usd_atoms"`
	Metrics                      string `json:"metrics"`
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
	body, err := json.Marshal(event)
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
