package billing

import (
	"encoding/json"
	"fmt"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

type ProviderAttempt struct {
	CatalogChainHash         *string `json:"catalog_chain_hash"`
	SelectedCatalogChainHash *string `json:"selected_catalog_chain_hash,omitempty"`
	Provider                 string  `json:"provider"`
	Status                   string  `json:"status"`
	StatusCode               *int    `json:"status_code"`
	LatencyMS                uint32  `json:"latency_ms"`
	OutputObserved           bool    `json:"output_observed"`
	ProviderRequestID        string  `json:"provider_request_id"`
	FinishReason             string  `json:"finish_reason"`
	UpstreamByok             *string `json:"upstream_byok"`
}

// RequestPerformance records elapsed request and provider time.
// Provider attempts retain their own durations and outcomes.
type RequestPerformance struct {
	TotalMS         uint32  `json:"total_ms"`
	ProviderMS      uint32  `json:"provider_ms"`
	ProviderStartMS *uint32 `json:"provider_start_ms"`
	TTFTMS          *uint32 `json:"ttft_ms"`
}

type EventError struct {
	Code   string `json:"code"`
	Status int    `json:"status"`
}

const RequestLogSchemaVersion uint8 = 1

type RequestEvent struct {
	SchemaVersion         uint8              `json:"schema_version"`
	RequestID             string             `json:"request_id"`
	CreatedAt             string             `json:"created_at"`
	LastRequestAt         string             `json:"last_request_at"`
	RequestCount          uint32             `json:"request_count"`
	Error                 *EventError        `json:"error"`
	StogasAPIKeyID        string             `json:"stogas_api_key_id"`
	StogasGrantID         *string            `json:"stogas_grant_id"`
	StogasUserID          string             `json:"stogas_user_id"`
	StogasOrganizationID  string             `json:"stogas_organization_id"`
	RequestType           string             `json:"request_type"`
	Cancelled             bool               `json:"cancelled"`
	ClientStopMS          *uint32            `json:"client_stop_ms"`
	CatalogVersion        *uint64            `json:"catalog_version"`
	PolicyVersions        *PolicyVersions    `json:"policy_versions"`
	CatalogChainHash      *string            `json:"catalog_chain_hash"`
	ProviderAttempts      []ProviderAttempt  `json:"provider_attempts"`
	NodeID                string             `json:"node_id"`
	Performance           RequestPerformance `json:"performance"`
	UpstreamCostUSD       string             `json:"upstream_cost_usd"`
	BilledCostUSD         string             `json:"billed_cost_usd"`
	CacheReadSavingsUSD   *string            `json:"cache_read_savings_usd"`
	CacheWriteOverheadUSD *string            `json:"cache_write_overhead_usd"`
	Meters                EventMeters        `json:"meters"`
	Plugins               plugins.Metrics    `json:"plugins"`
	GatewayVersion        string             `json:"gateway_version"`
	analyticsQuantities   map[string]uint64
	holdParamsHash        string
}

type EventMeter struct {
	Quantity string  `json:"quantity"`
	RateKey  *string `json:"rateKey,omitempty"`
	RateUSD  *string `json:"rateUsd,omitempty"`
	USD      *string `json:"usd,omitempty"`
}

type EventMeters map[string]EventMeter

func encodeGatewayRequestEvent(event RequestEvent) (string, error) {
	if event.SchemaVersion != RequestLogSchemaVersion {
		return "", fmt.Errorf("unsupported request log schema version: %d", event.SchemaVersion)
	}
	if event.Meters == nil {
		event.Meters = EventMeters{}
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("marshal gateway request log payload: %w", err)
	}
	if len(encoded)+1 > requestLogMaxEventBytes {
		return "", fmt.Errorf("gateway request log payload is %d bytes, limit is %d", len(encoded), requestLogMaxEventBytes-1)
	}
	return string(encoded), nil
}

func decodeGatewayRequestEvent(payload string) (RequestEvent, error) {
	event := RequestEvent{}
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		return RequestEvent{}, fmt.Errorf("unmarshal gateway request log payload: %w", err)
	}
	if event.SchemaVersion != RequestLogSchemaVersion {
		return RequestEvent{}, fmt.Errorf("unsupported request log schema version: %d", event.SchemaVersion)
	}
	pricing, analyticsQuantities, err := ValidateMeters(event.Meters)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("validate gateway request log payload: %w", err)
	}
	event.Meters = pricing
	event.analyticsQuantities = analyticsQuantities
	event.CacheReadSavingsUSD, err = requestOptionalUSD(
		event.CacheReadSavingsUSD,
		"cache read savings",
	)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("validate gateway request log payload: %w", err)
	}
	event.CacheWriteOverheadUSD, err = requestOptionalUSD(
		event.CacheWriteOverheadUSD,
		"cache write overhead",
	)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("validate gateway request log payload: %w", err)
	}
	return event, nil
}
