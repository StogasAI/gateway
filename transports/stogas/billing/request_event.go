package billing

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

type ProviderAttempt struct {
	CatalogChainHash         string  `json:"catalog_chain_hash"`
	SelectedCatalogChainHash string  `json:"selected_catalog_chain_hash,omitempty"`
	Provider                 string  `json:"provider"`
	Status                   string  `json:"status"`
	StatusCode               *int    `json:"status_code"`
	LatencyMS                uint32  `json:"latency_ms"`
	OutputObserved           bool    `json:"output_observed"`
	ProviderRequestID        string  `json:"provider_request_id"`
	FinishReason             string  `json:"finish_reason"`
	Byok                     *string `json:"byok"`
}

// RequestPerformance records elapsed request and provider time.
// Provider attempts retain their own durations and outcomes.
type RequestPerformance struct {
	TotalMS         uint32  `json:"total_ms"`
	ProviderMS      uint32  `json:"provider_ms"`
	ProviderStartMS *uint32 `json:"provider_start_ms"`
	FirstOutputMS   *uint32 `json:"first_output_ms"`
	TTFTMS          *uint32 `json:"ttft_ms"`
}

type EventError struct {
	Code   string `json:"code"`
	Status int    `json:"status"`
}

const RequestLogSchemaVersion uint8 = 1

type RequestEvent struct {
	SchemaVersion        uint8              `json:"schema_version"`
	RequestID            string             `json:"request_id"`
	CreatedAt            string             `json:"created_at"`
	LastRequestAt        string             `json:"last_request_at"`
	RequestCount         uint32             `json:"request_count"`
	GatewayError         *EventError        `json:"gateway_error"`
	StogasAPIKeyID       string             `json:"stogas_api_key_id"`
	StogasGrantID        *string            `json:"stogas_grant_id"`
	StogasUserID         string             `json:"stogas_user_id"`
	StogasOrganizationID string             `json:"stogas_organization_id"`
	RequestType          string             `json:"request_type"`
	Cancelled            bool               `json:"cancelled"`
	ClientStopMS         *uint32            `json:"client_stop_ms"`
	CatalogVersion       *uint64            `json:"catalog_version"`
	PolicyVersions       *PolicyVersions    `json:"policy_versions"`
	ProviderAttempts     []ProviderAttempt  `json:"provider_attempts"`
	NodeID               string             `json:"node_id"`
	Performance          RequestPerformance `json:"performance"`
	Usage                RequestUsage       `json:"usage"`
	Plugins              plugins.Metrics    `json:"plugins,omitzero"`
	GatewayVersion       string             `json:"gateway_version"`
}

type RequestUsage struct {
	UpstreamCostUSD       string             `json:"upstream_cost_usd"`
	BilledCostUSD         string             `json:"billed_cost_usd"`
	CacheReadSavingsUSD   *string            `json:"cache_read_savings_usd,omitempty"`
	CacheWriteOverheadUSD *string            `json:"cache_write_overhead_usd,omitempty"`
	Meters                EventMeters        `json:"meters"`
	StandardTextTokens    StandardTextTokens `json:"standard_text_tokens"`
}

// StandardTextTokens counts four visible UTF-8 bytes per unit. Unknown material,
// including opaque reasoning, is omitted; observed empty text is exactly zero.
type StandardTextTokens struct {
	Input     *string `json:"input,omitempty"`
	Reasoning *string `json:"reasoning,omitempty"`
	Output    *string `json:"output,omitempty"`
}

func standardTextTokens(meters EventMeters) StandardTextTokens {
	tokens := func(key string) *string {
		meter, known := meters[key]
		if !known {
			return nil
		}
		bytes, err := strconv.ParseUint(meter.Quantity, 10, 64)
		if err != nil {
			return nil
		}
		value := strconv.FormatUint(bytes/4, 10) + [4]string{"", ".25", ".5", ".75"}[bytes%4]
		return &value
	}
	return StandardTextTokens{Input: tokens(MeterInputTextBytes), Reasoning: tokens(MeterReasoningTextBytes), Output: tokens(MeterOutputTextBytes)}
}

type EventMeter struct {
	Quantity string  `json:"quantity"`
	RateKey  *string `json:"rateKey,omitempty"`
	RateUSD  *string `json:"rateUsd,omitempty"`
	USD      *string `json:"usd,omitempty"`
}

type EventMeters map[string]EventMeter

const requestLogMaxEventBytes = 64 * 1024

// settlementLog carries the hold binding, which settlement checks and removes
// before the log reaches customer history.
type settlementLog struct {
	RequestEvent
	HoldParamsHash string `json:"hold_params_hash"`
}

// encodeRequestLog encodes a request's log for settlement. Rejections have no
// hold and pass an empty hash.
func encodeRequestLog(event RequestEvent, holdParamsHash string) (string, error) {
	if event.SchemaVersion != RequestLogSchemaVersion {
		return "", fmt.Errorf("unsupported request log schema version: %d", event.SchemaVersion)
	}
	if event.Usage.Meters == nil {
		event.Usage.Meters = EventMeters{}
	}
	var encoded []byte
	var err error
	if holdParamsHash == "" {
		encoded, err = json.Marshal(event)
	} else {
		encoded, err = json.Marshal(settlementLog{event, holdParamsHash})
	}
	if err != nil {
		return "", fmt.Errorf("marshal request log: %w", err)
	}
	if len(encoded) > requestLogMaxEventBytes {
		return "", fmt.Errorf("request log is %d bytes, limit is %d", len(encoded), requestLogMaxEventBytes)
	}
	return string(encoded), nil
}
