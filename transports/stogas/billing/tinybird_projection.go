package billing

import (
	"encoding/json"
	"strconv"
	"strings"
)

type tinybirdGatewayRequestEventPayload struct {
	SchemaVersion                   uint8    `json:"schema_version"`
	RequestID                       string   `json:"request_id"`
	CreatedAt                       string   `json:"created_at"`
	LastRequestAt                   string   `json:"last_request_at"`
	RequestCount                    uint32   `json:"request_count"`
	GatewayError                    string   `json:"gateway_error"`
	AnalyticsErrorCode              string   `json:"analytics_error_code"`
	AnalyticsErrorStatus            *int     `json:"analytics_error_status"`
	StogasAPIKeyID                  string   `json:"stogas_api_key_id"`
	StogasGrantID                   *string  `json:"stogas_grant_id"`
	StogasUserID                    string   `json:"stogas_user_id"`
	StogasOrganizationID            string   `json:"stogas_organization_id"`
	RequestType                     string   `json:"request_type"`
	Cancelled                       uint8    `json:"cancelled"`
	ClientStopMS                    *uint32  `json:"client_stop_ms"`
	CatalogVersion                  *uint64  `json:"catalog_version"`
	PolicyVersions                  string   `json:"policy_versions"`
	AnalyticsCatalogChainHash       *string  `json:"analytics_catalog_chain_hash"`
	ProviderAttempts                string   `json:"provider_attempts"`
	AnalyticsProviderStatus         string   `json:"analytics_provider_status"`
	AnalyticsProviderOutputObserved uint8    `json:"analytics_provider_output_observed"`
	AnalyticsProviderLatencyMS      uint32   `json:"analytics_provider_latency_ms"`
	AnalyticsProviders              []string `json:"analytics_providers"`
	AnalyticsProviderStatuses       []string `json:"analytics_provider_statuses"`
	NodeID                          string   `json:"node_id"`
	Performance                     string   `json:"performance"`
	AnalyticsTotalMS                uint32   `json:"analytics_total_ms"`
	AnalyticsTTFTMS                 *uint32  `json:"analytics_ttft_ms"`
	UpstreamCostUSD                 string   `json:"upstream_cost_usd"`
	BilledCostUSD                   string   `json:"billed_cost_usd"`
	CacheReadSavingsUSD             *string  `json:"cache_read_savings_usd"`
	CacheWriteOverheadUSD           *string  `json:"cache_write_overhead_usd"`
	AnalyticsUpstreamByok           []string `json:"analytics_upstream_byok"`
	Usage                           string   `json:"usage"`
	Plugins                         string   `json:"plugins"`
	AnalyticsRedactedItems          *uint32  `json:"analytics_redacted_items"`
	AnalyticsInputTokens            *uint64  `json:"analytics_input_tokens"`
	AnalyticsCachedInputTokens      uint64   `json:"analytics_cached_input_tokens"`
	AnalyticsCacheWriteTokens       uint64   `json:"analytics_cache_write_input_tokens"`
	AnalyticsOutputTokens           *uint64  `json:"analytics_output_tokens"`
	AnalyticsTotalTokens            *uint64  `json:"analytics_total_tokens"`
	AnalyticsHostedToolCalls        *uint64  `json:"analytics_hosted_tool_calls"`
	AnalyticsClientToolCalls        *uint64  `json:"analytics_client_tool_calls"`
	AnalyticsReasoningTokens        uint64   `json:"analytics_reasoning_tokens"`
	GatewayVersion                  string   `json:"gateway_version"`
	HoldParamsHash                  string   `json:"hold_params_hash"`
}

func tinybirdGatewayRequestEvent(event RequestEvent) tinybirdGatewayRequestEventPayload {
	attemptsJSON := mustJSONString(event.ProviderAttempts, "[]")
	pluginsJSON := mustJSONString(event.Plugins, `{}`)
	var redactedItems *uint32
	if metrics := event.Plugins.StogasStructuredPIIRedaction; metrics != nil {
		redactedItems = &metrics.ItemsRedacted
	}
	performanceJSON := mustJSONString(event.Performance, `{}`)
	errorCode := ""
	var errorStatus *int
	if event.GatewayError != nil {
		errorCode = event.GatewayError.Code
		errorStatus = &event.GatewayError.Status
	}
	cancelled := uint8(0)
	if event.Cancelled {
		cancelled = 1
	}
	providerStatus := ""
	providerOutputObserved := uint8(0)
	providerLatencyMS := event.Performance.ProviderMS
	upstreamByok := make([]string, 0, len(event.ProviderAttempts))
	providers := make([]string, 0, len(event.ProviderAttempts))
	providerStatuses := make([]string, 0, len(event.ProviderAttempts))
	var catalogChainHash *string
	if finalAttempt, ok := event.FinalProviderAttempt(); ok {
		catalogChainHash = finalAttempt.CatalogChainHash
		providerStatus = finalAttempt.Status
		if finalAttempt.OutputObserved {
			providerOutputObserved = 1
		}
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
		if attempt.Byok == nil {
			upstreamByok = append(upstreamByok, ManagedUpstreamByok)
		} else {
			upstreamByok = append(upstreamByok, *attempt.Byok)
		}
	}
	return tinybirdGatewayRequestEventPayload{
		SchemaVersion:                   event.SchemaVersion,
		AnalyticsCachedInputTokens:      event.analyticsPricingQuantity(MeterCachedInputTokens),
		AnalyticsCacheWriteTokens:       event.analyticsPricingQuantity(MeterTotalCacheWriteTokens),
		AnalyticsInputTokens:            event.analyticsMeterQuantity(MeterTotalInputTokens),
		AnalyticsOutputTokens:           event.analyticsMeterQuantity(MeterTotalOutputTokens),
		AnalyticsProviderLatencyMS:      providerLatencyMS,
		AnalyticsProviderStatus:         providerStatus,
		AnalyticsProviderOutputObserved: providerOutputObserved,
		AnalyticsProviders:              providers,
		AnalyticsProviderStatuses:       providerStatuses,
		AnalyticsTotalTokens:            event.analyticsMeterQuantity(MeterTotalTokens),
		AnalyticsHostedToolCalls:        event.analyticsMeterQuantity(MeterHostedToolCalls),
		AnalyticsClientToolCalls:        event.analyticsMeterQuantity(MeterClientToolCalls),
		AnalyticsReasoningTokens:        event.analyticsPricingQuantity(MeterReasoningTokens),
		AnalyticsTTFTMS:                 event.Performance.TTFTMS,
		AnalyticsUpstreamByok:           upstreamByok,
		Cancelled:                       cancelled,
		ClientStopMS:                    event.ClientStopMS,
		CatalogVersion:                  event.CatalogVersion,
		PolicyVersions:                  mustJSONString(event.PolicyVersions, "null"),
		AnalyticsCatalogChainHash:       catalogChainHash,
		CreatedAt:                       event.CreatedAt,
		LastRequestAt:                   event.LastRequestAt,
		RequestCount:                    event.RequestCount,
		GatewayError:                    mustJSONString(event.GatewayError, "null"),
		AnalyticsErrorCode:              errorCode,
		AnalyticsErrorStatus:            errorStatus,
		Usage:                           mustJSONString(event.Usage, "{}"),
		Plugins:                         pluginsJSON,
		AnalyticsRedactedItems:          redactedItems,
		Performance:                     performanceJSON,
		ProviderAttempts:                attemptsJSON,
		NodeID:                          strings.ToLower(strings.TrimSpace(event.NodeID)),
		GatewayVersion:                  strings.TrimSpace(event.GatewayVersion),
		RequestID:                       event.RequestID,
		RequestType:                     event.RequestType,
		HoldParamsHash:                  event.holdParamsHash,
		StogasAPIKeyID:                  event.StogasAPIKeyID,
		StogasGrantID:                   event.StogasGrantID,
		StogasOrganizationID:            event.StogasOrganizationID,
		StogasUserID:                    event.StogasUserID,
		UpstreamCostUSD:                 event.Usage.UpstreamCostUSD,
		BilledCostUSD:                   event.Usage.BilledCostUSD,
		CacheReadSavingsUSD:             event.Usage.CacheReadSavingsUSD,
		CacheWriteOverheadUSD:           event.Usage.CacheWriteOverheadUSD,
		AnalyticsTotalMS:                event.Performance.TotalMS,
	}
}

func saturatingUint32(value uint64) uint32 {
	const maximum = ^uint32(0)
	if value > uint64(maximum) {
		return maximum
	}
	return uint32(value)
}

func (event RequestEvent) analyticsMeterQuantity(meter string) *uint64 {
	value, known := event.analyticsQuantities[meter]
	if !known {
		return nil
	}
	return &value
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
