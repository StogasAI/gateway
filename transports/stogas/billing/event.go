package billing

import (
	"fmt"
	"github.com/maximhq/bifrost/transports/stogas/money"
	"math/big"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

const (
	maxProviderNameBytes      = 64
	maxProviderRequestIDBytes = 512
	maxProviderReasonBytes    = 128
)

type EventInput struct {
	PolicyVersions           *PolicyVersions
	UpstreamCostUSD          string
	Authorization            *Authorization
	Cancelled                bool
	ClientStoppedAt          time.Time
	CatalogVersion           uint64
	CatalogChainHash         string
	SelectedCatalogChainHash string
	Error                    *schemas.BifrostError
	Meters                   EventMeters
	Plugins                  plugins.Metrics
	ProviderAttempts         []ProviderAttemptInput
	ProviderCompletedAt      time.Time
	ProviderStartedAt        time.Time
	TTFTMS                   *uint32
	ProviderOutputObserved   bool
	CacheReadSavingsUSD      *string
	CacheWriteOverheadUSD    *string
	NodeID                   string
	GatewayVersion           string
	RequestType              string
	Response                 *schemas.BifrostResponse
	StartedAt                time.Time
}

type ProviderAttemptInput struct {
	CatalogChainHash         string
	SelectedCatalogChainHash string
	Provider                 string
	StartedAt                time.Time
	CompletedAt              time.Time
	OutputObserved           bool
	Response                 *schemas.BifrostResponse
	Error                    *schemas.BifrostError
}

func NewRequestEvent(input EventInput) (RequestEvent, error) {
	authorization := input.Authorization
	if authorization == nil {
		authorization = &Authorization{}
	}
	startedAt := input.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	// Keep monotonic clocks for elapsed time. Convert only persisted wall
	// timestamps to UTC; UTC() here would make NTP adjustments affect latency.
	finishedAt := time.Now()
	createdAt := startedAt
	if !authorization.CreatedAt.IsZero() {
		createdAt = authorization.CreatedAt
	}
	totalTimeMS := uint32Duration(finishedAt.Sub(startedAt))
	upstreamTimeMS := totalTimeMS
	if !input.ProviderStartedAt.IsZero() && !input.ProviderStartedAt.Before(startedAt) {
		providerCompletedAt := input.ProviderCompletedAt
		if providerCompletedAt.IsZero() || providerCompletedAt.Before(input.ProviderStartedAt) {
			providerCompletedAt = finishedAt
		}
		upstreamTimeMS = uint32Duration(providerCompletedAt.Sub(input.ProviderStartedAt))
	} else if extra := responseExtraFields(input.Response); extra != nil && extra.Latency > 0 {
		upstreamTimeMS = uint32FromInt64(extra.Latency)
	}
	if upstreamTimeMS > totalTimeMS {
		upstreamTimeMS = totalTimeMS
	}
	var clientStopMS *uint32
	if !input.ClientStoppedAt.IsZero() && !input.ClientStoppedAt.Before(startedAt) {
		value := uint32Duration(input.ClientStoppedAt.Sub(startedAt))
		if value > totalTimeMS {
			value = totalTimeMS
		}
		clientStopMS = &value
	}
	upstreamCostRaw := input.UpstreamCostUSD
	if upstreamCostRaw == "" {
		upstreamCostRaw = ZeroChargeUSD
	}
	upstreamCostUSD, err := ParseUSD(upstreamCostRaw)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("invalid upstream cost: %w", err)
	}
	ttftMS := cloneUint32Pointer(input.TTFTMS)
	if !isStreamingRequest(input.RequestType) {
		ttftMS = nil
	} else if ttftMS != nil && *ttftMS > totalTimeMS {
		*ttftMS = totalTimeMS
	}
	pricing, analyticsQuantities, err := ValidateMeters(input.Meters)
	if err != nil {
		return RequestEvent{}, err
	}
	billedCostUSD := calculateBilledCostUSD(authorization, upstreamCostUSD)
	cacheReadSavingsUSD, err := requestOptionalUSD(
		input.CacheReadSavingsUSD,
		"cache read savings",
	)
	if err != nil {
		return RequestEvent{}, err
	}
	cacheWriteOverheadUSD, err := requestOptionalUSD(
		input.CacheWriteOverheadUSD,
		"cache write overhead",
	)
	if err != nil {
		return RequestEvent{}, err
	}
	providerAttempts := requestProviderAttempts(input, authorization, upstreamTimeMS)
	providerStartMS, providerMS := requestProviderTiming(input, startedAt, finishedAt, totalTimeMS)

	return RequestEvent{
		SchemaVersion:        RequestLogSchemaVersion,
		PolicyVersions:       input.PolicyVersions,
		RequestID:            authorization.RequestID,
		CreatedAt:            createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		LastRequestAt:        createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		RequestCount:         1,
		StogasAPIKeyID:       authorization.KeyID,
		StogasGrantID:        authorization.GrantID,
		StogasUserID:         authorization.UserID,
		StogasOrganizationID: authorization.OrganizationID,
		RequestType:          normalizeRequestType(input.RequestType),
		Cancelled:            input.Cancelled,
		ClientStopMS:         clientStopMS,
		CatalogVersion:       catalogVersion(input.CatalogVersion),
		CatalogChainHash:     optionalString(input.CatalogChainHash),
		ProviderAttempts:     providerAttempts,
		NodeID:               strings.ToLower(strings.TrimSpace(input.NodeID)),
		Performance: RequestPerformance{
			TotalMS:         totalTimeMS,
			ProviderMS:      providerMS,
			ProviderStartMS: providerStartMS,
			TTFTMS:          ttftMS,
		},
		UpstreamCostUSD:       upstreamCostUSD.String(),
		BilledCostUSD:         billedCostUSD.String(),
		CacheReadSavingsUSD:   cacheReadSavingsUSD,
		CacheWriteOverheadUSD: cacheWriteOverheadUSD,
		Meters:                pricing,
		Plugins:               input.Plugins,
		GatewayVersion:        strings.TrimSpace(input.GatewayVersion),
		analyticsQuantities:   analyticsQuantities,
	}, nil
}

func catalogVersion(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	return &value
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func requestProviderTiming(input EventInput, startedAt time.Time, finishedAt time.Time, totalTimeMS uint32) (*uint32, uint32) {
	if input.ProviderStartedAt.IsZero() || input.ProviderStartedAt.Before(startedAt) {
		return nil, 0
	}

	admissionMS := min(uint32Duration(input.ProviderStartedAt.Sub(startedAt)), totalTimeMS)
	providerCompletedAt := input.ProviderCompletedAt
	if providerCompletedAt.IsZero() || providerCompletedAt.Before(input.ProviderStartedAt) {
		providerCompletedAt = finishedAt
	}
	return &admissionMS, min(
		uint32Duration(providerCompletedAt.Sub(input.ProviderStartedAt)),
		totalTimeMS-admissionMS,
	)
}

func requestProviderAttempts(input EventInput, authorization *Authorization, fallbackLatencyMS uint32) []ProviderAttempt {
	if len(input.ProviderAttempts) == 0 {
		if input.ProviderStartedAt.IsZero() {
			return []ProviderAttempt{}
		}
		return []ProviderAttempt{{
			Provider:                 authorization.ProviderKey,
			CatalogChainHash:         optionalString(input.CatalogChainHash),
			SelectedCatalogChainHash: changedCatalogSelection(input.SelectedCatalogChainHash, input.CatalogChainHash),
			Status:                   providerAttemptStatus(input.Error, input.Response),
			StatusCode:               providerStatusCode(input.Error),
			LatencyMS:                fallbackLatencyMS,
			OutputObserved:           input.ProviderOutputObserved,
			ProviderRequestID:        upstreamRequestID(input.Response),
			FinishReason:             finishReason(input.Response),
			UpstreamByok:             loggedCredentialID(authorization),
		}}
	}

	attempts := make([]ProviderAttempt, len(input.ProviderAttempts))
	for index, observed := range input.ProviderAttempts {
		provider := boundedTelemetryValue(observed.Provider, maxProviderNameBytes)
		if provider == "" {
			provider = authorization.ProviderKey
		}
		attempts[index] = ProviderAttempt{
			Provider:                 provider,
			CatalogChainHash:         optionalString(observed.CatalogChainHash),
			SelectedCatalogChainHash: changedCatalogSelection(observed.SelectedCatalogChainHash, observed.CatalogChainHash),
			Status:                   providerAttemptStatus(observed.Error, observed.Response),
			StatusCode:               providerStatusCode(observed.Error),
			LatencyMS:                uint32Duration(observed.CompletedAt.Sub(observed.StartedAt)),
			OutputObserved:           observed.OutputObserved,
			ProviderRequestID:        upstreamRequestID(observed.Response),
			FinishReason:             finishReason(observed.Response),
			UpstreamByok:             loggedCredentialID(authorization),
		}
	}
	return attempts
}

func changedCatalogSelection(selected, settled string) *string {
	if selected == settled {
		return nil
	}
	return optionalString(selected)
}

func providerAttemptStatus(bifrostErr *schemas.BifrostError, response *schemas.BifrostResponse) string {
	if bifrostErr != nil {
		return NormalizeUpstreamStatus(bifrostErr)
	}
	if providerResponseContentFiltered(response) {
		return "content_filter"
	}
	return "success"
}

func providerResponseContentFiltered(response *schemas.BifrostResponse) bool {
	switch finishReason(response) {
	case "content_filter", "refusal":
		return true
	}
	var incomplete *schemas.ResponsesResponseIncompleteDetails
	switch {
	case response == nil:
		return false
	case response.ResponsesResponse != nil:
		incomplete = response.ResponsesResponse.IncompleteDetails
	case response.ResponsesStreamResponse != nil && response.ResponsesStreamResponse.Response != nil:
		incomplete = response.ResponsesStreamResponse.Response.IncompleteDetails
	}
	return incomplete != nil && incomplete.Reason == schemas.ResponsesResponseIncompleteReasonContentFilter
}

func requestOptionalUSD(raw *string, name string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := ParseUSD(*raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", name, err)
	}
	normalized := value.String()
	return &normalized, nil
}

func (event RequestEvent) FinalProviderAttempt() (ProviderAttempt, bool) {
	if len(event.ProviderAttempts) == 0 {
		return ProviderAttempt{}, false
	}
	return event.ProviderAttempts[len(event.ProviderAttempts)-1], true
}

func cloneUint32Pointer(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func normalizedUpstreamByok(authorization *Authorization) string {
	if authorization == nil || strings.TrimSpace(authorization.UpstreamByok) == "" {
		return "stogas"
	}
	return strings.TrimSpace(authorization.UpstreamByok)
}

func loggedCredentialID(authorization *Authorization) *string {
	id := normalizedUpstreamByok(authorization)
	if id == ManagedUpstreamByok {
		return nil
	}
	return &id
}

func calculateBilledCostUSD(authorization *Authorization, upstreamCostUSD *money.USD) *money.USD {
	if normalizedUpstreamByok(authorization) == "stogas" {
		return new(money.USD).Set(upstreamCostUSD)
	}
	return new(money.USD).MulRatioCeil(upstreamCostUSD, big.NewInt(2), 100)
}

func isStreamingRequest(requestType string) bool {
	switch requestType {
	case string(schemas.ChatCompletionStreamRequest), string(schemas.ResponsesStreamRequest):
		return true
	default:
		return false
	}
}

func responseExtraFields(resp *schemas.BifrostResponse) *schemas.BifrostResponseExtraFields {
	if resp == nil {
		return nil
	}
	return resp.GetExtraFields()
}

func providerStatusCode(bifrostErr *schemas.BifrostError) *int {
	if bifrostErr == nil {
		status := 200
		return &status
	}
	if bifrostErr.StatusCode == nil {
		return nil
	}
	status := *bifrostErr.StatusCode
	return &status
}

func NormalizeUpstreamStatus(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil {
		return "success"
	}

	statusCode := 0
	if bifrostErr.StatusCode != nil {
		statusCode = *bifrostErr.StatusCode
	}
	identifiers := upstreamErrorIdentifiers(bifrostErr)

	switch {
	case identifiers.has(schemas.RequestCancelled) || statusCode == 499:
		return "cancelled"
	case identifiers.has(schemas.RequestTimedOut, "timeout", "timeout_error"):
		return "timeout"
	case identifiers.has(schemas.ProviderConnectionFailed):
		return "connection_error"
	case identifiers.has("context_length_exceeded", "max_tokens_exceeded", "token_limit_exceeded"):
		return "context_length_exceeded"
	case identifiers.has("request_too_large", "payload_too_large"):
		return "request_too_large"
	case identifiers.has("invalid_image", "image_too_large", "image_too_small", "unsupported_image_format", "image_not_found", "image_download_failed"):
		return "invalid_image"
	case identifiers.has("overloaded_error", "provider_overloaded"):
		return "provider_overloaded"
	case identifiers.has("upstream_response_invalid", "upstream_execution_invalid", "upstream_protocol_error", "upstream_response_too_large"):
		return "invalid_response"
	case identifiers.has("authentication_error", "invalid_api_key", "unauthorized", "upstream_authentication_failed"):
		return "authentication_error"
	case identifiers.has("permission_error", "permission_denied", "forbidden", "upstream_access_denied"):
		return "permission_error"
	case identifiers.has("billing_error", "insufficient_quota", "over_budget", "upstream_quota_exceeded", "payment_required"):
		return "over_budget"
	case identifiers.has("rate_limit_error", "rate_limited", "too_many_requests", "upstream_rate_limit_error", "rate_limit_exceeded"):
		return "rate_limited"
	case identifiers.has("content_filter", "content_filter_error", "safety_error", "content_policy_violation", "refusal"):
		return "content_filter"
	case statusCode == 401:
		return "authentication_error"
	case statusCode == 403:
		return "permission_error"
	case statusCode == 402:
		return "over_budget"
	case statusCode == 429:
		return "rate_limited"
	case statusCode == 408 || statusCode == 504:
		return "timeout"
	case statusCode == 503 || identifiers.has("provider_unavailable"):
		return "provider_unavailable"
	case statusCode == 529:
		return "provider_overloaded"
	case statusCode == 413:
		return "request_too_large"
	case statusCode >= 500:
		return "provider_error"
	case statusCode == 404:
		// The catalog already resolved a known upstream model. A provider 404
		// therefore means that the selected deployment is unavailable or drifted.
		return "model_unavailable"
	case statusCode == 400 || statusCode == 409 || statusCode == 415 || statusCode == 422:
		return "invalid_request"
	case identifiers.has("invalid_request", "invalid_request_error", "bad_request_error"):
		// A generic invalid-request type is useful when status is absent. It must
		// not hide a more reliable 404, 429, or 5xx status.
		return "invalid_request"
	default:
		return "provider_error"
	}
}

type errorIdentifierSet map[string]struct{}

func upstreamErrorIdentifiers(bifrostErr *schemas.BifrostError) errorIdentifierSet {
	identifiers := errorIdentifierSet{}
	if bifrostErr == nil {
		return identifiers
	}
	add := func(value *string) {
		if value == nil {
			return
		}
		if len(*value) > maxProviderReasonBytes {
			return
		}
		identifier := strings.ToLower(strings.TrimSpace(*value))
		if identifier != "" {
			identifiers[identifier] = struct{}{}
		}
	}
	add(bifrostErr.Type)
	if bifrostErr.Error != nil {
		add(bifrostErr.Error.Type)
		add(bifrostErr.Error.Code)
	}
	return identifiers
}

func (identifiers errorIdentifierSet) has(values ...string) bool {
	for _, value := range values {
		if _, ok := identifiers[strings.ToLower(value)]; ok {
			return true
		}
	}
	return false
}

func normalizeRequestType(requestType string) string {
	switch requestType {
	case string(schemas.ChatCompletionRequest):
		return "chat_completion_request"
	case string(schemas.ResponsesRequest):
		return "responses_request"
	default:
		return requestType
	}
}

func finishReason(resp *schemas.BifrostResponse) string {
	if resp == nil {
		return ""
	}
	choices := []schemas.BifrostResponseChoice{}
	if resp.ChatResponse != nil {
		choices = resp.ChatResponse.Choices
	} else if resp.TextCompletionResponse != nil {
		choices = resp.TextCompletionResponse.Choices
	}
	for _, choice := range choices {
		if choice.FinishReason != nil {
			return boundedTelemetryValue(*choice.FinishReason, maxProviderReasonBytes)
		}
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.StopReason != nil {
		return boundedTelemetryValue(*resp.ResponsesResponse.StopReason, maxProviderReasonBytes)
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.StopReason != nil {
		return boundedTelemetryValue(*resp.ResponsesStreamResponse.Response.StopReason, maxProviderReasonBytes)
	}
	return ""
}

func upstreamRequestID(resp *schemas.BifrostResponse) string {
	if resp == nil {
		return ""
	}
	if resp.ChatResponse != nil {
		return boundedTelemetryValue(resp.ChatResponse.ID, maxProviderRequestIDBytes)
	}
	if resp.TextCompletionResponse != nil {
		return boundedTelemetryValue(resp.TextCompletionResponse.ID, maxProviderRequestIDBytes)
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.ID != nil {
		return boundedTelemetryValue(*resp.ResponsesResponse.ID, maxProviderRequestIDBytes)
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.ID != nil {
		return boundedTelemetryValue(*resp.ResponsesStreamResponse.Response.ID, maxProviderRequestIDBytes)
	}
	return ""
}

func boundedTelemetryValue(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) > maximum {
		return ""
	}
	return value
}

// PricedMeter records the quantity used in the charge, including a known free rate.
func PricedMeter(quantity, rateKey, rateUSD, usd string) EventMeter {
	return EventMeter{Quantity: quantity, RateKey: &rateKey, RateUSD: &rateUSD, USD: &usd}
}

// IsInformationalMeter identifies quantities that never carry prices.
func IsInformationalMeter(key string) bool {
	switch key {
	case MeterInputTextBytes, MeterInputFileCount, MeterInputFileURLCount, MeterInputInlineFileBytes, MeterOutputTextBytes, MeterReasoningTextBytes, MeterEstimatedInputTokens, MeterTotalInputTokens, MeterTotalOutputTokens, MeterTotalTokens, MeterTotalCacheWriteTokens, MeterHostedToolCalls, MeterClientToolCalls:
		return true
	default:
		return false
	}
}

func ValidateMeters(pricing EventMeters) (EventMeters, map[string]uint64, error) {
	cloned := make(EventMeters, len(pricing))
	quantities := make(map[string]uint64, len(pricing))
	for key, meter := range pricing {
		if key == "" || strings.TrimSpace(key) != key {
			return nil, nil, fmt.Errorf("invalid meter identity")
		}
		quantity, err := ParseNonnegativeInteger(meter.Quantity)
		if err != nil || !quantity.IsUint64() {
			return nil, nil, fmt.Errorf("invalid meter quantity for %s", key)
		}
		if meter.RateKey == nil && meter.RateUSD == nil && meter.USD == nil {
			// A count without a price is not evidence of a free rate.
		} else {
			if IsInformationalMeter(key) {
				return nil, nil, fmt.Errorf("informational meter cannot be priced: %s", key)
			}
			if meter.RateKey == nil || meter.RateUSD == nil || meter.USD == nil ||
				*meter.RateKey == "" || strings.TrimSpace(*meter.RateKey) != *meter.RateKey {
				return nil, nil, fmt.Errorf("incomplete meter pricing for %s", key)
			}
			rate, rateErr := ParseUSD(*meter.RateUSD)
			amount, amountErr := ParseUSD(*meter.USD)
			if rateErr != nil || amountErr != nil ||
				(quantity.Sign() == 0 && amount.Sign() != 0) ||
				(quantity.Sign() > 0 && (rate.Sign() == 0) != (amount.Sign() == 0)) {
				return nil, nil, fmt.Errorf("invalid meter amount for %s", key)
			}
		}
		cloned[key] = meter
		quantities[key] = quantity.Uint64()
	}
	return cloned, quantities, nil
}

func uint32Duration(value time.Duration) uint32 {
	if value <= 0 {
		return 0
	}
	return uint32FromInt64(value.Milliseconds())
}

func uint32FromInt64(value int64) uint32 {
	if value <= 0 {
		return 0
	}
	if value > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}
