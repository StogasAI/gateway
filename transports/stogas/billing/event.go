package billing

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

type EventInput struct {
	ActualCostUSDAtoms    string
	Authorization         *Authorization
	Cancelled             bool
	ClientStoppedAt       time.Time
	CatalogDigest         string
	Error                 *schemas.BifrostError
	Pricing               EventPricing
	ProviderAttempts      []ProviderAttemptInput
	ProviderCompletedAt   time.Time
	ProviderStartedAt     time.Time
	ProviderFirstOutputMS *uint32
	NodeID                string
	GatewayVersion        string
	RequestType           string
	CatalogNodeIDs        []string
	Response              *schemas.BifrostResponse
	StartedAt             time.Time
}

type ProviderAttemptInput struct {
	Provider              string
	StartedAt             time.Time
	CompletedAt           time.Time
	ProviderFirstOutputMS *uint32
	Response              *schemas.BifrostResponse
	Error                 *schemas.BifrostError
}

func NewRequestEvent(input EventInput) (RequestEvent, error) {
	authorization := input.Authorization
	if authorization == nil {
		authorization = &Authorization{}
	}
	startedAt := input.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	createdAt := startedAt
	if !authorization.CreatedAt.IsZero() {
		createdAt = authorization.CreatedAt
	}
	totalTimeMS := uint32Duration(time.Since(startedAt))
	upstreamTimeMS := totalTimeMS
	if !input.ProviderStartedAt.IsZero() && input.ProviderStartedAt.After(startedAt) {
		providerCompletedAt := input.ProviderCompletedAt
		if providerCompletedAt.IsZero() || providerCompletedAt.Before(input.ProviderStartedAt) {
			providerCompletedAt = time.Now().UTC()
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
	actualCost := input.ActualCostUSDAtoms
	if actualCost == "" {
		actualCost = ZeroChargeUSDAtoms
	}
	actualCostUSDAtoms, err := ParseUSDAtoms(actualCost)
	if err != nil {
		return RequestEvent{}, fmt.Errorf("invalid upstream cost: %w", err)
	}
	firstOutputMS := input.ProviderFirstOutputMS
	if !isStreamingRequest(input.RequestType) {
		firstOutputMS = nil
	}
	pricing, analyticsQuantities, err := validateEventPricing(input.Pricing)
	if err != nil {
		return RequestEvent{}, err
	}
	billedCostUSDAtoms := billedRequestCost(authorization, actualCostUSDAtoms)
	providerAttempts := requestProviderAttempts(input, authorization, upstreamTimeMS, firstOutputMS)

	return RequestEvent{
		RequestID:               authorization.RequestID,
		CreatedAt:               createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		StogasAPIKeyID:          authorization.KeyID,
		StogasProvisioningKeyID: authorization.ProvisioningKeyID,
		StogasUserID:            authorization.UserID,
		StogasOrganizationID:    authorization.OrganizationID,
		StogasWorkspaceID:       authorization.WorkspaceID,
		RequestType:             normalizeRequestType(input.RequestType),
		Cancelled:               input.Cancelled,
		ClientStopMS:            clientStopMS,
		CatalogDigest:           strings.TrimSpace(input.CatalogDigest),
		ProviderAttempts:        providerAttempts,
		StogasProcessingSuccess: true,
		StogasBillingStatus:     settlementStatus(authorization.AuthorizedAmount, authorization.AvailableAfter, billedCostUSDAtoms),
		NodeID:                  strings.ToLower(strings.TrimSpace(input.NodeID)),
		TotalTimeMS:             totalTimeMS,
		UpstreamCostUSDAtoms:    actualCostUSDAtoms.String(),
		BilledCostUSDAtoms:      billedCostUSDAtoms.String(),
		Pricing:                 pricing,
		GatewayVersion:          strings.TrimSpace(input.GatewayVersion),
		CatalogNodeIDs:          append([]string(nil), input.CatalogNodeIDs...),
		analyticsQuantities:     analyticsQuantities,
	}, nil
}

func requestProviderAttempts(input EventInput, authorization *Authorization, fallbackLatencyMS uint32, fallbackFirstOutputMS *uint32) []ProviderAttempt {
	if len(input.ProviderAttempts) == 0 {
		return []ProviderAttempt{{
			Provider:              authorization.ProviderKey,
			Status:                NormalizeUpstreamStatus(input.Error),
			StatusCode:            providerStatusCode(input.Error),
			LatencyMS:             fallbackLatencyMS,
			ProviderFirstOutputMS: cloneUint32Pointer(fallbackFirstOutputMS),
			ProviderRequestID:     upstreamRequestID(input.Response),
			FinishReason:          finishReason(input.Response),
			UpstreamByok:          normalizedUpstreamByok(authorization),
		}}
	}

	attempts := make([]ProviderAttempt, len(input.ProviderAttempts))
	for index, observed := range input.ProviderAttempts {
		provider := strings.TrimSpace(observed.Provider)
		if provider == "" {
			provider = authorization.ProviderKey
		}
		firstOutputMS := cloneUint32Pointer(observed.ProviderFirstOutputMS)
		if !isStreamingRequest(input.RequestType) {
			firstOutputMS = nil
		}
		attempts[index] = ProviderAttempt{
			Provider:              provider,
			Status:                NormalizeUpstreamStatus(observed.Error),
			StatusCode:            providerStatusCode(observed.Error),
			LatencyMS:             uint32Duration(observed.CompletedAt.Sub(observed.StartedAt)),
			ProviderFirstOutputMS: firstOutputMS,
			ProviderRequestID:     upstreamRequestID(observed.Response),
			FinishReason:          finishReason(observed.Response),
			UpstreamByok:          normalizedUpstreamByok(authorization),
		}
	}
	return attempts
}

func (event RequestEvent) FinalProviderAttempt() (ProviderAttempt, bool) {
	if len(event.ProviderAttempts) == 0 {
		return ProviderAttempt{}, false
	}
	return event.ProviderAttempts[len(event.ProviderAttempts)-1], true
}

func (event RequestEvent) ProviderTiming() (uint32, *uint32) {
	finalAttempt, ok := event.FinalProviderAttempt()
	if !ok {
		return 0, nil
	}
	var priorLatency uint64
	for _, attempt := range event.ProviderAttempts[:len(event.ProviderAttempts)-1] {
		priorLatency += uint64(attempt.LatencyMS)
	}
	providerLatencyMS := saturatingUint32(priorLatency + uint64(finalAttempt.LatencyMS))
	if finalAttempt.ProviderFirstOutputMS == nil {
		return providerLatencyMS, nil
	}
	firstOutputMS := saturatingUint32(priorLatency + uint64(*finalAttempt.ProviderFirstOutputMS))
	return providerLatencyMS, &firstOutputMS
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

func billedRequestCost(authorization *Authorization, upstreamCost *big.Int) *big.Int {
	if normalizedUpstreamByok(authorization) == "stogas" {
		return new(big.Int).Set(upstreamCost)
	}
	numerator := new(big.Int).Mul(upstreamCost, big.NewInt(2))
	numerator.Add(numerator, big.NewInt(99))
	return numerator.Quo(numerator, big.NewInt(100))
}

func isStreamingRequest(requestType string) bool {
	switch requestType {
	case string(schemas.ChatCompletionStreamRequest), string(schemas.ResponsesStreamRequest):
		return true
	default:
		return false
	}
}

func ProviderErrorIsInsured(bifrostErr *schemas.BifrostError, managed bool) bool {
	switch NormalizeUpstreamStatus(bifrostErr) {
	case "network_error", "provider_error":
		return true
	case "authentication_error", "permission_error", "rate_limited", "over_budget":
		return managed
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
	text := strings.ToLower(errorText(bifrostErr))

	switch {
	case statusCode == 401:
		return "authentication_error"
	case statusCode == 403:
		return "permission_error"
	case statusCode == 402:
		return "over_budget"
	case statusCode == 429:
		return "rate_limited"
	case statusCode == 408 || statusCode == 504:
		return "network_error"
	case statusCode >= 500:
		return "provider_error"
	case statusCode == 404:
		// The catalog already resolved a known upstream model. A provider 404
		// therefore means that the selected deployment is unavailable or drifted.
		return "provider_error"
	case looksLikeContentFilterError(text):
		return "content_filter"
	case statusCode == 400 || statusCode == 409 || statusCode == 413 || statusCode == 415 || statusCode == 422:
		return "invalid_request"
	case looksLikeRequestConversionError(text):
		return "invalid_request"
	case strings.Contains(text, "rate limit") ||
		strings.Contains(text, "rate_limit") ||
		strings.Contains(text, "slow down"):
		return "rate_limited"
	case strings.Contains(text, "budget") ||
		strings.Contains(text, "quota") ||
		strings.Contains(text, "insufficient_quota"):
		return "over_budget"
	case strings.Contains(text, "timeout") ||
		strings.Contains(text, "timed out") ||
		strings.Contains(text, "connection") ||
		strings.Contains(text, "network") ||
		strings.Contains(text, "eof"):
		return "network_error"
	default:
		return "provider_error"
	}
}

func errorText(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil {
		return ""
	}
	parts := []string{}
	if bifrostErr.Type != nil {
		parts = append(parts, *bifrostErr.Type)
	}
	if bifrostErr.Error != nil {
		if bifrostErr.Error.Type != nil {
			parts = append(parts, *bifrostErr.Error.Type)
		}
		if bifrostErr.Error.Code != nil {
			parts = append(parts, *bifrostErr.Error.Code)
		}
		parts = append(parts, bifrostErr.Error.Message)
		if bifrostErr.Error.Error != nil {
			parts = append(parts, bifrostErr.Error.Error.Error())
		}
	}
	return strings.Join(parts, " ")
}

func looksLikeRequestConversionError(text string) bool {
	for _, needle := range []string{
		"invalid request",
		"invalid chat completion request",
		"invalid responses request",
		"failed to marshal",
		"failed to unmarshal",
		"marshal request",
		"unmarshal request",
		"request conversion",
		"convert request",
		"unsupported request",
		"could not parse request",
		"invalid json",
		"missing required",
		"required field",
		"cannot be nil",
		"request cannot be nil",
		"bifrost request cannot be nil",
	} {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func looksLikeContentFilterError(text string) bool {
	for _, needle := range []string{
		"content_filter",
		"content filter",
		"safety policy",
		"safety filter",
		"safety system refusal",
		"blocked by safety",
		"blocked for safety",
	} {
		if strings.Contains(text, needle) {
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
			return *choice.FinishReason
		}
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.StopReason != nil {
		return *resp.ResponsesResponse.StopReason
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.StopReason != nil {
		return *resp.ResponsesStreamResponse.Response.StopReason
	}
	return ""
}

func upstreamRequestID(resp *schemas.BifrostResponse) string {
	if resp == nil {
		return ""
	}
	if resp.ChatResponse != nil {
		return resp.ChatResponse.ID
	}
	if resp.TextCompletionResponse != nil {
		return resp.TextCompletionResponse.ID
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.ID != nil {
		return *resp.ResponsesResponse.ID
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.ID != nil {
		return *resp.ResponsesStreamResponse.Response.ID
	}
	return ""
}

func validateEventPricing(pricing EventPricing) (EventPricing, map[string]uint64, error) {
	cloned := make(EventPricing, len(pricing))
	quantities := make(map[string]uint64, len(pricing))
	for key, meter := range pricing {
		if key == "" || strings.TrimSpace(key) != key || meter.RateKey == "" || strings.TrimSpace(meter.RateKey) != meter.RateKey {
			return nil, nil, fmt.Errorf("invalid pricing meter identity")
		}
		quantity, err := ParseNonnegativeInteger(meter.Quantity)
		if err != nil || quantity.Sign() <= 0 || !quantity.IsUint64() {
			return nil, nil, fmt.Errorf("invalid pricing meter quantity for %s", key)
		}
		rate, rateErr := ParseUSDAtoms(meter.RateUSDAtoms)
		amount, amountErr := ParseUSDAtoms(meter.USDAtoms)
		if rateErr != nil || amountErr != nil || rate.Sign() <= 0 || amount.Sign() <= 0 {
			return nil, nil, fmt.Errorf("invalid pricing meter amount for %s", key)
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
