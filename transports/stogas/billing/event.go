package billing

import (
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

type EventInput struct {
	ActualCostUSDAtoms string
	Authorization      *Authorization
	Error              *schemas.BifrostError
	FirstByteAt        time.Time
	Pricing            map[string]any
	ProviderTTFBMS     *uint32
	ReleaseMeasurement string
	RequestType        string
	ResolvedCatalogNodeIDs []string
	Response           *schemas.BifrostResponse
	StartedAt          time.Time
}

func NewRequestEvent(input EventInput) RequestEvent {
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
	if extra := responseExtraFields(input.Response); extra != nil && extra.Latency > 0 {
		upstreamTimeMS = uint32FromInt64(extra.Latency)
	}
	ttfbMS := uint32(0)
	if !input.FirstByteAt.IsZero() && input.FirstByteAt.After(startedAt) {
		ttfbMS = uint32Duration(input.FirstByteAt.Sub(startedAt))
	}

	actualCostUSDAtoms := input.ActualCostUSDAtoms
	if actualCostUSDAtoms == "" {
		actualCostUSDAtoms = ZeroChargeUSDAtoms
	}

	return RequestEvent{
		RequestID:                    authorization.RequestID,
		CreatedAt:                    createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		StogasAPIKeyID:               authorization.KeyID,
		StogasUserID:                 authorization.UserID,
		StogasOrganizationID:         authorization.OrganizationID,
		StogasWorkspaceID:            authorization.WorkspaceID,
		RequestType:                  normalizeRequestType(input.RequestType),
		ProviderAttempts:             []ProviderAttempt{{Provider: authorization.ProviderKey, Status: NormalizeUpstreamStatus(input.Error), StatusCode: providerStatusCode(input.Error), LatencyMS: upstreamTimeMS, ProviderTTFBMS: input.ProviderTTFBMS, IsBYOK: false}},
		StogasProcessingSuccess:      true,
		StogasBillingStatus:          settlementStatus(authorization.AuthorizedAmount, authorization.AvailableAfter, actualCostUSDAtoms),
		UpstreamProviderFinishReason: finishReason(input.Response),
		ProviderRequestID:            upstreamRequestID(input.Response),
		TotalTimeMS:                  totalTimeMS,
		UpstreamProviderTimeMS:       upstreamTimeMS,
		TTFBMS:                       ttfbMS,
		TotalCostUSDAtoms:            actualCostUSDAtoms,
		Pricing:                      canonicalPricing(input.Pricing),
		ReleaseMeasurement:           strings.ToLower(strings.TrimSpace(input.ReleaseMeasurement)),
		ResolvedCatalogNodeIDs:       append([]string(nil), input.ResolvedCatalogNodeIDs...),
	}
}

func LLMUsage(resp *schemas.BifrostResponse) *schemas.BifrostLLMUsage {
	if resp == nil {
		return nil
	}
	if resp.ChatResponse != nil {
		return resp.ChatResponse.Usage
	}
	if resp.TextCompletionResponse != nil {
		return resp.TextCompletionResponse.Usage
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.Usage != nil {
		return resp.ResponsesResponse.Usage.ToBifrostLLMUsage()
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.Usage != nil {
		return resp.ResponsesStreamResponse.Response.Usage.ToBifrostLLMUsage()
	}
	return nil
}

func ProviderErrorIsInsured(bifrostErr *schemas.BifrostError) bool {
	switch NormalizeUpstreamStatus(bifrostErr) {
	case "network_error", "provider_error", "rate_limited", "over_budget":
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
	text := strings.ToLower(errorText(bifrostErr))

	switch {
	case statusCode == 402:
		return "over_budget"
	case statusCode == 429:
		return "rate_limited"
	case statusCode == 408 || statusCode == 504:
		return "network_error"
	case statusCode >= 500:
		return "provider_error"
	case looksLikeContentFilterError(text):
		return "content_filter"
	case statusCode == 400 || statusCode == 404 || statusCode == 409 || statusCode == 413 || statusCode == 415 || statusCode == 422:
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

func canonicalPricing(pricing map[string]any) map[string]any {
	canonicalPricing := make(map[string]any, len(pricing))
	for key, value := range pricing {
		if isLegacyPricingMetricKey(key) {
			continue
		}
		canonicalPricing[key] = value
	}
	return canonicalPricing
}

func isLegacyPricingMetricKey(key string) bool {
	switch key {
	case "usageMetrics", "hold_meters", "final_meters", "hold", "final", "basis", "hold_usd_atoms", "total_cost_usd_atoms":
		return true
	default:
		return false
	}
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
