package stogas

import (
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func gatewayRequestEvent(ctx *schemas.BifrostContext, authorization *BillingAuthorization, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError, metrics map[string]any, actualCostUSDAtoms string) GatewayRequestEvent {
	startedAt, _ := ctx.Value(requestStartContextKey).(time.Time)
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	createdAt := startedAt
	if !authorization.CreatedAt.IsZero() {
		createdAt = authorization.CreatedAt
	}
	totalTimeMS := uint32Duration(time.Since(startedAt))
	upstreamTimeMS := totalTimeMS
	if extra := responseExtraFields(resp); extra != nil && extra.Latency > 0 {
		upstreamTimeMS = uint32FromInt64(extra.Latency)
	}

	requestType, _ := ctx.Value(requestTypeContextKey).(string)
	model, _ := ctx.Value(requestModelContextKey).(string)
	if actualCostUSDAtoms == "" {
		actualCostUSDAtoms = "0"
	}

	return GatewayRequestEvent{
		RequestID:                    authorization.RequestID,
		CreatedAt:                    createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		StogasAPIKeyID:               authorization.KeyID,
		StogasUserID:                 authorization.UserID,
		StogasOrganizationID:         authorization.OrganizationID,
		StogasWorkspaceID:            authorization.WorkspaceID,
		RequestType:                  normalizeRequestType(requestType),
		ProviderAttempts:             []ProviderAttempt{{Provider: authorization.ProviderKey, Status: normalizeUpstreamStatus(bifrostErr), StatusCode: providerStatusCode(bifrostErr), LatencyMS: upstreamTimeMS, ProviderTTFBMS: nil, IsBYOK: false}},
		StogasProcessingSuccess:      true,
		StogasBillingStatus:          billing.SettlementStatus(authorization.AuthorizedAmount, authorization.AvailableAfter, actualCostUSDAtoms),
		UpstreamProviderFinishReason: finishReason(resp),
		ProviderRequestID:            upstreamRequestID(resp),
		TotalTimeMS:                  totalTimeMS,
		UpstreamProviderTimeMS:       upstreamTimeMS,
		TTFBMS:                       0,
		TotalCostUSDAtoms:            actualCostUSDAtoms,
		Metrics:                      metricsObject(model, metrics),
	}
}

func usageMetrics(resp *schemas.BifrostResponse) map[string]any {
	metrics := map[string]any{}
	usage := llmUsage(resp)
	if usage == nil {
		return metrics
	}
	metrics["promptTokens"] = usage.PromptTokens
	metrics["completionTokens"] = usage.CompletionTokens
	metrics["totalTokens"] = usage.TotalTokens
	return metrics
}

func llmUsage(resp *schemas.BifrostResponse) *schemas.BifrostLLMUsage {
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

func normalizeUpstreamStatus(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil {
		return "success"
	}

	statusCode := 0
	if bifrostErr.StatusCode != nil {
		statusCode = *bifrostErr.StatusCode
	}
	text := strings.ToLower(errorText(bifrostErr))

	switch {
	case strings.Contains(text, "content_filter") ||
		strings.Contains(text, "content filter") ||
		strings.Contains(text, "safety") ||
		strings.Contains(text, "policy"):
		return "content_filter"
	case statusCode == 402 ||
		strings.Contains(text, "budget") ||
		strings.Contains(text, "quota") ||
		strings.Contains(text, "insufficient_quota"):
		return "over_budget"
	case statusCode == 429 ||
		strings.Contains(text, "rate limit") ||
		strings.Contains(text, "rate_limit") ||
		strings.Contains(text, "slow down"):
		return "rate_limited"
	case statusCode == 400 || statusCode == 404 || statusCode == 409 || statusCode == 422:
		return "invalid_request"
	case statusCode == 408 || statusCode == 504 ||
		strings.Contains(text, "timeout") ||
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

func metricsObject(model string, usage map[string]any) map[string]any {
	tokens := map[string]any{
		"prompt":     numberMetric(usage, "promptTokens"),
		"completion": numberMetric(usage, "completionTokens"),
		"reasoning":  nil,
		"cached":     nil,
	}
	return map[string]any{
		"model":  model,
		"tokens": tokens,
	}
}

func numberMetric(metrics map[string]any, key string) any {
	value, ok := metrics[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return typed
	case uint:
		return typed
	case uint64:
		return typed
	case float64:
		return typed
	default:
		return 0
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
