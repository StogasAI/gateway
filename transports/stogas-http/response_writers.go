package stogashttp

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	stogasbilling "github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"net/http"
)

func (s *Server) writeBifrostError(ctx *requestContext, bifrostErr *schemas.BifrostError) {
	statusCode, payload := publicBifrostError(bifrostErr)
	s.writeError(ctx, statusCode, payload)
}

// writeProviderError passes on the provider's wait, which SDKs wait for
// instead of their short backoff when a provider is rate limited or overloaded.
func (s *Server) writeProviderError(ctx *requestContext, bifrostCtx *schemas.BifrostContext, bifrostErr *schemas.BifrostError) {
	statusCode, payload := publicBifrostError(bifrostErr)
	if retryAfter := providerErrorRetryAfter(statusCode, bifrostCtx); retryAfter != "" {
		ctx.writer.Header().Set("Retry-After", retryAfter)
	}
	s.writeError(ctx, statusCode, payload)
}

// providerErrorRetryAfter spreads a provider's wait as spreadRetryAfter does
// ours: one provider account refuses many callers together. A zero wait sends
// no header, because openai-node and the AI SDK retry at once on
// Retry-After: 0, while without it they wait their randomized backoff.
func providerErrorRetryAfter(statusCode int, bifrostCtx *schemas.BifrostContext) string {
	if statusCode != http.StatusTooManyRequests && statusCode != http.StatusServiceUnavailable && statusCode != 529 {
		return ""
	}
	if wait, ok := providerRetryAfter(bifrostCtx); ok && wait > 0 {
		return spreadRetryAfter(wait)
	}
	return ""
}

// providerResponseHeader returns a header of the provider's response.
func providerResponseHeader(bifrostCtx *schemas.BifrostContext, name string) string {
	headers, _ := bifrostCtx.Value(schemas.BifrostContextKeyProviderResponseHeaders).(map[string]string)
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// providerRetryAfter reads how long the provider asks callers to wait, as the
// OpenAI and Anthropic SDKs do: retry-after-ms first, then Retry-After in
// seconds or as an HTTP date.
func providerRetryAfter(bifrostCtx *schemas.BifrostContext) (time.Duration, bool) {
	milliseconds, seconds := providerResponseHeader(bifrostCtx, "retry-after-ms"), providerResponseHeader(bifrostCtx, "retry-after")
	if wait, ok := parseRetryAfter(milliseconds, time.Millisecond); ok {
		return wait, true
	}
	if wait, ok := parseRetryAfter(seconds, time.Second); ok {
		return wait, true
	}
	if at, err := http.ParseTime(seconds); err == nil {
		return max(0, time.Until(at)), true
	}
	return 0, false
}

func parseRetryAfter(value string, unit time.Duration) (time.Duration, bool) {
	amount, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || !(amount >= 0) {
		return 0, false
	}
	// Larger waits saturate; float64(math.MaxInt64) is 2^63.
	if amount*float64(unit) >= math.MaxInt64 {
		return math.MaxInt64, true
	}
	return time.Duration(amount * float64(unit)), true
}

// spreadRetryAfter turns a refusal's wait into Retry-After: whole seconds
// rounded up, so a client never retries early, at least one, plus a second for
// a random half of the waits under a minute. SDKs retry exactly when
// Retry-After says, so the requests of a burst that a limit refused together
// would otherwise come back together and find it nearly empty again. Exact
// waits in retry-after-ms would bring them back together sooner.
func spreadRetryAfter(wait time.Duration) string {
	seconds := max(1, int64(math.Ceil(wait.Seconds())))
	if seconds < 60 {
		seconds += rand.Int64N(2)
	}
	return strconv.FormatInt(seconds, 10)
}

func bifrostErrorPayload(bifrostErr *schemas.BifrostError) any {
	_, payload := publicBifrostError(bifrostErr)
	return payload
}

func publicBifrostError(bifrostErr *schemas.BifrostError) (int, map[string]any) {
	if statusCode, errorType, code, message, ok := publicStableGatewayError(bifrostErr); ok {
		return statusCode, map[string]any{
			"error": map[string]any{
				"code":    code,
				"message": message,
				"param":   nil,
				"type":    errorType,
			},
		}
	}
	statusCode := publicBifrostStatus(bifrostErr)
	errorType := publicBifrostType(statusCode, bifrostErr)
	message := publicBifrostMessage(statusCode, errorType, bifrostErr)
	code := publicBifrostCode(statusCode, bifrostErr)
	param := publicBifrostParam(statusCode, bifrostErr)

	return statusCode, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
			"param":   param,
			"type":    errorType,
		},
	}
}

func publicStableGatewayError(bifrostErr *schemas.BifrostError) (int, string, string, string, bool) {
	if bifrostErr == nil {
		return 0, "", "", "", false
	}
	code := bifrostErrorCode(bifrostErr)
	switch code {
	case "request_timeout":
		return http.StatusGatewayTimeout, schemas.RequestTimedOut, code,
			"The response timed out. Generation may continue and be billed.", true
	case "upstream_verification_failed":
		return http.StatusServiceUnavailable, "gateway_error", code,
			"Provider verification failed; the request was not sent", true
	case "upstream_capacity_unavailable":
		return http.StatusServiceUnavailable, "gateway_error", code,
			"Provider temporarily unavailable.", true
	case "upstream_configuration_error":
		return http.StatusServiceUnavailable, "gateway_error", code,
			"The managed provider configuration is unavailable", true
	case "upstream_protocol_error":
		return http.StatusBadGateway, "gateway_error", code,
			"The provider returned an invalid private response", true
	case "gateway_capacity_exceeded":
		return http.StatusServiceUnavailable, "gateway_error", code,
			"Gateway capacity is temporarily exhausted", true
	case responseProofErrorCode:
		return http.StatusInternalServerError, "internal_error", code,
			"Failed to build confidential response proof", true
	case "billing_price_invalid", "response_encoding_failed":
		return http.StatusInternalServerError, "internal_error", code,
			"We could not complete the response. Retry the request later.", true
	case "upstream_rate_limit_error":
		return http.StatusTooManyRequests, "rate_limit_error", code,
			"The upstream provider rate limit was exceeded", true
	}

	// Use the same bounded structured classification as request telemetry. A
	// provider code such as insufficient_quota must not become a rate limit only
	// because the provider paired it with HTTP 429.
	switch stogasbilling.NormalizeUpstreamStatus(bifrostErr) {
	case "authentication_error":
		return http.StatusBadGateway, "gateway_error", "upstream_authentication_failed",
			"The configured provider credential was rejected", true
	case "over_budget":
		return http.StatusBadGateway, "gateway_error", "upstream_quota_exceeded",
			"The configured provider account has insufficient quota", true
	case "permission_error":
		return http.StatusBadGateway, "gateway_error", "upstream_access_denied",
			"The configured provider credential cannot access the requested model", true
	case "rate_limited":
		return http.StatusTooManyRequests, "rate_limit_error", "upstream_rate_limit_error",
			"The upstream provider rate limit was exceeded", true
	default:
		return 0, "", "", "", false
	}
}

func publicBifrostStatus(bifrostErr *schemas.BifrostError) int {
	if bifrostErr == nil {
		return http.StatusInternalServerError
	}
	if bifrostErr.StatusCode != nil {
		switch status := *bifrostErr.StatusCode; {
		case status == http.StatusUnauthorized || status == http.StatusPaymentRequired || status == http.StatusForbidden:
			// The gateway owns the provider credential, so these statuses never
			// pass through. Credential, quota and access errors have stable codes;
			// any other error here carries a more specific identifier.
		case status >= 400 && status <= 599:
			return status
		default:
			return http.StatusInternalServerError
		}
	}

	switch stogasbilling.NormalizeUpstreamStatus(bifrostErr) {
	case "cancelled":
		return 499
	case "timeout":
		return http.StatusGatewayTimeout
	case "connection_error", "invalid_response":
		return http.StatusBadGateway
	case "provider_unavailable", "provider_overloaded", "model_unavailable":
		return http.StatusServiceUnavailable
	case "request_too_large":
		return http.StatusRequestEntityTooLarge
	case "invalid_request", "context_length_exceeded", "invalid_image", "content_filter":
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func publicBifrostType(statusCode int, bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil {
		return "internal_error"
	}

	if statusCode >= 400 && statusCode < 500 {
		if errorType := bifrostErrorType(bifrostErr); isSafeClientErrorType(errorType) {
			return errorType
		}
	}

	switch statusCode {
	case http.StatusBadRequest, http.StatusMethodNotAllowed, http.StatusConflict, http.StatusUnprocessableEntity:
		return "invalid_request_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusPaymentRequired:
		return "billing_error"
	case http.StatusForbidden:
		return "permission_denied"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case 499:
		return schemas.RequestCancelled
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return "gateway_error"
	case http.StatusGatewayTimeout:
		return schemas.RequestTimedOut
	case 529:
		return "overloaded_error"
	default:
		if statusCode >= 500 && bifrostErr.StatusCode != nil {
			return "gateway_error"
		}
		return "internal_error"
	}
}

func publicBifrostMessage(statusCode int, errorType string, bifrostErr *schemas.BifrostError) string {
	switch {
	case bifrostErr == nil:
		return "Internal server error"
	case statusCode >= 400 && statusCode < 500:
		message := bifrostErrorMessage(bifrostErr)
		if safeProviderClientMessage(message) {
			return message
		}
	}

	switch errorType {
	case "invalid_request_error":
		return "Invalid request"
	case "authentication_error":
		return "Authentication failed"
	case "billing_error":
		return "Billing rejected the request"
	case "permission_denied", "permission_error":
		return "Permission denied"
	case "not_found_error":
		return "Requested resource was not found"
	case "request_too_large":
		return "Request is too large"
	case "rate_limit_error":
		return "Rate limit exceeded"
	case schemas.RequestCancelled:
		return "Request cancelled"
	case schemas.RequestTimedOut, "timeout_error":
		return "Upstream request timed out"
	case "overloaded_error":
		return "Upstream provider is overloaded"
	case "gateway_error":
		if statusCode == http.StatusServiceUnavailable {
			return "Upstream provider is unavailable"
		}
		return "Upstream provider error"
	default:
		return "Internal server error"
	}
}

func publicBifrostCode(statusCode int, bifrostErr *schemas.BifrostError) any {
	if statusCode >= 500 || bifrostErr == nil || bifrostErr.Error == nil || bifrostErr.Error.Code == nil || *bifrostErr.Error.Code == "" {
		return nil
	}
	code := *bifrostErr.Error.Code
	if !safeProviderErrorIdentifier(code, 128, false) {
		return nil
	}
	return code
}

func publicBifrostParam(statusCode int, bifrostErr *schemas.BifrostError) any {
	if statusCode >= 500 || bifrostErr == nil || bifrostErr.Error == nil {
		return nil
	}
	var param string
	switch value := bifrostErr.Error.Param.(type) {
	case string:
		param = value
	case *string:
		if value != nil {
			param = *value
		}
	default:
		return nil
	}
	if !safeProviderErrorIdentifier(param, 256, true) {
		return nil
	}
	return param
}

func bifrostErrorType(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil {
		return ""
	}
	if bifrostErr.Error != nil && bifrostErr.Error.Type != nil && *bifrostErr.Error.Type != "" {
		return *bifrostErr.Error.Type
	}
	if bifrostErr.Type != nil && *bifrostErr.Type != "" {
		return *bifrostErr.Type
	}
	return ""
}

func bifrostErrorCode(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil || bifrostErr.Error == nil || bifrostErr.Error.Code == nil {
		return ""
	}
	return *bifrostErr.Error.Code
}

func bifrostErrorMessage(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil || bifrostErr.Error == nil {
		return ""
	}
	return strings.TrimSpace(bifrostErr.Error.Message)
}

func isSafeClientErrorType(errorType string) bool {
	switch errorType {
	case "invalid_request_error", "authentication_error", "billing_error", "permission_denied", "permission_error", "not_found_error", "request_too_large", "rate_limit_error", schemas.RequestCancelled, schemas.RequestTimedOut:
		return true
	default:
		return false
	}
}

func messageLooksSensitive(message string) bool {
	text := strings.ToLower(message)
	for _, needle := range []string{
		"api key",
		"authorization",
		"bearer ",
		"database",
		"postgres",
		"bifrost",
		"panic",
		"stack",
		"internal",
		"secret",
	} {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func safeProviderClientMessage(message string) bool {
	return message != "" && len(message) <= 1024 && utf8.ValidString(message) &&
		!strings.ContainsRune(message, '\x00') && !messageLooksSensitive(message)
}

func safeProviderErrorIdentifier(value string, maximum int, allowBrackets bool) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '_' || character == '-' ||
			character == '.' || allowBrackets && (character == '[' || character == ']') {
			continue
		}
		return false
	}
	return true
}

func (s *Server) writeJSON(ctx *requestContext, statusCode int, payload any) {
	data, err := marshalPayload(payload)
	if err != nil {
		s.writeError(ctx, http.StatusInternalServerError, map[string]any{
			"error": map[string]any{"message": "Failed to encode response", "type": "internal_error"},
		})
		return
	}
	if _, borrowed := payload.([]byte); !borrowed {
		defer clear(data)
	}
	s.writeResponse(ctx, statusCode, "application/json", data)
}

// Byte-slice payloads are borrowed; all other variants return an owned encoding.
func marshalPayload(payload any) ([]byte, error) {
	switch typed := payload.(type) {
	case []byte:
		return typed, nil
	case string:
		return []byte(typed), nil
	default:
		return sonic.Marshal(payload)
	}
}

func (s *Server) writeError(ctx *requestContext, statusCode int, payload any) {
	code := ""
	if body, ok := payload.(map[string]any); ok {
		if detail, ok := body["error"].(map[string]any); ok {
			rawCode, hasCode := detail["code"]
			code, _ = rawCode.(string)
			if !hasCode || rawCode == "" {
				code = stogasbilling.NormalizeStogasErrorCode("", statusCode)
				detail["code"] = code
			}
			if _, ok := detail["param"]; !ok {
				detail["param"] = nil
			}
		}
	}
	switch code {
	case "upstream_authentication_failed", "upstream_quota_exceeded", "upstream_access_denied":
		// A retry cannot fix the provider account. OpenAI and Anthropic SDKs
		// otherwise retry these 502 responses twice.
		ctx.writer.Header().Set("X-Should-Retry", "false")
	}
	if len(ctx.writer.Header().Get("X-Request-ID")) == 0 {
		_, _ = inferenceRequestID(ctx)
	}
	s.recordAdmissionRejection(ctx, statusCode, stogasbilling.NormalizeStogasErrorCode(code, statusCode), nil)
	data, err := sonic.Marshal(payload)
	if err != nil {
		data = []byte(`{"error":{"message":"We could not complete the response.","type":"internal_error","code":"internal_error","param":null}}`)
	}
	defer clear(data)
	s.writeResponse(ctx, statusCode, "application/json", data)
}

func (s *Server) writeCatalogError(ctx *requestContext, err error) {
	s.writeErrorResponse(ctx, catalogErrorResponse(err))
}

func (s *Server) writeBillingError(ctx *requestContext, err error) {
	s.writeErrorResponse(ctx, billingErrorResponse(err))
}

func (s *Server) writeRequestMemoryCapacity(ctx *requestContext) {
	s.writeErrorResponse(ctx, capacityErrorResponse())
}

type errorResponse struct {
	status     int
	payload    map[string]any
	retryAfter string
	// final tells SDK clients not to retry.
	final bool
}

// code is the error code that writeError reports for the response.
func (r errorResponse) code() string {
	code := ""
	if detail, ok := r.payload["error"].(map[string]any); ok {
		code, _ = detail["code"].(string)
	}
	return stogasbilling.NormalizeStogasErrorCode(code, r.status)
}

func (s *Server) writeErrorResponse(ctx *requestContext, response errorResponse) {
	if response.retryAfter != "" {
		ctx.writer.Header().Set("Retry-After", response.retryAfter)
	}
	if response.final {
		ctx.writer.Header().Set("X-Should-Retry", "false")
	}
	s.writeError(ctx, response.status, response.payload)
}

// localErrorResponse answers a request that ended before any provider call
// reached a provider.
func localErrorResponse(err error) errorResponse {
	var unsent *unsentCall
	var refusal billingFailure
	switch {
	case errors.As(err, &unsent):
		status, payload := publicBifrostError(unsent.failure)
		return errorResponse{status: status, payload: payload, retryAfter: providerErrorRetryAfter(status, unsent.ctx)}
	case errors.Is(err, errRequestMemoryCapacity):
		return capacityErrorResponse()
	case errors.As(err, &refusal), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return billingErrorResponse(err)
	default:
		return catalogErrorResponse(err)
	}
}

func catalogErrorResponse(err error) errorResponse {
	apiErr := catalog.PublicError(err)
	return errorResponse{status: apiErr.StatusCode, payload: map[string]any{
		"error": map[string]any{"message": apiErr.Message, "type": apiErr.Type, "code": stogasbilling.NormalizeStogasErrorCode(apiErr.Code, apiErr.StatusCode)},
	}}
}

func billingErrorResponse(err error) errorResponse {
	apiErr := stogas.PublicBillingErrorFor(err)
	response := errorResponse{status: apiErr.StatusCode, payload: map[string]any{
		"error": map[string]any{"message": apiErr.Message, "type": apiErr.Type, "code": apiErr.Code, "param": nil},
	}}
	var retry interface{ RetryAfter() time.Duration }
	if errors.As(err, &retry) {
		response.retryAfter = spreadRetryAfter(retry.RetryAfter())
	}
	// SDKs retry a 429 within seconds unless told not to. openai-node honors
	// Retry-After only up to a minute and otherwise retries sooner, and
	// Anthropic's SDKs honor any length, so a longer wait would be retried in
	// vain or hold the caller. A per-minute window never waits longer.
	response.final = apiErr.StatusCode == http.StatusTooManyRequests && (retry == nil || retry.RetryAfter() > time.Minute)
	return response
}

func capacityErrorResponse() errorResponse {
	return errorResponse{status: http.StatusServiceUnavailable, payload: map[string]any{
		"error": map[string]any{"message": "Gateway capacity is temporarily exhausted. Retry the request later.", "type": "service_unavailable", "code": "gateway_capacity_exceeded"},
	}, retryAfter: spreadRetryAfter(0)}
}
