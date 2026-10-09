package stogashttp

import (
	"errors"
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

func bifrostErrorPayload(bifrostErr *schemas.BifrostError) any {
	_, payload := publicBifrostError(bifrostErr)
	return payload
}

func publicBifrostError(bifrostErr *schemas.BifrostError) (int, any) {
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
			"Stogas could not complete the response. Retry the request later.", true
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
		status := *bifrostErr.StatusCode
		if status >= 400 && status <= 599 {
			switch status {
			case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden:
				return http.StatusServiceUnavailable
			}
			return status
		}
		return http.StatusInternalServerError
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
	case "invalid_request", "context_length_exceeded", "invalid_image":
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
		"token",
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
	if len(ctx.writer.Header().Get("X-Request-ID")) == 0 {
		_, _ = inferenceRequestID(ctx)
	}
	s.recordAdmissionRejection(ctx, statusCode, stogasbilling.NormalizeStogasErrorCode(code, statusCode))
	data, err := sonic.Marshal(payload)
	if err != nil {
		data = []byte(`{"error":{"message":"Stogas could not complete the response.","type":"internal_error","code":"internal_error","param":null}}`)
	}
	defer clear(data)
	s.writeResponse(ctx, statusCode, "application/json", data)
}

func (s *Server) writeCatalogError(ctx *requestContext, err error) {
	apiErr := catalog.PublicError(err)
	s.writeError(ctx, apiErr.StatusCode, map[string]any{
		"error": map[string]any{"message": apiErr.Message, "type": apiErr.Type, "code": stogasbilling.NormalizeStogasErrorCode(apiErr.Code, apiErr.StatusCode)},
	})
}

func (s *Server) writeBillingError(ctx *requestContext, err error) {
	apiErr := stogas.PublicBillingErrorFor(err)
	var retry interface{ RetryAfter() time.Duration }
	if errors.As(err, &retry) {
		ctx.writer.Header().Set("Retry-After", strconv.FormatInt(max(1, int64((retry.RetryAfter()+time.Second-1)/time.Second)), 10))
	}
	s.writeError(ctx, apiErr.StatusCode, map[string]any{
		"error": map[string]any{"message": apiErr.Message, "type": apiErr.Type, "code": apiErr.Code, "param": nil},
	})
}
