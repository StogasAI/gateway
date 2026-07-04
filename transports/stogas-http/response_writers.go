package stogashttp

import (
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/valyala/fasthttp"
)

func (s *Server) forwardProviderHeadersFromContext(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext) {
	if headers, ok := bifrostCtx.Value(schemas.BifrostContextKeyProviderResponseHeaders).(map[string]string); ok {
		s.forwardProviderHeaders(ctx, bifrostCtx, schemas.BifrostResponseExtraFields{ProviderResponseHeaders: headers})
	}
}

func (s *Server) writeBifrostError(ctx *fasthttp.RequestCtx, bifrostErr *schemas.BifrostError) {
	statusCode, payload := publicBifrostError(bifrostErr)
	s.writeError(ctx, statusCode, payload)
}

func bifrostErrorPayload(bifrostErr *schemas.BifrostError) any {
	_, payload := publicBifrostError(bifrostErr)
	return payload
}

func publicBifrostError(bifrostErr *schemas.BifrostError) (int, any) {
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

func publicBifrostStatus(bifrostErr *schemas.BifrostError) int {
	if bifrostErr == nil {
		return fasthttp.StatusInternalServerError
	}
	if bifrostErr.StatusCode != nil {
		status := *bifrostErr.StatusCode
		if status >= 400 && status <= 599 {
			switch status {
			case fasthttp.StatusUnauthorized, fasthttp.StatusPaymentRequired, fasthttp.StatusForbidden:
				return fasthttp.StatusServiceUnavailable
			}
			return status
		}
		return fasthttp.StatusInternalServerError
	}

	errorText := bifrostErrorText(bifrostErr)
	switch {
	case bifrostHasType(bifrostErr, schemas.RequestCancelled):
		return 499
	case bifrostHasType(bifrostErr, schemas.RequestTimedOut), looksLikeTimeoutError(errorText):
		return fasthttp.StatusGatewayTimeout
	case looksLikeNetworkError(errorText):
		return fasthttp.StatusServiceUnavailable
	case looksLikeClientConversionError(errorText):
		return fasthttp.StatusBadRequest
	default:
		return fasthttp.StatusInternalServerError
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
	case fasthttp.StatusBadRequest, fasthttp.StatusMethodNotAllowed, fasthttp.StatusConflict, fasthttp.StatusUnprocessableEntity:
		return "invalid_request_error"
	case fasthttp.StatusUnauthorized:
		return "authentication_error"
	case fasthttp.StatusPaymentRequired:
		return "billing_error"
	case fasthttp.StatusForbidden:
		return "permission_denied"
	case fasthttp.StatusNotFound:
		return "not_found_error"
	case fasthttp.StatusRequestEntityTooLarge:
		return "request_too_large"
	case fasthttp.StatusTooManyRequests:
		return "rate_limit_error"
	case 499:
		return schemas.RequestCancelled
	case fasthttp.StatusBadGateway, fasthttp.StatusServiceUnavailable:
		return "gateway_error"
	case fasthttp.StatusGatewayTimeout:
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
	case statusCode == fasthttp.StatusBadRequest && looksLikeClientConversionError(bifrostErrorText(bifrostErr)):
		return "Invalid request"
	case statusCode >= 400 && statusCode < 500:
		message := bifrostErrorMessage(bifrostErr)
		if message != "" && !messageLooksSensitive(message) {
			return message
		}
	}

	switch errorType {
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
		if statusCode == fasthttp.StatusServiceUnavailable {
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
	return *bifrostErr.Error.Code
}

func publicBifrostParam(statusCode int, bifrostErr *schemas.BifrostError) any {
	if statusCode >= 500 || bifrostErr == nil || bifrostErr.Error == nil {
		return nil
	}
	return bifrostErr.Error.Param
}

func bifrostHasType(bifrostErr *schemas.BifrostError, errorType string) bool {
	return bifrostErrorType(bifrostErr) == errorType
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

func bifrostErrorMessage(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil || bifrostErr.Error == nil {
		return ""
	}
	return strings.TrimSpace(bifrostErr.Error.Message)
}

func bifrostErrorText(bifrostErr *schemas.BifrostError) string {
	if bifrostErr == nil {
		return ""
	}
	parts := []string{bifrostErrorType(bifrostErr), bifrostErrorMessage(bifrostErr)}
	if bifrostErr.Error != nil {
		if bifrostErr.Error.Code != nil {
			parts = append(parts, *bifrostErr.Error.Code)
		}
		if bifrostErr.Error.Error != nil {
			parts = append(parts, bifrostErr.Error.Error.Error())
		}
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func isSafeClientErrorType(errorType string) bool {
	switch errorType {
	case "invalid_request_error", "authentication_error", "billing_error", "permission_denied", "permission_error", "not_found_error", "request_too_large", "rate_limit_error", schemas.RequestCancelled, schemas.RequestTimedOut:
		return true
	default:
		return false
	}
}

func looksLikeClientConversionError(text string) bool {
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
		"invalid json",
		"missing required",
		"required field",
		"cannot be nil",
	} {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func looksLikeTimeoutError(text string) bool {
	return strings.Contains(text, "timeout") || strings.Contains(text, "timed out") || strings.Contains(text, "deadline exceeded")
}

func looksLikeNetworkError(text string) bool {
	for _, needle := range []string{
		"api connection",
		"connection refused",
		"connection reset",
		"connection closed",
		"no such host",
		"network is unreachable",
		"temporary failure in name resolution",
		"tls handshake",
		"unexpected eof",
		"provider do request failed",
	} {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
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

func (s *Server) writeJSON(ctx *fasthttp.RequestCtx, statusCode int, payload any) {
	data, err := marshalPayload(payload)
	if err != nil {
		s.writeError(ctx, fasthttp.StatusInternalServerError, map[string]any{
			"error": map[string]any{"message": "Failed to encode response", "type": "internal_error"},
		})
		return
	}
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")
	_, _ = ctx.Write(data)
}

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

func (s *Server) writeError(ctx *fasthttp.RequestCtx, statusCode int, payload any) {
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")
	data, err := sonic.Marshal(payload)
	if err != nil {
		ctx.Response.SetBodyString(`{"error":{"message":"Failed to encode error","type":"internal_error"}}`)
		return
	}
	_, _ = ctx.Write(data)
}

func (s *Server) writeCatalogError(ctx *fasthttp.RequestCtx, err error) {
	apiErr := catalog.PublicError(err)
	s.writeError(ctx, apiErr.StatusCode, map[string]any{
		"error": map[string]any{"message": apiErr.Message, "type": apiErr.Type},
	})
}

func (s *Server) writeBillingError(ctx *fasthttp.RequestCtx, err error) {
	apiErr := stogas.PublicBillingErrorFor(err)
	s.writeError(ctx, apiErr.StatusCode, map[string]any{
		"error": map[string]any{"message": apiErr.Message, "type": apiErr.Type},
	})
}

func (s *Server) forwardProviderHeaders(ctx *fasthttp.RequestCtx, bifrostCtx *schemas.BifrostContext, extra schemas.BifrostResponseExtraFields) {
	headers := extra.ProviderResponseHeaders
	if state, ok := stogas.StateFrom(bifrostCtx); ok && state.ProviderResponseHeaders != nil {
		headers = state.ProviderResponseHeaders
	}
	for key, value := range safeProviderResponseHeaders(headers) {
		ctx.Response.Header.Set(key, value)
	}
}
