package billing

// RequestError holds only reviewed public text. Wrapped errors can retain private
// details, so HTTP responses must read Message instead of calling err.Error().
type RequestError struct {
	Code       string
	Message    string
	statusCode int
}

func (e *RequestError) Error() string   { return e.Message }
func (e *RequestError) StatusCode() int { return e.statusCode }

var (
	ErrAPIKeyDisabled      = &RequestError{"key_disabled", "API key is disabled", 403}
	ErrAPIKeyExpired       = &RequestError{"key_expired", "API key is expired", 403}
	ErrGrantDisabled       = &RequestError{"grant_disabled", "Grant is disabled", 403}
	ErrInvalidAPIKey       = &RequestError{"invalid_api_key", "Invalid API key", 401}
	ErrRequestAlreadyUsed  = &RequestError{"request_already_used", "Request already finalized; use a new request ID", 409}
	ErrAuthorizationClosed = &RequestError{"authorization_closed", "Authorization already completed; use a new request ID", 409}
	ErrParamsMismatch      = &RequestError{"authorization_conflict", "Authorization already exists with different parameters", 409}
	ErrInsufficientBalance = &RequestError{"insufficient_balance", "Insufficient credit. Add funds to your organization to retry this request.", 402}
	ErrAPIKeySpendLimit    = &RequestError{"key_spend_limit", "API key spend limit exceeded", 402}
	ErrAPIKeyRateLimit     = &RequestError{"key_rate_limited", "API key rate limit exceeded", 429}
	ErrAPIKeyConfigStale   = &RequestError{"key_configuration_changed", "API key configuration changed. Retry the request.", 503}
	ErrAPIKeyLimit         = &RequestError{"key_limit_exceeded", "API key limit reached or disabled/expired", 402}
	ErrByok                = &RequestError{"byok_unavailable", "BYOK key is unavailable", 503}
	ErrByokRequired        = &RequestError{"byok_required", "A BYOK key is required for this provider", 400}
	ErrByokTarget          = &RequestError{"byok_target_unavailable", "The assigned BYOK credential does not provide this deployment", 400}
	ErrDashboardKeyDenied  = &RequestError{"dashboard_key_denied", "API key is not available to this dashboard session", 403}
	ErrGatewayUnavailable  = &RequestError{"gateway_unavailable", "Stogas is temporarily unavailable. Retry the request later.", 503}
	ErrLocalAdmissionLimit = &RequestError{"key_concurrency_limit", "Too many concurrent requests for this API key", 429}

	errByokNotAllowed               = &RequestError{"byok_not_allowed", "Pass-through BYOK is not allowed by this API key", 400}
	errOrganizationSpendLimit       = &RequestError{"organization_spend_limit", "Organization spend limit exceeded", 402}
	errGrantSpendLimit              = &RequestError{"grant_spend_limit", "Grant spend limit exceeded", 402}
	errOrganizationRateLimit        = &RequestError{"organization_rate_limited", "Organization request rate limit exceeded", 429}
	errGrantRateLimit               = &RequestError{"grant_rate_limited", "Grant request rate limit exceeded", 429}
	errKeyTokenLimit                = &RequestError{"key_token_limit", "API key token limit exceeded", 429}
	errOrganizationTokenLimit       = &RequestError{"organization_token_limit", "Organization token limit exceeded", 429}
	errGrantTokenLimit              = &RequestError{"grant_token_limit", "Grant token limit exceeded", 429}
	errKeyConcurrencyLimit          = &RequestError{"key_concurrency_limit", "API key concurrent-request limit exceeded", 429}
	errOrganizationConcurrencyLimit = &RequestError{"organization_concurrency_limit", "Organization concurrent-request limit exceeded", 429}
	errGrantConcurrencyLimit        = &RequestError{"grant_concurrency_limit", "Grant concurrent-request limit exceeded", 429}
)

// NormalizeStogasErrorCode bounds public history to identifiers owned by the
// gateway. Unknown details remain private and fall back to the HTTP category.
func NormalizeStogasErrorCode(code string, status int) string {
	switch code {
	case "authorization_closed", "authorization_conflict", "billing_price_invalid", "byok_api_key_required",
		"byok_not_allowed", "byok_required", "byok_target_unavailable", "byok_unavailable",
		"catalog_unavailable", "dashboard_key_denied", "gateway_capacity_exceeded", "gateway_draining",
		"gateway_unavailable", "grant_concurrency_limit", "grant_disabled", "grant_rate_limited",
		"grant_spend_limit", "grant_token_limit", "insufficient_balance", "internal_error",
		"invalid_api_key", "invalid_json", "invalid_request", "key_concurrency_limit",
		"key_configuration_changed", "key_disabled", "key_expired", "key_limit_exceeded",
		"key_rate_limited", "key_spend_limit", "key_token_limit", "method_not_allowed",
		"model_ambiguous", "model_unavailable", "organization_concurrency_limit", "organization_rate_limited",
		"organization_spend_limit", "organization_token_limit", "parameter_limit_exceeded", "permission_denied",
		"provider_not_allowed", "provider_unavailable", "rate_limit_exceeded", "reconciliation_released",
		"request_already_used", "request_preparation_failed", "request_too_large", "response_encoding_failed",
		"stogas_response_proof_failed", "route_not_found", "schedule_denied", "service_tier_unavailable",
		"unsupported_media_type", "unsupported_request", "unsupported_service_tier", "unsupported_tool":
		return code
	}

	switch status {
	case 401:
		return "invalid_api_key"
	case 402:
		return "insufficient_balance"
	case 403:
		return "permission_denied"
	case 404:
		return "route_not_found"
	case 405:
		return "method_not_allowed"
	case 413:
		return "request_too_large"
	case 415:
		return "unsupported_media_type"
	case 429:
		return "rate_limit_exceeded"
	case 503:
		return "gateway_unavailable"
	default:
		if status < 500 {
			return "invalid_request"
		}
		return "internal_error"
	}
}
