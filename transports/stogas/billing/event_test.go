package billing

import (
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestNormalizeUpstreamStatusAndInsurance(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  *int
		message     string
		errorType   string
		code        string
		wantStatus  string
		wantInsured bool
	}{
		{name: "nil success", wantStatus: "success", wantInsured: false},
		{name: "provider auth failure", statusCode: intPtr(401), message: "invalid provider key", wantStatus: "provider_error", wantInsured: true},
		{name: "provider permission failure", statusCode: intPtr(403), message: "permission denied", wantStatus: "provider_error", wantInsured: true},
		{name: "provider permission policy failure is insured", statusCode: intPtr(403), message: "organization policy disabled provider access", wantStatus: "provider_error", wantInsured: true},
		{name: "provider quota failure", statusCode: intPtr(402), message: "insufficient_quota", wantStatus: "over_budget", wantInsured: true},
		{name: "provider rate limit", statusCode: intPtr(429), message: "rate_limit exceeded", wantStatus: "rate_limited", wantInsured: true},
		{name: "provider timeout", statusCode: intPtr(504), message: "upstream timed out", wantStatus: "network_error", wantInsured: true},
		{name: "provider server error", statusCode: intPtr(500), message: "provider failed", wantStatus: "provider_error", wantInsured: true},
		{name: "provider server invalid request wording is insured", statusCode: intPtr(500), message: "provider invalid request processor failed", wantStatus: "provider_error", wantInsured: true},
		{name: "provider safety backend error is insured", statusCode: intPtr(500), message: "provider safety service unavailable", wantStatus: "provider_error", wantInsured: true},
		{name: "network error without status", message: "dial tcp: connection refused", wantStatus: "network_error", wantInsured: true},
		{name: "bad request captures hold", statusCode: intPtr(400), message: "messages.0.content is required", wantStatus: "invalid_request", wantInsured: false},
		{name: "not found captures hold", statusCode: intPtr(404), message: "model not found", wantStatus: "invalid_request", wantInsured: false},
		{name: "conflict captures hold", statusCode: intPtr(409), message: "conflicting request state", wantStatus: "invalid_request", wantInsured: false},
		{name: "request too large captures hold", statusCode: intPtr(413), message: "request exceeds maximum size", wantStatus: "invalid_request", wantInsured: false},
		{name: "unsupported media captures hold", statusCode: intPtr(415), message: "unsupported media type", wantStatus: "invalid_request", wantInsured: false},
		{name: "unprocessable captures hold", statusCode: intPtr(422), message: "invalid tool schema", wantStatus: "invalid_request", wantInsured: false},
		{name: "bad request budget parameter captures hold", statusCode: intPtr(400), message: "task_budget.total is below the provider minimum", wantStatus: "invalid_request", wantInsured: false},
		{name: "bad request rate limit parameter captures hold", statusCode: intPtr(400), message: "rate_limit field is not valid for this model", wantStatus: "invalid_request", wantInsured: false},
		{name: "bad request timeout parameter captures hold", statusCode: intPtr(400), message: "timeout parameter is not supported", wantStatus: "invalid_request", wantInsured: false},
		{name: "bad request network option captures hold", statusCode: intPtr(400), message: "network setting is invalid", wantStatus: "invalid_request", wantInsured: false},
		{name: "content filter captures hold", statusCode: intPtr(400), message: "content_filter", wantStatus: "content_filter", wantInsured: false},
		{name: "safety filter captures hold", statusCode: intPtr(400), message: "blocked by safety filter", wantStatus: "content_filter", wantInsured: false},
		{name: "conversion error without status captures hold", message: "failed to marshal request: missing required field messages", wantStatus: "invalid_request", wantInsured: false},
		{name: "missing required field without status captures hold", message: "missing required 'type' field in ResponsesTool", wantStatus: "invalid_request", wantInsured: false},
		{name: "nil bifrost request without status captures hold", message: "bifrost request cannot be nil", wantStatus: "invalid_request", wantInsured: false},
		{name: "unsupported request without status captures hold", message: "unsupported request type: responses_stream", wantStatus: "invalid_request", wantInsured: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bifrostErr *schemas.BifrostError
			if tt.name != "nil success" {
				bifrostErr = &schemas.BifrostError{
					StatusCode: tt.statusCode,
					Error: &schemas.ErrorField{
						Message: tt.message,
					},
				}
				if tt.errorType != "" {
					bifrostErr.Error.Type = stringPtr(tt.errorType)
				}
				if tt.code != "" {
					bifrostErr.Error.Code = stringPtr(tt.code)
				}
			}
			if got := NormalizeUpstreamStatus(bifrostErr); got != tt.wantStatus {
				t.Fatalf("NormalizeUpstreamStatus = %s, want %s", got, tt.wantStatus)
			}
			if got := ProviderErrorIsInsured(bifrostErr); got != tt.wantInsured {
				t.Fatalf("ProviderErrorIsInsured = %v, want %v", got, tt.wantInsured)
			}
		})
	}
}

func intPtr(value int) *int {
	return &value
}

func stringPtr(value string) *string {
	return &value
}
