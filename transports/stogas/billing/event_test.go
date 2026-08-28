package billing

import (
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/providers/anthropic"
	"github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

var stableUpstreamStatuses = map[string]bool{
	"authentication_error": true,
	"cancelled":            true,
	"content_filter":       true,
	"invalid_request":      true,
	"network_error":        true,
	"over_budget":          true,
	"permission_error":     true,
	"provider_error":       true,
	"rate_limited":         true,
	"success":              true,
}

func TestNormalizeUpstreamStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode *int
		message    string
		outerType  string
		errorType  string
		code       string
		wantStatus string
	}{
		{name: "nil success", wantStatus: "success"},
		{name: "provider auth failure", statusCode: intPtr(401), message: "invalid provider key", wantStatus: "authentication_error"},
		{name: "provider permission failure", statusCode: intPtr(403), message: "permission denied", wantStatus: "permission_error"},
		{name: "provider permission policy failure", statusCode: intPtr(403), message: "organization policy disabled provider access", wantStatus: "permission_error"},
		{name: "provider quota failure", statusCode: intPtr(402), message: "insufficient_quota", wantStatus: "over_budget"},
		{name: "provider rate limit", statusCode: intPtr(429), message: "rate_limit exceeded", wantStatus: "rate_limited"},
		{name: "client cancellation", statusCode: intPtr(499), errorType: schemas.RequestCancelled, wantStatus: "cancelled"},
		{name: "canonical cancellation without status", errorType: schemas.RequestCancelled, wantStatus: "cancelled"},
		{name: "provider timeout", statusCode: intPtr(504), message: "upstream timed out", wantStatus: "network_error"},
		{name: "canonical timeout without status", errorType: schemas.RequestTimedOut, wantStatus: "network_error"},
		{name: "canonical connection failure keeps network meaning through 502", statusCode: intPtr(502), errorType: schemas.ProviderConnectionFailed, wantStatus: "network_error"},
		{name: "ordinary bad gateway remains provider error", statusCode: intPtr(502), errorType: "upstream_error", wantStatus: "provider_error"},
		{name: "canonical authentication type without status", errorType: "authentication_error", wantStatus: "authentication_error"},
		{name: "canonical permission type without status", outerType: "permission_denied", wantStatus: "permission_error"},
		{name: "canonical billing code without status", code: "insufficient_quota", wantStatus: "over_budget"},
		{name: "OpenAI insufficient quota overrides HTTP 429", statusCode: intPtr(429), code: "insufficient_quota", wantStatus: "over_budget"},
		{name: "Chutes authentication code overrides HTTP 503", statusCode: intPtr(503), code: "upstream_authentication_failed", wantStatus: "authentication_error"},
		{name: "Chutes access code overrides HTTP 503", statusCode: intPtr(503), code: "upstream_access_denied", wantStatus: "permission_error"},
		{name: "Chutes quota code overrides HTTP 429", statusCode: intPtr(429), code: "upstream_quota_exceeded", wantStatus: "over_budget"},
		{name: "Chutes rate code overrides HTTP 503", statusCode: intPtr(503), code: "upstream_rate_limit_error", wantStatus: "rate_limited"},
		{name: "Anthropic rate limit type", statusCode: intPtr(429), errorType: "rate_limit_error", wantStatus: "rate_limited"},
		{name: "Anthropic overloaded error", statusCode: intPtr(529), errorType: "overloaded_error", wantStatus: "provider_error"},
		{name: "canonical invalid request type without status", errorType: "invalid_request_error", wantStatus: "invalid_request"},
		{name: "generic invalid request type does not hide rate limit status", statusCode: intPtr(429), errorType: "invalid_request_error", wantStatus: "rate_limited"},
		{name: "generic invalid request type does not hide provider status", statusCode: intPtr(500), errorType: "invalid_request_error", wantStatus: "provider_error"},
		{name: "canonical content filter code without status", code: "content_filter", wantStatus: "content_filter"},
		{name: "canonical content filter code overrides generic permission status", statusCode: intPtr(403), code: "content_filter", wantStatus: "content_filter"},
		{name: "provider server error", statusCode: intPtr(500), message: "provider failed", wantStatus: "provider_error"},
		{name: "provider server invalid request wording", statusCode: intPtr(500), message: "provider invalid request processor failed", wantStatus: "provider_error"},
		{name: "provider safety backend error", statusCode: intPtr(500), message: "provider safety service unavailable", wantStatus: "provider_error"},
		{name: "untyped network wording is not guessed", message: "dial tcp: connection refused", wantStatus: "provider_error"},
		{name: "untyped quota wording is not guessed", message: "quota exhausted", wantStatus: "provider_error"},
		{name: "bad request", statusCode: intPtr(400), message: "messages.0.content is required", wantStatus: "invalid_request"},
		{name: "cataloged provider model not found", statusCode: intPtr(404), message: "model not found", errorType: "invalid_request_error", code: "model_not_found", wantStatus: "provider_error"},
		{name: "conflict", statusCode: intPtr(409), message: "conflicting request state", wantStatus: "invalid_request"},
		{name: "request too large", statusCode: intPtr(413), message: "request exceeds maximum size", wantStatus: "invalid_request"},
		{name: "request-too-large type without status", errorType: "request_too_large", wantStatus: "invalid_request"},
		{name: "unsupported media", statusCode: intPtr(415), message: "unsupported media type", wantStatus: "invalid_request"},
		{name: "unprocessable", statusCode: intPtr(422), message: "invalid tool schema", wantStatus: "invalid_request"},
		{name: "bad request budget parameter", statusCode: intPtr(400), message: "task_budget.total is below the provider minimum", wantStatus: "invalid_request"},
		{name: "bad request rate limit parameter", statusCode: intPtr(400), message: "rate_limit field is not valid for this model", wantStatus: "invalid_request"},
		{name: "bad request timeout parameter", statusCode: intPtr(400), message: "timeout parameter is not supported", wantStatus: "invalid_request"},
		{name: "bad request network option", statusCode: intPtr(400), message: "network setting is invalid", wantStatus: "invalid_request"},
		{name: "Azure content filter code", statusCode: intPtr(400), message: "content_filter", code: "content_filter", wantStatus: "content_filter"},
		{name: "provider safety type", statusCode: intPtr(400), message: "blocked by safety filter", errorType: "safety_error", wantStatus: "content_filter"},
		{name: "untyped conversion wording is not guessed", message: "failed to marshal request: missing required field messages", wantStatus: "provider_error"},
		{name: "untyped required-field wording is not guessed", message: "missing required 'type' field in ResponsesTool", wantStatus: "provider_error"},
		{name: "untyped nil-request wording is not guessed", message: "bifrost request cannot be nil", wantStatus: "provider_error"},
		{name: "untyped unsupported-request wording is not guessed", message: "unsupported request type: responses_stream", wantStatus: "provider_error"},
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
				if tt.outerType != "" {
					bifrostErr.Type = stringPtr(tt.outerType)
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
		})
	}
}

func TestNormalizeUpstreamStatusCoversCanonicalBifrostTransportTypes(t *testing.T) {
	tests := []struct {
		errorType string
		want      string
	}{
		{errorType: schemas.RequestCancelled, want: "cancelled"},
		{errorType: schemas.RequestTimedOut, want: "network_error"},
		{errorType: schemas.ProviderConnectionFailed, want: "network_error"},
		{errorType: schemas.RequestDropped, want: "provider_error"},
	}
	for _, test := range tests {
		t.Run(test.errorType, func(t *testing.T) {
			for _, location := range []string{"outer", "type", "code"} {
				t.Run(location, func(t *testing.T) {
					bifrostErr := &schemas.BifrostError{Error: &schemas.ErrorField{}}
					switch location {
					case "outer":
						bifrostErr.Type = stringPtr("  " + test.errorType + "  ")
					case "type":
						bifrostErr.Error.Type = stringPtr("  " + test.errorType + "  ")
					case "code":
						bifrostErr.Error.Code = stringPtr("  " + test.errorType + "  ")
					}
					if got := NormalizeUpstreamStatus(bifrostErr); got != test.want {
						t.Fatalf("NormalizeUpstreamStatus = %s, want %s", got, test.want)
					}
				})
			}
		})
	}
}

func TestNormalizeUpstreamStatusAlwaysReturnsAStableCategory(t *testing.T) {
	for statusCode := 100; statusCode <= 599; statusCode++ {
		got := NormalizeUpstreamStatus(&schemas.BifrostError{
			StatusCode: &statusCode,
			Error: &schemas.ErrorField{
				Type:    stringPtr("provider_type_added_in_the_future"),
				Code:    stringPtr("provider_code_added_in_the_future"),
				Message: "unrecognized provider rejection",
			},
		})
		if !stableUpstreamStatuses[got] {
			t.Fatalf("HTTP %d returned unsupported category %q", statusCode, got)
		}
	}
}

func TestNormalizeUpstreamStatusExhaustiveStructuredIdentifierMatrix(t *testing.T) {
	type identifierCase struct {
		identifier string
		want       string
		generic    bool
	}
	identifiers := []identifierCase{
		{identifier: schemas.RequestCancelled, want: "cancelled"},
		{identifier: schemas.RequestTimedOut, want: "network_error"},
		{identifier: schemas.ProviderConnectionFailed, want: "network_error"},
		{identifier: "authentication_error", want: "authentication_error"},
		{identifier: "invalid_api_key", want: "authentication_error"},
		{identifier: "unauthorized", want: "authentication_error"},
		{identifier: "upstream_authentication_failed", want: "authentication_error"},
		{identifier: "permission_error", want: "permission_error"},
		{identifier: "permission_denied", want: "permission_error"},
		{identifier: "forbidden", want: "permission_error"},
		{identifier: "upstream_access_denied", want: "permission_error"},
		{identifier: "billing_error", want: "over_budget"},
		{identifier: "insufficient_quota", want: "over_budget"},
		{identifier: "over_budget", want: "over_budget"},
		{identifier: "upstream_quota_exceeded", want: "over_budget"},
		{identifier: "rate_limit_error", want: "rate_limited"},
		{identifier: "rate_limited", want: "rate_limited"},
		{identifier: "too_many_requests", want: "rate_limited"},
		{identifier: "upstream_rate_limit_error", want: "rate_limited"},
		{identifier: "content_filter", want: "content_filter"},
		{identifier: "content_filter_error", want: "content_filter"},
		{identifier: "safety_error", want: "content_filter"},
		{identifier: "invalid_request", want: "invalid_request", generic: true},
		{identifier: "invalid_request_error", want: "invalid_request", generic: true},
		{identifier: "bad_request_error", want: "invalid_request", generic: true},
		{identifier: "request_too_large", want: "invalid_request", generic: true},
	}
	statuses := []*int{
		nil,
		intPtr(200),
		intPtr(400),
		intPtr(401),
		intPtr(402),
		intPtr(403),
		intPtr(404),
		intPtr(408),
		intPtr(409),
		intPtr(413),
		intPtr(415),
		intPtr(418),
		intPtr(422),
		intPtr(429),
		intPtr(499),
		intPtr(500),
		intPtr(502),
		intPtr(504),
		intPtr(529),
	}
	locations := []string{"outer", "type", "code"}

	for _, identifier := range identifiers {
		for _, status := range statuses {
			for _, location := range locations {
				bifrostErr := &schemas.BifrostError{StatusCode: status, Error: &schemas.ErrorField{}}
				value := "  " + mixedCase(identifier.identifier) + "  "
				switch location {
				case "outer":
					bifrostErr.Type = stringPtr(value)
				case "type":
					bifrostErr.Error.Type = stringPtr(value)
				case "code":
					bifrostErr.Error.Code = stringPtr(value)
				}

				want := identifier.want
				if status != nil && *status == 499 {
					want = "cancelled"
				} else if identifier.generic {
					want = expectedStatusFallback(status, "invalid_request")
				}
				if got := NormalizeUpstreamStatus(bifrostErr); got != want {
					t.Fatalf("identifier=%q location=%s status=%v: got %q, want %q", identifier.identifier, location, pointerValue(status), got, want)
				}
			}
		}
	}
}

func TestNormalizeUpstreamStatusIgnoresUntrustedMessagesAndUnknownIdentifiers(t *testing.T) {
	messages := []string{
		"insufficient_quota authentication_error rate_limit_error",
		"content_filter request_cancelled request_timed_out",
		"EOF connection reset by peer broken pipe",
		"messages.0.content is required",
		"\x00\n\t arbitrary future provider text ",
	}
	for statusCode := -100; statusCode <= 700; statusCode++ {
		status := statusCode
		want := expectedStatusFallback(&status, "provider_error")
		for _, message := range messages {
			bifrostErr := &schemas.BifrostError{
				StatusCode: &status,
				Type:       stringPtr("future_outer_type"),
				Error: &schemas.ErrorField{
					Type:    stringPtr("future_nested_type"),
					Code:    stringPtr("future_nested_code"),
					Message: message,
				},
			}
			if got := NormalizeUpstreamStatus(bifrostErr); got != want {
				t.Fatalf("status=%d message=%q: got %q, want %q", statusCode, message, got, want)
			}
		}
	}

	if got := NormalizeUpstreamStatus(&schemas.BifrostError{Error: nil}); got != "provider_error" {
		t.Fatalf("nil nested error = %q, want provider_error", got)
	}
}

func FuzzNormalizeUpstreamStatus(f *testing.F) {
	seeds := []struct {
		status               int
		hasStatus, hasNested bool
		outer, nested, code  string
	}{
		{status: 429, hasStatus: true, hasNested: true, nested: "rate_limit_error"},
		{status: 429, hasStatus: true, hasNested: true, code: "insufficient_quota"},
		{status: 502, hasStatus: true, hasNested: true, nested: schemas.ProviderConnectionFailed},
		{status: 400, hasStatus: true, hasNested: true, outer: "future", nested: "invalid_request_error"},
		{hasNested: false, outer: "future"},
	}
	for _, seed := range seeds {
		f.Add(seed.status, seed.hasStatus, seed.hasNested, seed.outer, seed.nested, seed.code, "provider message")
	}

	f.Fuzz(func(t *testing.T, status int, hasStatus bool, hasNested bool, outer string, nested string, code string, message string) {
		bifrostErr := &schemas.BifrostError{}
		if hasStatus {
			bifrostErr.StatusCode = &status
		}
		if outer != "" {
			bifrostErr.Type = &outer
		}
		if hasNested {
			bifrostErr.Error = &schemas.ErrorField{Message: message}
			if nested != "" {
				bifrostErr.Error.Type = &nested
			}
			if code != "" {
				bifrostErr.Error.Code = &code
			}
		}

		got := NormalizeUpstreamStatus(bifrostErr)
		if !stableUpstreamStatuses[got] {
			t.Fatalf("unsupported category %q", got)
		}
		if hasStatus {
			if preserved := providerStatusCode(bifrostErr); preserved == nil || *preserved != status {
				t.Fatalf("HTTP status was not preserved: got %v, want %d", pointerValue(preserved), status)
			}
		}
		if bifrostErr.Error != nil {
			bifrostErr.Error.Message = "different untrusted message: quota auth EOF safety"
		}
		if afterMessageChange := NormalizeUpstreamStatus(bifrostErr); afterMessageChange != got {
			t.Fatalf("message changed category from %q to %q", got, afterMessageChange)
		}
	})
}

func TestNormalizeUpstreamStatusFromSupportedProviderErrorEnvelopes(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		parse  func(*fasthttp.Response) *schemas.BifrostError
		want   string
	}{
		{
			name:   "OpenAI quota code disambiguates 429",
			status: 429,
			body:   `{"error":{"type":"insufficient_quota","code":"insufficient_quota","message":"quota exhausted"}}`,
			parse:  openai.ParseOpenAIError,
			want:   "over_budget",
		},
		{
			name:   "Azure OpenAI content-filter shape",
			status: 400,
			body:   `{"error":{"type":"invalid_request_error","code":"content_filter","message":"blocked"}}`,
			parse:  openai.ParseOpenAIError,
			want:   "content_filter",
		},
		{
			name:   "Anthropic rate limit type",
			status: 429,
			body:   `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`,
			parse:  anthropic.ParseAnthropicError,
			want:   "rate_limited",
		},
		{
			name:   "Anthropic overload remains broad provider failure",
			status: 529,
			body:   `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`,
			parse:  anthropic.ParseAnthropicError,
			want:   "provider_error",
		},
		{
			name:   "Chutes synthetic access code",
			status: 503,
			body:   `{"error":{"type":"upstream_access_denied","code":"upstream_access_denied","message":"denied"}}`,
			parse:  openai.ParseOpenAIError,
			want:   "permission_error",
		},
		{
			name:   "future provider code safely uses HTTP fallback",
			status: 418,
			body:   `{"error":{"type":"new_error_type","code":"new_error_code","message":"new rejection"}}`,
			parse:  openai.ParseOpenAIError,
			want:   "provider_error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(response)
			response.SetStatusCode(test.status)
			response.Header.SetContentType("application/json")
			response.SetBodyString(test.body)
			bifrostErr := test.parse(response)
			if got := NormalizeUpstreamStatus(bifrostErr); got != test.want {
				t.Fatalf("NormalizeUpstreamStatus(%s) = %s, want %s; error=%s", test.body, got, test.want, bifrostErr)
			}
			if bifrostErr.StatusCode == nil || *bifrostErr.StatusCode != test.status {
				t.Fatalf("provider HTTP status was not preserved: %#v", bifrostErr.StatusCode)
			}
		})
	}
}

func TestProviderAttemptStatusUsesCanonicalResponseTerminal(t *testing.T) {
	refusal := "refusal"
	contentFilter := string(schemas.ResponsesResponseIncompleteReasonContentFilter)
	tests := []struct {
		name     string
		response *schemas.BifrostResponse
		want     string
	}{
		{
			name: "ordinary success",
			response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
				FinishReason: schemas.Ptr("stop"),
			}}}},
			want: "success",
		},
		{
			name: "classifier refusal",
			response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{Choices: []schemas.BifrostResponseChoice{{
				FinishReason: &refusal,
			}}}},
			want: "content_filter",
		},
		{
			name: "responses content filter",
			response: &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
				IncompleteDetails: &schemas.ResponsesResponseIncompleteDetails{Reason: contentFilter},
			}},
			want: "content_filter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := providerAttemptStatus(nil, tt.response); got != tt.want {
				t.Fatalf("providerAttemptStatus = %s, want %s", got, tt.want)
			}
		})
	}

	status := 502
	err := &schemas.BifrostError{StatusCode: &status}
	if got := providerAttemptStatus(err, tests[1].response); got != "provider_error" {
		t.Fatalf("terminal error must take precedence over response metadata, got %s", got)
	}
}

func intPtr(value int) *int {
	return &value
}

func stringPtr(value string) *string {
	return &value
}

func mixedCase(value string) string {
	return strings.ToUpper(value)
}

func expectedStatusFallback(statusCode *int, defaultStatus string) string {
	if statusCode == nil {
		return defaultStatus
	}
	switch {
	case *statusCode == 499:
		return "cancelled"
	case *statusCode == 401:
		return "authentication_error"
	case *statusCode == 403:
		return "permission_error"
	case *statusCode == 402:
		return "over_budget"
	case *statusCode == 429:
		return "rate_limited"
	case *statusCode == 408 || *statusCode == 504:
		return "network_error"
	case *statusCode >= 500 || *statusCode == 404:
		return "provider_error"
	case *statusCode == 400 || *statusCode == 409 || *statusCode == 413 || *statusCode == 415 || *statusCode == 422:
		return "invalid_request"
	default:
		return defaultStatus
	}
}

func pointerValue(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}
