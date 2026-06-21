package stogas

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

type statusError struct {
	err        error
	statusCode int
}

func mustBigInt(t *testing.T, value string) *big.Int {
	t.Helper()
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid big int %q", value)
	}
	return parsed
}

func (e *statusError) Error() string { return e.err.Error() }
func (e *statusError) Unwrap() error { return e.err }
func (e *statusError) StatusCode() int {
	return e.statusCode
}

type fakeBillingAuthorizer struct {
	attempts    []string
	finalEvents []billing.RequestEvent
	results     []*billing.Authorization
	errors      []error
	callCount   int
}

func (f *fakeBillingAuthorizer) AuthorizeRequest(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string, amountUSDAtoms string) (*billing.Authorization, error) {
	f.attempts = append(f.attempts, requestID)
	idx := f.callCount
	f.callCount++
	if idx < len(f.results) && f.results[idx] != nil {
		return f.results[idx], nil
	}
	if idx < len(f.errors) {
		return nil, f.errors[idx]
	}
	return nil, nil
}

func (f *fakeBillingAuthorizer) FinalizeRequest(ctx context.Context, authorization *billing.Authorization, event billing.RequestEvent) error {
	f.finalEvents = append(f.finalEvents, event)
	return nil
}

func TestAuthorizeWithFreshRequestIDRetriesConflict(t *testing.T) {
	initialRequestID := "11111111-1111-1111-1111-111111111111"
	expected := &billing.Authorization{HoldID: "hold-1"}
	authorizer := &fakeBillingAuthorizer{
		results: []*billing.Authorization{nil, expected},
		errors: []error{
			&statusError{err: billing.ErrRequestAlreadyUsed, statusCode: 409},
			nil,
		},
	}
	plugin := &Plugin{billing: authorizer}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, initialRequestID)

	authorization, err := plugin.authorizeWithFreshRequestID(ctx, "sk-user", initialRequestID, catalog.HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", MaxUSDAtoms: "1000"}, authorizer.errors[0])
	if err != nil {
		t.Fatalf("authorizeWithFreshRequestID returned error: %v", err)
	}
	if authorization != expected {
		t.Fatalf("expected authorization pointer to be reused")
	}
	if len(authorizer.attempts) != 2 {
		t.Fatalf("expected 2 authorization attempts, got %d", len(authorizer.attempts))
	}
	if authorizer.attempts[0] == initialRequestID {
		t.Fatalf("expected helper retries to use fresh request IDs")
	}
	if authorizer.attempts[1] == initialRequestID || authorizer.attempts[1] == authorizer.attempts[0] {
		t.Fatalf("expected each retry to use a distinct fresh request ID")
	}
	currentRequestID, _ := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if currentRequestID != authorizer.attempts[1] {
		t.Fatalf("expected context request ID to match retried request ID, got %q want %q", currentRequestID, authorizer.attempts[1])
	}
}

func TestAuthorizeWithFreshRequestIDLeavesNonConflictErrorsUntouched(t *testing.T) {
	initialRequestID := "11111111-1111-1111-1111-111111111111"
	expectedErr := &statusError{err: billing.ErrInvalidAPIKey, statusCode: 401}
	plugin := &Plugin{billing: &fakeBillingAuthorizer{}}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, initialRequestID)

	authorization, err := plugin.authorizeWithFreshRequestID(ctx, "sk-user", initialRequestID, catalog.HoldEstimate{ProviderKey: "openai", ProductKey: "gpt-5", MaxUSDAtoms: "1000"}, expectedErr)
	if authorization != nil {
		t.Fatalf("expected no authorization for non-conflict error")
	}
	if !errors.Is(err, billing.ErrInvalidAPIKey) {
		t.Fatalf("expected invalid API key error, got %v", err)
	}
	currentRequestID, _ := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if currentRequestID != initialRequestID {
		t.Fatalf("expected request ID to remain unchanged, got %q", currentRequestID)
	}
}

func TestPostLLMHookFinalizesProviderErrors(t *testing.T) {
	authorization := &billing.Authorization{
		AuthorizedAmount: mustBigInt(t, "5000"),
		AvailableAfter:   mustBigInt(t, "10000000000"),
		KeyID:            "key-1",
		ProductKey:       "gpt-4o-mini",
		ProviderKey:      "openai",
		RequestID:        "request-1",
		UserID:           "user-1",
	}
	authorizer := &fakeBillingAuthorizer{}
	plugin := &Plugin{billing: authorizer}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	setBillingAuthorization(ctx, authorization)
	ctx.SetValue(requestTypeContextKey, string(schemas.ChatCompletionRequest))
	ctx.SetValue(requestModelContextKey, "gpt-4o-mini")
	status := 502
	bifrostErr := &schemas.BifrostError{StatusCode: &status}

	_, returnedErr, err := plugin.PostLLMHook(ctx, nil, bifrostErr)
	if err != nil {
		t.Fatalf("PostLLMHook returned plugin error: %v", err)
	}
	if returnedErr != bifrostErr {
		t.Fatalf("expected original provider error to be preserved")
	}
	if len(authorizer.finalEvents) != 1 {
		t.Fatalf("expected one finalization event, got %#v", authorizer.finalEvents)
	}
	event := authorizer.finalEvents[0]
	if !event.StogasProcessingSuccess || len(event.ProviderAttempts) != 1 || event.ProviderAttempts[0].Status != "provider_error" {
		t.Fatalf("expected processed provider error attempt, got %#v", event)
	}
	if event.StogasBillingStatus != "over_reserved" {
		t.Fatalf("expected insured zero-cost provider error to return the hold, got %q", event.StogasBillingStatus)
	}
	if event.TotalCostUSDAtoms != billing.ZeroChargeUSDAtoms {
		t.Fatalf("expected insured provider error to settle at zero, got %s", event.TotalCostUSDAtoms)
	}
	if event.RequestType != "chat_completion_request" {
		t.Fatalf("expected normalized request type, got %q", event.RequestType)
	}
}

func TestPostLLMHookDoesNotInsureClientCausedProviderErrors(t *testing.T) {
	authorization := &billing.Authorization{
		AuthorizedAmount: mustBigInt(t, "5000"),
		AvailableAfter:   mustBigInt(t, "10000000000"),
		KeyID:            "key-1",
		ProductKey:       "gpt-4o-mini",
		ProviderKey:      "openai",
		RequestID:        "request-1",
		UserID:           "user-1",
	}
	authorizer := &fakeBillingAuthorizer{}
	plugin := &Plugin{billing: authorizer}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	setBillingAuthorization(ctx, authorization)
	ctx.SetValue(requestTypeContextKey, string(schemas.ChatCompletionRequest))
	ctx.SetValue(requestModelContextKey, "gpt-4o-mini")
	status := 400
	bifrostErr := &schemas.BifrostError{
		StatusCode: &status,
		Error:      &schemas.ErrorField{Message: "Unsupported parameter: tool_choice", Type: schemas.Ptr("invalid_request_error")},
	}

	_, returnedErr, err := plugin.PostLLMHook(ctx, nil, bifrostErr)
	if err != nil {
		t.Fatalf("PostLLMHook returned plugin error: %v", err)
	}
	if returnedErr != bifrostErr {
		t.Fatalf("expected original provider error to be preserved")
	}
	if len(authorizer.finalEvents) != 1 {
		t.Fatalf("expected one finalization event, got %#v", authorizer.finalEvents)
	}
	event := authorizer.finalEvents[0]
	if event.ProviderAttempts[0].Status != "invalid_request" {
		t.Fatalf("expected invalid_request provider attempt, got %#v", event.ProviderAttempts[0])
	}
	if event.TotalCostUSDAtoms != "5000" {
		t.Fatalf("expected client-caused upstream error to settle authorized hold, got %s", event.TotalCostUSDAtoms)
	}
	if event.StogasBillingStatus != "complete" {
		t.Fatalf("expected exact hold capture status, got %s", event.StogasBillingStatus)
	}
}

func TestNormalizeUpstreamStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		errorType  string
		errorCode  string
		message    string
		want       string
	}{
		{name: "success", want: "success"},
		{name: "bad request", statusCode: 400, errorType: "invalid_request_error", want: "invalid_request"},
		{name: "authentication", statusCode: 401, errorType: "authentication_error", want: "provider_error"},
		{name: "permission denied", statusCode: 403, errorType: "permission_error", want: "provider_error"},
		{name: "not found", statusCode: 404, errorType: "not_found_error", want: "invalid_request"},
		{name: "conflict", statusCode: 409, errorType: "conflict_error", want: "invalid_request"},
		{name: "unprocessable entity", statusCode: 422, errorType: "invalid_request_error", want: "invalid_request"},
		{name: "quota", statusCode: 429, errorCode: "insufficient_quota", want: "over_budget"},
		{name: "rate limited", statusCode: 429, errorType: "rate_limit_error", want: "rate_limited"},
		{name: "network timeout", statusCode: 408, message: "request timeout", want: "network_error"},
		{name: "internal server error", statusCode: 500, errorType: "server_error", want: "provider_error"},
		{name: "bad gateway", statusCode: 502, want: "provider_error"},
		{name: "overloaded", statusCode: 503, message: "The engine is currently overloaded", want: "provider_error"},
		{name: "slow down", statusCode: 503, message: "Slow Down", want: "rate_limited"},
		{name: "gateway timeout", statusCode: 504, want: "network_error"},
		{name: "connection error text", message: "connection reset by peer", want: "network_error"},
		{name: "content filter", statusCode: 400, message: "blocked by content filter", want: "content_filter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err *schemas.BifrostError
			if tt.statusCode != 0 || tt.message != "" || tt.errorType != "" || tt.errorCode != "" {
				statusCode := tt.statusCode
				if statusCode == 0 {
					statusCode = 500
				}
				errorField := &schemas.ErrorField{Message: tt.message}
				if tt.errorType != "" {
					errorField.Type = schemas.Ptr(tt.errorType)
				}
				if tt.errorCode != "" {
					errorField.Code = schemas.Ptr(tt.errorCode)
				}
				err = &schemas.BifrostError{
					StatusCode: &statusCode,
					Error:      errorField,
				}
			}
			if got := billing.NormalizeUpstreamStatus(err); got != tt.want {
				t.Fatalf("normalizeUpstreamStatus = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProviderErrorInsurancePolicyCoversOpenAIErrorClasses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		errorType  string
		errorCode  string
		message    string
		insured    bool
	}{
		{name: "BadRequestError", statusCode: 400, errorType: "invalid_request_error", insured: false},
		{name: "AuthenticationError", statusCode: 401, errorType: "authentication_error", insured: true},
		{name: "PermissionDeniedError", statusCode: 403, errorType: "permission_error", insured: true},
		{name: "NotFoundError", statusCode: 404, errorType: "not_found_error", insured: false},
		{name: "ConflictError", statusCode: 409, errorType: "conflict_error", insured: false},
		{name: "UnprocessableEntityError", statusCode: 422, errorType: "invalid_request_error", insured: false},
		{name: "RateLimitError", statusCode: 429, errorType: "rate_limit_error", insured: true},
		{name: "insufficient quota", statusCode: 429, errorCode: "insufficient_quota", insured: true},
		{name: "APIConnectionError", statusCode: 500, message: "connection reset by peer", insured: true},
		{name: "APITimeoutError", statusCode: 504, message: "request timed out", insured: true},
		{name: "InternalServerError", statusCode: 500, errorType: "server_error", insured: true},
		{name: "overloaded", statusCode: 503, message: "The engine is currently overloaded", insured: true},
		{name: "slow down", statusCode: 503, message: "Slow Down", insured: true},
		{name: "content policy", statusCode: 400, message: "blocked by content policy", insured: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorField := &schemas.ErrorField{Message: tt.message}
			if tt.errorType != "" {
				errorField.Type = schemas.Ptr(tt.errorType)
			}
			if tt.errorCode != "" {
				errorField.Code = schemas.Ptr(tt.errorCode)
			}
			err := &schemas.BifrostError{
				StatusCode: &tt.statusCode,
				Error:      errorField,
			}
			if got := billing.ProviderErrorIsInsured(err); got != tt.insured {
				t.Fatalf("ProviderErrorIsInsured = %v, want %v; normalized=%s", got, tt.insured, billing.NormalizeUpstreamStatus(err))
			}
		})
	}
}
