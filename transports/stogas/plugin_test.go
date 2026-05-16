package stogas

import (
	"context"
	"errors"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

type fakeHoldAuthorizer struct {
	attempts    []string
	finalEvents []GatewayRequestEvent
	results     []*HoldAuthorization
	errors      []error
	callCount   int
}

func (f *fakeHoldAuthorizer) AuthorizePlaceholderHold(ctx context.Context, rawAPIKey string, requestID string, providerKey string, productKey string) (*HoldAuthorization, error) {
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

func (f *fakeHoldAuthorizer) FinalizePlaceholderHold(ctx context.Context, authorization *HoldAuthorization, event GatewayRequestEvent) error {
	f.finalEvents = append(f.finalEvents, event)
	return nil
}

func (f *fakeHoldAuthorizer) ReleaseHold(ctx context.Context, authorization *HoldAuthorization) error {
	return nil
}

func TestAuthorizeWithFreshRequestIDRetriesConflict(t *testing.T) {
	initialRequestID := "11111111-1111-1111-1111-111111111111"
	expected := &HoldAuthorization{HoldID: "hold-1"}
	authorizer := &fakeHoldAuthorizer{
		results: []*HoldAuthorization{nil, expected},
		errors: []error{
			&holdError{err: ErrRequestAlreadyUsed, statusCode: 409},
			nil,
		},
	}
	plugin := &Plugin{holds: authorizer}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, initialRequestID)

	authorization, err := plugin.authorizeWithFreshRequestID(ctx, "sk-user", initialRequestID, "openai", "gpt-5", authorizer.errors[0])
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
	expectedErr := &holdError{err: ErrInvalidAPIKey, statusCode: 401}
	plugin := &Plugin{holds: &fakeHoldAuthorizer{}}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyRequestID, initialRequestID)

	authorization, err := plugin.authorizeWithFreshRequestID(ctx, "sk-user", initialRequestID, "openai", "gpt-5", expectedErr)
	if authorization != nil {
		t.Fatalf("expected no authorization for non-conflict error")
	}
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("expected invalid API key error, got %v", err)
	}
	currentRequestID, _ := ctx.Value(schemas.BifrostContextKeyRequestID).(string)
	if currentRequestID != initialRequestID {
		t.Fatalf("expected request ID to remain unchanged, got %q", currentRequestID)
	}
}

func TestPostLLMHookFinalizesProviderErrors(t *testing.T) {
	authorization := &HoldAuthorization{
		AuthorizedAmount: mustBigInt(t, placeholderChargeUsdAtoms),
		AvailableAfter:   mustBigInt(t, "10000000000"),
		KeyID:            "key-1",
		ProductKey:       "gpt-4o-mini",
		ProviderKey:      "openai",
		RequestID:        "request-1",
		UserID:           "user-1",
	}
	authorizer := &fakeHoldAuthorizer{}
	plugin := &Plugin{holds: authorizer}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	setHoldAuthorization(ctx, authorization)
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
	if event.StogasBillingStatus != "complete" {
		t.Fatalf("expected placeholder billing status complete, got %q", event.StogasBillingStatus)
	}
	if event.RequestType != "chat_completion_request" {
		t.Fatalf("expected normalized request type, got %q", event.RequestType)
	}
}

func TestNormalizeUpstreamStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
		want       string
	}{
		{name: "success", want: "success"},
		{name: "rate limited", statusCode: 429, want: "rate_limited"},
		{name: "over budget", statusCode: 402, want: "over_budget"},
		{name: "invalid request", statusCode: 400, want: "invalid_request"},
		{name: "content filter", statusCode: 400, message: "blocked by content filter", want: "content_filter"},
		{name: "network timeout", statusCode: 504, want: "network_error"},
		{name: "provider error", statusCode: 500, want: "provider_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err *schemas.BifrostError
			if tt.statusCode != 0 || tt.message != "" {
				statusCode := tt.statusCode
				err = &schemas.BifrostError{
					StatusCode: &statusCode,
					Error:      &schemas.ErrorField{Message: tt.message},
				}
			}
			if got := normalizeUpstreamStatus(err); got != tt.want {
				t.Fatalf("normalizeUpstreamStatus = %q, want %q", got, tt.want)
			}
		})
	}
}
