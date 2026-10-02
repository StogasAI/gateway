package billing

import (
	"errors"
	"testing"
)

func TestPolicyDenialsKeepTheirScopeAndHTTPMeaning(t *testing.T) {
	for _, test := range []struct {
		code   string
		status int
	}{
		{"folder_spend_limit", 402},
		{"role_rate_limited", 429},
		{"member_token_limit", 429},
		{"credential_concurrency_limit", 429},
		{"organization_expired", 403},
		{"folder_disabled", 403},
		{"key_token_limit", 429},
		{"grant_disabled", 403},
		{"key_configuration_too_large", 400},
	} {
		t.Run(test.code, func(t *testing.T) {
			var public *RequestError
			if !errors.As(authorizationResultError(test.code), &public) || public.Code != test.code || public.StatusCode() != test.status {
				t.Fatalf("policy denial lost its public meaning: %#v", public)
			}
			if got := NormalizeStogasErrorCode(public.Code, public.StatusCode()); got != test.code {
				t.Fatalf("history code = %s", got)
			}
		})
	}
	if authorizationResultError("private_scope_spend_limit") != nil || NormalizeStogasErrorCode("private_scope_spend_limit", 500) != "internal_error" {
		t.Fatal("an unrecognized scope entered the public error vocabulary")
	}
	if authorizationResultError("key_spend_limit") != ErrAPIKeySpendLimit || authorizationResultError("key_rate_limited") != ErrAPIKeyRateLimit {
		t.Fatal("key admission errors lost their identity")
	}
}
