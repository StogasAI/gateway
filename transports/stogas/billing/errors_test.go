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
		{"key_secret_replaced", 401},
	} {
		t.Run(test.code, func(t *testing.T) {
			var public *RequestError
			if !errors.As(authorizationResultError(test.code, nil, RefusedLimit{}), &public) || public.Code != test.code || public.StatusCode() != test.status {
				t.Fatalf("policy denial lost its public meaning: %#v", public)
			}
			if got := NormalizeStogasErrorCode(public.Code, public.StatusCode()); got != test.code {
				t.Fatalf("history code = %s", got)
			}
		})
	}
	if authorizationResultError("private_scope_spend_limit", nil, RefusedLimit{}) != nil || NormalizeStogasErrorCode("private_scope_spend_limit", 500) != "internal_error" {
		t.Fatal("an unrecognized scope entered the public error vocabulary")
	}
	// Another pair can serve a request whose Azure deployment is out of service.
	if !PairRefused(authorizationResultError("byok_target_unavailable", nil, RefusedLimit{})) {
		t.Fatal("an Azure target out of service stopped the request")
	}
}

// A refusal names its limit, and the rule that holds it, because a scope can
// have several limits of one kind.
func TestLimitRefusalsNameTheirLimit(t *testing.T) {
	for _, test := range []struct {
		result  string
		limit   RefusedLimit
		message string
	}{
		{"grant_token_limit", RefusedLimit{"daily", ""}, `Grant token limit "daily" exceeded`},
		{"key_rate_limited", RefusedLimit{"rpm", "openai_budget"}, `API key request rate limit "rpm" in rule "openai_budget" exceeded`},
		{"member_concurrency_limit", RefusedLimit{"parallel", ""}, `Member concurrent-request limit "parallel" exceeded`},
		{"folder_spend_limit", RefusedLimit{"monthly", ""}, `Folder spend limit "monthly" exceeded`},
	} {
		wait := int64(1000)
		err := authorizationResultError(test.result, &wait, test.limit)
		var limited *LimitError
		var public *RequestError
		if !errors.As(err, &limited) || limited.Limit != test.limit || !errors.As(err, &public) ||
			public.Message != test.message || public.Code != test.result || !PairRefused(err) {
			t.Fatalf("%s = %v", test.result, err)
		}
		// The shared refusal keeps its message for the requests of other limits.
		if policyResultErrors[test.result].Message == test.message {
			t.Fatalf("%s changed the shared refusal", test.result)
		}
	}
}
