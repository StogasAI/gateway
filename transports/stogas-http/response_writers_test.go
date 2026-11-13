package stogashttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

type retryableBillingTestError struct{ delay time.Duration }

func (e retryableBillingTestError) Error() string             { return billing.ErrRateLimit.Error() }
func (e retryableBillingTestError) Unwrap() error             { return billing.ErrRateLimit }
func (e retryableBillingTestError) RetryAfter() time.Duration { return e.delay }

func TestBillingRefusalsTellClientsWhenToRetry(t *testing.T) {
	for _, tc := range []struct {
		name, retry string
		err         error
		want        []string
	}{
		{"hold-back", "", retryableBillingTestError{25 * time.Millisecond}, []string{"1", "2"}},
		{"one second", "", retryableBillingTestError{time.Second}, []string{"1", "2"}},
		{"just over a second", "", retryableBillingTestError{time.Second + time.Nanosecond}, []string{"2", "3"}},
		{"under a minute", "", retryableBillingTestError{59 * time.Second}, []string{"59", "60"}},
		{"a minute", "", retryableBillingTestError{59*time.Second + time.Millisecond}, []string{"60"}},
		{"over a minute", "false", retryableBillingTestError{90 * time.Second}, []string{"90"}},
		{"no wait", "false", billing.ErrRateLimit, []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[string]bool{}
			// Each wait of a spread is missed by all 64 draws with chance 2⁻⁶⁴.
			for range 64 {
				ctx := newTestRequest(t)
				s := &Server{}
				s.writeBillingError(ctx, fmt.Errorf("internal detail: %w", tc.err))
				header := ctx.writer.Header()
				if testResponse(ctx).Code != 429 || header.Get("X-Should-Retry") != tc.retry {
					t.Fatalf("response = %d %s, X-Should-Retry = %q", testResponse(ctx).Code, testResponse(ctx).Body.Bytes(), header.Get("X-Should-Retry"))
				}
				seen[header.Get("Retry-After")] = true
				var body struct {
					Error struct{ Code, Type, Message string }
				}
				if err := json.Unmarshal(testResponse(ctx).Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Error.Code != "rate_limit_exceeded" || body.Error.Type != "rate_limit_error" || body.Error.Message != billing.ErrRateLimit.Message {
					t.Fatalf("wrong public error: %s", testResponse(ctx).Body.Bytes())
				}
			}
			want := map[string]bool{}
			for _, value := range tc.want {
				want[value] = true
			}
			if !maps.Equal(seen, want) {
				t.Fatalf("Retry-After values = %v, want %v", seen, tc.want)
			}
		})
	}
}

func TestWriteProviderErrorTellsClientsWhenToRetry(t *testing.T) {
	for _, tc := range []struct {
		name      string
		headers   map[string]string
		err       *schemas.BifrostError
		want      []string
		wantRetry string
	}{
		{"rate limit", map[string]string{"Retry-After": "7"}, testBifrostError(http.StatusTooManyRequests, "slow down", "rate_limit_error", ""), []string{"7", "8"}, ""},
		{"milliseconds", map[string]string{"retry-after-ms": "250", "Retry-After": "9"}, testBifrostError(http.StatusTooManyRequests, "slow down", "rate_limit_error", ""), []string{"1", "2"}, ""},
		{"overloaded for over a minute", map[string]string{"Retry-After": "90"}, testBifrostError(529, "overloaded", "overloaded_error", ""), []string{"90"}, "false"},
		{"no wait", map[string]string{"Retry-After": "0"}, testBifrostError(http.StatusServiceUnavailable, "unavailable", "", ""), []string{""}, ""},
		{"overload until a past date", map[string]string{"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}, testBifrostError(529, "overloaded", "overloaded_error", ""), []string{""}, ""},
		{"invalid delay", map[string]string{"Retry-After": "soon"}, testBifrostError(http.StatusServiceUnavailable, "unavailable", "", ""), []string{""}, ""},
		{"request error", map[string]string{"Retry-After": "7"}, testBifrostError(http.StatusBadRequest, "bad request", "invalid_request_error", ""), []string{""}, ""},
		{"rejected credential", map[string]string{"Retry-After": "7"}, testBifrostError(http.StatusUnauthorized, "bad key", "authentication_error", ""), []string{""}, "false"},
		{"exhausted quota", map[string]string{"Retry-After": "7"}, testBifrostError(http.StatusTooManyRequests, "quota", "", "insufficient_quota"), []string{""}, "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[string]bool{}
			for range 64 {
				ctx := newTestRequest(t)
				bifrostCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
				bifrostCtx.SetValue(schemas.BifrostContextKeyProviderResponseHeaders, tc.headers)
				(&Server{}).writeProviderError(ctx, nil, bifrostCtx, tc.err)
				header := ctx.writer.Header()
				if header.Get("X-Should-Retry") != tc.wantRetry {
					t.Fatalf("X-Should-Retry = %q", header.Get("X-Should-Retry"))
				}
				seen[header.Get("Retry-After")] = true
			}
			want := map[string]bool{}
			for _, value := range tc.want {
				want[value] = true
			}
			if !maps.Equal(seen, want) {
				t.Fatalf("Retry-After values = %v, want %v", seen, tc.want)
			}
		})
	}
}

func TestPublicBifrostErrorNamesAProviderRetirementAsTheCatalogDoes(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  *schemas.BifrostError
	}{
		{"Groq under 400", testBifrostError(http.StatusBadRequest, "The model `mixtral-8x7b-32768` has been decommissioned and is no longer supported.", "invalid_request_error", "model_decommissioned")},
		{"Azure under 410", testBifrostError(http.StatusGone, "The model associated with the deployment is deprecated and no longer available.", "", "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, payload := publicBifrostError(tc.err)
			errorObject := publicErrorObject(t, payload)
			if status != http.StatusBadRequest || errorObject["code"] != "model_retired" || errorObject["type"] != "invalid_request_error" ||
				errorObject["message"] != "The provider retired the requested model. Choose another model." {
				t.Fatalf("status = %d, error = %#v", status, errorObject)
			}
		})
	}
}

func TestPublicBifrostErrorKeepsProviderLimitAndPolicyDetails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      *schemas.BifrostError
		wantCode any
	}{
		{"prompt too long", testBifrostError(http.StatusBadRequest, "prompt is too long: 215000 tokens > 200000 maximum", "invalid_request_error", ""), nil},
		{"OpenAI cyber policy on 403", testBifrostError(http.StatusForbidden, "Request blocked by cyber policy.", "", "cyber_policy"), "cyber_policy"},
		{"OpenAI cyber policy inside a stream", testBifrostError(0, "Request blocked by cyber policy.", "", "cyber_policy"), "cyber_policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, payload := publicBifrostError(tc.err)
			errorObject := publicErrorObject(t, payload)
			if status != http.StatusBadRequest || errorObject["code"] != tc.wantCode || errorObject["message"] != tc.err.Error.Message {
				t.Fatalf("status = %d, error = %#v", status, errorObject)
			}
		})
	}
}

// Claude's refusal of changed reasoning history names its own message positions and a setting
// that neither API has, so the client reads what it can do, with either kind of credential.
func TestPublicProviderErrorSaysHowToRecoverRefusedReasoningHistory(t *testing.T) {
	refusal := testBifrostError(http.StatusBadRequest, "messages.5.content.0: Invalid `signature` in `thinking` block. The block is bound to a different conversation. "+
		"Remove the block, or set `thinking.block_binding.prefix_mismatch_behavior` to \"drop_block\". That setting requires the `thinking-binding-controls-2026-08-01` value in the `anthropic-beta` header.",
		"invalid_request_error", "")
	for _, use := range []providerMessageUse{filterProviderMessage, passProviderMessage, withholdProviderMessage} {
		status, payload := publicProviderError(refusal, use)
		if errorObject := publicErrorObject(t, payload); status != http.StatusBadRequest || errorObject["type"] != "invalid_request_error" || errorObject["message"] != reasoningHistoryRefused {
			t.Fatalf("use %d: status = %d, error = %#v", use, status, errorObject)
		}
	}
	// A signature that Claude cannot read is another failure and keeps Anthropic's words.
	tampered := testBifrostError(http.StatusBadRequest, "messages.1.content.0: Invalid `signature` in `thinking` block.", "invalid_request_error", "")
	if _, payload := publicBifrostError(tampered); publicErrorObject(t, payload)["message"] != tampered.Error.Message {
		t.Fatalf("error = %#v", payload)
	}
}

// A provider's words about the customer's own account are the customer's to
// read, so a call with their credential carries them where a managed account's
// refusal names nothing.
func TestProviderErrorCarriesProviderWordsForACustomerCredential(t *testing.T) {
	const keyMessage = "Incorrect API key provided: sk-proj-****abcd. You can find your API key at https://platform.openai.com/account/api-keys."
	long := strings.Repeat("é", maxProviderMessageBytes)
	gatewayMade := testBifrostError(http.StatusBadRequest, "failed to marshal the internal request", "invalid_request_error", "")
	gatewayMade.IsBifrostError = true
	for _, tc := range []struct {
		name        string
		err         *schemas.BifrostError
		customer    bool
		wantStatus  int
		wantCode    any
		wantMessage string
	}{
		{"customer credential refused", testBifrostError(http.StatusUnauthorized, keyMessage, "invalid_request_error", "invalid_api_key"), true,
			http.StatusFailedDependency, "upstream_authentication_failed", "The configured provider credential was rejected: " + keyMessage},
		{"managed credential refused", testBifrostError(http.StatusUnauthorized, keyMessage, "invalid_request_error", "invalid_api_key"), false,
			http.StatusFailedDependency, "upstream_authentication_failed", "The configured provider credential was rejected"},
		{"customer rate limit", testBifrostError(http.StatusTooManyRequests, "Rate limit reached for gpt-5 in organization org-1 on tokens per min (TPM): Limit 30000.", "", ""), true,
			http.StatusTooManyRequests, "upstream_rate_limit_error", "The upstream provider rate limit was exceeded: Rate limit reached for gpt-5 in organization org-1 on tokens per min (TPM): Limit 30000."},
		{"customer message with a withheld word", testBifrostError(http.StatusBadRequest, "The stack of tool definitions is invalid.", "invalid_request_error", ""), true,
			http.StatusBadRequest, nil, "The stack of tool definitions is invalid."},
		{"managed message with a withheld word", testBifrostError(http.StatusBadRequest, "The stack of tool definitions is invalid.", "invalid_request_error", ""), false,
			http.StatusBadRequest, nil, "Invalid request"},
		{"customer message over the bound", testBifrostError(http.StatusBadRequest, long, "invalid_request_error", ""), true,
			http.StatusBadRequest, nil, strings.Repeat("é", maxProviderMessageBytes/2) + "…"},
		{"gateway's own failure", gatewayMade, true,
			http.StatusBadRequest, nil, "Invalid request"},
		// No holder of an API key learns the provider credential behind it.
		{"customer refusal that repeats the credential", testBifrostError(http.StatusUnauthorized, "Invalid API key: "+testProviderSecret, "", "invalid_api_key"), true,
			http.StatusFailedDependency, "upstream_authentication_failed", "The configured provider credential was rejected"},
		{"customer message that repeats the credential", testBifrostError(http.StatusBadRequest, "Unknown header value "+testProviderSecret, "invalid_request_error", ""), true,
			http.StatusBadRequest, nil, "Invalid request"},
		{"managed message that repeats the credential", testBifrostError(http.StatusBadRequest, "Unknown header value "+testProviderSecret, "invalid_request_error", ""), false,
			http.StatusBadRequest, nil, "Invalid request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			byok := billing.ManagedUpstreamByok
			if tc.customer {
				byok = "byok_1"
			}
			state := &stogas.State{Authorization: &billing.Authorization{UpstreamByok: byok, UpstreamByokSecret: testProviderSecret}}
			status, payload := publicProviderError(tc.err, providerMessageUseFor(state, tc.err))
			errorObject := publicErrorObject(t, payload)
			if status != tc.wantStatus || errorObject["code"] != tc.wantCode || errorObject["message"] != tc.wantMessage {
				t.Fatalf("status = %d, error = %#v", status, errorObject)
			}
		})
	}
}

const testProviderSecret = "sk-test-0123456789abcdef"

// A JSON credential's secret fields never pass, while a provider's error may name its
// identifiers, as Entra ID names the tenant and the application.
func TestMessageNamesCredential(t *testing.T) {
	const azure = `{"tenant_id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","client_id":"9b2e1a56-0d8c-4f0b-8a53-6d1f0c2f7e11","client_secret":"Xy8~Q.secretValue0123"}`
	for _, tc := range []struct {
		name, message, secret string
		want                  bool
	}{
		{"whole key", "Invalid API key: " + testProviderSecret, testProviderSecret, true},
		{"masked key", "Incorrect API key provided: sk-test-****cdef.", testProviderSecret, false},
		{"secret field", "Invalid client secret Xy8~Q.secretValue0123 provided", azure, true},
		{"identifier field", "Application 9b2e1a56-0d8c-4f0b-8a53-6d1f0c2f7e11 was not found in tenant 3f2504e0-4f89-11d3-9a0c-0305e82c3301", azure, false},
		{"no credential", "Invalid request", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := messageNamesCredential(tc.message, tc.secret); got != tc.want {
				t.Fatalf("messageNamesCredential = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestUsesCustomerCredential(t *testing.T) {
	for byok, want := range map[string]bool{"": false, billing.ManagedUpstreamByok: false, "byok_1": true} {
		state := &stogas.State{Authorization: &billing.Authorization{UpstreamByok: byok}}
		if got := usesCustomerCredential(state); got != want {
			t.Fatalf("usesCustomerCredential(%q) = %t, want %t", byok, got, want)
		}
	}
	if usesCustomerCredential(nil) || usesCustomerCredential(&stogas.State{}) {
		t.Fatal("a request without a bound pair uses no customer credential")
	}
}

// A pair that the plan refused can carry its credential's wait, which its
// answer passes on as the gateway's own refusals do.
func TestCatalogRefusalPassesOnItsWait(t *testing.T) {
	refusal := func(wait time.Duration) error {
		public := stogas.PublicBillingErrorFor(billing.ErrRateLimit)
		apiErr := catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message}
		if wait == 0 {
			return errors.Join(billing.ErrRateLimit, apiErr)
		}
		return errors.Join(waitRefusal{billing.ErrRateLimit, wait}, apiErr)
	}
	for _, tc := range []struct {
		name       string
		err        error
		retryAfter []string
		final      bool
	}{
		{"a short wait", refusal(5 * time.Second), []string{"5", "6"}, false},
		{"a wait over a minute", refusal(2 * time.Minute), []string{"120"}, true},
		{"no wait", refusal(0), []string{""}, true},
		{"not a refusal", catalog.ErrModelUnavailable, []string{""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := catalogErrorResponse(tc.err)
			if !slices.Contains(tc.retryAfter, response.retryAfter) || response.final != tc.final {
				t.Fatalf("Retry-After %q, final %v", response.retryAfter, response.final)
			}
		})
	}
}
