package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
)

func TestParseSignedAPIKey(t *testing.T) {
	secret := "test-token-pepper"
	keyID := "019de515-eabf-7c0e-89bd-400629a79580"
	organizationID := "019de516-7df8-71d6-80e4-3c62090d4e94"
	workspaceID := "019de516-9c1b-7061-a9f0-bbdcaa8946e5"
	userID := "019de516-b10f-786f-97f8-b95c71dfe1b6"
	rawKey := testSignedAPIKey(t, secret, keyID, organizationID, workspaceID, userID, "", apiKeyVersion)

	claims, err := parseSignedAPIKey(rawKey, secret)
	if err != nil {
		t.Fatalf("parseSignedAPIKey returned error: %v", err)
	}
	if claims.KeyID != keyID || claims.OrganizationID != organizationID || claims.WorkspaceID != workspaceID || claims.ResponsibleID != userID {
		t.Fatalf("claims = %#v", claims)
	}
	if claims.ProvisioningID != nil {
		t.Fatalf("provisioning = %#v", claims)
	}
	if claims.FormatVersion != apiKeyVersion {
		t.Fatalf("FormatVersion = %d, want %d", claims.FormatVersion, apiKeyVersion)
	}

	tamperedIndex := len(apiKeyPrefix) + 10
	tamperedChar := byte('A')
	if rawKey[tamperedIndex] == tamperedChar {
		tamperedChar = 'B'
	}
	tamperedKey := rawKey[:tamperedIndex] + string(tamperedChar) + rawKey[tamperedIndex+1:]
	if _, err := parseSignedAPIKey(tamperedKey, secret); err == nil {
		t.Fatal("parseSignedAPIKey accepted a tampered key")
	}
}

func TestParseProvisionedSignedAPIKey(t *testing.T) {
	secret := "test-token-pepper"
	keyID := "019de515-eabf-7c0e-89bd-400629a79580"
	organizationID := "019de516-7df8-71d6-80e4-3c62090d4e94"
	workspaceID := "019de516-9c1b-7061-a9f0-bbdcaa8946e5"
	userID := "019de516-b10f-786f-97f8-b95c71dfe1b6"
	provisioningID := "019de516-c9ac-79cf-b701-4cf1b21f0a8c"
	rawKey := testSignedAPIKey(t, secret, keyID, organizationID, workspaceID, userID, provisioningID, apiKeyVersion)

	claims, err := parseSignedAPIKey(rawKey, secret)
	if err != nil {
		t.Fatalf("parseSignedAPIKey returned error: %v", err)
	}
	if claims.ProvisioningID == nil || *claims.ProvisioningID != provisioningID {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestParseSignedAPIKeyRejectsWrongVersion(t *testing.T) {
	secret := "test-token-pepper"
	rawKey := testSignedAPIKey(
		t,
		secret,
		"019de515-eabf-7c0e-89bd-400629a79580",
		"019de516-7df8-71d6-80e4-3c62090d4e94",
		"019de516-9c1b-7061-a9f0-bbdcaa8946e5",
		"019de516-b10f-786f-97f8-b95c71dfe1b6",
		"",
		apiKeyVersion+1,
	)

	if _, err := parseSignedAPIKey(rawKey, secret); err == nil {
		t.Fatal("expected version mismatch to be rejected")
	}
}

func TestParseSignedAPIKeyRejectsZeroIssuanceEntropy(t *testing.T) {
	secret := "test-token-pepper"
	rawKey := testSignedAPIKey(
		t,
		secret,
		"019de515-eabf-7c0e-89bd-400629a79580",
		"019de516-7df8-71d6-80e4-3c62090d4e94",
		"019de516-9c1b-7061-a9f0-bbdcaa8946e5",
		"019de516-b10f-786f-97f8-b95c71dfe1b6",
		"",
		apiKeyVersion,
	)
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rawKey, apiKeyPrefix))
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	clear(body[84:100])
	hasher := hmac.New(sha256.New, []byte(secret))
	_, _ = hasher.Write(body[:apiKeyPayloadBytes])
	copy(body[apiKeyPayloadBytes:], hasher.Sum(nil)[:apiKeyMACBytes])

	if _, err := parseSignedAPIKey(apiKeyPrefix+base64.RawURLEncoding.EncodeToString(body), secret); err == nil {
		t.Fatal("expected zero issuance entropy to be rejected")
	}
}

func testSignedAPIKey(t *testing.T, secret string, keyID string, organizationID string, workspaceID string, userID string, provisioningID string, version uint32) string {
	t.Helper()
	payload := make([]byte, apiKeyPayloadBytes)
	binary.BigEndian.PutUint32(payload[0:4], version)
	keyUUID := uuid.MustParse(keyID)
	organizationUUID := uuid.MustParse(organizationID)
	workspaceUUID := uuid.MustParse(workspaceID)
	userUUID := uuid.MustParse(userID)
	copy(payload[4:20], keyUUID[:])
	copy(payload[20:36], organizationUUID[:])
	copy(payload[36:52], workspaceUUID[:])
	copy(payload[52:68], userUUID[:])
	if provisioningID != "" {
		provisioningUUID := uuid.MustParse(provisioningID)
		copy(payload[68:84], provisioningUUID[:])
	}
	for index := 84; index < 100; index++ {
		payload[index] = byte(index - 83)
	}
	hasher := hmac.New(sha256.New, []byte(secret))
	_, _ = hasher.Write(payload)
	body := append(payload, hasher.Sum(nil)[:apiKeyMACBytes]...)
	return apiKeyPrefix + base64.RawURLEncoding.EncodeToString(body)
}

func TestSettlementStatuses(t *testing.T) {
	tests := []struct {
		name           string
		availableAfter string
		authorized     string
		actual         string
		wantStatus     string
	}{
		{name: "exact", availableAfter: "9000", authorized: "1000", actual: "1000", wantStatus: "complete"},
		{name: "refund", availableAfter: "9000", authorized: "1000", actual: "400", wantStatus: "complete"},
		{name: "extra debit positive", availableAfter: "2000", authorized: "1000", actual: "1500", wantStatus: "under_reserved"},
		{name: "extra debit negative", availableAfter: "0", authorized: "1000", actual: "1500", wantStatus: "negative_balance"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorization := &Authorization{
				AuthorizedAmount: mustBigInt(t, tt.authorized),
				AvailableAfter:   mustBigInt(t, tt.availableAfter),
				KeyID:            "key",
				ProductKey:       "model",
				ProviderKey:      "provider",
				RequestID:        "request",
				UserID:           "user",
			}

			if got := settlementStatus(authorization.AuthorizedAmount, authorization.AvailableAfter, tt.actual); got != tt.wantStatus {
				t.Fatalf("settlementStatus = %s, want %s", got, tt.wantStatus)
			}
		})
	}
}

func TestEncodeGatewayRequestEventDefaultsPricing(t *testing.T) {
	payload, err := encodeGatewayRequestEvent(RequestEvent{RequestID: "request"})
	if err != nil {
		t.Fatalf("encodeGatewayRequestEvent returned error: %v", err)
	}

	decoded := map[string]any{}
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if _, exists := decoded["meter_quantities"]; exists {
		t.Fatal("meter_quantities must not duplicate pricing quantities")
	}
	if _, exists := decoded["pricing_input_sha256"]; exists {
		t.Fatal("pricing_input_sha256 must not duplicate the catalog-bound pricing record")
	}
	pricing, ok := decoded["pricing"].(map[string]any)
	if !ok || len(pricing) != 0 {
		t.Fatalf("pricing = %#v, want empty object", decoded["pricing"])
	}
}

func TestTinybirdGatewayRequestEventStringifiesNestedPayload(t *testing.T) {
	status := 200
	firstOutput := uint32(46)
	event := tinybirdGatewayRequestEvent(RequestEvent{
		Pricing: map[string]any{
			"input_tokens": map[string]any{"quantity": "12", "rateKey": "per_mill_tokens", "rateUsdAtoms": "1", "usdAtoms": "1"},
		},
		ProviderAttempts: []ProviderAttempt{{
			LatencyMS:             12,
			Provider:              "openai",
			ProviderFirstOutputMS: &firstOutput,
			ProviderRequestID:     "provider-request",
			FinishReason:          "stop",
			Status:                "success",
			StatusCode:            &status,
			UpstreamCredential:    "stogas",
		}},
		GatewayVersion:          "v1.5.13",
		ResolvedCatalogNodeIDs:  []string{"route:chat", "provider:openai", "deployment:gpt-5"},
		StogasProcessingSuccess: true,
	})

	if event.StogasProcessingSuccess != 1 {
		t.Fatalf("stogas_processing_success = %d, want 1", event.StogasProcessingSuccess)
	}
	if event.AnalyticsInputTokens != 12 || event.AnalyticsProviderStatus != "success" {
		t.Fatalf("analytics projections do not match canonical payload: %#v", event)
	}
	if event.AnalyticsTimeToFirstOutputMS == nil || *event.AnalyticsTimeToFirstOutputMS != firstOutput {
		t.Fatalf("analytics_time_to_first_output_ms = %#v", event.AnalyticsTimeToFirstOutputMS)
	}
	if event.GatewayVersion != "v1.5.13" {
		t.Fatalf("gateway_version = %q", event.GatewayVersion)
	}
	var nodeIDs []string
	if err := json.Unmarshal([]byte(event.ResolvedCatalogNodeIDs), &nodeIDs); err != nil || len(nodeIDs) != 3 {
		t.Fatalf("resolved_catalog_node_ids = %q, err=%v", event.ResolvedCatalogNodeIDs, err)
	}
	var attempts []ProviderAttempt
	if err := json.Unmarshal([]byte(event.ProviderAttempts), &attempts); err != nil || len(attempts) != 1 {
		t.Fatalf("provider_attempts = %q, err=%v", event.ProviderAttempts, err)
	}
	var pricing map[string]map[string]string
	if err := json.Unmarshal([]byte(event.Pricing), &pricing); err != nil || pricing["input_tokens"]["quantity"] != "12" {
		t.Fatalf("pricing = %q, err=%v", event.Pricing, err)
	}
}

func TestNewRequestEventPreservesSettledPricingAudit(t *testing.T) {
	startedAt := time.Now().Add(-25 * time.Millisecond)
	providerFirstOutput := uint32(8)
	provisioningKeyID := "019de515-eabf-7c0e-89bd-400629a79580"
	event := NewRequestEvent(EventInput{
		Authorization:         &Authorization{AuthorizedAmount: mustParseBigInt("10"), ProvisioningKeyID: &provisioningKeyID, RequestID: "request-1"},
		ProviderFirstOutputMS: &providerFirstOutput,
		RequestType:           string(schemas.ChatCompletionStreamRequest),
		Pricing: map[string]any{
			"input_tokens": map[string]any{"quantity": "1", "rateKey": "per_mill_tokens", "rateUsdAtoms": "2000000", "usdAtoms": "2"},
		},
		StartedAt: startedAt,
	})

	if event.Pricing["input_tokens"].(map[string]any)["rateUsdAtoms"] != "2000000" {
		t.Fatalf("expected settled pricing audit, got %#v", event.Pricing)
	}
	if event.ProviderAttempts[0].ProviderFirstOutputMS == nil || *event.ProviderAttempts[0].ProviderFirstOutputMS != providerFirstOutput {
		t.Fatalf("expected provider first output on provider attempt, got %#v", event.ProviderAttempts)
	}
	if event.StogasProvisioningKeyID == nil || *event.StogasProvisioningKeyID != provisioningKeyID {
		t.Fatalf("expected provisioning key attribution, got %#v", event.StogasProvisioningKeyID)
	}
}

func TestBilledRequestCostUsesFullManagedCostAndCeilingTwoPercentForBYOK(t *testing.T) {
	managed := &Authorization{UpstreamCredential: "stogas"}
	byok := &Authorization{UpstreamCredential: "0198f4cc-6c25-7000-8000-000000000001"}
	for _, tc := range []struct {
		name          string
		authorization *Authorization
		upstream      string
		want          string
	}{
		{name: "managed", authorization: managed, upstream: "101", want: "101"},
		{name: "BYOK zero", authorization: byok, upstream: "0", want: "0"},
		{name: "BYOK minimum nonzero", authorization: byok, upstream: "1", want: "1"},
		{name: "BYOK exact", authorization: byok, upstream: "100", want: "2"},
		{name: "BYOK rounds up", authorization: byok, upstream: "101", want: "3"},
		{name: "BYOK larger", authorization: byok, upstream: "999", want: "20"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := billedRequestCost(tc.authorization, tc.upstream); got != tc.want {
				t.Fatalf("billedRequestCost(%q) = %q, want %q", tc.upstream, got, tc.want)
			}
		})
	}
}

func TestNewRequestEventUsesProviderClockAndClampsItToTotal(t *testing.T) {
	now := time.Now()
	startedAt := now.Add(-100 * time.Millisecond)
	providerStartedAt := now.Add(-60 * time.Millisecond)
	providerCompletedAt := now.Add(-20 * time.Millisecond)
	event := NewRequestEvent(EventInput{
		Authorization:       &Authorization{RequestID: "request-1"},
		ProviderCompletedAt: providerCompletedAt,
		ProviderStartedAt:   providerStartedAt,
		StartedAt:           startedAt,
	})
	if event.TotalTimeMS < 90 {
		t.Fatalf("total time should begin at request admission, got %dms", event.TotalTimeMS)
	}
	providerTime := event.ProviderAttempts[0].LatencyMS
	if providerTime < 35 || providerTime > 45 {
		t.Fatalf("provider time should end at observed provider completion, got %dms", providerTime)
	}

	event = NewRequestEvent(EventInput{
		Authorization:       &Authorization{RequestID: "request-provider-clock"},
		ProviderCompletedAt: providerCompletedAt,
		ProviderStartedAt:   providerStartedAt,
		Response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{
			ExtraFields: schemas.BifrostResponseExtraFields{Latency: 2},
		}},
		StartedAt: startedAt,
	})
	if event.ProviderAttempts[0].LatencyMS < 35 || event.ProviderAttempts[0].LatencyMS > 45 {
		t.Fatalf(
			"provider metadata must not replace the gateway provider clock, got %dms",
			event.ProviderAttempts[0].LatencyMS,
		)
	}

	event = NewRequestEvent(EventInput{
		Authorization: &Authorization{RequestID: "request-2"},
		Response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{
			ExtraFields: schemas.BifrostResponseExtraFields{Latency: 500},
		}},
		StartedAt: startedAt,
	})
	if event.ProviderAttempts[0].LatencyMS != event.TotalTimeMS {
		t.Fatalf(
			"provider time must not exceed total time: provider=%d total=%d",
			event.ProviderAttempts[0].LatencyMS,
			event.TotalTimeMS,
		)
	}
}

func TestPublishUncommittedFallbackSendsFinalRequestLog(t *testing.T) {
	var captured tinybirdGatewayRequestEventPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("wait"); got != "true" {
			t.Fatalf("wait query = %q, want true", got)
		}
		if got := r.Header.Get("authorization"); got != "Bearer gateway-requests-token" {
			t.Fatalf("authorization header = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("failed to decode Tinybird payload: %v", err)
		}
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	service := &Service{tinybird: newTestTinybirdClient(t, server.URL)}
	service.publishUncommittedFallback(
		&Authorization{RequestID: "request-1"},
		RequestEvent{
			RequestID:               "request-1",
			StogasBillingStatus:     "complete",
			StogasProcessingSuccess: true,
			UpstreamCostUSDAtoms:    ZeroChargeUSDAtoms,
			BilledCostUSDAtoms:      ZeroChargeUSDAtoms,
		},
	)

	if captured.RequestID != "request-1" {
		t.Fatalf("request_id = %q, want request-1", captured.RequestID)
	}
	if captured.StogasBillingStatus != "complete" {
		t.Fatalf("stogas_billing_status = %q, want final status complete", captured.StogasBillingStatus)
	}
	if captured.StogasProcessingSuccess != 1 {
		t.Fatalf("stogas_processing_success = %d, want 1", captured.StogasProcessingSuccess)
	}
}

func TestRetrySettleExhaustionPublishesFinalTinybirdFallback(t *testing.T) {
	var captured tinybirdGatewayRequestEventPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("failed to decode Tinybird payload: %v", err)
		}
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	attempts := 0
	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       5 * time.Millisecond,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			attempts++
			return errors.New("simulated postgres outage")
		},
		tinybird: newTestTinybirdClient(t, server.URL),
	}
	service.retrySettle(
		&Authorization{RequestID: "request-1"},
		"params",
		ZeroChargeUSDAtoms,
		`{"request_id":"request-1"}`,
		RequestEvent{
			RequestID:               "request-1",
			StogasBillingStatus:     "complete",
			StogasProcessingSuccess: true,
			UpstreamCostUSDAtoms:    ZeroChargeUSDAtoms,
			BilledCostUSDAtoms:      ZeroChargeUSDAtoms,
		},
		true,
	)

	if attempts == 0 {
		t.Fatal("expected settlement retry attempts")
	}
	if captured.RequestID != "request-1" {
		t.Fatalf("fallback request_id = %q, want request-1", captured.RequestID)
	}
	if captured.StogasBillingStatus != "complete" {
		t.Fatalf("fallback status = %q, want final billing status", captured.StogasBillingStatus)
	}
}

func TestFinalizeRequestSelectsTinybirdFirstSettlementMode(t *testing.T) {
	tests := []struct {
		name         string
		handler      http.HandlerFunc
		tinybird     func(*httptest.Server) *TinybirdClient
		wantOutbox   bool
		wantRequests int
	}{
		{
			name: "committed row skips outbox",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
			},
			wantOutbox:   false,
			wantRequests: 1,
		},
		{
			name: "async acceptance falls back to outbox",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
			},
			wantOutbox:   true,
			wantRequests: 1,
		},
		{
			name: "rate limit falls back to outbox",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantOutbox:   true,
			wantRequests: 1,
		},
		{
			name: "unprocessable row falls back to outbox",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnprocessableEntity)
			},
			wantOutbox:   true,
			wantRequests: 1,
		},
		{
			name: "quarantine falls back to outbox",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"successful_rows":0,"quarantined_rows":1}`))
			},
			wantOutbox:   true,
			wantRequests: 1,
		},
		{
			name: "network failure falls back to outbox",
			tinybird: func(*httptest.Server) *TinybirdClient {
				return newTestTinybirdClient(t, "http://127.0.0.1:1")
			},
			wantOutbox: true,
		},
		{
			name: "timeout falls back to outbox",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(20 * time.Millisecond)
				_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
			},
			tinybird: func(server *httptest.Server) *TinybirdClient {
				client := newTestTinybirdClient(t, server.URL)
				client.client.Timeout = time.Millisecond
				return client
			},
			wantOutbox:   true,
			wantRequests: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			handler := tt.handler
			if handler == nil {
				handler = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if got := r.URL.Query().Get("wait"); got != "true" {
					t.Fatalf("wait query = %q, want true", got)
				}
				handler(w, r)
			}))
			defer server.Close()

			tinybird := newTestTinybirdClient(t, server.URL)
			if tt.tinybird != nil {
				tinybird = tt.tinybird(server)
			}
			var writeOutbox *bool
			service := &Service{
				settleFunc: func(_ context.Context, _ *Authorization, _ string, _ string, _ string, fallback bool) error {
					writeOutbox = &fallback
					return nil
				},
				tinybird: tinybird,
			}
			if err := service.FinalizeRequest(context.Background(), testAuthorization(), testGatewayRequestEvent()); err != nil {
				t.Fatalf("FinalizeRequest returned error: %v", err)
			}
			if writeOutbox == nil || *writeOutbox != tt.wantOutbox {
				t.Fatalf("writeOutbox = %v, want %t", writeOutbox, tt.wantOutbox)
			}
			if requests != tt.wantRequests {
				t.Fatalf("Tinybird requests = %d, want %d", requests, tt.wantRequests)
			}
		})
	}
}

func TestTinybirdAppendRequiresCommittedSingleRowAcknowledgement(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantErr    bool
		errContain string
	}{
		{
			name:   "single row",
			status: http.StatusOK,
			body:   `{"successful_rows":1,"quarantined_rows":0}`,
		},
		{
			name:       "multiple rows",
			status:     http.StatusOK,
			body:       `{"successful_rows":2,"quarantined_rows":0}`,
			wantErr:    true,
			errContain: "successful_rows=2",
		},
		{
			name:       "missing acknowledgement",
			status:     http.StatusOK,
			body:       `{}`,
			wantErr:    true,
			errContain: "successful_rows=0",
		},
		{
			name:       "accepted async",
			status:     http.StatusAccepted,
			wantErr:    true,
			errContain: "status 202",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			err := newTestTinybirdClient(t, server.URL).AppendGatewayRequest(context.Background(), testGatewayRequestEvent())
			if (err != nil) != tt.wantErr {
				t.Fatalf("AppendGatewayRequest error = %v, wantErr=%t", err, tt.wantErr)
			}
			if err != nil && tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
				t.Fatalf("AppendGatewayRequest error = %q, want to contain %q", err, tt.errContain)
			}
		})
	}
}

func TestRetrySettleAfterTinybirdCommitDoesNotAppendDuplicateRescueEvidence(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       5 * time.Millisecond,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			return errors.New("simulated postgres outage after tinybird commit")
		},
		tinybird: newTestTinybirdClient(t, server.URL),
	}
	service.retrySettle(
		testAuthorization(),
		"params",
		ZeroChargeUSDAtoms,
		`{"request_id":"request-1"}`,
		testGatewayRequestEvent(),
		false,
	)

	if requests != 0 {
		t.Fatalf("Tinybird rescue requests = %d, want 0 after committed evidence", requests)
	}
}

func TestFinalizeRequestRetriesPostgresAfterTinybirdCommitWithoutDuplicateAppend(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	attempts := 0
	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       20 * time.Millisecond,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			attempts++
			if attempts == 1 {
				return errors.New("transient postgres failure")
			}
			return nil
		},
		tinybird: newTestTinybirdClient(t, server.URL),
	}

	if err := service.FinalizeRequest(context.Background(), testAuthorization(), testGatewayRequestEvent()); err != nil {
		t.Fatalf("FinalizeRequest returned error: %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	if attempts < 2 {
		t.Fatalf("settlement attempts = %d, want retry after initial failure", attempts)
	}
	if requests != 1 {
		t.Fatalf("Tinybird requests = %d, want only initial committed append", requests)
	}
}

func TestCloseWaitsForActiveSettlementRetry(t *testing.T) {
	retryStarted := make(chan struct{})
	releaseRetry := make(chan struct{})
	closeReturned := make(chan struct{})
	attempts := 0
	var once sync.Once
	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       time.Second,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			attempts++
			if attempts == 1 {
				return errors.New("transient postgres failure")
			}
			once.Do(func() { close(retryStarted) })
			<-releaseRetry
			return nil
		},
	}

	if err := service.FinalizeRequest(context.Background(), testAuthorization(), testGatewayRequestEvent()); err != nil {
		t.Fatalf("FinalizeRequest returned error: %v", err)
	}
	<-retryStarted

	go func() {
		service.Close()
		close(closeReturned)
	}()

	select {
	case <-closeReturned:
		t.Fatal("Close returned before active settlement retry finished")
	case <-time.After(10 * time.Millisecond):
	}

	close(releaseRetry)
	select {
	case <-closeReturned:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after settlement retry finished")
	}
}

func TestRetrySettleDoesNotPublishRescueEvidenceForPermanentSettlementRejection(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       20 * time.Millisecond,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			return &settleResultError{
				err:        errors.New("Invalid settlement payload"),
				result:     "payload_mismatch",
				statusCode: 400,
			}
		},
		tinybird: newTestTinybirdClient(t, server.URL),
	}
	service.retrySettle(
		testAuthorization(),
		"params",
		ZeroChargeUSDAtoms,
		`{"request_id":"request-1"}`,
		testGatewayRequestEvent(),
		true,
	)

	if requests != 0 {
		t.Fatalf("Tinybird rescue requests = %d, want 0 for permanent settlement rejection", requests)
	}
}

func testAuthorization() *Authorization {
	return &Authorization{
		AuthorizedAmount:   mustParseBigInt(ZeroChargeUSDAtoms),
		AvailableAfter:     mustParseBigInt("100000000000"),
		KeyID:              "key-1",
		ProductKey:         "gpt-4o-mini",
		ProviderKey:        "openai",
		RequestID:          "request-1",
		UpstreamCredential: "stogas",
		UserID:             "user-1",
	}
}

func testGatewayRequestEvent() RequestEvent {
	return RequestEvent{
		CreatedAt:               time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		RequestID:               "request-1",
		StogasAPIKeyID:          "key-1",
		StogasBillingStatus:     "complete",
		StogasProcessingSuccess: true,
		UpstreamCostUSDAtoms:    ZeroChargeUSDAtoms,
		BilledCostUSDAtoms:      ZeroChargeUSDAtoms,
	}
}

func mustParseBigInt(value string) *big.Int {
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("invalid big int test fixture")
	}
	return parsed
}

func mustBigInt(t *testing.T, value string) *big.Int {
	t.Helper()
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid big int %q", value)
	}
	return parsed
}
