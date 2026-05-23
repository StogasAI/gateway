package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSettlementStatuses(t *testing.T) {
	tests := []struct {
		name           string
		availableAfter string
		authorized     string
		actual         string
		wantStatus     string
	}{
		{name: "exact", availableAfter: "9000", authorized: "1000", actual: "1000", wantStatus: "complete"},
		{name: "refund", availableAfter: "9000", authorized: "1000", actual: "400", wantStatus: "over_reserved"},
		{name: "extra debit positive", availableAfter: "2000", authorized: "1000", actual: "1500", wantStatus: "under_reserved"},
		{name: "extra debit negative", availableAfter: "0", authorized: "1000", actual: "1500", wantStatus: "negative_balance"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorization := &HoldAuthorization{
				AuthorizedAmount: mustBigInt(t, tt.authorized),
				AvailableAfter:   mustBigInt(t, tt.availableAfter),
				KeyID:            "key",
				ProductKey:       "model",
				ProviderKey:      "provider",
				RequestID:        "request",
				UserID:           "user",
			}

			if got := settlementStatus(authorization, tt.actual); got != tt.wantStatus {
				t.Fatalf("settlementStatus = %s, want %s", got, tt.wantStatus)
			}
		})
	}
}

func TestEncodeGatewayRequestEventDefaultsMetrics(t *testing.T) {
	payload, err := encodeGatewayRequestEvent(GatewayRequestEvent{RequestID: "request"})
	if err != nil {
		t.Fatalf("encodeGatewayRequestEvent returned error: %v", err)
	}

	decoded := map[string]any{}
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	metrics, ok := decoded["metrics"].(map[string]any)
	if !ok || len(metrics) != 0 {
		t.Fatalf("metrics = %v, want empty object", decoded["metrics"])
	}
}

func TestTinybirdGatewayRequestEventStringifiesNestedPayload(t *testing.T) {
	status := 200
	event := tinybirdGatewayRequestEvent(GatewayRequestEvent{
		Metrics: map[string]any{
			"model":  "gpt-4o-mini",
			"tokens": map[string]any{"prompt": 1, "completion": 2},
		},
		ProviderAttempts: []ProviderAttempt{{
			IsBYOK:     false,
			LatencyMS:  12,
			Provider:   "openai",
			Status:     "success",
			StatusCode: &status,
		}},
		StogasProcessingSuccess: true,
	})

	if event.StogasProcessingSuccess != 1 {
		t.Fatalf("stogas_processing_success = %d, want 1", event.StogasProcessingSuccess)
	}
	var attempts []ProviderAttempt
	if err := json.Unmarshal([]byte(event.ProviderAttempts), &attempts); err != nil || len(attempts) != 1 {
		t.Fatalf("provider_attempts = %q, err=%v", event.ProviderAttempts, err)
	}
	var metrics map[string]any
	if err := json.Unmarshal([]byte(event.Metrics), &metrics); err != nil || metrics["model"] != "gpt-4o-mini" {
		t.Fatalf("metrics = %q, err=%v", event.Metrics, err)
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

	service := &HoldService{tinybird: NewTinybirdClient(server.URL, "gateway-requests-token")}
	service.publishUncommittedFallback(
		&HoldAuthorization{RequestID: "request-1"},
		GatewayRequestEvent{
			RequestID:               "request-1",
			StogasBillingStatus:     "complete",
			StogasProcessingSuccess: true,
			TotalCostUSDAtoms:       placeholderChargeUsdAtoms,
		},
		nil,
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
	service := &HoldService{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       5 * time.Millisecond,
		settleFunc: func(context.Context, *HoldAuthorization, string, string, string, string, bool) error {
			attempts++
			return errors.New("simulated postgres outage")
		},
		tinybird: NewTinybirdClient(server.URL, "gateway-requests-token"),
	}
	service.retrySettle(
		&HoldAuthorization{RequestID: "request-1"},
		"params",
		placeholderChargeUsdAtoms,
		"{}",
		`{"request_id":"request-1"}`,
		GatewayRequestEvent{
			RequestID:               "request-1",
			StogasBillingStatus:     "complete",
			StogasProcessingSuccess: true,
			TotalCostUSDAtoms:       placeholderChargeUsdAtoms,
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

func TestFinalizePlaceholderHoldSelectsTinybirdFirstSettlementMode(t *testing.T) {
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
				return NewTinybirdClient("http://127.0.0.1:1", "gateway-requests-token")
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
				client := NewTinybirdClient(server.URL, "gateway-requests-token")
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

			tinybird := NewTinybirdClient(server.URL, "gateway-requests-token")
			if tt.tinybird != nil {
				tinybird = tt.tinybird(server)
			}
			var writeOutbox *bool
			service := &HoldService{
				settleFunc: func(_ context.Context, _ *HoldAuthorization, _ string, _ string, _ string, _ string, fallback bool) error {
					writeOutbox = &fallback
					return nil
				},
				tinybird: tinybird,
			}
			if err := service.FinalizePlaceholderHold(context.Background(), testAuthorization(), testGatewayRequestEvent()); err != nil {
				t.Fatalf("FinalizePlaceholderHold returned error: %v", err)
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

			err := NewTinybirdClient(server.URL, "gateway-requests-token").AppendGatewayRequest(context.Background(), testGatewayRequestEvent())
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

	service := &HoldService{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       5 * time.Millisecond,
		settleFunc: func(context.Context, *HoldAuthorization, string, string, string, string, bool) error {
			return errors.New("simulated postgres outage after tinybird commit")
		},
		tinybird: NewTinybirdClient(server.URL, "gateway-requests-token"),
	}
	service.retrySettle(
		testAuthorization(),
		"params",
		placeholderChargeUsdAtoms,
		"{}",
		`{"request_id":"request-1"}`,
		testGatewayRequestEvent(),
		false,
	)

	if requests != 0 {
		t.Fatalf("Tinybird rescue requests = %d, want 0 after committed evidence", requests)
	}
}

func TestFinalizePlaceholderHoldRetriesPostgresAfterTinybirdCommitWithoutDuplicateAppend(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	attempts := 0
	service := &HoldService{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       20 * time.Millisecond,
		settleFunc: func(context.Context, *HoldAuthorization, string, string, string, string, bool) error {
			attempts++
			if attempts == 1 {
				return errors.New("transient postgres failure")
			}
			return nil
		},
		tinybird: NewTinybirdClient(server.URL, "gateway-requests-token"),
	}

	if err := service.FinalizePlaceholderHold(context.Background(), testAuthorization(), testGatewayRequestEvent()); err != nil {
		t.Fatalf("FinalizePlaceholderHold returned error: %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	if attempts < 2 {
		t.Fatalf("settlement attempts = %d, want retry after initial failure", attempts)
	}
	if requests != 1 {
		t.Fatalf("Tinybird requests = %d, want only initial committed append", requests)
	}
}

func TestRetrySettleDoesNotPublishRescueEvidenceForPermanentSettlementRejection(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	service := &HoldService{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       20 * time.Millisecond,
		settleFunc: func(context.Context, *HoldAuthorization, string, string, string, string, bool) error {
			return &settleResultError{
				err:        errors.New("Invalid settlement payload"),
				result:     "payload_mismatch",
				statusCode: 400,
			}
		},
		tinybird: NewTinybirdClient(server.URL, "gateway-requests-token"),
	}
	service.retrySettle(
		testAuthorization(),
		"params",
		placeholderChargeUsdAtoms,
		"{}",
		`{"request_id":"request-1"}`,
		testGatewayRequestEvent(),
		true,
	)

	if requests != 0 {
		t.Fatalf("Tinybird rescue requests = %d, want 0 for permanent settlement rejection", requests)
	}
}

func testAuthorization() *HoldAuthorization {
	return &HoldAuthorization{
		AuthorizedAmount: mustParseBigInt(placeholderChargeUsdAtoms),
		AvailableAfter:   mustParseBigInt("100000000000"),
		KeyID:            "key-1",
		ProductKey:       "gpt-4o-mini",
		ProviderKey:      "openai",
		RequestID:        "request-1",
		UserID:           "user-1",
	}
}

func testGatewayRequestEvent() GatewayRequestEvent {
	return GatewayRequestEvent{
		CreatedAt:               time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Metrics:                 map[string]any{},
		RequestID:               "request-1",
		StogasAPIKeyID:          "key-1",
		StogasBillingStatus:     "complete",
		StogasProcessingSuccess: true,
		TotalCostUSDAtoms:       placeholderChargeUsdAtoms,
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
