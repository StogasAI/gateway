package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
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
		w.WriteHeader(http.StatusOK)
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
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	attempts := 0
	service := &HoldService{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       5 * time.Millisecond,
		settleFunc: func(context.Context, *HoldAuthorization, string, string, string, string) error {
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

func mustBigInt(t *testing.T, value string) *big.Int {
	t.Helper()
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid big int %q", value)
	}
	return parsed
}
