package stogas

import (
	"encoding/json"
	"math/big"
	"testing"
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
	if decoded["metrics"] != "{}" {
		t.Fatalf("metrics = %v, want {}", decoded["metrics"])
	}
	if _, ok := decoded["postgres_financial_state_committed"]; ok {
		t.Fatalf("payload contains deprecated postgres_financial_state_committed: %s", payload)
	}
}

func TestProvisionalBillingEvent(t *testing.T) {
	event := provisionalBillingEvent(GatewayRequestEvent{
		RequestID:           "request",
		StogasStatus:        "success",
		StogasBillingStatus: "complete",
	})

	if event.StogasStatus != "success" {
		t.Fatalf("stogas status should preserve request outcome, got %q", event.StogasStatus)
	}
	if event.StogasBillingStatus != "not_settled" {
		t.Fatalf("billing status = %q, want not_settled", event.StogasBillingStatus)
	}
	if event.StogasBillingRecordStatus != "provisional" {
		t.Fatalf("billing record status = %q, want provisional", event.StogasBillingRecordStatus)
	}
	if event.UpstreamStatus != "unknown" {
		t.Fatalf("upstream status = %q, want unknown", event.UpstreamStatus)
	}
	if event.Metrics != "{}" {
		t.Fatalf("metrics = %q, want {}", event.Metrics)
	}
	if event.CreatedAt == "" {
		t.Fatal("createdAt should be refreshed for provisional fallback logs")
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
