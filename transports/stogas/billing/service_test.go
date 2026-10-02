package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/maximhq/bifrost/transports/stogas/money"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
)

func TestParseSignedAPIKey(t *testing.T) {
	secret := "test-token-pepper"
	keyID := "019de515-eabf-7c0e-89bd-400629a79580"
	organizationID := "019de516-7df8-71d6-80e4-3c62090d4e94"
	userID := "019de516-b10f-786f-97f8-b95c71dfe1b6"
	rawKey := testSignedAPIKey(t, secret, keyID, organizationID, userID, "", apiKeyVersion)

	claims, err := parseSignedAPIKey(rawKey, secret)
	if err != nil {
		t.Fatalf("parseSignedAPIKey returned error: %v", err)
	}
	if claims.KeyID != keyID || claims.OrganizationID != organizationID || claims.ResponsibleID != userID {
		t.Fatalf("claims = %#v", claims)
	}
	if claims.GrantID != nil {
		t.Fatalf("grant = %#v", claims)
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

func TestParseGrantSignedAPIKey(t *testing.T) {
	secret := "test-token-pepper"
	keyID := "019de515-eabf-7c0e-89bd-400629a79580"
	organizationID := "019de516-7df8-71d6-80e4-3c62090d4e94"
	userID := "019de516-b10f-786f-97f8-b95c71dfe1b6"
	grantID := "019de516-c9ac-79cf-b701-4cf1b21f0a8c"
	rawKey := testSignedAPIKey(t, secret, keyID, organizationID, userID, grantID, apiKeyVersion)

	claims, err := parseSignedAPIKey(rawKey, secret)
	if err != nil {
		t.Fatalf("parseSignedAPIKey returned error: %v", err)
	}
	if claims.GrantID == nil || *claims.GrantID != grantID {
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
		"019de516-b10f-786f-97f8-b95c71dfe1b6",
		"",
		apiKeyVersion+1)

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
		"019de516-b10f-786f-97f8-b95c71dfe1b6",
		"",
		apiKeyVersion)
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rawKey, apiKeyPrefix))
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	clear(body[68:84])
	hasher := hmac.New(sha256.New, []byte(secret))
	_, _ = hasher.Write(body[:apiKeyPayloadBytes])
	copy(body[apiKeyPayloadBytes:], hasher.Sum(nil)[:apiKeyMACBytes])

	if _, err := parseSignedAPIKey(apiKeyPrefix+base64.RawURLEncoding.EncodeToString(body), secret); err == nil {
		t.Fatal("expected zero issuance entropy to be rejected")
	}
}

func testSignedAPIKey(t testing.TB, secret string, keyID string, organizationID string, userID string, grantID string, version uint32) string {
	t.Helper()
	payload := make([]byte, apiKeyPayloadBytes)
	binary.BigEndian.PutUint32(payload[0:4], version)
	keyUUID := uuid.MustParse(keyID)
	organizationUUID := uuid.MustParse(organizationID)
	userUUID := uuid.MustParse(userID)
	copy(payload[4:20], keyUUID[:])
	copy(payload[20:36], organizationUUID[:])
	copy(payload[36:52], userUUID[:])
	if grantID != "" {
		grantUUID := uuid.MustParse(grantID)
		copy(payload[52:68], grantUUID[:])
	}
	for index := 68; index < apiKeyPayloadBytes; index++ {
		payload[index] = byte(index - 67)
	}
	hasher := hmac.New(sha256.New, []byte(secret))
	_, _ = hasher.Write(payload)
	body := append(payload, hasher.Sum(nil)[:apiKeyMACBytes]...)
	return apiKeyPrefix + base64.RawURLEncoding.EncodeToString(body)
}

func TestParseUSDRejectsNoncanonicalOrOutOfRangeValues(t *testing.T) {
	for _, value := range []string{
		"",
		"abc",
		"-1",
		"+1",
		" 1",
		"1 ",
		"01",
		"1000000000000000000000000000001",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseUSD(value); err == nil {
				t.Fatalf("ParseUSD(%q) succeeded", value)
			}
		})
	}

	for _, value := range []string{"0", "1", maximumUSD} {
		t.Run("valid_"+value, func(t *testing.T) {
			parsed, err := ParseUSD(value)
			if err != nil {
				t.Fatalf("ParseUSD(%q) returned error: %v", value, err)
			}
			if parsed.String() != value {
				t.Fatalf("ParseUSD(%q) = %s", value, parsed)
			}
		})
	}
}

func TestParseDatabaseMoneyRejectsMissingOrMalformedValues(t *testing.T) {
	if _, err := parseDatabaseMoney(nil, "authorized billed cost"); err == nil {
		t.Fatal("parseDatabaseMoney accepted a missing amount")
	}
	malformed := "invalid"
	if _, err := parseDatabaseMoney(&malformed, "authorized billed cost"); err == nil {
		t.Fatal("parseDatabaseMoney accepted a malformed amount")
	}
}

func TestEncodeGatewayRequestEventDefaultsPricing(t *testing.T) {
	payload, err := encodeGatewayRequestEvent(RequestEvent{SchemaVersion: RequestLogSchemaVersion, RequestID: "request"})
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
	if _, exists := decoded["hold_params_hash"]; exists {
		t.Fatal("the private reconciliation hash must not enter the public request-log payload")
	}
	pricing, ok := decoded["meters"].(map[string]any)
	if !ok || len(pricing) != 0 {
		t.Fatalf("pricing = %#v, want empty object", decoded["meters"])
	}
}

func TestRequestLogRejectsUnsupportedSchemaVersions(t *testing.T) {
	for _, version := range []uint8{0, 2} {
		event := testGatewayRequestEvent()
		event.SchemaVersion = version
		if _, err := encodeGatewayRequestEvent(event); err == nil {
			t.Fatalf("encoded unsupported version %d", version)
		}
		client := &TinybirdClient{}
		if _, err := client.enqueueGatewayRequest(event, false); err == nil {
			t.Fatalf("enqueued unsupported version %d", version)
		}
	}
	for _, payload := range []string{`{}`, `{"schema_version":0}`, `{"schema_version":2}`, `{"schema_version":"1"}`} {
		if _, err := decodeGatewayRequestEvent(payload); err == nil {
			t.Fatalf("decoded unsupported payload %s", payload)
		}
	}
}

func TestDecodeGatewayRequestEventRestoresTinybirdAnalyticsProjection(t *testing.T) {
	event := testGatewayRequestEvent()
	event.CatalogVersion = catalogVersion(39)
	event.CatalogChainHash = optionalString("sha256:" + strings.Repeat("b", 64))
	overhead := "29"
	event.CacheWriteOverheadUSD = &overhead
	event.Meters = EventMeters{
		MeterCachedInputTokens: PricedMeter("300", RatePerMillionTokens, "0", "0"),
		MeterInputTokens:       PricedMeter("17", "per_mill_tokens", "100", "2"),
		MeterTotalInputTokens:  {Quantity: "317"},
	}
	payload, err := encodeGatewayRequestEvent(event)
	if err != nil {
		t.Fatalf("encodeGatewayRequestEvent returned error: %v", err)
	}
	decoded, err := decodeGatewayRequestEvent(payload)
	if err != nil {
		t.Fatalf("decodeGatewayRequestEvent returned error: %v", err)
	}
	projected := tinybirdGatewayRequestEvent(decoded)
	if projected.CatalogVersion == nil || *projected.CatalogVersion != 39 || projected.CatalogChainHash == nil || *projected.CatalogChainHash != *event.CatalogChainHash {
		t.Fatalf("outbox projection lost the historical catalog identity: %#v", projected)
	}
	if projected.SchemaVersion != RequestLogSchemaVersion || projected.RequestID != event.RequestID ||
		projected.AnalyticsInputTokens == nil || *projected.AnalyticsInputTokens != 317 ||
		projected.AnalyticsCachedInputTokens != 300 ||
		projected.CacheWriteOverheadUSD == nil ||
		*projected.CacheWriteOverheadUSD != overhead {
		t.Fatalf("decoded Tinybird projection = %#v", projected)
	}

	if _, err := decodeGatewayRequestEvent(`{"schema_version":1,"meters":{"input_tokens":{"quantity":"invalid","rateKey":"per_mill_tokens","rateUsd":"1","usd":"1"}}}`); err == nil {
		t.Fatal("decodeGatewayRequestEvent accepted invalid canonical pricing")
	}
	if _, err := decodeGatewayRequestEvent(`{"schema_version":1,"cache_read_savings_usd":"-1","meters":{}}`); err == nil {
		t.Fatal("decodeGatewayRequestEvent accepted invalid cache read savings")
	}
	if _, err := decodeGatewayRequestEvent(`{"schema_version":1,"cache_write_overhead_usd":"-1","meters":{}}`); err == nil {
		t.Fatal("decodeGatewayRequestEvent accepted invalid cache write overhead")
	}
}

func TestTinybirdGatewayRequestEventStringifiesNestedPayload(t *testing.T) {
	failedStatus := 502
	successStatus := 200
	ttftMS := uint32(150)
	event := tinybirdGatewayRequestEvent(RequestEvent{
		SchemaVersion:         RequestLogSchemaVersion,
		CacheWriteOverheadUSD: stringPtr("23"),
		Performance:           RequestPerformance{TotalMS: 150, ProviderMS: 140, TTFTMS: &ttftMS},
		Meters: EventMeters{
			"input_tokens":                PricedMeter("12", "per_mill_tokens", "1", "1"),
			"total_input_tokens":          {Quantity: "19"},
			"total_cache_write_tokens":    {Quantity: "7"},
			"cache_write_input_tokens":    {Quantity: "1"},
			"cache_write_5m_input_tokens": {Quantity: "2"},
			"cache_write_1h_input_tokens": {Quantity: "4"},
		},
		analyticsQuantities: map[string]uint64{
			"input_tokens":                12,
			"total_input_tokens":          19,
			"total_cache_write_tokens":    7,
			"cache_write_input_tokens":    1,
			"cache_write_5m_input_tokens": 2,
			"cache_write_1h_input_tokens": 4,
		},
		Plugins: plugins.Metrics{StogasStructuredPIIRedaction: &plugins.StogasStructuredPIIRedactionMetrics{ItemsRedacted: 3, DurationUS: 41}},
		ProviderAttempts: []ProviderAttempt{{
			LatencyMS:    30,
			Provider:     "openai",
			Status:       "connection_error",
			StatusCode:   &failedStatus,
			UpstreamByok: nil,
		}, {
			LatencyMS:         90,
			Provider:          "anthropic",
			ProviderRequestID: "provider-request",
			FinishReason:      "stop",
			Status:            "success",
			StatusCode:        &successStatus,
			UpstreamByok:      nil,
		}},
		GatewayVersion: "v1.5.13",
	})

	if event.Error != "null" || event.AnalyticsErrorCode != "" || event.AnalyticsErrorStatus != nil {
		t.Fatalf("unexpected error: %#v", event)
	}
	if event.AnalyticsInputTokens == nil || *event.AnalyticsInputTokens != 19 || event.AnalyticsProviderStatus != "success" {
		t.Fatalf("analytics projections do not match canonical payload: %#v", event)
	}
	if event.AnalyticsProviderLatencyMS != 140 {
		t.Fatalf("analytics_provider_latency_ms = %d, want 140", event.AnalyticsProviderLatencyMS)
	}
	if event.AnalyticsCacheWriteTokens != 7 {
		t.Fatalf("analytics cache-write tokens = %d, want 7", event.AnalyticsCacheWriteTokens)
	}
	if event.CacheWriteOverheadUSD == nil || *event.CacheWriteOverheadUSD != "23" {
		t.Fatalf("cache-write overhead = %#v, want 23", event.CacheWriteOverheadUSD)
	}
	if strings.Join(event.AnalyticsProviders, ",") != "openai,anthropic" ||
		strings.Join(event.AnalyticsProviderStatuses, ",") != "connection_error,502,success,200" {
		t.Fatalf("analytics provider projections do not include every attempt: %#v", event)
	}
	if event.AnalyticsTTFTMS == nil || *event.AnalyticsTTFTMS != 150 {
		t.Fatalf("ttft_ms = %#v, want 150", event.AnalyticsTTFTMS)
	}
	if event.GatewayVersion != "v1.5.13" {
		t.Fatalf("gateway_version = %q", event.GatewayVersion)
	}
	var attempts []ProviderAttempt
	if err := json.Unmarshal([]byte(event.ProviderAttempts), &attempts); err != nil ||
		len(attempts) != 2 || attempts[1].Provider != "anthropic" {
		t.Fatalf("provider_attempts = %q, err=%v", event.ProviderAttempts, err)
	}
	var pricing map[string]map[string]string
	if err := json.Unmarshal([]byte(event.Meters), &pricing); err != nil || pricing["input_tokens"]["quantity"] != "12" {
		t.Fatalf("pricing = %q, err=%v", event.Meters, err)
	}
	var pluginMetrics plugins.Metrics
	if err := json.Unmarshal([]byte(event.Plugins), &pluginMetrics); err != nil ||
		pluginMetrics.StogasStructuredPIIRedaction == nil ||
		pluginMetrics.StogasStructuredPIIRedaction.ItemsRedacted != 3 ||
		pluginMetrics.StogasStructuredPIIRedaction.DurationUS != 41 {
		t.Fatalf("plugins = %q, err=%v", event.Plugins, err)
	}
	var performance RequestPerformance
	if err := json.Unmarshal([]byte(event.Performance), &performance); err != nil ||
		performance.TotalMS != 150 || performance.ProviderMS != 140 || performance.TTFTMS == nil || *performance.TTFTMS != 150 {
		t.Fatalf("timings = %q, err=%v", event.Performance, err)
	}
}

func TestTinybirdGatewayRequestEventPreservesMaximumPerformance(t *testing.T) {
	maximum := ^uint32(0)
	ttftMS := uint32(1)
	event := tinybirdGatewayRequestEvent(RequestEvent{SchemaVersion: RequestLogSchemaVersion, Performance: RequestPerformance{TotalMS: maximum, ProviderMS: maximum, TTFTMS: &ttftMS}, ProviderAttempts: []ProviderAttempt{
		{LatencyMS: maximum, Provider: "openai", Status: "connection_error"},
		{
			LatencyMS: 1,
			Provider:  "anthropic",
			Status:    "success",
		},
	}})

	if event.AnalyticsProviderLatencyMS != maximum {
		t.Fatalf("analytics_provider_latency_ms = %d, want %d", event.AnalyticsProviderLatencyMS, maximum)
	}
	if event.AnalyticsTTFTMS == nil || *event.AnalyticsTTFTMS != ttftMS {
		t.Fatalf("ttft_ms = %#v, want %d", event.AnalyticsTTFTMS, ttftMS)
	}
}

func TestNewRequestEventPreservesSettledPricingAudit(t *testing.T) {
	startedAt := time.Now().Add(-25 * time.Millisecond)
	ttftMS := uint32(8)
	grantID := "019de515-eabf-7c0e-89bd-400629a79580"
	event := mustNewRequestEvent(t, EventInput{
		Authorization: &Authorization{AuthorizedBilledCostUSD: mustUSD("10"), GrantID: &grantID, RequestID: "request-1"},
		TTFTMS:        &ttftMS,
		RequestType:   string(schemas.ChatCompletionStreamRequest),
		Meters: EventMeters{
			"input_tokens": PricedMeter("1", "per_mill_tokens", "2000000", "2"),
		},
		Plugins:   plugins.Metrics{StogasStructuredPIIRedaction: &plugins.StogasStructuredPIIRedactionMetrics{ItemsRedacted: 2, DurationUS: 17}},
		StartedAt: startedAt,
	})

	if *event.Meters["input_tokens"].RateUSD != "2000000" {
		t.Fatalf("expected settled pricing audit, got %#v", event.Meters)
	}
	if event.Performance.TTFTMS == nil || *event.Performance.TTFTMS != ttftMS {
		t.Fatalf("expected request TTFT, got %#v", event.Performance.TTFTMS)
	}
	if event.StogasGrantID == nil || *event.StogasGrantID != grantID {
		t.Fatalf("expected grant attribution, got %#v", event.StogasGrantID)
	}
	if event.Plugins.StogasStructuredPIIRedaction == nil ||
		event.Plugins.StogasStructuredPIIRedaction.ItemsRedacted != 2 ||
		event.Plugins.StogasStructuredPIIRedaction.DurationUS != 17 {
		t.Fatalf("expected plugin metrics, got %#v", event.Plugins)
	}
}

func TestBilledRequestCostUsesFullManagedCostAndCeilingTwoPercentForBYOK(t *testing.T) {
	managed := &Authorization{UpstreamByok: "stogas"}
	byok := &Authorization{UpstreamByok: "0198f4cc-6c25-8000-8000-000000000001"}
	for _, tc := range []struct {
		name          string
		authorization *Authorization
		upstream      string
		want          string
	}{
		{name: "managed", authorization: managed, upstream: "101", want: "101"},
		{name: "BYOK zero", authorization: byok, upstream: "0", want: "0"},
		{name: "BYOK minimum nonzero", authorization: byok, upstream: "0.000000000000000000000000000000000001", want: "0.000000000000000000000000000000000001"},
		{name: "BYOK exact", authorization: byok, upstream: "100", want: "2"},
		{name: "BYOK rounds up", authorization: byok, upstream: "101", want: "2.02"},
		{name: "BYOK larger", authorization: byok, upstream: "999", want: "19.98"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := calculateBilledCostUSD(tc.authorization, mustUSDTest(t, tc.upstream)).String(); got != tc.want {
				t.Fatalf("calculateBilledCostUSD(%q) = %q, want %q", tc.upstream, got, tc.want)
			}
		})
	}
}

func TestNewRequestEventKeepsCacheEconomicsIndependentFromCustomerBilling(t *testing.T) {
	upstreamSavings := "90"
	for _, tc := range []struct {
		name           string
		authorization  *Authorization
		wantBilledCost string
	}{
		{
			name:           "managed",
			authorization:  &Authorization{UpstreamByok: "stogas"},
			wantBilledCost: "101",
		},
		{
			name:           "BYOK",
			authorization:  &Authorization{UpstreamByok: "0198f4cc-6c25-8000-8000-000000000001"},
			wantBilledCost: "2.02",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := mustNewRequestEvent(t, EventInput{
				UpstreamCostUSD:     "101",
				Authorization:       tc.authorization,
				CacheReadSavingsUSD: &upstreamSavings,
			})
			if event.BilledCostUSD != tc.wantBilledCost ||
				event.CacheReadSavingsUSD == nil || *event.CacheReadSavingsUSD != "90" {
				t.Fatalf("unexpected cache savings projection: %#v", event)
			}
		})
	}
}

func TestNewRequestEventUsesProviderClockAndClampsItToTotal(t *testing.T) {
	now := time.Now()
	startedAt := now.Add(-100 * time.Millisecond)
	providerStartedAt := now.Add(-60 * time.Millisecond)
	providerCompletedAt := now.Add(-20 * time.Millisecond)
	event := mustNewRequestEvent(t, EventInput{
		Authorization:       &Authorization{RequestID: "request-1"},
		ClientStoppedAt:     now.Add(-55 * time.Millisecond),
		ProviderCompletedAt: providerCompletedAt,
		ProviderStartedAt:   providerStartedAt,
		StartedAt:           startedAt,
	})
	if event.Performance.TotalMS < 90 {
		t.Fatalf("total time should begin at request admission, got %dms", event.Performance.TotalMS)
	}
	providerTime := event.ProviderAttempts[0].LatencyMS
	if providerTime < 35 || providerTime > 45 {
		t.Fatalf("provider time should end at observed provider completion, got %dms", providerTime)
	}
	if event.ClientStopMS == nil || *event.ClientStopMS < 40 || *event.ClientStopMS > 50 {
		t.Fatalf("client stop time should use the request clock, got %#v", event.ClientStopMS)
	}
	if event.Performance.ProviderMS < 35 || event.Performance.ProviderMS > 45 ||
		event.Performance.ProviderMS > event.Performance.TotalMS {
		t.Fatalf("provider duration exceeds the request clock: %#v", event)
	}

	event = mustNewRequestEvent(t, EventInput{
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

	event = mustNewRequestEvent(t, EventInput{
		Authorization: &Authorization{RequestID: "request-2"},
		Response: &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{
			ExtraFields: schemas.BifrostResponseExtraFields{Latency: 500},
		}},
		StartedAt: startedAt,
	})
	if len(event.ProviderAttempts) != 0 {
		t.Fatalf("a request that never started a provider has attempts: %#v", event.ProviderAttempts)
	}
	if event.Performance.ProviderMS != 0 {
		t.Fatalf("a request never dispatched must not record provider time: %#v", event.Performance)
	}
	if payload := tinybirdGatewayRequestEvent(event); payload.ProviderAttempts != "[]" || len(payload.AnalyticsProviders) != 0 || payload.AnalyticsProviderStatus != "" {
		t.Fatalf("pre-provider analytics projection is not empty: %#v", payload)
	}

	event = mustNewRequestEvent(t, EventInput{
		Authorization:   &Authorization{RequestID: "request-client-stop-clamp"},
		ClientStoppedAt: now.Add(time.Hour),
		StartedAt:       startedAt,
	})
	if event.ClientStopMS == nil || *event.ClientStopMS != event.Performance.TotalMS {
		t.Fatalf("client stop time must not exceed total time: stop=%#v total=%d", event.ClientStopMS, event.Performance.TotalMS)
	}
}

func TestNewRequestEventCanonicalizesPerformanceBounds(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name              string
		startedAt         time.Time
		providerStartedAt time.Time
		providerEndedAt   time.Time
		wantProvider      bool
	}{
		{
			name:              "provider clock before request",
			startedAt:         now.Add(-100 * time.Millisecond),
			providerStartedAt: now.Add(-110 * time.Millisecond),
			providerEndedAt:   now.Add(-20 * time.Millisecond),
		},
		{
			name:              "provider completion before start",
			startedAt:         now.Add(-100 * time.Millisecond),
			providerStartedAt: now.Add(-75 * time.Millisecond),
			providerEndedAt:   now.Add(-80 * time.Millisecond),
			wantProvider:      true,
		},
		{
			name:              "provider completion after snapshot",
			startedAt:         now.Add(-100 * time.Millisecond),
			providerStartedAt: now.Add(-75 * time.Millisecond),
			providerEndedAt:   now.Add(time.Hour),
			wantProvider:      true,
		},
		{
			name:              "provider starts after snapshot",
			startedAt:         now.Add(-100 * time.Millisecond),
			providerStartedAt: now.Add(time.Hour),
			providerEndedAt:   now.Add(2 * time.Hour),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := mustNewRequestEvent(t, EventInput{
				Authorization:       &Authorization{ProviderKey: "openai", RequestID: "request-timing"},
				ProviderCompletedAt: test.providerEndedAt,
				ProviderStartedAt:   test.providerStartedAt,
				StartedAt:           test.startedAt,
			})
			timings := event.Performance
			if timings.ProviderMS > timings.TotalMS {
				t.Fatalf("provider duration = %#v, total = %d", timings, event.Performance.TotalMS)
			}
			if test.wantProvider && timings.ProviderMS == 0 {
				t.Fatalf("valid provider start lost provider wall time: %#v", timings)
			}
			if !test.wantProvider && timings.ProviderMS != 0 {
				t.Fatalf("invalid provider clock created provider wall time: %#v", timings)
			}
		})
	}
}

func TestNewRequestEventCanonicalizesTTFT(t *testing.T) {
	startedAt := time.Now().UTC().Add(-100 * time.Millisecond)
	ttftMS := uint32(40)
	event := mustNewRequestEvent(t, EventInput{
		Authorization: &Authorization{RequestID: "request-stream"},
		RequestType:   string(schemas.ResponsesStreamRequest),
		StartedAt:     startedAt,
		TTFTMS:        &ttftMS,
	})
	ttftMS = 1
	if event.Performance.TTFTMS == nil || *event.Performance.TTFTMS != 40 {
		t.Fatalf("request event did not preserve an immutable TTFT: %#v", event.Performance.TTFTMS)
	}

	tooLarge := ^uint32(0)
	clamped := mustNewRequestEvent(t, EventInput{
		Authorization: &Authorization{RequestID: "request-clamped"},
		RequestType:   string(schemas.ChatCompletionStreamRequest),
		StartedAt:     startedAt,
		TTFTMS:        &tooLarge,
	})
	if clamped.Performance.TTFTMS == nil || *clamped.Performance.TTFTMS != clamped.Performance.TotalMS {
		t.Fatalf("TTFT must not exceed total request time: %#v", clamped)
	}

	buffered := mustNewRequestEvent(t, EventInput{
		Authorization: &Authorization{RequestID: "request-buffered"},
		RequestType:   string(schemas.ResponsesRequest),
		StartedAt:     startedAt,
		TTFTMS:        &tooLarge,
	})
	if buffered.Performance.TTFTMS != nil {
		t.Fatalf("buffered request fabricated TTFT: %#v", buffered.Performance.TTFTMS)
	}
}

func TestNewRequestEventProjectsSequentialProviderAttempts(t *testing.T) {
	base := time.Now().UTC().Add(-time.Second)
	statusCode := 502
	ttftMS := uint32(145)
	response := &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{ID: "provider-request"}}
	event := mustNewRequestEvent(t, EventInput{
		Authorization: &Authorization{
			ProviderKey: "openai",
			RequestID:   "request-retry",
		},
		ProviderAttempts: []ProviderAttemptInput{
			{
				Provider:    "openai",
				StartedAt:   base.Add(10 * time.Millisecond),
				CompletedAt: base.Add(40 * time.Millisecond),
				Error: &schemas.BifrostError{
					StatusCode: &statusCode,
					Error:      &schemas.ErrorField{Message: "upstream unavailable"},
				},
			},
			{
				Provider:    "anthropic",
				StartedAt:   base.Add(55 * time.Millisecond),
				CompletedAt: base.Add(145 * time.Millisecond),
				Response:    response,
			},
		},
		ProviderStartedAt:   base.Add(5 * time.Millisecond),
		ProviderCompletedAt: base.Add(150 * time.Millisecond),
		RequestType:         string(schemas.ChatCompletionStreamRequest),
		Response:            response,
		StartedAt:           base,
		TTFTMS:              &ttftMS,
	})

	if len(event.ProviderAttempts) != 2 {
		t.Fatalf("provider attempts = %#v, want two attempts", event.ProviderAttempts)
	}
	if event.ProviderAttempts[0].LatencyMS != 30 || event.ProviderAttempts[1].LatencyMS != 90 {
		t.Fatalf("provider attempt latencies = %#v", event.ProviderAttempts)
	}
	if event.ProviderAttempts[0].Status != "provider_error" || event.ProviderAttempts[1].Status != "success" {
		t.Fatalf("provider attempt statuses = %#v", event.ProviderAttempts)
	}
	payload := tinybirdGatewayRequestEvent(event)
	if payload.AnalyticsProviderLatencyMS != 145 {
		t.Fatalf("analytics provider latency = %d, want 145", payload.AnalyticsProviderLatencyMS)
	}
	if payload.AnalyticsTTFTMS == nil || *payload.AnalyticsTTFTMS != ttftMS {
		t.Fatalf("TTFT = %#v, want %d", payload.AnalyticsTTFTMS, ttftMS)
	}
	if payload.AnalyticsProviderStatus != "success" || strings.Join(payload.AnalyticsProviders, ",") != "openai,anthropic" {
		t.Fatalf("analytics provider projection = %#v", payload)
	}

	requestTTFTMS := uint32(7)
	singleAttempt := mustNewRequestEvent(t, EventInput{
		Authorization:       &Authorization{ProviderKey: "openai", RequestID: "request-single"},
		ProviderAttempts:    []ProviderAttemptInput{{Provider: "anthropic", StartedAt: base.Add(20 * time.Millisecond), CompletedAt: base.Add(21 * time.Millisecond)}},
		ProviderStartedAt:   base.Add(10 * time.Millisecond),
		ProviderCompletedAt: base.Add(50 * time.Millisecond),
		TTFTMS:              &requestTTFTMS,
		RequestType:         string(schemas.ChatCompletionStreamRequest),
		StartedAt:           base,
	})
	if len(singleAttempt.ProviderAttempts) != 1 || singleAttempt.ProviderAttempts[0].Provider != "anthropic" || singleAttempt.ProviderAttempts[0].LatencyMS != 1 {
		t.Fatalf("single observed attempt was not preserved: %#v", singleAttempt.ProviderAttempts)
	}
	if got := singleAttempt.Performance.TTFTMS; got == nil || *got != requestTTFTMS {
		t.Fatalf("single observed attempt lost request TTFT: %#v", got)
	}
}

func mustNewRequestEvent(t testing.TB, input EventInput) RequestEvent {
	t.Helper()
	event, err := NewRequestEvent(input)
	if err != nil {
		t.Fatalf("NewRequestEvent returned error: %v", err)
	}
	return event
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
			SchemaVersion:   RequestLogSchemaVersion,
			RequestID:       "request-1",
			UpstreamCostUSD: ZeroChargeUSD,
			BilledCostUSD:   ZeroChargeUSD,
		},
	)

	if captured.RequestID != "request-1" {
		t.Fatalf("request_id = %q, want request-1", captured.RequestID)
	}
	if captured.Error != "null" || captured.AnalyticsErrorCode != "" || captured.AnalyticsErrorStatus != nil {
		t.Fatalf("unexpected error: %#v", captured)
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
	event := RequestEvent{
		SchemaVersion:   RequestLogSchemaVersion,
		RequestID:       "request-1",
		UpstreamCostUSD: ZeroChargeUSD,
		BilledCostUSD:   ZeroChargeUSD,
	}
	payload, err := encodeGatewayRequestEvent(event)
	if err != nil {
		t.Fatalf("encode fallback event: %v", err)
	}
	service.retrySettle(
		&Authorization{RequestID: "request-1"},
		"params",
		ZeroChargeUSD,
		payload,
		true,
	)

	if attempts == 0 {
		t.Fatal("expected settlement retry attempts")
	}
	if captured.RequestID != "request-1" {
		t.Fatalf("fallback request_id = %q, want request-1", captured.RequestID)
	}
	if captured.HoldParamsHash != "params" {
		t.Fatalf("fallback hold_params_hash = %q, want params", captured.HoldParamsHash)
	}
}

func TestEncodeGatewayRequestEventRejectsOversizedPayload(t *testing.T) {
	event := testGatewayRequestEvent()
	event.GatewayVersion = strings.Repeat("v", tinybirdMaxEventBytes)
	if _, err := encodeGatewayRequestEvent(event); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized gateway request event error = %v, want bounded-payload rejection", err)
	}
}

func TestRequestHoldExpiryOutlivesEverySupportedRoute(t *testing.T) {
	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name            string
		requestLifetime time.Duration
		want            time.Time
	}{
		{
			name:            "Chat Completions",
			requestLifetime: GatewayRequestLifetime,
			want:            now.Add(70 * time.Minute),
		},
		{
			name:            "Responses",
			requestLifetime: GatewayRequestLifetime,
			want:            now.Add(70 * time.Minute),
		},
		{
			name: "unspecified route uses the maximum",
			want: now.Add(70 * time.Minute),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestHoldExpiresAt(now, tt.requestLifetime); !got.Equal(tt.want) {
				t.Fatalf("request hold expiry = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestFinalizeRequestSelectsTinybirdFirstSettlementMode(t *testing.T) {
	tests := []struct {
		name             string
		handler          http.HandlerFunc
		tinybird         func(*httptest.Server) *TinybirdClient
		wantOutbox       bool
		wantRequests     int
		skipRequestCount bool
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
			wantOutbox:       true,
			skipRequestCount: true,
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
			if err := service.FinalizeRequest(context.Background(), testAuthorization(), testGatewayRequestEvent(), nil); err != nil {
				t.Fatalf("FinalizeRequest returned error: %v", err)
			}
			if writeOutbox == nil || *writeOutbox != tt.wantOutbox {
				t.Fatalf("writeOutbox = %v, want %t", writeOutbox, tt.wantOutbox)
			}
			if !tt.skipRequestCount && requests != tt.wantRequests {
				t.Fatalf("Tinybird requests = %d, want %d", requests, tt.wantRequests)
			}
		})
	}
}

func TestFinalizeRequestPassesUpstreamCostBasisAndBilledEventToSettlement(t *testing.T) {
	authorization := testAuthorization()
	authorization.UpstreamByok = "0198f4cc-6c25-8000-8000-000000000001"
	event := mustNewRequestEvent(t, EventInput{
		Authorization:   authorization,
		UpstreamCostUSD: "100",
	})
	settlementUpstreamCostUSD := ""
	settlementRequestEventPayload := ""
	service := &Service{
		settleFunc: func(_ context.Context, _ *Authorization, _ string, upstreamCostUSD string, requestEventPayload string, _ bool) error {
			settlementUpstreamCostUSD = upstreamCostUSD
			settlementRequestEventPayload = requestEventPayload
			return nil
		},
	}

	if err := service.FinalizeRequest(context.Background(), authorization, event, nil); err != nil {
		t.Fatalf("FinalizeRequest returned error: %v", err)
	}
	if settlementUpstreamCostUSD != "100" {
		t.Fatalf("settlement upstream cost = %q, want 100", settlementUpstreamCostUSD)
	}
	settlementEvent, err := decodeGatewayRequestEvent(settlementRequestEventPayload)
	if err != nil {
		t.Fatalf("decode settlement request event: %v", err)
	}
	if settlementEvent.UpstreamCostUSD != "100" || settlementEvent.BilledCostUSD != "2" {
		t.Fatalf(
			"settlement event costs = upstream %q, billed %q; want upstream 100, billed 2",
			settlementEvent.UpstreamCostUSD,
			settlementEvent.BilledCostUSD,
		)
	}
}

func TestFinalizeRequestBindsDirectTinybirdEvidenceToTheExactHold(t *testing.T) {
	var captured tinybirdGatewayRequestEventPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode Tinybird request: %v", err)
		}
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	authorization := testAuthorization()
	authorization.UpstreamTargetJSON = `{"model":"gpt-4o-mini"}`
	var settlementPayload string
	service := &Service{
		settleFunc: func(_ context.Context, _ *Authorization, _ string, _ string, payload string, _ bool) error {
			settlementPayload = payload
			return nil
		},
		tinybird: newTestTinybirdClient(t, server.URL),
	}
	defer service.Close()

	if err := service.FinalizeRequest(context.Background(), authorization, testGatewayRequestEvent(), nil); err != nil {
		t.Fatalf("FinalizeRequest returned error: %v", err)
	}
	want := createHoldParamsHash(
		authorization.ProviderKey,
		authorization.ProductKey,
		authorization.UpstreamTargetJSON,
	)
	if captured.HoldParamsHash != want {
		t.Fatalf("hold_params_hash = %q, want %q", captured.HoldParamsHash, want)
	}
	if strings.Contains(settlementPayload, "hold_params_hash") {
		t.Fatal("the private reconciliation hash entered the public outbox payload")
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
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
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
		ZeroChargeUSD,
		`{"request_id":"request-1"}`,
		false,
	)

	if requests.Load() != 0 {
		t.Fatalf("Tinybird rescue requests = %d, want 0 after committed evidence", requests.Load())
	}
}

func TestFinalizeRequestRetriesPostgresAfterTinybirdCommitWithoutDuplicateAppend(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	var attempts atomic.Int32
	settled := make(chan struct{}, 1)
	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       20 * time.Millisecond,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			if attempts.Add(1) == 1 {
				return errors.New("transient postgres failure")
			}
			settled <- struct{}{}
			return nil
		},
		tinybird: newTestTinybirdClient(t, server.URL),
	}
	defer service.Close()

	if err := service.FinalizeRequest(context.Background(), testAuthorization(), testGatewayRequestEvent(), nil); err != nil {
		t.Fatalf("FinalizeRequest returned error: %v", err)
	}
	select {
	case <-settled:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for settlement retry")
	}
	if attempts.Load() < 2 {
		t.Fatalf("settlement attempts = %d, want retry after initial failure", attempts.Load())
	}
	if requests.Load() != 1 {
		t.Fatalf("Tinybird requests = %d, want only initial committed append", requests.Load())
	}
}

func TestFinalizeRequestRetriesTransactionalOutboxAfterTinybirdFailure(t *testing.T) {
	var tinybirdRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tinybirdRequests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	var attempts atomic.Int32
	settled := make(chan bool, 1)
	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       100 * time.Millisecond,
		settleFunc: func(_ context.Context, _ *Authorization, _ string, _ string, _ string, writeOutbox bool) error {
			if attempts.Add(1) == 1 {
				return errors.New("simulated transient postgres failure")
			}
			settled <- writeOutbox
			return nil
		},
		tinybird: newTestTinybirdClient(t, server.URL),
	}
	defer service.Close()

	if err := service.FinalizeRequest(context.Background(), testAuthorization(), testGatewayRequestEvent(), nil); err != nil {
		t.Fatalf("FinalizeRequest returned error: %v", err)
	}
	select {
	case writeOutbox := <-settled:
		if !writeOutbox {
			t.Fatal("Postgres retry lost the required transactional outbox mode")
		}
	case <-time.After(time.Second):
		t.Fatal("Postgres fallback did not recover inside the retry window")
	}
	if got := tinybirdRequests.Load(); got != 1 {
		t.Fatalf("Tinybird requests = %d, want only the initial failed append", got)
	}
}

func TestFinalizeRequestRescuesEvidenceAfterBothInitialSinksFail(t *testing.T) {
	var tinybirdRequests atomic.Int32
	rescued := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if tinybirdRequests.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		rescued <- struct{}{}
		_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
	}))
	defer server.Close()

	tinybird := newTestTinybirdClient(t, server.URL)
	tinybird.circuitOpenDuration = 2 * time.Millisecond
	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       15 * time.Millisecond,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			return errors.New("simulated postgres outage")
		},
		tinybird: tinybird,
	}

	if err := service.FinalizeRequest(context.Background(), testAuthorization(), testGatewayRequestEvent(), nil); err != nil {
		t.Fatalf("FinalizeRequest returned error: %v", err)
	}
	service.Close()
	select {
	case <-rescued:
	case <-time.After(time.Second):
		t.Fatal("final event was not rescued after Tinybird recovered")
	}
	if got := tinybirdRequests.Load(); got != 2 {
		t.Fatalf("Tinybird requests = %d, want one failure and one final rescue", got)
	}
}

func TestFinalizeRequestBoundsMemoryWhenNeitherSinkRecovers(t *testing.T) {
	var tinybirdRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tinybirdRequests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	tinybird := newTestTinybirdClient(t, server.URL)
	tinybird.circuitOpenDuration = time.Hour
	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       5 * time.Millisecond,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			return errors.New("simulated persistent postgres outage")
		},
		tinybird: tinybird,
	}

	if err := service.FinalizeRequest(context.Background(), testAuthorization(), testGatewayRequestEvent(), nil); err != nil {
		t.Fatalf("FinalizeRequest returned error: %v", err)
	}
	service.Close()

	diagnostics := service.Diagnostics()
	if diagnostics.SettlementRetries != 0 || diagnostics.SettlementRetryQueueDepth != 0 {
		t.Fatalf("settlement retry state after exhaustion = %#v, want no retained work", diagnostics)
	}
	if got := tinybirdRequests.Load(); got != 1 {
		t.Fatalf("Tinybird HTTP requests = %d, want one initial attempt while its circuit remains open", got)
	}
	if diagnostics.Tinybird == nil || diagnostics.Tinybird.ShortCircuits == 0 {
		t.Fatalf("Tinybird diagnostics after bounded rescue = %#v, want a short-circuited rescue", diagnostics.Tinybird)
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

	if err := service.FinalizeRequest(context.Background(), testAuthorization(), testGatewayRequestEvent(), nil); err != nil {
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

func TestSettlementRetryQueueRetainsABoundedBurst(t *testing.T) {
	retryStarted := make(chan struct{})
	releaseRetry := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseRetry) })
	}

	var attempts atomic.Int32
	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     time.Millisecond,
		retryWindow:       time.Second,
		retryQueue:        make(chan settlementRetryTask, 1),
		retryWorkerCount:  1,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			if attempts.Add(1) == 1 {
				close(retryStarted)
				<-releaseRetry
			}
			return nil
		},
	}
	defer service.Close()
	defer release()
	var retained atomic.Int64
	var bytesRetained atomic.Int64
	retain := func(bytes int) (func(), bool) {
		if bytes < len(`{}`) || bytes >= tinybirdMaxEventBytes {
			t.Fatalf("unexpected task size: %d", bytes)
		}
		retained.Add(1)
		bytesRetained.Add(int64(bytes))
		return func() { retained.Add(-1); bytesRetained.Add(-int64(bytes)) }, true
	}

	start := func(requestID string) bool {
		authorization := testAuthorization()
		authorization.RequestID = requestID
		return service.startSettleRetry(authorization, "params", ZeroChargeUSD, `{}`, true, retain)
	}
	if !start("request-1") {
		t.Fatal("first settlement retry was not admitted")
	}
	select {
	case <-retryStarted:
	case <-time.After(time.Second):
		t.Fatal("first settlement retry did not start")
	}
	if !start("request-2") {
		t.Fatal("queued settlement retry was not admitted")
	}
	if start("request-3") {
		t.Fatal("settlement retry beyond the configured queue bound was admitted")
	}
	if retained.Load() != 2 || bytesRetained.Load() <= 0 {
		t.Fatal("queue rejection leaked a retained task or released active work")
	}
	diagnostics := service.Diagnostics()
	if diagnostics.SettlementRetries != 1 || diagnostics.SettlementRetryQueueDepth != 1 || diagnostics.SettlementRetryQueueCapacity != 1 {
		t.Fatalf("settlement retry diagnostics = %#v", diagnostics)
	}
	if diagnostics.SettlementRetryDeferrals != 1 {
		t.Fatalf("settlement retry deferrals = %d, want 1", diagnostics.SettlementRetryDeferrals)
	}
	if diagnostics.SettlementRetryLastDeferredAt == nil || time.Since(*diagnostics.SettlementRetryLastDeferredAt) > time.Second {
		t.Fatalf("settlement retry last deferred time = %v, want a current timestamp", diagnostics.SettlementRetryLastDeferredAt)
	}
	release()
	service.Close()
	if retained.Load() != 0 || bytesRetained.Load() != 0 {
		t.Fatal("retry completion leaked memory ownership")
	}
	if start("closed") || retained.Load() != 0 || bytesRetained.Load() != 0 {
		t.Fatal("closed service retained retry memory")
	}
}

func TestFinalizeRequestAtRetryCapacityKeepsOnlyDurableEvidence(t *testing.T) {
	for _, test := range []struct {
		name           string
		tinybirdStatus int
		wantCircuitHit bool
	}{
		{name: "Tinybird already committed", tinybirdStatus: http.StatusOK},
		{name: "neither sink acknowledged", tinybirdStatus: http.StatusServiceUnavailable, wantCircuitHit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var tinybirdRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tinybirdRequests.Add(1)
				w.WriteHeader(test.tinybirdStatus)
				if test.tinybirdStatus == http.StatusOK {
					_, _ = w.Write([]byte(`{"successful_rows":1,"quarantined_rows":0}`))
				}
			}))
			defer server.Close()

			retryStarted := make(chan struct{})
			releaseRetry := make(chan struct{})
			var startOnce sync.Once
			var releaseOnce sync.Once
			release := func() {
				releaseOnce.Do(func() { close(releaseRetry) })
			}
			service := &Service{
				retryInitialDelay: time.Millisecond,
				retryMaxDelay:     time.Millisecond,
				retryWindow:       time.Second,
				retryQueue:        make(chan settlementRetryTask, 1),
				retryWorkerCount:  1,
				settleFunc: func(_ context.Context, authorization *Authorization, _ string, _ string, _ string, _ bool) error {
					switch authorization.RequestID {
					case "active-retry":
						startOnce.Do(func() { close(retryStarted) })
						<-releaseRetry
						return nil
					case "queued-retry":
						return nil
					default:
						return errors.New("simulated postgres outage")
					}
				},
				tinybird: newTestTinybirdClient(t, server.URL),
			}
			defer func() {
				release()
				service.Close()
			}()

			for _, requestID := range []string{"active-retry", "queued-retry"} {
				authorization := testAuthorization()
				authorization.RequestID = requestID
				if !service.startSettleRetry(authorization, "params", ZeroChargeUSD, `{}`, false, nil) {
					t.Fatalf("failed to admit %s", requestID)
				}
				if requestID == "active-retry" {
					select {
					case <-retryStarted:
					case <-time.After(time.Second):
						t.Fatal("active retry did not start")
					}
				}
			}

			authorization := testAuthorization()
			authorization.RequestID = "capacity-request"
			event := testGatewayRequestEvent()
			event.RequestID = authorization.RequestID
			if err := service.FinalizeRequest(context.Background(), authorization, event, nil); err != nil {
				t.Fatalf("FinalizeRequest returned error: %v", err)
			}
			diagnostics := service.Diagnostics()
			if diagnostics.SettlementRetryDeferrals != 1 || diagnostics.SettlementRetryQueueDepth != 1 {
				t.Fatalf("retry capacity diagnostics = %#v", diagnostics)
			}
			if got := tinybirdRequests.Load(); got != 1 {
				t.Fatalf("Tinybird HTTP requests = %d, want one bounded append", got)
			}
			if got := service.tinybird.Diagnostics().ShortCircuits > 0; got != test.wantCircuitHit {
				t.Fatalf("Tinybird circuit rescue hit = %t, want %t", got, test.wantCircuitHit)
			}

			release()
			service.Close()
		})
	}
}

func TestSettlementRetryQueueWaitsThroughDatabaseFailover(t *testing.T) {
	const requests = 12
	var databaseAvailable atomic.Bool
	var settled atomic.Int32
	databaseAttempted := make(chan struct{})
	var databaseAttemptedOnce sync.Once
	service := &Service{
		retryInitialDelay: time.Millisecond,
		retryMaxDelay:     5 * time.Millisecond,
		retryWindow:       250 * time.Millisecond,
		retryQueue:        make(chan settlementRetryTask, requests),
		retryWorkerCount:  2,
		settleFunc: func(context.Context, *Authorization, string, string, string, bool) error {
			if !databaseAvailable.Load() {
				databaseAttemptedOnce.Do(func() { close(databaseAttempted) })
				return errors.New("simulated postgres failover")
			}
			settled.Add(1)
			return nil
		},
	}
	defer service.Close()

	for index := range requests {
		authorization := testAuthorization()
		authorization.RequestID = fmt.Sprintf("request-%d", index)
		if !service.startSettleRetry(authorization, "params", ZeroChargeUSD, `{}`, true, nil) {
			t.Fatalf("settlement retry %d was not admitted", index)
		}
	}
	select {
	case <-databaseAttempted:
	case <-time.After(time.Second):
		t.Fatal("settlement retry did not reach the unavailable database")
	}
	databaseAvailable.Store(true)

	deadline := time.Now().Add(time.Second)
	for settled.Load() != requests && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if settled.Load() != requests {
		t.Fatalf("settled requests = %d, want %d after database recovery", settled.Load(), requests)
	}
	if diagnostics := service.Diagnostics(); diagnostics.SettlementRetryDeferrals != 0 || diagnostics.SettlementRetryQueueDepth != 0 {
		t.Fatalf("settlement retry diagnostics after recovery = %#v", diagnostics)
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
		ZeroChargeUSD,
		`{"request_id":"request-1"}`,
		true,
	)

	if requests != 0 {
		t.Fatalf("Tinybird rescue requests = %d, want 0 for permanent settlement rejection", requests)
	}
}

func testAuthorization() *Authorization {
	return &Authorization{
		AuthorizedBilledCostUSD: mustUSD(ZeroChargeUSD),
		AvailableBalanceUSD:     mustUSD("100000000000"),
		KeyID:                   "key-1",
		ProductKey:              "gpt-4o-mini",
		ProviderKey:             "openai",
		RequestID:               "request-1",
		UpstreamByok:            "stogas",
		UserID:                  "user-1",
	}
}

func testGatewayRequestEvent() RequestEvent {
	return RequestEvent{
		SchemaVersion:   RequestLogSchemaVersion,
		CreatedAt:       time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		RequestID:       "request-1",
		StogasAPIKeyID:  "key-1",
		UpstreamCostUSD: ZeroChargeUSD,
		BilledCostUSD:   ZeroChargeUSD,
	}
}

func mustUSD(value string) *money.USD {
	parsed, err := money.Parse(value)
	if err != nil {
		panic("invalid big int test fixture")
	}
	return parsed
}

func mustUSDTest(t *testing.T, value string) *money.USD {
	t.Helper()
	parsed, err := money.Parse(value)
	if err != nil {
		t.Fatalf("invalid big int %q", value)
	}
	return parsed
}

func TestMetersDistinguishFreeUnpricedAndAggregateCounts(t *testing.T) {
	for name, meter := range map[string]EventMeter{
		"free":       PricedMeter("300", RatePerMillionTokens, "0", "0"),
		"unpriced":   {Quantity: "300"},
		"known zero": {Quantity: "0"},
	} {
		if _, _, err := ValidateMeters(EventMeters{MeterCachedInputTokens: meter}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	rate := "0"
	for name, meters := range map[string]EventMeters{
		"incomplete":        {MeterCachedInputTokens: {Quantity: "300", USD: &rate}},
		"priced aggregate":  {MeterTotalTokens: PricedMeter("300", RatePerMillionTokens, "1", "0.0003")},
		"priced estimate":   {MeterEstimatedInputTokens: PricedMeter("300", RatePerMillionTokens, "1", "0.0003")},
		"priced text bytes": {MeterInputTextBytes: PricedMeter("300", RatePerMillionTokens, "1", "0.0003")},
		"negative":          {MeterTotalTokens: {Quantity: "-1"}},
		"overflow":          {MeterTotalTokens: {Quantity: "18446744073709551616"}},
	} {
		if _, _, err := ValidateMeters(meters); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}
