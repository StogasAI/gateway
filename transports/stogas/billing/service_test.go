package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/maximhq/bifrost/transports/stogas/money"
	"net/http"
	"net/http/httptest"
	"strings"
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
	pricing, ok := decoded["usage"].(map[string]any)["meters"].(map[string]any)
	if !ok || len(pricing) != 0 {
		t.Fatalf("pricing = %#v, want empty object", decoded["usage"].(map[string]any)["meters"])
	}
}

func TestRequestLogRejectsUnsupportedSchemaVersions(t *testing.T) {
	for _, version := range []uint8{0, 2} {
		event := testGatewayRequestEvent()
		event.SchemaVersion = version
		if _, err := encodeGatewayRequestEvent(event); err == nil {
			t.Fatalf("encoded unsupported version %d", version)
		}
		client := &RequestLogClient{}
		if _, err := client.enqueueGatewayRequest(event); err == nil {
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
	event.ProviderAttempts = []ProviderAttempt{{CatalogChainHash: optionalString("sha256:" + strings.Repeat("b", 64))}}
	overhead := "29"
	event.Usage.CacheWriteOverheadUSD = &overhead
	event.Usage.Meters = EventMeters{
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
	if projected.CatalogVersion == nil || *projected.CatalogVersion != 39 || projected.AnalyticsCatalogChainHash == nil || *projected.AnalyticsCatalogChainHash != *event.ProviderAttempts[0].CatalogChainHash {
		t.Fatalf("request log projection lost the historical catalog identity: %#v", projected)
	}
	if projected.SchemaVersion != RequestLogSchemaVersion || projected.RequestID != event.RequestID ||
		projected.AnalyticsInputTokens == nil || *projected.AnalyticsInputTokens != 317 ||
		projected.AnalyticsCachedInputTokens != 300 ||
		projected.CacheWriteOverheadUSD == nil ||
		*projected.CacheWriteOverheadUSD != overhead {
		t.Fatalf("decoded Tinybird projection = %#v", projected)
	}

	if _, err := decodeGatewayRequestEvent(`{"schema_version":1,"usage":{"meters":{"input_tokens":{"quantity":"invalid","rateKey":"per_mill_tokens","rateUsd":"1","usd":"1"}}}}`); err == nil {
		t.Fatal("decodeGatewayRequestEvent accepted invalid canonical pricing")
	}
	if _, err := decodeGatewayRequestEvent(`{"schema_version":1,"usage":{"cache_read_savings_usd":"-1","meters":{}}}`); err == nil {
		t.Fatal("decodeGatewayRequestEvent accepted invalid cache read savings")
	}
	if _, err := decodeGatewayRequestEvent(`{"schema_version":1,"usage":{"cache_write_overhead_usd":"-1","meters":{}}}`); err == nil {
		t.Fatal("decodeGatewayRequestEvent accepted invalid cache write overhead")
	}
}

func TestTinybirdGatewayRequestEventStringifiesNestedPayload(t *testing.T) {
	failedStatus := 502
	successStatus := 200
	ttftMS := uint32(150)
	event := tinybirdGatewayRequestEvent(RequestEvent{
		SchemaVersion: RequestLogSchemaVersion,

		Performance: RequestPerformance{TotalMS: 150, ProviderMS: 140, TTFTMS: &ttftMS},

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
			LatencyMS:  30,
			Provider:   "openai",
			Status:     "connection_error",
			StatusCode: &failedStatus,
			Byok:       nil,
		}, {
			LatencyMS:         90,
			Provider:          "anthropic",
			ProviderRequestID: "provider-request",
			FinishReason:      "stop",
			Status:            "success",
			StatusCode:        &successStatus,
			Byok:              nil,
		}},
		GatewayVersion: "v1.5.13", Usage: RequestUsage{CacheWriteOverheadUSD: stringPtr("23"),

			Meters: EventMeters{
				"input_tokens":                PricedMeter("12", "per_mill_tokens", "1", "1"),
				"total_input_tokens":          {Quantity: "19"},
				"total_cache_write_tokens":    {Quantity: "7"},
				"cache_write_input_tokens":    {Quantity: "1"},
				"cache_write_5m_input_tokens": {Quantity: "2"},
				"cache_write_1h_input_tokens": {Quantity: "4"},
			}},
	})

	if event.GatewayError != "null" || event.AnalyticsErrorCode != "" || event.AnalyticsErrorStatus != nil {
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
	var usage RequestUsage
	if err := json.Unmarshal([]byte(event.Usage), &usage); err != nil || usage.Meters["input_tokens"].Quantity != "12" {
		t.Fatalf("pricing = %q, err=%v", event.Usage, err)
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

	if *event.Usage.Meters["input_tokens"].RateUSD != "2000000" {
		t.Fatalf("expected settled pricing audit, got %#v", event.Usage.Meters)
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
			if event.Usage.BilledCostUSD != tc.wantBilledCost ||
				event.Usage.CacheReadSavingsUSD == nil || *event.Usage.CacheReadSavingsUSD != "90" {
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
	if event.Performance.ProviderStartMS == nil || *event.Performance.ProviderStartMS != 40 {
		t.Fatalf("provider start must share the request clock: %#v", event.Performance)
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
	if event.Performance.ProviderStartMS != nil {
		t.Fatalf("a request never dispatched must not have a provider start: %#v", event.Performance)
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

func TestEncodeGatewayRequestEventRejectsOversizedPayload(t *testing.T) {
	event := testGatewayRequestEvent()
	event.GatewayVersion = strings.Repeat("v", requestLogMaxEventBytes)
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
			want:            now.Add(80 * time.Minute),
		},
		{
			name:            "Responses",
			requestLifetime: GatewayRequestLifetime,
			want:            now.Add(80 * time.Minute),
		},
		{
			name: "unspecified route uses the maximum",
			want: now.Add(80 * time.Minute),
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
			errContain: "did not commit every request log row",
		},
		{
			name:       "missing acknowledgement",
			status:     http.StatusOK,
			body:       `{}`,
			wantErr:    true,
			errContain: "did not commit every request log row",
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

			_, err := newTestRequestLogClient(t, server.URL).AppendGatewayRequest(context.Background(), testGatewayRequestEvent())
			if (err != nil) != tt.wantErr {
				t.Fatalf("AppendGatewayRequest error = %v, wantErr=%t", err, tt.wantErr)
			}
			if err != nil && tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
				t.Fatalf("AppendGatewayRequest error = %q, want to contain %q", err, tt.errContain)
			}
		})
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
		SchemaVersion:  RequestLogSchemaVersion,
		CreatedAt:      time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		RequestID:      "request-1",
		StogasAPIKeyID: "key-1", Usage: RequestUsage{UpstreamCostUSD: ZeroChargeUSD,
			BilledCostUSD: ZeroChargeUSD},
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
		"incomplete":             {MeterCachedInputTokens: {Quantity: "300", USD: &rate}},
		"priced aggregate":       {MeterTotalTokens: PricedMeter("300", RatePerMillionTokens, "1", "0.0003")},
		"priced estimate":        {MeterEstimatedInputTokens: PricedMeter("300", RatePerMillionTokens, "1", "0.0003")},
		"priced files":           {MeterInputFileCount: PricedMeter("1", RatePerMillionTokens, "1", "0.000001")},
		"priced file URLs":       {MeterInputFileURLCount: PricedMeter("1", RatePerMillionTokens, "1", "0.000001")},
		"priced inline files":    {MeterInputInlineFileBytes: PricedMeter("1", RatePerMillionTokens, "1", "0.000001")},
		"priced text bytes":      {MeterInputTextBytes: PricedMeter("300", RatePerMillionTokens, "1", "0.0003")},
		"priced output bytes":    {MeterOutputTextBytes: PricedMeter("300", RatePerMillionTokens, "1", "0.0003")},
		"priced reasoning bytes": {MeterReasoningTextBytes: PricedMeter("300", RatePerMillionTokens, "1", "0.0003")},
		"negative":               {MeterTotalTokens: {Quantity: "-1"}},
		"overflow":               {MeterTotalTokens: {Quantity: "18446744073709551616"}},
	} {
		if _, _, err := ValidateMeters(meters); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}

func TestRequestUsagePreservesExactStandardTextAndPluginPresence(t *testing.T) {
	for _, item := range []struct{ bytes, tokens string }{{"0", "0"}, {"6", "1.5"}, {"7", "1.75"}, {"18446744073709551615", "4611686018427387903.75"}} {
		event, err := NewRequestEvent(EventInput{Meters: EventMeters{MeterInputTextBytes: {Quantity: item.bytes}, MeterOutputTextBytes: {Quantity: "0"}}, CacheReadSavingsUSD: stringPtr("0")})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := encodeGatewayRequestEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal([]byte(payload), &wire); err != nil {
			t.Fatal(err)
		}
		if wire["plugins"] != nil || wire["meters"] != nil || wire["catalog_chain_hash"] != nil || wire["error"] != nil {
			t.Fatal("request log contains empty plugins or obsolete root fields")
		}
		var usage map[string]json.RawMessage
		if err := json.Unmarshal(wire["usage"], &usage); err != nil {
			t.Fatal(err)
		}
		if usage["cache_write_overhead_usd"] != nil || string(usage["cache_read_savings_usd"]) != `"0"` {
			t.Fatal("cache costs did not distinguish unknown from measured zero")
		}
		var standardText map[string]string
		if err := json.Unmarshal(usage["standard_text_tokens"], &standardText); err != nil {
			t.Fatal(err)
		}
		if _, present := standardText["reasoning"]; present || standardText["output"] != "0" || standardText["input"] != item.tokens {
			t.Fatalf("standard text JSON contains an unmeasured value or lost measured zero: %s", usage["standard_text_tokens"])
		}
		restored, err := decodeGatewayRequestEvent(payload)
		if err != nil {
			t.Fatal(err)
		}
		stt := restored.Usage.StandardTextTokens
		if stt.Input == nil || *stt.Input != item.tokens || stt.Output == nil || *stt.Output != "0" || stt.Reasoning != nil {
			t.Fatalf("standard text units changed presence or precision: %#v", stt)
		}
		restored.Usage.StandardTextTokens.Input = stringPtr("1.25")
		invalid, _ := encodeGatewayRequestEvent(restored)
		if _, err := decodeGatewayRequestEvent(invalid); err == nil {
			t.Fatal("inconsistent standard text units accepted")
		}
	}
	event := testGatewayRequestEvent()
	event.Plugins = plugins.Metrics{StogasStructuredPIIRedaction: &plugins.StogasStructuredPIIRedactionMetrics{}, StogasExport: &plugins.StogasExportMetrics{}}
	payload, err := encodeGatewayRequestEvent(event)
	if err != nil || !strings.Contains(payload, `"plugins":{"stogas_structured_pii_redaction":{"items_redacted":0,"duration_us":0},"stogas_export":{"capture_us":0}}`) {
		t.Fatalf("configured plugins with measured zero disappeared: %s, %v", payload, err)
	}
}
