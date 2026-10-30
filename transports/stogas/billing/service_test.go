package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/money"
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

// Control and the monitor compute the same fingerprints; these vectors appear
// in their tests too.
func TestAPIKeyPepperFingerprint(t *testing.T) {
	for pepper, want := range map[string]string{
		"test-pepper-0123456789abcdef0123456789":  "a0c5e3f1e838e326",
		"another-pepper-0123456789abcdef01234567": "4093c9c8af3c8bf1",
	} {
		if got := apiKeyPepperFingerprint(pepper); got != want {
			t.Fatalf("fingerprint of %q = %s, want %s", pepper, got, want)
		}
	}
	service := &Service{apiKeyPepperFingerprint: apiKeyPepperFingerprint("test-pepper-0123456789abcdef0123456789")}
	if got := service.Diagnostics().APIKeyPepperFingerprint; got != "a0c5e3f1e838e326" {
		t.Fatalf("diagnostics fingerprint = %q", got)
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
	rawKey = resignTestAPIKey(t, secret, rawKey, func(payload []byte) { clear(payload[68:84]) })

	if _, err := parseSignedAPIKey(rawKey, secret); err == nil {
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
	return signTestAPIKeyPayload(secret, payload)
}

// resignTestAPIKey changes a signed key's payload and signs it again.
func resignTestAPIKey(t testing.TB, secret string, rawKey string, change func(payload []byte)) string {
	t.Helper()
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rawKey, apiKeyPrefix))
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	payload := body[:apiKeyPayloadBytes:apiKeyPayloadBytes]
	change(payload)
	return signTestAPIKeyPayload(secret, payload)
}

func signTestAPIKeyPayload(secret string, payload []byte) string {
	hasher := hmac.New(sha256.New, []byte(secret))
	_, _ = hasher.Write(payload)
	return apiKeyPrefix + base64.RawURLEncoding.EncodeToString(append(payload, hasher.Sum(nil)[:apiKeyMACBytes]...))
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

func TestEncodeRequestLogDefaultsPricing(t *testing.T) {
	payload, err := encodeRequestLog(RequestEvent{SchemaVersion: RequestLogSchemaVersion, RequestID: "request"}, "")
	if err != nil {
		t.Fatalf("encodeRequestLog returned error: %v", err)
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
		t.Fatal("a rejection has no hold binding")
	}
	pricing, ok := decoded["usage"].(map[string]any)["meters"].(map[string]any)
	if !ok || len(pricing) != 0 {
		t.Fatalf("pricing = %#v, want empty object", decoded["usage"].(map[string]any)["meters"])
	}
}

// Settlement checks the hold binding and removes it before storing the log.
func TestEncodeRequestLogCarriesTheHoldBinding(t *testing.T) {
	hash := strings.Repeat("a", 64)
	payload, err := encodeRequestLog(testGatewayRequestEvent(), hash)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &wire); err != nil {
		t.Fatal(err)
	}
	if string(wire["hold_params_hash"]) != `"`+hash+`"` || string(wire["request_id"]) != `"request-1"` {
		t.Fatalf("settlement log lost its hold binding or event fields: %s", payload)
	}
}

func TestRequestLogRejectsUnsupportedSchemaVersions(t *testing.T) {
	for _, version := range []uint8{0, 2} {
		event := testGatewayRequestEvent()
		event.SchemaVersion = version
		if _, err := encodeRequestLog(event, ""); err == nil {
			t.Fatalf("encoded unsupported version %d", version)
		}
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
		Plugins:           plugins.Metrics{Redaction: &plugins.RedactionMetrics{ItemsRedacted: 2, DurationUS: 17}},
		ProviderAttempts:  []ProviderAttemptInput{{Provider: "openai", StartedAt: startedAt}},
		ProviderStartedAt: startedAt,
		StartedAt:         startedAt,
	})

	if *event.Usage.Meters["input_tokens"].RateUSD != "2000000" {
		t.Fatalf("expected settled pricing audit, got %#v", event.Usage.Meters)
	}
	if event.Performance.TTFTMS == nil || *event.Performance.TTFTMS != ttftMS {
		t.Fatalf("expected request TTFT, got %#v", event.Performance.TTFTMS)
	}
	if event.GrantID == nil || *event.GrantID != grantID {
		t.Fatalf("expected grant attribution, got %#v", event.GrantID)
	}
	if event.Plugins.Redaction == nil ||
		event.Plugins.Redaction.ItemsRedacted != 2 ||
		event.Plugins.Redaction.DurationUS != 17 {
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

func TestParseTaxRateAcceptsOnlyWhatAuthorizationReturns(t *testing.T) {
	for value, want := range map[string]int64{
		"0": 0, "0.0635": 6_350_000, "0.08875": 8_875_000, "0.00000001": 1, "0.99999999": 99_999_999,
	} {
		if got, err := parseTaxRate(&value); err != nil || got != want {
			t.Fatalf("parseTaxRate(%q) = %d, %v; want %d", value, got, err, want)
		}
	}
	if _, err := parseTaxRate(nil); err == nil {
		t.Fatal("parseTaxRate accepted a missing rate")
	}
	for _, value := range []string{"", "0.", "0.0", "0.10", "1", "1.5", "-0.1", "0.123456789", "0.1e2", " 0.1", "0x1", ".5"} {
		if _, err := parseTaxRate(&value); err == nil {
			t.Fatalf("parseTaxRate accepted %q", value)
		}
	}
}

// Settlement refuses a log whose tax differs from ceil(billed × rate) at 36
// decimal places.
func TestTaxRoundsUpOnceAsSettlementDoes(t *testing.T) {
	for _, tc := range []struct {
		name, billed, rate, want string
	}{
		{name: "no rate", billed: "12.5", rate: "0", want: "0"},
		{name: "no charge", billed: "0", rate: "0.0635", want: "0"},
		{name: "exact", billed: "0.000123", rate: "0.0635", want: "0.0000078105"},
		{name: "several jurisdictions", billed: "100", rate: "0.08875", want: "8.875"},
		{name: "rounds up", billed: "0.000000000000000000000000000000000001", rate: "0.01", want: "0.000000000000000000000000000000000001"},
		{name: "largest rate", billed: "3", rate: "0.99999999", want: "2.99999997"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rate, err := parseTaxRate(&tc.rate)
			if err != nil {
				t.Fatal(err)
			}
			if got := calculateTaxUSD(&Authorization{taxRate: rate}, mustUSDTest(t, tc.billed)).String(); got != tc.want {
				t.Fatalf("tax on %s at %s = %s, want %s", tc.billed, tc.rate, got, tc.want)
			}
		})
	}
}

func TestNewRequestEventChargesTaxOnTheBilledCostAndNamesTheRate(t *testing.T) {
	startedAt := time.Now().Add(-25 * time.Millisecond)
	rateID := "0198f4cc-6c25-8000-8000-0000000000aa"
	event := mustNewRequestEvent(t, EventInput{
		Authorization: &Authorization{
			AuthorizedBilledCostUSD: mustUSD("10"), RequestID: "request-1",
			UpstreamByok: "0198f4cc-6c25-8000-8000-000000000001", taxRate: 6_350_000,
			taxRateText: "0.0635", taxRateID: &rateID,
		},
		RequestType:       string(schemas.ChatCompletionRequest),
		UpstreamCostUSD:   "100",
		Meters:            EventMeters{"input_tokens": PricedMeter("1", "per_mill_tokens", "100000000", "100")},
		ProviderAttempts:  []ProviderAttemptInput{{Provider: "openai", StartedAt: startedAt}},
		ProviderStartedAt: startedAt,
		StartedAt:         startedAt,
	})
	// A BYOK request bills 2% of the provider's cost, and the tax is on that.
	if event.Usage.BilledCostUSD != "2" || event.Usage.TaxUSD != "0.127" {
		t.Fatalf("billed %s with tax %s, want 2 with tax 0.127", event.Usage.BilledCostUSD, event.Usage.TaxUSD)
	}
	// The log names the rate and its row, which says where the tax is owed.
	if event.Usage.TaxRate != "0.0635" || event.Usage.TaxRateID == nil || *event.Usage.TaxRateID != rateID {
		t.Fatalf("tax rate %s with row %v, want 0.0635 with %s", event.Usage.TaxRate, event.Usage.TaxRateID, rateID)
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
		ProviderAttempts:    []ProviderAttemptInput{{Provider: "openai", StartedAt: providerStartedAt, CompletedAt: providerCompletedAt}},
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
	if providerTime < 35 || providerTime > 45 || event.ProviderAttempts[0].StartMS != 40 {
		t.Fatalf("provider attempt should use the request clock, got %#v", event.ProviderAttempts[0])
	}
	if event.ClientStopMS == nil || *event.ClientStopMS < 40 || *event.ClientStopMS > 50 {
		t.Fatalf("client stop time should use the request clock, got %#v", event.ClientStopMS)
	}
	if event.Performance.ProviderMS < 35 || event.Performance.ProviderMS > 45 ||
		event.Performance.ProviderMS > event.Performance.TotalMS {
		t.Fatalf("provider duration exceeds the request clock: %#v", event)
	}

	event = mustNewRequestEvent(t, EventInput{
		Authorization: &Authorization{RequestID: "request-2"},
		Meters:        EventMeters{"input_text_bytes": {Quantity: "12"}},
		StartedAt:     startedAt,
	})
	if len(event.ProviderAttempts) != 0 {
		t.Fatalf("a request that never started a provider has attempts: %#v", event.ProviderAttempts)
	}
	if len(event.Usage.Meters) != 0 || event.Usage.StandardTextTokens != (StandardTextTokens{}) {
		t.Fatalf("a request that never started a provider has usage: %#v", event.Usage)
	}
	if event.Performance.ProviderMS != 0 {
		t.Fatalf("a request never dispatched must not record provider time: %#v", event.Performance)
	}
	if event.Performance.ProviderStartMS != nil {
		t.Fatalf("a request never dispatched must not have a provider start: %#v", event.Performance)
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
				Byok:        ManagedUpstreamByok,
				StartedAt:   base.Add(10 * time.Millisecond),
				CompletedAt: base.Add(40 * time.Millisecond),
				Error: &schemas.BifrostError{
					StatusCode: &statusCode,
					Error:      &schemas.ErrorField{Message: "upstream unavailable"},
				},
			},
			{
				Provider:    "anthropic",
				Byok:        "0198f4cc-6c25-8000-8000-000000000001",
				StartedAt:   base.Add(55 * time.Millisecond),
				CompletedAt: base.Add(145 * time.Millisecond),
				Response:    response,
			},
		},
		ProviderStartedAt:   base.Add(5 * time.Millisecond),
		ProviderCompletedAt: base.Add(150 * time.Millisecond),
		RequestType:         string(schemas.ChatCompletionStreamRequest),
		StartedAt:           base,
		TTFTMS:              &ttftMS,
	})

	if len(event.ProviderAttempts) != 2 {
		t.Fatalf("provider attempts = %#v, want two attempts", event.ProviderAttempts)
	}
	if event.ProviderAttempts[0].StartMS != 10 || event.ProviderAttempts[0].LatencyMS != 30 ||
		event.ProviderAttempts[1].StartMS != 55 || event.ProviderAttempts[1].LatencyMS != 90 {
		t.Fatalf("provider attempt timings = %#v", event.ProviderAttempts)
	}
	if event.ProviderAttempts[0].Byok != nil || event.ProviderAttempts[1].Byok == nil ||
		*event.ProviderAttempts[1].Byok != "0198f4cc-6c25-8000-8000-000000000001" {
		t.Fatalf("provider attempt credentials = %#v", event.ProviderAttempts)
	}
	if event.ProviderAttempts[0].Status != "provider_error" || event.ProviderAttempts[1].Status != "success" {
		t.Fatalf("provider attempt statuses = %#v", event.ProviderAttempts)
	}
	if event.Performance.ProviderMS != 145 {
		t.Fatalf("provider duration = %d, want 145", event.Performance.ProviderMS)
	}
	if event.Performance.TTFTMS == nil || *event.Performance.TTFTMS != ttftMS {
		t.Fatalf("TTFT = %#v, want %d", event.Performance.TTFTMS, ttftMS)
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

func TestEncodeRequestLogRejectsOversizedPayload(t *testing.T) {
	event := testGatewayRequestEvent()
	event.GatewayVersion = strings.Repeat("v", requestLogMaxEventBytes)
	if _, err := encodeRequestLog(event, ""); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized gateway request event error = %v, want bounded-payload rejection", err)
	}
}

// A log that does not fit makes the gateway refuse new requests, so the
// largest log that clients and providers can cause must fit. Their strings are
// quotes, which JSON writes as two bytes each. A request records fewer than 25
// meters with today's catalog.
func TestLargestRequestLogFitsTheLimit(t *testing.T) {
	quotes := func(n int) string { return strings.Repeat(`"`, n) }
	setting, usd, count := quotes(maxSettingBytes), "9"+strings.Repeat("9", money.Precision-money.Scale-1)+"."+strings.Repeat("9", money.Scale), uint32(1<<32-1)
	integer, number, flag := maxExactJSONInteger, -1.2345678901234567e-300, true
	include := make([]string, maxSettingValues)
	for i := range include {
		include[i] = setting
	}
	event := RequestEvent{
		SchemaVersion: RequestLogSchemaVersion, RequestID: uuid.NewString(), CreatedAt: "2026-10-16T12:00:00.000Z", LastRequestAt: "2026-10-16T12:00:00.000Z",
		RequestCount: 1, GatewayError: &EventError{Code: "upstream_configuration_error", Status: 599}, APIKeyID: uuid.NewString(),
		GrantID: new(uuid.NewString()), MemberID: uuid.NewString(), OrganizationID: uuid.NewString(), RequestType: "chat_completion_stream",
		RequestSettings: RequestSettings{
			MaxOutputTokens: &integer, ReasoningEnabled: &flag, ReasoningEffort: setting, ReasoningMaxTokens: &integer, ReasoningSummary: setting,
			ReasoningDisplay: setting, TaskBudgetTokens: &integer, Temperature: &number, TopP: &number, TopK: &integer, FrequencyPenalty: &number,
			PresencePenalty: &number, RepetitionPenalty: &number, Seed: &integer, Logprobs: &flag, TopLogprobs: &integer, Verbosity: setting,
			ResponseFormat: setting, Include: include, ToolChoice: setting, ParallelToolCalls: &flag, MaxToolCalls: &integer, Truncation: setting,
		},
		SessionID: quotes(MaxSessionIDBytes), Metadata: map[string]string{}, Transport: TransportAttestedTLS, Cancelled: true, ClientStopMS: &count, CatalogVersion: new(uint64(1<<64 - 1)),
		PolicyVersions: &PolicyVersions{}, NodeID: strings.Repeat("f", 64), GatewayVersion: "v" + strings.Repeat("9", 31),
		Performance: RequestPerformance{TotalMS: count, ProviderMS: count, ProviderStartMS: &count, FirstOutputMS: &count, TTFTMS: &count},
		Usage: RequestUsage{UpstreamCostUSD: usd, BilledCostUSD: usd, CacheReadSavingsUSD: &usd, CacheWriteOverheadUSD: &usd, Meters: EventMeters{},
			StandardTextTokens: StandardTextTokens{Input: &usd, Reasoning: &usd, Output: &usd}},
		Plugins: plugins.Metrics{Redaction: &plugins.RedactionMetrics{ItemsRedacted: count, DurationUS: count},
			Export: &plugins.ExportMetrics{DurationUS: count}},
	}
	for i := range MaxMetadataEntries {
		event.Metadata[quotes(MaxMetadataKeyBytes-2)+fmt.Sprintf("%02d", i)] = quotes(MaxMetadataValueBytes)
	}
	for range 36 {
		*event.PolicyVersions = append(*event.PolicyVersions, PolicyVersion{Scope: "credential", ID: uuid.NewString(), Revision: 1<<31 - 1})
	}
	for range 12 {
		status := 599
		event.ProviderAttempts = append(event.ProviderAttempts, ProviderAttempt{
			CatalogChainHash: "sha256:" + strings.Repeat("f", 64), ResolvedCatalogChainHash: "sha256:" + strings.Repeat("e", 64),
			Provider: quotes(maxProviderNameBytes), Status: "context_length_exceeded", StatusCode: &status, StartMS: count, LatencyMS: count,
			OutputObserved: true, ProviderRequestID: quotes(maxProviderRequestIDBytes), FinishReason: quotes(maxProviderReasonBytes), Byok: new(uuid.NewString()),
		})
	}
	for i := range 40 {
		rate := strings.Repeat("r", 64)
		event.Usage.Meters[fmt.Sprintf("%064d", i)] = EventMeter{Quantity: "18446744073709551615", RateKey: &rate, RateUSD: &usd, USD: &usd}
	}
	payload, err := encodeRequestLog(event, strings.Repeat("h", 64))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("largest request log: %d of %d bytes", len(payload), requestLogMaxEventBytes)
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

func testAuthorization() *Authorization {
	return &Authorization{
		AuthorizedBilledCostUSD: mustUSD(ZeroChargeUSD),
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
		SchemaVersion: RequestLogSchemaVersion,
		CreatedAt:     time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		RequestID:     "request-1",
		APIKeyID:      "key-1", Usage: RequestUsage{UpstreamCostUSD: ZeroChargeUSD,
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
		if _, err := ValidateMeters(EventMeters{MeterCachedInputTokens: meter}); err != nil {
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
		if _, err := ValidateMeters(meters); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}

func TestRequestUsagePreservesExactStandardTextAndPluginPresence(t *testing.T) {
	for _, item := range []struct{ bytes, tokens string }{{"0", "0"}, {"6", "1.5"}, {"7", "1.75"}, {"18446744073709551615", "4611686018427387903.75"}} {
		event, err := NewRequestEvent(EventInput{Meters: EventMeters{MeterInputTextBytes: {Quantity: item.bytes}, MeterOutputTextBytes: {Quantity: "0"}}, CacheReadSavingsUSD: stringPtr("0"), ProviderAttempts: []ProviderAttemptInput{{Provider: "openai"}}})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := encodeRequestLog(event, "")
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
	}
	event := testGatewayRequestEvent()
	event.Plugins = plugins.Metrics{Redaction: &plugins.RedactionMetrics{}, Export: &plugins.ExportMetrics{}}
	payload, err := encodeRequestLog(event, "")
	if err != nil || !strings.Contains(payload, `"plugins":{"redaction":{"items_redacted":0,"duration_us":0},"export":{"duration_us":0}}`) {
		t.Fatalf("configured plugins with measured zero disappeared: %s, %v", payload, err)
	}
}
