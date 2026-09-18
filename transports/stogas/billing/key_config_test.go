package billing

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func keyConfigSnapshot(generation int, digest string) *KeyConfigSnapshot {
	return &KeyConfigSnapshot{
		Config: &policy.Config{
			CompilerVersion: policy.CompilerVersion,
			Routing: policy.Routing{
				MaxPreDispatchCandidates: 1,
			},
			Schema: "stogas.key-config.compiled.v1",
		},
		Digest:     digest,
		Generation: generation,
	}
}

func TestKeyConfigCacheIsBoundedExpiringAndGenerationMonotonic(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var cache keyConfigCache
	if _, ok := cache.get("missing", now); ok {
		t.Fatal("empty cache returned an entry")
	}

	newer := keyConfigSnapshot(2, strings.Repeat("b", 64))
	cache.put("key", newer, now)
	if got, ok := cache.get("key", now.Add(keyConfigCacheTTL-time.Nanosecond)); !ok || got != newer {
		t.Fatalf("cached snapshot = %#v, %t", got, ok)
	}
	cache.put("key", keyConfigSnapshot(1, strings.Repeat("a", 64)), now)
	if got, ok := cache.get("key", now); !ok || got.Generation != 2 {
		t.Fatalf("older generation replaced current snapshot: %#v, %t", got, ok)
	}
	if _, ok := cache.get("key", now.Add(keyConfigCacheTTL)); ok {
		t.Fatal("snapshot remained live at the exclusive TTL boundary")
	}

	for index := 0; index < keyConfigCacheEntries*2; index++ {
		cache.put(
			"key-"+strings.Repeat("x", index%17)+time.Unix(int64(index), 0).String(),
			keyConfigSnapshot(1, strings.Repeat("c", 64)),
			now,
		)
	}
	if len(cache.entries) > keyConfigCacheEntries {
		t.Fatalf("cache retained %d entries, limit = %d", len(cache.entries), keyConfigCacheEntries)
	}

	cache.remove("not-present")
	cache.remove("")
	cache.put("", newer, now)
	cache.put("nil", nil, now)
	if _, exists := cache.entries[""]; exists {
		t.Fatal("cache retained an empty identity")
	}
}

func TestConfigDigestAndDashboardCacheIdentityAreClosed(t *testing.T) {
	for value, want := range map[string]bool{
		strings.Repeat("0", 64): true,
		strings.Repeat("a", 64): true,
		strings.Repeat("A", 64): false,
		strings.Repeat("g", 64): false,
		strings.Repeat("0", 63): false,
		strings.Repeat("0", 65): false,
		"":                      false,
	} {
		if got := validConfigDigest(value); got != want {
			t.Errorf("validConfigDigest(%q) = %t, want %t", value, got, want)
		}
	}

	first := dashboardConfigCacheKey(&DashboardCredential{
		ActorUserID: "actor-a",
		KeyID:       "key-a",
		SessionID:   "session-a",
	})
	for _, credential := range []*DashboardCredential{
		{ActorUserID: "actor-b", KeyID: "key-a", SessionID: "session-a"},
		{ActorUserID: "actor-a", KeyID: "key-b", SessionID: "session-a"},
		{ActorUserID: "actor-a", KeyID: "key-a", SessionID: "session-b"},
	} {
		if candidate := dashboardConfigCacheKey(credential); candidate == first || candidate == "" {
			t.Fatalf("dashboard cache identities collided: %q", candidate)
		}
	}
	if dashboardConfigCacheKey(nil) != "" {
		t.Fatal("nil dashboard credential produced a cache identity")
	}
}

func TestEveryPolicyDetectorReachesChatAndResponsesRedaction(t *testing.T) {
	fixtures := []struct{ pattern, input, placeholder string }{
		{"email_address", "alice@corp.io", "<EMAIL_ADDRESS>"},
		{"phone_number", "+44 (20) 7123 4567", "<PHONE_NUMBER>"},
		{"social_security_number", "SSN 856-45-6789", "<US_SSN>"},
		{"credit_card_number", "card 4532015112830366", "<PAYMENT_CARD>"},
		{"ip_address", "198.51.100.24", "<IP_ADDRESS>"},
		{"api_keys_and_secrets", "Authorization: Bearer AbCdEf0123456789-_", "<CREDENTIAL>"},
		{"api_keys_and_secrets", "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----", "<PRIVATE_KEY>"},
		{"api_keys_and_secrets", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "<JSON_WEB_TOKEN>"},
		{"api_keys_and_secrets", "postgresql://app:Sup3rSecret!@db.internal:5432/stogas", "<DATABASE_URL>"},
		{"api_keys_and_secrets", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", "<VENDOR_TOKEN>"},
		{"bank_identifiers", "Send to GB82 WEST 1234 5698 7654 32", "<IBAN>"},
		{"bank_identifiers", "ABA routing number 021000021", "<US_ROUTING_NUMBER>"},
		{"national_identifiers", "ITIN 900-70-0001", "<US_ITIN>"},
		{"national_identifiers", "National Insurance AB 12 34 56 C", "<UK_NATIONAL_INSURANCE_NUMBER>"},
		{"national_identifiers", "Canadian SIN 130 692 544", "<CA_SOCIAL_INSURANCE_NUMBER>"},
		{"national_identifiers", "TFN 123 456 782", "<AU_TAX_FILE_NUMBER>"},
		{"national_identifiers", "ABN 51 824 753 556", "<AU_BUSINESS_NUMBER>"},
		{"national_identifiers", "ACN 004 085 616", "<AU_COMPANY_NUMBER>"},
		{"national_identifiers", "Aadhaar 9999 9999 0019", "<IN_AADHAAR_NUMBER>"},
		{"national_identifiers", "CPF 529.982.247-25", "<BR_CPF>"},
		{"national_identifiers", "CNPJ 04.252.011/0001-10", "<BR_CNPJ>"},
		{"national_identifiers", "DNI 12345678Z", "<ES_NATIONAL_ID>"},
		{"national_identifiers", "Codice fiscale RSSMRA85T10A562S", "<IT_FISCAL_CODE>"},
		{"national_identifiers", "PESEL 44051401458", "<PL_PESEL>"},
		{"national_identifiers", "RRN 900101-1234568", "<KR_RESIDENT_NUMBER>"},
		{"national_identifiers", "HETU 131052-308T", "<FI_PERSONAL_ID>"},
		{"national_identifiers", "Thai national ID 1-2345-67890-12-1", "<TH_NATIONAL_ID>"},
		{"national_identifiers", "NRIC S1234567D", "<SG_NATIONAL_ID>"},
		{"national_identifiers", "Chinese resident ID 11010519491231002X", "<CN_RESIDENT_ID>"},
		{"national_identifiers", "Israeli ID 123456782", "<IL_NATIONAL_ID>"},
		{"national_identifiers", "South African ID 8001015009087", "<ZA_NATIONAL_ID>"},
		{"national_identifiers", "TCKN 10000000146", "<TR_NATIONAL_ID>"},
		{"national_identifiers", "Steuer-ID 12345678903", "<DE_TAX_ID>"},
		{"national_identifiers", "Personnummer 871220-2384", "<SE_PERSONAL_ID>"},
		{"national_identifiers", "Korean BRN 104-86-56659", "<KR_BUSINESS_REGISTRATION_NUMBER>"},
		{"national_identifiers", "Partita IVA 01333550323", "<IT_VAT_NUMBER>"},
		{"national_identifiers", "NIMC NIN 12345678902", "<NG_NATIONAL_ID>"},
		{"national_identifiers", "RVNR 15070649C103", "<DE_SOCIAL_SECURITY_NUMBER>"},
		{"health_identifiers", "NHS number 943 476 5919", "<UK_NHS_NUMBER>"},
		{"health_identifiers", "Medicare 2123 45670 1", "<AU_MEDICARE_NUMBER>"},
		{"health_identifiers", "NPI 1234567893", "<US_NPI>"},
		{"health_identifiers", "Medicare MBI 1EG4-TE5-MK73", "<US_MEDICARE_ID>"},
		{"health_identifiers", "KVNR A123456780", "<DE_HEALTH_INSURANCE_ID>"},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.pattern, func(t *testing.T) {
			for _, enabled := range []bool{true, false} {
				patterns := []string{}
				if enabled {
					patterns = append(patterns, fixture.pattern)
				}
				configuration := policy.Config{Schema: "stogas.key-config.compiled.v1", CompilerVersion: policy.CompilerVersion,
					Routing: policy.Routing{MaxPreDispatchCandidates: 1}, Plugins: &policy.Plugins{StogasRedaction: &policy.Redaction{Presets: patterns}}}
				encoded, err := json.Marshal(configuration)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := policy.Parse(encoded)
				if err != nil {
					t.Fatal(err)
				}
				compiled, err := compileKeyRedactionPolicy(parsed)
				if err != nil {
					t.Fatal(err)
				}
				for _, surface := range []redaction.Surface{redaction.SurfaceChat, redaction.SurfaceResponses} {
					key := "input"
					var value any = fixture.input
					if surface == redaction.SurfaceChat {
						key = "messages"
						value = []map[string]string{{"role": "user", "content": fixture.input}}
					}
					original, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					raw := map[string]json.RawMessage{key: original}
					if err := redaction.NewWithPolicy(compiled).RedactRequestFields(raw, surface); err != nil {
						t.Fatal(err)
					}
					var content string
					if surface == redaction.SurfaceChat {
						var messages []struct {
							Content string `json:"content"`
						}
						if err := json.Unmarshal(raw[key], &messages); err != nil {
							t.Fatal(err)
						}
						content = messages[0].Content
					} else if err := json.Unmarshal(raw[key], &content); err != nil {
						t.Fatal(err)
					}
					if enabled && !strings.Contains(content, fixture.placeholder) {
						t.Fatalf("missing selected detector: %s", raw[key])
					}
					if !enabled && string(raw[key]) != string(original) {
						t.Fatalf("disabled detector changed input: %s", raw[key])
					}
				}
			}
		})
	}
}

func TestKeyConfigurationRedactionDefaultsAndExplicitSelections(t *testing.T) {
	tests := []struct {
		name       string
		config     *policy.Config
		wantIP     bool
		wantCustom bool
		wantEmail  bool
	}{
		{name: "secure defaults", wantEmail: true},
		{name: "disabled built-ins", config: &policy.Config{Plugins: &policy.Plugins{StogasRedaction: &policy.Redaction{Presets: []string{}}}}},
		{name: "custom only", config: &policy.Config{Plugins: &policy.Plugins{StogasRedaction: &policy.Redaction{Presets: []string{}, CustomPatterns: []string{`EMP-[0-9]{6}`}}}}, wantCustom: true},
		{
			name: "IP and custom selection",
			config: &policy.Config{Plugins: &policy.Plugins{StogasRedaction: &policy.Redaction{
				CustomPatterns: []string{`EMP-[0-9]{6}`},
				Presets:        []string{"ip_address"},
			}}},
			wantIP:     true,
			wantCustom: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compiled, err := compileKeyRedactionPolicy(test.config)
			if err != nil {
				t.Fatal(err)
			}
			raw := map[string]json.RawMessage{
				"messages": json.RawMessage(`[{"role":"user","content":"alice@corp.dev 192.0.2.1 EMP-123456"}]`),
			}
			redactor := redaction.NewWithPolicy(compiled)
			if err := redactor.RedactRequestFields(raw, redaction.SurfaceChat); err != nil {
				t.Fatal(err)
			}
			result := string(raw["messages"])
			if got := strings.Contains(result, "<EMAIL_ADDRESS>"); got != test.wantEmail || strings.Contains(result, "alice@corp.dev") == test.wantEmail {
				t.Fatalf("email redaction = %t, want %t: %s", got, test.wantEmail, result)
			}
			if got := !strings.Contains(result, "192.0.2.1"); got != test.wantIP {
				t.Fatalf("IP redaction = %t, want %t: %s", got, test.wantIP, result)
			}
			if got := !strings.Contains(result, "EMP-123456"); got != test.wantCustom {
				t.Fatalf("custom redaction = %t, want %t: %s", got, test.wantCustom, result)
			}
		})
	}

	for _, patterns := range [][]string{{"unknown"}, {"a*"}, {"<EMAIL_ADDRESS>"}} {
		config := &policy.Config{Plugins: &policy.Plugins{StogasRedaction: &policy.Redaction{}}}
		if patterns[0] == "unknown" {
			config.Plugins.StogasRedaction.Presets = patterns
		} else {
			config.Plugins.StogasRedaction.CustomPatterns = patterns
		}
		if _, err := compileKeyRedactionPolicy(config); err == nil {
			t.Fatalf("invalid configured patterns were accepted: %q", patterns)
		}
	}
}
