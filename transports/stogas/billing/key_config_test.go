package billing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func keyConfigSnapshot(generation int, digest string) *KeyConfigSnapshot {
	return &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: &policy.Config{
		CompilerVersion: policy.CompilerVersion,
		Routing: policy.Routing{
			MaxPreDispatchCandidates: 1,
		},
		Schema: "stogas.key-config.compiled.v1",
	},
		Digest: digest}, Generation: generation,
	}
}

func TestHoldConfirmationRenewsOnlyItsSnapshotAndInvalidatesOnce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var cache keyConfigCache
	first := cache.put("key", keyConfigSnapshot(1, strings.Repeat("a", 64)), now)
	cache.put("other", keyConfigSnapshot(1, strings.Repeat("b", 64)), now.Add(time.Minute))
	checked := now.Add(2 * time.Minute)
	if cache.confirm("key", first, true, checked, checked.Add(time.Second)) {
		t.Fatal("matching confirmation requested a refresh")
	}
	if _, ok := cache.get("key", now.Add(4*time.Minute)); !ok {
		t.Fatal("confirmed snapshot expired using its original fetch time")
	}
	if _, ok := cache.get("other", now.Add(4*time.Minute)); ok {
		t.Fatal("renewal disturbed another entry's expiry")
	}
	cache.confirm("key", first, true, now.Add(time.Minute), checked.Add(time.Second))
	if _, ok := cache.get("key", checked.Add(keyConfigCacheTTL-time.Nanosecond)); !ok {
		t.Fatal("older confirmation shortened expiry")
	}
	if _, ok := cache.get("key", checked.Add(keyConfigCacheTTL)); ok {
		t.Fatal("network time extended the validation deadline")
	}

	// Start the invalidation cases after the preceding authority checks.
	now = now.Add(5 * time.Minute)
	checked = now.Add(2 * time.Minute)
	first = cache.put("key", keyConfigSnapshot(1, strings.Repeat("a", 64)), now)
	var workers sync.WaitGroup
	refreshes := make(chan bool, 32)
	for range 32 {
		workers.Go(func() { refreshes <- cache.confirm("key", first, false, now, now) })
	}
	workers.Wait()
	close(refreshes)
	count := 0
	for refresh := range refreshes {
		if refresh {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate invalidations started %d refreshes", count)
	}
	newer := cache.put("key", keyConfigSnapshot(2, strings.Repeat("b", 64)), now)
	if cache.confirm("key", first, false, now, now) {
		t.Fatal("old reply evicted a new snapshot")
	}
	cache.confirm("key", first, true, checked, checked)
	if got, ok := cache.get("key", now); !ok || got != newer {
		t.Fatal("old reply changed current snapshot")
	}
	if _, ok := cache.get("key", now.Add(keyConfigCacheTTL)); ok {
		t.Fatal("old reply renewed current snapshot")
	}
	cache.close()
	if cache.confirm("key", first, false, now, now) {
		t.Fatal("closed cache started a refresh")
	}
}

func TestCredentialSnapshotsShareCiphertextWithoutLosingInFlightVersions(t *testing.T) {
	now := time.Now()
	var cache keyConfigCache
	makeSnapshot := func(generation int, ciphertext string) *KeyConfigSnapshot {
		snapshot := keyConfigSnapshot(1, strings.Repeat("a", 64))
		snapshot.CredentialsGeneration = generation
		snapshot.Credentials = map[string][]CredentialSelection{"openai": {{Mode: "stored", ID: "01900000-0000-7000-8000-000000000001", Credential: &CachedCredential{
			ID: "01900000-0000-7000-8000-000000000001", OrganizationID: "org", Provider: "openai", Kind: "stored", Enabled: true, EncryptedSecret: ciphertext,
		}}}}
		return snapshot
	}
	first := cache.put("a", makeSnapshot(1, "ciphertext-1"), now)
	second := cache.put("b", makeSnapshot(1, "ciphertext-1"), now)
	if first.Credentials["openai"][0].Credential != second.Credentials["openai"][0].Credential || len(cache.credentials) != 1 {
		t.Fatal("identical referenced credentials were duplicated")
	}
	rotated := cache.put("a", makeSnapshot(2, "ciphertext-2"), now)
	if first.Credentials["openai"][0].Credential.EncryptedSecret != "ciphertext-1" || rotated.Credentials["openai"][0].Credential.EncryptedSecret != "ciphertext-2" || len(cache.credentials) != 2 {
		t.Fatal("rotation changed an in-flight credential")
	}
	if got := cache.put("a", makeSnapshot(1, "ciphertext-1"), now); got != rotated {
		t.Fatal("delayed read rolled credentials back")
	}
	cache.remove("b")
	if len(cache.credentials) != 1 {
		t.Fatal("old credential remained cached after its final reference")
	}
	cache.remove("a")
	if cache.bytes != 0 || cache.credentials != nil {
		t.Fatal("credential eviction leaked its cache charge")
	}
	if first.Credentials["openai"][0].Credential.EncryptedSecret != "ciphertext-1" {
		t.Fatal("eviction invalidated request-owned data")
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
	if got, ok := cache.get("key", now.Add(keyConfigCacheTTL-time.Nanosecond)); !ok || got.Config != newer.Config || got.Generation != newer.Generation || got.Digest != newer.Digest {
		t.Fatalf("cached snapshot = %#v, %t", got, ok)
	}
	cache.put("key", keyConfigSnapshot(1, strings.Repeat("a", 64)), now)
	if got, ok := cache.get("key", now); !ok || got.Generation != 2 {
		t.Fatalf("older generation replaced current snapshot: %#v, %t", got, ok)
	}
	if _, ok := cache.get("key", now.Add(keyConfigCacheTTL)); ok {
		t.Fatal("snapshot remained live at the exclusive TTL boundary")
	}

	for index := 0; index < 5000; index++ {
		cache.put(
			"key-"+strings.Repeat("x", index%17)+time.Unix(int64(index), 0).String(),
			keyConfigSnapshot(1, strings.Repeat("c", 64)),
			now,
		)
	}
	if cache.bytes > keyConfigCacheBytes {
		t.Fatalf("cache retained %d bytes, limit = %d", cache.bytes, keyConfigCacheBytes)
	}

	cache.remove("not-present")
	cache.remove("")
	cache.put("", newer, now)
	cache.put("nil", nil, now)
	if _, exists := cache.entries[""]; exists {
		t.Fatal("cache retained an empty identity")
	}
	stats := cache.diagnostics()
	if stats.Entries != len(cache.entries) || stats.EstimatedBytes != cache.bytes || stats.BudgetBytes != keyConfigCacheBytes || stats.Hits != 2 || stats.Misses != 2 || stats.Expired != 1 {
		t.Fatalf("unexpected cache diagnostics: %+v", stats)
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
				encoded, err := json.Marshal(map[string]any{"plugins": map[string]any{"stogasRedaction": map[string]bool{fixture.pattern: enabled}}})
				if err != nil {
					t.Fatal(err)
				}
				source, err := policy.CompileSource(encoded)
				if err != nil {
					t.Fatal(err)
				}
				parsed := source.Config
				compiled, err := policy.CompileRedaction(parsed)
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
					if err := redaction.NewWithPolicy(compiled).RedactRequestFields(raw, surface, nil); err != nil {
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

func TestKeyConfigurationRedactionRequiresExplicitSelections(t *testing.T) {
	tests := []struct {
		name       string
		config     *policy.Config
		wantIP     bool
		wantCustom bool
		wantEmail  bool
	}{
		{name: "omitted plugin"},
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
			compiled, err := policy.CompileRedaction(test.config)
			if err != nil {
				t.Fatal(err)
			}
			raw := map[string]json.RawMessage{
				"messages": json.RawMessage(`[{"role":"user","content":"alice@corp.dev 192.0.2.1 EMP-123456"}]`),
			}
			redactor := redaction.NewWithPolicy(compiled)
			if err := redactor.RedactRequestFields(raw, redaction.SurfaceChat, nil); err != nil {
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
		if _, err := policy.CompileRedaction(config); err == nil {
			t.Fatalf("invalid configured patterns were accepted: %q", patterns)
		}
	}
}

func TestOnDemandSourcesAndPIIMatchersShareAcrossDistinctKeys(t *testing.T) {
	var cache keyConfigCache
	now := time.Now()
	literals := make([]string, 1000)
	for i := range literals {
		literals[i] = fmt.Sprintf("ORGANIZATION_SECRET_%04d", i)
	}
	parent, _ := json.Marshal(map[string]any{"plugins": map[string]any{"stogasRedaction": map[string]any{"literals": []map[string]any{{"values": literals}}}}})
	var first *KeyConfigSnapshot
	for i := range 1000 {
		key, _ := json.Marshal(map[string]any{"routing": map[string]any{"filter": fmt.Sprintf("deployment.contextWindowTokens >= %d", i)}})
		sources, err := cache.acquireSources([]json.RawMessage{parent, json.RawMessage("null"), key}, "org", nil)
		if err != nil {
			t.Fatal(err)
		}
		var values []policy.ScopedSource
		for j, s := range sources {
			if s != nil {
				values = append(values, policy.ScopedSource{Scope: []policy.Scope{policy.OrganizationScope, policy.GrantScope, policy.KeyScope}[j], Value: s.value})
			}
		}
		digest := policy.ChainDigest(values)
		config, err := cache.composeSources(values, digest)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := cache.put(fmt.Sprint(i), &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: config, Digest: digest, sourceRefs: sources, cacheBytes: 16 << 10}, Generation: 1}, now)
		cache.releaseSources(sources)
		if first == nil {
			first = snapshot
		} else if first.sourceRefs[0] != snapshot.sourceRefs[0] || first.matchers[0] != snapshot.matchers[0] || first.Config.PluginSources[0] != snapshot.Config.PluginSources[0] {
			t.Fatal("large parent was duplicated")
		}
	}
	if len(cache.sources) != 1001 || len(cache.plans) != 1 || cache.bytes > 32<<20 {
		t.Fatalf("unexpected cache amplification: sources=%d plans=%d bytes=%d", len(cache.sources), len(cache.plans), cache.bytes)
	}
	t.Logf("1000 distinct keys + shared 1000-literal parent: %d estimated cache bytes", cache.bytes)
	p, err := first.RedactionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	cache.close()
	if cache.bytes != 0 || len(cache.sources) != 0 {
		t.Fatalf("cache leaked %d bytes", cache.bytes)
	}
	if p == nil || first.sourceRefs[0].value.Config.Plugins == nil {
		t.Fatal("eviction invalidated in-flight pointers")
	}
}

func TestPlaintextSourcesShareAcrossOrganizationsWithoutSharingAuthority(t *testing.T) {
	var cache keyConfigCache
	defer cache.close()
	first, err := cache.acquireSource([]byte(`{"plugins":{"stogasRedaction":{"literals":[{"values":["SharedDictionary"]}]}}}`), "first-org", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.acquireSource([]byte(`{ "plugins": { "stogasRedaction": { "literals": [{ "values": ["SharedDictionary"] }] } } }`), "second-org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(cache.sources) != 1 {
		t.Fatal("equal plaintext content was duplicated across organizations")
	}
	cache.releaseSources([]*sharedPolicySource{first})
	if second.value.Config.Plugins == nil || second.refs != 1 {
		t.Fatal("one organization removed another's shared source")
	}
	cache.releaseSources([]*sharedPolicySource{second})
	if cache.bytes != 0 || len(cache.sources) != 0 {
		t.Fatal("final source reference leaked cached content")
	}
}

func TestSiblingKeyPinsReuseConfirmedSourcesAcrossEviction(t *testing.T) {
	var cache keyConfigCache
	defer cache.close()
	claims := &APIKeyClaims{OrganizationID: "org", KeyID: "first", ResponsibleID: "user"}
	versions := &PolicyVersions{{Scope: policy.OrganizationScope, ID: "org", Revision: 7}, {Scope: policy.KeyScope, ID: "first", Revision: 1}}
	sources, err := cache.acquireSources([]json.RawMessage{
		json.RawMessage(`{"input":{"asciiOnly":true}}`), json.RawMessage(`null`), json.RawMessage(`{}`),
	}, "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	values := []policy.ScopedSource{{Scope: policy.OrganizationScope, Value: sources[0].value}, {Scope: policy.KeyScope, Value: sources[2].value}}
	config, err := policy.ComposeSources(values)
	if err != nil {
		t.Fatal(err)
	}
	digest := policy.ChainDigest(values)
	cache.put("first", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Versions: versions, Config: config, Digest: digest, sourceRefs: []*sharedPolicySource{sources[0], sources[2]}}, Claims: claims, Generation: 1}, time.Now())
	cache.releaseSources(sources)
	sibling := *claims
	sibling.KeyID = "second"
	pins := cache.pinSourcesForClaims(&sibling, nil)
	if pins.known["organization:org"] != 7 || pins.known["key:first"] != 0 {
		t.Fatal("sibling hints include the wrong source identity")
	}
	cache.remove("first")
	reused, err := cache.acquireSourceDelta([]policySourceRecord{{PolicyVersion: PolicyVersion{Scope: policy.OrganizationScope, ID: "org", Revision: 7}}, {PolicyVersion: PolicyVersion{Scope: policy.KeyScope, ID: "second", Revision: 1}, Source: json.RawMessage(`null`)}}, "org", pins, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reused[0] != sources[0] || policy.ChainDigest([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: reused[0].value}, {Scope: policy.KeyScope, Value: reused[1].value}}) != digest {
		t.Fatal("source delta changed the inherited restrictions")
	}
	cache.releaseSources(pins.sources)
	cache.releaseSources(reused)
	if cache.bytes != 0 || len(cache.sourceOwners) != 0 {
		t.Fatal("source pins or owner indexes leaked after eviction")
	}
}

func TestSourceDeltaRequiresPinnedIdentityAndRevision(t *testing.T) {
	var cache keyConfigCache
	defer cache.close()
	record := policySourceRecord{PolicyVersion: PolicyVersion{Scope: policy.OrganizationScope, ID: "org", Revision: 2}}
	for _, pins := range []policySourcePins{
		{},
		{known: map[string]int{"organization:org": 2}},
		{known: map[string]int{"organization:foreign": 2}},
	} {
		if sources, err := cache.acquireSourceDelta([]policySourceRecord{record}, "org", pins, nil); err == nil || sources != nil {
			t.Fatal("unresolved cached source became an empty policy")
		}
	}
	source, err := cache.acquireSource([]byte(`{"input":{"asciiOnly":true}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	pins := policySourcePins{known: map[string]int{"organization:org": 1}, byID: map[string]*sharedPolicySource{"organization:org": source}}
	if _, err := cache.acquireSourceDelta([]policySourceRecord{record}, "org", pins, nil); err == nil {
		t.Fatal("stale pinned revision accepted")
	}
	// A newly empty source must replace the old requirements, never reuse them.
	record.Source = json.RawMessage(`null`)
	refs, err := cache.acquireSourceDelta([]policySourceRecord{record}, "org", pins, nil)
	if err != nil || len(refs) != 1 || refs[0].value.Config.Input != nil {
		t.Fatalf("explicit empty source was not applied: %v", err)
	}
	cache.releaseSources(refs)
	if _, err := cache.acquireSourceDelta([]policySourceRecord{record, record}, "org", pins, nil); err == nil {
		t.Fatal("duplicate source identity accepted")
	}
	cache.releaseSources([]*sharedPolicySource{source})
	if cache.bytes != 0 || len(cache.sources) != 0 {
		t.Fatal("failed deltas leaked source references")
	}
}

func TestDelayedSourceRefreshCannotReplaceNewerParentSnapshot(t *testing.T) {
	var cache keyConfigCache
	defer cache.close()
	old := time.Now()
	first := cache.put("key", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Digest: "old-parent"}, Generation: 1, CredentialsGeneration: 1}, old)
	second := cache.put("key", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Digest: "new-parent"}, Generation: 1, CredentialsGeneration: 1}, old.Add(time.Second))
	if got := cache.put("key", first, old.Add(time.Millisecond)); got != second {
		t.Fatal("a delayed refresh replaced a newer parent revision")
	}
	// A late hold reply for the prior object cannot renew the new object.
	cache.confirm("key", first, true, old.Add(2*time.Second), old.Add(3*time.Second))
	if _, fresh := cache.get("key", old.Add(keyConfigCacheTTL+1500*time.Millisecond)); fresh {
		t.Fatal("an unrelated hold extended the new snapshot")
	}
}

func TestConcurrentSourceMissesInternOnceAndCleanUpPins(t *testing.T) {
	var cache keyConfigCache
	raw := []byte(`{"plugins":{"stogasRedaction":{"email_address":true}}}`)
	refs := make(chan *sharedPolicySource, 32)
	errs := make(chan error, 32)
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() { s, err := cache.acquireSource(raw, "org", nil); refs <- s; errs <- err })
	}
	workers.Wait()
	close(refs)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var held []*sharedPolicySource
	for ref := range refs {
		if len(held) > 0 && ref != held[0] {
			t.Fatal("concurrent compile duplicated source")
		}
		held = append(held, ref)
	}
	if len(cache.sources) != 1 {
		t.Fatal("source was not interned")
	}
	cache.releaseSources(held)
	if cache.bytes != 0 || len(cache.sources) != 0 {
		t.Fatal("pins leaked")
	}
	if _, err := cache.acquireSources([]json.RawMessage{raw, json.RawMessage("null"), json.RawMessage(`{"version":2}`)}, "org", nil); err == nil {
		t.Fatal("invalid chain accepted")
	}
	if cache.bytes != 0 || len(cache.sources) != 0 {
		t.Fatal("failed composition leaked parent")
	}
	cache.close()
	if _, err := cache.acquireSource(raw, "org", nil); err == nil {
		t.Fatal("closed cache accepted a source")
	}
}

func TestSourceRevisionSharesPIIAndKeepsInFlightSnapshotAfterClose(t *testing.T) {
	var cache keyConfigCache
	original, err := cache.acquireSource([]byte(`{"plugins":{"stogasRedaction":{"literals":[{"values":["COMPANY_SECRET"]}]}}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := cache.acquireSource([]byte(`{"limits":{"spend":{"lifetimeUsd":"10"}},"plugins":{"stogasRedaction":{"literals":[{"values":["COMPANY_SECRET"]}]}}}`), "org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if original == changed || original.value.Digest == changed.value.Digest || original.plan != changed.plan || original.value.Config.Plugins != changed.value.Config.Plugins {
		t.Fatal("a non-PII revision failed to reuse the existing plugin section")
	}
	plan, err := original.plan.get()
	if err != nil {
		t.Fatal(err)
	}
	cache.close()
	if _, err := cache.acquireSource([]byte(`{"plugins":{"stogasRedaction":{"literals":[{"values":["COMPANY_SECRET"]}]}}}`), "org", nil); err == nil {
		t.Fatal("a closed cache accepted an existing pinned source")
	}
	cache.releaseSources([]*sharedPolicySource{original, changed})
	if cache.bytes != 0 || len(cache.sources) != 0 || len(cache.plans) != 0 {
		t.Fatal("retired revisions leaked cache references")
	}
	if plan == nil || original.value.Config.Plugins != changed.value.Config.Plugins {
		t.Fatal("closing invalidated in-flight content")
	}
}

// Pins cover the short interval between source lookup and installing a key
// snapshot. The same byte budget covers pinned sources and cached key entries.
func (c *keyConfigCache) acquireSources(raw []json.RawMessage, organizationID string, key customerkey.Keys) ([]*sharedPolicySource, error) {
	if len(raw) != 3 {
		return nil, ErrGatewayUnavailable
	}
	sources := make([]*sharedPolicySource, 3)
	for i, document := range raw {
		if bytes.Equal(bytes.TrimSpace(document), []byte("null")) && i == 1 {
			continue
		}
		source, err := c.acquireSource(document, organizationID, key)
		if err != nil {
			c.releaseSources(sources)
			return nil, err
		}
		sources[i] = source
	}
	return sources, nil
}
