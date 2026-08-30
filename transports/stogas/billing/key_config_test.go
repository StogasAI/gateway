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

func TestKeyConfigurationRedactionKeepsSecureDefaultsAndAddsOnlyConfiguredDetectors(t *testing.T) {
	tests := []struct {
		name       string
		config     *policy.Config
		wantIP     bool
		wantCustom bool
	}{
		{name: "secure defaults"},
		{
			name: "IP and custom additions",
			config: &policy.Config{Plugins: &policy.Plugins{StogasPIIRedaction: &policy.PIIRedaction{
				CustomPatterns: []string{`EMP-[0-9]{6}`},
				Patterns:       []string{"ip_address"},
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
			if strings.Contains(result, "alice@corp.dev") || !strings.Contains(result, "<EMAIL_ADDRESS>") {
				t.Fatalf("secure default email policy was disabled: %s", result)
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
		config := &policy.Config{Plugins: &policy.Plugins{StogasPIIRedaction: &policy.PIIRedaction{}}}
		if patterns[0] == "unknown" {
			config.Plugins.StogasPIIRedaction.Patterns = patterns
		} else {
			config.Plugins.StogasPIIRedaction.CustomPatterns = patterns
		}
		if _, err := compileKeyRedactionPolicy(config); err == nil {
			t.Fatalf("invalid configured patterns were accepted: %q", patterns)
		}
	}
}
