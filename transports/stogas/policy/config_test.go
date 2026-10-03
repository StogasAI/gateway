package policy

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestDenyPeriodsUseTheSourceBudgetAndShareTimeZones(t *testing.T) {
	windows := make([]DenyWindow, 1000)
	for i := range windows {
		windows[i] = DenyWindow{Days: []string{"mon"}, TimeZone: "America/New_York",
			Start: fmt.Sprintf("%02d:%02d", i/60, i%60), End: fmt.Sprintf("%02d:%02d", (i+1)/60, (i+1)%60)}
	}
	raw := mustRawJSON(map[string]any{"access": &Access{Deny: windows}})
	source, err := CompileSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	if source.Config.Access.Deny[0].location != source.Config.Access.Deny[999].location {
		t.Fatal("repeated time zones were parsed repeatedly")
	}
	lastMinute := time.Date(2026, 6, 1, 20, 39, 0, 0, time.UTC)
	if !source.Config.DeniedAt(lastMinute) || source.Config.DeniedAt(lastMinute.Add(time.Minute)) {
		t.Fatal("last deny period or its exclusive endpoint was lost")
	}
}

func validCompiledConfig() Config {
	return Config{Schema: "stogas.key-config.compiled.v1", CompilerVersion: CompilerVersion, Routing: Routing{MaxPreDispatchCandidates: 1}}
}
func parseCompiledConfig(t *testing.T, config Config) *Config {
	t.Helper()
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	return &config
}
func mustRawJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

type testValues map[string]Value

func (v testValues) PolicyValue(path string) (Value, bool) { value, ok := v[path]; return value, ok }

func TestDenyWindowsAreTimeZoneAwareAndHalfOpen(t *testing.T) {
	config := validCompiledConfig()
	config.Access = &Access{Deny: []DenyWindow{{
		Days:     []string{"mon"},
		Start:    "09:00",
		End:      "10:00",
		TimeZone: "America/New_York",
	}}}
	parsed := parseCompiledConfig(t, config)
	for _, test := range []struct {
		at   string
		want bool
	}{
		{at: "2026-06-01T12:59:59Z"},
		{at: "2026-06-01T13:00:00Z", want: true},
		{at: "2026-06-01T13:59:59Z", want: true},
		{at: "2026-06-01T14:00:00Z"},
		{at: "2026-06-02T13:30:00Z"},
	} {
		at, err := time.Parse(time.RFC3339, test.at)
		if err != nil {
			t.Fatal(err)
		}
		if got := parsed.DeniedAt(at); got != test.want {
			t.Errorf("DeniedAt(%s) = %t, want %t", test.at, got, test.want)
		}
	}
	if (&Config{}).DeniedAt(time.Now()) {
		t.Fatal("config without access policy denied a request")
	}
}

func TestDenyWindowCanEndAtMidnight(t *testing.T) {
	config := validCompiledConfig()
	config.Access = &Access{Deny: []DenyWindow{{
		Days:     []string{"mon"},
		Start:    "20:00",
		End:      "24:00",
		TimeZone: "UTC",
	}}}
	parsed := parseCompiledConfig(t, config)
	for _, test := range []struct {
		at   string
		want bool
	}{
		{at: "2026-06-01T19:59:59Z"},
		{at: "2026-06-01T20:00:00Z", want: true},
		{at: "2026-06-01T23:59:59Z", want: true},
		{at: "2026-06-02T00:00:00Z"},
	} {
		at, err := time.Parse(time.RFC3339, test.at)
		if err != nil {
			t.Fatal(err)
		}
		if got := parsed.DeniedAt(at); got != test.want {
			t.Errorf("DeniedAt(%s) = %t, want %t", test.at, got, test.want)
		}
	}
}

func TestPolicyFieldRegistryIsClosed(t *testing.T) {
	paths := FieldPaths()
	for _, path := range paths {
		if fieldType, ok := FieldType(path); !ok || fieldType == "" {
			t.Fatalf("registered field %q did not resolve", path)
		}
	}
	validDynamic := []string{
		"deployment.pricing.input_tokens.per_mill_tokens",
		"deployment.pricing.output_tokens.per_mill_context_gt_272k",
	}
	for _, path := range validDynamic {
		if fieldType, ok := FieldType(path); !ok || fieldType != "decimal" {
			t.Fatalf("dynamic field %q = %q, %t", path, fieldType, ok)
		}
	}
	for _, path := range []string{
		"pricing.input_tokens.per_mill_tokens",
		"deployment.pricing.input_tokens.per_1k_calls",
		"deployment.pricing.unknown.per_mill_tokens",
		"deployment.pricing.anthropic_web_search_calls.per_mill_tokens",
		"deployment.pricing.anthropic_web_search_calls.per_1k_calls",
		"deployment.pricing.openai_chat_completion_search_preview_model_calls.per_1k_search_context_high_calls",
		"deployment.__proto__",
	} {
		if fieldType, ok := FieldType(path); ok || fieldType != "" {
			t.Fatalf("unregistered field %q resolved as %q", path, fieldType)
		}
	}
}

func FuzzCompileSourceNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte(`{}`), []byte(`null`), []byte(`{}`), []byte(`{"routing":{"filter":"model.id == 'model-a'"}}`), {0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = CompileSource(raw) })
}
