package billing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func encryptedPolicyFixture(t testing.TB) ([]json.RawMessage, string, customerkey.Keys) {
	t.Helper()
	raw, err := os.ReadFile("../customerkey/testdata/webcrypto.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Root           string
		OrganizationID string
		Envelope       customerkey.Envelope
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := customerkey.ParseKeys(map[string]string{"default": fixture.Root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Clear)
	source, _ := json.Marshal(map[string]any{"encryption": map[string]any{"keys": map[string]string{"default": key["default"].ID()}}, "plugins": map[string]any{"redaction": map[string]any{"encrypted": fixture.Envelope}}})
	return []json.RawMessage{source, json.RawMessage(`null`), json.RawMessage(`{}`)}, fixture.OrganizationID, key
}

func TestEncryptedPolicyWarmCacheRequiresKeyAndRefreshKeepsPlan(t *testing.T) {
	raw, org, key := encryptedPolicyFixture(t)
	s := &Service{}
	sources, err := s.keyConfigs.acquireSources(raw, org, key)
	if err != nil {
		t.Fatal(err)
	}
	config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: sources[0].value}, {Scope: policy.KeyScope, Value: sources[2].value}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := s.keyConfigs.put("api", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: config, Digest: policy.ChainDigest([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: sources[0].value}, {Scope: policy.KeyScope, Value: sources[2].value}}), sourceRefs: sources}, CredentialsGeneration: 1}, time.Now())
	s.keyConfigs.releaseSources(sources)
	plan, err := snapshot.RedactionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := customerkey.ParseKeys(map[string]string{"default": base64.RawURLEncoding.EncodeToString(make([]byte, 32))})
	defer wrong.Clear()
	for _, supplied := range []customerkey.Keys{nil, wrong, key} {
		got, err := s.cachedOrFetchKeyConfig(context.Background(), "api", nil, nil, "", supplied, nil)
		if supplied.Identity() == key.Identity() {
			if err != nil || got != snapshot {
				t.Fatal("warm lookup fetched the database", err)
			}
		} else if !errors.Is(err, customerkey.ErrKey) {
			t.Fatal("warm cache bypassed key", err)
		}
	}
	if _, err := s.keyConfigs.acquireSources(raw, org, wrong); !errors.Is(err, customerkey.ErrKey) {
		t.Fatal("source cache bypassed key", err)
	}
	if _, err := s.keyConfigs.acquireSources(raw, "other-org", key); !errors.Is(err, customerkey.ErrEnvelope) {
		t.Fatal("source cache bypassed organization binding", err)
	}
	pinned := s.keyConfigs.pinForRefresh("api")
	s.keyConfigs.remove("api")
	replacement := s.keyConfigs.put("api", pinned, time.Now())
	s.keyConfigs.releaseSources(pinned.sourceRefs)
	next, err := replacement.RedactionPolicy()
	if err != nil || plan != next {
		t.Fatal("refresh rebuilt unchanged plan", err)
	}
	s.keyConfigs.close()
	if s.keyConfigs.bytes != 0 || len(s.keyConfigs.sources) != 0 {
		t.Fatal("refresh leaked references")
	}
}

type conditionalPolicyValues map[string]policy.Value

func (v conditionalPolicyValues) PolicyValue(path string) (policy.Value, bool) {
	value, ok := v[path]
	return value, ok
}

func (v conditionalPolicyValues) PolicyTokenPrice(meter string, _ int64) (policy.Value, bool) {
	return v.PolicyValue("deployment.pricing." + meter + ".per_mill_tokens")
}

func TestConditionalEncryptedPluginRequiresOnlyItsActiveRoot(t *testing.T) {
	raw, org, keys := encryptedPolicyFixture(t)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw[0], &fields); err != nil {
		t.Fatal(err)
	}
	plugins := fields["plugins"]
	delete(fields, "plugins")
	rules, _ := json.Marshal(map[string]any{"private": map[string]any{"when": "provider.id == 'openai'", "plugins": plugins}})
	fields["rules"] = rules
	raw[0], _ = json.Marshal(fields)
	validation := &Service{}
	unchecked, err := validation.ValidatePolicySources(validationSources(raw), org, nil)
	if err != nil || unchecked.Status != "partial" || len(unchecked.UncheckedPlugins) != 1 || unchecked.UncheckedPlugins[0] != (UncheckedPolicyPlugin{PolicyValidationReference: PolicyValidationReference{Scope: policy.OrganizationScope}, Rule: "private", Plugin: "redaction"}) {
		t.Fatalf("conditional plugin incorrectly certified: %+v %v", unchecked, err)
	}
	checked, err := validation.ValidatePolicySources(validationSources(raw), org, keys)
	if err != nil || checked.Status != "valid" || len(checked.UncheckedPlugins) != 0 {
		t.Fatalf("conditional plugin not validated: %+v %v", checked, err)
	}
	if _, err := validation.ValidatePolicySources(validationSources(raw), "other-org", keys); !errors.Is(err, customerkey.ErrEnvelope) {
		t.Fatalf("conditional ciphertext accepted in another organization: %v", err)
	}
	cache := &keyConfigCache{}
	refs, err := cache.acquireSources(raw, org, nil)
	if err != nil {
		t.Fatalf("inactive plugin required a root during fetch: %v", err)
	}
	sources := []policy.ScopedSource{{Scope: policy.OrganizationScope, Value: refs[0].value}, {Scope: policy.KeyScope, Value: refs[2].value}}
	config, err := policy.ComposeSources(sources)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := cache.put("api", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: config, Digest: policy.ChainDigest(sources), sourceRefs: refs}, Claims: &APIKeyClaims{OrganizationID: org}, CredentialsGeneration: 1}, time.Now())
	cache.releaseSources(refs)
	for _, provider := range []string{"anthropic", "openai", "anthropic", "openai"} {
		active, err := snapshot.Config.Activate(conditionalPolicyValues{"provider.id": {Type: "string", String: provider}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := snapshot.ActivePlugins(active, nil); provider == "openai" && !errors.Is(err, customerkey.ErrKey) || provider == "anthropic" && err != nil {
			t.Fatalf("wrong root requirement for %s: %v", provider, err)
		}
		if _, err := snapshot.ActivePlugins(active, keys); err != nil {
			t.Fatal(err)
		}
	}
	if len(snapshot.conditionalSources) != 1 {
		t.Fatalf("encrypted fragment not retained once: %d", len(snapshot.conditionalSources))
	}
	if cache.planStats.Builds != 1 {
		t.Fatalf("warm conditional dictionary rebuilt: %d", cache.planStats.Builds)
	}
	cache.close()
	if cache.bytes != 0 || len(cache.sources) != 0 || len(cache.plans) != 0 {
		t.Fatalf("conditional cache leaked: %d bytes", cache.bytes)
	}
}

// A requirement replaces a default's plugin of the same kind, so a request
// needs no root for an encrypted default plugin that another policy requires
// in its place, while the default's other plugins still need theirs.
func TestSuppressedEncryptedDefaultPluginNeedsNoRoot(t *testing.T) {
	const org = "test-organization"
	roots := map[string][]byte{"exports": make([]byte, 32), "redactions": make([]byte, 32)}
	encoded := map[string]string{}
	for name, root := range roots {
		for i := range root {
			root[i] = byte(3*i + len(name))
		}
		encoded[name] = base64.RawURLEncoding.EncodeToString(root)
	}
	keys, err := customerkey.ParseKeys(encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Clear)
	export := sealTestEnvelope(t, roots["exports"], keys["exports"].ID(), org, "plugins/export", `{"destinations":[{"url":"https://collector.example/v1/traces"}]}`)
	redaction := sealTestEnvelope(t, roots["redactions"], keys["redactions"].ID(), org, "plugins/redaction", `{"literals":[{"values":["CUSTOMER_PRIVATE_VALUE"]}]}`)
	organization, _ := json.Marshal(map[string]any{
		"encryption": map[string]any{"keys": map[string]string{"exports": keys["exports"].ID(), "redactions": keys["redactions"].ID()}},
		"delegation": map[string]any{"keys": []string{"plugins.redaction"}},
		"rules": map[string]any{"defaults": map[string]any{"mode": "default", "plugins": map[string]any{
			"export":    map[string]any{"encrypted": json.RawMessage(export)},
			"redaction": map[string]any{"encrypted": json.RawMessage(redaction)},
		}}},
	})
	for _, test := range []struct {
		name     string
		key      string
		required []string
	}{
		{"defaults apply", `{}`, []string{keys["exports"].ID(), keys["redactions"].ID()}},
		{"a required redaction replaces the default one", `{"plugins":{"redaction":{"email_address":true}}}`, []string{keys["exports"].ID()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := &keyConfigCache{}
			defer cache.close()
			raw := []json.RawMessage{organization, json.RawMessage(`null`), json.RawMessage(test.key)}
			refs, err := cache.acquireSources(raw, org, nil)
			if err != nil {
				t.Fatal(err)
			}
			sources := []policy.ScopedSource{{Scope: policy.OrganizationScope, Value: refs[0].value}, {Scope: policy.KeyScope, Value: refs[2].value}}
			config, err := policy.ComposeSources(sources)
			if err != nil {
				t.Fatal(err)
			}
			snapshot := cache.put("api", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: config, Digest: policy.ChainDigest(sources), sourceRefs: refs}, Claims: &APIKeyClaims{OrganizationID: org}, CredentialsGeneration: 1}, time.Now())
			cache.releaseSources(refs)
			active, err := snapshot.Config.Activate(conditionalPolicyValues{})
			if err != nil {
				t.Fatal(err)
			}
			if got := snapshot.RequiredRoots("openai", -1, active); !reflect.DeepEqual(got, test.required) {
				t.Fatalf("required roots %v, want %v", got, test.required)
			}
			// Without the default redaction's root, only the export's is needed.
			if _, err := snapshot.ActivePlugins(active, customerkey.Keys{"exports": keys["exports"]}); (len(test.required) == 1) != (err == nil) {
				t.Fatalf("export root alone: %v", err)
			}
			if _, err := snapshot.ActivePlugins(active, nil); !errors.Is(err, customerkey.ErrKey) {
				t.Fatalf("the export's root was not required: %v", err)
			}
			if _, err := snapshot.ActivePlugins(active, keys); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOptionalValidationDistinguishesUncheckedFromInvalid(t *testing.T) {
	raw, org, key := encryptedPolicyFixture(t)
	s := &Service{}
	for _, supplied := range []customerkey.Keys{nil, key} {
		got, err := s.ValidatePolicySources(validationSources(raw), org, supplied)
		if err != nil {
			t.Fatal(err)
		}
		if supplied == nil {
			if got.Status != "partial" || len(got.UncheckedPlugins) != 1 || got.UncheckedPlugins[0] != (UncheckedPolicyPlugin{PolicyValidationReference: PolicyValidationReference{Scope: policy.OrganizationScope}, Plugin: "redaction"}) {
				t.Fatalf("opaque content certified: %+v", got)
			}
		} else if got.Status != "valid" || len(got.UncheckedPlugins) != 0 {
			t.Fatalf("valid content not checked: %+v", got)
		}
	}
	bad := append([]json.RawMessage(nil), raw...)
	bad[2] = json.RawMessage(`{"plugins":{"redaction":{"customPattern":"("}}}`)
	if _, err := s.ValidatePolicySources(validationSources(bad), org, key); err == nil {
		t.Fatal("malformed regex accepted")
	}
	bad[2] = json.RawMessage(`{"encryption":{"keys":{"default":"` + key["default"].ID() + `"}}}`)
	if _, err := s.ValidatePolicySources(validationSources(bad), org, key); err == nil {
		t.Fatal("child root accepted")
	}
	if _, err := s.ValidatePolicySources(validationSources(raw)[:1], org, key); err == nil {
		t.Fatal("missing source accepted")
	}
	if _, err := s.ValidatePolicySources(validationSources(raw), "other-org", key); !errors.Is(err, customerkey.ErrEnvelope) {
		t.Fatal("wrong organization accepted", err)
	}
	if s.keyConfigs.bytes != 0 {
		t.Fatal("temporary validation retained secret plans")
	}
}

// Each plugin may use its own root. A check opens the plugins whose root it
// received, names the others, and still checks every readable setting.
func TestPolicyValidationOpensEachPluginWithItsOwnRoot(t *testing.T) {
	const org = "test-organization"
	roots := map[string][]byte{"exports": make([]byte, 32), "redactions": make([]byte, 32)}
	encoded := map[string]string{}
	for name, root := range roots {
		for i := range root {
			root[i] = byte(i + len(name))
		}
		encoded[name] = base64.RawURLEncoding.EncodeToString(root)
	}
	keys, err := customerkey.ParseKeys(encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Clear)
	export := sealTestEnvelope(t, roots["exports"], keys["exports"].ID(), org, "plugins/export", `{"destinations":[{"url":"https://collector.example/v1/traces","headers":{"Authorization":"Bearer private"}}]}`)
	redaction := sealTestEnvelope(t, roots["redactions"], keys["redactions"].ID(), org, "plugins/redaction", `{"literals":[{"values":["CUSTOMER_PRIVATE_VALUE"]}]}`)
	registry := map[string]any{"keys": map[string]string{"exports": keys["exports"].ID(), "redactions": keys["redactions"].ID()}}
	plugins := map[string]any{"textExtraction": "always", "export": map[string]any{"encrypted": json.RawMessage(export)}, "redaction": map[string]any{"encrypted": json.RawMessage(redaction)}}
	base, _ := json.Marshal(map[string]any{"encryption": registry, "plugins": plugins})
	rule, _ := json.Marshal(map[string]any{"rules": map[string]any{"private": map[string]any{"when": `provider.id == "openai"`, "plugins": plugins}}})
	s := &Service{}
	for _, test := range []struct {
		sent    []string
		missing []string
	}{
		{nil, []string{"export", "redaction"}},
		{[]string{"exports"}, []string{"redaction"}},
		{[]string{"redactions"}, []string{"export"}},
		{[]string{"exports", "redactions"}, nil},
	} {
		sent := customerkey.Keys{}
		for _, name := range test.sent {
			sent[name] = keys[name]
		}
		got, err := s.ValidatePolicySources(validationSources([]json.RawMessage{base, json.RawMessage(`null`), rule}), org, sent)
		if err != nil {
			t.Fatalf("roots %v: %v", test.sent, err)
		}
		var want []UncheckedPolicyPlugin
		for _, plugin := range test.missing {
			want = append(want, UncheckedPolicyPlugin{PolicyValidationReference: PolicyValidationReference{Scope: policy.OrganizationScope}, Plugin: plugin})
		}
		for _, plugin := range test.missing {
			want = append(want, UncheckedPolicyPlugin{PolicyValidationReference: PolicyValidationReference{Scope: policy.KeyScope}, Rule: "private", Plugin: plugin})
		}
		status := "valid"
		if len(want) > 0 {
			status = "partial"
		}
		if got.Status != status || !reflect.DeepEqual(got.UncheckedPlugins, append([]UncheckedPolicyPlugin{}, want...)) {
			t.Fatalf("roots %v: %+v, want %s %+v", test.sent, got, status, want)
		}
	}
	// A readable setting that fails its checks still fails without any root.
	invalid, _ := json.Marshal(map[string]any{"rules": map[string]any{"private": map[string]any{"when": `provider.id == "openai"`, "plugins": map[string]any{"textExtraction": "yes", "redaction": plugins["redaction"]}}}})
	if _, err := s.ValidatePolicySources(validationSources([]json.RawMessage{base, json.RawMessage(`null`), invalid}), org, nil); err == nil {
		t.Fatal("a readable plugin beside an unchecked one escaped its check")
	}
	// Ciphertext moved under another plugin does not open.
	swapped, _ := json.Marshal(map[string]any{"encryption": registry, "plugins": map[string]any{"export": plugins["redaction"]}})
	if _, err := s.ValidatePolicySources(validationSources([]json.RawMessage{swapped, json.RawMessage(`null`), json.RawMessage(`{}`)}), org, keys); !errors.Is(err, customerkey.ErrEnvelope) {
		t.Fatalf("redaction ciphertext opened as an export: %v", err)
	}
	if s.keyConfigs.bytes != 0 {
		t.Fatal("temporary validation retained secret plans")
	}
}

func TestPolicyValidationChecksEveryRuleAgainstCombinedLimits(t *testing.T) {
	plugins := func(prefix string) map[string]any {
		literals := make([]string, 600)
		for i := range literals {
			literals[i] = fmt.Sprintf("%s-%04d", prefix, i)
		}
		return map[string]any{"redaction": map[string]any{"literals": []map[string]any{{"values": literals}}}}
	}
	rule := func(name string) map[string]any {
		return map[string]any{"when": `provider.id == "` + name + `"`, "plugins": plugins(name)}
	}
	base, _ := json.Marshal(map[string]any{"plugins": plugins("base")})
	one, _ := json.Marshal(map[string]any{"rules": map[string]any{"azure": rule("azure")}})
	two, _ := json.Marshal(map[string]any{"rules": map[string]any{"azure": rule("azure"), "openai": rule("openai")}})
	empty, none := json.RawMessage(`{}`), json.RawMessage(`null`)
	s := &Service{}
	for _, raw := range [][]json.RawMessage{{base, none, empty}, {empty, none, one}} {
		if _, err := s.ValidatePolicySources(validationSources(raw), "org", nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range [][]json.RawMessage{{base, none, one}, {empty, none, two}} {
		if _, err := s.ValidatePolicySources(validationSources(raw), "org", nil); err == nil {
			t.Fatal("rules that exceed the combined literal limit together were accepted")
		}
	}
}

func BenchmarkEncryptedPolicy(b *testing.B) {
	raw, org, key := encryptedPolicyFixture(b)
	b.Run("cold-validation", func(b *testing.B) {
		s := &Service{}
		for b.Loop() {
			if _, err := s.ValidatePolicySources(validationSources(raw), org, key); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("warm-key-check", func(b *testing.B) {
		s := &Service{}
		sources, err := s.keyConfigs.acquireSources(raw, org, key)
		if err != nil {
			b.Fatal(err)
		}
		config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: sources[0].value}, {Scope: policy.KeyScope, Value: sources[2].value}})
		if err != nil {
			b.Fatal(err)
		}
		s.keyConfigs.put("api", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: config, Digest: "test", sourceRefs: sources}, CredentialsGeneration: 1}, time.Now())
		s.keyConfigs.releaseSources(sources)
		defer s.keyConfigs.close()
		for b.Loop() {
			if _, err := s.cachedOrFetchKeyConfig(context.Background(), "api", nil, nil, "", key, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// A maximum-count fuzzy dictionary exercises the expensive compilation path.
func BenchmarkEncryptedPolicyFullDictionary(b *testing.B) {
	raw, org, key := encryptedPolicyFixture(b)
	literals := make([]string, 1000)
	for i := range literals {
		literals[i] = fmt.Sprintf("%064x", sha256.Sum256([]byte(fmt.Sprint(i))))
	}
	plaintext, _ := json.Marshal(map[string]any{"literals": []map[string]any{{"values": literals, "fuzzy": true}}})
	root, _ := base64.RawURLEncoding.DecodeString("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	envelope := sealTestEnvelope(b, root, key["default"].ID(), org, "plugins/redaction", string(plaintext))
	raw[0], _ = json.Marshal(map[string]any{"encryption": map[string]any{"keys": map[string]string{"default": key["default"].ID()}}, "plugins": map[string]any{"redaction": map[string]any{"encrypted": json.RawMessage(envelope)}}})
	s := &Service{}
	b.SetBytes(int64(len(plaintext)))
	for b.Loop() {
		if _, err := s.ValidatePolicySources(validationSources(raw), org, key); err != nil {
			b.Fatal(err)
		}
	}
}

// A check that sends no keys opens nothing, so it says what is wrong with the readable settings
// that it sends.
func TestCheckWithoutKeysNamesWhatIsWrong(t *testing.T) {
	validation := &Service{}
	check := func(plugins string) (*PolicyValidation, error) {
		return validation.ValidatePolicySources(validationSources([]json.RawMessage{json.RawMessage(`{"plugins":` + plugins + `}`), json.RawMessage(`null`), json.RawMessage(`{}`)}), "test-organization", nil)
	}
	if result, err := check(`{"redaction":{"email_address":true,"literals":[{"values":["Project Falcon"]}]}}`); err != nil || result.Status != "valid" || len(result.UncheckedPlugins) != 0 {
		t.Fatalf("readable settings were not checked: %+v %v", result, err)
	}
	if _, err := check(`{"redaction":{"email_adress":true}}`); !errors.Is(err, policy.ErrInvalidConfig) || !strings.HasSuffix(err.Error(), ": unknown redaction preset email_adress") {
		t.Fatalf("an unknown preset was not named: %v", err)
	}
}

func validationSources(raw []json.RawMessage) []PolicyValidationSource {
	var result []PolicyValidationSource
	for i, scope := range []policy.Scope{policy.OrganizationScope, policy.GrantScope, policy.KeyScope} {
		if i >= len(raw) {
			break
		}
		if i == 1 && string(raw[i]) == "null" {
			continue
		}
		result = append(result, PolicyValidationSource{PolicyValidationReference: PolicyValidationReference{Scope: scope}, Config: raw[i]})
	}
	return result
}
