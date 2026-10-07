package billing

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	source, _ := json.Marshal(map[string]any{"encryption": map[string]any{"keys": map[string]string{"default": key["default"].ID()}}, "plugins": map[string]any{"encrypted": fixture.Envelope}})
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
	snapshot := s.keyConfigs.put("api", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: config, Digest: policy.ChainDigest([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: sources[0].value}, {Scope: policy.KeyScope, Value: sources[2].value}}), sourceRefs: sources}, Generation: 1}, time.Now())
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
	if err != nil || unchecked.Status != "partial" || len(unchecked.UncheckedPlugins) != 1 || unchecked.UncheckedPlugins[0].Rule != "private" {
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
	snapshot := cache.put("api", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: config, Digest: policy.ChainDigest(sources), sourceRefs: refs}, Claims: &APIKeyClaims{OrganizationID: org}, Generation: 1}, time.Now())
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

func TestOptionalValidationDistinguishesUncheckedFromInvalid(t *testing.T) {
	raw, org, key := encryptedPolicyFixture(t)
	s := &Service{}
	for _, supplied := range []customerkey.Keys{nil, key} {
		got, err := s.ValidatePolicySources(validationSources(raw), org, supplied)
		if err != nil {
			t.Fatal(err)
		}
		if supplied == nil {
			if got.Status != "partial" || len(got.UncheckedPlugins) != 1 || got.UncheckedPlugins[0].Scope != policy.OrganizationScope {
				t.Fatalf("opaque content certified: %+v", got)
			}
		} else if got.Status != "valid" || len(got.UncheckedPlugins) != 0 {
			t.Fatalf("valid content not checked: %+v", got)
		}
	}
	bad := append([]json.RawMessage(nil), raw...)
	bad[2] = json.RawMessage(`{"plugins":{"stogasRedaction":{"customPattern":"("}}}`)
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
		s.keyConfigs.put("api", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: config, Digest: "test", sourceRefs: sources}, Generation: 1}, time.Now())
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
	plaintext, _ := json.Marshal(map[string]any{"stogasRedaction": map[string]any{"literals": []map[string]any{{"values": literals, "fuzzy": true}}}})
	root, _ := base64.RawURLEncoding.DecodeString("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	salt, nonce := make([]byte, 32), make([]byte, 12)
	context := "stogas.customer-content.v1\x00" + org + "\x00plugins\x00" + key["default"].ID()
	derived, err := hkdf.Key(sha256.New, root, salt, context, 32)
	if err != nil {
		b.Fatal(err)
	}
	block, _ := aes.NewCipher(derived)
	aead, _ := cipher.NewGCM(block)
	envelope := customerkey.Envelope{Version: 1, KeyID: key["default"].ID(), Salt: base64.RawURLEncoding.EncodeToString(salt), Nonce: base64.RawURLEncoding.EncodeToString(nonce), Blob: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, []byte(context)))}
	raw[0], _ = json.Marshal(map[string]any{"encryption": map[string]any{"keys": map[string]string{"default": key["default"].ID()}}, "plugins": map[string]any{"encrypted": envelope}})
	s := &Service{}
	b.SetBytes(int64(len(plaintext)))
	for b.Loop() {
		if _, err := s.ValidatePolicySources(validationSources(raw), org, key); err != nil {
			b.Fatal(err)
		}
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
