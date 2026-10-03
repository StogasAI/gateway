package billing

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func credentialPolicySnapshot(t testing.TB, cache *keyConfigCache, organization string, organizationPolicy json.RawMessage, credentials map[string][]json.RawMessage) *KeyConfigSnapshot {
	t.Helper()
	records := []policySourceRecord{
		{PolicyVersion: PolicyVersion{Scope: policy.OrganizationScope, ID: organization, Revision: 1}, Source: organizationPolicy},
		{PolicyVersion: PolicyVersion{Scope: policy.KeyScope, ID: "key", Revision: 1}, Source: json.RawMessage(`null`)},
	}
	sources, err := cache.acquireSourceDelta(records, organization, policySourcePins{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.releaseSources(sources)
	versions := PolicyVersions{records[0].PolicyVersion, records[1].PolicyVersion}
	values := []policy.ScopedSource{{Scope: policy.OrganizationScope, Value: sources[0].value}, {Scope: policy.KeyScope, Value: sources[1].value}}
	config, err := policy.ComposeSources(values)
	if err != nil {
		t.Fatal(err)
	}
	selections := map[string][]CredentialSelection{"chutes": {{Mode: "managed"}}}
	for provider, sources := range credentials {
		for index, source := range sources {
			id := fmt.Sprintf("credential-%s-%d", provider, index)
			selections[provider] = append(selections[provider], CredentialSelection{Mode: "stored", ID: id, Credential: &CachedCredential{ID: id, OrganizationID: organization, Provider: provider, Kind: "stored", Enabled: true, EncryptedSecret: "ciphertext", Policy: credentialPolicyRecord{
				policySourceRecord: policySourceRecord{PolicyVersion: PolicyVersion{Scope: policy.CredentialScope, ID: id, Revision: 1}, Source: source}, Enabled: true,
			}}})
		}
	}

	return cache.put("key", &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: config, Digest: policy.ChainDigest(values), Versions: &versions, sourceRefs: sources}, Claims: &APIKeyClaims{OrganizationID: organization, KeyID: "key"}, Generation: 1, CredentialsGeneration: 1, Credentials: selections}, time.Now())
}

func TestCredentialPolicyCacheIsolationAndEviction(t *testing.T) {
	var cache keyConfigCache
	literal := func(text string) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"plugins": map[string]any{"stogasRedaction": map[string]any{"literals": []any{map[string]any{"values": []string{text}}}}}})
		return raw
	}
	snapshot := credentialPolicySnapshot(t, &cache, "org", literal("ROOT_PRIVATE"), map[string][]json.RawMessage{"openai": {literal("OPENAI_PRIVATE")}, "azure": {literal("AZURE_PRIVATE")}})
	selected, err := snapshot.PolicyForCredential("openai", 0, nil, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(*selected.Versions) != 3 || (*selected.Versions)[1].ID != "credential-openai-0" || snapshot.credentialPolicies["credential-azure-0"] != nil {
		t.Fatal("included an unselected credential")
	}
	plan, err := selected.RedactionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]json.RawMessage{"input": json.RawMessage(`"ROOT_PRIVATE OPENAI_PRIVATE AZURE_PRIVATE"`)}
	if err := redaction.NewWithPolicy(plan).RedactRequestFields(raw, redaction.SurfaceResponses, nil); err != nil || strings.Contains(string(raw["input"]), "ROOT_PRIVATE") || strings.Contains(string(raw["input"]), "OPENAI_PRIVATE") || !strings.Contains(string(raw["input"]), "AZURE_PRIVATE") {
		t.Fatalf("wrong combined dictionary: %s %v", raw["input"], err)
	}
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			value, err := snapshot.PolicyForCredential("openai", 0, nil, time.Now(), nil)
			if err != nil || value != selected {
				t.Errorf("warm combination changed: %v", err)
			}
		})
	}
	workers.Wait()
	pins := cache.pinSourcesForClaims(snapshot.Claims, snapshot)
	if pins.known["credential:credential-openai-0"] != 1 || pins.known["credential:credential-azure-0"] != 0 {
		t.Fatal("wrong credential delta hints")
	}
	cache.releaseSources(pins.sources)
	cache.remove("key")
	if cache.bytes != 0 {
		t.Fatalf("eviction retained %d bytes", cache.bytes)
	}
	// A different candidate may be prepared by an already admitted HTTP request.
	other, err := snapshot.PolicyForCredential("azure", 0, nil, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.RedactionPolicy(); err != nil || cache.bytes != 0 || len(cache.entries) != 0 {
		t.Fatalf("detached preparation repopulated the cache: %v, %d bytes", err, cache.bytes)
	}
	if retained, err := selected.RedactionPolicy(); err != nil || retained != plan {
		t.Fatal("eviction broke in-flight dictionary")
	}
}

func TestUnusedEncryptedCredentialPolicyDoesNotRequireItsRoot(t *testing.T) {
	raw, organization, key := encryptedPolicyFixture(t)
	var source map[string]json.RawMessage
	if err := json.Unmarshal(raw[0], &source); err != nil {
		t.Fatal(err)
	}
	delete(source, "encryption")
	encrypted, _ := json.Marshal(source)
	org, _ := json.Marshal(map[string]any{"encryption": map[string]any{"keys": map[string]string{"default": key["default"].ID()}}})
	var cache keyConfigCache
	snapshot := credentialPolicySnapshot(t, &cache, organization, org, map[string][]json.RawMessage{"openai": {encrypted}, "azure": {json.RawMessage(`null`)}})
	defer cache.close()
	for _, provider := range []string{"chutes", "azure"} {
		if _, err := snapshot.PolicyForCredential(provider, 0, nil, time.Now(), nil); err != nil {
			t.Fatalf("unused encrypted policy blocked %s: %v", provider, err)
		}
	}
	selected, err := snapshot.PolicyForCredential("openai", 0, nil, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	active, err := selected.Config.Activate(conditionalPolicyValues{})
	if err != nil {
		t.Fatal(err)
	}
	if len(active.ActiveEncryptedPlugins) != 1 || selected.Config.Plugins != nil || cache.planStats.Builds != 0 {
		t.Fatal("candidate enumeration opened encrypted plugins")
	}
	for range 2 {
		if _, err := snapshot.ActiveRedactionPolicy(active, nil); !errors.Is(err, customerkey.ErrKey) {
			t.Fatalf("selected encrypted plugin bypassed its root: %v", err)
		}
		if _, err := snapshot.ActiveRedactionPolicy(active, key); err != nil {
			t.Fatal(err)
		}
	}
	if cache.planStats.Builds != 1 {
		t.Fatal("warm selected plugin was rebuilt")
	}
	if _, err := snapshot.PolicyForCredential("azure", 0, nil, time.Now(), nil); err != nil {
		t.Fatal("unlock altered another candidate", err)
	}
}

func TestSameProviderCredentialPolicyIsolationAndSharing(t *testing.T) {
	var cache keyConfigCache
	snapshot := credentialPolicySnapshot(t, &cache, "org", json.RawMessage(`null`), map[string][]json.RawMessage{
		"openai": {
			json.RawMessage(`{"plugins":{"stogasRedaction":{"literals":[{"values":["FIRST_SECRET"]}]}}}`),
			json.RawMessage(`{"plugins":{"stogasRedaction":{"literals":[{"values":["SECOND_SECRET"]}]}}}`),
		},
	})
	defer cache.close()
	var policies [2]*PolicySnapshot
	for index := range policies {
		selected, err := snapshot.PolicyForCredential("openai", index, nil, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		policies[index] = selected
		if (*selected.Versions)[1].ID != fmt.Sprintf("credential-openai-%d", index) {
			t.Fatal("policy revisions identify a different credential")
		}
		plan, err := selected.RedactionPolicy()
		if err != nil {
			t.Fatal(err)
		}
		raw := map[string]json.RawMessage{"input": json.RawMessage(`"FIRST_SECRET SECOND_SECRET"`)}
		if err := redaction.NewWithPolicy(plan).RedactRequestFields(raw, redaction.SurfaceResponses, nil); err != nil {
			t.Fatal(err)
		}
		remaining := "SECOND_SECRET"
		removed := "FIRST_SECRET"
		if index == 1 {
			remaining, removed = removed, remaining
		}
		if !strings.Contains(string(raw["input"]), remaining) || strings.Contains(string(raw["input"]), removed) {
			t.Fatalf("credential %d transformed another credential's literals: %s", index, raw["input"])
		}
	}
	if policies[0] == policies[1] {
		t.Fatal("different credential policies share the same combination")
	}
	copy := cache.put("other-key", snapshot, time.Now())
	for index := range policies {
		if copy.Credentials["openai"][index].Credential != snapshot.Credentials["openai"][index].Credential {
			t.Fatal("identical credential ciphertext and metadata were copied between keys")
		}
		selected, err := copy.PolicyForCredential("openai", index, nil, time.Now(), nil)
		if err != nil || selected.Config != policies[index].Config {
			t.Fatalf("credential %d did not share its immutable compiled policy: %v", index, err)
		}
	}
	cache.remove("key")
	cache.remove("other-key")
	if cache.bytes != 0 || len(cache.credentials) != 0 {
		t.Fatal("credential alternatives survived final eviction")
	}
}

func TestCredentialSourcePoolRestoresOnlyValidReferences(t *testing.T) {
	source := json.RawMessage(`{"input":{"asciiOnly":true}}`)
	index := func(value int) *int { return &value }
	for _, test := range []struct {
		name  string
		index *int
		raw   json.RawMessage
		valid bool
	}{
		{"shared source", index(0), nil, true},
		{"explicit empty", nil, json.RawMessage(`null`), true},
		{"negative index", index(-1), nil, false},
		{"missing index", index(1), nil, false},
		{"two source values", index(0), json.RawMessage(`null`), false},
		{"unpinned omission", nil, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := &CachedCredential{Policy: credentialPolicyRecord{SourceIndex: test.index, policySourceRecord: policySourceRecord{Source: test.raw}}}
			selections := map[string][]CredentialSelection{"openai": {{Credential: record}}}
			err := restoreCredentialPolicySources(selections, policySourcePins{}, []json.RawMessage{source})
			if (err == nil) != test.valid {
				t.Fatalf("restoration: %v", err)
			}
			if test.valid && record.Policy.SourceIndex != nil {
				t.Fatal("wire index escaped restoration")
			}
			if test.valid && test.index != nil && &record.Policy.Source[0] != &source[0] {
				t.Fatal("restoration copied the shared document")
			}
		})
	}
}

func TestDifferentCredentialIdentitiesShareOnePolicyDocument(t *testing.T) {
	var cache keyConfigCache
	defer cache.close()
	const count = 128
	policies := make([]json.RawMessage, count)
	for index := range policies {
		policies[index] = json.RawMessage(`{"input":{"asciiOnly":true}}`)
	}
	snapshot := credentialPolicySnapshot(t, &cache, "org", json.RawMessage(`null`), map[string][]json.RawMessage{"openai": policies})
	first := snapshot.Credentials["openai"][0].Credential
	var workers sync.WaitGroup
	for index := range policies {
		workers.Go(func() {
			value, err := snapshot.PolicyForCredential("openai", index, nil, time.Now(), nil)
			if err != nil || value == nil || value.Config.Input == nil || !value.Config.Input.ASCIIOnly {
				t.Errorf("credential %d policy: %v", index, err)
			}
		})
	}
	workers.Wait()
	for _, selection := range snapshot.Credentials["openai"] {
		if selection.Credential.policySource != first.policySource {
			t.Fatal("equal policies retained different source documents")
		}
	}
	if len(cache.credentialSources) != 1 {
		t.Fatal("equal credential policies were not shared")
	}
	if snapshot.MemoryBytes()+int64(len("key")) != cache.bytes {
		t.Fatal("request memory accounting lost or duplicated shared credential content")
	}
	cache.remove("key")
	if cache.bytes != 0 || len(cache.credentialSources) != 0 {
		t.Fatal("shared document survived its final credential")
	}
	if snapshot.MemoryBytes() == 0 {
		t.Fatal("cache eviction hid memory retained by an active request")
	}
}

func TestCredentialAlternativesShareOneCompilationBudget(t *testing.T) {
	var alternatives []json.RawMessage
	for choice := range 3 {
		models := make([]string, 8000)
		for index := range models {
			models[index] = fmt.Sprintf("model-%d-%08d-abcdefghij", choice, index)
		}
		raw, err := json.Marshal(map[string]any{"routing": map[string]any{"allowedCatalogNodes": map[string]any{"models": models}}})
		if err != nil {
			t.Fatal(err)
		}
		alternatives = append(alternatives, raw)
	}
	for _, warm := range []bool{false, true} {
		t.Run(fmt.Sprintf("warm_%t", warm), func(t *testing.T) {
			var cache keyConfigCache
			defer cache.close()
			snapshot := credentialPolicySnapshot(t, &cache, "org", json.RawMessage(`null`), map[string][]json.RawMessage{"openai": alternatives})
			if warm {
				for index := range alternatives {
					if _, err := snapshot.PolicyForCredential("openai", index, nil, time.Now(), nil); err != nil {
						t.Fatal(err)
					}
				}
			}
			var budget policy.SourceBudget
			for index := range alternatives {
				_, err := snapshot.PolicyForCredential("openai", index, nil, time.Now(), &budget)
				if index < 2 && err != nil || index == 2 && !errors.Is(err, policy.ErrSourceBudget) {
					t.Fatalf("alternative %d: %v", index, err)
				}
			}
			if !warm && snapshot.credentialPolicies["credential-openai-2"] != nil {
				t.Fatal("compiled an alternative after the content budget was exhausted")
			}
			if _, err := snapshot.PolicyForCredential("chutes", 0, nil, time.Now(), &budget); !errors.Is(err, policy.ErrSourceBudget) {
				t.Fatalf("an empty alternative bypassed the exhausted budget: %v", err)
			}
		})
	}
}
