package billing

import (
	"encoding/json"
	"errors"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
	"strings"
	"testing"
)

func TestCredentialSelectionRequiresTheOrganizationKey(t *testing.T) {
	const id = "01900000-0000-7000-8000-000000000001"
	key, err := customerkey.Parse("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatal(err)
	}
	defer key.Clear()
	wrong, _ := customerkey.Parse(strings.Repeat("A", 43))
	defer wrong.Clear()
	registered := CredentialSelection{Mode: "encrypted", ID: id, Credential: &CachedCredential{ID: id, EncryptionKeyID: key.ID()}}
	for _, tc := range []struct {
		name      string
		selection CredentialSelection
		key       customerkey.Keys
		want      error
	}{
		{"matching root", registered, customerkey.Keys{"default": key}, nil},
		{"missing root", registered, nil, customerkey.ErrKey},
		{"wrong root", registered, customerkey.Keys{"default": wrong}, customerkey.ErrKey},
		{"missing credential", CredentialSelection{Mode: "encrypted", ID: id}, customerkey.Keys{"default": key}, customerkey.ErrKey},
		{"missing assignment", CredentialSelection{Mode: "encrypted", Credential: registered.Credential}, customerkey.Keys{"default": key}, customerkey.ErrKey},
		{"managed plugins can use root", CredentialSelection{Mode: "managed"}, customerkey.Keys{"default": key}, nil},
		{"stored plugins can use root", CredentialSelection{Mode: "stored", ID: id}, customerkey.Keys{"default": key}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: &policy.Config{EncryptionKeys: map[string]string{"default": key.ID()}}}, Credentials: map[string][]CredentialSelection{"chutes": {tc.selection}}}
			selection, err := snapshot.credentialSelection("chutes", 0, tc.key)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if err == nil && selection.ID != tc.selection.ID {
				t.Fatal("changed credential assignment")
			}
		})
	}
}

func TestEncryptedCredentialEligibilityUsesItsOwnSuppliedRoot(t *testing.T) {
	keys, err := customerkey.ParseKeys(map[string]string{
		"providers": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		"redaction": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Clear()
	openAIID, chutesID := "01900000-0000-7000-8000-000000000001", "01900000-0000-7000-8000-000000000002"
	snapshot := &KeyConfigSnapshot{
		Claims: &APIKeyClaims{OrganizationID: "org"},
		PolicySnapshot: PolicySnapshot{Config: &policy.Config{EncryptionKeys: map[string]string{
			"providers": keys["providers"].ID(), "redaction": keys["redaction"].ID(),
		}}},
		Credentials: map[string][]CredentialSelection{
			"openai":    {{Mode: "encrypted", ID: openAIID, Credential: &CachedCredential{ID: openAIID, EncryptionKeyID: keys["providers"].ID(), EncryptedSecret: "invalid ciphertext"}}},
			"chutes":    {{Mode: "encrypted", ID: chutesID, Credential: &CachedCredential{ID: chutesID, EncryptionKeyID: keys["redaction"].ID()}}},
			"anthropic": {{Mode: "stored"}},
		},
	}
	for _, item := range []struct {
		keys           customerkey.Keys
		openai, chutes bool
	}{
		{nil, false, false},
		{customerkey.Keys{"providers": keys["providers"]}, true, false},
		{customerkey.Keys{"redaction": keys["redaction"]}, false, true},
		{keys, true, true},
		{customerkey.Keys{"wrong_label": keys["providers"]}, false, false},
	} {
		available := snapshot.AvailableCredentials(item.keys)
		if (len(available["openai"]) != 0) != item.openai || (len(available["chutes"]) != 0) != item.chutes || len(available["anthropic"]) == 0 {
			t.Fatal("credential eligibility ignored its registered label or required root")
		}
	}
}

func TestCredentialSnapshotRejectsConfusedScopeAndMaterial(t *testing.T) {
	claims := &APIKeyClaims{OrganizationID: "org"}
	valid := func() map[string][]CredentialSelection {
		const id = "01900000-0000-7000-8000-000000000001"
		return map[string][]CredentialSelection{"openai": {{Mode: "stored", ID: id, Credential: &CachedCredential{
			ID: id, OrganizationID: "org", Provider: "openai", Kind: "stored", Enabled: true, EncryptedSecret: "ciphertext",
			Policy: credentialPolicyRecord{policySourceRecord: policySourceRecord{PolicyVersion: PolicyVersion{Scope: policy.CredentialScope, ID: id, Revision: 1}, Source: json.RawMessage(`null`)}, Enabled: true},
		}}}}
	}
	if err := validateCredentials(claims, valid()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CredentialSelection){
		"another organization":        func(s *CredentialSelection) { s.Credential.OrganizationID = "other" },
		"another provider":            func(s *CredentialSelection) { s.Credential.Provider = "chutes" },
		"another identifier":          func(s *CredentialSelection) { s.Credential.ID = "01900000-0000-7000-8000-000000000002" },
		"noncanonical identifier":     func(s *CredentialSelection) { s.ID = "urn:uuid:" + s.ID },
		"missing material":            func(s *CredentialSelection) { s.Credential = nil },
		"missing selected identifier": func(s *CredentialSelection) { s.ID = "" },
		"wrong kind":                  func(s *CredentialSelection) { s.Credential.Kind = "encrypted" },
		"empty ciphertext":            func(s *CredentialSelection) { s.Credential.EncryptedSecret = "" },
		"mixed secret forms":          func(s *CredentialSelection) { s.Credential.EncryptionKeyID = strings.Repeat("a", 64) },
		"unknown mode":                func(s *CredentialSelection) { s.Mode = "automatic" },
		"managed secret injection":    func(s *CredentialSelection) { s.Mode = "managed" },
		"any secret injection":        func(s *CredentialSelection) { s.Mode = "any" },
	} {
		t.Run(name, func(t *testing.T) {
			credentials := valid()
			selection := credentials["openai"][0]
			change(&selection)
			credentials["openai"][0] = selection
			if validateCredentials(claims, credentials) == nil {
				t.Fatal("accepted invalid credential snapshot")
			}
		})
	}
	if validateCredentials(nil, valid()) == nil {
		t.Fatal("accepted credentials without a caller")
	}
	if validateCredentials(claims, map[string][]CredentialSelection{"unknown": {{Mode: "any"}}}) == nil {
		t.Fatal("accepted unknown provider")
	}
	for _, provider := range []string{"openai", "anthropic", "chutes", "azure"} {
		for _, mode := range []string{"any", "managed", "encrypted"} {
			want := mode == "managed" && provider == "chutes"
			err := validateCredentials(claims, map[string][]CredentialSelection{provider: {{Mode: mode}}})
			if (err == nil) != want {
				t.Fatalf("unassigned %s/%s accepted=%t, want %t", provider, mode, err == nil, want)
			}
		}
	}
	credentials := valid()
	selection := credentials["openai"][0]
	selection.Mode, selection.Credential.Kind = "encrypted", "encrypted"
	selection.Credential.EncryptedSecret, selection.Credential.EncryptionKeyID = "encrypted-envelope", strings.Repeat("a", 64)
	credentials["openai"][0] = selection
	if err := validateCredentials(claims, credentials); err != nil {
		t.Fatal(err)
	}
	selection.Credential.EncryptionKeyID = strings.Repeat("a", 128)
	if validateCredentials(claims, credentials) == nil {
		t.Fatal("accepted invalid key identifier")
	}
}

func TestCredentialBindingsRejectMalformedSnapshotsDuringDecode(t *testing.T) {
	for _, raw := range []string{`{"bindings":[}`, `{"bindings":{}}`, `{"bindings":[{"modelDeprecationAt":"invalid"}]}`} {
		var credential CachedCredential
		if json.Unmarshal([]byte(raw), &credential) == nil {
			t.Fatal("accepted malformed credential target metadata")
		}
	}
}

func TestPrepareCredentialDecryptsLocallyAndBindsTheSnapshot(t *testing.T) {
	decryptor, err := newByokDecryptor("test-master-secret-0123456789-abcdef")
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{byok: decryptor}
	const id = "0198f4cc-6c25-7000-8000-000000000001"
	snapshot := &KeyConfigSnapshot{
		Claims:         &APIKeyClaims{OrganizationID: "org-test"},
		PolicySnapshot: PolicySnapshot{Config: &policy.Config{}},
		Credentials: map[string][]CredentialSelection{"openai": {{Mode: "stored", ID: id, Credential: &CachedCredential{
			ID: id, OrganizationID: "org-test", Provider: "openai", Kind: "stored", Enabled: true,
			EncryptedSecret: "v1.AAECAwQFBgcICQoL.M5UHaC_cZlPfCGItSfcUCDWzgSAaM5hTU7KSERrvi3SeVgsdZ4HR",
		}}}},
	}
	prepared, err := service.PrepareCredential(snapshot, "openai", 0, nil)
	if err != nil || prepared == nil {
		t.Fatalf("prepare failed: %v", err)
	}
	if prepared.snapshot != snapshot || prepared.provider != "openai" || prepared.selection.ID != id || prepared.Secret != "sk-upstream-test-secret" {
		t.Fatal("prepared credential lost its secret or authority binding")
	}
	if !prepared.UsesBYOK() {
		t.Fatal("prepared customer credential cannot use provider file IDs")
	}
	prepared.Clear()
	if prepared.Secret != "" || prepared.snapshot != nil || prepared.UsesBYOK() {
		t.Fatal("request cleanup retained credential")
	}
	snapshot.Credentials["chutes"] = []CredentialSelection{{Mode: "managed"}}
	credential := snapshot.Credentials["openai"][0].Credential
	if available := snapshot.AvailableCredentials(nil); len(available["openai"]) != 1 || len(available["chutes"]) != 1 || len(available["azure"]) != 0 || len(available["anthropic"]) != 0 {
		t.Fatalf("configured providers: %v", available)
	}
	credential.Enabled = false
	if len(snapshot.AvailableCredentials(nil)["openai"]) == 0 {
		t.Fatal("credential failure silently changed initial provider eligibility")
	}
	if _, err := service.PrepareCredential(snapshot, "openai", 0, nil); !errors.Is(err, policyResultErrors["credential_disabled"]) {
		t.Fatal("disabled credential prepared")
	}
	credential.Enabled = true
	credential.EncryptedSecret = "invalid"
	if _, err := service.PrepareCredential(snapshot, "openai", 0, nil); !errors.Is(err, ErrByok) {
		t.Fatal("corrupt credential prepared")
	}
	for _, provider := range []string{"openai", "azure", "anthropic", "chutes"} {
		delete(snapshot.Credentials, "openai")
		prepared, err := service.PrepareCredential(snapshot, provider, 0, nil)
		if provider == "chutes" {
			if err != nil || prepared.Secret != "" || prepared.UsesBYOK() {
				t.Fatal("managed credential preparation failed")
			}
		} else if !errors.Is(err, ErrByokRequired) {
			t.Fatal("missing BYOK accepted")
		}
	}
}
