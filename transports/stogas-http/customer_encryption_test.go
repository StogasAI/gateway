package stogashttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func TestEncryptionKeyIsValidatedAndRemoved(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want error
	}{
		{"valid", `{"providers":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}`, nil},
		{"invalid", `{"providers":"bad"}`, customerkey.ErrKey},
		{"empty", `{}`, nil},
		{"string", `"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`, customerkey.ErrKey},
		{"invalid label", `{"__proto__":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}`, customerkey.ErrKey},
		{"null", `null`, customerkey.ErrKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := map[string]json.RawMessage{"encryption_keys": json.RawMessage(test.raw), "model": json.RawMessage(`"test"`)}
			key, err := takeEncryptionKeys(fields)
			defer key.Clear()
			if !errors.Is(err, test.want) {
				t.Fatal(err)
			}
			if _, ok := fields["encryption_keys"]; ok || len(fields) != 1 {
				t.Fatal("key forwarded")
			}
		})
	}
	key, err := takeEncryptionKeys(map[string]json.RawMessage{"model": json.RawMessage(`"test"`)})
	if key != nil || err != nil {
		t.Fatal("requests without customer encryption must remain valid")
	}
}

// The log lists the roots that a request needs, so a request can need at most
// customerkey.MaxRequestKeys of them, however many its pairs repeat.
func TestRequestNeedsAtMostTheKeysItsLogLists(t *testing.T) {
	var selections []billing.CredentialSelection
	var pairs []catalog.PlannedPair
	for i := range customerkey.MaxRequestKeys + 1 {
		id := fmt.Sprintf("%064x", i)
		selections = append(selections, billing.CredentialSelection{Mode: "encrypted", Credential: &billing.CachedCredential{EncryptionKeyID: id}})
		pairs = append(pairs, catalog.PlannedPair{Provider: schemas.OpenAI, Credential: i, Policy: &policy.Config{RequiredEncryptionKeys: []string{id}}})
	}
	keyConfig := &billing.KeyConfigSnapshot{Credentials: map[string][]billing.CredentialSelection{"openai": selections}}
	roots, err := neededRoots(keyConfig, pairs[:customerkey.MaxRequestKeys])
	if err != nil || len(roots) != customerkey.MaxRequestKeys || roots[0] != fmt.Sprintf("%064x", 0) {
		t.Fatalf("roots %v, %v; want the %d distinct roots, sorted", roots, err, customerkey.MaxRequestKeys)
	}
	if roots, err := neededRoots(keyConfig, pairs); roots != nil || !errors.Is(err, billing.ErrRequestKeys) {
		t.Fatalf("roots %v, %v; want %v", roots, err, billing.ErrRequestKeys)
	}
}
