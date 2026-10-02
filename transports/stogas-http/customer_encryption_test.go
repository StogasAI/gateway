package stogashttp

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
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
