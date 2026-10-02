package customerkey

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestWebCryptoInteroperabilityAndBinding(t *testing.T) {
	raw, err := os.ReadFile("testdata/webcrypto.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Root, OrganizationID, Plaintext string
		Envelope                        Envelope
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := Parse(fixture.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Clear()
	if !key.Matches(fixture.Envelope.KeyID) {
		t.Fatal("key identifier differs from Web Crypto")
	}
	opened, err := key.Open(fixture.Envelope, fixture.OrganizationID, "plugins", 256<<10)
	if err != nil || string(opened) != fixture.Plaintext {
		t.Fatalf("Web Crypto decryption failed: %v", err)
	}
	for name, change := range map[string]func(*Envelope){
		"key identifier":  func(e *Envelope) { e.KeyID = strings.Repeat("a", 64) },
		"version":         func(e *Envelope) { e.Version++ },
		"salt":            func(e *Envelope) { e.Salt = strings.Repeat("A", 43) },
		"nonce":           func(e *Envelope) { e.Nonce = strings.Repeat("A", 16) },
		"ciphertext":      func(e *Envelope) { e.Blob = "A" + e.Blob[1:] },
		"short tag":       func(e *Envelope) { e.Blob = "AA" },
		"padded encoding": func(e *Envelope) { e.Blob += "=" },
	} {
		t.Run(name, func(t *testing.T) {
			e := fixture.Envelope
			change(&e)
			if _, err := key.Open(e, fixture.OrganizationID, "plugins", 256<<10); err == nil {
				t.Fatal("tampered envelope opened")
			}
		})
	}
	for _, scope := range [][2]string{{"another-org", "plugins"}, {fixture.OrganizationID, "byok/openai"}, {"", "plugins"}} {
		if _, err := key.Open(fixture.Envelope, scope[0], scope[1], 256<<10); err == nil {
			t.Fatal("scope substitution opened ciphertext")
		}
	}
	if _, err := key.Open(fixture.Envelope, fixture.OrganizationID, "plugins", len(fixture.Plaintext)-1); err == nil {
		t.Fatal("plaintext size bound was bypassed")
	}
	var absent *Key
	if _, err := absent.Open(fixture.Envelope, fixture.OrganizationID, "plugins", 256<<10); !errors.Is(err, ErrKey) {
		t.Fatal("missing key was accepted")
	}
	key.Clear()
	if key.Matches(fixture.Envelope.KeyID) {
		t.Fatal("cleared key remained usable")
	}
	for _, raw := range []string{"", fixture.Root + "=", strings.Repeat("A", 42), strings.Repeat("A", 44), strings.Repeat("A", 42) + "B"} {
		if _, err := Parse(raw); err == nil {
			t.Fatal("invalid root encoding accepted")
		}
	}
}
