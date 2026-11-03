package billing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
)

func byokCheckTestClaims(t *testing.T, now time.Time) byokCheckGrantClaims {
	t.Helper()
	return byokCheckGrantClaims{
		Audience:     byokCheckGrantAudience,
		Byok:         mustUUIDV7(t),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		IssuedAt:     now.Unix(),
		Issuer:       inferenceTokenIssuer,
		JWTID:        uuid.NewString(),
		Organization: mustUUIDV7(t),
		Scope:        byokCheckGrantScope,
		Subject:      mustUUIDV7(t),
	}
}

func TestParseByokCheckGrant(t *testing.T) {
	key := newInferenceTokenTestKey(t)
	now := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	claims := byokCheckTestClaims(t, now)
	grant, err := parseByokCheckGrant(byokCheckGrantPrefix+signDashboardToken(t, key, claims), key.public, now)
	if err != nil {
		t.Fatal(err)
	}
	if *grant != (ByokCheckGrant{ActorUserID: claims.Subject, OrganizationID: claims.Organization, ByokID: claims.Byok}) {
		t.Fatalf("grant = %#v", grant)
	}
	// Within the clock skew a grant that Control issued a moment ahead still verifies.
	if _, err := parseByokCheckGrant(byokCheckGrantPrefix+signDashboardToken(t, key, claims), key.public, now.Add(-20*time.Second)); err != nil {
		t.Fatalf("grant issued within the clock skew: %v", err)
	}

	for name, change := range map[string]func(*byokCheckGrantClaims){
		"another audience":         func(c *byokCheckGrantClaims) { c.Audience = inferenceTokenAudience },
		"another scope":            func(c *byokCheckGrantClaims) { c.Scope = inferenceTokenScope },
		"another issuer":           func(c *byokCheckGrantClaims) { c.Issuer = "https://example.com" },
		"expired":                  func(c *byokCheckGrantClaims) { c.ExpiresAt = now.Unix() },
		"longer than five minutes": func(c *byokCheckGrantClaims) { c.ExpiresAt = now.Add(5*time.Minute + time.Second).Unix() },
		"issued in the future": func(c *byokCheckGrantClaims) {
			c.IssuedAt = now.Add(time.Minute).Unix()
			c.ExpiresAt = now.Add(2 * time.Minute).Unix()
		},
		"ending before it starts": func(c *byokCheckGrantClaims) { c.ExpiresAt = c.IssuedAt },
		"credential not UUIDv7":   func(c *byokCheckGrantClaims) { c.Byok = uuid.NewString() },
		"uppercase credential":    func(c *byokCheckGrantClaims) { c.Byok = strings.ToUpper(c.Byok) },
		"uppercase organization":  func(c *byokCheckGrantClaims) { c.Organization = strings.ToUpper(c.Organization) },
		"nil member":              func(c *byokCheckGrantClaims) { c.Subject = uuid.Nil.String() },
		"missing token ID":        func(c *byokCheckGrantClaims) { c.JWTID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := claims
			change(&changed)
			raw := byokCheckGrantPrefix + signDashboardToken(t, key, changed)
			if _, err := parseByokCheckGrant(raw, key.public, now); !errors.Is(err, ErrByokCheckGrant) {
				t.Fatalf("err = %v, want ErrByokCheckGrant", err)
			}
		})
	}

	t.Run("unknown claim", func(t *testing.T) {
		withExtra := map[string]any{}
		encoded, _ := json.Marshal(claims)
		_ = json.Unmarshal(encoded, &withExtra)
		withExtra["sid"] = mustUUIDV7(t)
		if _, err := parseByokCheckGrant(byokCheckGrantPrefix+signDashboardToken(t, key, withExtra), key.public, now); err == nil {
			t.Fatal("a grant with an unknown claim verified")
		}
	})
	t.Run("another signer", func(t *testing.T) {
		raw := byokCheckGrantPrefix + signDashboardToken(t, newInferenceTokenTestKey(t), claims)
		if _, err := parseByokCheckGrant(raw, key.public, now); err == nil {
			t.Fatal("a grant from another signer verified")
		}
	})
	t.Run("dashboard credential", func(t *testing.T) {
		token := signDashboardToken(t, key, dashboardTokenClaims{
			Audience: inferenceTokenAudience, ExpiresAt: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
			Issuer: inferenceTokenIssuer, JWTID: uuid.NewString(), Scope: inferenceTokenScope,
			SessionID: mustUUIDV7(t), Subject: mustUUIDV7(t),
		})
		for _, raw := range []string{byokCheckGrantPrefix + token, dashboardCredentialPrefix + mustUUIDV7(t) + "." + token} {
			if _, err := parseByokCheckGrant(raw, key.public, now); err == nil {
				t.Fatal("a dashboard credential worked as a check grant")
			}
		}
		// And a grant never works as a dashboard credential.
		grant := signDashboardToken(t, key, claims)
		if _, err := parseDashboardCredential(dashboardCredentialPrefix+mustUUIDV7(t)+"."+grant, key.public, now); err == nil {
			t.Fatal("a check grant worked as a dashboard credential")
		}
	})
	t.Run("without prefix", func(t *testing.T) {
		if _, err := parseByokCheckGrant(signDashboardToken(t, key, claims), key.public, now); err == nil {
			t.Fatal("a grant without its prefix verified")
		}
	})
}

// sealTestEnvelope seals plaintext as stogas encrypt does.
func sealTestEnvelope(t testing.TB, root []byte, keyID, organizationID, purpose, plaintext string) string {
	t.Helper()
	salt, nonce := make([]byte, 32), make([]byte, 12)
	salt[0], nonce[0] = 1, 2
	context := strings.Join([]string{"stogas.customer-content.v1", organizationID, purpose, keyID}, "\x00")
	derived, err := hkdf.Key(sha256.New, root, salt, context, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(customerkey.Envelope{
		Version: 1, KeyID: keyID,
		Salt:  base64.RawURLEncoding.EncodeToString(salt),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Blob:  base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, []byte(plaintext), []byte(context))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestByokCheckTargetOpensAsRequestsDo(t *testing.T) {
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
	}
	otherRoot := make([]byte, 32)
	otherRoot[0] = 9
	encodedRoot, encodedOther := base64.RawURLEncoding.EncodeToString(root), base64.RawURLEncoding.EncodeToString(otherRoot)
	keys := func(t *testing.T, encoded map[string]string) customerkey.Keys {
		t.Helper()
		parsed, err := customerkey.ParseKeys(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	keyID := keys(t, map[string]string{"prod": encodedRoot})["prod"].ID()
	otherID := keys(t, map[string]string{"old": encodedOther})["old"].ID()
	organizationID := mustUUIDV7(t)
	target := func(registered map[string]string, sealed string) *ByokCheckTarget {
		return &ByokCheckTarget{
			Grant:    ByokCheckGrant{ActorUserID: mustUUIDV7(t), OrganizationID: organizationID, ByokID: mustUUIDV7(t)},
			Provider: "openai", EncryptedSecret: sealed, EncryptionKeyID: keyID, Registered: registered,
		}
	}
	sealed := sealTestEnvelope(t, root, keyID, organizationID, "byok/openai", "sk-test-secret")
	both := map[string]string{"prod": keyID, "old": otherID}

	secret, err := target(both, sealed).Open(keys(t, map[string]string{"prod": encodedRoot}))
	if err != nil || secret != "sk-test-secret" {
		t.Fatalf("Open = %q, %v", secret, err)
	}
	// Every key that the check sends must be the one registered under its label.
	if _, err := target(both, sealed).Open(keys(t, map[string]string{"prod": encodedRoot, "old": encodedRoot})); !errors.Is(err, customerkey.ErrKey) {
		t.Fatalf("a key under another key's label: %v", err)
	}
	if _, err := target(both, sealed).Open(keys(t, map[string]string{"staging": encodedRoot})); !errors.Is(err, customerkey.ErrKey) {
		t.Fatalf("a key under an unregistered label: %v", err)
	}
	// Without the key that sealed the credential, the check names its label.
	var missing *customerkey.MissingError
	if _, err := target(both, sealed).Open(keys(t, map[string]string{"old": encodedOther})); !errors.As(err, &missing) || strings.Join(missing.Labels, ",") != "prod" {
		t.Fatalf("missing key: %v", err)
	}
	// A credential sealed with a key that the organization no longer registers never serves requests.
	if _, err := target(map[string]string{"old": otherID}, sealed).Open(keys(t, map[string]string{"old": encodedOther})); !errors.Is(err, ErrByokKeyUnregistered) {
		t.Fatalf("unregistered sealing key: %v", err)
	}
	// The envelope binds the organization and the provider.
	for name, wrong := range map[string]string{
		"another organization": sealTestEnvelope(t, root, keyID, mustUUIDV7(t), "byok/openai", "sk-test-secret"),
		"another provider":     sealTestEnvelope(t, root, keyID, organizationID, "byok/anthropic", "sk-test-secret"),
		"not an envelope":      `{"version":1}`,
	} {
		if _, err := target(both, wrong).Open(keys(t, map[string]string{"prod": encodedRoot})); !errors.Is(err, customerkey.ErrEnvelope) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
