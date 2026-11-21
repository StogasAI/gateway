package billing

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func storedByokTestClaims(t *testing.T, now time.Time) storedByokGrantClaims {
	t.Helper()
	return storedByokGrantClaims{
		Audience:     storedByokGrantAudience,
		Byok:         mustUUIDV7(t),
		ExpiresAt:    now.Add(time.Minute).Unix(),
		IssuedAt:     now.Unix(),
		Issuer:       inferenceTokenIssuer,
		JWTID:        uuid.NewString(),
		Organization: mustUUIDV7(t),
		Provider:     "openai",
		Scope:        StoredByokProbe,
	}
}

func TestParseStoredByokGrant(t *testing.T) {
	key := newInferenceTokenTestKey(t)
	now := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	claims := storedByokTestClaims(t, now)
	grant, err := parseStoredByokGrant(storedByokGrantPrefix+signDashboardToken(t, key, claims), key.public, now)
	if err != nil {
		t.Fatal(err)
	}
	if *grant != (StoredByokGrant{OrganizationID: claims.Organization, ByokID: claims.Byok, Provider: "openai", Scope: StoredByokProbe}) {
		t.Fatalf("grant = %#v", grant)
	}
	// Within the clock skew a grant that Control issued a moment ahead still verifies.
	if _, err := parseStoredByokGrant(storedByokGrantPrefix+signDashboardToken(t, key, claims), key.public, now.Add(-20*time.Second)); err != nil {
		t.Fatalf("grant issued within the clock skew: %v", err)
	}
	accounts := claims
	accounts.Provider, accounts.Scope = "azure", StoredByokAzureAccounts
	if grant, err := parseStoredByokGrant(storedByokGrantPrefix+signDashboardToken(t, key, accounts), key.public, now); err != nil || grant.Scope != StoredByokAzureAccounts {
		t.Fatalf("Azure account listing grant = %#v, %v", grant, err)
	}

	for name, change := range map[string]func(*storedByokGrantClaims){
		"another audience": func(c *storedByokGrantClaims) { c.Audience = byokCheckGrantAudience },
		"another scope":    func(c *storedByokGrantClaims) { c.Scope = byokCheckGrantScope },
		// Gateways check stored credentials themselves, so no grant asks for a check.
		"a check":                   func(c *storedByokGrantClaims) { c.Scope = "check" },
		"account listing of OpenAI": func(c *storedByokGrantClaims) { c.Scope = StoredByokAzureAccounts },
		"unknown provider":          func(c *storedByokGrantClaims) { c.Provider = "mistral" },
		"uppercase provider":        func(c *storedByokGrantClaims) { c.Provider = "OpenAI" },
		"another issuer":            func(c *storedByokGrantClaims) { c.Issuer = "https://example.com" },
		"expired":                   func(c *storedByokGrantClaims) { c.ExpiresAt = now.Unix() },
		"longer than a minute":      func(c *storedByokGrantClaims) { c.ExpiresAt = now.Add(time.Minute + time.Second).Unix() },
		"issued in the future": func(c *storedByokGrantClaims) {
			c.IssuedAt = now.Add(time.Minute).Unix()
			c.ExpiresAt = now.Add(90 * time.Second).Unix()
		},
		"ending before it starts": func(c *storedByokGrantClaims) { c.ExpiresAt = c.IssuedAt },
		"credential not UUIDv7":   func(c *storedByokGrantClaims) { c.Byok = uuid.NewString() },
		"uppercase credential":    func(c *storedByokGrantClaims) { c.Byok = strings.ToUpper(c.Byok) },
		"uppercase organization":  func(c *storedByokGrantClaims) { c.Organization = strings.ToUpper(c.Organization) },
		"nil organization":        func(c *storedByokGrantClaims) { c.Organization = uuid.Nil.String() },
		"missing token ID":        func(c *storedByokGrantClaims) { c.JWTID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := claims
			change(&changed)
			raw := storedByokGrantPrefix + signDashboardToken(t, key, changed)
			if _, err := parseStoredByokGrant(raw, key.public, now); !errors.Is(err, ErrStoredByokGrant) {
				t.Fatalf("err = %v, want ErrStoredByokGrant", err)
			}
		})
	}

	t.Run("unknown claim", func(t *testing.T) {
		withExtra := map[string]any{}
		encoded, _ := json.Marshal(claims)
		_ = json.Unmarshal(encoded, &withExtra)
		withExtra["sub"] = mustUUIDV7(t)
		if _, err := parseStoredByokGrant(storedByokGrantPrefix+signDashboardToken(t, key, withExtra), key.public, now); err == nil {
			t.Fatal("a grant with an unknown claim verified")
		}
	})
	t.Run("another signer", func(t *testing.T) {
		raw := storedByokGrantPrefix + signDashboardToken(t, newInferenceTokenTestKey(t), claims)
		if _, err := parseStoredByokGrant(raw, key.public, now); err == nil {
			t.Fatal("a grant from another signer verified")
		}
	})
	// Each grant works only as itself: a member's check of a customer-encrypted credential never
	// opens a stored one, and Control's grant never checks a member's credential or makes a request.
	t.Run("other tokens", func(t *testing.T) {
		member := signDashboardToken(t, key, byokCheckTestClaims(t, now))
		if _, err := parseStoredByokGrant(storedByokGrantPrefix+member, key.public, now); err == nil {
			t.Fatal("a member's check grant worked as a stored credential grant")
		}
		stored := signDashboardToken(t, key, claims)
		if _, err := parseByokCheckGrant(byokCheckGrantPrefix+stored, key.public, now); err == nil {
			t.Fatal("a stored credential grant worked as a member's check grant")
		}
		if _, err := parsePolicyCheckGrant(policyCheckGrantPrefix+stored, key.public, now); err == nil {
			t.Fatal("a stored credential grant worked as a policy check grant")
		}
		if _, err := parseDashboardCredential(dashboardCredentialPrefix+mustUUIDV7(t)+"."+stored, key.public, now); err == nil {
			t.Fatal("a stored credential grant worked as a dashboard credential")
		}
		if _, err := parseStoredByokGrant(byokCheckGrantPrefix+stored, key.public, now); err == nil {
			t.Fatal("a stored credential grant verified under another prefix")
		}
	})
	t.Run("without prefix", func(t *testing.T) {
		if _, err := parseStoredByokGrant(signDashboardToken(t, key, claims), key.public, now); err == nil {
			t.Fatal("a grant without its prefix verified")
		}
	})
}

// sealStoredTestSecret seals plaintext as Control stores a credential's secret.
func sealStoredTestSecret(t *testing.T, masterSecret, byokID, organizationID, provider, plaintext string) string {
	t.Helper()
	key, err := deriveByokKey(masterSecret, byokHKDFSalt, byokHKDFInfo)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	aad := strings.Join([]string{byokAADPrefix, byokID, organizationID, provider}, "\x00")
	return strings.Join([]string{
		byokCiphertextVersion,
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))),
	}, ".")
}

func TestOpenStoredByokOpensOnlyTheGrantsCredential(t *testing.T) {
	const master = "test-master-secret-0123456789-abcdef"
	decryptor, err := newByokDecryptor(master)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{byok: decryptor}
	grant := &StoredByokGrant{OrganizationID: mustUUIDV7(t), ByokID: mustUUIDV7(t), Provider: "openai", Scope: StoredByokProbe}
	sealed := sealStoredTestSecret(t, master, grant.ByokID, grant.OrganizationID, grant.Provider, "sk-stored")
	if secret, err := service.OpenStoredByok(grant, sealed); err != nil || secret != "sk-stored" {
		t.Fatalf("secret = %q, %v", secret, err)
	}

	// A secret sealed for another credential, organization or provider, or with another key, stays
	// closed, so a grant opens only the secret of the credential that it names.
	for name, envelope := range map[string]string{
		"another credential":   sealStoredTestSecret(t, master, mustUUIDV7(t), grant.OrganizationID, grant.Provider, "sk-other"),
		"another organization": sealStoredTestSecret(t, master, grant.ByokID, mustUUIDV7(t), grant.Provider, "sk-other"),
		"another provider":     sealStoredTestSecret(t, master, grant.ByokID, grant.OrganizationID, "anthropic", "sk-other"),
		"another key":          sealStoredTestSecret(t, master+"-rotated", grant.ByokID, grant.OrganizationID, grant.Provider, "sk-other"),
		"an empty secret":      sealStoredTestSecret(t, master, grant.ByokID, grant.OrganizationID, grant.Provider, "  "),
		"no envelope":          "",
		"over 8 KiB":           sealStoredTestSecret(t, master, grant.ByokID, grant.OrganizationID, grant.Provider, strings.Repeat("s", storedByokMaxEnvelope)),
	} {
		if _, err := service.OpenStoredByok(grant, envelope); !errors.Is(err, ErrStoredByokSecret) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// The largest secret that Control seals still opens.
	largest := strings.Repeat("s", 6_000)
	if secret, err := service.OpenStoredByok(grant, sealStoredTestSecret(t, master, grant.ByokID, grant.OrganizationID, grant.Provider, largest)); err != nil || secret != largest {
		t.Fatalf("a 6,000-byte secret: %v", err)
	}

	for name, unavailable := range map[string]*Service{"no service": nil, "no decryptor": {}} {
		if _, err := unavailable.OpenStoredByok(grant, sealed); !errors.Is(err, ErrGatewayUnavailable) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := service.OpenStoredByok(nil, sealed); !errors.Is(err, ErrGatewayUnavailable) {
		t.Fatalf("no grant: %v", err)
	}

	// A gateway's claimed check opens its credential's secret in the same way, and only a claimed one
	// opens, so a member's customer-encrypted credential never takes this path.
	claimed := &ByokCheckTarget{
		Grant:    ByokCheckGrant{OrganizationID: grant.OrganizationID, ByokID: grant.ByokID},
		Provider: grant.Provider, EncryptedSecret: sealed, claimedUntil: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	if secret, err := service.OpenStored(claimed); err != nil || secret != "sk-stored" {
		t.Fatalf("claimed secret = %q, %v", secret, err)
	}
	moved := *claimed
	moved.Grant.ByokID = mustUUIDV7(t)
	if _, err := service.OpenStored(&moved); !errors.Is(err, ErrStoredByokSecret) {
		t.Fatalf("another credential's claim: %v", err)
	}
	unclaimed := *claimed
	unclaimed.claimedUntil = pgtype.Timestamptz{}
	if _, err := service.OpenStored(&unclaimed); !errors.Is(err, ErrGatewayUnavailable) {
		t.Fatalf("unclaimed: %v", err)
	}
}
