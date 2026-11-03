package billing

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func policyCheckTestClaims(t *testing.T, now time.Time) policyCheckGrantClaims {
	t.Helper()
	return policyCheckGrantClaims{
		Audience:     policyCheckGrantAudience,
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		IssuedAt:     now.Unix(),
		Issuer:       inferenceTokenIssuer,
		JWTID:        uuid.NewString(),
		Organization: mustUUIDV7(t),
		Scope:        policyCheckGrantScope,
		Subject:      mustUUIDV7(t),
	}
}

func TestParsePolicyCheckGrant(t *testing.T) {
	key := newInferenceTokenTestKey(t)
	now := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	claims := policyCheckTestClaims(t, now)
	grant, err := parsePolicyCheckGrant(policyCheckGrantPrefix+signDashboardToken(t, key, claims), key.public, now)
	if err != nil {
		t.Fatal(err)
	}
	if *grant != (PolicyCheckGrant{ActorUserID: claims.Subject, OrganizationID: claims.Organization}) {
		t.Fatalf("grant = %#v", grant)
	}
	// Within the clock skew a grant that Control issued a moment ahead still verifies.
	if _, err := parsePolicyCheckGrant(policyCheckGrantPrefix+signDashboardToken(t, key, claims), key.public, now.Add(-20*time.Second)); err != nil {
		t.Fatalf("grant issued within the clock skew: %v", err)
	}

	for name, change := range map[string]func(*policyCheckGrantClaims){
		"another audience":         func(c *policyCheckGrantClaims) { c.Audience = byokCheckGrantAudience },
		"another scope":            func(c *policyCheckGrantClaims) { c.Scope = byokCheckGrantScope },
		"another issuer":           func(c *policyCheckGrantClaims) { c.Issuer = "https://example.com" },
		"expired":                  func(c *policyCheckGrantClaims) { c.ExpiresAt = now.Unix() },
		"longer than five minutes": func(c *policyCheckGrantClaims) { c.ExpiresAt = now.Add(5*time.Minute + time.Second).Unix() },
		"issued in the future": func(c *policyCheckGrantClaims) {
			c.IssuedAt = now.Add(time.Minute).Unix()
			c.ExpiresAt = now.Add(2 * time.Minute).Unix()
		},
		"ending before it starts": func(c *policyCheckGrantClaims) { c.ExpiresAt = c.IssuedAt },
		"uppercase organization":  func(c *policyCheckGrantClaims) { c.Organization = strings.ToUpper(c.Organization) },
		"no organization":         func(c *policyCheckGrantClaims) { c.Organization = "" },
		"nil member":              func(c *policyCheckGrantClaims) { c.Subject = uuid.Nil.String() },
		"missing token ID":        func(c *policyCheckGrantClaims) { c.JWTID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := claims
			change(&changed)
			raw := policyCheckGrantPrefix + signDashboardToken(t, key, changed)
			if _, err := parsePolicyCheckGrant(raw, key.public, now); !errors.Is(err, ErrPolicyCheckGrant) {
				t.Fatalf("err = %v, want ErrPolicyCheckGrant", err)
			}
		})
	}

	t.Run("unknown claim", func(t *testing.T) {
		withExtra := map[string]any{}
		encoded, _ := json.Marshal(claims)
		_ = json.Unmarshal(encoded, &withExtra)
		withExtra["sid"] = mustUUIDV7(t)
		if _, err := parsePolicyCheckGrant(policyCheckGrantPrefix+signDashboardToken(t, key, withExtra), key.public, now); err == nil {
			t.Fatal("a grant with an unknown claim verified")
		}
	})
	t.Run("another signer", func(t *testing.T) {
		raw := policyCheckGrantPrefix + signDashboardToken(t, newInferenceTokenTestKey(t), claims)
		if _, err := parsePolicyCheckGrant(raw, key.public, now); err == nil {
			t.Fatal("a grant from another signer verified")
		}
	})
	// Each grant works only as itself, so a credential check's grant never checks policy text, and
	// a policy check's grant never checks a credential or makes a request.
	t.Run("other tokens", func(t *testing.T) {
		byok := signDashboardToken(t, key, byokCheckTestClaims(t, now))
		dashboard := signDashboardToken(t, key, dashboardTokenClaims{
			Audience: inferenceTokenAudience, ExpiresAt: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
			Issuer: inferenceTokenIssuer, JWTID: uuid.NewString(), Scope: inferenceTokenScope,
			SessionID: mustUUIDV7(t), Subject: mustUUIDV7(t),
		})
		for _, raw := range []string{policyCheckGrantPrefix + byok, policyCheckGrantPrefix + dashboard, byokCheckGrantPrefix + byok} {
			if _, err := parsePolicyCheckGrant(raw, key.public, now); err == nil {
				t.Fatalf("%.30s… worked as a policy check grant", raw)
			}
		}
		grant := signDashboardToken(t, key, claims)
		if _, err := parseByokCheckGrant(byokCheckGrantPrefix+grant, key.public, now); err == nil {
			t.Fatal("a policy check grant worked as a credential check grant")
		}
		if _, err := parseDashboardCredential(dashboardCredentialPrefix+mustUUIDV7(t)+"."+grant, key.public, now); err == nil {
			t.Fatal("a policy check grant worked as a dashboard credential")
		}
	})
	t.Run("without prefix", func(t *testing.T) {
		if _, err := parsePolicyCheckGrant(signDashboardToken(t, key, claims), key.public, now); err == nil {
			t.Fatal("a grant without its prefix verified")
		}
	})
}

// Checks count against the member in the organization, so a new grant adds nothing to their
// allowance, while their checks for another organization and other members' checks count apart.
func TestPolicyCheckGrantAdmission(t *testing.T) {
	key := newInferenceTokenTestKey(t)
	now := time.Now()
	claims := policyCheckTestClaims(t, now)
	service := &Service{inferenceTokenPublicKey: key.public}
	sign := func(change func(*policyCheckGrantClaims)) string {
		changed := claims
		changed.JWTID = uuid.NewString()
		change(&changed)
		return policyCheckGrantPrefix + signDashboardToken(t, key, changed)
	}
	grant, err := service.ParsePolicyCheckGrant(sign(func(*policyCheckGrantClaims) {}))
	if err != nil {
		t.Fatal(err)
	}
	// Spending the allowance at a later time leaves nothing to refill while the test runs.
	limit := credentialRequestLimit(defaultPlatformRequestsPerSecond)
	for range int(limit.burst) {
		service.credentialRequests.allow(grant.admissionKey(), now.Add(time.Hour), limit)
	}
	if _, err := service.ParsePolicyCheckGrant(sign(func(*policyCheckGrantClaims) {})); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("a new grant got a fresh allowance: %v", err)
	}
	for name, change := range map[string]func(*policyCheckGrantClaims){
		"another organization": func(c *policyCheckGrantClaims) { c.Organization = mustUUIDV7(t) },
		"another member":       func(c *policyCheckGrantClaims) { c.Subject = mustUUIDV7(t) },
	} {
		if _, err := service.ParsePolicyCheckGrant(sign(change)); err != nil {
			t.Fatalf("%s shared the allowance: %v", name, err)
		}
	}
	if _, err := service.ParsePolicyCheckGrant(policyCheckGrantPrefix + "a.b.c"); !errors.Is(err, ErrPolicyCheckGrant) {
		t.Fatalf("an unsigned grant was not refused as invalid: %v", err)
	}
}
