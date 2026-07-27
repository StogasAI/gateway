package billing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParseDashboardCredential(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	keyID := mustUUIDV7(t)
	userID := mustUUIDV7(t)
	sessionID := mustUUIDV7(t)
	token := signDashboardToken(t, privateKey, dashboardTokenClaims{
		Audience:  inferenceTokenAudience,
		ExpiresAt: now.Add(15 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Issuer:    inferenceTokenIssuer,
		JWTID:     mustUUIDV7(t),
		Scope:     inferenceTokenScope,
		SessionID: sessionID,
		Subject:   userID,
	})

	credential, err := parseDashboardCredential(
		dashboardCredentialPrefix+keyID+"."+token,
		publicKey,
		now,
	)
	if err != nil {
		t.Fatalf("parseDashboardCredential returned error: %v", err)
	}
	if credential.KeyID != keyID ||
		credential.ActorUserID != userID ||
		credential.SessionID != sessionID {
		t.Fatalf("unexpected credential: %#v", credential)
	}
}

func TestParseDashboardCredentialRejectsExpiredAndWrongSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	token := signDashboardToken(t, privateKey, dashboardTokenClaims{
		Audience:  inferenceTokenAudience,
		ExpiresAt: now.Add(-time.Second).Unix(),
		IssuedAt:  now.Add(-time.Minute).Unix(),
		Issuer:    inferenceTokenIssuer,
		JWTID:     mustUUIDV7(t),
		Scope:     inferenceTokenScope,
		SessionID: mustUUIDV7(t),
		Subject:   mustUUIDV7(t),
	})
	raw := dashboardCredentialPrefix + mustUUIDV7(t) + "." + token

	if _, err := parseDashboardCredential(raw, publicKey, now); err == nil {
		t.Fatal("expired credential was accepted")
	}
	if _, err := parseDashboardCredential(raw, otherPublicKey, now.Add(-2*time.Second)); err == nil {
		t.Fatal("credential with the wrong signing key was accepted")
	}
}

func signDashboardToken(t *testing.T, privateKey ed25519.PrivateKey, claims dashboardTokenClaims) string {
	t.Helper()
	header := dashboardTokenHeader{Algorithm: "EdDSA", Type: "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := ed25519.Sign(privateKey, []byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func mustUUIDV7(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}
