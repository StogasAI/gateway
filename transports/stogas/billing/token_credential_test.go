package billing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParseDashboardCredential(t *testing.T) {
	privateKey := newInferenceTokenTestKey(t)
	publicKey := privateKey.public
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
	privateKey := newInferenceTokenTestKey(t)
	publicKey := privateKey.public
	otherPublicKey := newInferenceTokenTestKey(t).public
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

func TestDashboardTokenRequiresBothSignatureComponents(t *testing.T) {
	privateKey := newInferenceTokenTestKey(t)
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	token := signDashboardToken(t, privateKey, dashboardTokenClaims{
		Audience:  inferenceTokenAudience,
		ExpiresAt: now.Add(15 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Issuer:    inferenceTokenIssuer,
		JWTID:     mustUUIDV7(t),
		Scope:     inferenceTokenScope,
		SessionID: mustUUIDV7(t),
		Subject:   mustUUIDV7(t),
	})
	cut := strings.LastIndexByte(token, '.')
	signature, err := base64.RawURLEncoding.DecodeString(token[cut+1:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyDashboardToken(token, privateKey.public, now); err != nil {
		t.Fatalf("valid token was rejected: %v", err)
	}
	for _, index := range []int{0, mldsa.MLDSA65SignatureSize} {
		changed := bytes.Clone(signature)
		changed[index] ^= 1
		forged := token[:cut+1] + base64.RawURLEncoding.EncodeToString(changed)
		if _, err := verifyDashboardToken(forged, privateKey.public, now); err == nil {
			t.Fatalf("token with a changed signature byte %d was accepted", index)
		}
	}
}

// A signature whose last character differs only in its unused low bits decodes to the same
// bytes, so the gateway refuses it to keep one spelling for each token.
func TestSignedTokenRefusesAnotherSpelling(t *testing.T) {
	privateKey := newInferenceTokenTestKey(t)
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	token := signDashboardToken(t, privateKey, dashboardTokenClaims{
		Audience:  inferenceTokenAudience,
		ExpiresAt: now.Add(15 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Issuer:    inferenceTokenIssuer,
		JWTID:     mustUUIDV7(t),
		Scope:     inferenceTokenScope,
		SessionID: mustUUIDV7(t),
		Subject:   mustUUIDV7(t),
	})
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, token[len(token)-1])
	respelled := token[:len(token)-1] + string(alphabet[last^1])
	cut := strings.LastIndexByte(token, '.')
	original, _ := base64.RawURLEncoding.DecodeString(token[cut+1:])
	lenient, err := base64.RawURLEncoding.DecodeString(respelled[cut+1:])
	if err != nil || !bytes.Equal(lenient, original) {
		t.Fatal("the respelled signature must decode to the same bytes")
	}
	if _, err := verifyDashboardToken(token, privateKey.public, now); err != nil {
		t.Fatalf("valid token was rejected: %v", err)
	}
	if _, err := verifyDashboardToken(respelled, privateKey.public, now); err == nil {
		t.Fatal("a respelled token was accepted")
	}
}

func TestDashboardAdmissionUsesSignedPrincipalInsteadOfKeyPrefix(t *testing.T) {
	privateKey := newInferenceTokenTestKey(t)
	publicKey := privateKey.public
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	token := signDashboardToken(t, privateKey, dashboardTokenClaims{
		Audience:  inferenceTokenAudience,
		ExpiresAt: now.Add(15 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Issuer:    inferenceTokenIssuer,
		JWTID:     mustUUIDV7(t),
		Scope:     inferenceTokenScope,
		SessionID: mustUUIDV7(t),
		Subject:   mustUUIDV7(t),
	})

	first, err := parseDashboardCredential(
		dashboardCredentialPrefix+mustUUIDV7(t)+"."+token,
		publicKey,
		now,
	)
	if err != nil {
		t.Fatalf("parse first dashboard credential: %v", err)
	}
	second, err := parseDashboardCredential(
		dashboardCredentialPrefix+mustUUIDV7(t)+"."+token,
		publicKey,
		now,
	)
	if err != nil {
		t.Fatalf("parse second dashboard credential: %v", err)
	}
	if first.KeyID == second.KeyID {
		t.Fatal("test credentials unexpectedly used the same key ID")
	}
	firstAdmissionKey := tokenAdmissionKey(first)
	secondAdmissionKey := tokenAdmissionKey(second)
	if firstAdmissionKey != secondAdmissionKey {
		t.Fatalf("rotated key prefix changed admission identity: %q != %q", firstAdmissionKey, secondAdmissionKey)
	}
	otherSession := *first
	otherSession.SessionID = mustUUIDV7(t)
	if tokenAdmissionKey(&otherSession) == firstAdmissionKey {
		t.Fatal("different signed sessions shared an admission identity")
	}
	otherActor := *first
	otherActor.ActorUserID = mustUUIDV7(t)
	if tokenAdmissionKey(&otherActor) == firstAdmissionKey {
		t.Fatal("different signed actors shared an admission identity")
	}

	var requests localRequestLimiter
	for index := 0; index < int(credentialRequestLimit(defaultPlatformRequestsPerSecond).burst); index++ {
		if retryAfter := requests.allow(firstAdmissionKey, now, credentialRequestLimit(defaultPlatformRequestsPerSecond)); retryAfter != 0 {
			t.Fatalf("request %d was rejected for %s", index+1, retryAfter)
		}
	}
	if retryAfter := requests.allow(secondAdmissionKey, now, credentialRequestLimit(defaultPlatformRequestsPerSecond)); retryAfter <= 0 {
		t.Fatal("rotated key prefix received a fresh request burst")
	}

	var refusals refusalCache
	refusals.record(firstAdmissionKey, nil, refusalHoldBack, now)
	if refusals.get(secondAdmissionKey, now) == nil {
		t.Fatal("rotated key prefix bypassed the refusal")
	}

}

// A workload's token names its key and identity in its signed claims, and lasts at most an hour.
func TestParseWorkloadCredential(t *testing.T) {
	privateKey := newInferenceTokenTestKey(t)
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	keyID, identityID := mustUUIDV7(t), mustUUIDV7(t)
	claims := func(change func(*workloadTokenClaims)) string {
		value := workloadTokenClaims{
			Audience:  workloadTokenAudience,
			ExpiresAt: now.Add(time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			Identity:  identityID,
			Issuer:    inferenceTokenIssuer,
			JWTID:     mustUUIDV7(t),
			Scope:     inferenceTokenScope,
			Subject:   keyID,
		}
		if change != nil {
			change(&value)
		}
		return workloadCredentialPrefix + signDashboardToken(t, privateKey, value)
	}

	credential, err := parseTokenCredential(claims(nil), privateKey.public, now)
	if err != nil {
		t.Fatalf("valid workload credential was rejected: %v", err)
	}
	if credential.KeyID != keyID || credential.WorkloadIdentityID != identityID ||
		credential.ActorUserID != "" || credential.SessionID != "" {
		t.Fatalf("unexpected credential: %#v", credential)
	}
	if !IsWorkloadCredential(claims(nil)) || IsDashboardCredential(claims(nil)) {
		t.Fatal("the prefix does not name a workload credential")
	}

	refused := map[string]string{
		"expired":            claims(func(c *workloadTokenClaims) { c.ExpiresAt = now.Unix() }),
		"longer than a hour": claims(func(c *workloadTokenClaims) { c.ExpiresAt = now.Add(time.Hour + time.Second).Unix() }),
		"issued later":       claims(func(c *workloadTokenClaims) { c.IssuedAt = now.Add(time.Minute).Unix() }),
		"dashboard audience": claims(func(c *workloadTokenClaims) { c.Audience = inferenceTokenAudience }),
		"another scope":      claims(func(c *workloadTokenClaims) { c.Scope = "byok-check" }),
		"identity not v7":    claims(func(c *workloadTokenClaims) { c.Identity = uuid.NewString() }),
		"key not v7":         claims(func(c *workloadTokenClaims) { c.Subject = uuid.NewString() }),
		"another signer":     workloadCredentialPrefix + signDashboardToken(t, newInferenceTokenTestKey(t), workloadTokenClaims{Audience: workloadTokenAudience, ExpiresAt: now.Add(time.Hour).Unix(), IssuedAt: now.Unix(), Identity: identityID, Issuer: inferenceTokenIssuer, JWTID: mustUUIDV7(t), Scope: inferenceTokenScope, Subject: keyID}),
		// A dashboard token's claims carry a session, which a workload's never do.
		"dashboard claims": workloadCredentialPrefix + signDashboardToken(t, privateKey, dashboardTokenClaims{Audience: workloadTokenAudience, ExpiresAt: now.Add(time.Hour).Unix(), IssuedAt: now.Unix(), Issuer: inferenceTokenIssuer, JWTID: mustUUIDV7(t), Scope: inferenceTokenScope, SessionID: mustUUIDV7(t), Subject: keyID}),
		// The dashboard prefix takes a key ID and a session token, never a workload's token.
		"dashboard prefix": dashboardCredentialPrefix + keyID + "." + strings.TrimPrefix(claims(nil), workloadCredentialPrefix),
	}
	for name, raw := range refused {
		if _, err := parseTokenCredential(raw, privateKey.public, now); err == nil {
			t.Errorf("%s: credential was accepted", name)
		}
	}

	// Each identity has its own admission and cached configuration, apart from dashboard sessions.
	other := *credential
	other.WorkloadIdentityID = mustUUIDV7(t)
	dashboard := &TokenCredential{KeyID: keyID, ActorUserID: identityID, SessionID: identityID}
	for _, key := range []func(*TokenCredential) string{tokenAdmissionKey, tokenConfigCacheKey} {
		if key(credential) == key(&other) || key(credential) == key(dashboard) {
			t.Fatal("two credentials share an admission or cache key")
		}
	}
}

type inferenceTokenTestKey struct {
	mldsa   *mldsa.PrivateKey
	ed25519 ed25519.PrivateKey
	public  *inferenceTokenKey
}

func newInferenceTokenTestKey(t *testing.T) inferenceTokenTestKey {
	t.Helper()
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	ed25519Public, ed25519Key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	public, err := parseInferenceTokenPublicKey(
		base64.RawURLEncoding.EncodeToString(append(mldsaKey.PublicKey().Bytes(), ed25519Public...)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return inferenceTokenTestKey{mldsa: mldsaKey, ed25519: ed25519Key, public: public}
}

// signDashboardToken signs claims as Control signs every token it gives the gateway.
func signDashboardToken(t *testing.T, privateKey inferenceTokenTestKey, claims any) string {
	t.Helper()
	header := dashboardTokenHeader{Algorithm: inferenceTokenAlgorithm, Type: "JWT"}
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
	digest := sha512.Sum512([]byte(unsigned))
	representative := append([]byte(compositePrefix+compositeLabel+"\x00"), digest[:]...)
	signature, err := privateKey.mldsa.Sign(nil, representative, &mldsa.Options{Context: compositeLabel})
	if err != nil {
		t.Fatal(err)
	}
	signature = append(signature, ed25519.Sign(privateKey.ed25519, representative)...)
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
