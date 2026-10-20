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
	firstAdmissionKey := dashboardAdmissionKey(first)
	secondAdmissionKey := dashboardAdmissionKey(second)
	if firstAdmissionKey != secondAdmissionKey {
		t.Fatalf("rotated key prefix changed admission identity: %q != %q", firstAdmissionKey, secondAdmissionKey)
	}
	otherSession := *first
	otherSession.SessionID = mustUUIDV7(t)
	if dashboardAdmissionKey(&otherSession) == firstAdmissionKey {
		t.Fatal("different signed sessions shared an admission identity")
	}
	otherActor := *first
	otherActor.ActorUserID = mustUUIDV7(t)
	if dashboardAdmissionKey(&otherActor) == firstAdmissionKey {
		t.Fatal("different signed actors shared an admission identity")
	}

	var requests localRequestLimiter
	for index := 0; index < localRequestBurst; index++ {
		if retryAfter := requests.allow(firstAdmissionKey, now); retryAfter != 0 {
			t.Fatalf("request %d was rejected for %s", index+1, retryAfter)
		}
	}
	if retryAfter := requests.allow(secondAdmissionKey, now); retryAfter <= 0 {
		t.Fatal("rotated key prefix received a fresh request burst")
	}

	var refusals refusalCache
	refusals.record(firstAdmissionKey, nil, refusalHoldBack, now)
	if refusals.get(secondAdmissionKey, now) == nil {
		t.Fatal("rotated key prefix bypassed the refusal")
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

func signDashboardToken(t *testing.T, privateKey inferenceTokenTestKey, claims dashboardTokenClaims) string {
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
