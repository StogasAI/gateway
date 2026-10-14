package billing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	dashboardCredentialPrefix = "stogas_dashboard_v1."
	inferenceTokenAudience    = "stogas-inference"
	inferenceTokenIssuer      = "https://control.stogas.ai"
	inferenceTokenScope       = "inference"
	inferenceTokenMaxLifetime = 15 * time.Minute
	inferenceTokenClockSkew   = 30 * time.Second
	// Composite ML-DSA-65 and Ed25519 (draft-ietf-jose-pq-composite-sigs): both
	// components sign one representative of the JWS input and both must verify.
	inferenceTokenAlgorithm = "ML-DSA-65-Ed25519"
	compositePrefix         = "CompositeAlgorithmSignatures2025"
	compositeLabel          = "COMPSIG-MLDSA65-Ed25519-SHA512"
)

type inferenceTokenKey struct {
	mldsa   *mldsa.PublicKey
	ed25519 ed25519.PublicKey
}

type DashboardCredential struct {
	ActorUserID string
	KeyID       string
	SessionID   string
	Claims      *APIKeyClaims
}

func IsDashboardCredential(raw string) bool {
	return strings.HasPrefix(raw, dashboardCredentialPrefix)
}

type dashboardTokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type dashboardTokenClaims struct {
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Issuer    string `json:"iss"`
	JWTID     string `json:"jti"`
	Scope     string `json:"scope"`
	SessionID string `json:"sid"`
	Subject   string `json:"sub"`
}

// The encoding is the ML-DSA-65 public key, then the Ed25519 public key.
func parseInferenceTokenPublicKey(raw string) (*inferenceTokenKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(decoded) != mldsa.MLDSA65PublicKeySize+ed25519.PublicKeySize {
		return nil, errors.New("invalid inference-token public key")
	}
	mldsaKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), decoded[:mldsa.MLDSA65PublicKeySize])
	if err != nil {
		return nil, errors.New("invalid inference-token public key")
	}
	return &inferenceTokenKey{
		mldsa:   mldsaKey,
		ed25519: ed25519.PublicKey(decoded[mldsa.MLDSA65PublicKeySize:]),
	}, nil
}

func (k *inferenceTokenKey) verify(message []byte, signature []byte) bool {
	if len(signature) != mldsa.MLDSA65SignatureSize+ed25519.SignatureSize {
		return false
	}
	digest := sha512.Sum512(message)
	// The empty application context is encoded as its zero length.
	representative := make([]byte, 0, len(compositePrefix)+len(compositeLabel)+1+len(digest))
	representative = append(representative, compositePrefix...)
	representative = append(representative, compositeLabel...)
	representative = append(representative, 0)
	representative = append(representative, digest[:]...)
	return mldsa.Verify(
		k.mldsa,
		representative,
		signature[:mldsa.MLDSA65SignatureSize],
		&mldsa.Options{Context: compositeLabel},
	) == nil && ed25519.Verify(k.ed25519, representative, signature[mldsa.MLDSA65SignatureSize:])
}

func parseDashboardCredential(
	raw string,
	publicKey *inferenceTokenKey,
	now time.Time,
) (*DashboardCredential, error) {
	if !strings.HasPrefix(raw, dashboardCredentialPrefix) {
		return nil, ErrInvalidAPIKey
	}
	parts := strings.SplitN(strings.TrimPrefix(raw, dashboardCredentialPrefix), ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidAPIKey
	}
	keyID, err := uuid.Parse(parts[0])
	if err != nil || keyID == uuid.Nil || keyID.Version() != 7 {
		return nil, ErrInvalidAPIKey
	}
	claims, err := verifyDashboardToken(parts[1], publicKey, now.UTC())
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	return &DashboardCredential{
		ActorUserID: claims.Subject,
		KeyID:       keyID.String(),
		SessionID:   claims.SessionID,
	}, nil
}

func verifyDashboardToken(
	token string,
	publicKey *inferenceTokenKey,
	now time.Time,
) (*dashboardTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidAPIKey
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	var header dashboardTokenHeader
	if err := decodeStrictJSON(headerBytes, &header); err != nil ||
		header.Algorithm != inferenceTokenAlgorithm ||
		header.Type != "JWT" {
		return nil, ErrInvalidAPIKey
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !publicKey.verify([]byte(parts[0]+"."+parts[1]), signature) {
		return nil, ErrInvalidAPIKey
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	var claims dashboardTokenClaims
	if err := decodeStrictJSON(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidAPIKey
	}
	subject, subjectErr := uuid.Parse(claims.Subject)
	sessionID, sessionErr := uuid.Parse(claims.SessionID)
	jwtID, jwtIDErr := uuid.Parse(claims.JWTID)
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	if claims.Issuer != inferenceTokenIssuer ||
		claims.Audience != inferenceTokenAudience ||
		claims.Scope != inferenceTokenScope ||
		subjectErr != nil ||
		subject == uuid.Nil ||
		sessionErr != nil ||
		sessionID == uuid.Nil ||
		jwtIDErr != nil ||
		jwtID == uuid.Nil ||
		claims.ExpiresAt <= claims.IssuedAt ||
		expiresAt.Sub(issuedAt) > inferenceTokenMaxLifetime ||
		!now.Before(expiresAt) ||
		issuedAt.After(now.Add(inferenceTokenClockSkew)) {
		return nil, ErrInvalidAPIKey
	}
	return &claims, nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidAPIKey
	}
	return nil
}
