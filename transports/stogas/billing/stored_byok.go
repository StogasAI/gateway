package billing

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Control asks a gateway to use a stored credential with its provider: to check the credential, to
// probe a secret before Control saves it, and to list the Azure accounts that an application can
// read. Every use runs here, so it reaches the provider from the fleet's addresses, which a
// provider account's IP allowlist can admit. A check reads the credential from the database and
// records its result, as a member's check of a customer-encrypted credential does. A probe and a
// listing read a secret that no credential holds yet, which Control sends sealed as it would store
// it, and record nothing. Control's grant names the organization, credential and provider that the
// secret is sealed to, and the one use that it allows.
const (
	storedByokGrantPrefix   = "stogas_stored_byok_v1."
	storedByokGrantAudience = "stogas-stored-byok"
	// Control signs a grant for each call that it makes at once.
	storedByokGrantMaxLifetime = time.Minute
	// A sealed secret of the largest secret that a credential holds.
	storedByokMaxEnvelope = 8 << 10

	// The uses that a grant allows: checking the credential, probing a secret, and listing the
	// accounts that an Azure application can read.
	StoredByokCheck         = "check"
	StoredByokProbe         = "probe"
	StoredByokAzureAccounts = "azure-accounts"
)

var (
	ErrStoredByokGrant   = &RequestError{"invalid_grant", "The grant is invalid or expired.", 401}
	ErrStoredByokRequest = &RequestError{"invalid_request", "Send the sealed secret with what its provider's check needs, and nothing to check a credential.", 400}
	// Only a member can have a customer-encrypted credential checked, with the key that sealed it.
	ErrStoredByokEncrypted = &RequestError{"credential_encrypted", "The customer encrypted this credential, so only its member can check it.", 400}
	// Control sealed the secret with a key that this gateway does not hold, or for another credential.
	ErrStoredByokSecret = &RequestError{"secret_unreadable", "The gateway cannot open this credential's secret.", 500}
	// The secret cannot serve the target that Control stores beside it, which Control derives from
	// the secret as gateways do, so the two read the secret differently.
	ErrStoredByokTarget = &RequestError{"target_mismatch", "The credential's secret cannot serve the target stored with it.", 500}
)

// StoredByokGrant names the use of a stored credential that Control allowed.
type StoredByokGrant struct {
	OrganizationID string
	ByokID         string
	Provider       string
	Scope          string
}

type storedByokGrantClaims struct {
	Audience     string `json:"aud"`
	Byok         string `json:"byok"`
	ExpiresAt    int64  `json:"exp"`
	IssuedAt     int64  `json:"iat"`
	Issuer       string `json:"iss"`
	JWTID        string `json:"jti"`
	Organization string `json:"org"`
	Provider     string `json:"provider"`
	Scope        string `json:"scope"`
}

func IsStoredByokGrant(raw string) bool {
	return strings.HasPrefix(raw, storedByokGrantPrefix)
}

func parseStoredByokGrant(raw string, publicKey *inferenceTokenKey, now time.Time) (*StoredByokGrant, error) {
	if !IsStoredByokGrant(raw) || publicKey == nil {
		return nil, ErrStoredByokGrant
	}
	payload, err := verifySignedToken(strings.TrimPrefix(raw, storedByokGrantPrefix), publicKey)
	if err != nil {
		return nil, ErrStoredByokGrant
	}
	var claims storedByokGrantClaims
	if err := decodeStrictJSON(payload, &claims); err != nil {
		return nil, ErrStoredByokGrant
	}
	organization, organizationErr := uuid.Parse(claims.Organization)
	byok, byokErr := uuid.Parse(claims.Byok)
	jwtID, jwtIDErr := uuid.Parse(claims.JWTID)
	_, knownProvider := credentialProviders[claims.Provider]
	allowed := claims.Scope == StoredByokCheck || claims.Scope == StoredByokProbe ||
		claims.Scope == StoredByokAzureAccounts && claims.Provider == "azure"
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	now = now.UTC()
	if claims.Issuer != inferenceTokenIssuer ||
		claims.Audience != storedByokGrantAudience ||
		!allowed || !knownProvider ||
		organizationErr != nil || organization == uuid.Nil || organization.String() != claims.Organization ||
		byokErr != nil || byok.Version() != 7 || byok.String() != claims.Byok ||
		jwtIDErr != nil || jwtID == uuid.Nil ||
		claims.ExpiresAt <= claims.IssuedAt ||
		expiresAt.Sub(issuedAt) > storedByokGrantMaxLifetime ||
		!now.Before(expiresAt) ||
		issuedAt.After(now.Add(inferenceTokenClockSkew)) {
		return nil, ErrStoredByokGrant
	}
	return &StoredByokGrant{OrganizationID: claims.Organization, ByokID: claims.Byok, Provider: claims.Provider, Scope: claims.Scope}, nil
}

// ParseStoredByokGrant verifies a grant that Control signed for one use of a stored credential.
func (s *Service) ParseStoredByokGrant(raw string) (*StoredByokGrant, error) {
	if s == nil {
		return nil, ErrStoredByokGrant
	}
	return parseStoredByokGrant(raw, s.inferenceTokenPublicKey, time.Now())
}

// StoredByokCheckTarget reads the stored credential that Control's grant names. The grant names
// the provider that Control read, which the credential keeps for life.
func (s *Service) StoredByokCheckTarget(ctx context.Context, grant *StoredByokGrant) (*ByokCheckTarget, error) {
	if grant == nil {
		return nil, ErrStoredByokGrant
	}
	target, err := s.ByokCheckTarget(ctx, &ByokCheckGrant{OrganizationID: grant.OrganizationID, ByokID: grant.ByokID})
	if err != nil {
		return nil, err
	}
	if target.Provider != grant.Provider {
		return nil, ErrStoredByokGrant
	}
	return target, nil
}

// OpenStoredByok opens the secret that Control sealed for the grant's credential, as requests open
// stored credentials.
func (s *Service) OpenStoredByok(grant *StoredByokGrant, envelope string) (string, error) {
	if s == nil || s.byok == nil || grant == nil {
		return "", ErrGatewayUnavailable
	}
	if len(envelope) > storedByokMaxEnvelope {
		return "", ErrStoredByokSecret
	}
	secret, err := s.byok.decrypt(envelope, grant.ByokID, grant.OrganizationID, grant.Provider)
	if err != nil {
		return "", ErrStoredByokSecret
	}
	return secret, nil
}
