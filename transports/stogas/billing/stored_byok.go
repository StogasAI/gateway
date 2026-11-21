package billing

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// Control asks a gateway to use a secret before it stores the secret: to probe the secret with its
// provider, and to list the Azure accounts that an application can read. Both run here, so they
// reach the provider from the fleet's addresses, which a provider account's IP allowlist can
// admit, as the gateways' own checks of stored credentials do. Control sends the secret sealed as
// it would store it, and nothing is recorded. Control's grant names the organization, credential
// and provider that the secret is sealed to, and the one use that it allows.
const (
	storedByokGrantPrefix   = "stogas_stored_byok_v1."
	storedByokGrantAudience = "stogas-stored-byok"
	// Control signs a grant for each call that it makes at once.
	storedByokGrantMaxLifetime = time.Minute
	// A sealed secret of the largest secret that a credential holds.
	storedByokMaxEnvelope = 8 << 10

	// The uses that a grant allows: probing a secret, and listing the accounts that an Azure
	// application can read.
	StoredByokProbe         = "probe"
	StoredByokAzureAccounts = "azure-accounts"
)

var (
	ErrStoredByokGrant   = &RequestError{"invalid_grant", "The grant is invalid or expired.", 401}
	ErrStoredByokRequest = &RequestError{"invalid_request", "Send the sealed secret with what its provider's check needs.", 400}
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
	allowed := claims.Scope == StoredByokProbe ||
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
