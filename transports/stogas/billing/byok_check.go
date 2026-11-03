package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
)

// A member checks a customer-encrypted credential through a gateway, the only place that can open
// it, with the key that the member sends. Control signs a short check grant for one credential
// after it finds that the member manages it, and the database finds those rights again when the
// gateway reads the credential and when it records the result.
const (
	byokCheckGrantPrefix      = "stogas_byok_check_v1."
	byokCheckGrantAudience    = "stogas-byok-check"
	byokCheckGrantScope       = "byok-check"
	byokCheckGrantMaxLifetime = 5 * time.Minute
	byokCheckQueryTimeout     = 5 * time.Second
	// The largest secret that a credential's envelope holds, as requests open it.
	byokCheckMaxSecret = 4096
)

var (
	ErrByokCheckGrant     = &RequestError{"invalid_check_grant", "The credential check grant is invalid or expired. Run the check again.", 401}
	ErrByokCheckNotFound  = &RequestError{"credential_not_found", "No credential with this ID is in the organization, or you are not its member.", 404}
	ErrByokCheckForbidden = &RequestError{"permission_denied", "You do not manage this credential.", 403}
	ErrByokCheckInactive  = &RequestError{"organization_inactive", "The organization is inactive.", 403}
	ErrByokCheckStored    = &RequestError{"credential_stored", "Stogas stores this credential, so check it on the dashboard or with the dashboard API.", 400}
	ErrByokCheckChanged   = &RequestError{"credential_changed", "The credential changed or another check finished during this one. Check it again.", 409}
)

// ByokCheckGrant names the member, organization and credential that Control allowed to be checked.
type ByokCheckGrant struct {
	ActorUserID    string
	OrganizationID string
	ByokID         string
}

type byokCheckGrantClaims struct {
	Audience     string `json:"aud"`
	Byok         string `json:"byok"`
	ExpiresAt    int64  `json:"exp"`
	IssuedAt     int64  `json:"iat"`
	Issuer       string `json:"iss"`
	JWTID        string `json:"jti"`
	Organization string `json:"org"`
	Scope        string `json:"scope"`
	Subject      string `json:"sub"`
}

func IsByokCheckGrant(raw string) bool {
	return strings.HasPrefix(raw, byokCheckGrantPrefix)
}

func parseByokCheckGrant(raw string, publicKey *inferenceTokenKey, now time.Time) (*ByokCheckGrant, error) {
	if !IsByokCheckGrant(raw) || publicKey == nil {
		return nil, ErrByokCheckGrant
	}
	payload, err := verifySignedToken(strings.TrimPrefix(raw, byokCheckGrantPrefix), publicKey)
	if err != nil {
		return nil, ErrByokCheckGrant
	}
	var claims byokCheckGrantClaims
	if err := decodeStrictJSON(payload, &claims); err != nil {
		return nil, ErrByokCheckGrant
	}
	subject, subjectErr := uuid.Parse(claims.Subject)
	organization, organizationErr := uuid.Parse(claims.Organization)
	byok, byokErr := uuid.Parse(claims.Byok)
	jwtID, jwtIDErr := uuid.Parse(claims.JWTID)
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	now = now.UTC()
	if claims.Issuer != inferenceTokenIssuer ||
		claims.Audience != byokCheckGrantAudience ||
		claims.Scope != byokCheckGrantScope ||
		subjectErr != nil || subject == uuid.Nil || subject.String() != claims.Subject ||
		organizationErr != nil || organization == uuid.Nil || organization.String() != claims.Organization ||
		byokErr != nil || byok.Version() != 7 || byok.String() != claims.Byok ||
		jwtIDErr != nil || jwtID == uuid.Nil ||
		claims.ExpiresAt <= claims.IssuedAt ||
		expiresAt.Sub(issuedAt) > byokCheckGrantMaxLifetime ||
		!now.Before(expiresAt) ||
		issuedAt.After(now.Add(inferenceTokenClockSkew)) {
		return nil, ErrByokCheckGrant
	}
	return &ByokCheckGrant{ActorUserID: claims.Subject, OrganizationID: claims.Organization, ByokID: claims.Byok}, nil
}

// ParseByokCheckGrant verifies a grant that Control signed for one credential check.
func (s *Service) ParseByokCheckGrant(raw string) (*ByokCheckGrant, error) {
	if s == nil {
		return nil, ErrByokCheckGrant
	}
	return parseByokCheckGrant(raw, s.inferenceTokenPublicKey, time.Now())
}

// ByokCheckTarget is a customer-encrypted credential that a member asked a gateway to check, as
// the database showed it. The result is recorded only if no other check finished after checkedAt.
// A discovery of an Azure credential's targets reads the account AzureAccountID from StartedAt,
// the database's time.
type ByokCheckTarget struct {
	Grant           ByokCheckGrant
	Provider        string
	EncryptedSecret string
	EncryptionKeyID string
	Target          *CloudTarget
	AzureAccountID  string
	// Registered maps the organization's key labels to the keys that they name.
	Registered map[string]string
	StartedAt  time.Time
	checkedAt  pgtype.Timestamptz
}

// ByokCheckRecord is a recorded check: when it was recorded and, for an Azure credential, its
// target counts as the dashboard shows them.
type ByokCheckRecord struct {
	CheckedAt    time.Time
	AzureTargets *AzureTargetCounts
}

// AzureTargetCounts counts an Azure credential's model matches: those with a selected target, the
// selected ones that cannot serve, and those with a usable target but none selected.
type AzureTargetCounts struct {
	Selected    int `json:"selected"`
	Unavailable int `json:"unavailable"`
	Unselected  int `json:"unselected"`
}

// ByokCheckTarget reads the credential that grant names, after the database finds again that its
// member manages it.
func (s *Service) ByokCheckTarget(ctx context.Context, grant *ByokCheckGrant) (*ByokCheckTarget, error) {
	if s == nil || s.db == nil || grant == nil {
		return nil, ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, byokCheckQueryTimeout)
	defer cancel()
	var result string
	var provider, encryptedSecret, encryptionKeyID, azureAccountID pgtype.Text
	var cloudTarget, keys []byte
	var startedAt pgtype.Timestamptz
	checked := &ByokCheckTarget{Grant: *grant}
	if err := s.db.pool.QueryRow(queryCtx, s.byokCheckTargetQuery, grant.ActorUserID, grant.OrganizationID, grant.ByokID).
		Scan(&result, &provider, &encryptedSecret, &encryptionKeyID, &cloudTarget, &azureAccountID, &keys, &checked.checkedAt, &startedAt); err != nil {
		return nil, fmt.Errorf("%w: read credential check: %v", ErrGatewayUnavailable, err)
	}
	switch result {
	case "ok":
	case "not_found":
		return nil, ErrByokCheckNotFound
	case "inactive":
		return nil, ErrByokCheckInactive
	case "forbidden":
		return nil, ErrByokCheckForbidden
	case "stored":
		return nil, ErrByokCheckStored
	default:
		return nil, fmt.Errorf("%w: read credential check: %s", ErrGatewayUnavailable, result)
	}
	if !provider.Valid || !encryptedSecret.Valid || !encryptionKeyID.Valid || !startedAt.Valid ||
		(provider.String == "azure") != azureAccountID.Valid || json.Unmarshal(keys, &checked.Registered) != nil {
		return nil, fmt.Errorf("%w: read credential check: incomplete credential", ErrGatewayUnavailable)
	}
	checked.Provider, checked.EncryptedSecret, checked.EncryptionKeyID = provider.String, encryptedSecret.String, encryptionKeyID.String
	checked.AzureAccountID, checked.StartedAt = azureAccountID.String, startedAt.Time
	if len(cloudTarget) > 0 && string(cloudTarget) != "null" {
		checked.Target = new(CloudTarget)
		if err := json.Unmarshal(cloudTarget, checked.Target); err != nil {
			return nil, fmt.Errorf("%w: read credential check: %v", ErrGatewayUnavailable, err)
		}
	}
	return checked, nil
}

// Open opens the credential's secret with keys, as a request would: every key must be the one that
// the organization registered under its label, and the key that sealed the credential must be
// registered and among them.
func (t *ByokCheckTarget) Open(keys customerkey.Keys) (string, error) {
	if t == nil {
		return "", ErrGatewayUnavailable
	}
	if !customerkey.Registered(t.Registered, t.EncryptionKeyID) {
		return "", ErrByokKeyUnregistered
	}
	if err := keys.Validate(t.Registered); err != nil {
		return "", err
	}
	if err := keys.Missing(t.Registered, t.EncryptionKeyID); err != nil {
		return "", err
	}
	var envelope customerkey.Envelope
	if json.Unmarshal([]byte(t.EncryptedSecret), &envelope) != nil {
		return "", customerkey.ErrEnvelope
	}
	plaintext, err := keys.Open(envelope, t.Grant.OrganizationID, "byok/"+t.Provider, byokCheckMaxSecret)
	if err != nil {
		return "", err
	}
	secret := string(plaintext)
	clear(plaintext)
	return secret, nil
}

// RecordByokCheck records the check: failure is empty when the provider accepted the credential, and
// otherwise the message that the dashboard shows. discovery is what a check of an Azure credential
// found in its account, nil when it read no deployments.
func (s *Service) RecordByokCheck(ctx context.Context, target *ByokCheckTarget, failure string, discovery *AzureDiscoveryResult) (*ByokCheckRecord, error) {
	if s == nil || s.db == nil || target == nil {
		return nil, ErrGatewayUnavailable
	}
	var message pgtype.Text
	if failure != "" {
		message = pgtype.Text{String: failure, Valid: true}
	}
	bindings, deployments, err := discovery.parameters()
	if err != nil {
		return nil, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, byokCheckQueryTimeout)
	defer cancel()
	var result string
	var checkedAt pgtype.Timestamptz
	var targets []byte
	grant := target.Grant
	if err := s.db.pool.QueryRow(queryCtx, s.recordByokCheckQuery, grant.ActorUserID, grant.OrganizationID, grant.ByokID,
		target.EncryptedSecret, target.checkedAt, message, target.StartedAt, bindings, deployments).Scan(&result, &checkedAt, &targets); err != nil {
		return nil, fmt.Errorf("%w: record credential check: %v", ErrGatewayUnavailable, err)
	}
	switch result {
	case "ok":
		if !checkedAt.Valid {
			return nil, fmt.Errorf("%w: record credential check: no time", ErrGatewayUnavailable)
		}
		record := &ByokCheckRecord{CheckedAt: checkedAt.Time}
		if len(targets) > 0 && string(targets) != "null" {
			record.AzureTargets = new(AzureTargetCounts)
			if err := json.Unmarshal(targets, record.AzureTargets); err != nil {
				return nil, fmt.Errorf("%w: record credential check: %v", ErrGatewayUnavailable, err)
			}
		}
		return record, nil
	case "not_found":
		return nil, ErrByokCheckNotFound
	case "forbidden":
		return nil, ErrByokCheckForbidden
	case "changed":
		return nil, ErrByokCheckChanged
	default:
		return nil, fmt.Errorf("%w: record credential check: %s", ErrGatewayUnavailable, result)
	}
}
