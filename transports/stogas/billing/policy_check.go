package billing

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	policyCheckGrantPrefix      = "stogas_policy_check_v1."
	policyCheckGrantAudience    = "stogas-policy-check"
	policyCheckGrantScope       = "policy-check"
	policyCheckGrantMaxLifetime = 5 * time.Minute
)

var ErrPolicyCheckGrant = &RequestError{"invalid_check_grant", "The policy check grant is invalid or expired. Run the check again.", 401}

// PolicyCheckGrant names the member and organization that Control let check policy text. A
// member's check needs no API key: it reads nothing that the request does not send, and opens
// only the envelopes whose keys the request sends, as the organization's.
type PolicyCheckGrant struct {
	ActorUserID    string
	OrganizationID string
}

type policyCheckGrantClaims struct {
	Audience     string `json:"aud"`
	ExpiresAt    int64  `json:"exp"`
	IssuedAt     int64  `json:"iat"`
	Issuer       string `json:"iss"`
	JWTID        string `json:"jti"`
	Organization string `json:"org"`
	Scope        string `json:"scope"`
	Subject      string `json:"sub"`
}

func IsPolicyCheckGrant(raw string) bool {
	return strings.HasPrefix(raw, policyCheckGrantPrefix)
}

func parsePolicyCheckGrant(raw string, publicKey *inferenceTokenKey, now time.Time) (*PolicyCheckGrant, error) {
	if !IsPolicyCheckGrant(raw) || publicKey == nil {
		return nil, ErrPolicyCheckGrant
	}
	payload, err := verifySignedToken(strings.TrimPrefix(raw, policyCheckGrantPrefix), publicKey)
	if err != nil {
		return nil, ErrPolicyCheckGrant
	}
	var claims policyCheckGrantClaims
	if err := decodeStrictJSON(payload, &claims); err != nil {
		return nil, ErrPolicyCheckGrant
	}
	subject, subjectErr := uuid.Parse(claims.Subject)
	organization, organizationErr := uuid.Parse(claims.Organization)
	jwtID, jwtIDErr := uuid.Parse(claims.JWTID)
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	now = now.UTC()
	if claims.Issuer != inferenceTokenIssuer ||
		claims.Audience != policyCheckGrantAudience ||
		claims.Scope != policyCheckGrantScope ||
		subjectErr != nil || subject == uuid.Nil || subject.String() != claims.Subject ||
		organizationErr != nil || organization == uuid.Nil || organization.String() != claims.Organization ||
		jwtIDErr != nil || jwtID == uuid.Nil ||
		claims.ExpiresAt <= claims.IssuedAt ||
		expiresAt.Sub(issuedAt) > policyCheckGrantMaxLifetime ||
		!now.Before(expiresAt) ||
		issuedAt.After(now.Add(inferenceTokenClockSkew)) {
		return nil, ErrPolicyCheckGrant
	}
	return &PolicyCheckGrant{ActorUserID: claims.Subject, OrganizationID: claims.Organization}, nil
}

// ParsePolicyCheckGrant verifies a grant and admits its check, which counts against the member in
// the organization at the organization's rate, as each grant that Control signs for them does.
func (s *Service) ParsePolicyCheckGrant(raw string) (*PolicyCheckGrant, error) {
	if s == nil {
		return nil, ErrPolicyCheckGrant
	}
	now := time.Now()
	grant, err := parsePolicyCheckGrant(raw, s.inferenceTokenPublicKey, now)
	if err != nil {
		return nil, err
	}
	return grant, s.admitCredential(grant.admissionKey(), grant.OrganizationID, now)
}

func (g *PolicyCheckGrant) admissionKey() string {
	return "policy-check:" + g.ActorUserID + ":" + g.OrganizationID
}
