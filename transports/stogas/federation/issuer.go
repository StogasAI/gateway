// Package federation issues the identity tokens that a customer's cloud
// exchanges for its own short-lived credentials, so that a provider credential
// holds no secret. Each organization has its own issuer URL, so a cloud that
// trusts one organization's issuer accepts no token of another. Control serves
// the issuer's discovery document and public keys; only gateways hold the
// signing key.
package federation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// The audiences that each cloud's documentation names for an external issuer. Google's
	// audience is the customer's workload identity provider, so GoogleAudience builds it.
	AudienceAWS   = "sts.amazonaws.com"
	AudienceAzure = "api://AzureADTokenExchange"

	// A token is exchanged at once, so it lives only long enough for a slow sign-in.
	tokenLife      = 5 * time.Minute
	minimumKeyBits = 2048
)

// ErrUnavailable means that this gateway holds no signing key.
var ErrUnavailable = errors.New("federation is unavailable")

var organizationPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Issuer signs tokens with RS256, the one algorithm that AWS, Google Cloud and
// Microsoft Entra all accept from an external issuer.
type Issuer struct {
	key    *rsa.PrivateKey
	keyID  string
	origin string
}

// NewIssuer reads the signing key, an RSA key of at least 2048 bits in PKCS #8
// DER and standard base64. origin is the dashboard's origin, where Control
// serves each organization's discovery document.
func NewIssuer(privateKey, origin string) (*Issuer, error) {
	der, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, errors.New("the federation signing key is not base64")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("the federation signing key is not PKCS #8")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < minimumKeyBits {
		return nil, errors.New("the federation signing key must be an RSA key of at least 2048 bits")
	}
	if origin == "" {
		return nil, errors.New("the federation issuer needs an origin")
	}
	return &Issuer{key: key, keyID: KeyID(&key.PublicKey), origin: origin}, nil
}

// KeyID is a public key's RFC 7638 thumbprint, which names the key in the
// published key set.
func KeyID(key *rsa.PublicKey) string {
	encode := base64.RawURLEncoding.EncodeToString
	// RFC 7638 fixes the members and their order.
	digest := sha256.Sum256([]byte(`{"e":"` + encode(big.NewInt(int64(key.E)).Bytes()) + `","kty":"RSA","n":"` + encode(key.N.Bytes()) + `"}`))
	return encode(digest[:])
}

// IssuerURL is the issuer of one organization's tokens.
func (i *Issuer) IssuerURL(organizationID string) string {
	return i.origin + "/api/federation/" + organizationID
}

// Subject is the subject of every token of one organization. Provider
// credentials belong to the organization, so it is what a cloud trusts.
func Subject(organizationID string) string {
	return "organization:" + organizationID
}

// GoogleAudience is the audience that Google expects for a workload identity
// pool provider, named by its resource path.
func GoogleAudience(provider string) string {
	return "https://iam.googleapis.com/" + provider
}

// Token signs a token that states the organization to one audience.
func (i *Issuer) Token(organizationID, audience string, now time.Time) (string, error) {
	if i == nil {
		return "", ErrUnavailable
	}
	if !organizationPattern.MatchString(organizationID) || audience == "" {
		return "", errors.New("invalid federation token request")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	// The audience is one string, the form that every cloud documents.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": i.IssuerURL(organizationID),
		"sub": Subject(organizationID),
		"aud": audience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(tokenLife).Unix(),
		"jti": hex.EncodeToString(id),
	})
	token.Header["kid"] = i.keyID
	return token.SignedString(i.key)
}
