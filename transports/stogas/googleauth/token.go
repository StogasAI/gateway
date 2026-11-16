// Package googleauth signs in to Google Cloud with a service-account key, or
// without a secret through a workload identity pool that trusts an
// organization's federation issuer. It exchanges a signed JWT at Google's fixed
// endpoints, so nothing in a credential can name another URL, file or command.
// Tokens live in a bounded accesstoken cache; keys are used only for a cache miss.
package googleauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/accesstoken"
	"github.com/maximhq/bifrost/transports/stogas/federation"
)

const (
	tokenURL = "https://oauth2.googleapis.com/token"
	// The endpoints of workload identity federation: the exchange of an external token, and the
	// service account that a federated identity may act as.
	federationURL    = "https://sts.googleapis.com/v1/token"
	impersonationURL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
	// Scope is the only scope requested: Vertex and Claude on Google Cloud both take it.
	Scope          = "https://www.googleapis.com/auth/cloud-platform"
	assertionLife  = time.Hour
	minimumKeyBits = 2048
)

var (
	ErrCredential  = accesstoken.ErrCredential
	ErrUnavailable = accesstoken.ErrUnavailable
	// ErrProvider means that the pool provider did not accept the organization's
	// token, and ErrServiceAccount that the organization may not act as the
	// service account. Both are ErrCredential, and name the part of the trust to
	// correct.
	ErrProvider       = fmt.Errorf("%w: provider", ErrCredential)
	ErrServiceAccount = fmt.Errorf("%w: service account", ErrCredential)
)

// Credential is a service-account key, or a workload identity pool provider
// that trusts the organization's issuer. PrivateKey is the key's PKCS #8 DER in
// standard base64, which is the body of the PEM block in Google's key file.
// Provider is the provider's resource path, and with it ClientEmail is the
// service account to act as, if any. The caller checks both against their
// patterns.
type Credential struct {
	ClientEmail  string
	PrivateKeyID string
	PrivateKey   string

	OrganizationID string
	Provider       string
}

type Diagnostics = accesstoken.Diagnostics

type Cache struct {
	tokens *accesstoken.Cache
	client *http.Client
	issuer *federation.Issuer
}

// New starts the token cache. requirePostQuantumTLS accepts only TLS 1.3 with
// X25519MLKEM768 to Google's endpoints. issuer signs the tokens of federated
// credentials and is nil where the gateway holds no signing key.
func New(ctx context.Context, requirePostQuantumTLS bool, issuer *federation.Issuer) *Cache {
	client, transport := accesstoken.NewClient(requirePostQuantumTLS)
	cache := &Cache{client: client, issuer: issuer}
	cache.tokens = accesstoken.New(ctx, func(ctx context.Context, parts []string) (accesstoken.Token, error) {
		return cache.signIn(ctx, Credential{ClientEmail: parts[0], PrivateKeyID: parts[1], PrivateKey: parts[2], OrganizationID: parts[3], Provider: parts[4]})
	}, transport)
	return cache
}

func (c *Cache) signIn(ctx context.Context, credential Credential) (accesstoken.Token, error) {
	if credential.Provider != "" {
		return federate(ctx, c.client, c.issuer, federationURL, impersonationURL, credential, time.Now())
	}
	return exchange(ctx, c.client, tokenURL, credential, time.Now())
}

// SignIn signs in anew and discards the token, which shows whether Google accepts the key or
// the organization's token now. The cache neither answers nor keeps it.
func (c *Cache) SignIn(ctx context.Context, credential Credential) error {
	if c == nil {
		return ErrUnavailable
	}
	_, err := c.signIn(ctx, credential)
	return err
}

func (c *Cache) Token(ctx context.Context, credential Credential) (string, error) {
	if c == nil {
		return "", ErrUnavailable
	}
	return c.tokens.Token(ctx, credential.ClientEmail, credential.PrivateKeyID, credential.PrivateKey, credential.OrganizationID, credential.Provider)
}

func (c *Cache) Diagnostics() Diagnostics {
	if c == nil {
		return Diagnostics{}
	}
	return c.tokens.Diagnostics()
}

func (c *Cache) Close() {
	if c != nil {
		c.tokens.Close()
	}
}

// ParsePrivateKey decodes a service-account key: an RSA key of at least 2048
// bits in PKCS #8 DER, in standard base64.
func ParsePrivateKey(encoded string) (*rsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrCredential
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, ErrCredential
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < minimumKeyBits {
		return nil, ErrCredential
	}
	return key, nil
}

func exchange(ctx context.Context, client *http.Client, endpoint string, credential Credential, now time.Time) (accesstoken.Token, error) {
	key, err := ParsePrivateKey(credential.PrivateKey)
	if err != nil {
		return accesstoken.Token{}, err
	}
	assertion, err := signAssertion(key, credential, endpoint, now)
	if err != nil {
		return accesstoken.Token{}, ErrCredential
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	defer response.Body.Close()
	body, err := accesstoken.ReadBounded(response.Body)
	if err != nil {
		return accesstoken.Token{}, err
	}
	switch {
	case response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		// Google answers an unknown, disabled or deleted key with invalid_grant.
		return accesstoken.Token{}, ErrCredential
	case response.StatusCode != http.StatusOK:
		return accesstoken.Token{}, ErrUnavailable
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if json.Unmarshal(body, &token) != nil || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") ||
		token.ExpiresIn <= 0 || token.ExpiresIn > int64(12*time.Hour/time.Second) {
		return accesstoken.Token{}, ErrUnavailable
	}
	return accesstoken.Token{Value: token.AccessToken, ExpiresAt: now.Add(time.Duration(token.ExpiresIn) * time.Second)}, nil
}

// federate exchanges the organization's token for a federated access token at
// Google's Security Token Service and, when the credential names a service
// account, for that account's token.
func federate(ctx context.Context, client *http.Client, issuer *federation.Issuer, exchangeURL, impersonation string, credential Credential, now time.Time) (accesstoken.Token, error) {
	identity, err := issuer.Token(credential.OrganizationID, federation.GoogleAudience(credential.Provider), now)
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {"//iam.googleapis.com/" + credential.Provider},
		"scope":                {Scope},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
		"subject_token":        {identity},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var federated struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := post(client, request, &federated); err != nil {
		return accesstoken.Token{}, refused(err, ErrProvider)
	}
	if federated.AccessToken == "" || federated.ExpiresIn <= 0 || federated.ExpiresIn > int64(12*time.Hour/time.Second) {
		return accesstoken.Token{}, ErrUnavailable
	}
	if credential.ClientEmail == "" {
		return accesstoken.Token{Value: federated.AccessToken, ExpiresAt: now.Add(time.Duration(federated.ExpiresIn) * time.Second)}, nil
	}
	body, err := json.Marshal(map[string]any{"scope": []string{Scope}})
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, impersonation+url.PathEscape(credential.ClientEmail)+":generateAccessToken", strings.NewReader(string(body)))
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+federated.AccessToken)
	var account struct {
		AccessToken string    `json:"accessToken"`
		ExpireTime  time.Time `json:"expireTime"`
	}
	if err := post(client, request, &account); err != nil {
		return accesstoken.Token{}, refused(err, ErrServiceAccount)
	}
	if account.AccessToken == "" {
		return accesstoken.Token{}, ErrUnavailable
	}
	return accesstoken.Token{Value: account.AccessToken, ExpiresAt: account.ExpireTime}, nil
}

// refused names the step that Google refused, and leaves an outage as it is.
func refused(err, step error) error {
	if errors.Is(err, ErrCredential) {
		return step
	}
	return err
}

// post sends a federation request and reads its JSON answer. Google answers a
// token that the pool does not accept with 400 or 401, and an identity that may
// not act as the service account with 403 or 404, which only the customer can
// change.
func post(client *http.Client, request *http.Request, answer any) error {
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	body, err := accesstoken.ReadBounded(response.Body)
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return ErrCredential
	default:
		return ErrUnavailable
	}
	if json.Unmarshal(body, answer) != nil {
		return ErrUnavailable
	}
	return nil
}

// signAssertion builds the RS256 JWT that Google's token endpoint exchanges.
func signAssertion(key *rsa.PrivateKey, credential Credential, audience string, now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": credential.PrivateKeyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss":   credential.ClientEmail,
		"scope": Scope,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(assertionLife).Unix(),
	})
	if err != nil {
		return "", err
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
