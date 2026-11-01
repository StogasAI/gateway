// Package googleauth signs in to Google Cloud with a service-account key. It
// signs a JWT with the key and exchanges it at Google's fixed token endpoint, so
// nothing in a credential can name another URL, file or command. Tokens live in
// a bounded accesstoken cache; keys are used only for a cache miss.
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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/accesstoken"
)

const (
	tokenURL = "https://oauth2.googleapis.com/token"
	// Scope is the only scope requested: Vertex and Claude on Google Cloud both take it.
	Scope          = "https://www.googleapis.com/auth/cloud-platform"
	assertionLife  = time.Hour
	minimumKeyBits = 2048
)

var (
	ErrCredential  = accesstoken.ErrCredential
	ErrUnavailable = accesstoken.ErrUnavailable
)

// Credential is a service-account key. PrivateKey is the key's PKCS #8 DER in
// standard base64, which is the body of the PEM block in Google's key file.
type Credential struct {
	ClientEmail  string
	PrivateKeyID string
	PrivateKey   string
}

type Diagnostics = accesstoken.Diagnostics

type Cache struct{ tokens *accesstoken.Cache }

// New starts the token cache. requirePostQuantumTLS accepts only TLS 1.3 with
// X25519MLKEM768 to the token endpoint.
func New(ctx context.Context, requirePostQuantumTLS bool) *Cache {
	client, transport := accesstoken.NewClient(requirePostQuantumTLS)
	return &Cache{accesstoken.New(ctx, func(ctx context.Context, parts []string) (accesstoken.Token, error) {
		return exchange(ctx, client, tokenURL, Credential{ClientEmail: parts[0], PrivateKeyID: parts[1], PrivateKey: parts[2]}, time.Now())
	}, transport)}
}

func (c *Cache) Token(ctx context.Context, credential Credential) (string, error) {
	if c == nil {
		return "", ErrUnavailable
	}
	return c.tokens.Token(ctx, credential.ClientEmail, credential.PrivateKeyID, credential.PrivateKey)
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
