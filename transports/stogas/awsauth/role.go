// Package awsauth signs in to AWS as an IAM role that trusts an organization's
// federation issuer. It exchanges a newly signed identity token at the Region's
// STS endpoint, so nothing in a credential can name another URL. Role
// credentials live in a bounded accesstoken cache.
package awsauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/maximhq/bifrost/transports/stogas/accesstoken"
	"github.com/maximhq/bifrost/transports/stogas/federation"
)

// AWS issues role credentials for an hour unless asked otherwise, which every role allows.
const sessionSeconds = "3600"

var (
	ErrCredential  = accesstoken.ErrCredential
	ErrUnavailable = accesstoken.ErrUnavailable
)

// Credential names the role that an organization's tokens assume. The caller
// checks Region and RoleARN against their patterns.
type Credential struct {
	OrganizationID string
	Region         string
	RoleARN        string
}

type Diagnostics = accesstoken.Diagnostics

type Cache struct {
	tokens *accesstoken.Cache
	client *http.Client
	issuer *federation.Issuer
}

// New starts the cache. AWS endpoints offer TLS 1.3 with classical key
// exchange, so requireTLS13 sets the floor that production holds.
func New(ctx context.Context, issuer *federation.Issuer, requireTLS13 bool) *Cache {
	client, transport := accesstoken.NewClient(false)
	if requireTLS13 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	}
	cache := &Cache{client: client, issuer: issuer}
	cache.tokens = accesstoken.New(ctx, func(ctx context.Context, parts []string) (accesstoken.Token, error) {
		return cache.assume(ctx, Credential{OrganizationID: parts[0], Region: parts[1], RoleARN: parts[2]})
	}, transport)
	return cache
}

// roleCredentials is how the cache holds a role's credentials: as one token value.
type roleCredentials struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
}

// SignIn assumes the role anew and discards the credentials, which shows
// whether AWS accepts the organization's token for it now.
func (c *Cache) SignIn(ctx context.Context, credential Credential) error {
	if c == nil {
		return ErrUnavailable
	}
	_, err := c.assume(ctx, credential)
	return err
}

// Credentials returns the role's current credentials.
func (c *Cache) Credentials(ctx context.Context, credential Credential) (aws.Credentials, error) {
	if c == nil {
		return aws.Credentials{}, ErrUnavailable
	}
	value, err := c.tokens.Token(ctx, credential.OrganizationID, credential.Region, credential.RoleARN)
	if err != nil {
		return aws.Credentials{}, err
	}
	var role roleCredentials
	if json.Unmarshal([]byte(value), &role) != nil {
		return aws.Credentials{}, ErrUnavailable
	}
	return aws.Credentials{AccessKeyID: role.AccessKeyID, SecretAccessKey: role.SecretAccessKey, SessionToken: role.SessionToken}, nil
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

func (c *Cache) assume(ctx context.Context, credential Credential) (accesstoken.Token, error) {
	return assume(ctx, c.client, c.issuer, "https://sts."+credential.Region+".amazonaws.com/", credential, time.Now())
}

// assume exchanges the organization's token for the role's credentials at one
// Region's Security Token Service.
func assume(ctx context.Context, client *http.Client, issuer *federation.Issuer, endpoint string, credential Credential, now time.Time) (accesstoken.Token, error) {
	identity, err := issuer.Token(credential.OrganizationID, federation.AudienceAWS, now)
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {credential.RoleARN},
		"RoleSessionName":  {"stogas-" + credential.OrganizationID},
		"WebIdentityToken": {identity},
		"DurationSeconds":  {sessionSeconds},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	response, err := client.Do(request)
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	defer response.Body.Close()
	body, err := accesstoken.ReadBounded(response.Body)
	if err != nil {
		return accesstoken.Token{}, err
	}
	if response.StatusCode != http.StatusOK {
		return accesstoken.Token{}, refusal(response.StatusCode, body)
	}
	var result struct {
		Credentials struct {
			AccessKeyID     string    `xml:"AccessKeyId"`
			SecretAccessKey string    `xml:"SecretAccessKey"`
			SessionToken    string    `xml:"SessionToken"`
			Expiration      time.Time `xml:"Expiration"`
		} `xml:"AssumeRoleWithWebIdentityResult>Credentials"`
	}
	role := &result.Credentials
	if xml.Unmarshal(body, &result) != nil || role.AccessKeyID == "" || role.SecretAccessKey == "" || role.SessionToken == "" {
		return accesstoken.Token{}, ErrUnavailable
	}
	value, err := json.Marshal(roleCredentials{AccessKeyID: role.AccessKeyID, SecretAccessKey: role.SecretAccessKey, SessionToken: role.SessionToken})
	if err != nil {
		return accesstoken.Token{}, ErrUnavailable
	}
	return accesstoken.Token{Value: string(value), ExpiresAt: role.Expiration}, nil
}

// refusal sorts an STS error. AWS refuses a role that does not trust the
// token, a token that it cannot verify and a Region that the account has
// disabled, which only the customer can change. IDPCommunicationError means
// that AWS could not read the issuer's keys, and throttling passes.
func refusal(status int, body []byte) error {
	var failure struct {
		Code string `xml:"Error>Code"`
	}
	if xml.Unmarshal(body, &failure) != nil {
		return ErrUnavailable
	}
	switch failure.Code {
	case "AccessDenied", "InvalidIdentityToken", "IDPRejectedClaim", "ExpiredTokenException", "RegionDisabledException", "ValidationError", "MalformedPolicyDocument", "PackedPolicyTooLarge":
		if status == http.StatusBadRequest || status == http.StatusForbidden {
			return ErrCredential
		}
	}
	return ErrUnavailable
}
