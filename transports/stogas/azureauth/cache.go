// Package azureauth signs in to Microsoft Entra as an application: with its
// client secret, or without one when the application holds a federated
// credential that trusts an organization's federation issuer. Tokens live in a
// bounded accesstoken cache; client secrets are used only for a cache miss and
// are never retained in cache entries.
package azureauth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/maximhq/bifrost/transports/stogas/accesstoken"
	"github.com/maximhq/bifrost/transports/stogas/federation"
)

var (
	ErrCredential  = accesstoken.ErrCredential
	ErrUnavailable = accesstoken.ErrUnavailable
)

// Credential is an application and the scope to sign in for. Without a
// Secret, the application signs in with the token of OrganizationID.
type Credential struct {
	TenantID string
	ClientID string
	Secret   string
	Scope    string

	OrganizationID string
}

type Diagnostics = accesstoken.Diagnostics

type Cache struct {
	tokens *accesstoken.Cache
	client *http.Client
	issuer *federation.Issuer
}

// New starts the token cache. issuer signs the tokens of federated
// applications and is nil where the gateway holds no signing key.
func New(ctx context.Context, issuer *federation.Issuer) *Cache {
	client, transport := accesstoken.NewClient(false)
	return &Cache{tokens: accesstoken.New(ctx, func(ctx context.Context, parts []string) (accesstoken.Token, error) {
		return signIn(ctx, client, issuer, Credential{TenantID: parts[0], ClientID: parts[1], Secret: parts[2], Scope: parts[3], OrganizationID: parts[4]})
	}, transport), client: client, issuer: issuer}
}

func signIn(ctx context.Context, client *http.Client, issuer *federation.Issuer, credential Credential) (accesstoken.Token, error) {
	options := azcore.ClientOptions{
		Transport: accesstoken.BoundedTransport{Client: client},
		Retry:     policy.RetryOptions{MaxRetries: -1},
	}
	var auth azcore.TokenCredential
	var err error
	if credential.Secret == "" {
		if issuer == nil {
			return accesstoken.Token{}, ErrUnavailable
		}
		auth, err = azidentity.NewClientAssertionCredential(credential.TenantID, credential.ClientID, func(context.Context) (string, error) {
			return issuer.Token(credential.OrganizationID, federation.AudienceAzure, time.Now())
		}, &azidentity.ClientAssertionCredentialOptions{ClientOptions: options})
	} else {
		auth, err = azidentity.NewClientSecretCredential(credential.TenantID, credential.ClientID, credential.Secret, &azidentity.ClientSecretCredentialOptions{ClientOptions: options})
	}
	if err != nil {
		return accesstoken.Token{}, ErrCredential
	}
	token, err := auth.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{credential.Scope}})
	if err != nil {
		var rejected *azidentity.AuthenticationFailedError
		if errors.As(err, &rejected) && rejected.RawResponse != nil {
			switch rejected.RawResponse.StatusCode {
			case 400, 401, 403:
				return accesstoken.Token{}, ErrCredential
			}
		}
		return accesstoken.Token{}, ErrUnavailable
	}
	return accesstoken.Token{Value: token.Token, ExpiresAt: token.ExpiresOn}, nil
}

// SignIn signs in anew and returns the token, which shows whether Entra accepts the application's
// secret now. The cache neither answers nor keeps it.
func (c *Cache) SignIn(ctx context.Context, credential Credential) (string, error) {
	if c == nil {
		return "", ErrUnavailable
	}
	token, err := signIn(ctx, c.client, c.issuer, credential)
	if err != nil {
		return "", err
	}
	if !accesstoken.Usable(token, time.Now()) {
		return "", ErrUnavailable
	}
	return token.Value, nil
}

func (c *Cache) Token(ctx context.Context, credential Credential) (string, error) {
	if c == nil {
		return "", ErrUnavailable
	}
	return c.tokens.Token(ctx, credential.TenantID, credential.ClientID, credential.Secret, credential.Scope, credential.OrganizationID)
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
