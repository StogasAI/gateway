// Package azureauth signs in to Microsoft Entra with a client secret. Tokens
// live in a bounded accesstoken cache; client secrets are used only for a cache
// miss and are never retained in cache entries.
package azureauth

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/maximhq/bifrost/transports/stogas/accesstoken"
)

var (
	ErrCredential  = accesstoken.ErrCredential
	ErrUnavailable = accesstoken.ErrUnavailable
)

type Credential struct {
	TenantID string
	ClientID string
	Secret   string
	Scope    string
}

type Diagnostics = accesstoken.Diagnostics

type Cache struct{ tokens *accesstoken.Cache }

func New(ctx context.Context) *Cache {
	client, transport := accesstoken.NewClient(false)
	return &Cache{accesstoken.New(ctx, func(ctx context.Context, parts []string) (accesstoken.Token, error) {
		tenantID, clientID, secret, scope := parts[0], parts[1], parts[2], parts[3]
		auth, err := azidentity.NewClientSecretCredential(tenantID, clientID, secret, &azidentity.ClientSecretCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Transport: accesstoken.BoundedTransport{Client: client},
				Retry:     policy.RetryOptions{MaxRetries: -1},
			},
		})
		if err != nil {
			return accesstoken.Token{}, ErrCredential
		}
		token, err := auth.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
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
	}, transport)}
}

func (c *Cache) Token(ctx context.Context, credential Credential) (string, error) {
	if c == nil {
		return "", ErrUnavailable
	}
	return c.tokens.Token(ctx, credential.TenantID, credential.ClientID, credential.Secret, credential.Scope)
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
