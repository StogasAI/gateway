package stogas

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/googleauth"
)

// A member checks a customer-encrypted credential through a gateway, which alone can open it.
// The check makes the free read that Control's check of a stored credential makes, and reports
// and records the result in the same words, so the dashboard shows both kinds alike. A 2xx answer
// accepts the credential, a 4xx answer other than 408, 409, 425 and 429 rejects it, and anything
// else leaves it unverified.
const (
	byokCheckTimeout       = 8 * time.Second
	byokCheckLimit         = 4
	byokCheckResponseLimit = 64 << 10
	stsRequestBody         = "Action=GetCallerIdentity&Version=2011-06-15"
)

var byokProviderNames = map[string]string{
	"anthropic": "Anthropic", "aws": "AWS", "azure": "Azure", "chutes": "Chutes", "google-cloud": "Google Cloud", "openai": "OpenAI",
}

// ByokCheckResult is a recorded check. CheckError is nil when the provider accepted the
// credential, and otherwise the message that the dashboard shows for it.
type ByokCheckResult struct {
	CheckedAt  time.Time `json:"checkedAt"`
	CheckError *string   `json:"checkError"`
}

type googleSignIn interface {
	SignIn(context.Context, googleauth.Credential) error
}

type byokChecker struct {
	openAIBaseURL    string
	anthropicBaseURL string
	chutesAPIBaseURL string
	// client reaches OpenAI, Anthropic and Chutes, which take post-quantum key exchange; aws
	// reaches AWS, whose endpoints offer TLS 1.3 with classical key exchange.
	client *http.Client
	aws    *http.Client
	google googleSignIn
	now    func() time.Time
	slots  chan struct{}
}

// newByokChecker reaches each provider as requests do. The runtime sets google once its token
// cache starts.
func newByokChecker(config Config) (*byokChecker, error) {
	chutesAPIBaseURL, err := chutesE2EEAPIBaseURL(config.ChutesBaseURL)
	if err != nil {
		return nil, err
	}
	production := confidentialProduction(config)
	modern := &tls.Config{MinVersion: tls.VersionTLS12}
	awsTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	if production {
		modern = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
		awsTLS = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	return &byokChecker{
		openAIBaseURL:    strings.TrimRight(defaultString(config.OpenAIBaseURL, "https://api.openai.com"), "/"),
		anthropicBaseURL: strings.TrimRight(defaultString(config.AnthropicBaseURL, "https://api.anthropic.com"), "/"),
		chutesAPIBaseURL: chutesAPIBaseURL,
		client:           byokCheckClient(modern),
		aws:              byokCheckClient(awsTLS),
		now:              time.Now,
		slots:            make(chan struct{}, byokCheckLimit),
	}, nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// byokCheckClient never follows a redirect, as Control's check does not.
func byokCheckClient(config *tls.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = config
	transport.MaxIdleConnsPerHost = byokCheckLimit
	transport.IdleConnTimeout = 30 * time.Second
	return &http.Client{Transport: transport, Timeout: byokCheckTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// CheckByok checks the customer-encrypted credential that grant names with keys, and records the
// result for the dashboard.
func (r *Runtime) CheckByok(ctx context.Context, grant *billing.ByokCheckGrant, keys customerkey.Keys) (*ByokCheckResult, error) {
	if r == nil || r.billing == nil || r.byokChecks == nil {
		return nil, billing.ErrGatewayUnavailable
	}
	return checkByok(ctx, r.billing, r.byokChecks, grant, keys)
}

type byokCheckStore interface {
	ByokCheckTarget(context.Context, *billing.ByokCheckGrant) (*billing.ByokCheckTarget, error)
	RecordByokCheck(context.Context, *billing.ByokCheckTarget, string) (time.Time, error)
}

func checkByok(ctx context.Context, store byokCheckStore, checker *byokChecker, grant *billing.ByokCheckGrant, keys customerkey.Keys) (*ByokCheckResult, error) {
	target, err := store.ByokCheckTarget(ctx, grant)
	if err != nil {
		return nil, err
	}
	secret, err := target.Open(keys)
	if err != nil {
		return nil, err
	}
	select {
	case checker.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	failure := checker.check(ctx, target.Provider, secret, target.Target)
	<-checker.slots
	checkedAt, err := store.RecordByokCheck(ctx, target, failure)
	if err != nil {
		return nil, err
	}
	result := &ByokCheckResult{CheckedAt: checkedAt}
	if failure != "" {
		result.CheckError = &failure
	}
	return result, nil
}

// check returns "" when the provider accepts secret, and otherwise why it did not.
func (c *byokChecker) check(ctx context.Context, provider, secret string, registered *billing.CloudTarget) string {
	ctx, cancel := context.WithTimeout(ctx, byokCheckTimeout)
	defer cancel()
	switch provider {
	case "openai", "anthropic", "chutes":
		if !validUpstreamAPIKey(secret) {
			return invalidByokSecret(provider)
		}
		var request *http.Request
		var err error
		switch provider {
		case "openai":
			request, err = http.NewRequestWithContext(ctx, http.MethodGet, c.openAIBaseURL+"/v1/models", nil)
			if err == nil {
				request.Header.Set("Authorization", "Bearer "+secret)
			}
		case "anthropic":
			request, err = http.NewRequestWithContext(ctx, http.MethodGet, c.anthropicBaseURL+"/v1/models?limit=1", nil)
			if err == nil {
				request.Header.Set("anthropic-version", "2023-06-01")
				request.Header.Set("x-api-key", secret)
			}
		default:
			request, err = http.NewRequestWithContext(ctx, http.MethodGet, c.chutesAPIBaseURL+"/users/me/quotas", nil)
			if err == nil {
				request.Header.Set("Authorization", "Bearer "+secret)
			}
		}
		if err != nil {
			return byokUnavailable(provider)
		}
		return c.read(provider, c.client, request)
	case "aws":
		return c.checkAWS(ctx, secret, registered)
	case "google-cloud":
		return c.checkGoogle(ctx, secret, registered)
	}
	return byokUnavailable(provider)
}

// checkAWS makes the cheapest request that each AWS credential can: an access key asks STS who it
// is, which needs no permission; a Bedrock API key lists Anthropic models, and a Claude Platform on
// AWS API key lists its workspace's models.
func (c *byokChecker) checkAWS(ctx context.Context, secret string, registered *billing.CloudTarget) string {
	credential, err := parseAWSByokCredential(secret)
	if err != nil {
		return invalidByokSecret("aws")
	}
	if failure := cloudTargetMismatch(catalog.ProviderAWS, secret, registered); failure != "" {
		return failure
	}
	var request *http.Request
	switch {
	case credential.AccessKeyID != "":
		request, err = http.NewRequestWithContext(ctx, http.MethodPost, "https://sts."+credential.Region+".amazonaws.com/", strings.NewReader(stsRequestBody))
		if err != nil {
			return byokUnavailable("aws")
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		digest := sha256.Sum256([]byte(stsRequestBody))
		if err := v4.NewSigner().SignHTTP(ctx, aws.Credentials{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey},
			request, hex.EncodeToString(digest[:]), "sts", credential.Region, c.now()); err != nil {
			return byokUnavailable("aws")
		}
	case credential.WorkspaceID != "":
		request, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://aws-external-anthropic."+credential.Region+".api.aws/v1/models?limit=1", nil)
		if err != nil {
			return byokUnavailable("aws")
		}
		request.Header.Set("Authorization", "Bearer "+credential.APIKey)
		request.Header.Set("anthropic-version", "2023-06-01")
		request.Header.Set("anthropic-workspace-id", credential.WorkspaceID)
	default:
		request, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://bedrock."+credential.Region+".amazonaws.com/foundation-models?byProvider=Anthropic", nil)
		if err != nil {
			return byokUnavailable("aws")
		}
		request.Header.Set("Authorization", "Bearer "+credential.APIKey)
	}
	return c.read("aws", c.aws, request)
}

// checkGoogle exchanges a newly signed assertion at Google's token endpoint, bypassing the token
// cache, so a key that Google disabled since its last token fails now.
func (c *byokChecker) checkGoogle(ctx context.Context, secret string, registered *billing.CloudTarget) string {
	credential, err := parseGoogleCloudByokCredential(secret)
	if err != nil {
		return invalidByokSecret("google-cloud")
	}
	if failure := cloudTargetMismatch(catalog.ProviderGoogleCloud, secret, registered); failure != "" {
		return failure
	}
	if c.google == nil {
		return byokUnavailable("google-cloud")
	}
	err = c.google.SignIn(ctx, googleauth.Credential{ClientEmail: credential.ClientEmail, PrivateKeyID: credential.PrivateKeyID, PrivateKey: credential.PrivateKey})
	switch {
	case err == nil:
		return ""
	case errors.Is(err, googleauth.ErrCredential):
		return byokRejected("google-cloud")
	default:
		return byokUnavailable("google-cloud")
	}
}

// cloudTargetMismatch reports a secret that cannot serve the target that the credential was added
// with, which requests would refuse: another Region, or a hosting that the secret does not serve.
func cloudTargetMismatch(provider schemas.ModelProvider, secret string, registered *billing.CloudTarget) string {
	actual, err := cloudCredentialTarget(provider, secret)
	if err != nil {
		return invalidByokSecret(string(provider))
	}
	if registered == nil || registered.Region != actual.Region {
		return "The credential is for another Region than the target it was added with. Add the target that stogas encrypt printed for it."
	}
	for _, hosting := range registered.Hosting {
		if !slices.Contains(actual.Hosting, hosting) {
			return "The credential cannot serve every hosting of the target it was added with. Add the target that stogas encrypt printed for it."
		}
	}
	return ""
}

func (c *byokChecker) read(provider string, client *http.Client, request *http.Request) string {
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return byokUnavailable(provider)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, byokCheckResponseLimit))
	switch status := response.StatusCode; {
	case status >= 200 && status < 300:
		return ""
	case status >= 400 && status < 500 && status != 408 && status != 409 && status != 425 && status != 429:
		return byokRejected(provider)
	default:
		return byokUnavailable(provider)
	}
}

// byokCredentialName names what a provider's secret is: AWS and Google Cloud take a credential
// document rather than an API key.
func byokCredentialName(provider string) string {
	if provider == "aws" || provider == "google-cloud" {
		return "credential"
	}
	return "API key"
}

func byokRejected(provider string) string {
	return byokProviderNames[provider] + " did not accept this " + byokCredentialName(provider) + " or configuration"
}

func byokUnavailable(provider string) string {
	return "Could not verify the " + byokProviderNames[provider] + " " + byokCredentialName(provider) + ". Try again."
}

func invalidByokSecret(provider string) string {
	return "The decrypted secret is not a valid " + byokProviderNames[provider] + " " + byokCredentialName(provider) +
		". Encrypt it again with stogas encrypt --purpose byok/" + provider + "."
}
