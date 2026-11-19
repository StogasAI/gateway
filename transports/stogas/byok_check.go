package stogas

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/accesstoken"
	"github.com/maximhq/bifrost/transports/stogas/awsauth"
	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/googleauth"
)

// Gateways check every credential: a member checks a customer-encrypted one, which only a gateway
// can open, and Control checks stored ones when they are saved, on demand and on its schedule. A
// check makes the cheapest read that the provider answers for the credential. A 2xx answer accepts
// it, a 4xx answer other than 408, 409, 425 and 429 rejects it, and anything else leaves it
// unverified. An Azure credential's check signs in to Entra anew and discovers the account's
// targets.
const (
	byokCheckTimeout = 8 * time.Second
	// A run of Control's schedule sends four checks at once, which four slots start together, and
	// the slots bound the Azure discoveries in flight, whose reads request admission does not count.
	byokCheckLimit         = 4
	byokCheckResponseLimit = 64 << 10
	stsRequestBody         = "Action=GetCallerIdentity&Version=2011-06-15"
)

var byokProviderNames = map[string]string{
	"anthropic": "Anthropic", "aws": "AWS", "azure": "Azure", "chutes": "Chutes", "google-cloud": "Google Cloud", "openai": "OpenAI",
}

// ByokCheckResult is a recorded check. CheckError is nil when the provider accepted the
// credential, and otherwise the message that the dashboard shows for it. AzureTargets counts an
// Azure credential's model matches after the check, as the dashboard does, and is nil for other
// providers.
type ByokCheckResult struct {
	CheckedAt    time.Time                  `json:"checkedAt"`
	CheckError   *string                    `json:"checkError"`
	AzureTargets *billing.AzureTargetCounts `json:"azureTargets"`
}

type googleSignIn interface {
	SignIn(context.Context, googleauth.Credential) error
}

type azureSignIn interface {
	SignIn(context.Context, azureauth.Credential) (string, error)
}

type awsRoleSignIn interface {
	SignIn(context.Context, awsauth.Credential) error
}

type byokChecker struct {
	openAIBaseURL    string
	anthropicBaseURL string
	chutesAPIBaseURL string
	// client reaches OpenAI, Anthropic and Chutes, which take post-quantum key exchange; aws
	// reaches AWS, whose endpoints offer TLS 1.3 with classical key exchange.
	client *http.Client
	aws    *http.Client
	// arm reads Azure Resource Manager as the gateway's checks of Azure deployments do.
	arm    *http.Client
	google googleSignIn
	azure  azureSignIn
	roles  awsRoleSignIn
	now    func() time.Time
	slots  *checkSlots
}

// newByokChecker reaches each provider as requests do. The runtime sets google and azure once
// their token caches start.
func newByokChecker(config Config) (*byokChecker, error) {
	chutesAPIBaseURL, err := chutesE2EEAPIBaseURL(config.ChutesBaseURL)
	if err != nil {
		return nil, err
	}
	production := confidentialProduction(config)
	armClient, _ := accesstoken.NewClient(false)
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
		arm:              armClient,
		now:              time.Now,
		slots:            newCheckSlots(byokCheckLimit),
	}, nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// byokCheckClient never follows a redirect.
func byokCheckClient(config *tls.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = config
	transport.MaxIdleConnsPerHost = byokCheckLimit
	transport.IdleConnTimeout = 30 * time.Second
	return &http.Client{Transport: transport, Timeout: byokCheckTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// byokFailure is why a check did not accept a credential: the message that the dashboard shows,
// whether the provider or the secret itself refused the credential, which trying again does not
// change, rather than leaving it unverified, and whether the secret holds no credential of its
// provider at all. The zero value accepts the credential.
type byokFailure struct {
	message  string
	rejected bool
	invalid  bool
	// The secret cannot serve the target that the credential names.
	target bool
}

func refusal(message string) byokFailure { return byokFailure{message: message, rejected: true} }

func unverified(message string) byokFailure { return byokFailure{message: message} }

func invalidSecret(provider string) byokFailure {
	return byokFailure{message: invalidByokSecret(provider), rejected: true, invalid: true}
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
	RecordByokCheck(context.Context, *billing.ByokCheckTarget, string, *billing.AzureDiscoveryResult) (*billing.ByokCheckRecord, error)
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
	found, failure, err := checker.run(ctx, grant.OrganizationID, target.Provider, secret, target.Target, target.AzureAccountID, target.StartedAt)
	if err != nil {
		return nil, err
	}
	message, discovery := failure.message, (*billing.AzureDiscoveryResult)(nil)
	if found != nil {
		message, discovery = azureDiscoveryOutcome(found, nil)
	}
	record, err := store.RecordByokCheck(ctx, target, message, discovery)
	if err != nil {
		return nil, err
	}
	result := &ByokCheckResult{CheckedAt: record.CheckedAt, AzureTargets: record.AzureTargets}
	if message != "" {
		result.CheckError = &message
	}
	return result, nil
}

// checkSlots bounds the checks that a gateway runs at once to byokCheckLimit and shares them between
// organizations, as an Azure discovery can hold a slot for 25 seconds:
//   - An organization that holds a slot never takes the last free one, which stays for an
//     organization that holds none. Alone, an organization runs all slots but one.
//   - A slot that frees goes to the waiting organization that holds the fewest, and among equals to
//     the check that has waited longest, so one organization's queued checks never hold back
//     another organization's.
type checkSlots struct {
	mu   sync.Mutex
	free int
	// The slots that each organization holds, and its waiting checks, oldest first.
	held    map[string]int
	waiting map[string][]*checkWaiter
	queued  uint64
}

type checkWaiter struct {
	ready chan struct{}
	order uint64
}

func newCheckSlots(limit int) *checkSlots {
	return &checkSlots{free: limit, held: map[string]int{}, waiting: map[string][]*checkWaiter{}}
}

// take waits for a slot for the organization and returns what frees it.
func (s *checkSlots) take(ctx context.Context, organizationID string) (func(), error) {
	release := func() {
		s.mu.Lock()
		s.release(organizationID)
		s.mu.Unlock()
	}
	s.mu.Lock()
	// A check that waits leaves the free slot as the one kept for organizations that hold none.
	if s.free > 1 || s.free == 1 && s.held[organizationID] == 0 {
		s.free--
		s.held[organizationID]++
		s.mu.Unlock()
		return release, nil
	}
	s.queued++
	waiter := &checkWaiter{ready: make(chan struct{}), order: s.queued}
	s.waiting[organizationID] = append(s.waiting[organizationID], waiter)
	s.mu.Unlock()
	select {
	case <-waiter.ready:
		return release, nil
	case <-ctx.Done():
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	queue := s.waiting[organizationID]
	if at := slices.Index(queue, waiter); at >= 0 {
		if queue = slices.Delete(queue, at, at+1); len(queue) == 0 {
			delete(s.waiting, organizationID)
		} else {
			s.waiting[organizationID] = queue
		}
	} else {
		// The slot came as the wait ended, so the next check takes it.
		s.release(organizationID)
	}
	return nil, ctx.Err()
}

// release frees one of the organization's slots and hands free slots to waiting checks. The caller
// holds s.mu.
func (s *checkSlots) release(organizationID string) {
	if s.held[organizationID]--; s.held[organizationID] == 0 {
		delete(s.held, organizationID)
	}
	s.free++
	for s.free > 0 {
		next, first := "", (*checkWaiter)(nil)
		for organization, queue := range s.waiting {
			if first == nil || s.held[organization] < s.held[next] ||
				s.held[organization] == s.held[next] && queue[0].order < first.order {
				next, first = organization, queue[0]
			}
		}
		if first == nil || s.free == 1 && s.held[next] > 0 {
			return
		}
		if queue := s.waiting[next][1:]; len(queue) == 0 {
			delete(s.waiting, next)
		} else {
			s.waiting[next] = queue
		}
		s.free--
		s.held[next]++
		close(first.ready)
	}
}

// run checks an organization's credential while it holds one of the checker's slots. For an Azure
// credential, it discovers the targets of the account accountID from startedAt, the database's
// time, and returns what the discovery found when it read the account.
func (c *byokChecker) run(ctx context.Context, organizationID, provider, secret string, registered *billing.CloudTarget, accountID string, startedAt time.Time) (*azureDiscovery, byokFailure, error) {
	release, err := c.slots.take(ctx, organizationID)
	if err != nil {
		return nil, byokFailure{}, err
	}
	defer release()
	if provider == "azure" {
		found, failure := c.discover(ctx, organizationID, secret, accountID, startedAt)
		return found, failure, nil
	}
	return nil, c.check(ctx, organizationID, provider, secret, registered), nil
}

// check returns why the provider did not accept secret, the zero value when it did.
func (c *byokChecker) check(ctx context.Context, organizationID, provider, secret string, registered *billing.CloudTarget) byokFailure {
	ctx, cancel := context.WithTimeout(ctx, byokCheckTimeout)
	defer cancel()
	switch provider {
	case "openai", "anthropic", "chutes":
		if !validUpstreamAPIKey(secret) {
			return invalidSecret(provider)
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
			return unverified(byokUnavailable(provider))
		}
		return c.read(provider, c.client, request)
	case "aws":
		return c.checkAWS(ctx, organizationID, secret, registered)
	case "google-cloud":
		return c.checkGoogle(ctx, organizationID, secret, registered)
	}
	return unverified(byokUnavailable(provider))
}

// discover signs in to Entra anew with the application in secret, bypassing the token cache, so
// an application whose secret expired or was deleted fails now. It then discovers the targets of
// the account from startedAt, the database's time.
func (c *byokChecker) discover(ctx context.Context, organizationID, secret, accountID string, startedAt time.Time) (*azureDiscovery, byokFailure) {
	app, err := parseAzureByokCredential(secret)
	if err != nil {
		return nil, invalidSecret("azure")
	}
	// The sign-in and the discovery share the discovery's bound, so the wait has one.
	ctx, cancel := context.WithTimeout(ctx, azureDiscoveryTimeout)
	defer cancel()
	token, failure := c.signIn(ctx, organizationID, app)
	if failure.message != "" {
		return nil, failure
	}
	found, err := discoverAzure(ctx, c.arm, token, accountID, startedAt)
	if err != nil {
		return nil, azureDiscoveryFailure(err)
	}
	return found, byokFailure{}
}

// signIn returns an Azure Resource Manager token for an organization's app, signed in anew.
func (c *byokChecker) signIn(ctx context.Context, organizationID string, app azureByokCredential) (string, byokFailure) {
	if c.azure == nil {
		return "", unverified(azureAppUnavailable)
	}
	token, err := c.azure.SignIn(ctx, azureauth.Credential{TenantID: app.TenantID, ClientID: app.ClientID, Secret: app.ClientSecret, Scope: armScope, OrganizationID: organizationID})
	switch {
	case err == nil:
		return token, byokFailure{}
	case errors.Is(err, azureauth.ErrCredential):
		return "", refusal(azureSignInRejected(app.ClientSecret))
	default:
		return "", unverified(azureAppUnavailable)
	}
}

// azureDiscoveryFailure is a discovery that stopped, as a check reports it.
func azureDiscoveryFailure(err error) byokFailure {
	var problem *azureDiscoveryError
	return byokFailure{message: azureDiscoveryMessage(err), rejected: errors.As(err, &problem) && problem.rejected}
}

// azureDiscoveryOutcome is a discovery as a check records it: the message, empty when nothing is
// wrong, and what the discovery found, nil when it read no deployments. A problem that leaves the
// targets in place, such as a missing data role, comes with them.
func azureDiscoveryOutcome(found *azureDiscovery, err error) (string, *billing.AzureDiscoveryResult) {
	if err != nil {
		return azureDiscoveryMessage(err), nil
	}
	bindings := found.Bindings
	if bindings == nil {
		bindings = []azureDiscoveredBinding{}
	}
	encoded, err := json.Marshal(bindings)
	if err != nil {
		return azureDiscoveryUnavailable, nil
	}
	return found.CheckError, &billing.AzureDiscoveryResult{Bindings: encoded, Deployments: found.Deployments, AccountOptions: found.AccountOptions}
}

// checkAWS makes the cheapest request that each AWS credential can: a role is assumed anew with
// the organization's token; an access key asks STS who it is, which needs no permission; a Bedrock
// API key lists Anthropic models, and a Claude Platform on AWS API key lists its workspace's
// models.
func (c *byokChecker) checkAWS(ctx context.Context, organizationID, secret string, registered *billing.CloudTarget) byokFailure {
	credential, err := parseAWSByokCredential(secret)
	if err != nil {
		return invalidSecret("aws")
	}
	if failure := cloudTargetMismatch(catalog.ProviderAWS, secret, registered); failure.message != "" {
		return failure
	}
	var request *http.Request
	switch {
	case credential.RoleARN != "":
		if c.roles == nil {
			return unverified(byokUnavailable("aws"))
		}
		err := c.roles.SignIn(ctx, awsauth.Credential{OrganizationID: organizationID, Region: credential.Region, RoleARN: credential.RoleARN})
		switch {
		case err == nil:
			return byokFailure{}
		case errors.Is(err, awsauth.ErrIssuer):
			return refusal(awsIssuerRejected)
		case errors.Is(err, awsauth.ErrRole):
			return refusal(awsRoleRejected)
		case errors.Is(err, awsauth.ErrCredential):
			return refusal(byokRejected("aws"))
		default:
			return unverified(byokUnavailable("aws"))
		}
	case credential.AccessKeyID != "":
		request, err = http.NewRequestWithContext(ctx, http.MethodPost, "https://sts."+credential.Region+".amazonaws.com/", strings.NewReader(stsRequestBody))
		if err != nil {
			return unverified(byokUnavailable("aws"))
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		digest := sha256.Sum256([]byte(stsRequestBody))
		if err := v4.NewSigner().SignHTTP(ctx, aws.Credentials{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey},
			request, hex.EncodeToString(digest[:]), "sts", credential.Region, c.now()); err != nil {
			return unverified(byokUnavailable("aws"))
		}
	case credential.WorkspaceID != "":
		request, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://aws-external-anthropic."+credential.Region+".api.aws/v1/models?limit=1", nil)
		if err != nil {
			return unverified(byokUnavailable("aws"))
		}
		request.Header.Set("Authorization", "Bearer "+credential.APIKey)
		request.Header.Set("anthropic-version", "2023-06-01")
		request.Header.Set("anthropic-workspace-id", credential.WorkspaceID)
	default:
		request, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://bedrock."+credential.Region+".amazonaws.com/foundation-models?byProvider=Anthropic", nil)
		if err != nil {
			return unverified(byokUnavailable("aws"))
		}
		request.Header.Set("Authorization", "Bearer "+credential.APIKey)
	}
	return c.read("aws", c.aws, request)
}

// checkGoogle signs in to Google anew, bypassing the token cache, so a key that Google disabled
// since its last token, or a pool that no longer trusts the organization, fails now.
func (c *byokChecker) checkGoogle(ctx context.Context, organizationID, secret string, registered *billing.CloudTarget) byokFailure {
	credential, err := parseGoogleCloudByokCredential(secret)
	if err != nil {
		return invalidSecret("google-cloud")
	}
	if failure := cloudTargetMismatch(catalog.ProviderGoogleCloud, secret, registered); failure.message != "" {
		return failure
	}
	if c.google == nil {
		return unverified(byokUnavailable("google-cloud"))
	}
	err = c.google.SignIn(ctx, credential.signIn(organizationID))
	switch {
	case err == nil:
		return byokFailure{}
	case errors.Is(err, googleauth.ErrProvider):
		return refusal(googleProviderRejected)
	case errors.Is(err, googleauth.ErrServiceAccount):
		return refusal(googleServiceAccountRejected)
	case errors.Is(err, googleauth.ErrCredential):
		return refusal(byokRejected("google-cloud"))
	default:
		return unverified(byokUnavailable("google-cloud"))
	}
}

// cloudTargetMismatch refuses a secret that cannot serve the target that the credential was added
// with, which requests would refuse: another Region, or a hosting that the secret does not serve.
func cloudTargetMismatch(provider schemas.ModelProvider, secret string, registered *billing.CloudTarget) byokFailure {
	actual, err := cloudCredentialTarget(provider, secret)
	if err != nil {
		return invalidSecret(string(provider))
	}
	failure := byokFailure{rejected: true, target: true}
	if registered == nil || registered.Region != actual.Region {
		failure.message = "The credential is for another Region than the target it was added with. Add the target that stogas encrypt printed for it."
		return failure
	}
	for _, hosting := range registered.Hosting {
		if !slices.Contains(actual.Hosting, hosting) {
			failure.message = "The credential cannot serve every hosting of the target it was added with. Add the target that stogas encrypt printed for it."
			return failure
		}
	}
	return byokFailure{}
}

func (c *byokChecker) read(provider string, client *http.Client, request *http.Request) byokFailure {
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return unverified(byokUnavailable(provider))
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, byokCheckResponseLimit))
	switch status := response.StatusCode; {
	case status >= 200 && status < 300:
		return byokFailure{}
	case status >= 400 && status < 500 && status != 408 && status != 409 && status != 425 && status != 429:
		return refusal(byokRejected(provider))
	default:
		return unverified(byokUnavailable(provider))
	}
}

// byokCredentialName names what a provider's secret is: AWS and Google Cloud take a credential
// document rather than an API key, and Azure an application's tenant, client ID and secret.
func byokCredentialName(provider string) string {
	switch provider {
	case "aws", "google-cloud":
		return "credential"
	case "azure":
		return "application"
	}
	return "API key"
}

// A credential without a secret needs a trust in the customer's cloud, which has several parts.
// Each message names the part that the cloud refused.
const (
	awsIssuerRejected            = "AWS could not verify this organization's token. Add the issuer URL to IAM as an identity provider with the audience sts.amazonaws.com."
	awsRoleRejected              = "AWS did not let this organization assume the role. Check the role ARN and the subject in the role's trust policy."
	googleProviderRejected       = "Google Cloud did not accept this organization's token. Check the provider's path and its issuer URL."
	googleServiceAccountRejected = "Google Cloud did not let this organization act as the service account. Grant the subject roles/iam.workloadIdentityUser on it."
)

// azureSignInRejected says what Entra refused: an application's client secret, or the
// organization's token when the application has none.
func azureSignInRejected(clientSecret string) string {
	if clientSecret == "" {
		return azureFederationRejected
	}
	return azureAppRejected
}

func byokRejected(provider string) string {
	return byokProviderNames[provider] + " did not accept this " + byokCredentialName(provider) + " or configuration"
}

func byokUnavailable(provider string) string {
	return "Could not verify the " + byokProviderNames[provider] + " " + byokCredentialName(provider) + ". Try again."
}

func invalidByokSecret(provider string) string {
	return "The decrypted secret is not a valid " + byokProviderNames[provider] + " " + byokCredentialName(provider) +
		". Encrypt it again with stogas encrypt --credential " + provider + "."
}

// invalidStoredSecret is invalidByokSecret for a stored credential, whose secret a member replaces
// in the dashboard rather than encrypts.
func invalidStoredSecret(provider string) string {
	return "The secret is not a valid " + byokProviderNames[provider] + " " + byokCredentialName(provider)
}
