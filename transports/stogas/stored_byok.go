package stogas

import (
	"context"
	"regexp"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// Outcomes of a secret's use with its provider before Control stores it. Accepted may carry a
// problem that leaves the credential usable, such as an Azure application without a data role.
// Rejected means that the provider or the secret refused the credential, which trying again does
// not change, and unavailable that the probe could not tell.
const (
	storedByokAccepted    = "accepted"
	storedByokRejected    = "rejected"
	storedByokUnavailable = "unavailable"
	// The subscriptions that one listing of Azure accounts may search, as the dashboard bounds them.
	storedAzureMaxSubscriptions = 64
)

// A subscription ID only names a path of Azure Resource Manager, so it takes any UUID that an
// account's resource ID may hold.
var azureSubscriptionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// StoredByokProbe is how a probe of a secret ended. Message is nil when nothing is wrong.
// AccountName is the name of the Azure account that the probe read, which the credential shows.
type StoredByokProbe struct {
	Outcome     string  `json:"outcome"`
	Message     *string `json:"message"`
	AccountName *string `json:"accountName,omitempty"`
}

// StoredByokProbeRequest probes a secret that Control has not saved: the secret, sealed as Control
// would store it, for an AWS or Google Cloud credential the target that Control would store beside
// it, and for an Azure credential the account that it would connect.
type StoredByokProbeRequest struct {
	Secret         string               `json:"secret"`
	Target         *billing.CloudTarget `json:"target,omitempty"`
	AzureAccountID string               `json:"azureAccountId,omitempty"`
}

// StoredAzureAccountsRequest lists the accounts that the application in a sealed secret can read
// in each subscription.
type StoredAzureAccountsRequest struct {
	Secret          string   `json:"secret"`
	SubscriptionIDs []string `json:"subscriptionIds"`
}

// StoredAzureAccounts is a listing of Azure accounts. Accounts is empty unless the outcome is
// accepted.
type StoredAzureAccounts struct {
	Outcome  string               `json:"outcome"`
	Message  *string              `json:"message"`
	Accounts []StoredAzureAccount `json:"accounts"`
}

// ParseStoredByokGrant verifies a grant that Control signed for one use of a stored credential.
func (r *Runtime) ParseStoredByokGrant(raw string) (*billing.StoredByokGrant, error) {
	if r == nil || r.billing == nil {
		return nil, billing.ErrStoredByokGrant
	}
	return r.billing.ParseStoredByokGrant(raw)
}

// storedByokOpener opens the secret that Control sealed for a grant's credential.
type storedByokOpener interface {
	OpenStoredByok(*billing.StoredByokGrant, string) (string, error)
}

// ProbeStoredByok checks a secret that Control has not saved, so that Control saves only a secret
// that its provider accepts, and records nothing. An Azure application signs in and reads the
// account that it would connect, and the first check after the save discovers its targets.
func (r *Runtime) ProbeStoredByok(ctx context.Context, grant *billing.StoredByokGrant, request StoredByokProbeRequest) (*StoredByokProbe, error) {
	if r == nil || r.billing == nil || r.byokChecks == nil {
		return nil, billing.ErrGatewayUnavailable
	}
	return probeStoredByok(ctx, r.billing, r.byokChecks, grant, request)
}

func probeStoredByok(ctx context.Context, opener storedByokOpener, checker *byokChecker, grant *billing.StoredByokGrant, request StoredByokProbeRequest) (*StoredByokProbe, error) {
	if grant == nil || grant.Scope != billing.StoredByokProbe {
		return nil, billing.ErrStoredByokGrant
	}
	azure := grant.Provider == "azure"
	cloud := grant.Provider == string(catalog.ProviderAWS) || grant.Provider == string(catalog.ProviderGoogleCloud)
	if request.Secret == "" || cloud != (request.Target != nil) || azure != (request.AzureAccountID != "") ||
		azure && !azureAccountIDPattern.MatchString(request.AzureAccountID) {
		return nil, billing.ErrStoredByokRequest
	}
	secret, err := opener.OpenStoredByok(grant, request.Secret)
	if err != nil {
		return nil, err
	}
	accountName, failure, err := checker.probe(ctx, grant.OrganizationID, grant.Provider, secret, request.Target, request.AzureAccountID)
	if err != nil {
		return nil, err
	}
	failure, err = storedByokFailure(grant.Provider, failure)
	if err != nil {
		return nil, err
	}
	return &StoredByokProbe{Outcome: storedByokOutcome(failure), Message: optionalMessage(failure.message), AccountName: optionalMessage(accountName)}, nil
}

// storedByokFailure is a check's failure as a stored credential shows it.
func storedByokFailure(provider string, failure byokFailure) (byokFailure, error) {
	switch {
	case failure.invalid:
		// Control reads only the form of a new secret, so a gateway is the first to read it as its
		// provider's credential, and a secret that is not one, such as a Google key that is not RSA,
		// is the member's to replace, as one that the provider refuses is.
		failure.message = invalidStoredSecret(provider)
	case failure.target:
		return failure, billing.ErrStoredByokTarget
	}
	return failure, nil
}

// probe checks a secret that no credential holds yet, while it holds one of the checker's slots.
// For an Azure application it returns the name of the account accountID, which the application
// must read.
func (c *byokChecker) probe(ctx context.Context, organizationID, provider, secret string, registered *billing.CloudTarget, accountID string) (string, byokFailure, error) {
	release, err := c.slots.take(ctx, organizationID)
	if err != nil {
		return "", byokFailure{}, err
	}
	defer release()
	if provider != "azure" {
		return "", c.check(ctx, organizationID, provider, secret, registered), nil
	}
	app, err := parseAzureByokCredential(secret)
	if err != nil {
		return "", invalidSecret("azure"), nil
	}
	ctx, cancel := context.WithTimeout(ctx, azureDiscoveryTimeout)
	defer cancel()
	token, failure := c.signIn(ctx, organizationID, app)
	if failure.message != "" {
		return "", failure, nil
	}
	account, _, _, err := readModelAccount(ctx, newARMReads(c.arm, token), accountID)
	if err != nil {
		return "", azureDiscoveryFailure(err), nil
	}
	return trimJS(account.name), byokFailure{}, nil
}

// ListStoredAzureAccounts lists the Foundry and Azure OpenAI accounts that the application in a
// sealed secret can read in each subscription, signing in to Entra anew as checks do.
func (r *Runtime) ListStoredAzureAccounts(ctx context.Context, grant *billing.StoredByokGrant, request StoredAzureAccountsRequest) (*StoredAzureAccounts, error) {
	if r == nil || r.billing == nil || r.byokChecks == nil {
		return nil, billing.ErrGatewayUnavailable
	}
	return listStoredAzureAccounts(ctx, r.billing, r.byokChecks, grant, request)
}

func listStoredAzureAccounts(ctx context.Context, opener storedByokOpener, checker *byokChecker, grant *billing.StoredByokGrant, request StoredAzureAccountsRequest) (*StoredAzureAccounts, error) {
	if grant == nil || grant.Scope != billing.StoredByokAzureAccounts {
		return nil, billing.ErrStoredByokGrant
	}
	if request.Secret == "" || !validSubscriptionIDs(request.SubscriptionIDs) {
		return nil, billing.ErrStoredByokRequest
	}
	secret, err := opener.OpenStoredByok(grant, request.Secret)
	if err != nil {
		return nil, err
	}
	accounts, failure, err := checker.accounts(ctx, grant.OrganizationID, secret, request.SubscriptionIDs)
	if err != nil {
		return nil, err
	}
	if failure.invalid {
		failure.message = invalidStoredSecret("azure")
	}
	if failure.message != "" {
		return &StoredAzureAccounts{Outcome: storedByokOutcome(failure), Message: &failure.message, Accounts: []StoredAzureAccount{}}, nil
	}
	return &StoredAzureAccounts{Outcome: storedByokAccepted, Accounts: accounts}, nil
}

// accounts lists the model accounts in subscriptionIDs that the application in secret can read,
// while it holds one of the checker's slots.
func (c *byokChecker) accounts(ctx context.Context, organizationID, secret string, subscriptionIDs []string) ([]StoredAzureAccount, byokFailure, error) {
	release, err := c.slots.take(ctx, organizationID)
	if err != nil {
		return nil, byokFailure{}, err
	}
	defer release()
	app, err := parseAzureByokCredential(secret)
	if err != nil {
		return nil, invalidSecret("azure"), nil
	}
	ctx, cancel := context.WithTimeout(ctx, azureDiscoveryTimeout)
	defer cancel()
	token, failure := c.signIn(ctx, organizationID, app)
	if failure.message != "" {
		return nil, failure, nil
	}
	accounts, err := listAzureAccounts(ctx, c.arm, token, subscriptionIDs)
	if err != nil {
		return nil, azureDiscoveryFailure(err), nil
	}
	return accounts, byokFailure{}, nil
}

// validSubscriptionIDs holds for 1 to 64 distinct subscription IDs in lowercase.
func validSubscriptionIDs(ids []string) bool {
	if len(ids) == 0 || len(ids) > storedAzureMaxSubscriptions {
		return false
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, repeated := seen[id]; repeated || !azureSubscriptionIDPattern.MatchString(id) {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

func storedByokOutcome(failure byokFailure) string {
	switch {
	case failure.message == "":
		return storedByokAccepted
	case failure.rejected:
		return storedByokRejected
	default:
		return storedByokUnavailable
	}
}

func optionalMessage(message string) *string {
	if message == "" {
		return nil
	}
	return &message
}
