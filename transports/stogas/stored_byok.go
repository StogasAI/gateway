package stogas

import (
	"context"
	"encoding/json"
	"regexp"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// Outcomes of a stored credential's use with its provider. Accepted may carry a problem that leaves
// the credential usable, such as an Azure application without a data role. Rejected means that the
// provider or the secret refused the credential, which trying again does not change, and
// unavailable that the check could not tell.
const (
	storedByokAccepted    = "accepted"
	storedByokRejected    = "rejected"
	storedByokUnavailable = "unavailable"
	// The subscriptions that one listing of Azure accounts may search, as the dashboard bounds them.
	storedAzureMaxSubscriptions = 64
	// Control saves a stored credential's discovery in a Worker, which has 128 MB and holds about
	// twice an answer while it reads one, so an answer's targets and deployments take at most 32 MiB
	// as JSON. At the bound on targets they take about 18 MiB with names of usual length.
	storedAzureMaxDiscoveryBytes = 32 << 20
)

// A subscription ID only names a path of Azure Resource Manager, so it takes any UUID that an
// account's resource ID may hold.
var azureSubscriptionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// StoredByokCheckRequest checks a stored credential: its secret, sealed as Control stores it, and
// for an Azure credential the account that it connects and the database time that the check
// starts from.
type StoredByokCheckRequest struct {
	Secret         string     `json:"secret"`
	AzureAccountID string     `json:"azureAccountId,omitempty"`
	StartedAt      *time.Time `json:"startedAt,omitempty"`
}

// StoredByokCheck is how a check of a stored credential ended. Message is nil when nothing is
// wrong. Azure is what the discovery of an Azure credential found when it read the account.
type StoredByokCheck struct {
	Outcome string                `json:"outcome"`
	Message *string               `json:"message"`
	Azure   *StoredAzureDiscovery `json:"azure"`
}

// StoredAzureDiscovery is a discovery as Control saves it: the account's name, its targets and
// every deployment that it lists, each list encoded as JSON.
type StoredAzureDiscovery struct {
	Name        string          `json:"name"`
	Bindings    json.RawMessage `json:"bindings"`
	Deployments json.RawMessage `json:"deployments"`
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

// CheckStoredByok checks the stored credential that grant names, as checks of customer-encrypted
// credentials do. Control records the result, so the gateway reads and writes no database row.
func (r *Runtime) CheckStoredByok(ctx context.Context, grant *billing.StoredByokGrant, request StoredByokCheckRequest) (*StoredByokCheck, error) {
	if r == nil || r.billing == nil || r.byokChecks == nil {
		return nil, billing.ErrGatewayUnavailable
	}
	return checkStoredByok(ctx, r.billing, r.byokChecks, grant, request)
}

func checkStoredByok(ctx context.Context, opener storedByokOpener, checker *byokChecker, grant *billing.StoredByokGrant, request StoredByokCheckRequest) (*StoredByokCheck, error) {
	if grant == nil || grant.Scope != billing.StoredByokCheck {
		return nil, billing.ErrStoredByokGrant
	}
	azure := grant.Provider == "azure"
	var startedAt time.Time
	switch {
	case request.Secret == "":
		return nil, billing.ErrStoredByokRequest
	case azure:
		if request.StartedAt == nil || !azureAccountIDPattern.MatchString(request.AzureAccountID) {
			return nil, billing.ErrStoredByokRequest
		}
		startedAt = request.StartedAt.UTC()
	case request.AzureAccountID != "" || request.StartedAt != nil:
		return nil, billing.ErrStoredByokRequest
	}
	secret, err := opener.OpenStoredByok(grant, request.Secret)
	if err != nil {
		return nil, err
	}
	found, failure, err := checker.run(ctx, grant.OrganizationID, grant.Provider, secret, storedCloudTarget(grant.Provider, secret), request.AzureAccountID, startedAt)
	if err != nil {
		return nil, err
	}
	// Control reads only the form of a new secret, so this check is the first to read it as its
	// provider's credential, and a secret that is not one, such as a Google key that is not RSA, is
	// the member's to replace, as one that the provider refuses is.
	if failure.invalid {
		failure.message = invalidStoredSecret(grant.Provider)
	}
	if found == nil {
		return &StoredByokCheck{Outcome: storedByokOutcome(failure), Message: optionalMessage(failure.message)}, nil
	}
	if found.Bindings == nil {
		found.Bindings = []azureDiscoveredBinding{}
	}
	if found.Deployments == nil {
		found.Deployments = []billing.AzureDeployment{}
	}
	bindings, err := json.Marshal(found.Bindings)
	if err != nil {
		return nil, err
	}
	deployments, err := json.Marshal(found.Deployments)
	if err != nil {
		return nil, err
	}
	if len(bindings)+len(deployments) > storedAzureMaxDiscoveryBytes {
		message := azureTooManyTargets
		return &StoredByokCheck{Outcome: storedByokRejected, Message: &message}, nil
	}
	return &StoredByokCheck{
		Outcome: storedByokAccepted,
		Message: optionalMessage(found.CheckError),
		Azure:   &StoredAzureDiscovery{Name: found.Name, Bindings: bindings, Deployments: deployments},
	}, nil
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
	select {
	case c.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, byokFailure{}, ctx.Err()
	}
	defer func() { <-c.slots }()
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

// storedCloudTarget is the target that a stored AWS or Google Cloud secret serves, which Control
// stores beside it, so the check compares the secret with its own target. It is nil for other
// providers and for a secret that does not parse, which the check refuses.
func storedCloudTarget(provider, secret string) *billing.CloudTarget {
	if provider != string(catalog.ProviderAWS) && provider != string(catalog.ProviderGoogleCloud) {
		return nil
	}
	target, err := cloudCredentialTarget(schemas.ModelProvider(provider), secret)
	if err != nil {
		return nil
	}
	return &target
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
