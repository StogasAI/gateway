package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/accesstoken"
	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"golang.org/x/sync/singleflight"
)

// A gateway rereads the deployments that an Azure credential's account lists while requests use
// the credential, so a deployment that Azure upgraded, deleted or failed stops serving within
// minutes instead of at the daily discovery. Requests never wait for Azure: they use the targets
// that the last read left in service while the next read runs in the background. Reads are shared
// through PostgreSQL, so one gateway reads Azure for the fleet. Control schedules the discovery of
// a stored credential's targets, which a gateway runs for it; only gateways can open a
// customer-encrypted one, so a request that finds its discovery due starts one in the background,
// under the same claim.
const (
	// A request whose targets were confirmed longer ago than this starts a check.
	azureCheckFresh = 10 * time.Minute
	// While checks here fail, requests keep their targets until the last confirmation is this old.
	azureCheckGrace = 2 * time.Hour
	// A gateway starts a credential's checks no closer together than this.
	azureCheckPace = 5 * time.Second
	// A gateway retries a failed check no sooner than this.
	azureCheckRetry   = 30 * time.Second
	azureCheckTimeout = 30 * time.Second
	azureCheckLimit   = 4
	// A gateway keeps marks for about this many credentials before it drops those that passed.
	azureCheckMarks = 4096

	armHost             = "management.azure.com"
	armAPIVersion       = "2025-06-01"
	armScope            = "https://management.azure.com/.default"
	armMaxPages         = 100
	armMaxDeployments   = 20_000
	armMaxResponseBytes = 16 << 20
)

var (
	errAzureCheck           = errors.New("azure deployments unavailable")
	azureDeploymentNamePart = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,255}$`)
	// Control's account ID schema, so a hold can name only an account that discovery accepted.
	azureAccountIDPattern = regexp.MustCompile(`^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/resourcegroups/[-\w.()\p{L}\p{N}]{0,89}[-\w()\p{L}\p{N}]/providers/microsoft\.cognitiveservices/accounts/[a-z0-9][a-z0-9-]{1,63}$`)
)

type azureCheckStore interface {
	ClaimAzureCheck(ctx context.Context, byokID string, staleAfter time.Duration) (billing.AzureClaim, error)
	RecordAzureCheck(ctx context.Context, byokID string, startedAt time.Time, deployments []billing.AzureDeployment) error
	ClaimAzureDiscovery(ctx context.Context, byokID string) (bool, time.Time, error)
	RecordAzureDiscovery(ctx context.Context, byokID string, startedAt time.Time, envelope string, failure string, discovery *billing.AzureDiscoveryResult) (changed bool, err error)
}

type azureTargetChecker interface {
	Confirm(ctx context.Context, target azureCheckTarget) error
}

// azureCheckTarget is the Azure target that a request holds. VerifiedAt is the credential's last
// confirmation when the hold ran, zero when there was none. DiscoverAt is when a customer-encrypted
// credential's next discovery is due, zero for a stored credential, and Envelope that credential's
// envelope, so a discovery records only while the credential holds the application that it used.
type azureCheckTarget struct {
	ByokID     string
	AccountID  string
	VerifiedAt time.Time
	DiscoverAt time.Time
	Envelope   string
	Credential azureauth.Credential
}

// azureCheckMark paces one credential's checks on this gateway.
type azureCheckMark struct {
	// No check starts here before this time.
	until time.Time
	// The last check here failed.
	failed bool
}

type AzureChecks struct {
	ctx     context.Context
	store   azureCheckStore
	tokens  azureTokenSource
	client  *http.Client
	slots   chan struct{}
	flights singleflight.Group
	now     func() time.Time

	mu    sync.Mutex
	marks map[string]azureCheckMark
	// Marks that passed are dropped when the map reaches this size.
	pruneAt int
}

func NewAzureChecks(ctx context.Context, store azureCheckStore, tokens azureTokenSource) *AzureChecks {
	client, _ := accesstoken.NewClient(false)
	return &AzureChecks{
		ctx:     ctx,
		store:   store,
		tokens:  tokens,
		client:  client,
		slots:   make(chan struct{}, azureCheckLimit),
		now:     time.Now,
		marks:   make(map[string]azureCheckMark),
		pruneAt: azureCheckMarks,
	}
}

// Confirm reports whether a request may use its Azure target, which its hold found in service,
// and starts the check or discovery that is due. It refuses only a credential whose checks fail
// here and whose last confirmation is past its grace, so an account that this gateway cannot read
// stops serving instead of serving whatever its deployments became.
func (c *AzureChecks) Confirm(_ context.Context, target azureCheckTarget) error {
	if !azureAccountIDPattern.MatchString(target.AccountID) || target.ByokID == "" {
		return billing.ErrByok
	}
	c.discover(target)
	age := c.age(target.VerifiedAt)
	if age < azureCheckFresh {
		return nil
	}
	c.background(target, target.ByokID, azureCheckFresh)
	if age >= azureCheckGrace && c.failing(target.ByokID) {
		return billing.ErrByok
	}
	return nil
}

func (c *AzureChecks) age(verifiedAt time.Time) time.Duration {
	if verifiedAt.IsZero() {
		return azureCheckGrace
	}
	return c.now().Sub(verifiedAt)
}

// background checks target unless a confirmation is younger than fresh or this gateway tried
// for key recently.
func (c *AzureChecks) background(target azureCheckTarget, key string, fresh time.Duration) {
	if !c.due(key) {
		return
	}
	go c.flights.Do(key, func() (any, error) {
		ctx, cancel := context.WithTimeout(c.ctx, azureCheckTimeout)
		defer cancel()
		claim, err := c.store.ClaimAzureCheck(ctx, target.ByokID, fresh)
		switch {
		case err != nil:
			c.fail(key)
		case claim.Claimed:
			c.check(ctx, target, key, fresh, claim.StartedAt)
		case !claim.VerifiedAt.IsZero() && claim.StartedAt.Sub(claim.VerifiedAt) < fresh:
			// Another gateway confirmed the targets recently.
			c.pause(key, max(azureCheckPace, fresh-claim.StartedAt.Sub(claim.VerifiedAt)))
		default:
			// Another gateway holds the claim.
			c.wait(key)
		}
		return nil, nil
	})
}

// discover discovers a customer-encrypted credential's targets in the background once they are
// due, unless this gateway tried recently. The request goes on with the targets that it holds: a
// discovery adds and returns targets for later requests, and confirms them as a check does.
func (c *AzureChecks) discover(target azureCheckTarget) {
	key := target.ByokID + "/discover"
	if target.DiscoverAt.IsZero() || target.Envelope == "" || c.now().Before(target.DiscoverAt) || !c.due(key) {
		return
	}
	go c.flights.Do(key, func() (any, error) {
		// The claim, the wait for a slot, the sign-in and the reads end within the discovery's bound,
		// and the record has its own, so a discovery records before its 30-second claim lapses.
		ctx, cancel := context.WithTimeout(c.ctx, azureDiscoveryTimeout)
		defer cancel()
		claimed, startedAt, err := c.store.ClaimAzureDiscovery(ctx, target.ByokID)
		if err != nil {
			c.fail(key)
			return nil, nil
		}
		if !claimed {
			// Another gateway holds the claim for at most 30 seconds, or recorded since the hold.
			c.pause(key, azureCheckRetry)
			return nil, nil
		}
		select {
		case c.slots <- struct{}{}:
		case <-ctx.Done():
			// This gateway was too busy, which says nothing about the credential: the claim lapses,
			// and a later request tries again.
			c.fail(key)
			writeOperationalLog(operationalLogEvent{Event: "azure_discovery_failed", ReasonCode: "busy", Severity: "warning"})
			return nil, nil
		}
		failure, discovery, reason := c.discoverTargets(ctx, target, startedAt)
		<-c.slots
		changed, err := c.store.RecordAzureDiscovery(c.ctx, target.ByokID, startedAt, target.Envelope, failure, discovery)
		switch {
		case err != nil:
			c.fail(key)
			reason = "record_failed"
		case changed:
			// The credential holds another application now, whose holds bring their own due time.
			reason = "credential_changed"
		default:
			c.pause(key, azureCheckFresh)
		}
		if reason != "" {
			writeOperationalLog(operationalLogEvent{Event: "azure_discovery_failed", ReasonCode: reason, Severity: "warning"})
		}
		return nil, nil
	})
}

// discoverTargets discovers the target's account from startedAt, the database's time, with a
// cached token: requests sign in with the same one. It returns the message to record, empty when
// nothing is wrong, what the discovery found, nil when it read no deployments, and a code-owned
// reason when the discovery failed.
func (c *AzureChecks) discoverTargets(ctx context.Context, target azureCheckTarget, startedAt time.Time) (string, *billing.AzureDiscoveryResult, string) {
	credential := target.Credential
	credential.Scope = armScope
	token, err := c.tokens.Token(ctx, credential)
	if err != nil {
		if errors.Is(err, azureauth.ErrCredential) {
			return azureAppRejected, nil, "sign_in_rejected"
		}
		return azureAppUnavailable, nil, "sign_in_unavailable"
	}
	found, err := discoverAzure(ctx, c.client, token, target.AccountID, startedAt)
	failure, discovery := azureDiscoveryOutcome(found, err)
	var problem *azureDiscoveryError
	switch {
	case errors.As(err, &problem) && problem.rejected:
		return failure, discovery, "account_rejected"
	case err != nil:
		return failure, discovery, "discovery_unavailable"
	}
	return failure, discovery, ""
}

// due reports whether a background check may start now, and if so holds off the next one for
// azureCheckPace.
func (c *AzureChecks) due(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	mark := c.marks[key]
	if now.Before(mark.until) {
		return false
	}
	mark.until = now.Add(azureCheckPace)
	c.mark(key, mark)
	return true
}

// failing reports whether the last check here failed.
func (c *AzureChecks) failing(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.marks[key].failed
}

// wait holds off the next check while another gateway runs one, which says nothing about whether
// checks here fail.
func (c *AzureChecks) wait(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mark := c.marks[key]
	mark.until = c.now().Add(azureCheckPace)
	c.mark(key, mark)
}

func (c *AzureChecks) pause(key string, wait time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mark(key, azureCheckMark{until: c.now().Add(wait)})
}

func (c *AzureChecks) fail(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mark(key, azureCheckMark{until: c.now().Add(azureCheckRetry), failed: true})
}

// mark records a credential's mark; the caller holds mu. The map holds only credentials checked
// recently: when it grows to pruneAt, marks that passed leave, and the next pruning waits until
// the map doubles, so pruning costs constant time per mark. A credential whose failure leaves
// with its mark serves one request before its next check fails again.
func (c *AzureChecks) mark(byokID string, mark azureCheckMark) {
	if len(c.marks) >= c.pruneAt {
		now := c.now()
		for id, existing := range c.marks {
			if !now.Before(existing.until) {
				delete(c.marks, id)
			}
		}
		c.pruneAt = max(azureCheckMarks, 2*len(c.marks))
	}
	c.marks[byokID] = mark
}

// check reads the account's deployments and records them, which stops the selected targets that
// they no longer serve. startedAt comes from the database before the read, so a check that started
// earlier never overwrites a newer one.
func (c *AzureChecks) check(ctx context.Context, target azureCheckTarget, key string, fresh time.Duration, startedAt time.Time) {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		c.fail(key)
		return
	}
	deployments, reason, err := c.deployments(ctx, target)
	if err == nil {
		if err = c.store.RecordAzureCheck(ctx, target.ByokID, startedAt, deployments); err == nil {
			c.pause(key, fresh)
			return
		}
		reason = "record_failed"
	}
	c.fail(key)
	writeOperationalLog(operationalLogEvent{
		Event:      "azure_target_check_failed",
		ReasonCode: reason,
		Severity:   "warning",
	})
}

// deployments lists the account's deployments as discoveries report them. On failure
// it returns a code-owned reason.
func (c *AzureChecks) deployments(ctx context.Context, target azureCheckTarget) ([]billing.AzureDeployment, string, error) {
	credential := target.Credential
	credential.Scope = armScope
	token, err := c.tokens.Token(ctx, credential)
	if err != nil {
		if errors.Is(err, azureauth.ErrCredential) {
			return nil, "sign_in_rejected", err
		}
		return nil, "sign_in_unavailable", err
	}
	prefix := target.AccountID + "/deployments/"
	account := target.AccountID[strings.LastIndexByte(target.AccountID, '/')+1:]
	next := (&url.URL{
		Scheme:   "https",
		Host:     armHost,
		Path:     target.AccountID + "/deployments",
		RawQuery: "api-version=" + armAPIVersion,
	}).String()
	seen := make(map[string]bool)
	deployments := []billing.AzureDeployment{}
	for page := 0; next != ""; page++ {
		if page == armMaxPages {
			return nil, "too_many_pages", errAzureCheck
		}
		body, reason, err := c.armPage(ctx, next, token)
		if err != nil {
			return nil, reason, err
		}
		var listing struct {
			NextLink string            `json:"nextLink"`
			Value    []json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(body, &listing); err != nil {
			return nil, "invalid_response", errAzureCheck
		}
		for _, value := range listing.Value {
			deployment, ok := armDeployment(value, prefix, account)
			if !ok {
				return nil, "invalid_deployment", errAzureCheck
			}
			// A page that repeats a deployment does not report it twice.
			if seen[deployment.ID] {
				continue
			}
			seen[deployment.ID] = true
			if deployments = append(deployments, deployment); len(deployments) > armMaxDeployments {
				return nil, "too_many_deployments", errAzureCheck
			}
		}
		next = ""
		if listing.NextLink != "" {
			if next, err = armNextLink(listing.NextLink); err != nil {
				return nil, "invalid_next_link", err
			}
		}
	}
	return deployments, "", nil
}

func (c *AzureChecks) armPage(ctx context.Context, pageURL string, token string) ([]byte, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "invalid_request", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, "unreachable", errAzureCheck
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, armMaxResponseBytes))
		return nil, fmt.Sprintf("status_%d", response.StatusCode), errAzureCheck
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, armMaxResponseBytes+1))
	if err != nil {
		return nil, "unreachable", errAzureCheck
	}
	if len(body) > armMaxResponseBytes {
		return nil, "response_too_large", errAzureCheck
	}
	return body, "", nil
}

// armNextLink accepts a continuation only on Azure Resource Manager over HTTPS.
func armNextLink(link string) (string, error) {
	next, err := url.Parse(link)
	if err != nil || next.Scheme != "https" || next.Hostname() != armHost ||
		(next.Port() != "" && next.Port() != "443") || next.User != nil || next.Fragment != "" {
		return "", errAzureCheck
	}
	next.Host = armHost
	return next.String(), nil
}

// armDeployment reads one listed deployment. Its ID must name a deployment of the account, as
// discovery requires; the other values are read leniently, because the database judges them.
func armDeployment(value json.RawMessage, prefix string, account string) (billing.AzureDeployment, bool) {
	var identity struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if json.Unmarshal(value, &identity) != nil {
		return billing.AzureDeployment{}, false
	}
	id := trimJS(identity.ID)
	leaf := id[strings.LastIndexByte(id, '/')+1:]
	name := strings.ToLower(identity.Name)
	if !azureDeploymentNamePart.MatchString(leaf) || !strings.EqualFold(id[:len(id)-len(leaf)], prefix) ||
		(name != strings.ToLower(leaf) && name != account+"/"+strings.ToLower(leaf)) {
		return billing.AzureDeployment{}, false
	}
	return armDeploymentFact(value, prefix+strings.ToLower(leaf)), true
}

// armDeploymentFact reads a listed deployment as gateways' checks and discoveries report it: its
// model, SKU and provisioning state, each trimmed, or "" where the
// deployment has no such string. Each object is decoded once, which keeps a listing at the bound on
// targets quick to read.
func armDeploymentFact(value json.RawMessage, id string) billing.AzureDeployment {
	deployment, _ := armObject(value)
	properties, _ := armObject(deployment["properties"])
	model, _ := armObject(properties["model"])
	sku, _ := armObject(deployment["sku"])
	return armDeploymentFactOf(id, properties, model, sku)
}

// armDeploymentFactOf reads the fact from a deployment's decoded objects, each nil when the
// deployment has no such object.
func armDeploymentFactOf(id string, properties, model, sku map[string]json.RawMessage) billing.AzureDeployment {
	return billing.AzureDeployment{
		ID:           id,
		ModelFormat:  jsonText(model["format"]),
		ModelName:    jsonText(model["name"]),
		ModelVersion: jsonText(model["version"]),
		SkuName:      jsonText(sku["name"]),
		State:        jsonText(properties["provisioningState"]),
	}
}

// jsonText reads a string, trimmed, or "" when value is not one.
func jsonText(value json.RawMessage) string {
	var text string
	if json.Unmarshal(value, &text) != nil {
		return ""
	}
	return trimJS(text)
}

// trimJS trims what JavaScript's String.prototype.trim does, as the dashboard's schemas trim the
// values that discovery reports.
func trimJS(value string) string {
	return strings.TrimFunc(value, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
			return true
		}
		return r >= 0x2000 && r <= 0x200a
	})
}
