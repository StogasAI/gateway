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

// A gateway confirms an Azure credential's targets against the deployments that its account
// lists when a request uses one, so a deployment that Azure upgraded, deleted or failed stops
// serving within minutes instead of at the daily discovery. Confirmations are shared through
// PostgreSQL, so one gateway reads Azure for the fleet. Control discovers a stored credential's
// targets; only gateways can open a customer-encrypted one, so a request that finds its discovery
// due starts one in the background, under the same claim.
const (
	// A younger confirmation needs no check, and an older one starts a check in the background.
	azureCheckFresh = 10 * time.Minute
	// A request whose targets went unconfirmed this long waits for a check.
	azureCheckStale = 30 * time.Minute
	// A reply that names no model version cannot show that Azure moved its target, so a request
	// that gets one needs a younger confirmation.
	azureCheckUnreportedFresh = time.Minute
	azureCheckUnreportedStale = 10 * time.Minute
	// Requests keep their targets while checks fail until the last confirmation is this old.
	azureCheckGrace = 2 * time.Hour
	// How long a request waits for a check, and lets another gateway finish the check it claimed.
	azureCheckWait = 5 * time.Second
	azureCheckPoll = 250 * time.Millisecond
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
	RecordAzureCheck(ctx context.Context, byokID string, startedAt time.Time, deployments []billing.AzureDeployment) (billing.AzureCheckResult, error)
	StopAzureTarget(ctx context.Context, byokID, bindingID, servedModel string) (bool, error)
	ClaimAzureDiscovery(ctx context.Context, byokID string) (bool, time.Time, error)
	RecordAzureDiscovery(ctx context.Context, byokID string, startedAt time.Time, envelope string, failure string, discovery *billing.AzureDiscoveryResult) (billing.AzureCheckResult, error)
}

type azureTargetChecker interface {
	Confirm(ctx context.Context, target azureCheckTarget) error
}

// azureCheckTarget is the Azure target that a request holds. VerifiedAt is the credential's last
// confirmation when the hold ran, zero when there was none. DiscoverAt is when a customer-encrypted
// credential's next discovery is due, zero for a stored credential, and Envelope that credential's
// envelope, so a discovery records only while the credential holds the application that it used.
// Unreported marks a request whose reply will not name the model version that served it.
type azureCheckTarget struct {
	ByokID     string
	BindingID  string
	AccountID  string
	VerifiedAt time.Time
	DiscoverAt time.Time
	Envelope   string
	Unreported bool
	Credential azureauth.Credential
}

// windows returns how old the target's confirmation may be before a check starts in the
// background and before the request waits for one, and the key that paces those checks here.
func (t azureCheckTarget) windows() (fresh, stale time.Duration, key string) {
	if t.Unreported {
		return azureCheckUnreportedFresh, azureCheckUnreportedStale, t.ByokID + "/unreported"
	}
	return azureCheckFresh, azureCheckStale, t.ByokID
}

// azureCheckOutcome reports a check: whether the targets were confirmed, and the selected targets
// that are out of service, with why.
type azureCheckOutcome struct {
	confirmed   bool
	unavailable map[string]string
}

// azureCheckMark paces one credential's checks on this gateway.
type azureCheckMark struct {
	// No check starts here before this time.
	until time.Time
	// The last check here failed, so until then requests do not wait for another.
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
	// How long a request waits for a check.
	wait time.Duration

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
		wait:    azureCheckWait,
		marks:   make(map[string]azureCheckMark),
		pruneAt: azureCheckMarks,
	}
}

// Confirm reports whether a request may use its Azure target. A target that is out of service
// refuses the pair, so the request moves on to its next one.
func (c *AzureChecks) Confirm(ctx context.Context, target azureCheckTarget) error {
	if !azureAccountIDPattern.MatchString(target.AccountID) || target.ByokID == "" || target.BindingID == "" {
		return billing.ErrByok
	}
	c.discover(target)
	fresh, stale, key := target.windows()
	age := c.age(target.VerifiedAt)
	if age < fresh {
		return nil
	}
	if age < stale {
		c.refresh(target)
		return nil
	}
	// After a check here failed, requests wait for no other until its retry.
	if c.failing(key) {
		if age < azureCheckGrace {
			return nil
		}
		return billing.ErrByok
	}
	results := c.flights.DoChan(key, func() (any, error) {
		return c.confirm(target), nil
	})
	// The check goes on for later requests when this one stops waiting.
	timer := time.NewTimer(c.wait)
	defer timer.Stop()
	var outcome azureCheckOutcome
	select {
	case result := <-results:
		outcome = result.Val.(azureCheckOutcome)
	case <-timer.C:
	case <-ctx.Done():
		return ctx.Err()
	}
	if reason, unavailable := outcome.unavailable[target.BindingID]; unavailable {
		if reason == "changed" {
			return billing.ErrByokTargetChanged
		}
		return billing.ErrByokTarget
	}
	if outcome.confirmed || c.age(target.VerifiedAt) < azureCheckGrace {
		return nil
	}
	return billing.ErrByok
}

func (c *AzureChecks) age(verifiedAt time.Time) time.Duration {
	if verifiedAt.IsZero() {
		return azureCheckGrace
	}
	return c.now().Sub(verifiedAt)
}

// confirm waits for the credential's targets to be confirmed: by this gateway when it claims the
// check, or by the gateway holding the claim. After azureCheckWait it checks unclaimed only when
// the targets are past their grace.
func (c *AzureChecks) confirm(target azureCheckTarget) azureCheckOutcome {
	ctx, cancel := context.WithTimeout(c.ctx, azureCheckTimeout)
	defer cancel()
	_, stale, key := target.windows()
	deadline := c.now().Add(azureCheckWait)
	for {
		claim, err := c.store.ClaimAzureCheck(ctx, target.ByokID, stale)
		if err != nil {
			c.fail(key)
			return azureCheckOutcome{}
		}
		// The database's own clock times the confirmation.
		if confirmedWithin(claim, stale) {
			return azureCheckOutcome{confirmed: true, unavailable: claim.Unavailable}
		}
		if claim.Claimed {
			return c.check(ctx, target, claim)
		}
		if !c.now().Before(deadline) {
			if confirmedWithin(claim, azureCheckGrace) {
				c.fail(key)
				return azureCheckOutcome{unavailable: claim.Unavailable}
			}
			return c.check(ctx, target, claim)
		}
		timer := time.NewTimer(azureCheckPoll)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			c.fail(key)
			return azureCheckOutcome{unavailable: claim.Unavailable}
		}
	}
}

// confirmedWithin reports whether the targets were confirmed within age of the claim.
func confirmedWithin(claim billing.AzureClaim, age time.Duration) bool {
	return !claim.VerifiedAt.IsZero() && claim.StartedAt.Sub(claim.VerifiedAt) < age
}

// refresh checks in the background, unless this gateway checked or tried recently.
func (c *AzureChecks) refresh(target azureCheckTarget) {
	fresh, _, key := target.windows()
	c.background(target, key, fresh)
}

// Recheck checks a target's account in the background after a reply showed that its deployment
// is gone or retired, so the fleet stops the target now rather than at the next due check. A
// check that any gateway made in the last few seconds answers it.
func (c *AzureChecks) Recheck(target azureCheckTarget) {
	c.background(target, target.ByokID+"/recheck", azureCheckWait)
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
		if err != nil {
			c.fail(key)
			return azureCheckOutcome{}, nil
		}
		if claim.Claimed {
			return c.check(ctx, target, claim), nil
		}
		// Another gateway checked recently or holds the claim.
		confirmed := confirmedWithin(claim, fresh)
		wait := azureCheckWait
		if confirmed {
			wait = max(wait, fresh-claim.StartedAt.Sub(claim.VerifiedAt))
		}
		c.pause(key, wait)
		return azureCheckOutcome{confirmed: confirmed, unavailable: claim.Unavailable}, nil
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
		result, err := c.store.RecordAzureDiscovery(c.ctx, target.ByokID, startedAt, target.Envelope, failure, discovery)
		switch {
		case err != nil:
			c.fail(key)
			reason = "record_failed"
		case result.Changed:
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

// Stop stops a target in the background after its reply named served, another model version,
// before the request moves on to its next pair.
func (c *AzureChecks) Stop(target azureCheckTarget, served string) {
	go func() {
		ctx, cancel := context.WithTimeout(c.ctx, azureCheckTimeout)
		defer cancel()
		reason := "stopped"
		if stopped, err := c.store.StopAzureTarget(ctx, target.ByokID, target.BindingID, served); err != nil {
			reason = "record_failed"
		} else if !stopped {
			reason = "already_stopped"
		}
		writeOperationalLog(operationalLogEvent{
			Event:      "azure_target_served_other_version",
			ReasonCode: reason,
			Severity:   "warning",
		})
	}()
}

// due reports whether a background check may start now, and if so holds off the next one for
// azureCheckWait.
func (c *AzureChecks) due(byokID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Before(c.marks[byokID].until) {
		return false
	}
	c.mark(byokID, azureCheckMark{until: now.Add(azureCheckWait)})
	return true
}

// failing reports whether a check here failed and its retry has not come.
func (c *AzureChecks) failing(byokID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	mark := c.marks[byokID]
	return mark.failed && c.now().Before(mark.until)
}

func (c *AzureChecks) pause(byokID string, wait time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mark(byokID, azureCheckMark{until: c.now().Add(wait)})
}

func (c *AzureChecks) fail(byokID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mark(byokID, azureCheckMark{until: c.now().Add(azureCheckRetry), failed: true})
}

// mark records a credential's mark; the caller holds mu. The map holds only credentials checked
// recently: when it grows to pruneAt, marks that passed leave, and the next pruning waits until
// the map doubles, so pruning costs constant time per mark.
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

// check reads the account's deployments and records them. The claim's start comes from the
// database before the read, so a check that started earlier never overwrites a newer one.
func (c *AzureChecks) check(ctx context.Context, target azureCheckTarget, claim billing.AzureClaim) azureCheckOutcome {
	fresh, _, key := target.windows()
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		c.fail(key)
		return azureCheckOutcome{unavailable: claim.Unavailable}
	}
	deployments, reason, err := c.deployments(ctx, target)
	if err == nil {
		var result billing.AzureCheckResult
		if result, err = c.store.RecordAzureCheck(ctx, target.ByokID, claim.StartedAt, deployments); err == nil {
			c.pause(key, fresh)
			return azureCheckOutcome{confirmed: true, unavailable: result.Unavailable}
		}
		reason = "record_failed"
	}
	c.fail(key)
	writeOperationalLog(operationalLogEvent{
		Event:      "azure_target_check_failed",
		ReasonCode: reason,
		Severity:   "warning",
	})
	return azureCheckOutcome{unavailable: claim.Unavailable}
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
// model, SKU, provisioning state and version upgrade option, each trimmed, or "" where the
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
		ID:             id,
		ModelFormat:    jsonText(model["format"]),
		ModelName:      jsonText(model["name"]),
		ModelVersion:   jsonText(model["version"]),
		SkuName:        jsonText(sku["name"]),
		State:          jsonText(properties["provisioningState"]),
		VersionUpgrade: jsonText(properties["versionUpgradeOption"]),
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

// trimJS trims what JavaScript's String.prototype.trim does, so gateways and Control's discovery
// report the same values.
func trimJS(value string) string {
	return strings.TrimFunc(value, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
			return true
		}
		return r >= 0x2000 && r <= 0x200a
	})
}
