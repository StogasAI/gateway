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
// serving within minutes instead of at Control's daily check. Confirmations are shared through
// PostgreSQL, so one gateway reads Azure for the fleet.
const (
	// A younger confirmation needs no check, and an older one starts a check in the background.
	azureCheckFresh = 10 * time.Minute
	// A request whose targets went unconfirmed this long waits for a check.
	azureCheckStale = 30 * time.Minute
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
}

type azureTargetChecker interface {
	Confirm(ctx context.Context, target azureCheckTarget) error
}

// azureCheckTarget is the Azure target that a request holds. VerifiedAt is the credential's last
// confirmation when the hold ran, zero when there was none.
type azureCheckTarget struct {
	ByokID     string
	BindingID  string
	AccountID  string
	VerifiedAt time.Time
	Credential azureauth.Credential
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
	age := c.age(target.VerifiedAt)
	if age < azureCheckFresh {
		return nil
	}
	if age < azureCheckStale {
		c.refresh(target)
		return nil
	}
	// After a check here failed, requests wait for no other until its retry.
	if c.failing(target.ByokID) {
		if age < azureCheckGrace {
			return nil
		}
		return billing.ErrByok
	}
	results := c.flights.DoChan(target.ByokID, func() (any, error) {
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
	deadline := c.now().Add(azureCheckWait)
	for {
		claim, err := c.store.ClaimAzureCheck(ctx, target.ByokID, azureCheckStale)
		if err != nil {
			c.fail(target.ByokID)
			return azureCheckOutcome{}
		}
		// The database's own clock times the confirmation.
		if confirmedWithin(claim, azureCheckStale) {
			return azureCheckOutcome{confirmed: true, unavailable: claim.Unavailable}
		}
		if claim.Claimed {
			return c.check(ctx, target, claim)
		}
		if !c.now().Before(deadline) {
			if confirmedWithin(claim, azureCheckGrace) {
				c.fail(target.ByokID)
				return azureCheckOutcome{unavailable: claim.Unavailable}
			}
			return c.check(ctx, target, claim)
		}
		timer := time.NewTimer(azureCheckPoll)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			c.fail(target.ByokID)
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
	if !c.due(target.ByokID) {
		return
	}
	go c.flights.Do(target.ByokID, func() (any, error) {
		ctx, cancel := context.WithTimeout(c.ctx, azureCheckTimeout)
		defer cancel()
		claim, err := c.store.ClaimAzureCheck(ctx, target.ByokID, azureCheckFresh)
		if err != nil {
			c.fail(target.ByokID)
			return azureCheckOutcome{}, nil
		}
		if claim.Claimed {
			return c.check(ctx, target, claim), nil
		}
		// Another gateway checked recently or holds the claim.
		confirmed := confirmedWithin(claim, azureCheckFresh)
		wait := azureCheckWait
		if confirmed {
			wait = max(wait, azureCheckFresh-claim.StartedAt.Sub(claim.VerifiedAt))
		}
		c.pause(target.ByokID, wait)
		return azureCheckOutcome{confirmed: confirmed, unavailable: claim.Unavailable}, nil
	})
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
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		c.fail(target.ByokID)
		return azureCheckOutcome{unavailable: claim.Unavailable}
	}
	deployments, reason, err := c.deployments(ctx, target)
	if err == nil {
		var result billing.AzureCheckResult
		if result, err = c.store.RecordAzureCheck(ctx, target.ByokID, claim.StartedAt, deployments); err == nil {
			c.pause(target.ByokID, azureCheckFresh)
			return azureCheckOutcome{confirmed: true, unavailable: result.Unavailable}
		}
		reason = "record_failed"
	}
	c.fail(target.ByokID)
	writeOperationalLog(operationalLogEvent{
		Event:      "azure_target_check_failed",
		ReasonCode: reason,
		Severity:   "warning",
	})
	return azureCheckOutcome{unavailable: claim.Unavailable}
}

// deployments lists the account's deployments as Control's discovery reports them. On failure
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
	return billing.AzureDeployment{
		ID:           prefix + strings.ToLower(leaf),
		ModelFormat:  jsonText(value, "properties", "model", "format"),
		ModelName:    jsonText(value, "properties", "model", "name"),
		ModelVersion: jsonText(value, "properties", "model", "version"),
		SkuName:      jsonText(value, "sku", "name"),
		State:        jsonText(value, "properties", "provisioningState"),
	}, true
}

// jsonText reads the string at path, trimmed, or "" when there is none.
func jsonText(value json.RawMessage, path ...string) string {
	for _, key := range path {
		var object map[string]json.RawMessage
		if json.Unmarshal(value, &object) != nil {
			return ""
		}
		value = object[key]
	}
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
