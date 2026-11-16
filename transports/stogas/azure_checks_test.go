package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

const testAzureAccount = "/subscriptions/00000000-0000-4000-8000-000000000003/resourcegroups/stogas/providers/microsoft.cognitiveservices/accounts/stogas-east"

type fakeAzureCheckStore struct {
	mu       sync.Mutex
	claims   []billing.AzureClaim
	claimed  int
	recorded [][]billing.AzureDeployment
	started  []time.Time
	// refused lists when each check that Azure refused started.
	refused  []time.Time
	claimErr error
	// staleAfter lists how old each claim let the last confirmation be.
	staleAfter []time.Duration
	// onClaim runs on each claim, such as to move the test clock.
	onClaim func()

	// Discoveries: whether each claim succeeds, from when, and what the records got and return.
	discoverClaimed  bool
	discoverStarted  time.Time
	discoverClaims   int
	discoverErr      error
	discoveries      []recordedAzureDiscovery
	discoveryChanged bool
	discoveryErr     error
}

type recordedAzureDiscovery struct {
	byokID, envelope, failure string
	startedAt                 time.Time
	discovery                 *billing.AzureDiscoveryResult
}

func (s *fakeAzureCheckStore) ClaimAzureCheck(_ context.Context, byokID string, staleAfter time.Duration) (billing.AzureClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if byokID != "byok-1" {
		return billing.AzureClaim{}, fmt.Errorf("unexpected credential %s", byokID)
	}
	if s.claimErr != nil {
		return billing.AzureClaim{}, s.claimErr
	}
	s.staleAfter = append(s.staleAfter, staleAfter)
	claim := s.claims[min(s.claimed, len(s.claims)-1)]
	s.claimed++
	if s.onClaim != nil {
		s.onClaim()
	}
	return claim, nil
}

func (s *fakeAzureCheckStore) RecordAzureCheck(_ context.Context, _ string, startedAt time.Time, deployments []billing.AzureDeployment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorded = append(s.recorded, deployments)
	s.started = append(s.started, startedAt)
	return nil
}

func (s *fakeAzureCheckStore) RefuseAzureCheck(_ context.Context, _ string, startedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refused = append(s.refused, startedAt)
	return nil
}

func (s *fakeAzureCheckStore) refusals() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.refused)
}

func (s *fakeAzureCheckStore) ClaimAzureDiscovery(_ context.Context, byokID string) (bool, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if byokID != "byok-1" {
		return false, time.Time{}, fmt.Errorf("unexpected credential %s", byokID)
	}
	s.discoverClaims++
	return s.discoverClaimed, s.discoverStarted, s.discoverErr
}

func (s *fakeAzureCheckStore) RecordAzureDiscovery(_ context.Context, byokID string, startedAt time.Time, envelope, failure string, discovery *billing.AzureDiscoveryResult) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discoveries = append(s.discoveries, recordedAzureDiscovery{byokID, envelope, failure, startedAt, discovery})
	return s.discoveryChanged, s.discoveryErr
}

func (s *fakeAzureCheckStore) discoveryCounts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.discoverClaims, len(s.discoveries)
}

func (s *fakeAzureCheckStore) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claimed, len(s.recorded)
}

// testClock is the checker's clock, which tests move while checks run.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Ago returns the time d before now.
func (c *testClock) Ago(d time.Duration) time.Time { return c.Now().Add(-d) }

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// armRedirect sends the checker's Azure Resource Manager requests to a test server.
type armRedirect struct{ server *httptest.Server }

func (r armRedirect) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != armHost {
		return nil, fmt.Errorf("request left Azure Resource Manager: %s", request.URL)
	}
	target, _ := url.Parse(r.server.URL)
	clone := request.Clone(request.Context())
	clone.URL.Scheme, clone.URL.Host = target.Scheme, target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func armDeploymentJSON(name, version, sku, state string) map[string]any {
	properties := map[string]any{
		"model":                map[string]any{"format": "OpenAI", "name": "gpt-5.6-sol", "version": version},
		"versionUpgradeOption": "OnceNewDefaultVersionAvailable",
	}
	if state != "" {
		properties["provisioningState"] = state
	}
	return map[string]any{
		// ARM reports IDs in mixed case.
		"id": strings.NewReplacer("resourcegroups", "resourceGroups", "microsoft.cognitiveservices", "Microsoft.CognitiveServices").
			Replace(testAzureAccount) + "/deployments/" + name,
		"name":       name,
		"properties": properties,
		"sku":        map[string]any{"name": sku, "capacity": 10},
	}
}

func newTestAzureChecks(t *testing.T, store *fakeAzureCheckStore, pages ...map[string]any) (*AzureChecks, *atomic.Int32, *testClock) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := int(requests.Add(1)) - 1
		if r.Header.Get("Authorization") != "Bearer arm-token" || r.URL.Query().Get("api-version") != armAPIVersion {
			t.Errorf("unexpected ARM request: %s", r.URL)
		}
		if index >= len(pages) {
			index = len(pages) - 1
		}
		if status, ok := pages[index]["status"].(int); ok {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(pages[index])
	}))
	t.Cleanup(server.Close)
	clock := &testClock{now: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	checks := NewAzureChecks(context.Background(), store, azureTokenFunc(func(_ context.Context, credential azureauth.Credential) (string, error) {
		if credential.Scope != armScope || credential.Secret != "azure-client-secret" {
			t.Errorf("unexpected token request for scope %q", credential.Scope)
		}
		return "arm-token", nil
	}))
	checks.client = &http.Client{Transport: armRedirect{server}}
	checks.now = clock.Now
	return checks, &requests, clock
}

func testCheckTarget(verifiedAt time.Time) azureCheckTarget {
	return azureCheckTarget{
		ByokID:     "byok-1",
		AccountID:  testAzureAccount,
		VerifiedAt: verifiedAt,
		Credential: azureauth.Credential{TenantID: "tenant", ClientID: "client", Secret: "azure-client-secret"},
	}
}

func TestAzureChecksSkipFreshConfirmations(t *testing.T) {
	store := &fakeAzureCheckStore{}
	checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	if err := checks.Confirm(context.Background(), testCheckTarget(clock.Ago(9*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if claimed, recorded := store.counts(); claimed != 0 || recorded != 0 || requests.Load() != 0 {
		t.Fatalf("a fresh confirmation started a check: claims=%d records=%d requests=%d", claimed, recorded, requests.Load())
	}
}

func TestAzureChecksRefreshAgingConfirmationsInBackgroundOnce(t *testing.T) {
	store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{Claimed: true, StartedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}}}
	checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{armDeploymentJSON("Customer-Sol", "2026-07-09", "GlobalStandard", "Succeeded")}})
	target := testCheckTarget(clock.Ago(11 * time.Minute))
	for range 5 {
		if err := checks.Confirm(context.Background(), target); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(func() bool { _, recorded := store.counts(); return recorded == 1 })
	if claimed, _ := store.counts(); claimed != 1 || requests.Load() != 1 {
		t.Fatalf("aging confirmations started several checks: claims=%d requests=%d", claimed, requests.Load())
	}
	want := billing.AzureDeployment{
		ID:           testAzureAccount + "/deployments/customer-sol",
		ModelFormat:  "OpenAI",
		ModelName:    "gpt-5.6-sol",
		ModelVersion: "2026-07-09",
		SkuName:      "GlobalStandard",
		State:        "Succeeded",
	}
	if got := store.recorded[0]; len(got) != 1 || got[0] != want {
		t.Fatalf("recorded deployments = %#v", got)
	}
	// The check counts as this gateway's confirmation until it is due again.
	if checks.due("byok-1") {
		t.Fatal("a recorded check left the credential due")
	}
}

// waitFor polls until done reports true, or fails the test after five seconds.
// waitFor polls until done holds. A wait that never ends fails at go test's -timeout, which prints
// every goroutine's stack.
func waitFor(done func() bool) {
	for !done() {
		time.Sleep(10 * time.Millisecond)
	}
}

// settle waits for the check or discovery that runs for key, if one does. A check marks its result
// before it returns, and a check that starts before then joins it instead of reading Azure.
func settle(checks *AzureChecks, key string) {
	checks.flights.Do(key, func() (any, error) { return nil, nil })
}

// A request never waits for Azure: it keeps the target that its hold found in service, however old
// the last confirmation, while the check that it started goes on for later requests.
func TestAzureChecksNeverHoldARequestForACheck(t *testing.T) {
	for _, test := range []struct {
		name string
		age  time.Duration
	}{
		{"aging", 40 * time.Minute},
		{"past grace", 3 * time.Hour},
		{"never confirmed", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{Claimed: true, StartedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}}}
			checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
			release := make(chan struct{})
			tokens := checks.tokens
			checks.tokens = azureTokenFunc(func(ctx context.Context, credential azureauth.Credential) (string, error) {
				<-release
				return tokens.Token(ctx, credential)
			})
			verifiedAt := time.Time{}
			if test.age > 0 {
				verifiedAt = clock.Ago(test.age)
			}
			for range 8 {
				if err := checks.Confirm(context.Background(), testCheckTarget(verifiedAt)); err != nil {
					t.Fatalf("Confirm() = %v while the check ran", err)
				}
			}
			close(release)
			waitFor(func() bool { _, recorded := store.counts(); return recorded == 1 })
			if claimed, _ := store.counts(); claimed != 1 || requests.Load() != 1 {
				t.Fatalf("the requests did not share one check: claims=%d requests=%d", claimed, requests.Load())
			}
		})
	}
}

// Another gateway's recent confirmation answers a check, without a read of Azure.
func TestAzureChecksUseAnotherGatewaysConfirmation(t *testing.T) {
	started := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{StartedAt: started, VerifiedAt: started.Add(-time.Minute)}}}
	checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	target := testCheckTarget(clock.Ago(15 * time.Minute))
	if err := checks.Confirm(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	waitFor(func() bool { claimed, _ := store.counts(); return claimed == 1 })
	waitFor(func() bool {
		checks.mu.Lock()
		defer checks.mu.Unlock()
		return checks.marks["byok-1"].until.Equal(clock.Now().Add(azureCheckFresh - time.Minute))
	})
	if _, recorded := store.counts(); recorded != 0 || requests.Load() != 0 {
		t.Fatalf("a confirmed credential was read again: records=%d requests=%d", recorded, requests.Load())
	}
}

// While another gateway holds the claim, this one claims again no sooner than azureCheckPace.
func TestAzureChecksPaceBackgroundClaims(t *testing.T) {
	started := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{StartedAt: started, VerifiedAt: started.Add(-15 * time.Minute)}}}
	checks, _, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	target := testCheckTarget(clock.Ago(15 * time.Minute))
	waitForClaims := func(want int) {
		waitFor(func() bool { claimed, _ := store.counts(); return claimed == want })
		settle(checks, "byok-1")
	}
	if err := checks.Confirm(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	waitForClaims(1)
	for range 3 {
		if err := checks.Confirm(context.Background(), target); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if claimed, _ := store.counts(); claimed != 1 {
		t.Fatalf("requests claimed again at once: claims=%d", claimed)
	}
	clock.Advance(azureCheckPace)
	if err := checks.Confirm(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	waitForClaims(2)
}

// Marks that passed leave once the map is full, and pruning waits until the map doubles.
func TestAzureChecksDropMarksThatPassed(t *testing.T) {
	checks, _, clock := newTestAzureChecks(t, &fakeAzureCheckStore{}, map[string]any{"value": []any{}})
	checks.mu.Lock()
	defer checks.mu.Unlock()
	for index := range azureCheckMarks {
		checks.mark(fmt.Sprint("passed-", index), azureCheckMark{until: clock.Now()})
	}
	checks.mark("current", azureCheckMark{until: clock.Now().Add(time.Minute)})
	if len(checks.marks) != 1 || checks.pruneAt != azureCheckMarks {
		t.Fatalf("after pruning: marks=%d pruneAt=%d", len(checks.marks), checks.pruneAt)
	}
	for index := range 2 * azureCheckMarks {
		checks.mark(fmt.Sprint("current-", index), azureCheckMark{until: clock.Now().Add(time.Minute)})
	}
	if len(checks.marks) != 2*azureCheckMarks+1 || checks.pruneAt != 4*azureCheckMarks {
		t.Fatalf("with current marks: marks=%d pruneAt=%d", len(checks.marks), checks.pruneAt)
	}
}

// While this gateway's checks fail, requests keep their targets until the last confirmation is
// two hours old, and then stop until a check succeeds.
func TestAzureChecksServeThroughFailuresOnlyWithinGrace(t *testing.T) {
	for _, test := range []struct {
		name string
		age  time.Duration
		want error
	}{
		{"within grace", 90 * time.Minute, nil},
		{"past grace", 3 * time.Hour, billing.ErrByok},
		{"never confirmed", 0, billing.ErrByok},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{Claimed: true, StartedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}}}
			checks, requests, clock := newTestAzureChecks(t, store,
				map[string]any{"status": http.StatusServiceUnavailable},
				map[string]any{"status": http.StatusServiceUnavailable},
				map[string]any{"value": []any{}})
			verifiedAt := time.Time{}
			if test.age > 0 {
				verifiedAt = clock.Ago(test.age)
			}
			target := testCheckTarget(verifiedAt)
			// Nothing has failed yet, so the first request keeps its target and starts the check.
			if err := checks.Confirm(context.Background(), target); err != nil {
				t.Fatalf("Confirm() before any check = %v", err)
			}
			waitFor(func() bool { return checks.failing("byok-1") })
			settle(checks, "byok-1")
			if _, recorded := store.counts(); recorded != 0 || store.refusals() != 0 {
				t.Fatal("a check that Azure could not answer recorded deployments or a refusal")
			}
			// A failed check waits before the gateway tries Azure again.
			if err := checks.Confirm(context.Background(), target); !errors.Is(err, test.want) {
				t.Fatalf("Confirm() after the failure = %v, want %v", err, test.want)
			}
			if claimed, _ := store.counts(); claimed != 1 {
				t.Fatalf("a request during the retry claimed a check: claims=%d", claimed)
			}
			// The failure stands through the retry's own check, which fails too.
			clock.Advance(azureCheckRetry)
			if err := checks.Confirm(context.Background(), target); !errors.Is(err, test.want) {
				t.Fatalf("Confirm() at the retry = %v, want %v", err, test.want)
			}
			waitFor(func() bool { return requests.Load() == 2 && checks.failing("byok-1") })
			settle(checks, "byok-1")
			// A check that succeeds clears it.
			clock.Advance(azureCheckRetry)
			_ = checks.Confirm(context.Background(), target)
			waitFor(func() bool { _, recorded := store.counts(); return recorded == 1 })
			waitFor(func() bool { return !checks.failing("byok-1") })
			if err := checks.Confirm(context.Background(), target); err != nil {
				t.Fatalf("Confirm() after a check succeeded = %v", err)
			}
		})
	}
}

func TestAzureChecksRecordRefusalsAndWaitBeforeTheNext(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		signIn error
	}{
		{name: "sign-in rejected", signIn: azureauth.ErrCredential},
		{name: "account forbidden", status: http.StatusForbidden},
		{name: "account gone", status: http.StatusNotFound},
		{name: "token refused", status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{Claimed: true, StartedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}}}
			checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"status": test.status})
			if test.signIn != nil {
				checks.tokens = azureTokenFunc(func(context.Context, azureauth.Credential) (string, error) {
					return "", test.signIn
				})
			}
			target := testCheckTarget(clock.Ago(azureCheckFresh))
			if err := checks.Confirm(context.Background(), target); err != nil {
				t.Fatalf("Confirm() = %v", err)
			}
			waitFor(func() bool { return store.refusals() == 1 && checks.failing("byok-1") })
			settle(checks, "byok-1")
			if _, recorded := store.counts(); recorded != 0 {
				t.Fatal("a refused check recorded deployments")
			}
			// Trying again soon does not fix a refusal, so the next check waits as after a success.
			clock.Advance(azureCheckFresh - time.Second)
			_ = checks.Confirm(context.Background(), target)
			if claimed, _ := store.counts(); claimed != 1 {
				t.Fatalf("a refused credential was checked again early: claims=%d", claimed)
			}
			clock.Advance(time.Second)
			_ = checks.Confirm(context.Background(), target)
			waitFor(func() bool { return store.refusals() == 2 })
			if test.signIn == nil && requests.Load() != 2 {
				t.Fatalf("ARM reads = %d, want 2", requests.Load())
			}
		})
	}
}

func TestAzureChecksRefuseUnknownAccounts(t *testing.T) {
	store := &fakeAzureCheckStore{}
	checks, _, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	target := testCheckTarget(clock.Now())
	for _, account := range []string{"", testAzureAccount + "/../other", "/subscriptions/x/resourcegroups/rg/providers/microsoft.cognitiveservices/accounts/a"} {
		target.AccountID = account
		if err := checks.Confirm(context.Background(), target); !errors.Is(err, billing.ErrByok) {
			t.Fatalf("account %q: Confirm() = %v", account, err)
		}
	}
}

func TestAzureChecksReadDeploymentsLikeDiscovery(t *testing.T) {
	duplicate := armDeploymentJSON("customer-sol", "2026-07-09", "GlobalStandard", "")
	odd := map[string]any{
		"id":         testAzureAccount + "/deployments/Odd.Name_1",
		"name":       "stogas-east/odd.name_1",
		"properties": map[string]any{"model": map[string]any{"format": " OpenAI\u00a0", "name": 7, "version": nil}, "provisioningState": " Creating "},
		"sku":        "GlobalStandard",
	}
	store := &fakeAzureCheckStore{}
	checks, requests, _ := newTestAzureChecks(t, store,
		map[string]any{"value": []any{duplicate}, "nextLink": "https://management.azure.com" + testAzureAccount + "/deployments?api-version=" + armAPIVersion + "&$skiptoken=1"},
		map[string]any{"value": []any{}, "nextLink": "https://management.azure.com:443" + testAzureAccount + "/deployments?api-version=" + armAPIVersion + "&$skiptoken=2"},
		map[string]any{"value": []any{duplicate, odd}},
	)
	deployments, reason, err := checks.deployments(context.Background(), testCheckTarget(time.Time{}))
	if err != nil {
		t.Fatalf("deployments() = %v (%s)", err, reason)
	}
	want := []billing.AzureDeployment{
		{ID: testAzureAccount + "/deployments/customer-sol", ModelFormat: "OpenAI", ModelName: "gpt-5.6-sol", ModelVersion: "2026-07-09", SkuName: "GlobalStandard"},
		{ID: testAzureAccount + "/deployments/odd.name_1", ModelFormat: "OpenAI", State: "Creating"},
	}
	if requests.Load() != 3 || len(deployments) != len(want) || deployments[0] != want[0] || deployments[1] != want[1] {
		t.Fatalf("deployments = %#v after %d pages", deployments, requests.Load())
	}
}

func TestAzureChecksRejectDeploymentsOutsideTheAccount(t *testing.T) {
	other := armDeploymentJSON("customer-sol", "1", "GlobalStandard", "Succeeded")
	other["id"] = strings.Replace(testAzureAccount, "stogas-east", "stogas-west", 1) + "/deployments/customer-sol"
	nested := armDeploymentJSON("customer-sol", "1", "GlobalStandard", "Succeeded")
	nested["id"] = testAzureAccount + "/deployments/customer-sol/extra"
	renamed := armDeploymentJSON("customer-sol", "1", "GlobalStandard", "Succeeded")
	renamed["name"] = "another-name"
	for _, test := range []struct {
		name   string
		page   map[string]any
		reason string
	}{
		{"another account", map[string]any{"value": []any{other}}, "invalid_deployment"},
		{"a child resource", map[string]any{"value": []any{nested}}, "invalid_deployment"},
		{"another name", map[string]any{"value": []any{renamed}}, "invalid_deployment"},
		{"a plain HTTP continuation", map[string]any{"value": []any{}, "nextLink": "http://management.azure.com/next"}, "invalid_next_link"},
		{"another host", map[string]any{"value": []any{}, "nextLink": "https://management.azure.com.example.com/next"}, "invalid_next_link"},
		{"user information", map[string]any{"value": []any{}, "nextLink": "https://user@management.azure.com/next"}, "invalid_next_link"},
		{"a refusal", map[string]any{"status": http.StatusForbidden}, "status_403"},
	} {
		t.Run(test.name, func(t *testing.T) {
			checks, _, _ := newTestAzureChecks(t, &fakeAzureCheckStore{}, test.page)
			if _, reason, err := checks.deployments(context.Background(), testCheckTarget(time.Time{})); err == nil || reason != test.reason {
				t.Fatalf("deployments() = %v (%s), want %s", err, reason, test.reason)
			}
		})
	}
}

func TestAzureChecksBoundPages(t *testing.T) {
	loop := map[string]any{"value": []any{}, "nextLink": "https://management.azure.com" + testAzureAccount + "/deployments?api-version=" + armAPIVersion + "&$skiptoken=again"}
	checks, requests, _ := newTestAzureChecks(t, &fakeAzureCheckStore{}, loop)
	if _, reason, err := checks.deployments(context.Background(), testCheckTarget(time.Time{})); err == nil || reason != "too_many_pages" || requests.Load() != armMaxPages {
		t.Fatalf("deployments() = %v (%s) after %d pages", err, reason, requests.Load())
	}
}

func TestTrimJSMatchesJavaScript(t *testing.T) {
	// JavaScript trims U+FEFF but not U+0085 or U+200B.
	if got := trimJS("\ufeff\u00a0 \u2028gpt\u0085\u200b\u3000\t"); got != "gpt\u0085\u200b" {
		t.Fatalf("trimJS() = %q", got)
	}
}

// newTestAzureDiscoveries is a checker whose Azure Resource Manager answers as the named discovery
// case does, and whose sign-ins fail with signInErr.
func newTestAzureDiscoveries(t *testing.T, store *fakeAzureCheckStore, name string, signInErr error) (*AzureChecks, *azureDiscoveryARM, *testClock, azureDiscoveryCase) {
	t.Helper()
	entry := azureDiscoveryCaseNamed(t, name)
	arm, client := serveAzureDiscoveryCase(t, entry)
	clock := &testClock{now: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
	checks := NewAzureChecks(context.Background(), store, azureTokenFunc(func(_ context.Context, credential azureauth.Credential) (string, error) {
		if credential.Scope != armScope || credential.Secret != "azure-client-secret" {
			t.Errorf("unexpected token request for scope %q", credential.Scope)
		}
		return "arm-token", signInErr
	}))
	checks.client = client
	checks.now = clock.Now
	return checks, arm, clock, entry
}

// testDiscoveryTarget is a request's target on a customer-encrypted credential whose discovery is
// due, with a fresh confirmation, so only the discovery reads Azure.
func testDiscoveryTarget(clock *testClock, accountID string) azureCheckTarget {
	target := testCheckTarget(clock.Ago(time.Minute))
	target.AccountID = accountID
	target.DiscoverAt = clock.Ago(time.Second)
	target.Envelope = `{"v":1}`
	return target
}

func TestAzureChecksDiscoverAnEncryptedCredentialOnceWhenDue(t *testing.T) {
	started := time.Date(2026, 11, 3, 11, 59, 59, 0, time.UTC)
	store := &fakeAzureCheckStore{discoverClaimed: true, discoverStarted: started}
	checks, arm, clock, entry := newTestAzureDiscoveries(t, store, "named-deployments", nil)
	target := testDiscoveryTarget(clock, entry.AccountID)
	for range 5 {
		if err := checks.Confirm(context.Background(), target); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(func() bool { _, recorded := store.discoveryCounts(); return recorded == 1 })
	claims, _ := store.discoveryCounts()
	answered, unexpected := arm.counts()
	if claims != 1 || answered != len(entry.Responses) || len(unexpected) > 0 {
		t.Fatalf("discoveries: claims=%d reads=%d unexpected=%v", claims, answered, unexpected)
	}
	recorded := store.discoveries[0]
	if recorded.byokID != "byok-1" || !recorded.startedAt.Equal(started) || recorded.envelope != target.Envelope ||
		recorded.failure != "" || recorded.discovery == nil {
		t.Fatalf("recorded %+v", recorded)
	}
	var bindings []azureDiscoveredBinding
	if err := json.Unmarshal(recorded.discovery.Bindings, &bindings); err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, "bindings", bindings, entry.Outcome.Result.Bindings)
	assertSameJSON(t, "deployments", recorded.discovery.Deployments, entry.Outcome.Result.Deployments)
	// A fresh confirmation needs no check of the deployments.
	if claimed, _ := store.counts(); claimed != 0 {
		t.Fatalf("a fresh confirmation claimed %d checks", claimed)
	}
	// Holds made before the record still show the discovery due; this gateway waits.
	if checks.due("byok-1/discover") {
		t.Fatal("a recorded discovery left the credential due here")
	}
}

func TestAzureChecksDiscoverOnlyDueEncryptedCredentials(t *testing.T) {
	for name, change := range map[string]func(*azureCheckTarget, *testClock){
		"stored":      func(target *azureCheckTarget, _ *testClock) { target.DiscoverAt = time.Time{} },
		"not yet due": func(target *azureCheckTarget, clock *testClock) { target.DiscoverAt = clock.Ago(-time.Minute) },
		"no envelope": func(target *azureCheckTarget, _ *testClock) { target.Envelope = "" },
	} {
		t.Run(name, func(t *testing.T) {
			store := &fakeAzureCheckStore{discoverClaimed: true}
			checks, _, clock, entry := newTestAzureDiscoveries(t, store, "named-deployments", nil)
			target := testDiscoveryTarget(clock, entry.AccountID)
			change(&target, clock)
			if err := checks.Confirm(context.Background(), target); err != nil {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
			if claims, recorded := store.discoveryCounts(); claims != 0 || recorded != 0 {
				t.Fatalf("claims=%d records=%d", claims, recorded)
			}
		})
	}
}

func TestAzureChecksLeaveADiscoveryThatAnotherGatewayClaimed(t *testing.T) {
	store := &fakeAzureCheckStore{discoverClaimed: false}
	checks, arm, clock, entry := newTestAzureDiscoveries(t, store, "named-deployments", nil)
	if err := checks.Confirm(context.Background(), testDiscoveryTarget(clock, entry.AccountID)); err != nil {
		t.Fatal(err)
	}
	waitFor(func() bool { claims, _ := store.discoveryCounts(); return claims == 1 })
	waitFor(func() bool {
		checks.mu.Lock()
		defer checks.mu.Unlock()
		return checks.marks["byok-1/discover"].until.Equal(clock.Now().Add(azureCheckRetry))
	})
	if _, recorded := store.discoveryCounts(); recorded != 0 {
		t.Fatal("an unclaimed discovery recorded")
	}
	if answered, _ := arm.counts(); answered != 0 {
		t.Fatalf("an unclaimed discovery made %d Azure reads", answered)
	}
}

func TestAzureChecksRecordDiscoveryFailuresForTheDashboard(t *testing.T) {
	for _, test := range []struct {
		name, caseName string
		signInErr      error
		want           string
	}{
		{"application rejected", "named-deployments", azureauth.ErrCredential, azureAppRejected},
		{"sign-in unavailable", "named-deployments", azureauth.ErrUnavailable, azureAppUnavailable},
		{"account denied", "account-denied", nil, azureAccountDenied},
		{"no data role", "no-data-role", nil, azureRoleMissing},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeAzureCheckStore{discoverClaimed: true, discoverStarted: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
			checks, _, clock, entry := newTestAzureDiscoveries(t, store, test.caseName, test.signInErr)
			if err := checks.Confirm(context.Background(), testDiscoveryTarget(clock, entry.AccountID)); err != nil {
				t.Fatal(err)
			}
			waitFor(func() bool { _, recorded := store.discoveryCounts(); return recorded == 1 })
			recorded := store.discoveries[0]
			// A missing role keeps the targets that the discovery found; other failures keep the last.
			if recorded.failure != test.want || (recorded.discovery != nil) != (test.want == azureRoleMissing) {
				t.Fatalf("recorded %q with %+v", recorded.failure, recorded.discovery)
			}
		})
	}
}

func TestAzureChecksRetryDiscoveriesThatRecordedNothing(t *testing.T) {
	store := &fakeAzureCheckStore{discoverClaimed: true, discoveryErr: billing.ErrGatewayUnavailable}
	checks, _, clock, entry := newTestAzureDiscoveries(t, store, "named-deployments", nil)
	if err := checks.Confirm(context.Background(), testDiscoveryTarget(clock, entry.AccountID)); err != nil {
		t.Fatal(err)
	}
	waitFor(func() bool { return checks.failing("byok-1/discover") })

	// A gateway too busy to discover records nothing: the claim lapses for a later request.
	busy := &fakeAzureCheckStore{discoverClaimed: true}
	checks, arm, clock, entry := newTestAzureDiscoveries(t, busy, "named-deployments", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checks.ctx = ctx
	for range azureCheckLimit {
		checks.slots <- struct{}{}
	}
	if err := checks.Confirm(context.Background(), testDiscoveryTarget(clock, entry.AccountID)); err != nil {
		t.Fatal(err)
	}
	waitFor(func() bool { return checks.failing("byok-1/discover") })
	if _, recorded := busy.discoveryCounts(); recorded != 0 {
		t.Fatal("a busy gateway recorded a discovery")
	}
	if answered, _ := arm.counts(); answered != 0 {
		t.Fatal("a busy gateway read Azure")
	}
}
