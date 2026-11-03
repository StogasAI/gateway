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
	result   billing.AzureCheckResult
	claimErr error
	// staleAfter lists how old each claim let the last confirmation be.
	staleAfter []time.Duration
	// stopped lists the served models of the targets that replies stopped.
	stopped []string
	// onClaim runs on each claim, such as to move the test clock.
	onClaim func()
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

func (s *fakeAzureCheckStore) RecordAzureCheck(_ context.Context, _ string, startedAt time.Time, deployments []billing.AzureDeployment) (billing.AzureCheckResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorded = append(s.recorded, deployments)
	s.started = append(s.started, startedAt)
	return s.result, nil
}

func (s *fakeAzureCheckStore) StopAzureTarget(_ context.Context, byokID, bindingID, servedModel string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if byokID != "byok-1" || bindingID != "binding-1" {
		return false, fmt.Errorf("unexpected target %s %s", byokID, bindingID)
	}
	s.stopped = append(s.stopped, servedModel)
	return len(s.stopped) == 1, nil
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
		BindingID:  "binding-1",
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
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, recorded := store.counts(); recorded == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the background check did not record")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if claimed, _ := store.counts(); claimed != 1 || requests.Load() != 1 {
		t.Fatalf("aging confirmations started several checks: claims=%d requests=%d", claimed, requests.Load())
	}
	want := billing.AzureDeployment{
		ID:             testAzureAccount + "/deployments/customer-sol",
		ModelFormat:    "OpenAI",
		ModelName:      "gpt-5.6-sol",
		ModelVersion:   "2026-07-09",
		SkuName:        "GlobalStandard",
		State:          "Succeeded",
		VersionUpgrade: "OnceNewDefaultVersionAvailable",
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
func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAzureChecksGiveUnreportedRepliesYoungerConfirmations(t *testing.T) {
	started := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{Claimed: true, StartedAt: started}}}
	checks, _, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	// Two minutes is young for a reply that names its version.
	if err := checks.Confirm(context.Background(), testCheckTarget(clock.Ago(2*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if claimed, _ := store.counts(); claimed != 0 {
		t.Fatalf("a young confirmation started a check: claims=%d", claimed)
	}
	// A reply that names none needs a check, in the background, that asks for a younger one.
	target := testCheckTarget(clock.Ago(2 * time.Minute))
	target.Unreported = true
	if err := checks.Confirm(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the background check", func() bool { _, recorded := store.counts(); return recorded == 1 })
	if store.staleAfter[0] != azureCheckUnreportedFresh {
		t.Fatalf("the background claim let confirmations be %v old", store.staleAfter[0])
	}

	// Past ten minutes such a request waits for the check, which the other requests' pacing does
	// not hold back.
	waiting := &fakeAzureCheckStore{claims: []billing.AzureClaim{{Claimed: true, StartedAt: started}}}
	checks, requests, clock := newTestAzureChecks(t, waiting, map[string]any{"value": []any{}})
	checks.pause("byok-1", azureCheckFresh)
	target = testCheckTarget(clock.Ago(11 * time.Minute))
	target.Unreported = true
	if err := checks.Confirm(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if _, recorded := waiting.counts(); recorded != 1 || requests.Load() != 1 || waiting.staleAfter[0] != azureCheckUnreportedStale {
		t.Fatalf("the request did not wait for a check: records=%d requests=%d claims=%v", recorded, requests.Load(), waiting.staleAfter)
	}
}

func TestAzureChecksRecheckAGoneTargetOnceAtATime(t *testing.T) {
	store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{Claimed: true, StartedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}}}
	checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	target := testCheckTarget(clock.Ago(time.Minute))
	for range 3 {
		checks.Recheck(target)
	}
	waitFor(t, "the recheck", func() bool { _, recorded := store.counts(); return recorded == 1 })
	if claimed, _ := store.counts(); claimed != 1 || requests.Load() != 1 || store.staleAfter[0] != azureCheckWait {
		t.Fatalf("rechecks: claims=%d requests=%d stale after %v", claimed, requests.Load(), store.staleAfter)
	}
}

func TestAzureChecksStopATargetThatServedAnotherVersion(t *testing.T) {
	store := &fakeAzureCheckStore{}
	checks, requests, _ := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	checks.Stop(testCheckTarget(time.Time{}), "gpt-5.6-sol-2026-10-28")
	waitFor(t, "the stop", func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.stopped) == 1
	})
	if store.stopped[0] != "gpt-5.6-sol-2026-10-28" || requests.Load() != 0 {
		t.Fatalf("stopped %v after %d Azure requests", store.stopped, requests.Load())
	}
}

func TestAzureChecksStopRequestsWhoseTargetChanged(t *testing.T) {
	for _, test := range []struct {
		reason string
		want   error
	}{
		{"changed", billing.ErrByokTargetChanged},
		{"missing", billing.ErrByokTarget},
		{"failed", billing.ErrByokTarget},
	} {
		t.Run(test.reason, func(t *testing.T) {
			store := &fakeAzureCheckStore{
				claims: []billing.AzureClaim{{Claimed: true, StartedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}},
				result: billing.AzureCheckResult{Unavailable: map[string]string{"binding-1": test.reason}},
			}
			checks, _, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{armDeploymentJSON("customer-sol", "2026-10-28", "GlobalStandard", "Succeeded")}})
			if err := checks.Confirm(context.Background(), testCheckTarget(clock.Ago(31*time.Minute))); !errors.Is(err, test.want) {
				t.Fatalf("Confirm() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAzureChecksServeTargetsThatAnotherBindingsCheckLeft(t *testing.T) {
	store := &fakeAzureCheckStore{
		claims: []billing.AzureClaim{{Claimed: true, StartedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}},
		result: billing.AzureCheckResult{Unavailable: map[string]string{"binding-2": "changed"}},
	}
	checks, _, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	if err := checks.Confirm(context.Background(), testCheckTarget(clock.Ago(31*time.Minute))); err != nil {
		t.Fatal(err)
	}
}

func TestAzureChecksWaitForAnotherGatewaysCheck(t *testing.T) {
	started := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	store := &fakeAzureCheckStore{claims: []billing.AzureClaim{
		{StartedAt: started, VerifiedAt: started.Add(-40 * time.Minute)},
		{StartedAt: started, VerifiedAt: started.Add(-40 * time.Minute)},
		{StartedAt: started.Add(time.Second), VerifiedAt: started.Add(500 * time.Millisecond)},
	}}
	checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	if err := checks.Confirm(context.Background(), testCheckTarget(clock.Ago(40*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if claimed, recorded := store.counts(); claimed != 3 || recorded != 0 || requests.Load() != 0 {
		t.Fatalf("waiting for another gateway read Azure: claims=%d records=%d requests=%d", claimed, recorded, requests.Load())
	}
}

// A request that waited for another gateway's check refuses a target that the check stopped.
func TestAzureChecksRefuseTargetsThatAnotherGatewaysCheckStopped(t *testing.T) {
	started := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	store := &fakeAzureCheckStore{claims: []billing.AzureClaim{
		{StartedAt: started, VerifiedAt: started.Add(-40 * time.Minute)},
		{
			StartedAt:   started.Add(time.Second),
			VerifiedAt:  started.Add(500 * time.Millisecond),
			Unavailable: map[string]string{"binding-1": "changed"},
		},
	}}
	checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	if err := checks.Confirm(context.Background(), testCheckTarget(clock.Ago(40*time.Minute))); !errors.Is(err, billing.ErrByokTargetChanged) {
		t.Fatalf("Confirm() = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("waiting for another gateway read Azure")
	}
}

// A gateway waits azureCheckWait for another gateway's check. Within the grace it then serves,
// unless the database already knows the target is out of service; past it, it checks unclaimed.
func TestAzureChecksStopWaitingForAnotherGateway(t *testing.T) {
	for _, test := range []struct {
		name        string
		age         time.Duration
		binding     string
		want        error
		armRequests int32
	}{
		{"within grace", 40 * time.Minute, "binding-1", nil, 0},
		{"within grace with the target out", 40 * time.Minute, "binding-2", billing.ErrByokTarget, 0},
		{"past grace", 3 * time.Hour, "binding-1", nil, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
			store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{
				StartedAt:   started,
				VerifiedAt:  started.Add(-test.age),
				Unavailable: map[string]string{"binding-2": "missing"},
			}}}
			checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
			store.onClaim = func() { clock.Advance(time.Second) }
			target := testCheckTarget(clock.Ago(test.age))
			target.BindingID = test.binding
			if err := checks.Confirm(context.Background(), target); !errors.Is(err, test.want) {
				t.Fatalf("Confirm() = %v, want %v", err, test.want)
			}
			claimed, recorded := store.counts()
			if claimed < 5 || recorded != int(test.armRequests) || requests.Load() != test.armRequests {
				t.Fatalf("claims=%d records=%d requests=%d", claimed, recorded, requests.Load())
			}
		})
	}
}

// While another gateway holds the claim, this one claims again no sooner than azureCheckWait.
func TestAzureChecksPaceBackgroundClaims(t *testing.T) {
	started := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{StartedAt: started, VerifiedAt: started.Add(-15 * time.Minute)}}}
	checks, _, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	target := testCheckTarget(clock.Ago(15 * time.Minute))
	waitForClaims := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if claimed, _ := store.counts(); claimed == want {
				// Let the background check finish.
				time.Sleep(50 * time.Millisecond)
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected %d claims", want)
			}
			time.Sleep(5 * time.Millisecond)
		}
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
	clock.Advance(azureCheckWait)
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

// A request waits for a slow check only so long. Within the grace it then keeps its target, and
// the check goes on for later requests.
func TestAzureChecksBoundTheWaitForASlowCheck(t *testing.T) {
	for _, test := range []struct {
		name string
		age  time.Duration
		want error
	}{
		{"within grace", 40 * time.Minute, nil},
		{"never confirmed", 0, billing.ErrByok},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{Claimed: true, StartedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}}}
			checks, _, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
			checks.wait = 20 * time.Millisecond
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
			if err := checks.Confirm(context.Background(), testCheckTarget(verifiedAt)); !errors.Is(err, test.want) {
				t.Fatalf("Confirm() = %v, want %v", err, test.want)
			}
			close(release)
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, recorded := store.counts(); recorded == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the check did not go on after the request stopped waiting")
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

func TestAzureChecksCoalesceWaitingRequests(t *testing.T) {
	store := &fakeAzureCheckStore{claims: []billing.AzureClaim{{Claimed: true, StartedAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}}}
	checks, requests, clock := newTestAzureChecks(t, store, map[string]any{"value": []any{}})
	release := make(chan struct{})
	tokens := checks.tokens
	checks.tokens = azureTokenFunc(func(ctx context.Context, credential azureauth.Credential) (string, error) {
		<-release
		return tokens.Token(ctx, credential)
	})
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := checks.Confirm(context.Background(), testCheckTarget(clock.Ago(time.Hour))); err != nil {
				t.Error(err)
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	group.Wait()
	if claimed, recorded := store.counts(); claimed != 1 || recorded != 1 || requests.Load() != 1 {
		t.Fatalf("waiting requests did not share one check: claims=%d records=%d requests=%d", claimed, recorded, requests.Load())
	}
}

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
			checks, _, clock := newTestAzureChecks(t, store, map[string]any{"status": http.StatusServiceUnavailable})
			verifiedAt := time.Time{}
			if test.age > 0 {
				verifiedAt = clock.Ago(test.age)
			}
			target := testCheckTarget(verifiedAt)
			if err := checks.Confirm(context.Background(), target); !errors.Is(err, test.want) {
				t.Fatalf("Confirm() = %v, want %v", err, test.want)
			}
			if _, recorded := store.counts(); recorded != 0 {
				t.Fatal("a failed check recorded deployments")
			}
			// A failed check waits before the gateway tries Azure again.
			if checks.due("byok-1") {
				t.Fatal("a failed check left the credential due at once")
			}
			// Until then, requests answer at once instead of waiting for another check.
			if err := checks.Confirm(context.Background(), target); !errors.Is(err, test.want) {
				t.Fatalf("Confirm() during the retry = %v, want %v", err, test.want)
			}
			if claimed, _ := store.counts(); claimed != 1 {
				t.Fatalf("a request during the retry claimed a check: claims=%d", claimed)
			}
			clock.Advance(azureCheckRetry)
			_ = checks.Confirm(context.Background(), target)
			if claimed, _ := store.counts(); claimed != 2 {
				t.Fatalf("no check after the retry: claims=%d", claimed)
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
		{ID: testAzureAccount + "/deployments/customer-sol", ModelFormat: "OpenAI", ModelName: "gpt-5.6-sol", ModelVersion: "2026-07-09", SkuName: "GlobalStandard", VersionUpgrade: "OnceNewDefaultVersionAvailable"},
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
