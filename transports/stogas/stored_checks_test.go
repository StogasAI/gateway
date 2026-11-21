package stogas

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// fakeStoredChecks is the database's queue of due stored credentials, whose envelope "sealed" opens
// as each credential's secret, and what the checks recorded.
type fakeStoredChecks struct {
	mu      sync.Mutex
	due     []*billing.ByokCheckTarget
	secrets map[string]string
	// The limit of each claim, what each check recorded by credential, and our failures.
	limits      []int
	recorded    map[string]string
	discoveries map[string]*billing.AzureDiscoveryResult
	ours        []string
	record      error
}

func newFakeStoredChecks() *fakeStoredChecks {
	return &fakeStoredChecks{secrets: map[string]string{}, recorded: map[string]string{}, discoveries: map[string]*billing.AzureDiscoveryResult{}}
}

// add queues a due credential of the provider with the secret.
func (s *fakeStoredChecks) add(provider, secret string) *billing.ByokCheckTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	target := &billing.ByokCheckTarget{
		Grant:    billing.ByokCheckGrant{OrganizationID: testOrganizationID, ByokID: fmt.Sprintf("0196f0f4-0000-7000-8000-%012d", len(s.secrets)+1)},
		Provider: provider, EncryptedSecret: "sealed", StartedAt: time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC),
	}
	s.secrets[target.Grant.ByokID] = secret
	s.due = append(s.due, target)
	return target
}

func (s *fakeStoredChecks) ClaimByokChecks(_ context.Context, limit int) ([]*billing.ByokCheckTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limits = append(s.limits, limit)
	claimed := s.due[:min(limit, len(s.due))]
	s.due = s.due[len(claimed):]
	return claimed, nil
}

func (s *fakeStoredChecks) OpenStored(target *billing.ByokCheckTarget) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if target.EncryptedSecret != "sealed" {
		return "", billing.ErrStoredByokSecret
	}
	return s.secrets[target.Grant.ByokID], nil
}

func (s *fakeStoredChecks) RecordByokCheck(_ context.Context, target *billing.ByokCheckTarget, failure string, discovery *billing.AzureDiscoveryResult) (*billing.ByokCheckRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record != nil {
		return nil, s.record
	}
	s.recorded[target.Grant.ByokID] = failure
	s.discoveries[target.Grant.ByokID] = discovery
	return &billing.ByokCheckRecord{CheckedAt: time.Now()}, nil
}

func (s *fakeStoredChecks) RecordByokCheckFailure(_ context.Context, target *billing.ByokCheckTarget) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ours = append(s.ours, target.Grant.ByokID)
	return nil
}

// A check of a stored credential checks it as a member's check of a customer-encrypted one does,
// and records the result.
func TestStoredCheckRecordsWhatTheProviderAnswered(t *testing.T) {
	status := http.StatusOK
	server, seen := byokCheckTestServer(t, &status)
	ctx := context.Background()
	for code, want := range map[int]string{
		http.StatusOK:                 "",
		http.StatusUnauthorized:       byokRejected("openai"),
		http.StatusServiceUnavailable: byokUnavailable("openai"),
	} {
		status = code
		store := newFakeStoredChecks()
		target := store.add("openai", "sk-stored")
		runStoredCheck(ctx, store, newTestByokChecker(server, nil, target.StartedAt), target)
		if failure, recorded := store.recorded[target.Grant.ByokID]; !recorded || failure != want || store.discoveries[target.Grant.ByokID] != nil || len(store.ours) != 0 {
			t.Fatalf("status %d recorded %q", code, store.recorded)
		}
	}
	if r := seen()[len(seen())-1]; r.path != "/v1/models" || r.header.Get("Authorization") != "Bearer sk-stored" {
		t.Fatalf("the provider got %+v", r)
	}

	// A secret that is not its provider's credential is the member's to replace, and shows on the
	// credential.
	status = http.StatusOK
	store := newFakeStoredChecks()
	invalid := store.add("openai", "sk stored")
	runStoredCheck(ctx, store, newTestByokChecker(server, nil, invalid.StartedAt), invalid)
	if store.recorded[invalid.Grant.ByokID] != "The secret is not a valid OpenAI API key" {
		t.Fatalf("an invalid secret recorded %q", store.recorded)
	}

	// A secret that this gateway cannot open, or that cannot serve the target stored beside it, is
	// our failure: the check reaches no provider and records only that it failed.
	before := len(seen())
	store = newFakeStoredChecks()
	unreadable := store.add("openai", "sk-stored")
	unreadable.EncryptedSecret = "other"
	mismatched := store.add("aws", awsIAMSecret(t, "us-east-1", ""))
	mismatched.Target = &billing.CloudTarget{Hosting: []string{"amazon"}, Region: "eu-west-1"}
	for _, target := range []*billing.ByokCheckTarget{unreadable, mismatched} {
		runStoredCheck(ctx, store, newTestByokChecker(server, nil, target.StartedAt), target)
	}
	if len(store.recorded) != 0 || len(store.ours) != 2 || store.ours[0] != unreadable.Grant.ByokID || store.ours[1] != mismatched.Grant.ByokID {
		t.Fatalf("recorded %q and our failures %q", store.recorded, store.ours)
	}
	if len(seen()) != before {
		t.Fatal("a check that cannot run reached the provider")
	}

	// A credential that changed while the check ran keeps the newer result, and a check that the
	// gateway stops records nothing, so the credential is due again when the claim ends.
	for name, test := range map[string]struct {
		record error
		ctx    func() context.Context
	}{
		"changed": {billing.ErrByokCheckChanged, context.Background},
		"stopped": {nil, func() context.Context {
			stopped, cancel := context.WithCancel(context.Background())
			cancel()
			return stopped
		}},
	} {
		store := newFakeStoredChecks()
		store.record = test.record
		target := store.add("openai", "sk-stored")
		runStoredCheck(test.ctx(), store, newTestByokChecker(server, nil, target.StartedAt), target)
		if len(store.recorded) != 0 || len(store.ours) != 0 {
			t.Fatalf("%s: recorded %q and our failures %q", name, store.recorded, store.ours)
		}
	}
}

// An Azure credential's check discovers its account's targets from the database's time and records
// them. A missing data role keeps the targets and says why requests fail, and a failure records no
// discovery, so the credential keeps the targets of the last one.
func TestStoredCheckDiscoversAzureTargets(t *testing.T) {
	status := http.StatusOK
	server, _ := byokCheckTestServer(t, &status)
	for _, test := range []struct {
		name       string
		signIn     *fakeAzureSignIn
		want       string
		discovered bool
	}{
		{"named-deployments", &fakeAzureSignIn{}, "", true},
		{"no-data-role", &fakeAzureSignIn{}, azureRoleMissing, true},
		{"listing-without-value", &fakeAzureSignIn{}, "", true},
		{"account-denied", &fakeAzureSignIn{}, azureAccountDenied, false},
		{"account-outage", &fakeAzureSignIn{}, azureDiscoveryUnavailable, false},
		{"named-deployments", &fakeAzureSignIn{err: azureauth.ErrCredential}, azureAppRejected, false},
	} {
		entry := azureDiscoveryCaseNamed(t, test.name)
		_, client := serveAzureDiscoveryCase(t, entry)
		store := newFakeStoredChecks()
		target := store.add("azure", storedTestApp)
		target.AzureAccountID = entry.AccountID
		checker := newTestByokChecker(server, nil, target.StartedAt)
		checker.arm, checker.azure = client, test.signIn
		runStoredCheck(context.Background(), store, checker, target)
		failure, recorded := store.recorded[target.Grant.ByokID]
		discovery := store.discoveries[target.Grant.ByokID]
		if !recorded || failure != test.want || (discovery != nil) != test.discovered {
			t.Fatalf("%s: recorded %q", test.name, store.recorded)
		}
		if !test.discovered {
			continue
		}
		var bindings []azureDiscoveredBinding
		if err := json.Unmarshal(discovery.Bindings, &bindings); err != nil {
			t.Fatal(err)
		}
		assertSameJSON(t, test.name+" bindings", bindings, entry.Outcome.Result.Bindings)
	}
}

// A gateway claims due checks when it starts and again as each check ends, never runs more than
// storedCheckLimit at once, and waits for its running checks when it stops.
func TestStoredChecksRunTheQueue(t *testing.T) {
	var mu sync.Mutex
	running, most := 0, 0
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		running++
		most = max(most, running)
		mu.Unlock()
		<-release
		mu.Lock()
		running--
		mu.Unlock()
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	store := newFakeStoredChecks()
	checks := 2*storedCheckLimit + 1
	for range checks {
		store.add("openai", "sk-stored")
	}
	waitFor := func(what string, done func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !done(); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}
	inFlight := func(n int) func() bool {
		return func() bool {
			mu.Lock()
			defer mu.Unlock()
			return running == n
		}
	}
	recorded := func(n int) func() bool {
		return func() bool {
			store.mu.Lock()
			defer store.mu.Unlock()
			return len(store.recorded) == n
		}
	}

	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runStoredChecks(ctx, store, newTestByokChecker(server, nil, time.Now()))
	}()
	waitFor("the first claim", inFlight(storedCheckLimit))
	// Each check that ends makes room for the next one, which the gateway claims at once.
	for finished := 1; finished < checks; finished++ {
		release <- struct{}{}
		waitFor("a record", recorded(finished))
		waitFor("the next claim", inFlight(min(storedCheckLimit, checks-finished)))
	}
	// The last check is still waiting for the provider when the gateway stops. The gateway waits for
	// it, and it records nothing, so the credential is due again when its claim ends.
	stop()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the loop did not stop")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	if most != storedCheckLimit || len(store.due) != 0 || len(store.recorded) != checks-1 || len(store.ours) != 0 {
		t.Fatalf("%d checks ran at once, %d stayed due, %d recorded, our failures %q", most, len(store.due), len(store.recorded), store.ours)
	}
	if store.limits[0] != storedCheckLimit {
		t.Fatalf("claim limits %v", store.limits)
	}
	for _, limit := range store.limits {
		if limit < 1 || limit > storedCheckLimit {
			t.Fatalf("claim limits %v", store.limits)
		}
	}
}
