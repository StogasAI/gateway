package billing

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func BenchmarkAPIKeyAdmission(b *testing.B) {
	const secret = "benchmark-pepper"
	key := testSignedAPIKey(b, secret, "019de515-eabf-7c0e-89bd-400629a79580",
		"019de516-7df8-71d6-80e4-3c62090d4e94",
		"019de516-b10f-786f-97f8-b95c71dfe1b6", "", apiKeyVersion)
	for _, name := range []string{"malformed", "invalid-mac", "cached-claims", "blocked-caller"} {
		b.Run(name, func(b *testing.B) {
			s := &Service{apiKeyPepper: secret}
			claims, _, _, err := s.parseVerifiedAPIKey(key)
			if err != nil {
				b.Fatal(err)
			}
			input := key
			switch name {
			case "malformed":
				input = "invalid"
			case "invalid-mac":
				s.apiKeyPepper = "different-pepper"
			case "blocked-caller":
				s.refusals.record(claims.admissionKey, nil, time.Hour, time.Now())
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if name == "cached-claims" {
						if _, _, _, err := s.parseVerifiedAPIKey(input); err != nil {
							b.Fatal(err)
						}
					} else if _, err := s.ParseAPIKey(input); err == nil {
						b.Fatal("expected admission rejection")
					}
				}
			})
		})
	}
}

// A credential's requests spend its own allowance and its organization's.
// Other credentials of the organization share only the second, and the
// organization's refusal returns the credential's share.
func TestLocalLimitsChargeCredentialsAndTheirOrganization(t *testing.T) {
	const secret = "test-api-key-pepper"
	org := "019de516-7df8-71d6-80e4-3c62090d4e94"
	key := func(id, organization string) string {
		return testSignedAPIKey(t, secret, id, organization, "019de516-b10f-786f-97f8-b95c71dfe1b6", "", apiKeyVersion)
	}
	first := key("019de515-eabf-7c0e-89bd-400629a79580", org)
	second := key("019de515-eabf-7c0e-89bd-400629a79581", org)
	other := key("019de515-eabf-7c0e-89bd-400629a79582", "019de516-7df8-71d6-80e4-3c62090d4e95")
	service := &Service{apiKeyPepper: secret}
	firstClaims, err := service.ParseAPIKey(first)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(limiter *localRequestLimiter, identity string) (localRequestEntry, bool) {
		shard := &limiter.shards[localAdmissionShard(identity)]
		value, ok := shard.entries[identity]
		return value, ok
	}
	if _, ok := entry(&service.organizationRequests, org); !ok {
		t.Fatal("request was not attributed to its signed organization")
	}
	// Fix the organization's bucket empty in the future to avoid a
	// timing-dependent refill in race tests.
	empty := func() {
		service.organizationRequests.shards[localAdmissionShard(org)].entries[org] = localRequestEntry{updatedAt: time.Now().Add(time.Hour)}
	}
	empty()
	secondClaims, err := service.ParseAPIKey(second)
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("another key escaped the organization's bucket: %v", err)
	}
	if allowance, _ := entry(&service.credentialRequests, secondClaims.admissionKey); allowance.tokens != credentialRequestLimit.burst {
		t.Fatalf("the organization's refusal spent %v of the credential's allowance", credentialRequestLimit.burst-allowance.tokens)
	}
	if _, err := service.ParseAPIKey(other); err != nil {
		t.Fatalf("one organization blocked another: %v", err)
	}
	credential := &DashboardCredential{ActorUserID: "actor", SessionID: "session", KeyID: "key"}
	snapshot := keyConfigSnapshot(1, strings.Repeat("a", 64))
	snapshot.Claims = &APIKeyClaims{OrganizationID: org}
	service.keyConfigs.put(dashboardConfigCacheKey(credential), snapshot, time.Now())
	// ParseDashboardCredential charges the session, and the key it selects
	// names the organization.
	if err := service.admitCredential(dashboardAdmissionKey(credential), time.Now()); err != nil {
		t.Fatal(err)
	}
	empty()
	if _, err := service.ConfigForDashboard(context.Background(), credential, nil); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("dashboard escaped the organization's bucket: %v", err)
	}
	if allowance, _ := entry(&service.credentialRequests, dashboardAdmissionKey(credential)); allowance.tokens != credentialRequestLimit.burst {
		t.Fatal("the organization's refusal spent the dashboard session's allowance")
	}
	before := service.credentialRequests.attempts.Load() + service.organizationRequests.attempts.Load()
	if _, err := service.ParseAPIKey(first + "invalid"); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatal("accepted forged organization claim")
	}
	if service.credentialRequests.attempts.Load()+service.organizationRequests.attempts.Load() != before {
		t.Fatal("unauthenticated key consumed an allowance")
	}
	// A credential at its limit leaves the organization's other half.
	service = &Service{apiKeyPepper: secret}
	now := time.Now()
	for range int(credentialRequestLimit.burst) {
		if err := service.admitCredential(firstClaims.admissionKey, now); err != nil {
			t.Fatal(err)
		}
		if err := service.admitOrganization(firstClaims.admissionKey, org, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.admitCredential(firstClaims.admissionKey, now); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("credential beyond its burst = %v", err)
	}
	for range int(organizationRequestLimit.burst - credentialRequestLimit.burst) {
		if err := service.admitOrganization(secondClaims.admissionKey, org, now); err != nil {
			t.Fatalf("a runaway credential took more than its share: %v", err)
		}
	}
	diagnostics := service.localAdmissionDiagnostics()
	if diagnostics.CredentialRequests.Rejected != 1 || diagnostics.OrganizationRequests.Rejected != 0 ||
		diagnostics.CredentialRequests.Burst != int(credentialRequestLimit.burst) ||
		diagnostics.OrganizationRequests.RatePerSecond != int(organizationRequestLimit.ratePerSecond) {
		t.Fatalf("local admission diagnostics = %#v", diagnostics)
	}
}

// PostgreSQL admits an organization's requests at 120 a second, and 360 at
// once as they wait up to two seconds to start. After it refuses a
// credential's request, memory refuses that credential's next requests for
// refusalHoldBack. A gateway that receives every request of an organization's
// credentials refuses none of the others that PostgreSQL would admit.
func TestLocalLimitsRefuseNothingPostgreSQLWouldAdmit(t *testing.T) {
	const rate, depth = 120.0, 360.0
	random := rand.New(rand.NewPCG(1, 2))
	admitted, refused := map[int]int{}, map[int]int{}
	for run := range 300 {
		service := &Service{}
		credentials := []int{1, 2, 3, 12, 50}[run%5]
		start := time.Unix(1_700_000_000, 0)
		now, updated, tokens := start, start, depth
		heldUntil := make([]time.Time, credentials)
		for sent := 0; sent < 3000; {
			// Bursts, floods and steady rates near PostgreSQL's from some of the
			// credentials, with pauses longer than a refill between them.
			perSecond := []float64{0, 60, 119, 121, 240, 1000, 5000}[random.IntN(7)]
			active := 1 + random.IntN(credentials)
			for range 1 + random.IntN(500) {
				sent++
				if perSecond > 0 {
					now = now.Add(time.Duration(random.ExpFloat64() / perSecond * float64(time.Second)))
				}
				tokens, updated = min(depth, tokens+now.Sub(updated).Seconds()*rate), now
				index := random.IntN(active)
				if now.Before(heldUntil[index]) {
					continue
				}
				credential := fmt.Sprint("api:", index)
				local := service.admitCredential(credential, now) == nil && service.admitOrganization(credential, "org", now) == nil
				switch {
				case tokens >= 1 && !local:
					t.Fatalf("run %d: refused a request that PostgreSQL would admit with %.3f tokens", run, tokens)
				case !local:
				case tokens >= 1:
					tokens--
					admitted[credentials]++
				default:
					heldUntil[index] = now.Add(refusalHoldBack)
					refused[credentials]++
				}
			}
			if random.IntN(3) == 0 {
				now = now.Add(time.Duration(random.ExpFloat64() * 3 * float64(time.Second)))
			}
		}
	}
	for credentials, count := range admitted {
		if count == 0 || refused[credentials] == 0 {
			t.Fatalf("%d credentials: admitted %d and refused %d", credentials, count, refused[credentials])
		}
	}
}

func TestRefusedKeySpendsNoLocalAllowance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const secret = "test-api-key-pepper"
		raw := testSignedAPIKey(t, secret, "019de515-eabf-7c0e-89bd-400629a79580",
			"019de516-7df8-71d6-80e4-3c62090d4e94", "019de516-b10f-786f-97f8-b95c71dfe1b6", "", apiKeyVersion)
		service := &Service{apiKeyPepper: secret}
		claims, err := service.ParseAPIKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		// PostgreSQL found that the key has a new secret.
		service.RecordRefusal(claims, nil, ErrAPIKeyOldSecret.Code)
		spent := service.credentialRequests.attempts.Load() + service.organizationRequests.attempts.Load()
		for range int(organizationRequestLimit.burst) + 1 {
			if _, err := service.ParseAPIKey(raw); !errors.Is(err, ErrAPIKeyOldSecret) {
				t.Fatalf("refused secret got %v", err)
			}
			service.RecordRefusal(claims, nil, ErrAPIKeyOldSecret.Code)
		}
		if service.credentialRequests.attempts.Load()+service.organizationRequests.attempts.Load() != spent {
			t.Fatal("a refused secret spent a local allowance")
		}
		// Refusals from memory do not extend the minute, so PostgreSQL decides again after it.
		time.Sleep(refusedAPIKeyDuration)
		if _, err := service.ParseAPIKey(raw); err != nil {
			t.Fatalf("refusal outlasted its minute: %v", err)
		}
	})
}

func TestVerifiedAPIKeyCacheCopiesClaims(t *testing.T) {
	expectedGrantID := "019de516-c9ac-79cf-b701-4cf1b21f0a8c"
	grantID := expectedGrantID
	claims := &APIKeyClaims{
		FormatVersion:  apiKeyVersion,
		GrantID:        &grantID,
		KeyID:          "019de515-eabf-7c0e-89bd-400629a79580",
		OrganizationID: "019de516-7df8-71d6-80e4-3c62090d4e94",
		ResponsibleID:  "019de516-b10f-786f-97f8-b95c71dfe1b6",
	}
	var service Service
	cache := &service.apiKeys
	cache.put("key", claims)
	claims.KeyID = "changed"
	*claims.GrantID = "changed"

	first, ok := cache.get("key")
	if !ok || first.KeyID != "019de515-eabf-7c0e-89bd-400629a79580" || first.GrantID == nil || *first.GrantID != expectedGrantID {
		t.Fatalf("cached claims = %#v", first)
	}
	first.KeyID = "caller-change"
	*first.GrantID = "caller-change"
	second, ok := cache.get("key")
	if !ok || second.KeyID != "019de515-eabf-7c0e-89bd-400629a79580" || second.GrantID == nil || *second.GrantID != expectedGrantID {
		t.Fatalf("caller mutated cached claims: %#v", second)
	}
	if diagnostics := service.localAdmissionDiagnostics(); diagnostics.APIKeyCacheEntries != 1 || diagnostics.APIKeyCacheHits != 2 || diagnostics.APIKeyCacheLookups != 2 {
		t.Fatalf("API key cache diagnostics = %#v", diagnostics)
	}
}

func TestVerifiedAPIKeyCacheIsBounded(t *testing.T) {
	var cache verifiedAPIKeyCache
	for index := 0; index < localAdmissionShards*localAdmissionEntriesPerShard*2; index++ {
		cache.put(fmt.Sprintf("key-%d", index), &APIKeyClaims{KeyID: fmt.Sprintf("id-%d", index)})
	}
	if entries := cache.entryCount(); entries > localAdmissionShards*localAdmissionEntriesPerShard {
		t.Fatalf("cache retained %d entries", entries)
	}
}

func TestVerifiedAPIKeyCacheSupportsConcurrentAccess(t *testing.T) {
	var cache verifiedAPIKeyCache
	var workers sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for index := 0; index < 500; index++ {
				key := fmt.Sprintf("key-%d-%d", worker, index%64)
				cache.put(key, &APIKeyClaims{KeyID: key})
				if claims, ok := cache.get(key); ok && claims.KeyID != key {
					t.Errorf("claims for %s = %#v", key, claims)
				}
			}
		}(worker)
	}
	workers.Wait()
}

func TestParseVerifiedAPIKeyCachesOnlyValidClaims(t *testing.T) {
	secret := "test-api-key-pepper"
	rawKey := testSignedAPIKey(
		t,
		secret,
		"019de515-eabf-7c0e-89bd-400629a79580",
		"019de516-7df8-71d6-80e4-3c62090d4e94",
		"019de516-b10f-786f-97f8-b95c71dfe1b6",
		"",
		apiKeyVersion)
	service := &Service{apiKeyPepper: secret}
	for attempt := 0; attempt < 2; attempt++ {
		if _, _, _, err := service.parseVerifiedAPIKey(rawKey); err != nil {
			t.Fatalf("valid key attempt %d failed: %v", attempt+1, err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, _, _, err := service.parseVerifiedAPIKey(rawKey + "invalid"); err == nil {
			t.Fatalf("invalid key attempt %d succeeded", attempt+1)
		}
	}
	if _, _, _, err := service.parseVerifiedAPIKey(strings.Repeat("x", 1<<20)); err == nil {
		t.Fatal("oversized key succeeded")
	}
	cacheKey := "api:" + hashAPIKey(rawKey, secret)
	shard := &service.apiKeys.shards[localAdmissionShard(cacheKey)]
	shard.mu.Lock()
	_, cachedByHash := shard.entries[cacheKey]
	_, cachedByRawSecret := shard.entries[rawKey]
	shard.mu.Unlock()
	if !cachedByHash || cachedByRawSecret {
		t.Fatalf("cache key storage: hash=%t raw=%t", cachedByHash, cachedByRawSecret)
	}
	diagnostics := service.localAdmissionDiagnostics()
	if diagnostics.APIKeyCacheEntries != 1 || diagnostics.APIKeyCacheHits != 1 || diagnostics.APIKeyCacheLookups != 2 {
		t.Fatalf("API key cache diagnostics = %#v", diagnostics)
	}
}

func TestLocalRequestLimiterBoundsBurstAndRefills(t *testing.T) {
	var limiter localRequestLimiter
	limit := credentialRequestLimit
	now := time.Unix(1_700_000_000, 0)

	for index := range int(limit.burst) {
		if retryAfter := limiter.allow("key", now, limit); retryAfter != 0 {
			t.Fatalf("request %d was rejected for %s", index+1, retryAfter)
		}
	}
	if retryAfter := limiter.allow("key", now, limit); retryAfter != time.Second/time.Duration(limit.ratePerSecond)+1 {
		t.Fatalf("request beyond burst waits %s", retryAfter)
	}
	limiter.refund("key", limit)
	if retryAfter := limiter.allow("key", now, limit); retryAfter != 0 {
		t.Fatalf("refunded request was rejected for %s", retryAfter)
	}
	if retryAfter := limiter.allow("key", now.Add(time.Second), limit); retryAfter != 0 {
		t.Fatalf("refilled request was rejected for %s", retryAfter)
	}
	diagnostics := limiter.diagnostics(limit)
	if diagnostics.Attempts != uint64(limit.burst)+3 || diagnostics.Rejected != 1 || diagnostics.LastRejectedAt == nil {
		t.Fatalf("request admission diagnostics = %#v", diagnostics)
	}
}

func TestAuthorizationActivityTracksBurstAndReleasesOnce(t *testing.T) {
	var service Service
	finishes := make([]func(), 32)
	for i := range finishes {
		finishes[i] = service.authorizations.start()
	}
	stats := service.localAdmissionDiagnostics()
	if stats.AuthorizationInFlight != 32 || stats.AuthorizationPeakInFlight != 32 {
		t.Fatalf("burst was not tracked: %+v", stats)
	}
	var workers sync.WaitGroup
	for _, finish := range finishes {
		for range 2 {
			workers.Go(finish)
		}
	}
	workers.Wait()
	stats = service.localAdmissionDiagnostics()
	if stats.AuthorizationInFlight != 0 || stats.AuthorizationAttempts != 32 {
		t.Fatalf("duplicate completion corrupted activity: %+v", stats)
	}
}

// Authorizations that arrive while their organization's statement runs share
// the next one, in arrival order. A busy organization runs the same batch
// again before later arrivals.
func TestOrganizationQueueRunsInOrder(t *testing.T) {
	var queues organizationQueues
	pending := make([]*pendingAuthorization, maxAuthorizationBatch+6)
	var queue *organizationQueue
	for i := range pending {
		pending[i] = &pendingAuthorization{}
		var created bool
		if queue, created = queues.join("org", pending[i]); created != (i == 0) {
			t.Fatalf("authorization %d created a queue: %t", i, created)
		}
	}
	if waits := queues.waits.Load(); waits != uint64(len(pending)-1) {
		t.Fatalf("waits = %d", waits)
	}
	first := queue.take(maxAuthorizationBatch)
	if !slices.Equal(first, pending[:maxAuthorizationBatch]) {
		t.Fatal("the first batch is not the first arrivals in order")
	}
	if left := queue.putBack(first, false); len(left) != 0 {
		t.Fatalf("%d authorizations left without their callers leaving", len(left))
	}
	if again := queue.take(maxAuthorizationBatch); !slices.Equal(again, first) {
		t.Fatal("a busy batch lost its place")
	}
	if rest := queue.take(maxAuthorizationBatch); !slices.Equal(rest, pending[maxAuthorizationBatch:]) {
		t.Fatal("later arrivals ran out of order")
	}
	if _, _, ok := queue.next(time.Now()); ok {
		t.Fatal("an empty queue stayed")
	}
	if _, created := queues.join("org", &pendingAuthorization{}); !created {
		t.Fatal("a removed queue took new work")
	}
}

// A move runs alone, and so does each authorization of a batch that
// PostgreSQL rolled back, so one bad request fails by itself.
func TestOrganizationQueueRunsMovesAndFailedBatchesAlone(t *testing.T) {
	var queues organizationQueues
	first, move, second, third := &pendingAuthorization{}, &pendingAuthorization{alone: true}, &pendingAuthorization{}, &pendingAuthorization{}
	var queue *organizationQueue
	for _, p := range []*pendingAuthorization{first, move, second, third} {
		queue, _ = queues.join("org", p)
	}
	for _, want := range [][]*pendingAuthorization{{first}, {move}, {second, third}} {
		if got := queue.take(maxAuthorizationBatch); !slices.Equal(got, want) {
			t.Fatalf("took %d authorizations, want %d", len(got), len(want))
		}
	}
	queue.putBack([]*pendingAuthorization{second, third}, true)
	for _, want := range []*pendingAuthorization{second, third} {
		if got := queue.take(maxAuthorizationBatch); !slices.Equal(got, []*pendingAuthorization{want}) {
			t.Fatal("a failed batch ran together again")
		}
	}
}

// An authorization leaves its queue when its caller stops waiting, unless a
// statement has it. Then it gets the statement's answer, or the reason its
// caller left when the statement returns it unanswered.
func TestOrganizationQueueLetsWaitingAuthorizationsLeave(t *testing.T) {
	now := time.Now()
	var queues organizationQueues
	running := &pendingAuthorization{waitUntil: now.Add(time.Second)}
	waiting := &pendingAuthorization{waitUntil: now.Add(time.Second)}
	expired := &pendingAuthorization{waitUntil: now}
	queue, _ := queues.join("org", running)
	for _, p := range []*pendingAuthorization{waiting, expired} {
		queues.join("org", p)
	}
	queue.take(1)
	if !queue.leave(waiting, context.Canceled) {
		t.Fatal("a waiting authorization could not leave")
	}
	if queue.leave(running, context.DeadlineExceeded) {
		t.Fatal("an authorization left its statement")
	}
	gone, latest, ok := queue.next(now)
	if !slices.Equal(gone, []*pendingAuthorization{expired}) || !latest.IsZero() || ok {
		t.Fatalf("next = %d expired, latest %s, waiting %t", len(gone), latest, ok)
	}
	// The statement found the organization busy after its caller left.
	if left := queue.putBack([]*pendingAuthorization{running}, false); !slices.Equal(left, []*pendingAuthorization{running}) || !errors.Is(running.left, context.DeadlineExceeded) {
		t.Fatal("an authorization whose caller left was queued again")
	}
}

func TestStaleConfigurationIsServiceUnavailable(t *testing.T) {
	err := authorizationResultError("config_stale", nil)
	if !strings.Contains(err.Error(), ErrAPIKeyConfigStale.Error()) || ErrorStatus(err) != 503 {
		t.Fatalf("stale configuration error = %v, status = %d", err, ErrorStatus(err))
	}
}

func TestSharedPolicyDeclinesPreserveScopeStatus(t *testing.T) {
	for _, item := range []struct {
		result  string
		status  int
		message string
	}{
		{"organization_rate_limited", 429, "Organization request rate limit exceeded"},
		{"grant_rate_limited", 429, "Grant request rate limit exceeded"},
		{"key_token_limit", 429, "API key token limit exceeded"},
		{"organization_token_limit", 429, "Organization token limit exceeded"},
		{"grant_token_limit", 429, "Grant token limit exceeded"},
		{"key_concurrency_limit", 429, "API key concurrent-request limit exceeded"},
		{"organization_concurrency_limit", 429, "Organization concurrent-request limit exceeded"},
		{"grant_concurrency_limit", 429, "Grant concurrent-request limit exceeded"},
		{"organization_spend_limit", 402, "Organization spend limit exceeded"},
		{"grant_spend_limit", 402, "Grant spend limit exceeded"},
	} {
		err := authorizationResultError(item.result, nil)
		if ErrorStatus(err) != item.status || err.Error() != item.message {
			t.Fatalf("decline = %v, status = %d", err, ErrorStatus(err))
		}
	}
}

func TestParseAPIKeyRejectsFailuresBeforeDatabaseAndBodyWork(t *testing.T) {
	const secret = "test-api-key-pepper"
	raw := testSignedAPIKey(t, secret, "019de515-eabf-7c0e-89bd-400629a79580",
		"019de516-7df8-71d6-80e4-3c62090d4e94",
		"019de516-b10f-786f-97f8-b95c71dfe1b6", "", apiKeyVersion)
	service := &Service{apiKeyPepper: secret}
	claims, err := service.ParseAPIKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	service.RecordRefusal(claims, nil, ErrInsufficientBalance.Code)
	if _, err := service.ParseAPIKey(raw); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("failure did not block early: %v", err)
	}
}

func TestLocalRequestLimiterIsBounded(t *testing.T) {
	var limiter localRequestLimiter
	now := time.Unix(1_700_000_000, 0)
	for index := 0; index < localAdmissionShards*localAdmissionEntriesPerShard*2; index++ {
		limiter.allow(string(rune(index+1)), now, credentialRequestLimit)
	}
	total := 0
	for index := range limiter.shards {
		total += len(limiter.shards[index].entries)
	}
	if total > localAdmissionShards*localAdmissionEntriesPerShard {
		t.Fatalf("limiter retained %d entries", total)
	}
}

func TestLocalRateOutOfOrderArrivalDoesNotMintTokens(t *testing.T) {
	var limiter localRequestLimiter
	limit := organizationRequestLimit
	now := time.Unix(1700000000, 0)
	for range int(limit.burst) {
		if limiter.allow("org", now, limit) != 0 {
			t.Fatal("initial burst missing")
		}
	}
	if limiter.allow("org", now.Add(-time.Second), limit) <= 0 {
		t.Fatal("older arrival admitted")
	}
	if limiter.allow("org", now, limit) <= 0 {
		t.Fatal("older arrival minted refill credit")
	}
	if limiter.allow("org", now.Add(time.Second), limit) != 0 {
		t.Fatal("normal refill failed")
	}
}
