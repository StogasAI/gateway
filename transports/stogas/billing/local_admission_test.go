package billing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
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
				s.callerFailures.record("key:"+claims.KeyID, time.Now().Add(time.Hour))
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

func TestOrganizationAbuseLimitIsSharedByKeysAndDashboard(t *testing.T) {
	const secret = "test-api-key-pepper"
	org := "019de516-7df8-71d6-80e4-3c62090d4e94"
	key := func(id, organization string) string {
		return testSignedAPIKey(t, secret, id, organization, "019de516-b10f-786f-97f8-b95c71dfe1b6", "", apiKeyVersion)
	}
	first := key("019de515-eabf-7c0e-89bd-400629a79580", org)
	second := key("019de515-eabf-7c0e-89bd-400629a79581", org)
	other := key("019de515-eabf-7c0e-89bd-400629a79582", "019de516-7df8-71d6-80e4-3c62090d4e95")
	service := &Service{apiKeyPepper: secret}
	if _, err := service.ParseAPIKey(first); err != nil {
		t.Fatal(err)
	}
	identity := "org:" + org
	shard := &service.localRequests.shards[localAdmissionShard(identity)]
	if len(shard.entries) != 1 {
		t.Fatal("request was not attributed to its signed organization")
	}
	// Fix the bucket in the future to avoid a timing-dependent refill in race tests.
	shard.entries[identity] = localRequestEntry{updatedAt: time.Now().Add(time.Hour)}
	if _, err := service.ParseAPIKey(second); !errors.Is(err, ErrAbuseRateLimit) {
		t.Fatalf("another key escaped the organization's bucket: %v", err)
	}
	if _, err := service.ParseAPIKey(other); err != nil {
		t.Fatalf("one organization blocked another: %v", err)
	}
	credential := &DashboardCredential{ActorUserID: "actor", SessionID: "session", KeyID: "key"}
	snapshot := keyConfigSnapshot(1, strings.Repeat("a", 64))
	snapshot.Claims = &APIKeyClaims{OrganizationID: org}
	service.keyConfigs.put(dashboardConfigCacheKey(credential), snapshot, time.Now())
	shard.entries[identity] = localRequestEntry{updatedAt: time.Now().Add(time.Hour)}
	if _, err := service.ConfigForDashboard(context.Background(), credential, nil); !errors.Is(err, ErrAbuseRateLimit) {
		t.Fatalf("dashboard escaped the organization's bucket: %v", err)
	}
	before := service.localRequests.attempts.Load()
	if _, err := service.ParseAPIKey(first + "invalid"); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatal("accepted forged organization claim")
	}
	if service.localRequests.attempts.Load() != before {
		t.Fatal("unauthenticated key consumed an organization's allowance")
	}
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
	var cache verifiedAPIKeyCache
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
	if diagnostics := localAdmissionDiagnostics(nil, nil, nil, &cache); diagnostics.APIKeyCacheEntries != 1 || diagnostics.APIKeyCacheHits != 2 || diagnostics.APIKeyCacheLookups != 2 {
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
	cacheKey := apiKeyRejectionCacheKey(rawKey, secret)
	shard := &service.apiKeys.shards[localAdmissionShard(cacheKey)]
	shard.mu.Lock()
	_, cachedByHash := shard.entries[cacheKey]
	_, cachedByRawSecret := shard.entries[rawKey]
	shard.mu.Unlock()
	if !cachedByHash || cachedByRawSecret {
		t.Fatalf("cache key storage: hash=%t raw=%t", cachedByHash, cachedByRawSecret)
	}
	diagnostics := localAdmissionDiagnostics(nil, nil, nil, &service.apiKeys)
	if diagnostics.APIKeyCacheEntries != 1 || diagnostics.APIKeyCacheHits != 1 || diagnostics.APIKeyCacheLookups != 2 {
		t.Fatalf("API key cache diagnostics = %#v", diagnostics)
	}
}

func TestLocalRequestLimiterBoundsBurstAndRefills(t *testing.T) {
	var limiter localRequestLimiter
	now := time.Unix(1_700_000_000, 0)

	for index := 0; index < localRequestBurst; index++ {
		if retryAfter := limiter.allow("key", now); retryAfter != 0 {
			t.Fatalf("request %d was rejected for %s", index+1, retryAfter)
		}
	}
	if retryAfter := limiter.allow("key", now); retryAfter <= 0 {
		t.Fatal("request beyond burst was accepted")
	}
	if retryAfter := limiter.allow("key", now.Add(time.Second)); retryAfter != 0 {
		t.Fatalf("refilled request was rejected for %s", retryAfter)
	}
	diagnostics := localAdmissionDiagnostics(&limiter, nil, nil, nil)
	if diagnostics.RequestAttempts != localRequestBurst+2 ||
		diagnostics.RequestRejected != 1 ||
		diagnostics.RequestLastRejectedAt == nil {
		t.Fatalf("request admission diagnostics = %#v", diagnostics)
	}
}

func TestAuthorizationActivityTracksBurstAndReleasesOnce(t *testing.T) {
	var activity authorizationActivity
	finishes := make([]func(), 32)
	for i := range finishes {
		finishes[i] = activity.start()
	}
	stats := localAdmissionDiagnostics(nil, &activity, nil, nil)
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
	stats = localAdmissionDiagnostics(nil, &activity, nil, nil)
	if stats.AuthorizationInFlight != 0 || stats.AuthorizationAttempts != 32 {
		t.Fatalf("duplicate completion corrupted activity: %+v", stats)
	}
}

func TestCallerFailuresBackOffDecayAndDoNotExtendOnLookup(t *testing.T) {
	var cache callerFailureCache
	now := time.Unix(1_700_000_000, 0)
	for i := range 16 {
		cache.record("key", now)
		want := min(25*time.Millisecond*time.Duration(1<<i), 2*time.Second)
		if got := cache.get("key", now); got != want {
			t.Fatalf("failure %d: delay %s, want %s", i, got, want)
		}
		for range 100 {
			cache.get("key", now.Add(want/2))
		}
		if got := cache.get("key", now.Add(want)); got != 0 {
			t.Fatal("lookup extended the cooldown")
		}
	}
	now = now.Add(2 * time.Second)
	cache.record("key", now)
	if got := cache.get("key", now); got != 25*time.Millisecond {
		t.Fatalf("elapsed cooldown did not reset backoff: %s", got)
	}
	if cache.get("other", now) != 0 {
		t.Fatal("unrelated identity was limited")
	}
}

func TestCallerFailuresIncludeInfrastructureButExcludeCancellationAndBackoff(t *testing.T) {
	claims := &APIKeyClaims{KeyID: "key", OrganizationID: "org"}
	for _, status := range []int{200, 201, 204, 400, 401, 402, 403, 404, 408, 409, 413, 415, 422, 429, 499, 500, 502, 503, 504} {
		service := &Service{}
		service.RecordCallerFailure(claims, nil, status, "test")
		got := service.callerBackoff(claims, nil, time.Now()) != nil
		want := status >= 400 && status != 408 && status != 499
		if got != want {
			t.Errorf("status %d: backoff = %t, want %t", status, got, want)
		}
	}
	service := &Service{}
	service.RecordCallerFailure(claims, nil, 429, ErrAbuseRateLimit.Code)
	service.RecordCallerFailure(nil, nil, 400, "invalid_request")
	if service.callerBackoff(claims, nil, time.Now()) != nil {
		t.Fatal("unattributed or backoff rejection recorded another failure")
	}
}

func TestRequestSuccessEndsOnlyEarlierFailureStreaks(t *testing.T) {
	service := &Service{}
	dashboard := &DashboardCredential{ActorUserID: "actor", SessionID: "session"}
	now := time.Unix(1_700_000_000, 0)
	identities := []string{"key:key", dashboardAdmissionKey(dashboard)}
	for _, identity := range identities {
		for range 8 {
			service.callerFailures.record(identity, now)
		}
	}
	service.recordRequestSuccess("key", dashboardAdmissionKey(dashboard), now.Add(-time.Second))
	for _, identity := range identities {
		if service.callerFailures.get(identity, now) != 2*time.Second {
			t.Fatal("an older in-flight success erased a newer failure")
		}
	}
	service.recordRequestSuccess("key", dashboardAdmissionKey(dashboard), now.Add(3*time.Second))
	for _, identity := range identities {
		if service.callerFailures.get(identity, now) != 0 {
			t.Fatal("success retained an earlier cooldown")
		}
		service.callerFailures.record(identity, now.Add(4*time.Second))
		if service.callerFailures.get(identity, now.Add(4*time.Second)) != 25*time.Millisecond {
			t.Fatal("isolated failures accumulated across a success")
		}
	}
}

func TestCallerFailuresIsolateSiblingKeysAndDashboardActors(t *testing.T) {
	service := &Service{}
	claims := &APIKeyClaims{KeyID: "key-a", OrganizationID: "org-a"}
	service.RecordCallerFailure(claims, nil, 402, "insufficient_balance")
	now := time.Now()
	for _, item := range []struct {
		claims  *APIKeyClaims
		blocked bool
	}{
		{claims, true},
		{&APIKeyClaims{KeyID: "key-b", OrganizationID: "org-a"}, false},
		{&APIKeyClaims{KeyID: "key-a", OrganizationID: "org-b"}, true},
		{&APIKeyClaims{KeyID: "key-b", OrganizationID: "org-b"}, false},
	} {
		if got := service.callerBackoff(item.claims, nil, now) != nil; got != item.blocked {
			t.Fatalf("claims %+v: blocked = %t", item.claims, got)
		}
	}
	dashboard := &DashboardCredential{ActorUserID: "actor", SessionID: "session", KeyID: "untrusted-target"}
	service.RecordCallerFailure(nil, dashboard, 403, "dashboard_key_denied")
	dashboard.KeyID = "rotated-target"
	if service.callerBackoff(nil, dashboard, now) == nil {
		t.Fatal("changing the selected dashboard key bypassed actor backoff")
	}
	if service.callerBackoff(&APIKeyClaims{KeyID: "untrusted-target", OrganizationID: "org-c"}, nil, now) != nil {
		t.Fatal("unauthorized dashboard target was charged")
	}
}

func TestTerminalProviderFailuresBackOffWithoutRelabelingTheEvent(t *testing.T) {
	s := &Service{}
	claims := &APIKeyClaims{KeyID: "key", OrganizationID: "org"}
	a := &Authorization{KeyID: "key", OrganizationID: "org", admissionStartedAt: time.Now().Add(-time.Second), dashboardAdmissionIdentity: "dashboard:test"}
	event := RequestEvent{ProviderAttempts: []ProviderAttempt{{Status: "provider_error"}}}
	for range 8 {
		s.recordRequestOutcome(a, event)
	}
	if s.callerBackoff(claims, nil, time.Now()) == nil {
		t.Fatal("provider outage did not suppress repeated holds")
	}
	if event.GatewayError != nil {
		t.Fatal("provider outcome changed Stogas lifecycle classification")
	}
	success := RequestEvent{ProviderAttempts: []ProviderAttempt{{Status: "success"}}}
	s.recordRequestOutcome(a, success)
	if s.callerBackoff(claims, nil, time.Now()) == nil {
		t.Fatal("late success erased a newer failure")
	}
	a.admissionStartedAt = time.Now().Add(time.Second)
	s.recordRequestOutcome(a, success)
	if s.callerBackoff(claims, nil, time.Now()) != nil || s.callerFailures.get("dashboard:test", time.Now()) != 0 {
		t.Fatal("successful probe did not restore admission")
	}
	event.Cancelled = true
	s.recordRequestOutcome(a, event)
	if s.callerBackoff(claims, nil, time.Now()) != nil {
		t.Fatal("client cancellation penalized admission")
	}
}

func TestStaleConfigurationIsServiceUnavailable(t *testing.T) {
	err := authorizationResultError("config_stale")
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
		err := authorizationResultError(item.result)
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
	service.RecordCallerFailure(claims, nil, 402, "insufficient_balance")
	if _, err := service.ParseAPIKey(raw); !errors.Is(err, ErrAbuseRateLimit) {
		t.Fatalf("failure did not block early: %v", err)
	}
}

func TestLocalRequestLimiterIsBounded(t *testing.T) {
	var limiter localRequestLimiter
	now := time.Unix(1_700_000_000, 0)
	for index := 0; index < localAdmissionShards*localAdmissionEntriesPerShard*2; index++ {
		limiter.allow(string(rune(index+1)), now)
	}
	total := 0
	for index := range limiter.shards {
		total += len(limiter.shards[index].entries)
	}
	if total > localAdmissionShards*localAdmissionEntriesPerShard {
		t.Fatalf("limiter retained %d entries", total)
	}
}
