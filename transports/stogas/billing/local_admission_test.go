package billing

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVerifiedAPIKeyCacheCopiesClaims(t *testing.T) {
	expectedGrantID := "019de516-c9ac-79cf-b701-4cf1b21f0a8c"
	grantID := expectedGrantID
	claims := &APIKeyClaims{
		FormatVersion:  apiKeyVersion,
		GrantID:        &grantID,
		KeyID:          "019de515-eabf-7c0e-89bd-400629a79580",
		OrganizationID: "019de516-7df8-71d6-80e4-3c62090d4e94",
		ResponsibleID:  "019de516-b10f-786f-97f8-b95c71dfe1b6",
		WorkspaceID:    "019de516-9c1b-7061-a9f0-bbdcaa8946e5",
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
		"019de516-9c1b-7061-a9f0-bbdcaa8946e5",
		"019de516-b10f-786f-97f8-b95c71dfe1b6",
		"",
		apiKeyVersion,
	)
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

func TestLocalAuthorizationLimitFollowsDatabasePool(t *testing.T) {
	tests := []struct {
		poolMaxConns int32
		want         int32
	}{
		{poolMaxConns: -1, want: 0},
		{poolMaxConns: 0, want: 0},
		{poolMaxConns: 1, want: 1},
		{poolMaxConns: 4, want: 1},
		{poolMaxConns: 5, want: 2},
		{poolMaxConns: 6, want: 2},
		{poolMaxConns: 12, want: 3},
		{poolMaxConns: 32, want: 8},
	}
	for _, test := range tests {
		if got := localAuthorizationLimit(test.poolMaxConns); got != test.want {
			t.Errorf("localAuthorizationLimit(%d) = %d, want %d", test.poolMaxConns, got, test.want)
		}
	}
}

func TestLocalAuthorizationLimiterBoundsPerIdentityConcurrency(t *testing.T) {
	limiter := newLocalAuthorizationLimiter(6)
	limit := int(limiter.limit)
	releases := make([]func(), 0, limit)
	for index := 0; index < limit; index++ {
		release, ok := limiter.acquire("key")
		if !ok {
			t.Fatalf("authorization %d was rejected", index+1)
		}
		releases = append(releases, release)
	}
	if release, ok := limiter.acquire("key"); ok || release != nil {
		t.Fatal("authorization beyond concurrency limit was accepted")
	}
	if release, ok := limiter.acquire("other-key"); !ok || release == nil {
		t.Fatal("one key blocked another key")
	} else {
		release()
	}
	releases[0]()
	if release, ok := limiter.acquire("key"); !ok || release == nil {
		t.Fatal("released capacity was not reusable")
	} else {
		release()
	}
	for _, release := range releases[1:] {
		release()
	}
	diagnostics := localAdmissionDiagnostics(nil, limiter, nil, nil)
	if diagnostics.AuthorizationConcurrencyLimitPerIdentity != 2 ||
		diagnostics.AuthorizationAttempts != 5 ||
		diagnostics.AuthorizationRejected != 1 ||
		diagnostics.AuthorizationLastRejectedAt == nil ||
		diagnostics.AuthorizationInFlight != 0 ||
		diagnostics.AuthorizationActiveIdentities != 0 ||
		diagnostics.AuthorizationPeakInFlight != 3 {
		t.Fatalf("authorization admission diagnostics = %#v", diagnostics)
	}
}

func TestAuthorizationRejectionCacheBacksOffAndClears(t *testing.T) {
	var cache authorizationRejectionCache
	now := time.Unix(1_700_000_000, 0)
	cache.record("key", "key_rate_limited", now)

	result, retryAfter, ok := cache.get("key", now)
	if !ok || result != "key_rate_limited" || retryAfter != 25*time.Millisecond {
		t.Fatalf("first rejection = %q, %s, %t", result, retryAfter, ok)
	}
	if _, _, ok := cache.get("key", now.Add(25*time.Millisecond)); ok {
		t.Fatal("expired rejection remained active")
	}

	cache.record("key", "key_rate_limited", now.Add(25*time.Millisecond))
	_, retryAfter, ok = cache.get("key", now.Add(25*time.Millisecond))
	if !ok || retryAfter != 50*time.Millisecond {
		t.Fatalf("second rejection delay = %s, active = %t", retryAfter, ok)
	}

	cache.clear("key")
	if _, _, ok := cache.get("key", now.Add(25*time.Millisecond)); ok {
		t.Fatal("cleared rejection remained active")
	}
}

func TestAuthorizationRejectionCacheIgnoresRequestAndInfrastructureErrors(t *testing.T) {
	var cache authorizationRejectionCache
	now := time.Unix(1_700_000_000, 0)
	for _, result := range []string{"params_mismatch", "invalid_amount", "usage_exists"} {
		cache.record("key", result, now)
		if _, _, ok := cache.get("key", now); ok {
			t.Fatalf("%s was cached", result)
		}
	}
}

func TestParseAPIKeyReturnsCachedAuthoritativeDecline(t *testing.T) {
	secret := "test-api-key-pepper"
	rawKey := testSignedAPIKey(
		t,
		secret,
		"019de515-eabf-7c0e-89bd-400629a79580",
		"019de516-7df8-71d6-80e4-3c62090d4e94",
		"019de516-9c1b-7061-a9f0-bbdcaa8946e5",
		"019de516-b10f-786f-97f8-b95c71dfe1b6",
		"",
		apiKeyVersion,
	)
	service := &Service{apiKeyPepper: secret}
	service.rejections.record(
		apiKeyRejectionCacheKey(rawKey, secret),
		"insufficient_balance",
		time.Now(),
	)

	if _, err := service.ParseAPIKey(rawKey); err == nil {
		t.Fatal("cached decline was not returned")
	} else if ErrorStatus(err) != 402 {
		t.Fatalf("cached decline status = %d", ErrorStatus(err))
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
