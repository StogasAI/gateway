package billing

import (
	"testing"
	"time"
)

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
}

func TestLocalAuthorizationLimiterBoundsPerKeyConcurrency(t *testing.T) {
	var limiter localAuthorizationLimiter
	releases := make([]func(), 0, localAuthorizationConcurrency)
	for index := 0; index < localAuthorizationConcurrency; index++ {
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
