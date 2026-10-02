package billing

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

func matcherSnapshot(digest, literal string) *KeyConfigSnapshot {
	return &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Digest: digest, Config: &policy.Config{
		Plugins: &policy.Plugins{StogasRedaction: &policy.Redaction{Presets: []string{},
			Literals: []redaction.Literal{{Text: literal, Fuzzy: true}}}},
	}}, Generation: 1,
	}
}

func TestKeyCacheSharesPoliciesAndMatchersUntilLastReference(t *testing.T) {
	var cache keyConfigCache
	now := time.Now()
	first := cache.put("a", matcherSnapshot("policy-a", "ProjectAurora"), now)
	second := cache.put("b", matcherSnapshot("policy-a", "ProjectAurora"), now.Add(time.Second))
	third := cache.put("c", matcherSnapshot("policy-b", "ProjectAurora"), now.Add(2*time.Second))
	if first.Config != second.Config || first.Config == third.Config || first.matchers[0] != third.matchers[0] {
		t.Fatal("policy and matcher content identities were not shared independently")
	}
	compiled, err := first.RedactionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			for range 20 {
				got, err := second.RedactionPolicy()
				if err != nil || got != compiled {
					t.Errorf("warm plan not shared: %v", err)
				}
			}
		})
	}
	workers.Wait()
	cache.remove("a")
	if len(cache.policies) != 2 || len(cache.plans) != 1 {
		t.Fatal("removal released an object still referenced by another key")
	}
	if retained, fresh := cache.get("b", now.Add(keyConfigCacheTTL+time.Second)); retained != second || fresh {
		t.Fatal("stale data was lost or treated as fresh")
	}
	cache.remove("b")
	if len(cache.policies) != 1 || len(cache.plans) != 1 {
		t.Fatal("expiry did not release only the unreferenced policy")
	}
	cache.remove("c")
	if cache.bytes != 0 || cache.entries != nil || cache.policies != nil || cache.plans != nil {
		t.Fatal("last expiry retained cached data")
	}
	// Active requests may finish after every cache reference has disappeared.
	raw := map[string]json.RawMessage{"input": json.RawMessage(`"ProjectAruora"`)}
	if err := redaction.NewWithPolicy(compiled).RedactRequestFields(raw, redaction.SurfaceResponses, nil); err != nil || string(raw["input"]) != `"<CUSTOM_PII>"` {
		t.Fatalf("expiry invalidated an active plan: %s %v", raw["input"], err)
	}
	if got, err := first.RedactionPolicy(); err != nil || got != compiled || cache.bytes != 0 {
		t.Fatal("active snapshot repopulated the cache")
	}
}

func TestKeyCacheSharedObjectsCountOnceAndOldestEvicts(t *testing.T) {
	var cache keyConfigCache
	now := time.Now()
	for i := range 5000 {
		cache.put(fmt.Sprint(i), matcherSnapshot("shared", "ProjectAurora"), now)
	}
	stats := cache.diagnostics()
	if stats.Entries != 5000 || stats.SharedPolicies != 1 || len(cache.plans) != 1 || stats.EstimatedBytes > keyConfigCacheBytes {
		t.Fatalf("shared policies hit a count cap or duplicate accounting: %+v", stats)
	}
	large := matcherSnapshot("large", "DifferentProject")
	large.cacheBytes = keyConfigCacheBytes - 2*keyConfigEntryBytes
	active := cache.put("large", large, now.Add(time.Second))
	if cache.entries["large"] == nil || cache.entries["0"] != nil || cache.bytes > keyConfigCacheBytes || cache.evictions == 0 {
		t.Fatal("capacity eviction did not preserve the newest entry")
	}
	// Compiling a plan also consumes the shared budget.
	if _, err := active.RedactionPolicy(); err != nil || cache.bytes > keyConfigCacheBytes {
		t.Fatalf("lazy compilation escaped the budget: %v", err)
	}
	oversize := matcherSnapshot("oversize", "AnotherProject")
	oversize.cacheBytes = keyConfigCacheBytes + 1
	uncached := cache.put("oversize", oversize, now.Add(2*time.Second))
	if cache.bytes != 0 || len(cache.entries) != 0 {
		t.Fatal("an oversized snapshot retained cache references")
	}
	if _, err := uncached.RedactionPolicy(); err != nil || cache.bytes != 0 {
		t.Fatal("late compilation repopulated an evicted snapshot")
	}
}

func TestKeyCacheReplacementPreservesPlanAndGeneration(t *testing.T) {
	var cache keyConfigCache
	now := time.Now()
	first := cache.put("a", matcherSnapshot("same", "ProjectAurora"), now)
	compiled, err := first.RedactionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	next := matcherSnapshot("same", "ProjectAurora")
	next.Generation = 2
	replacement := cache.put("a", next, now.Add(time.Second))
	older := cache.put("a", first, now.Add(2*time.Second))
	if replacement.matchers[0] != first.matchers[0] || older != replacement || replacement.Config != first.Config {
		t.Fatal("replacement lost sharing or allowed a generation regression")
	}
	if got, err := replacement.RedactionPolicy(); err != nil || got != compiled {
		t.Fatal("unchanged replacement rebuilt the matcher")
	}
	cache.remove("a")
	if cache.bytes != 0 || len(cache.plans) != 0 || len(cache.policies) != 0 {
		t.Fatal("replacement leaked a reference")
	}
}

func TestRedactionBuildFailureBusyAndIndependentPlans(t *testing.T) {
	var cache keyConfigCache
	now := time.Now()
	first := cache.put("a", matcherSnapshot("a", "ProjectAurora"), now)
	first.matchers[0].building = true
	if _, err := first.RedactionPolicy(); err != ErrGatewayUnavailable {
		t.Fatalf("duplicate build queued: %v", err)
	}
	bad := matcherSnapshot("bad", "ProjectAurora")
	bad.Config.Plugins.StogasRedaction.CustomPatterns = []string{"("}
	bad = cache.put("bad", bad, now)
	if _, err := bad.RedactionPolicy(); err == nil || err == ErrGatewayUnavailable || bad.matchers[0].building {
		t.Fatalf("independent invalid plan was not validated/cleared: %v", err)
	}
	first.matchers[0].building = false
	if _, err := first.RedactionPolicy(); err != nil {
		t.Fatal(err)
	}
	stats := cache.redactionDiagnostics()
	if stats.Builds != 2 || stats.BuildFailures != 1 || stats.Busy != 1 || stats.Building != 0 || stats.BuildMaxMicros > stats.BuildTotalMicros {
		t.Fatalf("incorrect compilation diagnostics: %+v", stats)
	}
}

func TestKeyCacheConcurrentBuildEvictionAndClose(t *testing.T) {
	var cache keyConfigCache
	var workers sync.WaitGroup
	// Exercise eviction below the cold-build capacity. Saturation legitimately
	// returns ErrGatewayUnavailable and has its own capacity/recovery test.
	for i := range min(32, runtime.GOMAXPROCS(0)) {
		workers.Go(func() {
			key := fmt.Sprint(i)
			for range 10 {
				snapshot := cache.put(key, matcherSnapshot(key, "Project"+strings.Repeat("x", i%32+8)), time.Now())
				cache.remove(key)
				if _, err := snapshot.RedactionPolicy(); err != nil {
					t.Errorf("active request could not finish after eviction: %v", err)
				}
			}
		})
	}
	workers.Wait()
	cache.close()
	cache.close()
	snapshot := cache.put("after-close", matcherSnapshot("closed", "ProjectAurora"), time.Now())
	if cache.bytes != 0 || len(cache.entries) != 0 || snapshot == nil {
		t.Fatal("shutdown retained or accepted cache references")
	}
}

func TestKeyCacheRefreshRetainsMatcherAndRejectsStaleAuthority(t *testing.T) {
	var cache keyConfigCache
	defer cache.close()
	now := time.Now()
	first := cache.put("key", matcherSnapshot("policy", "ProjectAurora"), now)
	compiled, err := first.RedactionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	stale, fresh := cache.get("key", now.Add(keyConfigCacheTTL))
	if stale != first || fresh {
		t.Fatal("freshness expiry lost the cached plan or remained authorized")
	}
	if !cache.confirm("key", first, false, now, now) {
		t.Fatal("change did not request refresh")
	}
	cache.confirm("key", first, true, now.Add(time.Minute), now.Add(time.Minute))
	if _, fresh := cache.get("key", now.Add(time.Minute)); fresh {
		t.Fatal("a delayed matching check revived an invalidated snapshot")
	}
	next := cache.put("key", matcherSnapshot("policy", "ProjectAurora"), now.Add(time.Minute))
	got, err := next.RedactionPolicy()
	if err != nil || got != compiled {
		t.Fatal("refresh rebuilt an unchanged matcher")
	}
	if stats := cache.redactionDiagnostics(); stats.Builds != 1 {
		t.Fatalf("refresh compilation count: %+v", stats)
	}
}

func TestColdMatcherCapacityDoesNotBlockWarmPolicies(t *testing.T) {
	var cache keyConfigCache
	warm := cache.put("warm", matcherSnapshot("warm", "ProjectAurora"), time.Now())
	ready, err := warm.RedactionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	cold := cache.put("cold", matcherSnapshot("cold", "AnotherProject"), time.Now())
	cache.planStats.Building = runtime.GOMAXPROCS(0)
	if got, err := warm.RedactionPolicy(); err != nil || got != ready {
		t.Fatal("warm policy blocked by cold compilation", err)
	}
	if _, err := cold.RedactionPolicy(); err != ErrGatewayUnavailable {
		t.Fatal("cold capacity was not enforced", err)
	}
	if cold.matchers[0].building {
		t.Fatal("rejected build retained a slot")
	}
	cache.planStats.Building = 0
	if _, err := cold.RedactionPolicy(); err != nil {
		t.Fatal("capacity did not recover", err)
	}
	cache.close()
}
