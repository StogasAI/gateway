package billing

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Measures the real cache insertion/eviction path. Empty policies isolate key
// overhead; diverse compiled policies have different estimate/heap ratios.
func BenchmarkKeyCacheFootprint(b *testing.B) {
	for _, shared := range []bool{true, false} {
		b.Run(fmt.Sprintf("shared-policy-%t", shared), func(b *testing.B) {
			for range b.N {
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				var cache keyConfigCache
				now := time.Now()
				for index := range keyConfigCacheBytes / keyConfigEntryBytes * 2 {
					digest := fmt.Sprintf("%064x", index)
					if shared {
						digest = fmt.Sprintf("%064x", 0)
					}
					cache.put(fmt.Sprintf("key-%064x", index), keyConfigSnapshot(1, digest), now)
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
				b.ReportMetric(float64(cache.bytes), "estimated-B")
				b.ReportMetric(float64(len(cache.entries)), "entries")
				runtime.KeepAlive(&cache)
				cache.close()
			}
		})
	}
}

func BenchmarkIdentityCacheFootprint(b *testing.B) {
	for range b.N {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		var keys verifiedAPIKeyCache
		var rates localRequestLimiter
		var failures callerFailureCache
		now := time.Now()
		for index := range localAdmissionShards * localAdmissionEntriesPerShard * 2 {
			id := fmt.Sprintf("%08x-1111-4111-8111-111111111111", index)
			org := fmt.Sprintf("%08x-2222-4222-8222-222222222222", index)
			user := fmt.Sprintf("%08x-3333-4333-8333-333333333333", index)
			grant := fmt.Sprintf("%08x-4444-4444-8444-444444444444", index)
			keys.put(fmt.Sprintf("api:%0128x", index), &APIKeyClaims{KeyID: id, OrganizationID: org, ResponsibleID: user, GrantID: &grant})
			rates.allow("org:"+org, now)
			failures.record("key:"+id, now)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
		b.ReportMetric(float64(keys.entryCount()), "keys")
		runtime.KeepAlive(&keys)
		runtime.KeepAlive(&rates)
		runtime.KeepAlive(&failures)
	}
}

func BenchmarkCompiledPolicyCacheFootprint(b *testing.B) {
	for range b.N {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		var cache keyConfigCache
		now := time.Now()
		// Reach steady eviction with distinct maximum-count literal dictionaries.
		// This is a retained-data case, not a bound on every legal policy shape.
		for index := 0; cache.evictions < 100; index++ {
			literals := make([]string, 1000)
			for literal := range literals {
				literals[literal] = fmt.Sprintf("%012x%012x", index, literal) + strings.Repeat("A", 40)
			}
			raw, err := json.Marshal(map[string]any{"plugins": map[string]any{"stogasRedaction": map[string]any{"literals": []map[string]any{{"values": literals}}}}})
			if err != nil {
				b.Fatal(err)
			}
			source, err := cache.acquireSource(raw, "org", nil)
			if err != nil {
				b.Fatal(err)
			}
			snapshot := cache.put(fmt.Sprint(index), &KeyConfigSnapshot{PolicySnapshot: PolicySnapshot{Config: source.value.Config, Digest: source.value.Digest, sourceRefs: []*sharedPolicySource{source}}, Generation: 1}, now)
			cache.releaseSources([]*sharedPolicySource{source})
			if _, err := snapshot.RedactionPolicy(); err != nil {
				b.Fatal(err)
			}
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
		b.ReportMetric(float64(cache.bytes), "estimated-B")
		b.ReportMetric(float64(len(cache.entries)), "entries")
		runtime.KeepAlive(&cache)
		cache.close()
	}
}
