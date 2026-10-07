package chutese2ee

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These opt-in benchmarks measure retained Go heap at cache capacity through
// the real insertion paths. They exclude transient verification/network memory
// and use GC only to distinguish reachable cache data from discarded inputs.
func BenchmarkCacheFootprint(b *testing.B) {
	b.Run("tickets", func(b *testing.B) {
		for range b.N {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			state := newPoolState(nil, nil, &diagnostics{})
			now := time.Now()
			for targetIndex := range maximumPoolTargets {
				target := ModelTarget{ChuteID: fmt.Sprintf("%08x-1111-4111-8111-111111111111", targetIndex), GPUCount: testGPUCount}
				instances := make([]discoveredInstance, maximumDiscoveredInstances)
				state.verified[target.ChuteID] = make(map[string]verifiedInstance)
				for instanceIndex := range instances {
					id := fmt.Sprintf("%08x-2222-4222-8222-%012x", targetIndex, instanceIndex)
					key := fmt.Sprintf("%016x", targetIndex*maximumDiscoveredInstances+instanceIndex) + strings.Repeat("A", 1564)
					instances[instanceIndex] = discoveredInstance{ID: id, PublicKey: key}
					state.storeVerifiedLocked(target.ChuteID, id, verifiedInstance{InstanceID: id, PublicKey: key, GPUCount: testGPUCount, ValidUntil: now.Add(time.Minute)})
				}
				for ticketIndex := range maximumPooledTicketsPerTarget {
					instance := &instances[ticketIndex%len(instances)]
					instance.Tickets = append(instance.Tickets, fmt.Sprintf("%016x%016x", targetIndex, ticketIndex))
				}
				if !state.install(target, instances, now.Add(time.Minute)) {
					b.Fatal("ticket installation failed")
				}
				for range maximumTrackedTicketTakes {
					state.activity[target.ChuteID].Takes = append(state.activity[target.ChuteID].Takes, now)
				}
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
			b.ReportMetric(float64(state.diagnostics.poolTargets.Load()), "targets")
			runtime.KeepAlive(state)
			state.close()
		}
	})
	b.Run("observed-attestation", func(b *testing.B) {
		for range b.N {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			a := &attestor{observed: make(map[string]map[string]observedAttestationInstance), refresh: make(map[string]*attestationRefreshState)}
			for targetIndex := range maximumDiagnosticChutes {
				target := ModelTarget{ChuteID: fmt.Sprintf("%08x-1111-4111-8111-111111111111", targetIndex), GPUCount: testGPUCount}
				for instanceIndex := range maximumObservedInstancesPerChute {
					id := fmt.Sprintf("%08x-2222-4222-8222-%012x", targetIndex, instanceIndex)
					key := fmt.Sprintf("%016x", targetIndex*maximumObservedInstancesPerChute+instanceIndex) + strings.Repeat("A", 1564)
					a.observe(target, []discoveredInstance{{ID: id, PublicKey: key}})
				}
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
			b.ReportMetric(float64(len(a.observed)*maximumObservedInstancesPerChute), "instances")
			runtime.KeepAlive(a)
		}
	})
	b.Run("collateral", func(b *testing.B) {
		for range b.N {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			getter := newCollateralGetter()
			now := time.Now()
			for index := range maxCollateralEntries {
				body := make([]byte, maxCollateralSize)
				for offset := 0; offset < len(body); offset += 4096 {
					body[offset] = byte(index + 1)
				}
				getter.store(fmt.Sprintf("https://api.trustedservices.intel.com/fixture/%d", index), collateralEntry{body: body, expiresAt: now.Add(collateralCacheTTL)}, now)
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
			b.ReportMetric(float64(len(getter.cache)), "entries")
			runtime.KeepAlive(getter)
			getter.close()
		}
	})
}
