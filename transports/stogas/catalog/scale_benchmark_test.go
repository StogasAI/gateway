package catalog

import (
	"encoding/json"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"sort"
	"testing"
	"time"
)

// These synthetic variants measure catalog capacity, not provider availability.
func scaleCatalogBytes(b *testing.B, count int) []byte {
	b.Helper()
	var source compiledCatalog
	if err := json.Unmarshal(embeddedRuntimeCatalogJSON, &source); err != nil {
		b.Fatal(err)
	}
	ids := make([]string, 0, len(source.Graph.Deployments))
	for id := range source.Graph.Deployments {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	original := make(map[string]*compiledDeployment, len(ids))
	for _, id := range ids {
		original[id] = source.Graph.Deployments[id]
	}
	eligible := make([]string, 0, len(ids))
	for _, id := range ids {
		deployment := original[id]
		provider := source.Graph.Routes[sortedRouteIDs(deployment)[0]].ProviderID
		if _, ok := original[provider+"-"+deployment.ModelID]; ok {
			eligible = append(eligible, id)
		}
	}
	if len(eligible) == 0 {
		b.Fatal("no templates with an existing canonical base")
	}
	for n := len(ids); n < count; n++ {
		id := eligible[n%len(eligible)]
		source.Graph.Deployments[fmt.Sprintf("%s-bench-%06d", id, n)] = original[id]
	}
	data, err := json.Marshal(source)
	if err != nil {
		b.Fatal(err)
	}
	return data
}

func BenchmarkCatalogScaleDecode(b *testing.B) {
	for _, count := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			data := scaleCatalogBytes(b, count)
			for _, method := range []struct {
				name   string
				decode func([]byte) (compiledCatalog, error)
			}{
				{"standard", func(data []byte) (compiledCatalog, error) {
					var value compiledCatalog
					err := json.Unmarshal(data, &value)
					return value, err
				}},
				{"shared", decodeCompiledCatalog},
			} {
				b.Run(method.name, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(data)))
					// A second collection clears temporary encoder buffers from sync.Pool.
					runtime.GC()
					runtime.GC()
					var before runtime.MemStats
					runtime.ReadMemStats(&before)
					b.ResetTimer()
					var decoded compiledCatalog
					for n := 0; n < b.N; n++ {
						var err error
						decoded, err = method.decode(data)
						if err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
					b.ReportMetric(float64(len(data)), "catalog_bytes")
					runtime.GC()
					runtime.GC()
					var after runtime.MemStats
					runtime.ReadMemStats(&after)
					b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "retained_heap_bytes")
					runtime.KeepAlive(data)
					runtime.KeepAlive(decoded)
				})
			}
		})
	}
}

func BenchmarkCatalogScaleLoad(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			benchmarkCatalogLoad(b, scaleCatalogBytes(b, count))
		})
	}
}

// BenchmarkCatalogScaleDatedStates loads 10,000 deployments with dated states that each change one
// deployment, as an announced price change does.
func BenchmarkCatalogScaleDatedStates(b *testing.B) {
	for _, states := range []int{0, 8, 32} {
		b.Run(fmt.Sprint(states), func(b *testing.B) {
			var catalog compiledCatalog
			if err := json.Unmarshal(scaleCatalogBytes(b, 10000), &catalog); err != nil {
				b.Fatal(err)
			}
			ids := slices.Sorted(maps.Keys(catalog.Graph.Deployments))
			start := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
			for n := range states {
				catalog.Schedule = append(catalog.Schedule, scheduleEntry{
					Start: start.AddDate(0, 0, n),
					Graph: compiledGraph{Deployments: map[string]*compiledDeployment{ids[n]: catalog.Graph.Deployments[ids[n]]}},
				})
			}
			data, err := json.Marshal(catalog)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkCatalogLoad(b, data)
		})
	}
}

func benchmarkCatalogLoad(b *testing.B, data []byte) {
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	// A second collection clears temporary encoder buffers from sync.Pool.
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	b.ResetTimer()
	var decoded *snapshot
	for n := 0; n < b.N; n++ {
		var err error
		decoded, err = snapshotFromRelease(data, nil, nil, Identity{})
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(len(data)), "catalog_bytes")
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "retained_heap_bytes")
	runtime.KeepAlive(data)
	runtime.KeepAlive(decoded)
}

// Requests pin the release they resolved against, including both artifact
// bodies. Measure that ownership separately from load-time allocations.
func BenchmarkCatalogReleaseRetained(b *testing.B) {
	parts := embeddedParts(b)
	b.ReportAllocs()
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	b.ResetTimer()
	var release *snapshot
	for n := 0; n < b.N; n++ {
		var err error
		release, err = snapshotFromRelease(embeddedRuntimeCatalogJSON, embeddedPublicCatalogJSON, parts, Identity{})
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	b.ReportMetric(float64(len(embeddedRuntimeCatalogJSON)+len(embeddedPublicCatalogJSON)), "artifact_bytes")
	b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "retained_heap_bytes")
	runtime.KeepAlive(release)
}
