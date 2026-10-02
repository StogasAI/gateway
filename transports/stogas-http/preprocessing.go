package stogashttp

import (
	"math/bits"
	"sync"
	"time"
)

// Each work phase keeps only aggregate counters. No request values or labels
// survive completion. Snapshotting copies fixed storage under the same lock.
type requestWorkActivity struct {
	mu            sync.Mutex
	stats         requestWorkDiagnostics
	totalWallTime time.Duration
}

type requestWorkDiagnostics struct {
	Active                int        `json:"active"`
	Peak                  int        `json:"peak"`
	Completed             uint64     `json:"completed"`
	InputBytes            uint64     `json:"inputBytes"`
	TotalWallTimeMicros   uint64     `json:"totalWallTimeMicros"`
	MaxWallTimeMicros     uint64     `json:"maxWallTimeMicros"`
	InputBytesBuckets     [65]uint64 `json:"inputBytesBuckets"`
	WallTimeMicrosBuckets [65]uint64 `json:"wallTimeMicrosBuckets"`
}

func (a *requestWorkActivity) start() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.Active++
	a.stats.Peak = max(a.stats.Peak, a.stats.Active)
}

func (a *requestWorkActivity) finish(elapsed time.Duration, inputBytes uint64) {
	micros := uint64(max(0, elapsed.Microseconds()))
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.Active--
	a.stats.Completed++
	a.stats.InputBytes += inputBytes
	a.totalWallTime += max(0, elapsed)
	a.stats.MaxWallTimeMicros = max(a.stats.MaxWallTimeMicros, micros)
	// Disjoint buckets: zero, then [2^(i-1), 2^i) for i=1..64.
	// This covers every uint64 without workload-specific bounds or overflow.
	a.stats.InputBytesBuckets[bits.Len64(inputBytes)]++
	a.stats.WallTimeMicrosBuckets[bits.Len64(micros)]++
}

func (a *requestWorkActivity) diagnostics() requestWorkDiagnostics {
	a.mu.Lock()
	defer a.mu.Unlock()
	stats := a.stats
	stats.TotalWallTimeMicros = uint64(a.totalWallTime.Microseconds())
	return stats
}

func (a *requestWorkActivity) begin(inputBytes int) func() {
	started := time.Now()
	a.start()
	return sync.OnceFunc(func() { a.finish(time.Since(started), uint64(max(0, inputBytes))) })
}
