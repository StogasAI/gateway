//go:build linux

package stogashttp

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

type workerCostAccount struct{ workers int }

var workerCostProviders = []schemas.ModelProvider{schemas.OpenAI, schemas.Anthropic, schemas.Azure, schemas.Gemini}

func (workerCostAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return workerCostProviders, nil
}

func (workerCostAccount) GetKeysForProvider(context.Context, schemas.ModelProvider) ([]schemas.Key, error) {
	return []schemas.Key{{ID: "probe", Value: *schemas.NewSecretVar("probe"), Weight: 1}}, nil
}

func (a workerCostAccount) GetConfigForProvider(schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	return &schemas.ProviderConfig{
		ConcurrencyAndBufferSize: schemas.ConcurrencyAndBufferSize{Concurrency: a.workers, BufferSize: schemas.DefaultBufferSize},
		NetworkConfig:            schemas.DefaultNetworkConfig,
	}, nil
}

// An opt-in measurement of what idle provider workers cost: stack memory and
// the garbage collector's time scanning their stacks beside a live heap.
func TestProviderWorkerCost(t *testing.T) {
	raw := os.Getenv("STOGAS_PROVIDER_WORKERS")
	if raw == "" {
		t.Skip("opt-in provider worker measurement")
	}
	workers, err := strconv.Atoi(raw)
	if err != nil || workers <= 0 {
		t.Fatal("invalid worker count")
	}
	// A live heap of about 1 GiB in small pointer-holding objects, so each
	// collection also marks a realistic heap.
	type node struct {
		next    *node
		payload [112]byte
	}
	var head *node
	for range 8 << 20 {
		head = &node{next: head}
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	goroutines := runtime.NumGoroutine()
	client, err := bifrost.Init(context.Background(), schemas.BifrostConfig{Account: workerCostAccount{workers: workers}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown()
	time.Sleep(2 * time.Second)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// Idle mark workers use otherwise idle CPU, so they are reported apart.
	samples := []metrics.Sample{
		{Name: "/cpu/classes/gc/mark/dedicated:cpu-seconds"},
		{Name: "/cpu/classes/gc/mark/assist:cpu-seconds"},
		{Name: "/cpu/classes/gc/pause:cpu-seconds"},
		{Name: "/cpu/classes/gc/mark/idle:cpu-seconds"},
	}
	read := func() (busy, idle float64) {
		metrics.Read(samples)
		return samples[0].Value.Float64() + samples[1].Value.Float64() + samples[2].Value.Float64(), samples[3].Value.Float64()
	}
	busyBefore, idleBefore := read()
	const cycles = 20
	started := time.Now()
	for range cycles {
		runtime.GC()
	}
	wall := time.Since(started)
	busyAfter, idleAfter := read()
	runtime.KeepAlive(head)
	fmt.Printf("GOMAXPROCS=%d workers/provider=%d providers=%d goroutines=+%d stack=+%.1f MiB sys=+%.1f MiB gc/cycle: busy_cpu=%.1f ms idle_cpu=%.1f ms wall=%.1f ms\n",
		runtime.GOMAXPROCS(0), workers, len(workerCostProviders), runtime.NumGoroutine()-goroutines,
		float64(after.StackInuse-before.StackInuse)/(1<<20), float64(after.Sys-before.Sys)/(1<<20),
		(busyAfter-busyBefore)*1000/cycles, (idleAfter-idleBefore)*1000/cycles, float64(wall.Microseconds())/1000/cycles)
}
