//go:build linux

package stogashttp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"syscall"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
)

// An opt-in measurement process with the real HTTP, provider and database
// lifecycle. Budget variants and local diagnostics stay in the test binary.
// TLS is ordinary test TLS; this does not simulate confidential attestation.
func TestMemoryProfileServer(t *testing.T) {
	raw := os.Getenv("STOGAS_MEMORY_PROFILE")
	if raw == "" {
		t.Skip("opt-in runtime memory measurement")
	}
	var profile struct {
		GoBytes        int64 `json:"goBytes"`
		BudgetBytes    int64 `json:"budgetBytes"`
		CacheBytes     int   `json:"cacheBytes"`
		NativePressure bool  `json:"nativePressure"`
	}
	if err := json.Unmarshal([]byte(raw), &profile); err != nil || profile.GoBytes <= 0 || profile.BudgetBytes <= 0 {
		t.Fatal("invalid memory profile", err)
	}
	previous := debug.SetMemoryLimit(profile.GoBytes)
	defer debug.SetMemoryLimit(previous)
	config, err := stogas.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if config.Confidential.ControlConfigured() || !config.AllowPrivateProviderNetwork {
		t.Fatal("memory measurement requires an isolated local runtime")
	}
	server, err := New(context.Background(), config, bifrost.NewDefaultLogger(schemas.LogLevelError))
	if err != nil {
		t.Fatal(err)
	}
	// Use production drain ownership: completed client responses can still
	// have asynchronous finalization holding the request lease.
	defer server.shutdown()
	server.memory.budget = profile.BudgetBytes
	if err := server.memory.protectRequestMemory(config.MaxRequestBodyMiB * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	// Optional conservative memory pressure, separate from cache-shape tests.
	// Opaque Go ballast adds retained heap but no realistic cache scanning cost.
	// Anonymous mappings model every admitted native byte as resident; this
	// deliberately exceeds the measured ratchet allocator cost. They remain
	// pinned, so this does not claim idle-session reclamation or SNP coverage.
	if profile.CacheBytes < 0 || int64(profile.CacheBytes) >= profile.GoBytes {
		t.Fatal("invalid retained cache pressure")
	}
	cache := make([]byte, profile.CacheBytes)
	for offset := 0; offset < len(cache); offset += os.Getpagesize() {
		cache[offset] = 1
	}
	if profile.NativePressure {
		maximum := server.memory.budgetBytes() - server.memory.confidentialHeadroom
		bytes := int(maximum / encryptedSessionRetainedBytes * encryptedSessionRetainedBytes)
		lease := server.memory.newLease(confidentialStateMemory)
		if !lease.growWithin(bytes, maximum) {
			t.Fatal("native pressure admission failed")
		}
		defer lease.release()
		mapped, err := syscall.Mmap(-1, 0, bytes, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := syscall.Munmap(mapped); err != nil {
				t.Error(err)
			}
		}()
		for offset := 0; offset < len(mapped); offset += os.Getpagesize() {
			mapped[offset] = 1
		}
	}
	public := httptest.NewUnstartedServer(server.server.Handler)
	public.Config = server.server
	public.Listener = &publicListener{Listener: public.Listener, slots: make(chan struct{}, serverConcurrency), idle: &server.idleConnections}
	public.EnableHTTP2 = true
	public.StartTLS()
	defer public.Close()
	ready := httptest.NewServer(server.readinessServer.Handler)
	defer ready.Close()
	diagnostics := httptest.NewServer(server.diagnosticsServer.Handler)
	defer diagnostics.Close()
	addresses, err := json.Marshal(map[string]string{"gateway": public.URL, "readiness": ready.URL, "diagnostics": diagnostics.URL})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("STOGAS_MEMORY_PROFILE_READY=%s\n", addresses)
	stop := make(chan struct{})
	go func() {
		// Closing the controller's input terminates the measurement process.
		_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
		close(stop)
	}()
	select {
	case <-stop:
	case <-time.After(20 * time.Minute):
		t.Fatal("memory measurement controller timed out")
	}
	runtime.KeepAlive(cache)
}
