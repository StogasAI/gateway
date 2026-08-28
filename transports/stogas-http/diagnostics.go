package stogashttp

import (
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"github.com/valyala/fasthttp"
)

type privateNodeDiagnostics struct {
	Billing     billing.DiagnosticsSnapshot    `json:"billing"`
	ChutesE2EE  chutese2ee.DiagnosticsSnapshot `json:"chutesE2EE"`
	GeneratedAt time.Time                      `json:"generatedAt"`
	Listeners   listenerDiagnostics            `json:"listeners"`
	Process     processDiagnostics             `json:"process"`
	Requests    requestDiagnostics             `json:"requests"`
}

type listenerDiagnostics struct {
	Private serverListenerDiagnostics `json:"private"`
	Public  serverListenerDiagnostics `json:"public"`
}

type serverListenerDiagnostics struct {
	CurrentConnections  uint32 `json:"currentConnections"`
	MaximumConnections  int    `json:"maximumConnections"`
	OpenConnections     int32  `json:"openConnections"`
	RejectedConnections uint32 `json:"rejectedConnections"`
}

type processDiagnostics struct {
	GCCount                  uint32  `json:"gcCount"`
	GCCPUFraction            float64 `json:"gcCpuFraction"`
	GCPauseTotalMS           uint64  `json:"gcPauseTotalMs"`
	GoManagedBytes           uint64  `json:"goManagedBytes"`
	GoMemoryLimitBytes       int64   `json:"goMemoryLimitBytes"`
	GOMAXPROCS               int     `json:"gomaxprocs"`
	Goroutines               int     `json:"goroutines"`
	HeapAllocBytes           uint64  `json:"heapAllocBytes"`
	HeapInUseBytes           uint64  `json:"heapInUseBytes"`
	HeapReleasedBytes        uint64  `json:"heapReleasedBytes"`
	HeapSystemBytes          uint64  `json:"heapSystemBytes"`
	HostMemoryAvailableBytes uint64  `json:"hostMemoryAvailableBytes,omitempty"`
	HostMemoryTotalBytes     uint64  `json:"hostMemoryTotalBytes,omitempty"`
	Load1                    float64 `json:"load1,omitempty"`
	Load5                    float64 `json:"load5,omitempty"`
	Load15                   float64 `json:"load15,omitempty"`
	NumCPU                   int     `json:"numCpu"`
	OpenFileDescriptors      int     `json:"openFileDescriptors,omitempty"`
	ResidentBytes            uint64  `json:"residentBytes,omitempty"`
	StackInUseBytes          uint64  `json:"stackInUseBytes"`
	SystemBytes              uint64  `json:"systemBytes"`
	UptimeSeconds            int64   `json:"uptimeSeconds,omitempty"`
}

type requestDiagnostics struct {
	Drain  requestDrainDiagnostics  `json:"drain"`
	Memory requestMemoryDiagnostics `json:"memory"`
}

func (s *Server) privateDiagnostics() privateNodeDiagnostics {
	result := privateNodeDiagnostics{GeneratedAt: time.Now().UTC()}
	if s == nil {
		result.Process = currentProcessDiagnostics(time.Time{})
		return result
	}
	result.Process = currentProcessDiagnostics(s.startedAt)
	result.Listeners = listenerDiagnostics{
		Private: currentListenerDiagnostics(s.readinessServer, readinessConcurrency),
		Public:  currentListenerDiagnostics(s.server, serverConcurrency),
	}
	result.Requests = requestDiagnostics{
		Drain:  s.requests.diagnostics(),
		Memory: s.memory.diagnostics(),
	}
	if s.runtime != nil {
		result.Billing = s.runtime.BillingDiagnostics()
		result.ChutesE2EE = s.runtime.ChutesE2EEDiagnostics()
	}
	return result
}

func currentListenerDiagnostics(server *fasthttp.Server, defaultMaximum int) serverListenerDiagnostics {
	result := serverListenerDiagnostics{MaximumConnections: defaultMaximum}
	if server == nil {
		return result
	}
	if server.Concurrency > 0 {
		result.MaximumConnections = server.Concurrency
	}
	result.CurrentConnections = server.GetCurrentConcurrency()
	result.OpenConnections = max(0, server.GetOpenConnectionsCount())
	result.RejectedConnections = server.GetRejectedConnectionsCount()
	return result
}

func currentProcessDiagnostics(startedAt time.Time) processDiagnostics {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	totalMemory, availableMemory := linuxHostMemory()
	load1, load5, load15 := linuxLoadAverage()
	uptime := int64(0)
	if !startedAt.IsZero() {
		uptime = max(0, int64(time.Since(startedAt).Seconds()))
	}
	goManagedBytes := memory.Sys
	if memory.HeapReleased <= goManagedBytes {
		goManagedBytes -= memory.HeapReleased
	} else {
		goManagedBytes = 0
	}
	return processDiagnostics{
		GCCount:                  memory.NumGC,
		GCCPUFraction:            memory.GCCPUFraction,
		GCPauseTotalMS:           memory.PauseTotalNs / uint64(time.Millisecond),
		GoManagedBytes:           goManagedBytes,
		GoMemoryLimitBytes:       debug.SetMemoryLimit(-1),
		GOMAXPROCS:               runtime.GOMAXPROCS(0),
		Goroutines:               runtime.NumGoroutine(),
		HeapAllocBytes:           memory.HeapAlloc,
		HeapInUseBytes:           memory.HeapInuse,
		HeapReleasedBytes:        memory.HeapReleased,
		HeapSystemBytes:          memory.HeapSys,
		HostMemoryAvailableBytes: availableMemory,
		HostMemoryTotalBytes:     totalMemory,
		Load1:                    load1,
		Load5:                    load5,
		Load15:                   load15,
		NumCPU:                   runtime.NumCPU(),
		OpenFileDescriptors:      linuxOpenFileDescriptors(),
		ResidentBytes:            linuxResidentBytes(),
		StackInUseBytes:          memory.StackInuse,
		SystemBytes:              memory.Sys,
		UptimeSeconds:            uptime,
	}
}

func linuxResidentBytes() uint64 {
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

func linuxHostMemory() (uint64, uint64) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		if key != "MemTotal" && key != "MemAvailable" {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr == nil {
			values[key] = value * 1024
		}
	}
	return values["MemTotal"], values["MemAvailable"]
}

func linuxLoadAverage() (float64, float64, float64) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	load1, _ := strconv.ParseFloat(fields[0], 64)
	load5, _ := strconv.ParseFloat(fields[1], 64)
	load15, _ := strconv.ParseFloat(fields[2], 64)
	return load1, load5, load15
}

func linuxOpenFileDescriptors() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}
