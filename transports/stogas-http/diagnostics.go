package stogashttp

import (
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"net"
	"net/http"
	"sync/atomic"
)

type privateNodeDiagnostics struct {
	OmittedOperationalLogs int                            `json:"omittedOperationalLogs"`
	OmittedChutes          int                            `json:"omittedChutes"`
	DetailsUnavailable     bool                           `json:"detailsUnavailable"`
	HTTPServerErrors       uint64                         `json:"httpServerErrors"`
	OperationalLogs        []stogas.OperationalLogSeries  `json:"operationalLogs"`
	AzureAuth              azureauth.Diagnostics          `json:"azureAuth"`
	Billing                billing.DiagnosticsSnapshot    `json:"billing"`
	ChutesE2EE             chutese2ee.DiagnosticsSnapshot `json:"chutesE2EE"`
	GeneratedAt            time.Time                      `json:"generatedAt"`
	Listeners              listenerDiagnostics            `json:"listeners"`
	Process                processDiagnostics             `json:"process"`
	Requests               requestDiagnostics             `json:"requests"`
}

type listenerDiagnostics struct {
	Private     serverListenerDiagnostics `json:"private"`
	Public      serverListenerDiagnostics `json:"public"`
	Diagnostics serverListenerDiagnostics `json:"diagnostics"`
}

type serverListenerDiagnostics struct {
	AcceptedConnections uint64 `json:"acceptedConnections"`
	MaximumConnections  int    `json:"maximumConnections"`
	OpenConnections     int32  `json:"openConnections"`
	ActiveHandlers      int64  `json:"activeHandlers"`
	IdleEvictions       uint64 `json:"idleEvictions"`
	CapacityRejected    uint64 `json:"capacityRejected"`
}

type processDiagnostics struct {
	CPUTimeMicros            *uint64 `json:"cpuTimeMicros,omitempty"`
	AllocatedBytes           uint64  `json:"allocatedBytes"`
	Allocations              uint64  `json:"allocations"`
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
	IPAdmission   ipAdmissionDiagnostics      `json:"ipAdmission"`
	Admission     requestAdmissionDiagnostics `json:"admission"`
	Drain         requestDrainDiagnostics     `json:"drain"`
	Memory        requestMemoryDiagnostics    `json:"memory"`
	JSONDecode    requestWorkDiagnostics      `json:"jsonDecode"`
	Preprocessing requestWorkDiagnostics      `json:"preprocessing"`
}

func (s *Server) privateDiagnostics() privateNodeDiagnostics {
	return s.privateDiagnosticsSnapshot(true)
}

func (s *Server) privateDiagnosticsSnapshot(details bool) privateNodeDiagnostics {
	result := privateNodeDiagnostics{GeneratedAt: time.Now().UTC(), DetailsUnavailable: !details}
	if details {
		result.OperationalLogs = stogas.OperationalLogDiagnostics()
	}
	if s == nil {
		result.Process = currentProcessDiagnostics(time.Time{})
		return boundPrivateDiagnostics(result)
	}
	result.Process = currentProcessDiagnostics(s.startedAt)
	if s.httpErrors != nil {
		result.HTTPServerErrors = s.httpErrors.errors.Load()
	}
	result.Listeners = listenerDiagnostics{
		Private:     s.privateConnections.snapshot(readinessConcurrency),
		Public:      s.publicConnections.snapshot(serverConcurrency),
		Diagnostics: s.diagnosticConnections.snapshot(readinessConcurrency),
	}
	s.idleConnections.mu.Lock()
	result.Listeners.Public.IdleEvictions = s.idleConnections.evicted
	result.Listeners.Public.CapacityRejected = s.idleConnections.rejected
	s.idleConnections.mu.Unlock()
	result.Requests = requestDiagnostics{
		IPAdmission:   s.ipAdmission.diagnostics(),
		Admission:     s.admission.diagnostics(),
		Drain:         s.requests.diagnostics(),
		Memory:        s.memory.diagnostics(),
		JSONDecode:    s.jsonDecode.diagnostics(),
		Preprocessing: s.preprocessing.diagnostics(),
	}
	if s.runtime != nil {
		result.AzureAuth = s.runtime.AzureAuthDiagnostics()
		result.Billing = s.runtime.BillingDiagnostics()
		if details {
			result.ChutesE2EE = s.runtime.ChutesE2EEDiagnostics()
		}
	}
	return boundPrivateDiagnostics(result)
}

type connectionCounters struct {
	open     atomic.Int32
	accepted atomic.Uint64
	handlers atomic.Int64
}

func (c *connectionCounters) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.handlers.Add(1)
		defer c.handlers.Add(-1)
		next.ServeHTTP(w, r)
	})
}

func (c *connectionCounters) observe(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		c.open.Add(1)
		c.accepted.Add(1)
	case http.StateClosed, http.StateHijacked:
		c.open.Add(-1)
	}
}

func (c *connectionCounters) snapshot(maximum int) serverListenerDiagnostics {
	count := max(0, c.open.Load())
	return serverListenerDiagnostics{MaximumConnections: maximum, OpenConnections: count, AcceptedConnections: c.accepted.Load(), ActiveHandlers: c.handlers.Load()}
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
		CPUTimeMicros:            processCPUTimeMicros(),
		AllocatedBytes:           memory.TotalAlloc,
		Allocations:              memory.Mallocs,
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

// RUSAGE_SELF includes user and kernel CPU time across every process thread.
// Omit unavailable measurements rather than reporting a misleading zero.
func processCPUTimeMicros() *uint64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return nil
	}
	micros := uint64(usage.Utime.Sec+usage.Stime.Sec)*1_000_000 + uint64(usage.Utime.Usec+usage.Stime.Usec)
	return &micros
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
	directory, err := os.Open("/proc/self/fd")
	if err != nil {
		return 0
	}
	defer directory.Close()
	count := 0
	for {
		names, err := directory.Readdirnames(128)
		count += len(names)
		if err == io.EOF {
			return count
		}
		if err != nil {
			return 0
		}
	}
}
