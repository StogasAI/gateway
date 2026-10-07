package stogashttp

import (
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/azureauth"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter"
	"net"
	"net/http"
	"sync/atomic"
)

type privateNodeDiagnostics struct {
	Exports                exporter.Diagnostics           `json:"exports"`
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
	CPUTimeMicros             *uint64  `json:"cpuTimeMicros,omitempty"`
	AllocatedBytes            uint64   `json:"allocatedBytes"`
	Allocations               uint64   `json:"allocations"`
	GCCount                   uint32   `json:"gcCount"`
	GoCPUCapacitySeconds      *float64 `json:"goCPUCapacitySeconds,omitempty"`
	GoGCCPUSeconds            *float64 `json:"goGCCPUSeconds,omitempty"`
	GoGCIdleCPUSeconds        *float64 `json:"goGCIdleCPUSeconds,omitempty"`
	GCLimiterLastEnabledCycle *uint64  `json:"gcLimiterLastEnabledCycle,omitempty"`
	GCPercent                 *int64   `json:"gcPercent,omitempty"`
	HeapLiveBytes             *uint64  `json:"heapLiveBytes,omitempty"`
	HeapGoalBytes             *uint64  `json:"heapGoalBytes,omitempty"`
	HostMemorySomeStallMicros *uint64  `json:"hostMemorySomeStallMicros,omitempty"`
	HostMemoryFullStallMicros *uint64  `json:"hostMemoryFullStallMicros,omitempty"`
	GCPauseTotalMS            uint64   `json:"gcPauseTotalMs"`
	GoManagedBytes            uint64   `json:"goManagedBytes"`
	GoMemoryLimitBytes        int64    `json:"goMemoryLimitBytes"`
	GOMAXPROCS                int      `json:"gomaxprocs"`
	Goroutines                int      `json:"goroutines"`
	HeapAllocBytes            uint64   `json:"heapAllocBytes"`
	HeapUnusedBytes           uint64   `json:"heapUnusedBytes"`
	HeapFreeBytes             uint64   `json:"heapFreeBytes"`
	HeapReleasedBytes         uint64   `json:"heapReleasedBytes"`
	HostMemoryAvailableBytes  uint64   `json:"hostMemoryAvailableBytes,omitempty"`
	HostMemoryTotalBytes      uint64   `json:"hostMemoryTotalBytes,omitempty"`
	Load1                     float64  `json:"load1,omitempty"`
	Load5                     float64  `json:"load5,omitempty"`
	Load15                    float64  `json:"load15,omitempty"`
	NumCPU                    int      `json:"numCpu"`
	OpenFileDescriptors       int      `json:"openFileDescriptors,omitempty"`
	ResidentBytes             uint64   `json:"residentBytes,omitempty"`
	StackSystemBytes          uint64   `json:"stackSystemBytes"`
	RuntimeMetadataBytes      uint64   `json:"runtimeMetadataBytes"`
	UptimeSeconds             int64    `json:"uptimeSeconds,omitempty"`
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
	result.Exports = s.exports.Diagnostics()
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
	result := processDiagnostics{
		CPUTimeMicros:            processCPUTimeMicros(),
		AllocatedBytes:           memory.TotalAlloc,
		Allocations:              memory.Mallocs,
		GCCount:                  memory.NumGC,
		GCPauseTotalMS:           memory.PauseTotalNs / uint64(time.Millisecond),
		GoManagedBytes:           goManagedBytes,
		GoMemoryLimitBytes:       debug.SetMemoryLimit(-1),
		GOMAXPROCS:               runtime.GOMAXPROCS(0),
		Goroutines:               runtime.NumGoroutine(),
		HeapAllocBytes:           memory.HeapAlloc,
		HeapUnusedBytes:          memory.HeapInuse - memory.HeapAlloc,
		HeapFreeBytes:            memory.HeapIdle - memory.HeapReleased,
		HeapReleasedBytes:        memory.HeapReleased,
		HostMemoryAvailableBytes: availableMemory,
		HostMemoryTotalBytes:     totalMemory,
		Load1:                    load1,
		Load5:                    load5,
		Load15:                   load15,
		NumCPU:                   runtime.NumCPU(),
		OpenFileDescriptors:      linuxOpenFileDescriptors(),
		ResidentBytes:            linuxResidentBytes(),
		StackSystemBytes:         memory.StackSys,
		RuntimeMetadataBytes:     memory.MSpanSys + memory.MCacheSys + memory.BuckHashSys + memory.GCSys + memory.OtherSys,
		UptimeSeconds:            uptime,
	}
	// Runtime CPU classes are estimates of Go processor capacity, not OS CPU
	// time. Preserve their common denominator for interval GC fractions. A
	// missing metric is omitted; zero means supported but no activity.
	samples := []metrics.Sample{
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/cpu/classes/gc/total:cpu-seconds"},
		{Name: "/cpu/classes/gc/mark/idle:cpu-seconds"},
		{Name: "/gc/limiter/last-enabled:gc-cycle"},
		{Name: "/gc/gogc:percent"},
		{Name: "/gc/heap/live:bytes"},
		{Name: "/gc/heap/goal:bytes"},
	}
	metrics.Read(samples)
	for index, target := range []**float64{&result.GoCPUCapacitySeconds, &result.GoGCCPUSeconds, &result.GoGCIdleCPUSeconds} {
		if value := samples[index].Value; value.Kind() == metrics.KindFloat64 {
			seconds := value.Float64()
			*target = &seconds
		}
	}
	if value := samples[3].Value; value.Kind() == metrics.KindUint64 {
		cycle := value.Uint64()
		result.GCLimiterLastEnabledCycle = &cycle
	}
	if value := samples[4].Value; value.Kind() == metrics.KindUint64 {
		// The runtime represents GOGC=off as MaxUint64. Preserve the
		// conventional -1 without emitting an unsafe JavaScript integer.
		percent := int64(value.Uint64())
		result.GCPercent = &percent
	}
	for index, target := range []**uint64{&result.HeapLiveBytes, &result.HeapGoalBytes} {
		if value := samples[index+5].Value; value.Kind() == metrics.KindUint64 {
			bytes := value.Uint64()
			*target = &bytes
		}
	}
	if raw, err := os.ReadFile("/proc/pressure/memory"); err == nil {
		result.HostMemorySomeStallMicros, result.HostMemoryFullStallMicros = parseMemoryPressure(string(raw))
	}
	return result
}

// Cumulative PSI totals allow consumers to choose their observation interval.
// /proc reports the whole guest, not a container or this process alone.
// Missing or malformed measurements remain absent, including on non-Linux.
func parseMemoryPressure(raw string) (some, full *uint64) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || (fields[0] != "some" && fields[0] != "full") {
			continue
		}
		for _, field := range fields[1:] {
			text, ok := strings.CutPrefix(field, "total=")
			if !ok {
				continue
			}
			value, err := strconv.ParseUint(text, 10, 64)
			if err == nil {
				if fields[0] == "some" {
					some = &value
				} else {
					full = &value
				}
			}
			break
		}
	}
	return
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
