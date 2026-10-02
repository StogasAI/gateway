package stogashttp

import (
	"errors"
	"hash/maphash"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ipRequestRate              = 1000
	ipRequestBurst             = 2000
	ipSetupRate                = 100
	ipSetupBurst               = 200
	ipAdmissionShards          = 64
	ipAdmissionEntriesPerShard = 512
	ipFullRefillInterval       = time.Duration(max(ipRequestBurst/ipRequestRate, ipSetupBurst/ipSetupRate)) * time.Second
)

var errIPAdmission = errors.New("client IP admission unavailable")

type ipBudget struct {
	tokens  float64
	updated time.Time
}

func (b *ipBudget) take(now time.Time, rate, burst int) time.Duration {
	if b.updated.IsZero() {
		b.tokens, b.updated = float64(burst), now
	}
	if now.After(b.updated) {
		b.tokens = math.Min(float64(burst), b.tokens+now.Sub(b.updated).Seconds()*float64(rate))
		b.updated = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	return time.Duration(math.Ceil((1 - b.tokens) / float64(rate) * float64(time.Second)))
}

type ipAdmissionEntry struct{ request, setup ipBudget }
type ipAdmissionShard struct {
	sync.Mutex
	entries map[netip.Addr]ipAdmissionEntry
}
type ipAdmissionCounters struct {
	attempts, rejected atomic.Uint64
	lastRejected       atomic.Int64
}
type ipAdmission struct {
	seed             maphash.Seed
	shards           [ipAdmissionShards]ipAdmissionShard
	request, setup   ipAdmissionCounters
	capacityRejected atomic.Uint64
}

func newIPAdmission() *ipAdmission { return &ipAdmission{seed: maphash.MakeSeed()} }

// RemoteAddr comes from the accepted connection. Confidential ingress requires
// PROXYv2 before TLS on its restricted network; HTTP headers never select a key.
func (l *ipAdmission) allow(remote string, setup bool, now time.Time) (time.Duration, error) {
	if l == nil {
		return 0, nil
	}
	peer, err := netip.ParseAddrPort(remote)
	if err != nil || peer.Addr().Zone() != "" {
		return 0, errIPAdmission
	}
	ip := peer.Addr().Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() {
		return 0, errIPAdmission
	}
	counters := &l.request
	if setup {
		counters = &l.setup
	}
	counters.attempts.Add(1)
	shard := &l.shards[maphash.Comparable(l.seed, ip)%ipAdmissionShards]
	shard.Lock()
	defer shard.Unlock()
	entry, found := shard.entries[ip]
	if !found {
		if shard.entries == nil {
			shard.entries = make(map[netip.Addr]ipAdmissionEntry)
		}
		if len(shard.entries) >= ipAdmissionEntriesPerShard {
			// Replacing only fully refilled entries cannot reset a depleted
			// allowance. Scan at most one bounded shard, without timers.
			for key, value := range shard.entries {
				if now.Sub(value.request.updated) >= ipFullRefillInterval && now.Sub(value.setup.updated) >= ipFullRefillInterval {
					delete(shard.entries, key)
				}
			}
			if len(shard.entries) >= ipAdmissionEntriesPerShard {
				l.capacityRejected.Add(1)
				return time.Second, errIPAdmission
			}
		}
	}
	var wait time.Duration
	if setup {
		wait = entry.setup.take(now, ipSetupRate, ipSetupBurst)
	} else {
		wait = entry.request.take(now, ipRequestRate, ipRequestBurst)
	}
	shard.entries[ip] = entry
	if wait > 0 {
		counters.rejected.Add(1)
		counters.lastRejected.Store(now.UnixMilli())
	}
	return wait, nil
}

func (s *Server) ipRequestAdmission(next requestHandler) requestHandler {
	return func(ctx *requestContext) {
		if s.admitIP(ctx, false) {
			next(ctx)
		}
	}
}

func (s *Server) admitIP(ctx *requestContext, setup bool) bool {
	wait, err := s.ipAdmission.allow(ctx.request.RemoteAddr, setup, time.Now())
	if err == nil && wait == 0 {
		return true
	}
	closeUnreadRequest(ctx)
	ctx.writer.Header().Set("Cache-Control", "no-store")
	ctx.writer.Header().Set("Access-Control-Allow-Origin", "*")
	ctx.writer.Header().Set("Access-Control-Expose-Headers", "Retry-After")
	status, code, kind, message := http.StatusTooManyRequests, "ip_rate_limit_exceeded", "rate_limit_error", "Client network request limit reached"
	if err != nil {
		status, code, kind, message = http.StatusServiceUnavailable, "ip_admission_unavailable", "service_unavailable", "Gateway client admission is temporarily unavailable"
	}
	ctx.writer.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
	s.writeError(ctx, status, map[string]any{"error": map[string]any{"type": kind, "code": code, "message": message}})
	return false
}

type ipBudgetDiagnostics struct {
	RatePerSecond  int        `json:"ratePerSecond"`
	Burst          int        `json:"burst"`
	Attempts       uint64     `json:"attempts"`
	Rejected       uint64     `json:"rejected"`
	LastRejectedAt *time.Time `json:"lastRejectedAt,omitempty"`
}
type ipAdmissionDiagnostics struct {
	Entries          int                 `json:"entries"`
	MaximumEntries   int                 `json:"maximumEntries"`
	CapacityRejected uint64              `json:"capacityRejected"`
	Request          ipBudgetDiagnostics `json:"request"`
	Setup            ipBudgetDiagnostics `json:"setup"`
}

func (l *ipAdmission) diagnostics() ipAdmissionDiagnostics {
	result := ipAdmissionDiagnostics{MaximumEntries: ipAdmissionShards * ipAdmissionEntriesPerShard,
		Request: ipBudgetDiagnostics{RatePerSecond: ipRequestRate, Burst: ipRequestBurst},
		Setup:   ipBudgetDiagnostics{RatePerSecond: ipSetupRate, Burst: ipSetupBurst}}
	if l == nil {
		return result
	}
	for i := range l.shards {
		shard := &l.shards[i]
		shard.Lock()
		result.Entries += len(shard.entries)
		shard.Unlock()
	}
	result.CapacityRejected = l.capacityRejected.Load()
	for _, item := range []struct {
		source *ipAdmissionCounters
		target *ipBudgetDiagnostics
	}{{&l.request, &result.Request}, {&l.setup, &result.Setup}} {
		item.target.Attempts, item.target.Rejected = item.source.attempts.Load(), item.source.rejected.Load()
		if value := item.source.lastRejected.Load(); value != 0 {
			timestamp := time.UnixMilli(value).UTC()
			item.target.LastRejectedAt = &timestamp
		}
	}
	return result
}
