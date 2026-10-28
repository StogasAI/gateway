package stogashttp

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
)

// providerReach tells the monitor when this gateway stops reaching providers:
// the providers whose calls went unanswered since a provider last answered.
// One provider's outage leaves the others answering, while a fault in this
// gateway's network, DNS or TLS leaves every provider unanswered.
type providerReach struct {
	mu         sync.Mutex
	unanswered uint64
	// Unix milliseconds, zero when unset. since is read without the lock, so
	// an answer costs one atomic load while providers answer.
	lastUnansweredAt int64
	since            atomic.Int64
	providers        map[schemas.ModelProvider]struct{}
}

type providerReachDiagnostics struct {
	Unanswered          uint64     `json:"unanswered"`
	LastUnansweredAt    *time.Time `json:"lastUnansweredAt,omitempty"`
	UnansweredSince     *time.Time `json:"unansweredSince,omitempty"`
	UnansweredProviders int        `json:"unansweredProviders"`
}

// observe records a provider call that returned. A call that failed to
// connect or timed out went unanswered. Any provider response, an error status
// included, is an answer. Cancellations and this gateway's own failures are
// neither.
func (p *providerReach) observe(provider schemas.ModelProvider, failure *schemas.BifrostError) {
	if failure == nil {
		p.answered()
		return
	}
	switch billing.NormalizeUpstreamStatus(failure) {
	case "connection_error", "timeout":
		p.unansweredCall(provider, time.Now())
	case "cancelled":
	default:
		if !failure.IsBifrostError && failure.StatusCode != nil {
			p.answered()
		}
	}
}

func (p *providerReach) answered() {
	if p.since.Load() == 0 {
		return
	}
	p.mu.Lock()
	p.since.Store(0)
	clear(p.providers)
	p.mu.Unlock()
}

func (p *providerReach) unansweredCall(provider schemas.ModelProvider, now time.Time) {
	at := now.UTC().UnixMilli()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unanswered++
	p.lastUnansweredAt = at
	p.since.CompareAndSwap(0, at)
	if p.providers == nil {
		p.providers = make(map[schemas.ModelProvider]struct{})
	}
	p.providers[provider] = struct{}{}
}

func (p *providerReach) diagnostics() providerReachDiagnostics {
	p.mu.Lock()
	defer p.mu.Unlock()
	return providerReachDiagnostics{
		Unanswered:          p.unanswered,
		LastUnansweredAt:    unixMillisecondsTime(p.lastUnansweredAt),
		UnansweredSince:     unixMillisecondsTime(p.since.Load()),
		UnansweredProviders: len(p.providers),
	}
}

func unixMillisecondsTime(value int64) *time.Time {
	if value <= 0 {
		return nil
	}
	at := time.UnixMilli(value).UTC()
	return &at
}

// providerCalls counts each provider's calls that hold or wait for one of
// core's workers. Past stogas.ProviderWorkers, calls queue in core, which no
// other limit shows: they hold little memory and use no CPU while they wait.
type providerCalls struct {
	mu      sync.Mutex
	running map[schemas.ModelProvider]int
	// The most calls one provider had at once, this minute and the last.
	minute         int64
	peak, previous providerCallPeak
}

type providerCallPeak struct {
	provider schemas.ModelProvider
	calls    int
}

type providerCallDiagnostics struct {
	Workers            int    `json:"workers"`
	RecentPeak         int    `json:"recentPeak"`
	RecentPeakProvider string `json:"recentPeakProvider,omitempty"`
}

// begin counts a call until the returned function runs.
func (p *providerCalls) begin(provider schemas.ModelProvider, now time.Time) func() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running == nil {
		p.running = make(map[schemas.ModelProvider]int)
	}
	p.running[provider]++
	p.advance(now)
	if calls := p.running[provider]; calls > p.peak.calls {
		p.peak = providerCallPeak{provider: provider, calls: calls}
	}
	return func() {
		p.mu.Lock()
		p.running[provider]--
		p.mu.Unlock()
	}
}

func (p *providerCalls) advance(now time.Time) {
	switch minute := now.Unix() / 60; minute {
	case p.minute:
	case p.minute + 1:
		p.minute, p.previous, p.peak = minute, p.peak, providerCallPeak{}
	default:
		p.minute, p.previous, p.peak = minute, providerCallPeak{}, providerCallPeak{}
	}
}

// diagnostics reports the most calls one provider had at once in the last one
// to two minutes, including calls that started earlier and still run.
func (p *providerCalls) diagnostics(now time.Time) providerCallDiagnostics {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.advance(now)
	peak := p.peak
	if p.previous.calls > peak.calls {
		peak = p.previous
	}
	for provider, calls := range p.running {
		if calls > peak.calls {
			peak = providerCallPeak{provider: provider, calls: calls}
		}
	}
	return providerCallDiagnostics{
		Workers: stogas.ProviderWorkers, RecentPeak: peak.calls, RecentPeakProvider: string(peak.provider),
	}
}
