package stogashttp

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
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
