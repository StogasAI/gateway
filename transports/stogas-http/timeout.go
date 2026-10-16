package stogashttp

import (
	"context"
	"math"
	"sync"
	"time"
)

// Output progress moves the deadline without resetting a timer for every token.
// This limits client waiting, never the lifetime of dispatched provider work.
type responseDeadline struct {
	mu       sync.Mutex
	timer    *time.Timer
	total    time.Time
	deadline time.Time
	idle     time.Duration
	context  context.Context
	cancel   context.CancelFunc
	stopped  bool
	expired  bool
}

func newResponseDeadline(startedAt time.Time, total, idle time.Duration) *responseDeadline {
	ctx, cancel := context.WithCancel(context.Background())
	deadline := startedAt.Add(total)
	wait := &responseDeadline{total: deadline, deadline: deadline, idle: idle, context: ctx, cancel: cancel}
	wait.mu.Lock()
	wait.timer = time.AfterFunc(time.Until(deadline), wait.check)
	wait.mu.Unlock()
	return wait
}

// startOutput gives a provider call its output idle window. Each retry and
// fallback call gets a new window within the total deadline.
func (wait *responseDeadline) startOutput() bool {
	if wait == nil {
		return true
	}
	wait.mu.Lock()
	defer wait.mu.Unlock()
	// A caller that left before the deadline did not time out.
	if wait.stopped {
		return false
	}
	now := time.Now()
	if !now.Before(wait.deadline) {
		wait.expire()
		return false
	}
	next := now.Add(wait.idle)
	if next.After(wait.total) {
		next = wait.total
	}
	wait.deadline = next
	wait.timer.Reset(next.Sub(now))
	return true
}

// remaining reports how long the caller still waits for output.
func (wait *responseDeadline) remaining() time.Duration {
	if wait == nil {
		return time.Duration(math.MaxInt64)
	}
	wait.mu.Lock()
	defer wait.mu.Unlock()
	if wait.stopped {
		return 0
	}
	return time.Until(wait.deadline)
}

// Called with mu held, including when expiry races dispatch or completion.
func (wait *responseDeadline) expire() {
	wait.expired, wait.stopped = true, true
	wait.timer.Stop()
	wait.cancel()
}

func (wait *responseDeadline) check() {
	wait.mu.Lock()
	if wait.stopped {
		wait.mu.Unlock()
		return
	}
	remaining := time.Until(wait.deadline)
	if remaining > 0 {
		wait.timer.Reset(remaining)
	} else {
		wait.expire()
	}
	wait.mu.Unlock()
}

func (wait *responseDeadline) observe(at time.Time) {
	if wait == nil || at.IsZero() {
		return
	}
	wait.mu.Lock()
	if wait.stopped {
		wait.mu.Unlock()
		return
	}
	// Late output cannot revive a request while the timer callback is queued.
	if !at.Before(wait.deadline) {
		wait.expire()
	} else {
		next := at.Add(wait.idle)
		if next.After(wait.total) {
			next = wait.total
		}
		if next.After(wait.deadline) {
			wait.deadline = next
		}
	}
	wait.mu.Unlock()
}

func (wait *responseDeadline) stop() {
	if wait == nil {
		return
	}
	wait.mu.Lock()
	defer wait.mu.Unlock()
	if !wait.stopped {
		if !time.Now().Before(wait.deadline) {
			wait.expire()
		} else {
			wait.stopped = true
			wait.timer.Stop()
		}
	}
}

func (wait *responseDeadline) timedOut() bool {
	if wait == nil {
		return false
	}
	wait.mu.Lock()
	defer wait.mu.Unlock()
	return wait.expired || (!wait.stopped && !time.Now().Before(wait.deadline))
}

func (wait *responseDeadline) waiting() bool {
	if wait == nil {
		return true
	}
	wait.mu.Lock()
	defer wait.mu.Unlock()
	return !wait.stopped && time.Now().Before(wait.deadline)
}

func (wait *responseDeadline) done() <-chan struct{} {
	if wait == nil {
		return nil
	}
	return wait.context.Done()
}

func (wait *responseDeadline) deliveryContext(provider context.Context) context.Context {
	if wait == nil {
		return provider
	}
	return wait.context
}
