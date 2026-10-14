// Package clock reports whether the guest wall clock agrees with
// authenticated time. The host sets the guest's boot clock, so the guest runs
// an NTS daemon that clears the kernel's unsynchronized flag only after a
// majority of independent sources agree. The kernel sets the flag again when
// its error bound reaches 16 seconds, about nine hours without agreement, and
// whenever it changes clocksource; the daemon clears it at its next update.
package clock

import (
	"sync"
	"time"
)

// maxPoll is the daemon's longest poll interval in ntp.toml. While sources
// still agree, the flag a clocksource change sets is cleared within it.
const maxPoll = 1024 * time.Second

// Tolerant returns a check that reports false only once synchronized has kept
// returning false for longer than maxPoll.
func Tolerant(synchronized func() bool, now func() time.Time) func() bool {
	var mu sync.Mutex
	var since time.Time
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if synchronized() {
			since = time.Time{}
			return true
		}
		current := now()
		if since.IsZero() {
			since = current
		}
		return current.Sub(since) <= maxPoll
	}
}
