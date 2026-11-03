// Package retry holds what the gateway's retries share: which HTTP failures a repeated call
// may get past, how long a server asks callers to wait, and how to spread the waits of callers
// that failed together.
//
// Two retry loops keep their own rules on purpose. Provider calls wait as the OpenAI and
// Anthropic SDKs do, so a request through the gateway retries like a direct one, and log
// export retries only the statuses that OTLP marks retryable.
package retry

import (
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TransientStatus reports whether a call that failed with status may succeed if repeated: a
// timeout, a request sent too early, a rate limit or a server error.
func TransientStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	}
	return status >= 500
}

// After reads a Retry-After value as RFC 9110 defines it: a count of seconds, which some
// providers send with a fraction, or an HTTP date, counted from now. A date that has passed
// waits 0. ok is false when the value is absent or malformed.
func After(value string, now time.Time) (wait time.Duration, ok bool) {
	value = strings.TrimSpace(value)
	if wait, ok := count(value, time.Second); ok {
		return wait, true
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(0, at.Sub(now)), true
	}
	return 0, false
}

// AfterMilliseconds reads retry-after-ms, which OpenAI and Anthropic send beside Retry-After.
func AfterMilliseconds(value string) (time.Duration, bool) {
	return count(strings.TrimSpace(value), time.Millisecond)
}

func count(value string, unit time.Duration) (time.Duration, bool) {
	amount, err := strconv.ParseFloat(value, 64)
	if err != nil || !(amount >= 0) {
		return 0, false
	}
	// Longer waits saturate; float64(math.MaxInt64) is 2^63.
	if amount*float64(unit) >= math.MaxInt64 {
		return math.MaxInt64, true
	}
	return time.Duration(amount * float64(unit)), true
}

// Jitter picks a wait evenly between half of delay and delay, so that callers that failed
// together retry apart and none waits longer than delay.
func Jitter(delay time.Duration) time.Duration {
	if delay <= time.Nanosecond {
		return delay
	}
	half := delay / 2
	return half + rand.N(delay-half+1)
}
