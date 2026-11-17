package billing

import (
	"math/rand/v2"
	"testing"
	"time"
)

// Whatever the clock readings, a record keeps its calls in order within the request, with provider
// time from the start of the first call to the end of the last, the rate limit wait before the
// first call and the first output inside the calls.
func TestProviderTimingFitsTheRequestForEveryClockReading(t *testing.T) {
	startedAt := time.Now().Add(-time.Second)
	// Includes missing readings, sub-millisecond boundaries, readings before the request and after
	// it ends, and saturated elapsed time.
	readings := []time.Duration{-time.Hour, 0, time.Microsecond, 999 * time.Microsecond, time.Millisecond, 500 * time.Millisecond, time.Hour, 60 * 24 * time.Hour}
	rng := rand.New(rand.NewPCG(451, 779))
	reading := func() time.Time {
		if rng.IntN(len(readings)+1) == 0 {
			return time.Time{}
		}
		return startedAt.Add(readings[rng.IntN(len(readings))])
	}
	for range 20000 {
		input := EventInput{StartedAt: startedAt, RateLimitWait: readings[rng.IntN(len(readings))], FirstOutputAt: reading()}
		for range rng.IntN(4) {
			input.ProviderAttempts = append(input.ProviderAttempts, ProviderAttemptInput{StartedAt: reading(), CompletedAt: reading()})
		}
		event := mustNewRequestEvent(t, input)
		timing, attempts := event.Performance, event.ProviderAttempts
		end := uint32(0)
		for index, attempt := range attempts {
			end = attempt.StartMS + attempt.LatencyMS
			if end > timing.TotalMS || (index > 0 && attempt.StartMS < attempts[index-1].StartMS) {
				t.Fatalf("calls leave the request or its order: %+v in %d ms", attempts, timing.TotalMS)
			}
		}
		firstStart := timing.TotalMS
		if len(attempts) > 0 {
			firstStart = attempts[0].StartMS
		}
		if want := end - min(firstStart, end); event.ProviderMS() != want {
			t.Fatalf("provider time = %d, want %d for %+v", event.ProviderMS(), want, attempts)
		}
		if timing.RateLimitWaitMS > firstStart {
			t.Fatalf("rate limit wait %d ends after the first call starts at %d", timing.RateLimitWaitMS, firstStart)
		}
		if output := timing.FirstOutputMS; output != nil && (len(attempts) == 0 || *output < firstStart || *output > end) {
			t.Fatalf("first output %d lies outside the calls %+v", *output, attempts)
		}
	}
}

// Preparation occupies [0,20), a failed call [20,120), the wait before the next call [120,150),
// that call [150,335) and finalization the rest. Provider time includes the wait, and the first
// output keeps its place on the request clock.
func TestProviderTimeSpansTheCallsOnTheRequestClock(t *testing.T) {
	startedAt := time.Now().Add(-400 * time.Millisecond)
	event := mustNewRequestEvent(t, EventInput{
		StartedAt:     startedAt,
		RateLimitWait: 15 * time.Millisecond,
		FirstOutputAt: startedAt.Add(160 * time.Millisecond),
		ProviderAttempts: []ProviderAttemptInput{
			{StartedAt: startedAt.Add(20 * time.Millisecond), CompletedAt: startedAt.Add(120 * time.Millisecond)},
			{StartedAt: startedAt.Add(150 * time.Millisecond), CompletedAt: startedAt.Add(335 * time.Millisecond)},
		},
	})
	timing := event.Performance
	if event.ProviderMS() != 315 || timing.RateLimitWaitMS != 15 || timing.FirstOutputMS == nil || *timing.FirstOutputMS != 160 {
		t.Fatalf("provider time %d and timing %+v, want 315 ms of provider time, a 15 ms wait and first output at 160 ms", event.ProviderMS(), timing)
	}
}
