package billing

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// Whatever the clock readings, a record keeps its calls in order within the request, with provider
// time from the start of the first call to the end of the last, the rate limit wait before the
// first call and a stream's first output inside the calls.
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
		stream := rng.IntN(2) == 0
		if stream {
			input.RequestType = string(schemas.ChatCompletionStreamRequest)
		}
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
		if timing.RateLimitWaitMS > firstStart {
			t.Fatalf("rate limit wait %d ends after the first call starts at %d", timing.RateLimitWaitMS, firstStart)
		}
		if output := timing.FirstOutputMS; output != nil && (!stream || len(attempts) == 0 || *output < firstStart || *output > end) {
			t.Fatalf("first output %d of a stream %v lies outside the calls %+v", *output, stream, attempts)
		}
	}
}

// Preparation occupies [0,20), a failed call [20,120), the wait before the next call [120,150),
// that call [150,335) and finalization the rest. Provider time includes the wait, and a stream's
// first output keeps its place on the request clock. A response that is not streamed arrives whole
// when its call ends, so its record has no first output.
func TestProviderTimeSpansTheCallsOnTheRequestClock(t *testing.T) {
	startedAt := time.Now().Add(-400 * time.Millisecond)
	input := EventInput{
		RequestType:   string(schemas.ChatCompletionStreamRequest),
		StartedAt:     startedAt,
		RateLimitWait: 15 * time.Millisecond,
		FirstOutputAt: startedAt.Add(160 * time.Millisecond),
		ProviderAttempts: []ProviderAttemptInput{
			{StartedAt: startedAt.Add(20 * time.Millisecond), CompletedAt: startedAt.Add(120 * time.Millisecond)},
			{StartedAt: startedAt.Add(150 * time.Millisecond), CompletedAt: startedAt.Add(335 * time.Millisecond)},
		},
	}
	event := mustNewRequestEvent(t, input)
	timing := event.Performance
	calls := event.ProviderAttempts
	if calls[0].StartMS != 20 || calls[1].StartMS+calls[1].LatencyMS != 335 || timing.RateLimitWaitMS != 15 || timing.FirstOutputMS == nil || *timing.FirstOutputMS != 160 {
		t.Fatalf("calls %+v and timing %+v, want calls from 20 ms to 335 ms, a 15 ms wait and first output at 160 ms", calls, timing)
	}
	input.RequestType = string(schemas.ChatCompletionRequest)
	if output := mustNewRequestEvent(t, input).Performance.FirstOutputMS; output != nil {
		t.Fatalf("first output of a response that was not streamed = %d, want none", *output)
	}
}
