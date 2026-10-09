package billing

import (
	"math/rand/v2"
	"testing"
	"time"
)

func TestProviderDurationWithinEveryClockOrdering(t *testing.T) {
	base := time.Unix(1700000000, 0)
	// Includes sub-millisecond boundaries, backwards clocks, missing stages,
	// retries/draining spans and saturated elapsed time without sleeping.
	times := []time.Time{{}, base.Add(-time.Hour), base, base.Add(time.Microsecond), base.Add(999 * time.Microsecond), base.Add(time.Millisecond), base.Add(time.Second), base.Add(2 * time.Second), base.Add(60 * 24 * time.Hour)}
	for _, start := range times[1:] {
		for _, finish := range times[1:] {
			for _, providerStart := range times {
				for _, providerFinish := range times {
					total := uint32Duration(finish.Sub(start))
					offset, duration := requestProviderTiming(EventInput{ProviderStartedAt: providerStart, ProviderCompletedAt: providerFinish}, start, finish, total)
					if duration > total || (offset != nil && uint64(*offset)+uint64(duration) > uint64(total)) {
						t.Fatalf("provider exceeds request: %d total %d", duration, total)
					}
					if (providerStart.IsZero() || providerStart.Before(start)) && (duration != 0 || offset != nil) {
						t.Fatal("missing/invalid dispatch invented provider work")
					}
				}
			}
		}
	}
	// A later valid completion increases provider time without exceeding
	// the request interval.
	rng := rand.New(rand.NewPCG(451, 779))
	for range 10000 {
		admission := time.Duration(rng.IntN(100000)) * time.Microsecond
		provider := time.Duration(rng.IntN(100000)) * time.Microsecond
		response := time.Duration(rng.IntN(100000)) * time.Microsecond
		end := base.Add(admission + provider + response)
		_, a := requestProviderTiming(EventInput{ProviderStartedAt: base.Add(admission), ProviderCompletedAt: base.Add(admission + provider)}, base, end, uint32Duration(end.Sub(base)))
		_, b := requestProviderTiming(EventInput{ProviderStartedAt: base.Add(admission), ProviderCompletedAt: end}, base, end, uint32Duration(end.Sub(base)))
		if a > b || b > uint32Duration(end.Sub(base)) {
			t.Fatalf("nonmonotonic provider duration: %+v => %+v", a, b)
		}
	}
}

func TestProviderIntervalSharesRequestOrigin(t *testing.T) {
	start := time.Unix(1700000000, 0)
	// A first token at 35ms can precede the combined 85ms of gateway work:
	// preparation occupies [0,20), provider [20,335), finalization [335,400).
	input := EventInput{
		ProviderStartedAt:   start.Add(20 * time.Millisecond),
		ProviderCompletedAt: start.Add(335 * time.Millisecond),
		FirstOutputAt:       start.Add(35 * time.Millisecond),
	}
	offset, duration := requestProviderTiming(input, start, start.Add(400*time.Millisecond), 400)
	if offset == nil || *offset != 20 || duration != 315 {
		t.Fatalf("provider interval = %v + %d, want 20 + 315", offset, duration)
	}
	firstOutput := requestFirstOutput(input, start, offset, duration)
	if firstOutput == nil || *firstOutput != 35 {
		t.Fatalf("first provider output = %v, want 35ms from request start", firstOutput)
	}
}
