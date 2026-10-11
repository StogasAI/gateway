package clock

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitReturnsOnceTheClockIsSynchronized(t *testing.T) {
	checks := 0
	err := Wait(t.Context(), func() bool {
		checks++
		return checks == 2
	})
	if err != nil || checks != 2 {
		t.Fatal("wait did not return after synchronization", err, checks)
	}
}

func TestWaitStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := Wait(ctx, func() bool { return false }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("wait ignored its context", err)
	}
}
