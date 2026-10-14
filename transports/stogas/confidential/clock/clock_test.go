package clock

import (
	"testing"
	"time"
)

func TestTolerantIgnoresTheFlagForOneMaximumPoll(t *testing.T) {
	synchronized := false
	now := time.Unix(0, 0)
	check := Tolerant(func() bool { return synchronized }, func() time.Time { return now })
	if !check() {
		t.Fatal("a newly set flag closed readiness")
	}
	now = now.Add(maxPoll)
	if !check() {
		t.Fatal("the flag closed readiness within one maximum poll")
	}
	now = now.Add(time.Nanosecond)
	if check() {
		t.Fatal("a flag set for longer than one maximum poll kept readiness open")
	}
	synchronized = true
	if !check() {
		t.Fatal("an update did not reopen readiness")
	}
	synchronized = false
	now = now.Add(maxPoll)
	if !check() {
		t.Fatal("a new reset did not restart the tolerance")
	}
}
