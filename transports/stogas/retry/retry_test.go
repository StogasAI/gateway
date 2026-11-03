package retry

import (
	"math"
	"testing"
	"time"
)

func TestTransientStatus(t *testing.T) {
	for status, want := range map[int]bool{
		200: false, 400: false, 401: false, 403: false, 404: false, 409: false, 422: false,
		408: true, 425: true, 429: true, 500: true, 502: true, 503: true, 504: true, 520: true, 529: true,
	} {
		if TransientStatus(status) != want {
			t.Errorf("TransientStatus(%d) = %v, want %v", status, !want, want)
		}
	}
}

func TestAfterReadsSecondsAndDates(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{"", 0, false},
		{"soon", 0, false},
		{"-1", 0, false},
		{"NaN", 0, false},
		{"0", 0, true},
		{" 7 ", 7 * time.Second, true},
		{"1.5", 1500 * time.Millisecond, true},
		{"1e30", math.MaxInt64, true},
		{"Tue, 03 Nov 2026 12:00:30 GMT", 30 * time.Second, true},
		{"Tue, 03 Nov 2026 11:59:00 GMT", 0, true},
	} {
		wait, ok := After(test.value, now)
		if wait != test.want || ok != test.ok {
			t.Errorf("After(%q) = %v, %v, want %v, %v", test.value, wait, ok, test.want, test.ok)
		}
	}
	if wait, ok := AfterMilliseconds("250.5"); wait != 250500*time.Microsecond || !ok {
		t.Errorf("AfterMilliseconds = %v, %v", wait, ok)
	}
	if _, ok := AfterMilliseconds("Tue, 03 Nov 2026 12:00:30 GMT"); ok {
		t.Error("retry-after-ms took a date")
	}
}

func TestJitterStaysWithinTheSecondHalf(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Nanosecond, 3, time.Second} {
		for range 200 {
			if wait := Jitter(delay); wait > delay || wait < delay/2 {
				t.Fatalf("Jitter(%v) = %v", delay, wait)
			}
		}
	}
}
