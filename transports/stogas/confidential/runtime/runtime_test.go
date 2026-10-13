package runtime

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
)

func TestDisabledRuntimeAndIncompleteAdmission(t *testing.T) {
	r, err := Start(t.Context(), stogas.ConfidentialConfig{}, Resources{})
	if r != nil || err != nil {
		t.Fatal(r, err)
	}
	if !r.Readiness().Ready {
		t.Fatal("ordinary transport unexpectedly blocked")
	}
	if (&Runtime{}).Readiness().Ready {
		t.Fatal("incomplete confidential runtime admitted traffic")
	}
	r.Close()
}

func TestStartupRetryStopsOnCancellationAndDefinitiveRejection(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	err := retryStartup(ctx, func() (time.Duration, error) { calls++; cancel(); return 0, errors.New("delivery unavailable") })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancellation did not stop retry", calls, err)
	}
	denied := &provision.HTTPResponseError{StatusCode: http.StatusForbidden, Code: "instance_stopped"}
	err = retryStartup(t.Context(), func() (time.Duration, error) { return 0, denied })
	if !errors.Is(err, denied) {
		t.Fatal("definitive rejection retried", err)
	}
}

// A pending reply names when Control can take the next step, such as the end of the
// DNS wait before a certificate challenge. Failures still back off.
func TestStartupRetryWaitsAsControlAsksWithinItsBound(t *testing.T) {
	unavailable := errors.New("delivery unavailable")
	attempts := []struct {
		wait     time.Duration
		err      error
		min, max time.Duration // before the next attempt
	}{
		{0, unavailable, 900 * time.Millisecond, 1100 * time.Millisecond},
		{0, unavailable, 1800 * time.Millisecond, 2200 * time.Millisecond},
		{2 * time.Minute, nil, maxStartupWait, maxStartupWait},
		{5 * time.Second, nil, 5 * time.Second, 5 * time.Second},
		{0, unavailable, 900 * time.Millisecond, 1100 * time.Millisecond},
		{0, nil, 0, 0},
	}
	synctest.Test(t, func(t *testing.T) {
		calls, last := 0, time.Now()
		err := retryStartup(t.Context(), func() (time.Duration, error) {
			if calls > 0 {
				previous := attempts[calls-1]
				if waited := time.Since(last); waited < previous.min || waited > previous.max {
					t.Errorf("attempt %d waited %v", calls, waited)
				}
			}
			attempt := attempts[calls]
			calls, last = calls+1, time.Now()
			return attempt.wait, attempt.err
		})
		if err != nil || calls != len(attempts) {
			t.Fatal("startup retry did not finish", calls, err)
		}
	})
}

func TestDrainSignalIsTerminalAndIdempotent(t *testing.T) {
	r := &Runtime{shutdown: make(chan struct{}), maintenance: &bootMaintenance{}}
	r.Drain()
	r.Drain()
	select {
	case <-r.ShutdownRequested():
	default:
		t.Fatal("drain did not signal shutdown")
	}
	if !r.maintenance.terminal {
		t.Fatal("drain did not close admission")
	}
}

func TestMaintenanceJitterKeepsCadenceBounded(t *testing.T) {
	for range 100 {
		got := jitter(evidencePollInterval)
		if got < 108*time.Second || got > 132*time.Second {
			t.Fatal("maintenance jitter outside its bounds", got)
		}
	}
}
