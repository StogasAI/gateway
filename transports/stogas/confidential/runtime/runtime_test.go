package runtime

import (
	"context"
	"errors"
	"net/http"
	"testing"
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
	err := retryStartup(ctx, func() (bool, error) { calls++; cancel(); return false, errors.New("delivery unavailable") })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancellation did not stop retry", calls, err)
	}
	denied := &provision.HTTPResponseError{StatusCode: http.StatusForbidden, Code: "instance_stopped"}
	err = retryStartup(t.Context(), func() (bool, error) { return false, denied })
	if !errors.Is(err, denied) {
		t.Fatal("definitive rejection retried", err)
	}
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
