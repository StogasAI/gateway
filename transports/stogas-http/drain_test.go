package stogashttp

import (
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestRequestDrainRejectsNewWorkAndWaitsForEveryActiveRequest(t *testing.T) {
	drain := newRequestDrain()
	if !drain.begin() {
		t.Fatal("request drain rejected first request before draining")
	}
	if !drain.begin() {
		t.Fatal("request drain rejected work before draining")
	}
	idle := drain.start()
	if drain.begin() {
		t.Fatal("request drain accepted work after draining")
	}
	drain.end()
	select {
	case <-idle:
		t.Fatal("request drain completed with active work")
	default:
	}
	drain.end()
	select {
	case <-idle:
	case <-time.After(time.Second):
		t.Fatal("request drain did not complete at zero active requests")
	}
}

func TestServerDrainWaitsForActiveRequest(t *testing.T) {
	server := &Server{requests: newRequestDrain()}
	if !server.requests.begin() {
		t.Fatal("request drain rejected work before draining")
	}
	done := make(chan struct{})
	go func() {
		server.drainRequests()
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for !server.requests.diagnostics().Draining {
		if time.Now().After(deadline) {
			t.Fatal("server did not start draining")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("server drain completed with an active request")
	default:
	}

	server.requests.end()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server drain did not complete after the active request")
	}
}

func TestGuestShutdownBudgetPreservesRequestLifetimeAndHardCap(t *testing.T) {
	if got := guestDrainTimeout(); got != billing.GatewayRequestLifetime {
		t.Fatalf("guest drain timeout = %s, want %s", got, billing.GatewayRequestLifetime)
	}
	if downstreamWriteIdleTimeout != time.Minute {
		t.Fatalf("downstream write idle timeout = %s, want 1m", downstreamWriteIdleTimeout)
	}
	if serverShutdownTimeout != 5*time.Minute {
		t.Fatalf("server shutdown timeout = %s, want 5m", serverShutdownTimeout)
	}
	if got := guestDrainTimeout() + serverShutdownTimeout; got != guestShutdownHardCap || got > 65*time.Minute {
		t.Fatalf("guest shutdown budget = %s, want %s", got, guestShutdownHardCap)
	}
}
