package stogashttp

import (
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestRequestDrainRejectsNewWorkAndWaitsForEveryActiveRequest(t *testing.T) {
	drain := newRequestDrain()
	if !drain.begin() || !drain.begin() {
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

func TestGuestDrainNeverExceedsRequestLifetimeOrHardCap(t *testing.T) {
	if got := guestDrainTimeout(); got != billing.GatewayRequestLifetime || got > 65*time.Minute {
		t.Fatalf("guest drain timeout = %s", got)
	}
}
