package stogashttp

import (
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestProofUsesFinalAttemptBYOKAndRequestTiming(t *testing.T) {
	ttftMS := uint32(150)
	event := &billing.RequestEvent{
		TotalTimeMS:          180,
		TTFTMS:               &ttftMS,
		UpstreamCostUSDAtoms: "100",
		BilledCostUSDAtoms:   "2",
		ProviderAttempts: []billing.ProviderAttempt{
			{
				Provider:     "openai",
				Status:       "provider_error",
				LatencyMS:    30,
				UpstreamByok: "stogas",
			},
			{
				Provider:     "anthropic",
				Status:       "success",
				LatencyMS:    90,
				UpstreamByok: "0198f4cc-6c25-7000-8000-000000000001",
			},
		},
	}

	timing := proofTiming(event)
	if timing.TotalMS != 180 || timing.ProviderMS != 120 {
		t.Fatalf("proof timing = %#v, want total=180 provider=120", timing)
	}
	if timing.TTFTMS == nil || *timing.TTFTMS != 150 {
		t.Fatalf("proof TTFT = %#v, want 150", timing.TTFTMS)
	}
	pricing := proofPricing(event)
	if pricing.TotalCostUSDAtoms != "2" || pricing.BYOKCostUSDAtoms != "100" {
		t.Fatalf("proof pricing = %#v", pricing)
	}

	event.ProviderAttempts[0].UpstreamByok = "0198f4cc-6c25-7000-8000-000000000002"
	event.ProviderAttempts[1].UpstreamByok = "stogas"
	if pricing := proofPricing(event); pricing.BYOKCostUSDAtoms != "" {
		t.Fatalf("proof used a superseded attempt's BYOK attribution: %#v", pricing)
	}
}
