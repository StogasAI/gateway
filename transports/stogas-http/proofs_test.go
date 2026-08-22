package stogashttp

import (
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestProofUsesFinalAttemptBYOKAndSequentialProviderTiming(t *testing.T) {
	firstOutputMS := uint32(40)
	event := &billing.RequestEvent{
		TotalTimeMS:          180,
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
				Provider:              "anthropic",
				Status:                "success",
				LatencyMS:             90,
				ProviderFirstOutputMS: &firstOutputMS,
				UpstreamByok:          "0198f4cc-6c25-7000-8000-000000000001",
			},
		},
	}

	timing := proofTiming(event)
	if timing.TotalMS != 180 || timing.ProviderMS != 120 {
		t.Fatalf("proof timing = %#v, want total=180 provider=120", timing)
	}
	if timing.TimeToFirstOutputMS == nil || *timing.TimeToFirstOutputMS != 70 {
		t.Fatalf("proof first output = %#v, want 70", timing.TimeToFirstOutputMS)
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
