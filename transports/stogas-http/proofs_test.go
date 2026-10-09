package stogashttp

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas"

	"github.com/maximhq/bifrost/transports/stogas/billing"
)

func TestFinalMetadataKeepsCanonicalRequestTiming(t *testing.T) {
	ttftMS := uint32(150)
	credentialID := "0198f4cc-6c25-7000-8000-000000000001"
	event := &billing.RequestEvent{
		Performance: billing.RequestPerformance{TotalMS: 180, ProviderMS: 140, TTFTMS: &ttftMS},

		ProviderAttempts: []billing.ProviderAttempt{
			{
				Provider:     "openai",
				Status:       "provider_error",
				LatencyMS:    30,
				Byok: nil,
			},
			{
				Provider:     "anthropic",
				Status:       "success",
				LatencyMS:    90,
				Byok: &credentialID,
			},
		}, Usage: billing.RequestUsage{UpstreamCostUSD: "100",
			BilledCostUSD: "2"},
	}

	timing := stogas.FinalMetadata(context.Background(), &stogas.State{Resolution: testResolution(), FinalEvent: event}).Timing
	if timing.TotalMS != 180 || timing.ProviderMS != 140 {
		t.Fatalf("proof timing = %#v, want total=180 provider=140", timing)
	}
	if timing.TTFTMS == nil || *timing.TTFTMS != 150 {
		t.Fatalf("proof TTFT = %#v, want 150", timing.TTFTMS)
	}
}
