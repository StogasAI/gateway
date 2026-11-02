package stogashttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
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
				Provider:  "openai",
				Status:    "provider_error",
				LatencyMS: 30,
				Byok:      nil,
			},
			{
				Provider:  "anthropic",
				Status:    "success",
				LatencyMS: 90,
				Byok:      &credentialID,
			},
		}, Usage: billing.RequestUsage{UpstreamCostUSD: "100",
			BilledCostUSD: "2"},
	}

	timing := stogas.FinalMetadata(context.Background(), &stogas.State{Pair: stogas.Pair{Resolution: testResolution()}, FinalEvent: event}).Timing
	if timing.TotalMS != 180 || timing.ProviderMS != 140 {
		t.Fatalf("proof timing = %#v, want total=180 provider=140", timing)
	}
	if timing.TTFTMS == nil || *timing.TTFTMS != 150 {
		t.Fatalf("proof TTFT = %#v, want 150", timing.TTFTMS)
	}
}

// A receipt signs one hash of the policy list that the request log carries.
// Verifiers recompute it from the log's list in RFC 8785 form.
func TestFinalMetadataNamesTheLoggedPolicyList(t *testing.T) {
	versions := billing.LoggedPolicyVersions{
		{PolicyVersion: billing.PolicyVersion{Scope: "organization", ID: "org<&>", Revision: 7}, SHA256: strings.Repeat("a", 64)},
		{PolicyVersion: billing.PolicyVersion{Scope: "key", ID: "key", Revision: 1}, SHA256: strings.Repeat("b", 64)},
	}
	event := &billing.RequestEvent{PolicyVersions: &versions, Usage: billing.RequestUsage{UpstreamCostUSD: "0", BilledCostUSD: "0"}}
	metadata := stogas.FinalMetadata(context.Background(), &stogas.State{Pair: stogas.Pair{Resolution: testResolution()}, FinalEvent: event})
	want := sha256.Sum256([]byte(`[{"id":"org<&>","revision":7,"scope":"organization","sha256":"` + strings.Repeat("a", 64) +
		`"},{"id":"key","revision":1,"scope":"key","sha256":"` + strings.Repeat("b", 64) + `"}]`))
	if metadata.PolicyVersionsSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("receipt policy hash = %q", metadata.PolicyVersionsSHA256)
	}
	event.PolicyVersions = nil
	if metadata := stogas.FinalMetadata(context.Background(), &stogas.State{Pair: stogas.Pair{Resolution: testResolution()}, FinalEvent: event}); metadata.PolicyVersionsSHA256 != "" {
		t.Fatal("a request without policies named a policy hash")
	}
}
