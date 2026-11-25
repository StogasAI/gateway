package stogashttp

import (
	"crypto/sha512"
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
		Performance: billing.RequestPerformance{TotalMS: 180, RateLimitWaitMS: 4, FirstOutputMS: &ttftMS, TTFTMS: &ttftMS},
		// Provider time runs from the first call's start at 10 ms to the last call's end at 150 ms.
		ProviderAttempts: []billing.ProviderAttempt{
			{
				Provider:  "openai",
				Status:    "provider_error",
				StartMS:   10,
				LatencyMS: 30,
				Byok:      nil,
			},
			{
				Provider:  "anthropic",
				Status:    "success",
				StartMS:   60,
				LatencyMS: 90,
				Byok:      &credentialID,
			},
		}, Usage: billing.RequestUsage{UpstreamCostUSD: "100",
			BilledCostUSD: "2"},
	}

	metadata := stogas.FinalMetadata(&stogas.State{Pair: stogas.Pair{Resolution: testResolution()}, FinalEvent: event})
	timing := metadata.Performance
	if timing.TotalMS != 180 || timing.RateLimitWaitMS != 4 {
		t.Fatalf("proof timing = %#v, want total=180 wait=4", timing)
	}
	// The calls carry the provider time, as in the record.
	if calls := metadata.ProviderAttempts; len(calls) != 2 || calls[0].StartMS != 10 || calls[1].StartMS+calls[1].LatencyMS != 150 {
		t.Fatalf("proof calls = %#v", calls)
	}
	if timing.TTFTMS == nil || *timing.TTFTMS != 150 || timing.FirstOutputMS == nil || *timing.FirstOutputMS != 150 {
		t.Fatalf("proof TTFT = %#v and first output = %#v, want 150", timing.TTFTMS, timing.FirstOutputMS)
	}
}

// A receipt signs one hash of the policy list that the request log carries.
// Verifiers recompute it from the log's list in RFC 8785 form.
func TestFinalMetadataNamesTheLoggedPolicyList(t *testing.T) {
	versions := billing.LoggedPolicyVersions{
		{PolicyVersion: billing.PolicyVersion{Scope: "organization", ID: "org<&>", Revision: 7}, SHA512: strings.Repeat("a", 128)},
		{PolicyVersion: billing.PolicyVersion{Scope: "key", ID: "key", Revision: 1}, SHA512: strings.Repeat("b", 128)},
	}
	event := &billing.RequestEvent{PolicyVersions: &versions, Usage: billing.RequestUsage{UpstreamCostUSD: "0", BilledCostUSD: "0"}}
	metadata := stogas.FinalMetadata(&stogas.State{Pair: stogas.Pair{Resolution: testResolution()}, FinalEvent: event})
	want := sha512.Sum512([]byte(`[{"id":"org<&>","revision":7,"scope":"organization","sha512":"` + strings.Repeat("a", 128) +
		`"},{"id":"key","revision":1,"scope":"key","sha512":"` + strings.Repeat("b", 128) + `"}]`))
	if metadata.PolicyVersionsSHA512 != hex.EncodeToString(want[:]) {
		t.Fatalf("receipt policy hash = %q", metadata.PolicyVersionsSHA512)
	}
	event.PolicyVersions = nil
	if metadata := stogas.FinalMetadata(&stogas.State{Pair: stogas.Pair{Resolution: testResolution()}, FinalEvent: event}); metadata.PolicyVersionsSHA512 != "" {
		t.Fatal("a request without policies named a policy hash")
	}
}
