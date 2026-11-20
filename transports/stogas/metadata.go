package stogas

import (
	"context"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/chutese2ee"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
)

// FinalMetadata is shared by response receipts and request exports. The caller
// prepares the immutable billing event before taking this contextual snapshot.
func FinalMetadata(ctx context.Context, state *State) proof.Metadata {
	if state == nil || state.Resolution == nil {
		return proof.Metadata{}
	}
	catalogIdentity := state.Resolution.CatalogIdentity()
	executionDeployment := ExecutionDeployment(state)
	metadata := proof.Metadata{
		RequestID: state.RequestID,
		Catalog: proof.Catalog{
			Version:      catalogIdentity.Sequence,
			ChainHash:    executionDeployment.ChainHash,
			SelectionIDs: state.Resolution.CatalogNodeIDsForDeployment(executionDeployment),
		},

		Provider: chutese2ee.InvocationMetadata(ctx),
		Usage:    billing.RequestUsage{Meters: billing.EventMeters{}, UpstreamCostUSD: "0", BilledCostUSD: "0"},
	}
	if event := state.FinalEvent; event != nil {
		recordMetadata(&metadata, event)
	}
	return metadata
}

// recordMetadata copies the request record's time, times and usage, and the hash of the policies
// it names.
func recordMetadata(metadata *proof.Metadata, event *billing.RequestEvent) {
	metadata.CreatedAt = event.CreatedAt
	if event.PolicyVersions != nil {
		metadata.PolicyVersionsSHA512 = event.PolicyVersions.SHA512()
	}
	performance := event.Performance
	metadata.Performance = proof.Performance{
		TotalMS: performance.TotalMS, ProviderMS: event.ProviderMS(), RateLimitWaitMS: performance.RateLimitWaitMS,
		FirstOutputMS: performance.FirstOutputMS, TTFTMS: performance.TTFTMS,
	}
	metadata.Usage = event.Usage
}
