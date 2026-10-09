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
		Meters:   billing.EventMeters{}, UpstreamCostUSD: "0", BilledCostUSD: "0",
	}
	if event := state.FinalEvent; event != nil {
		metadata.CreatedAt = event.CreatedAt
		metadata.Timing = proof.Timing{TotalMS: event.Performance.TotalMS, ProviderMS: event.Performance.ProviderMS, TTFTMS: event.Performance.TTFTMS}
		metadata.Meters = event.Usage.Meters
		metadata.UpstreamCostUSD, metadata.BilledCostUSD = event.Usage.UpstreamCostUSD, event.Usage.BilledCostUSD
		metadata.CacheReadSavingsUSD, metadata.CacheWriteOverheadUSD = event.Usage.CacheReadSavingsUSD, event.Usage.CacheWriteOverheadUSD
	}
	return metadata
}
