package stogas

import "github.com/maximhq/bifrost/transports/stogas/confidential/proof"

// FinalMetadata is the caller's part of the request's finished record, which a receipt signs. A
// request has none before PrepareFinalState builds its record.
func FinalMetadata(state *State) proof.Metadata {
	if state == nil || state.FinalEvent == nil {
		return proof.Metadata{}
	}
	return proof.Select(state.FinalEvent)
}
