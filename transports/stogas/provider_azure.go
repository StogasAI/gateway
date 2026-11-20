package stogas

import (
	"encoding/json"

	"github.com/maximhq/bifrost/core/schemas"
)

// format is the adapter of the format that the deployment takes: Anthropic's for Claude, OpenAI's
// for the other models. Azure runs each step as that adapter does, so a priced feature that the
// format bills, such as Claude's web search, is billed on Azure too. Azure differs only where its
// methods below say so.
func (a AzureAdapter) format(state *State) Adapter {
	if stateUsesClaudeWire(state) {
		return AnthropicAdapter{a.DefaultAdapter}
	}
	return OpenAIFormatAdapter{OpenAIAdapter{a.DefaultAdapter}}
}

func (a AzureAdapter) ValidateRequest(state *State) error {
	return a.format(state).ValidateRequest(state)
}

// SanitizeRequest sends Claude neither speed nor inference_geo, which Anthropic's adapter sets for
// Anthropic's own API.
func (a AzureAdapter) SanitizeRequest(state *State) error {
	if !stateUsesClaudeWire(state) {
		return a.format(state).SanitizeRequest(state)
	}
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	state.Resolution.ApplyProviderSamplingParameters()
	applyAnthropicResponsesToolCap(state)
	return nil
}

func (a AzureAdapter) EstimateHold(state *State) error {
	return a.format(state).EstimateHold(state)
}

func (a AzureAdapter) IngestChunk(state *State, chunk *schemas.BifrostStreamChunk) error {
	return a.format(state).IngestChunk(state, chunk)
}

func (a AzureAdapter) IngestResponse(state *State, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) error {
	return a.format(state).IngestResponse(state, resp, bifrostErr)
}

func (a AzureAdapter) CalculateUpstreamCost(state *State) error {
	return a.format(state).CalculateUpstreamCost(state)
}

func (a AzureAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	return a.format(state).ValidateRawResponsesToolType(state, tool)
}
