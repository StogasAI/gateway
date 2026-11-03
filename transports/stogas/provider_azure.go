package stogas

import (
	"encoding/json"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// format is the adapter of the format that the deployment takes: Anthropic's for Claude, OpenAI's
// for the other models. Azure runs each step as that adapter does, so a priced feature that the
// format bills, such as Claude's web search, is billed on Azure too. Azure differs only where its
// methods below say so.
func (a AzureAdapter) format(state *State) Adapter {
	if azureDeploymentUsesAnthropicWire(state) {
		return AnthropicAdapter{a.DefaultAdapter}
	}
	return OpenAIAdapter{a.DefaultAdapter}
}

func (a AzureAdapter) ValidateRequest(state *State) error {
	if azureDeploymentUsesAnthropicWire(state) && rawJSONValueSet(state.Resolution.RawBody()["task_budget"]) {
		return invalidRequest("task_budget is not supported for Azure Claude deployments")
	}
	return a.format(state).ValidateRequest(state)
}

// SanitizeRequest sends Claude neither speed nor inference_geo, which Anthropic's adapter sets for
// Anthropic's own API.
func (a AzureAdapter) SanitizeRequest(state *State) error {
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	if azureDeploymentUsesAnthropicWire(state) {
		state.Resolution.ApplyProviderSamplingParameters()
		ensureAnthropicResponsesHostedToolCap(state)
		return nil
	}
	// The OpenAI format carries reasoning only as reasoning_effort, whose "none" turns reasoning
	// off, as Fireworks documents for the models it serves. Reasoning on leaves the model's default.
	state.Resolution.SendReasoningOffAsEffort()
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

func azureDeploymentUsesAnthropicWire(state *State) bool {
	return state != nil &&
		state.Resolution != nil &&
		schemas.IsAnthropicModel(state.Resolution.Deployment.ModelID)
}

func (AzureAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	if azureDeploymentUsesAnthropicWire(state) {
		return (AnthropicAdapter{}).ValidateRawResponsesToolType(state, tool)
	}
	switch toolType := catalog.CanonicalResponsesToolType(rawString(tool["type"])); toolType {
	case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
		return nil
	default:
		// The catalog offers no hosted tool on Azure's own routes.
		if err := hostedToolOffered(state, string(toolType)); err != nil {
			return err
		}
		return invalidRequest("Only function and custom tools are supported for Azure deployments")
	}
}
