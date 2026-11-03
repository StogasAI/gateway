package stogas

import (
	"encoding/json"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func (a AzureAdapter) ValidateRequest(state *State) error {
	if err := a.DefaultAdapter.ValidateRequest(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	if azureDeploymentUsesAnthropicWire(state) {
		if rawJSONValueSet(state.Resolution.RawBody()["task_budget"]) {
			return invalidRequest("task_budget is not supported for Azure Claude deployments")
		}
		if err := validateAnthropicOutputTokenLimit(state); err != nil {
			return err
		}
		if err := validateAnthropicContextManagement(state); err != nil {
			return err
		}
		if err := validateAnthropicChatCompletionPolicy(state); err != nil {
			return err
		}
		return validateAnthropicResponsesPolicy(state)
	}
	if err := validateOpenAIPromptCaching(state); err != nil {
		return err
	}
	if err := validateOpenAIWireChatPolicy(state); err != nil {
		return err
	}
	if err := validateOpenAIWireResponsesPolicy(state); err != nil {
		return err
	}
	return openAIGuardrailError(validateOpenAIGuardrails(openAIAdapterContextForState(state)))
}

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
	if err := a.DefaultAdapter.EstimateHold(state); err != nil {
		return err
	}
	if azureDeploymentUsesAnthropicWire(state) {
		return estimateAnthropicWireHold(state)
	}
	return nil
}

func (a AzureAdapter) CalculateUpstreamCost(state *State) error {
	if azureDeploymentUsesAnthropicWire(state) && anthropicRefusalUnbilled(state) {
		settleUnbilledRefusal(state)
		return nil
	}
	return a.DefaultAdapter.CalculateUpstreamCost(state)
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
