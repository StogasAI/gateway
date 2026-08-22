package stogas

import (
	"encoding/json"
	"strings"

	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
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
	state.Resolution.NormalizeMinimumOutputTokenLimit(openaiprovider.MinMaxCompletionTokens)
	if err := validateAzurePromptCaching(state); err != nil {
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
	}
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

func azureDeploymentUsesAnthropicWire(state *State) bool {
	return state != nil &&
		state.Resolution != nil &&
		strings.EqualFold(strings.TrimSpace(state.Resolution.Deployment.Upstream.ModelFormat), "Anthropic")
}

func validateAzurePromptCaching(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	raw := state.Resolution.RawBody()
	if err := validatePromptCacheKey(raw["prompt_cache_key"], "prompt_cache_key"); err != nil {
		return err
	}
	if rawJSONValueSet(raw["prompt_cache_options"]) {
		return invalidRequest("prompt_cache_options is not supported for Azure deployments")
	}
	breakpoints, err := validatePromptCacheBreakpoints(
		rawPromptContent(state.Resolution.Route, raw),
		state.Resolution.Route,
	)
	if err != nil {
		return err
	}
	if breakpoints > 0 {
		return invalidRequest("prompt_cache_breakpoint is not supported for Azure deployments")
	}
	retentionRaw := raw["prompt_cache_retention"]
	if !rawJSONValueSet(retentionRaw) {
		return nil
	}
	retention, ok := rawStringValue(retentionRaw)
	if !ok {
		return invalidRequest("prompt_cache_retention must be a string")
	}
	if retention != "24h" {
		return invalidRequest("prompt_cache_retention must be 24h for Azure GPT-5.6 deployments")
	}
	return nil
}

func (AzureAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	if azureDeploymentUsesAnthropicWire(state) {
		return (AnthropicAdapter{}).ValidateRawResponsesToolType(state, tool)
	}
	switch toolType := canonicalResponsesToolType(rawString(tool["type"])); toolType {
	case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
		return nil
	case schemas.ResponsesToolTypeMCP:
		return invalidRequest("Remote MCP tools are not supported because provider execution cannot be bounded or approved per request")
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
		return invalidRequest("Hosted tools are not supported because this Azure route has no cataloged tool pricing")
	default:
		return invalidRequest("Only function and custom tools are supported for Azure deployments")
	}
}
