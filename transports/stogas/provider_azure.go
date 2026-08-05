package stogas

import (
	"encoding/json"

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

func (AzureAdapter) ValidateRawResponsesToolType(_ *State, tool map[string]json.RawMessage) error {
	switch toolType := canonicalResponsesToolType(rawString(tool["type"])); toolType {
	case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom:
		return nil
	case schemas.ResponsesToolTypeMCP:
		return validateOpenAIResponsesMCPToolApproval(tool)
	case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
		return invalidRequest("Hosted tools are not supported because this Azure route has no cataloged tool pricing")
	default:
		return invalidRequest("Only function, custom, and approval-free MCP tools are supported for Azure deployments")
	}
}
