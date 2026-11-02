package stogas

import (
	"encoding/json"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// CloudClaudeAdapter serves Claude on AWS and Google Cloud. Every hosting takes
// the Messages API, so Anthropic's validation, holds and refusal billing apply;
// what Bedrock and Agent Platform (Vertex AI) lack is refused here instead of
// upstream.
type CloudClaudeAdapter struct {
	AnthropicAdapter
}

// stateUsesClaudeWire reports whether the selected deployment takes Anthropic's
// Messages API.
func stateUsesClaudeWire(state *State) bool {
	return state != nil && state.Resolution != nil &&
		catalog.UsesClaudeWire(state.Resolution.Provider, state.Resolution.Deployment.ModelID)
}

// cloudRunsClaude reports whether AWS or Google runs the model itself rather
// than Anthropic.
func cloudRunsClaude(state *State) bool {
	return state != nil && state.Resolution != nil &&
		catalog.CloudRunsClaude(state.Resolution.Provider, state.Resolution.Deployment)
}

func (a CloudClaudeAdapter) ValidateRequest(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	if state.Resolution.Deployment.Upstream.Hosting == hostingAWS && rawJSONValueSet(state.Resolution.RawBody()["task_budget"]) {
		return invalidRequest("task_budget is not supported for Claude in Amazon Bedrock")
	}
	return a.AnthropicAdapter.ValidateRequest(state)
}

// SanitizeRequest sends no speed: neither cloud offers fast mode for a cataloged
// deployment. Where the cloud runs Claude, the profile or endpoint fixes the
// geography; Anthropic takes inference_geo as on its own API.
func (a CloudClaudeAdapter) SanitizeRequest(state *State) error {
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	state.Resolution.ApplyProviderSamplingParameters()
	if !cloudRunsClaude(state) {
		switch geo := state.Resolution.Deployment.Upstream.InferenceGeo; geo {
		case "us", "global":
			state.Resolution.SetExtraParam("inference_geo", geo)
		}
	}
	ensureAnthropicResponsesHostedToolCap(state)
	return nil
}

// ValidateRawResponsesToolType refuses web search and web fetch where the cloud
// runs Claude. Bedrock has neither and Agent Platform has no web fetch. Agent
// Platform's web search is off unless an organization policy allows it, sends
// queries outside Google's commitments, and has no verified price.
func (a CloudClaudeAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	if cloudRunsClaude(state) {
		rawType := rawString(tool["type"])
		if anthropicResponsesWebSearchToolType(rawType) || anthropicResponsesWebFetchToolType(rawType) {
			return invalidRequest("Hosted tools are not supported when AWS or Google runs Claude")
		}
	}
	return a.AnthropicAdapter.ValidateRawResponsesToolType(state, tool)
}
