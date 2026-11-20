package stogas

import (
	"encoding/json"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// CloudAdapter serves AWS and Google Cloud: Claude takes Anthropic's Messages API there, which
// CloudClaudeAdapter serves, other models take OpenAI's format on AWS, and Gemini takes its own
// API on Google Cloud.
type CloudAdapter struct {
	DefaultAdapter
}

func (a CloudAdapter) format(state *State) Adapter {
	switch {
	case stateUsesClaudeWire(state):
		return CloudClaudeAdapter{AnthropicAdapter{a.DefaultAdapter}}
	case state != nil && state.Resolution != nil && state.Resolution.Provider == catalog.ProviderGoogleCloud:
		return GeminiAdapter{OpenAIAdapter{a.DefaultAdapter}}
	}
	return OpenAIFormatAdapter{OpenAIAdapter{a.DefaultAdapter}}
}

func (a CloudAdapter) ValidateRequest(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	return a.format(state).ValidateRequest(state)
}

func (a CloudAdapter) SanitizeRequest(state *State) error {
	return a.format(state).SanitizeRequest(state)
}

func (a CloudAdapter) EstimateHold(state *State) error {
	return a.format(state).EstimateHold(state)
}

func (a CloudAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	return a.format(state).ValidateRawResponsesToolType(state, tool)
}

func (a CloudAdapter) IngestChunk(state *State, chunk *schemas.BifrostStreamChunk) error {
	return a.format(state).IngestChunk(state, chunk)
}

func (a CloudAdapter) IngestResponse(state *State, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) error {
	return a.format(state).IngestResponse(state, resp, bifrostErr)
}

func (a CloudAdapter) CalculateUpstreamCost(state *State) error {
	return a.format(state).CalculateUpstreamCost(state)
}

// CloudClaudeAdapter serves Claude on AWS and Google Cloud. Every hosting takes
// the Messages API, so Anthropic's validation, holds and refusal billing apply;
// what Bedrock and Agent Platform (Vertex AI) lack is refused here instead of
// upstream. The catalog lists hosted tools only for the hosting that runs them,
// so Anthropic's tool checks refuse them where the cloud runs Claude.
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
		catalog.CloudRunsModel(state.Resolution.Provider, state.Resolution.Deployment)
}

// SanitizeRequest sends speed only for Fast, which only Anthropic's hosting on
// Google Cloud offers, so other requests keep the default the clouds share.
// Where the cloud runs Claude, the profile or endpoint fixes the geography;
// Anthropic takes inference_geo as on its own API.
func (a CloudClaudeAdapter) SanitizeRequest(state *State) error {
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	state.Resolution.ApplyProviderSamplingParameters()
	if state.Resolution.Deployment.Upstream.ServiceTier == catalog.TierFast {
		state.Resolution.SetSpeed("fast")
	}
	if !cloudRunsClaude(state) {
		switch geo := state.Resolution.Deployment.Upstream.InferenceGeo; geo {
		case "us", "global":
			state.Resolution.SetExtraParam("inference_geo", geo)
		}
	}
	applyAnthropicResponsesToolCap(state)
	return nil
}
