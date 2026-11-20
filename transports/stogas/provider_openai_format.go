package stogas

import (
	"encoding/json"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// OpenAIFormatAdapter serves a model that takes OpenAI's format on a provider other than OpenAI,
// such as Kimi on Azure or AWS. OpenAI's checks, holds and billing apply, and the provider runs no
// hosted tool.
type OpenAIFormatAdapter struct {
	OpenAIAdapter
}

// awsDroppedFields are the fields that Bedrock's Chat Completions API answers 200 without applying
// (captures aws/chat-completions-request-fields and aws/chat-completions-tools). Each one decides
// what the reply reports or how many tools the model calls in a turn, so a deployment that drops
// it cannot serve the request. parallel_tool_calls reaches this check only as false, because true
// allows what every provider allows. Routing leaves these deployments out for logit_bias, because
// their records state none, and for web_search_options, because they have no search prices.
var awsDroppedFields = []string{"logprobs", "parallel_tool_calls", "top_logprobs"}

func (a OpenAIFormatAdapter) ValidateRequest(state *State) error {
	if err := a.OpenAIAdapter.ValidateRequest(state); err != nil {
		return err
	}
	if state.Resolution.Provider != catalog.ProviderAWS {
		return nil
	}
	raw := wireState(state).Resolution.RawBody()
	for _, name := range awsDroppedFields {
		if rawJSONValueSet(raw[name]) {
			return invalidRequest(name + " is not supported for the selected AWS deployment")
		}
	}
	return nil
}

// SanitizeRequest sends reasoning off as reasoning_effort none, the one reasoning control of the
// format, as Fireworks documents for the models it serves. Reasoning on leaves the model's default.
func (a OpenAIFormatAdapter) SanitizeRequest(state *State) error {
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	state.Resolution.SendReasoningOffAsEffort()
	return nil
}

func (OpenAIFormatAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	toolType := catalog.CanonicalResponsesToolType(rawString(tool["type"]))
	switch toolType {
	case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeCustom, schemas.ResponsesToolTypeNamespace:
		// Anthropic's client tools read as functions, which only Claude takes.
		if _, anthropicTool := catalog.AnthropicClientToolName(rawString(tool["type"])); !anthropicTool {
			return nil
		}
	}
	// The catalog offers no hosted tool on these routes.
	if err := hostedToolOffered(state, string(toolType)); err != nil {
		return err
	}
	return invalidRequest("Only function, custom, and namespace tools are supported for " + providerName(state) + " deployments")
}

// providerName is the name of the deployment's provider in a message.
func providerName(state *State) string {
	if state != nil && state.Resolution != nil && state.Resolution.Provider == catalog.ProviderAWS {
		return "AWS"
	}
	return "Azure"
}
