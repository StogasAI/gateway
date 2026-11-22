package stogas

import (
	"encoding/json"
	"strings"

	bedrockprovider "github.com/maximhq/bifrost/core/providers/bedrock"
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
// for the models that it serves through an inference profile (captures
// aws/chat-completions-request-fields and aws/chat-completions-tools). Each one decides what the
// reply reports or how many tools the model calls in a turn, so a deployment that drops it cannot
// serve the request. parallel_tool_calls reaches this check only as false, because true allows
// what every provider allows. Bedrock applies all three for the models that run only in the Region
// of each request (capture aws/chat-completions-in-region-fields). Routing leaves out an AWS
// deployment whose record states no logit_bias, and every AWS deployment for web_search_options,
// because none has search prices.
var awsDroppedFields = []string{"logprobs", "parallel_tool_calls", "top_logprobs"}

func (a OpenAIFormatAdapter) ValidateRequest(state *State) error {
	if err := a.OpenAIAdapter.ValidateRequest(state); err != nil {
		return err
	}
	if state.Resolution.Provider != catalog.ProviderAWS || state.Resolution.Deployment.Upstream.Regions != nil {
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
// format, as Fireworks documents for the models it serves. Reasoning on leaves the model's default,
// except on Bedrock, which turns on the reasoning of a model with only a switch at high and at no
// other effort (capture aws/chat-completions-in-region-reasoning).
func (a OpenAIFormatAdapter) SanitizeRequest(state *State) error {
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	on := ""
	if state.Resolution.Provider == catalog.ProviderAWS {
		on = "high"
	}
	state.Resolution.SendReasoningSwitchAsEffort(on)
	return nil
}

// IngestResponse and IngestChunk give a reply of Bedrock's Chat Completions API the form of every
// other provider's (bedrockReasoning). DeepSeek V3.2 there also leaves the opening tag of its tool
// call markup at the end of the text before a call, which core's filter removes, holding back a
// stream's text while it can still be that tag.
func (a OpenAIFormatAdapter) IngestResponse(state *State, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) error {
	if bedrockChat(state) && resp != nil && resp.ChatResponse != nil {
		dsml := bedrockprovider.IsDSMLLeakModel(nil, state.Resolution.Deployment.Upstream.Model)
		for index := range resp.ChatResponse.Choices {
			reply := resp.ChatResponse.Choices[index].ChatNonStreamResponseChoice
			if reply == nil || reply.Message == nil || reply.Message.Content == nil || reply.Message.Content.ContentStr == nil {
				continue
			}
			text := *reply.Message.Content.ContentStr
			reasoning, answer, tagged := bedrockReasoning(text)
			assistant := reply.Message.ChatAssistantMessage
			if dsml && assistant != nil && len(assistant.ToolCalls) > 0 {
				answer = bedrockprovider.StripDSMLLeak(answer)
			}
			if !tagged && answer == text {
				continue
			}
			// A reply with nothing but reasoning or a tool call has no content, as OpenAI's has none.
			reply.Message.Content.ContentStr = &answer
			if answer == "" {
				reply.Message.Content = nil
			}
			if reasoning != "" {
				if assistant == nil {
					assistant = &schemas.ChatAssistantMessage{}
					reply.Message.ChatAssistantMessage = assistant
				}
				assistant.Reasoning, assistant.ReasoningDetails = bedrockReasoningText(reasoning)
			}
		}
	}
	return a.OpenAIAdapter.IngestResponse(state, resp, bifrostErr)
}

func (a OpenAIFormatAdapter) IngestChunk(state *State, chunk *schemas.BifrostStreamChunk) error {
	if bedrockChat(state) && chunk != nil && chunk.BifrostChatResponse != nil {
		for index := range chunk.BifrostChatResponse.Choices {
			stream := chunk.BifrostChatResponse.Choices[index].ChatStreamResponseChoice
			if stream == nil || stream.Delta == nil || stream.Delta.Content == nil {
				continue
			}
			reasoning, answer, tagged := bedrockReasoning(*stream.Delta.Content)
			if !tagged {
				continue
			}
			stream.Delta.Content = &answer
			if answer == "" {
				stream.Delta.Content = nil
			}
			if reasoning != "" {
				stream.Delta.Reasoning, stream.Delta.ReasoningDetails = bedrockReasoningText(reasoning)
			}
		}
		if state.bedrockDSML == nil && bedrockprovider.IsDSMLLeakModel(nil, state.Resolution.Deployment.Upstream.Model) {
			state.bedrockDSML = &bedrockprovider.DSMLStreamFilter{}
		}
		state.bedrockDSML.FilterChatChunk(chunk.BifrostChatResponse)
	}
	return a.OpenAIAdapter.IngestChunk(state, chunk)
}

// bedrockChat reports whether a request runs on Bedrock's Chat Completions API.
func bedrockChat(state *State) bool {
	return state != nil && state.Resolution != nil && state.Resolution.Provider == catalog.ProviderAWS
}

// Bedrock's Chat Completions API writes the reasoning of a model that has no reasoning field of
// its own into the text, in these tags before the answer: around all of it in a reply, and around
// each piece in a stream (capture aws/chat-completions-in-region-reasoning). AWS documents the tags
// for InvokeModel, which takes the same body.
const (
	bedrockReasoningOpen  = "<reasoning>"
	bedrockReasoningClose = "</reasoning>"
)

// bedrockReasoning splits text that starts with tagged reasoning into the reasoning and the answer
// after it. Text cut off inside the reasoning is all reasoning.
func bedrockReasoning(text string) (reasoning, answer string, tagged bool) {
	answer = text
	for strings.HasPrefix(answer, bedrockReasoningOpen) {
		rest := answer[len(bedrockReasoningOpen):]
		end := strings.Index(rest, bedrockReasoningClose)
		if end < 0 {
			return reasoning + rest, "", true
		}
		reasoning, answer, tagged = reasoning+rest[:end], rest[end+len(bedrockReasoningClose):], true
	}
	return reasoning, answer, tagged
}

// bedrockReasoningText returns the reasoning and details that core gives a reply whose provider
// returns its reasoning in a field.
func bedrockReasoningText(reasoning string) (*string, []schemas.ChatReasoningDetails) {
	text := reasoning
	return &reasoning, []schemas.ChatReasoningDetails{{Index: 0, Type: schemas.BifrostReasoningDetailsTypeText, Text: &text}}
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
	if err := hostedToolOffered(state, tool); err != nil {
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
