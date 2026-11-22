package stogas

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/bytedance/sonic"
	geminiprovider "github.com/maximhq/bifrost/core/providers/gemini"
	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// GeminiAdapter serves Gemini on Google Cloud, which takes Gemini's own generateContent API.
// Requests arrive in OpenAI's format, so OpenAI's checks, holds and billing apply, and core
// converts them. What core cannot carry to Gemini is refused here instead of dropped.
type GeminiAdapter struct {
	OpenAIAdapter
}

// stateRunsGemini reports whether the pair runs Gemini on Google Cloud.
func stateRunsGemini(state *State) bool {
	return state != nil && state.Resolution != nil && state.Resolution.RunsGeminiModel()
}

func (a GeminiAdapter) ValidateRequest(state *State) error {
	if err := a.OpenAIAdapter.ValidateRequest(state); err != nil {
		return err
	}
	wire := wireState(state).Resolution
	raw := wire.RawBody()
	// Every Gemini model of the route refuses log probabilities
	// (capture google-cloud/generate-content-request-fields).
	var logprobs bool
	var topLogprobs int
	_ = sonic.Unmarshal(raw["logprobs"], &logprobs)
	_ = sonic.Unmarshal(raw["top_logprobs"], &topLogprobs)
	if logprobs || topLogprobs > 0 {
		return invalidRequest("logprobs is not supported for Gemini on Google Cloud")
	}
	// Gemini declares functions only, and core leaves any other tool out.
	for _, tool := range wire.RawTools() {
		if rawString(tool["type"]) != string(schemas.ChatToolTypeFunction) {
			return invalidRequest("Only function tools are supported for Gemini on Google Cloud")
		}
	}
	return nil
}

func (GeminiAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	toolType := catalog.CanonicalResponsesToolType(rawString(tool["type"]))
	switch toolType {
	case schemas.ResponsesToolTypeFunction, schemas.ResponsesToolTypeNamespace:
		// Anthropic's client tools read as functions, which only Claude takes.
		if _, anthropicTool := catalog.AnthropicClientToolName(rawString(tool["type"])); !anthropicTool {
			return nil
		}
	}
	// The catalog offers no hosted tool on this route.
	if err := hostedToolOffered(state, tool); err != nil {
		return err
	}
	return invalidRequest("Only function and namespace tools are supported for Gemini on Google Cloud")
}

// IngestResponse and IngestChunk give a reply the form in which a client sends Gemini's reasoning
// back (geminiReasoning), each tool call the ID that Gemini gave it: core joins the call's thought
// signature to the ID, which would not fit the gateway's limit or another provider's, and a reply
// that Gemini cut at its output segment the reason length.
func (a GeminiAdapter) IngestResponse(state *State, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) error {
	if state != nil && resp != nil && resp.ChatResponse != nil {
		for index := range resp.ChatResponse.Choices {
			choice := &resp.ChatResponse.Choices[index]
			choice.FinishReason = geminiFinishReason(choice.FinishReason)
			if reply := choice.ChatNonStreamResponseChoice; reply != nil && reply.Message != nil && reply.Message.ChatAssistantMessage != nil {
				assistant := reply.Message.ChatAssistantMessage
				assistant.Reasoning, assistant.ReasoningDetails = geminiReasoning(state.Resolution, assistant.ReasoningDetails, true)
				withoutThoughtSignatures(assistant.ToolCalls)
			}
		}
	}
	return a.OpenAIAdapter.IngestResponse(state, resp, bifrostErr)
}

func (a GeminiAdapter) IngestChunk(state *State, chunk *schemas.BifrostStreamChunk) error {
	if state != nil && chunk != nil && chunk.BifrostChatResponse != nil {
		for index := range chunk.BifrostChatResponse.Choices {
			choice := &chunk.BifrostChatResponse.Choices[index]
			choice.FinishReason = geminiFinishReason(choice.FinishReason)
			if stream := choice.ChatStreamResponseChoice; stream != nil && stream.Delta != nil {
				stream.Delta.Reasoning, stream.Delta.ReasoningDetails = geminiReasoning(state.Resolution, stream.Delta.ReasoningDetails, false)
				withoutThoughtSignatures(stream.Delta.ToolCalls)
			}
		}
	}
	return a.OpenAIAdapter.IngestChunk(state, chunk)
}

// geminiSegmentEnd is core's reason for a reply that reached Gemini's output segment, which holds
// fewer tokens without streaming than with it. Only Google's v1beta1 API continues such a reply, and
// the gateway calls v1, so the reply ended at an output limit.
var geminiSegmentEnd = geminiprovider.ConvertGeminiFinishReasonToBifrost(geminiprovider.FinishReasonContinuation)

func geminiFinishReason(reason *string) *string {
	if reason != nil && *reason == geminiSegmentEnd {
		return schemas.Ptr(string(schemas.BifrostFinishReasonLength))
	}
	return reason
}

// geminiReasoning returns the reasoning text and details of a reply or a stream's delta. Gemini
// returns summaries of its thoughts, so each thought text becomes a summary, which no model reads
// back, and the reasoning text holds them. Each thought signature becomes encrypted reasoning bound
// to the account (catalog.ResolvedRequest.BindGeminiSignature), or goes without one. A reply lists
// the signature of its text before those of its tool calls, which name their call, so that its
// translation to Responses gives each signature a reasoning item of its own. A stream keeps the
// order and indexes of core's details, which a client joins by index.
func geminiReasoning(resolution *catalog.ResolvedRequest, details []schemas.ChatReasoningDetails, reply bool) (*string, []schemas.ChatReasoningDetails) {
	var text strings.Builder
	var kept, calls []schemas.ChatReasoningDetails
	for _, detail := range details {
		switch {
		case detail.Type == schemas.BifrostReasoningDetailsTypeText && detail.Text != nil && detail.Signature == nil:
			text.WriteString(*detail.Text)
			detail.Type, detail.Summary, detail.Text = schemas.BifrostReasoningDetailsTypeSummary, detail.Text, nil
		case detail.Type == schemas.BifrostReasoningDetailsTypeEncrypted && detail.Signature != nil:
			bound, ok := resolution.BindGeminiSignature(*detail.Signature)
			if !ok {
				continue
			}
			detail.Data, detail.Signature = &bound, nil
			if reply && detail.ID != nil {
				calls = append(calls, detail)
				continue
			}
		}
		kept = append(kept, detail)
	}
	kept = append(kept, calls...)
	if reply {
		for index := range kept {
			kept[index].Index = index
		}
	}
	var reasoning *string
	if text.Len() > 0 {
		reasoning = schemas.Ptr(text.String())
	}
	return reasoning, kept
}

// withoutThoughtSignatures gives each tool call the ID without the thought signature that core
// joins to it. The call's reasoning detail carries the signature.
func withoutThoughtSignatures(calls []schemas.ChatAssistantMessageToolCall) {
	for index := range calls {
		if id := calls[index].ID; id != nil {
			calls[index].ID = schemas.Ptr(providerutils.StripThoughtSignature(*id))
		}
	}
}

// coreThoughtSignatures returns the request with each signature that it sends back where core reads
// one: in signature, which a reply's conversion fills, rather than in data, which the gateway
// returns. The request's checks left out every other encrypted reasoning and unbound these
// (catalog.ResolvedRequest.KeepReadableHistory). Other requests of the same body share the
// messages, so it never changes them.
func coreThoughtSignatures(request *schemas.BifrostChatRequest) *schemas.BifrostChatRequest {
	encrypted := func(detail schemas.ChatReasoningDetails) bool {
		return detail.Type == schemas.BifrostReasoningDetailsTypeEncrypted && detail.Data != nil
	}
	var input []schemas.ChatMessage
	for index, message := range request.Input {
		assistant := message.ChatAssistantMessage
		if assistant == nil || !slices.ContainsFunc(assistant.ReasoningDetails, encrypted) {
			continue
		}
		if input == nil {
			input = slices.Clone(request.Input)
		}
		signed := *assistant
		signed.ReasoningDetails = slices.Clone(assistant.ReasoningDetails)
		for detail := range signed.ReasoningDetails {
			if encrypted(signed.ReasoningDetails[detail]) {
				signed.ReasoningDetails[detail].Signature, signed.ReasoningDetails[detail].Data = signed.ReasoningDetails[detail].Data, nil
			}
		}
		input[index].ChatAssistantMessage = &signed
	}
	if input == nil {
		return request
	}
	signed := *request
	signed.Input = input
	return &signed
}

// prepareGeminiChatBody builds the generateContent body with core's converter, then writes what
// core leaves out or approximates: the request's exact thinking level, which the catalog lists
// per model; seed and top_k; and thought summaries as the reasoning display asks.
func prepareGeminiChatBody(ctx *schemas.BifrostContext, request *schemas.BifrostChatRequest) ([]byte, *schemas.BifrostError) {
	request = coreThoughtSignatures(request)
	body, bifrostErr := providerutils.CheckContextAndGetRequestBody(ctx, request, func() (*geminiprovider.GeminiGenerationRequest, error) {
		return geminiprovider.ToGeminiChatCompletionRequest(ctx, request)
	})
	if bifrostErr != nil {
		return nil, bifrostErr
	}
	params := request.Params
	if params == nil {
		params = &schemas.ChatParameters{}
	}
	var err error
	set := func(path string, value any) {
		if err == nil {
			body, err = providerutils.SetJSONField(body, path, value)
		}
	}
	del := func(path string) {
		if err == nil && providerutils.GetJSONField(body, path).Exists() {
			body, err = providerutils.DeleteJSONField(body, path)
		}
	}
	reasoning := params.Reasoning
	if reasoning != nil && reasoning.Effort != nil && *reasoning.Effort != "none" {
		set("generationConfig.thinkingConfig.thinkingLevel", strings.ToUpper(*reasoning.Effort))
		del("generationConfig.thinkingConfig.thinkingBudget")
	}
	// Gemini returns summaries of its thoughts, which a request gets unless it asks for no display
	// or for progress updates, which Gemini does not write.
	set("generationConfig.thinkingConfig.includeThoughts", reasoning == nil || reasoning.Display == nil || *reasoning.Display == "summarized")
	if params.Seed != nil {
		set("generationConfig.seed", *params.Seed)
	}
	if params.TopK != nil {
		set("generationConfig.topK", *params.TopK)
	}
	if err != nil {
		return nil, providerutils.NewBifrostOperationError(schemas.ErrProviderRequestMarshal, err)
	}
	return body, nil
}
