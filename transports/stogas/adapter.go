package stogas

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

type Adapter interface {
	ValidateRequest(*State) error
	SanitizeRequest(*State) error
	EstimateHold(*State) error
	ValidateRawResponsesToolType(*State, map[string]json.RawMessage) error
	IngestChunk(*State, *schemas.BifrostStreamChunk) error
	IngestResponse(*State, *schemas.BifrostResponse, *schemas.BifrostError) error
	FinalPrice(*State) error
	SanitizeResponse(*State) error
}

type DefaultAdapter struct{}

type OpenAIAdapter struct {
	DefaultAdapter
}

type AnthropicAdapter struct {
	DefaultAdapter
}

func AdapterFor(provider schemas.ModelProvider) Adapter {
	switch provider {
	case schemas.OpenAI:
		return OpenAIAdapter{}
	case schemas.Anthropic:
		return AnthropicAdapter{}
	default:
		return DefaultAdapter{}
	}
}

func (DefaultAdapter) ValidateRequest(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	if err := validateCommonChatCompletionPolicy(state); err != nil {
		return err
	}
	if err := validateCommonResponsesPolicy(state); err != nil {
		return err
	}
	return nil
}

func (DefaultAdapter) SanitizeRequest(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	state.Resolution.SanitizeClientMetadata()
	state.Resolution.RequireUpstreamUsage()
	if state.APIKeyClaims != nil && catalog.ProviderUsesPseudoanonymousUserID(state.Resolution.Provider) {
		state.Resolution.SetUpstreamUser(state.APIKeyClaims.ResponsibleID)
	}
	return nil
}

func (DefaultAdapter) EstimateHold(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	state.Hold = baseHoldEstimate(state)
	return nil
}

func (DefaultAdapter) IngestChunk(state *State, chunk *schemas.BifrostStreamChunk) error {
	if state == nil || chunk == nil {
		return nil
	}
	if chunk.BifrostError != nil {
		state.BifrostError = chunk.BifrostError
		return nil
	}
	switch {
	case chunk.BifrostChatResponse != nil:
		state.Response = &schemas.BifrostResponse{ChatResponse: chunk.BifrostChatResponse}
		observeActualExecution(state, chunk.BifrostChatResponse.ServiceTier, chunk.BifrostChatResponse.Speed)
		setSignalsFromUsage(state, chunk.BifrostChatResponse.Usage)
	case chunk.BifrostResponsesStreamResponse != nil:
		streamResp := chunk.BifrostResponsesStreamResponse
		state.Response = &schemas.BifrostResponse{ResponsesStreamResponse: streamResp}
		if streamResp.Response != nil {
			observeActualExecution(state, streamResp.Response.ServiceTier, streamResp.Response.Speed)
			if streamResp.Response.Usage != nil {
				setSignalsFromUsage(state, streamResp.Response.Usage.ToBifrostLLMUsage())
			}
		}
	}
	return nil
}

func (DefaultAdapter) IngestResponse(state *State, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) error {
	if state == nil {
		return nil
	}
	state.Response = resp
	state.BifrostError = bifrostErr
	observeBifrostActualExecution(state, resp)
	setSignalsFromUsage(state, billing.LLMUsage(resp))
	return nil
}

func (DefaultAdapter) FinalPrice(state *State) error {
	if state == nil {
		return nil
	}
	state.FinalCostUSDAtoms = baseFinalPrice(state, nil)
	return nil
}

func (DefaultAdapter) SanitizeResponse(state *State) error {
	if state == nil {
		return nil
	}
	state.ProviderResponseHeaders = nil
	if state.Response == nil {
		return nil
	}
	extra := state.Response.GetExtraFields()
	if extra != nil {
		state.ProviderResponseHeaders = extra.ProviderResponseHeaders
	}
	return nil
}

func responsesStreamHasWebSearchCall(resp *schemas.BifrostResponsesStreamResponse) bool {
	if resp == nil {
		return false
	}
	if resp.Type == schemas.ResponsesStreamResponseTypeOutputItemDone && responsesMessageWebSearchCallIsBillable(resp.Item) {
		return true
	}
	switch resp.Type {
	case schemas.ResponsesStreamResponseTypeWebSearchCallCompleted:
		return true
	default:
		return false
	}
}

func observePricedResponsesWebSearchChunk(state *State, chunk *schemas.BifrostStreamChunk) {
	if state == nil || chunk == nil || chunk.BifrostResponsesStreamResponse == nil {
		return
	}
	streamResp := chunk.BifrostResponsesStreamResponse
	if responsesStreamHasWebSearchCall(streamResp) {
		observeWebSearchEvent(state, responsesStreamEventKey(streamResp), responsesStreamWebSearchCallID(streamResp))
	}
	observeResponseWebSearchCalls(state, streamResp.Response)
}

func observePricedResponsesWebSearchResponse(state *State, resp *schemas.BifrostResponse) {
	if resp == nil {
		return
	}
	switch {
	case resp.ResponsesResponse != nil:
		observeResponseWebSearchCalls(state, resp.ResponsesResponse)
	case resp.ResponsesStreamResponse != nil:
		observeResponseWebSearchCalls(state, resp.ResponsesStreamResponse.Response)
	}
}

func observeBifrostActualExecution(state *State, resp *schemas.BifrostResponse) {
	if resp == nil {
		return
	}
	switch {
	case resp.ChatResponse != nil:
		observeActualExecution(state, resp.ChatResponse.ServiceTier, resp.ChatResponse.Speed)
	case resp.ResponsesResponse != nil:
		observeActualExecution(state, resp.ResponsesResponse.ServiceTier, resp.ResponsesResponse.Speed)
	case resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil:
		observeActualExecution(state, resp.ResponsesStreamResponse.Response.ServiceTier, resp.ResponsesStreamResponse.Response.Speed)
	}
}

func observeResponseWebSearchCalls(state *State, resp *schemas.BifrostResponsesResponse) {
	if resp == nil {
		return
	}
	usageCount := -1
	if resp.Usage != nil && resp.Usage.OutputTokensDetails != nil && resp.Usage.OutputTokensDetails.NumSearchQueries != nil {
		usageCount = *resp.Usage.OutputTokensDetails.NumSearchQueries
		setWebSearchSignals(state, usageCount)
	}
	anonymousOutputCalls := 0
	for _, item := range resp.Output {
		if responsesMessageWebSearchCallIsBillable(&item) {
			if id := responsesMessageWebSearchCallID(item); id != "" {
				observeWebSearchCall(state, id)
			} else if usageCount < 0 {
				anonymousOutputCalls++
			}
		}
	}
	if anonymousOutputCalls > 0 {
		setWebSearchSignals(state, anonymousOutputCalls)
	}
}

func responsesMessageWebSearchCallIsBillable(item *schemas.ResponsesMessage) bool {
	if item == nil || item.Type == nil || *item.Type != schemas.ResponsesMessageTypeWebSearchCall {
		return false
	}
	if item.Status == nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(*item.Status)) {
	case "", "completed":
		return true
	default:
		return false
	}
}

func responsesMessageWebSearchCallID(item schemas.ResponsesMessage) string {
	switch {
	case item.ResponsesToolMessage != nil && item.ResponsesToolMessage.CallID != nil && strings.TrimSpace(*item.ResponsesToolMessage.CallID) != "":
		return "call:" + strings.TrimSpace(*item.ResponsesToolMessage.CallID)
	case item.ID != nil && strings.TrimSpace(*item.ID) != "":
		return "id:" + strings.TrimSpace(*item.ID)
	default:
		return ""
	}
}

func responsesStreamWebSearchCallID(resp *schemas.BifrostResponsesStreamResponse) string {
	if resp == nil {
		return ""
	}
	if resp.Item != nil {
		return responsesMessageWebSearchCallID(*resp.Item)
	}
	if resp.ItemID != nil && strings.TrimSpace(*resp.ItemID) != "" {
		return "id:" + strings.TrimSpace(*resp.ItemID)
	}
	if resp.OutputIndex != nil {
		return "output_index:" + strconv.Itoa(*resp.OutputIndex)
	}
	return ""
}

func responsesStreamEventKey(resp *schemas.BifrostResponsesStreamResponse) string {
	if resp == nil {
		return ""
	}
	if id := responsesStreamWebSearchCallID(resp); id != "" {
		return string(resp.Type) + ":" + id
	}
	if resp.SequenceNumber > 0 {
		return string(resp.Type) + ":seq:" + strconv.Itoa(resp.SequenceNumber)
	}
	return ""
}

func actualWebSearchCalls(state *State) int {
	if state == nil || state.Signals == nil {
		return 0
	}
	signals, ok := state.Signals.(SearchUsageSignals)
	if !ok {
		return 0
	}
	return signals.WebSearchCalls()
}

func responsesTopLevelMaxToolCallsOrDefault(state *State) int {
	if state == nil || state.Resolution == nil {
		return defaultResponsesHostedToolCalls
	}
	raw, ok := state.Resolution.RawBody()["max_tool_calls"]
	if !ok {
		return defaultResponsesHostedToolCalls
	}
	quantity, _, err := rawInteger(raw, "max_tool_calls")
	if err != nil || quantity < 1 {
		return defaultResponsesHostedToolCalls
	}
	return quantity
}

func resolutionUsesToolType(state *State, toolType schemas.ResponsesToolType) bool {
	if state == nil || state.Resolution == nil {
		return false
	}
	for _, candidate := range state.Resolution.ToolTypes() {
		if strings.EqualFold(strings.TrimSpace(candidate), string(toolType)) {
			return true
		}
	}
	return false
}

func (DefaultAdapter) ValidateRawResponsesToolType(state *State, tool map[string]json.RawMessage) error {
	return invalidRequest("Only function, custom, mcp, and priced hosted web search tools are supported")
}
