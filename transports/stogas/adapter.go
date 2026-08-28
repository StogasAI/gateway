package stogas

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

type Adapter interface {
	ValidateRequest(*State) error
	SanitizeRequest(*State) error
	EstimateHold(*State) error
	ValidateRawResponsesToolType(*State, map[string]json.RawMessage) error
	IngestChunk(*State, *schemas.BifrostStreamChunk) error
	IngestResponse(*State, *schemas.BifrostResponse, *schemas.BifrostError) error
	CalculateUpstreamCost(*State) error
	SanitizeResponse(*State)
}

type DefaultAdapter struct{}

type OpenAIAdapter struct {
	DefaultAdapter
}

type AzureAdapter struct {
	DefaultAdapter
}

type AnthropicAdapter struct {
	DefaultAdapter
}

type ChutesAdapter struct {
	DefaultAdapter
}

func AdapterFor(provider schemas.ModelProvider) Adapter {
	switch provider {
	case schemas.OpenAI:
		return OpenAIAdapter{}
	case schemas.Azure:
		return AzureAdapter{}
	case schemas.Anthropic:
		return AnthropicAdapter{}
	case catalog.ProviderChutes:
		return ChutesAdapter{}
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
	return nil
}

func (DefaultAdapter) EstimateHold(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	hold, err := baseHoldEstimate(state)
	if err != nil {
		return err
	}
	state.Hold = hold
	return nil
}

func (DefaultAdapter) IngestChunk(state *State, chunk *schemas.BifrostStreamChunk) error {
	if state == nil || chunk == nil {
		return nil
	}
	parts := 0
	if chunk.BifrostError != nil {
		parts++
	}
	if chunk.BifrostChatResponse != nil {
		parts++
	}
	if chunk.BifrostResponsesStreamResponse != nil {
		parts++
	}
	if parts != 1 {
		return ErrProviderResponseMalformed
	}
	if chunk.BifrostError != nil {
		state.BifrostError = chunk.BifrostError
		if usage := chunk.BifrostError.ExtraFields.BilledUsage; usage != nil {
			if err := ingestReportedUsage(state, usage); err != nil {
				return err
			}
		}
		return nil
	}
	switch {
	case chunk.BifrostChatResponse != nil:
		response := chunk.BifrostChatResponse
		if usage := response.Usage; usage != nil {
			if err := ingestReportedUsage(state, usage); err != nil {
				return err
			}
		}
		if err := validateProviderChatResponse(state, response, true); err != nil {
			return err
		}
		if err := validateActualExecutionReport(state, response.ServiceTier, response.Speed, response.InferenceGeo); err != nil {
			return err
		}
		if err := validateActualResponseModel(state, response.Model); err != nil {
			return err
		}
		if responseHasFallbackModel(response.ExtraFields.RoutingInfo.ServerSideFallbackModel) {
			return ErrProviderExecutionMismatch
		}
		observeActualExecution(state, response.ServiceTier, response.Speed, response.InferenceGeo)
		observeActualResponseModel(state, response.Model)
		state.observeChatProviderOutputEmitted(response)
		state.Response = &schemas.BifrostResponse{ChatResponse: response}
	case chunk.BifrostResponsesStreamResponse != nil:
		streamResp := chunk.BifrostResponsesStreamResponse
		if streamResp.Response != nil && streamResp.Response.Usage != nil {
			usage := streamResp.Response.Usage.ToBifrostLLMUsage()
			if err := ingestReportedUsage(state, usage); err != nil {
				return err
			}
		}
		if err := validateProviderResponsesStream(state, streamResp); err != nil {
			return err
		}
		if responseHasFallbackModel(streamResp.ExtraFields.RoutingInfo.ServerSideFallbackModel) {
			return ErrProviderExecutionMismatch
		}
		if streamResp.Response != nil {
			if err := validateActualExecutionReport(state, streamResp.Response.ServiceTier, streamResp.Response.Speed, streamResp.Response.InferenceGeo); err != nil {
				return err
			}
			if err := validateActualResponseModel(state, streamResp.Response.Model); err != nil {
				return err
			}
			if responseHasFallbackModel(streamResp.Response.ExtraFields.RoutingInfo.ServerSideFallbackModel) {
				return ErrProviderExecutionMismatch
			}
			observeActualExecution(state, streamResp.Response.ServiceTier, streamResp.Response.Speed, streamResp.Response.InferenceGeo)
			observeActualResponseModel(state, streamResp.Response.Model)
		}
		state.observeResponsesProviderOutputEmitted(streamResp)
		state.Response = &schemas.BifrostResponse{ResponsesStreamResponse: streamResp}
	}
	return nil
}

func (DefaultAdapter) IngestResponse(state *State, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) error {
	if state == nil {
		return nil
	}
	state.BifrostError = bifrostErr
	usage := unambiguousResponseUsage(resp)
	if usage != nil {
		if err := ingestReportedUsage(state, usage); err != nil {
			return err
		}
	}
	if bifrostErr == nil {
		if err := validateBifrostResponseShape(state, resp); err != nil {
			return err
		}
	}
	if err := validateBifrostActualExecution(state, resp); err != nil {
		return err
	}
	observeBifrostActualExecution(state, resp)
	if bifrostErr == nil {
		state.observeProviderResponseOutputEmitted(resp)
	}
	if bifrostErr != nil {
		if billedUsage := bifrostErr.ExtraFields.BilledUsage; billedUsage != nil {
			if err := ingestReportedUsage(state, billedUsage); err != nil {
				return err
			}
		}
	}
	state.Response = resp
	return nil
}

func ingestReportedUsage(state *State, usage *schemas.BifrostLLMUsage) error {
	metadataErr := validateReportedUsageMetadata(state, usage)
	setSignalsFromUsage(state, usage)
	if metadataErr == nil {
		observeUsageExecution(state, usage)
	}
	return metadataErr
}

func unambiguousResponseUsage(resp *schemas.BifrostResponse) *schemas.BifrostLLMUsage {
	if resp == nil {
		return nil
	}
	parts := 0
	for _, set := range []bool{
		resp.ChatResponse != nil,
		resp.ResponsesResponse != nil,
		resp.ResponsesStreamResponse != nil,
	} {
		if set {
			parts++
		}
	}
	if parts != 1 {
		return nil
	}
	if resp.ChatResponse != nil {
		return resp.ChatResponse.Usage
	}
	if resp.ResponsesResponse != nil && resp.ResponsesResponse.Usage != nil {
		return resp.ResponsesResponse.Usage.ToBifrostLLMUsage()
	}
	if resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil && resp.ResponsesStreamResponse.Response.Usage != nil {
		return resp.ResponsesStreamResponse.Response.Usage.ToBifrostLLMUsage()
	}
	return nil
}

func validateBifrostResponseShape(state *State, resp *schemas.BifrostResponse) error {
	if resp == nil {
		return ErrProviderResponseMalformed
	}
	parts := 0
	if resp.ChatResponse != nil {
		parts++
	}
	if resp.ResponsesResponse != nil {
		parts++
	}
	if resp.ResponsesStreamResponse != nil {
		parts++
	}
	if parts != 1 {
		return ErrProviderResponseMalformed
	}
	switch {
	case resp.ChatResponse != nil:
		return validateProviderChatResponse(state, resp.ChatResponse, false)
	case resp.ResponsesResponse != nil:
		return validateProviderResponsesResponse(state, resp.ResponsesResponse)
	case resp.ResponsesStreamResponse != nil:
		return validateProviderResponsesStream(state, resp.ResponsesStreamResponse)
	default:
		return ErrProviderResponseMalformed
	}
}

func validateBifrostActualExecution(state *State, resp *schemas.BifrostResponse) error {
	if resp == nil {
		return nil
	}
	switch {
	case resp.ChatResponse != nil:
		if responseHasFallbackModel(resp.ChatResponse.ExtraFields.RoutingInfo.ServerSideFallbackModel) {
			return ErrProviderExecutionMismatch
		}
		if err := validateActualResponseModel(state, resp.ChatResponse.Model); err != nil {
			return err
		}
		return validateActualExecutionReport(state, resp.ChatResponse.ServiceTier, resp.ChatResponse.Speed, resp.ChatResponse.InferenceGeo)
	case resp.ResponsesResponse != nil:
		if responseHasFallbackModel(resp.ResponsesResponse.ExtraFields.RoutingInfo.ServerSideFallbackModel) {
			return ErrProviderExecutionMismatch
		}
		if err := validateActualResponseModel(state, resp.ResponsesResponse.Model); err != nil {
			return err
		}
		return validateActualExecutionReport(state, resp.ResponsesResponse.ServiceTier, resp.ResponsesResponse.Speed, resp.ResponsesResponse.InferenceGeo)
	case resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil:
		if responseHasFallbackModel(resp.ResponsesStreamResponse.ExtraFields.RoutingInfo.ServerSideFallbackModel) ||
			responseHasFallbackModel(resp.ResponsesStreamResponse.Response.ExtraFields.RoutingInfo.ServerSideFallbackModel) {
			return ErrProviderExecutionMismatch
		}
		if err := validateActualResponseModel(state, resp.ResponsesStreamResponse.Response.Model); err != nil {
			return err
		}
		return validateActualExecutionReport(state, resp.ResponsesStreamResponse.Response.ServiceTier, resp.ResponsesStreamResponse.Response.Speed, resp.ResponsesStreamResponse.Response.InferenceGeo)
	default:
		return nil
	}
}

func (DefaultAdapter) CalculateUpstreamCost(state *State) error {
	if state == nil {
		return nil
	}
	upstreamCostUSDAtoms, err := calculateBaseUpstreamCost(state, nil)
	if err != nil {
		return err
	}
	state.UpstreamCostUSDAtoms = upstreamCostUSDAtoms
	return nil
}

func (DefaultAdapter) SanitizeResponse(state *State) {
	if state == nil {
		return
	}
	state.ProviderResponseHeaders = nil
	if state.Response == nil {
		return
	}
	extra := state.Response.GetExtraFields()
	if extra != nil {
		state.ProviderResponseHeaders = extra.ProviderResponseHeaders
	}
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
		observeActualExecution(state, resp.ChatResponse.ServiceTier, resp.ChatResponse.Speed, resp.ChatResponse.InferenceGeo)
		observeActualResponseModel(state, resp.ChatResponse.Model)
	case resp.ResponsesResponse != nil:
		observeActualExecution(state, resp.ResponsesResponse.ServiceTier, resp.ResponsesResponse.Speed, resp.ResponsesResponse.InferenceGeo)
		observeActualResponseModel(state, resp.ResponsesResponse.Model)
	case resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil:
		observeActualExecution(state, resp.ResponsesStreamResponse.Response.ServiceTier, resp.ResponsesStreamResponse.Response.Speed, resp.ResponsesStreamResponse.Response.InferenceGeo)
		observeActualResponseModel(state, resp.ResponsesStreamResponse.Response.Model)
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
	case item.ID != nil && strings.TrimSpace(*item.ID) != "":
		return "id:" + strings.TrimSpace(*item.ID)
	case item.ResponsesToolMessage != nil && item.ResponsesToolMessage.CallID != nil && strings.TrimSpace(*item.ResponsesToolMessage.CallID) != "":
		return "call:" + strings.TrimSpace(*item.ResponsesToolMessage.CallID)
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
	return invalidRequest("Only function, custom, and priced hosted web search tools are supported")
}
