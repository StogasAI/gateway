package stogas

import (
	"strconv"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	openaiadapter "github.com/maximhq/bifrost/transports/stogas/providers/openai"
)

type Adapter interface {
	ResolveDeployment(*State) error
	ValidateRequest(*State) error
	SanitizeRequest(*State) error
	EstimateHold(*State) error
	IngestChunk(*State, *schemas.BifrostStreamChunk) error
	IngestResponse(*State, *schemas.BifrostResponse, *schemas.BifrostError) error
	FinalPrice(*State) error
	SanitizeResponse(*State) error
}

type DefaultAdapter struct{}

const meterAnthropicWebSearchCalls = "anthropic_web_search_calls"
const (
	anthropicOpus48MaxToolOverheadTokens   = 410
	anthropicSonnet46MaxToolOverheadTokens = 589
)

func AdapterFor(provider schemas.ModelProvider) Adapter {
	switch provider {
	case schemas.OpenAI:
		return OpenAIAdapter{DefaultAdapter: DefaultAdapter{}}
	case schemas.Anthropic:
		return AnthropicAdapter{DefaultAdapter: DefaultAdapter{}}
	default:
		return DefaultAdapter{}
	}
}

func (DefaultAdapter) ResolveDeployment(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	return nil
}

func (DefaultAdapter) ValidateRequest(state *State) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	if err := validateChatCompletionPolicy(state); err != nil {
		return err
	}
	return validateResponsesPolicy(state)
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
		if responsesStreamHasWebSearchCall(streamResp) {
			observeWebSearchEvent(state, responsesStreamEventKey(streamResp), responsesStreamWebSearchCallID(streamResp))
		}
		observeResponseWebSearchCalls(state, streamResp.Response)
		if streamResp.Response != nil && streamResp.Response.Usage != nil {
			observeActualExecution(state, streamResp.Response.ServiceTier, streamResp.Response.Speed)
			setSignalsFromUsage(state, streamResp.Response.Usage.ToBifrostLLMUsage())
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
	observeBifrostResponseWebSearchCalls(state, resp)
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

type OpenAIAdapter struct {
	DefaultAdapter
}

func (a OpenAIAdapter) ValidateRequest(state *State) error {
	if err := a.DefaultAdapter.ValidateRequest(state); err != nil {
		return err
	}
	return catalog.ProviderPolicyError(openaiadapter.ValidateRequest(openAIPolicyRequest(state)))
}

func (a OpenAIAdapter) EstimateHold(state *State) error {
	if err := a.DefaultAdapter.EstimateHold(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	extra := openaiadapter.ExtraHoldMeters(openAIPolicyRequestForDeployment(state, state.Resolution.Deployment), state.Resolution.OutputTokenLimit(), state.Resolution.InputTokenLimit())
	state.Hold.Meters = append(state.Hold.Meters, extra...)
	state.Hold.MaxUSDAtoms = sumMeterAmounts(state.Hold.Meters)
	return nil
}

func (a OpenAIAdapter) FinalPrice(state *State) error {
	if state == nil {
		return nil
	}
	extra := openaiadapter.ExtraSettlementMeters(openAIPolicyRequestForFinalPrice(state))
	state.FinalCostUSDAtoms = baseFinalPrice(state, extra)
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
		return responsesStreamWebSearchCallID(resp) != "" || resp.Type == schemas.ResponsesStreamResponseTypeWebSearchCallCompleted
	default:
		return false
	}
}

func observeBifrostResponseWebSearchCalls(state *State, resp *schemas.BifrostResponse) {
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

func openAIPolicyRequest(state *State) openaiadapter.PolicyRequest {
	return openAIPolicyRequestForDeployment(state, pricingDeploymentForState(state))
}

func openAIPolicyRequestForFinalPrice(state *State) openaiadapter.PolicyRequest {
	req := openAIPolicyRequestForDeployment(state, pricingDeploymentForState(state))
	req.ActualWebSearchCalls = billableHostedToolCalls(state)
	return req
}

func openAIPolicyRequestForDeployment(state *State, deployment catalog.Deployment) openaiadapter.PolicyRequest {
	if state == nil || state.Resolution == nil {
		return openaiadapter.PolicyRequest{}
	}
	resolution := state.Resolution
	return openaiadapter.PolicyRequest{
		Route: openaiadapter.Route(resolution.Route),
		Deployment: openaiadapter.Deployment{
			Model:               deployment.Model,
			ContextWindowTokens: deployment.ContextWindowTokens,
			Pricing:             deployment.Pricing,
			ReasoningSupported:  deployment.ReasoningSupported,
		},
		OutputTokenLimit:    resolution.OutputTokenLimit(),
		HasWebSearchOptions: resolution.HasWebSearchOptions(),
		SearchContextSize:   resolution.SearchContextSize(),
		ToolsParseFailed:    resolution.ToolsParseFailed(),
		RawBody:             resolution.RawBody(),
		ToolTypes:           resolution.ToolTypes(),
		RawTools:            resolution.RawTools(),
		ActualWebSearchCalls: actualWebSearchCalls(state),
	}
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

func billableHostedToolCalls(state *State) int {
	actual := actualWebSearchCalls(state)
	if actual <= 0 {
		return 0
	}
	allowed := hostedToolHoldQuantity(state)
	if allowed > 0 && actual > allowed {
		return allowed
	}
	return actual
}

type AnthropicAdapter struct {
	DefaultAdapter
}

func (a AnthropicAdapter) SanitizeRequest(state *State) error {
	if err := a.DefaultAdapter.SanitizeRequest(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	if anthropicFastSlug(state.Resolution.RequestedModel) {
		state.Resolution.SetProviderExtraParam("speed", "fast")
	}
	if state.Resolution.Deployment.RegionID == "us" {
		state.Resolution.SetProviderExtraParam("inference_geo", "us")
	}
	return nil
}

func anthropicFastSlug(model string) bool {
	parts := strings.Split(model, "/")
	slug := parts[len(parts)-1]
	return strings.Contains(slug, "-fast")
}

func (a AnthropicAdapter) EstimateHold(state *State) error {
	if err := a.DefaultAdapter.EstimateHold(state); err != nil {
		return err
	}
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	inputTokenLimit := state.Resolution.InputTokenLimit()
	if inputTokenLimit <= 0 {
		inputTokenLimit = 0
	} else {
		state.Hold.Meters = billing.AppendTokenMeterCost(state.Hold.Meters, state.Resolution.Deployment.Pricing, billing.MeterCacheWrite1hInputTokens, inputTokenLimit, true, true)
	}
	if overhead := anthropicToolSystemPromptHoldTokens(state); overhead > 0 {
		state.Hold.Meters = billing.AppendTokenMeterCost(state.Hold.Meters, state.Resolution.Deployment.Pricing, billing.MeterInputTokens, overhead, true, true)
		state.Hold.Meters = billing.AppendTokenMeterCost(state.Hold.Meters, state.Resolution.Deployment.Pricing, billing.MeterCacheWrite1hInputTokens, overhead, true, true)
	}
	if state.Resolution.Route == catalog.RouteResponses && resolutionUsesToolType(state, schemas.ResponsesToolTypeWebSearch) {
		state.Hold.Meters = billing.AppendCallMeterCost(state.Hold.Meters, state.Resolution.Deployment.Pricing, meterAnthropicWebSearchCalls, hostedToolHoldQuantity(state), true)
	}
	state.Hold.MaxUSDAtoms = sumMeterAmounts(state.Hold.Meters)
	return nil
}

func (a AnthropicAdapter) FinalPrice(state *State) error {
	if state == nil {
		return nil
	}
	extra := []catalog.MeterEstimate(nil)
	if state.Resolution != nil && state.Resolution.Route == catalog.RouteResponses && resolutionUsesToolType(state, schemas.ResponsesToolTypeWebSearch) {
		if calls := billableHostedToolCalls(state); calls > 0 {
			extra = billing.AppendCallMeterCost(extra, pricingDeploymentForState(state).Pricing, meterAnthropicWebSearchCalls, calls, false)
		}
	}
	state.FinalCostUSDAtoms = baseFinalPrice(state, extra)
	return nil
}

func hostedToolHoldQuantity(state *State) int {
	if state == nil || state.Resolution == nil {
		return 1
	}
	raw, ok := state.Resolution.RawBody()["max_tool_calls"]
	if !ok {
		return 1
	}
	var quantity int
	if err := schemas.Unmarshal(raw, &quantity); err != nil || quantity < 1 {
		return 1
	}
	return quantity
}

func anthropicToolSystemPromptHoldTokens(state *State) int {
	if state == nil || state.Resolution == nil || len(state.Resolution.ToolTypes()) == 0 {
		return 0
	}
	model := strings.ToLower(strings.TrimSpace(state.Resolution.Deployment.Model))
	switch {
	case strings.HasPrefix(model, "claude-opus-4-8"):
		return anthropicOpus48MaxToolOverheadTokens
	case strings.HasPrefix(model, "claude-sonnet-4-6"):
		return anthropicSonnet46MaxToolOverheadTokens
	default:
		return anthropicSonnet46MaxToolOverheadTokens
	}
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
