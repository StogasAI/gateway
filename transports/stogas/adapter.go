package stogas

import (
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
		setSignalsFromUsage(state, chunk.BifrostChatResponse.Usage)
	case chunk.BifrostResponsesStreamResponse != nil:
		state.Response = &schemas.BifrostResponse{ResponsesStreamResponse: chunk.BifrostResponsesStreamResponse}
		if chunk.BifrostResponsesStreamResponse.Type == schemas.ResponsesStreamResponseTypeWebSearchCallCompleted {
			incrementWebSearchSignals(state)
		}
		if responseWebSearchCalls(chunk.BifrostResponsesStreamResponse.Response) > 0 {
			setWebSearchSignals(state, responseWebSearchCalls(chunk.BifrostResponsesStreamResponse.Response))
		}
		if chunk.BifrostResponsesStreamResponse.Response != nil && chunk.BifrostResponsesStreamResponse.Response.Usage != nil {
			setSignalsFromUsage(state, chunk.BifrostResponsesStreamResponse.Response.Usage.ToBifrostLLMUsage())
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
	setSignalsFromUsage(state, billing.LLMUsage(resp))
	if count := bifrostResponseWebSearchCalls(resp); count > 0 {
		setWebSearchSignals(state, count)
	}
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
	extra := openaiadapter.ExtraHoldMeters(openAIPolicyRequest(state), state.Resolution.OutputTokenLimit(), state.Resolution.InputTokenLimit())
	state.Hold.Meters = append(state.Hold.Meters, extra...)
	state.Hold.MaxUSDAtoms = sumMeterAmounts(state.Hold.Meters)
	return nil
}

func (a OpenAIAdapter) FinalPrice(state *State) error {
	if state == nil {
		return nil
	}
	extra := openaiadapter.ExtraSettlementMeters(openAIPolicyRequest(state))
	state.FinalCostUSDAtoms = baseFinalPrice(state, extra)
	return nil
}

func setWebSearchSignals(state *State, count int) {
	if state == nil || count <= 0 {
		return
	}
	signals, ok := state.Signals.(*StandardSignals)
	if !ok || signals == nil {
		signals = &StandardSignals{}
		state.Signals = signals
	}
	if count > signals.WebSearch {
		signals.WebSearch = count
	}
}

func bifrostResponseWebSearchCalls(resp *schemas.BifrostResponse) int {
	if resp == nil {
		return 0
	}
	switch {
	case resp.ResponsesResponse != nil:
		return responseWebSearchCalls(resp.ResponsesResponse)
	case resp.ResponsesStreamResponse != nil:
		return responseWebSearchCalls(resp.ResponsesStreamResponse.Response)
	default:
		return 0
	}
}

func responseWebSearchCalls(resp *schemas.BifrostResponsesResponse) int {
	if resp == nil {
		return 0
	}
	usageCount := 0
	if resp.Usage != nil && resp.Usage.OutputTokensDetails != nil && resp.Usage.OutputTokensDetails.NumSearchQueries != nil {
		usageCount = *resp.Usage.OutputTokensDetails.NumSearchQueries
	}
	outputCount := 0
	for _, item := range resp.Output {
		if item.Type != nil && *item.Type == schemas.ResponsesMessageTypeWebSearchCall {
			outputCount++
		}
	}
	if outputCount > usageCount {
		return outputCount
	}
	return usageCount
}

func openAIPolicyRequest(state *State) openaiadapter.PolicyRequest {
	if state == nil || state.Resolution == nil {
		return openaiadapter.PolicyRequest{}
	}
	resolution := state.Resolution
	return openaiadapter.PolicyRequest{
		Route: openaiadapter.Route(resolution.Route),
		Deployment: openaiadapter.Deployment{
			Model:               resolution.Deployment.Model,
			ContextWindowTokens: resolution.Deployment.ContextWindowTokens,
			Pricing:             resolution.Deployment.Pricing,
			ReasoningSupported:  resolution.Deployment.ReasoningSupported,
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
		return nil
	}
	state.Hold.Meters = billing.AppendTokenMeterCost(state.Hold.Meters, state.Resolution.Deployment.Pricing, billing.MeterCacheWrite1hInputTokens, inputTokenLimit, true, true)
	state.Hold.MaxUSDAtoms = sumMeterAmounts(state.Hold.Meters)
	return nil
}
