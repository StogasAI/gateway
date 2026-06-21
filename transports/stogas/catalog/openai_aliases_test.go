package catalog

import (
	"github.com/maximhq/bifrost/transports/stogas/providers"
	openaiadapter "github.com/maximhq/bifrost/transports/stogas/providers/openai"
)

const (
	meterOpenAIChatCompletionSearchModelCalls        = openaiadapter.MeterOpenAIChatCompletionSearchModelCalls
	meterOpenAIChatCompletionSearchPreviewModelCalls = openaiadapter.MeterOpenAIChatCompletionSearchPreviewModelCalls
	meterOpenAIResponsesWebSearchCalls               = openaiadapter.MeterOpenAIResponsesWebSearchCalls
	meterOpenAIResponsesWebSearchPreviewCalls        = openaiadapter.MeterOpenAIResponsesWebSearchPreviewCalls

	ratePerThousandSearchContextHighCalls   = openaiadapter.RatePerThousandSearchContextHighCalls
	ratePerThousandSearchContextLowCalls    = openaiadapter.RatePerThousandSearchContextLowCalls
	ratePerThousandSearchContextMediumCalls = openaiadapter.RatePerThousandSearchContextMediumCalls
)

func openAIWebSearchFixedContentInputTokensForRequest(model string, toolTypes []string) int {
	return openaiadapter.WebSearchFixedContentInputTokensForRequest(model, toolTypes)
}

func openAIWebSearchContentTokensBilledAtModelRates(deployment Deployment, pricing requestPricingContext) bool {
	return openaiadapter.WebSearchContentTokensBilledAtModelRates(providerRequestContext(pricing.Route, deployment, 0, pricing))
}

func openAIResponsesWebSearchCallMeter(deployment Deployment, pricing requestPricingContext) string {
	return openaiadapter.ResponsesWebSearchCallMeter(providers.RequestContext{
		Route: providers.Route(pricing.Route),
		Deployment: providers.Deployment{
			Model:               deployment.Model,
			ContextWindowTokens: deployment.ContextWindowTokens,
			Pricing:             providers.Pricing(deployment.Pricing),
			ReasoningSupported:  deployment.ReasoningSupported,
		},
		SearchContextSize: pricing.SearchContextSize,
		ToolTypes:         pricing.ToolTypes,
	})
}
