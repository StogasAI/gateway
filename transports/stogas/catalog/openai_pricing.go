package catalog

import (
	"math/big"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

const openAIWebSearchFixedContentInputTokens = 8000
const openAISearchModelCallQuantity = 1

const (
	meterOpenAIChatCompletionSearchModelCalls        = "openai_chat_completion_search_model_calls"
	meterOpenAIChatCompletionSearchPreviewModelCalls = "openai_chat_completion_search_preview_model_calls"
	meterOpenAIResponsesWebSearchCalls               = "openai_responses_web_search_calls"
	meterOpenAIResponsesWebSearchPreviewCalls        = "openai_responses_web_search_preview_calls"

	ratePerThousandSearchContextHighCalls   = "per_1k_search_context_high_calls"
	ratePerThousandSearchContextLowCalls    = "per_1k_search_context_low_calls"
	ratePerThousandSearchContextMediumCalls = "per_1k_search_context_medium_calls"
)

func appendProviderHoldMeterCosts(meters []MeterEstimate, provider schemas.ModelProvider, deployment Deployment, outputTokenLimit int, inputTokenLimit int, pricingContext requestPricingContext) []MeterEstimate {
	if provider != schemas.OpenAI {
		return meters
	}
	meters = appendOpenAIWebSearchFixedContentInputMeters(meters, deployment, pricingContext, true)
	meters = appendOpenAIWebSearchUnknownContentHoldMeter(meters, deployment, outputTokenLimit, inputTokenLimit, pricingContext)
	meters = appendOpenAIChatSearchModelCallMeter(meters, deployment, pricingContext, true)
	return appendOpenAIResponsesWebSearchCallMeter(meters, deployment, pricingContext, true)
}

func appendProviderSettlementMeterCosts(meters []MeterEstimate, resolution *ResolvedRequest) []MeterEstimate {
	if resolution == nil || resolution.Provider != schemas.OpenAI {
		return meters
	}
	meters = appendOpenAIWebSearchFixedContentInputMeters(meters, resolution.Deployment, resolution.pricing, false)
	meters = appendOpenAIChatSearchModelCallMeter(meters, resolution.Deployment, resolution.pricing, false)
	return appendOpenAIResponsesWebSearchCallMeter(meters, resolution.Deployment, resolution.pricing, false)
}

func appendOpenAIWebSearchFixedContentInputMeters(meters []MeterEstimate, deployment Deployment, pricingContext requestPricingContext, holdRequired bool) []MeterEstimate {
	if openAIWebSearchFixedContentInputTokensForRequest(deployment.Model, pricingContext.ToolTypes) == 0 {
		return meters
	}
	return appendMeterCost(meters, deployment.Pricing, meterInputTokens, openAIWebSearchFixedContentInputTokens, holdRequired, true)
}

func appendOpenAIWebSearchUnknownContentHoldMeter(meters []MeterEstimate, deployment Deployment, outputTokenLimit int, inputTokenLimit int, pricingContext requestPricingContext) []MeterEstimate {
	if !openAIWebSearchContentTokensBilledAtModelRates(deployment, pricingContext) {
		return meters
	}
	if deployment.ContextWindowTokens <= 0 {
		return meters
	}
	remainingInputTokens := deployment.ContextWindowTokens - outputTokenLimit - inputTokenLimit
	if remainingInputTokens <= 0 {
		return meters
	}
	return appendMeterCost(meters, deployment.Pricing, meterInputTokens, remainingInputTokens, true, true)
}

func appendOpenAIChatSearchModelCallMeter(meters []MeterEstimate, deployment Deployment, pricingContext requestPricingContext, holdRequired bool) []MeterEstimate {
	meterKey := openAISearchModelCallMeter(deployment.Model)
	if meterKey == "" {
		return meters
	}
	rateKey := openAISearchModelCallRateKey(deployment.Pricing, meterKey, pricingContext.SearchContextSize)
	return appendCallMeterCostWithRate(meters, deployment.Pricing, meterKey, rateKey, openAISearchModelCallQuantity, holdRequired)
}

func appendOpenAIResponsesWebSearchCallMeter(meters []MeterEstimate, deployment Deployment, pricingContext requestPricingContext, holdRequired bool) []MeterEstimate {
	meterKey := openAIResponsesWebSearchCallMeter(deployment, pricingContext)
	if meterKey == "" {
		return meters
	}
	return appendCallMeterCost(meters, deployment.Pricing, meterKey, openAISearchModelCallQuantity, holdRequired)
}

func openAISearchModelCallMeter(model string) string {
	normalized := strings.ToLower(strings.TrimSpace(model))
	switch {
	case normalized == "gpt-5-search-api" || (strings.HasPrefix(normalized, "gpt-5-search-api-") && hasDateSuffix(normalized)):
		return meterOpenAIChatCompletionSearchModelCalls
	case normalized == "gpt-4o-search-preview" || (strings.HasPrefix(normalized, "gpt-4o-search-preview-") && hasDateSuffix(normalized)):
		return meterOpenAIChatCompletionSearchPreviewModelCalls
	case normalized == "gpt-4o-mini-search-preview" || (strings.HasPrefix(normalized, "gpt-4o-mini-search-preview-") && hasDateSuffix(normalized)):
		return meterOpenAIChatCompletionSearchPreviewModelCalls
	default:
		return ""
	}
}

func openAIWebSearchFixedContentInputTokensForRequest(model string, toolTypes []string) int {
	if !openAIUsesNonPreviewWebSearch(toolTypes) || !openAIModelUsesFixedWebSearchContentTokens(model) {
		return 0
	}
	return openAIWebSearchFixedContentInputTokens
}

func openAIResponsesWebSearchCallMeter(deployment Deployment, pricingContext requestPricingContext) string {
	if pricingContext.Route != RouteResponses {
		return ""
	}
	usesWebSearch := openAIUsesNonPreviewWebSearch(pricingContext.ToolTypes)
	usesPreview := openAIUsesPreviewWebSearch(pricingContext.ToolTypes)
	switch {
	case usesWebSearch && usesPreview:
		return highestOpenAIResponsesSearchCallMeter(deployment.Pricing)
	case usesPreview:
		return meterOpenAIResponsesWebSearchPreviewCalls
	case usesWebSearch:
		return meterOpenAIResponsesWebSearchCalls
	default:
		return ""
	}
}

func highestOpenAIResponsesSearchCallMeter(pricing Pricing) string {
	webSearchRate := callRate(pricing, meterOpenAIResponsesWebSearchCalls)
	previewRate := callRate(pricing, meterOpenAIResponsesWebSearchPreviewCalls)
	if previewRate != nil && (webSearchRate == nil || previewRate.Cmp(webSearchRate) >= 0) {
		return meterOpenAIResponsesWebSearchPreviewCalls
	}
	if webSearchRate != nil {
		return meterOpenAIResponsesWebSearchCalls
	}
	return ""
}

func callRate(pricing Pricing, meterKey string) *big.Int {
	meter, ok := pricing[meterKey]
	if !ok {
		return nil
	}
	rate, ok := parseRate(meter[ratePerThousandCalls])
	if !ok {
		return nil
	}
	return rate
}

func openAISearchModelCallRateKey(pricing Pricing, meterKey string, searchContextSize string) string {
	meter, ok := pricing[meterKey]
	if !ok {
		return ratePerThousandCalls
	}
	switch strings.ToLower(strings.TrimSpace(searchContextSize)) {
	case "low":
		if _, ok := meter[ratePerThousandSearchContextLowCalls]; ok {
			return ratePerThousandSearchContextLowCalls
		}
	case "high":
		if _, ok := meter[ratePerThousandSearchContextHighCalls]; ok {
			return ratePerThousandSearchContextHighCalls
		}
	case "medium", "":
		if _, ok := meter[ratePerThousandSearchContextMediumCalls]; ok {
			return ratePerThousandSearchContextMediumCalls
		}
	}
	if _, ok := meter[ratePerThousandCalls]; ok {
		return ratePerThousandCalls
	}
	if _, ok := meter[ratePerThousandSearchContextHighCalls]; ok {
		return ratePerThousandSearchContextHighCalls
	}
	if _, ok := meter[ratePerThousandSearchContextMediumCalls]; ok {
		return ratePerThousandSearchContextMediumCalls
	}
	return ratePerThousandSearchContextLowCalls
}

func openAIWebSearchContentTokensBilledAtModelRates(deployment Deployment, pricingContext requestPricingContext) bool {
	if pricingContext.Route != RouteResponses {
		return false
	}
	if openAIUsesNonPreviewWebSearch(pricingContext.ToolTypes) && openAIWebSearchFixedContentInputTokensForRequest(deployment.Model, pricingContext.ToolTypes) == 0 {
		return true
	}
	if openAIUsesPreviewWebSearch(pricingContext.ToolTypes) && deployment.ReasoningSupported {
		return true
	}
	return false
}

func openAIUsesNonPreviewWebSearch(toolTypes []string) bool {
	for _, toolType := range toolTypes {
		normalized := strings.ToLower(strings.TrimSpace(toolType))
		if normalized == "web_search" || strings.HasPrefix(normalized, "web_search_") && !strings.HasPrefix(normalized, "web_search_preview") {
			return true
		}
	}
	return false
}

func openAIUsesPreviewWebSearch(toolTypes []string) bool {
	for _, toolType := range toolTypes {
		normalized := strings.ToLower(strings.TrimSpace(toolType))
		if normalized == "web_search_preview" || strings.HasPrefix(normalized, "web_search_preview_") {
			return true
		}
	}
	return false
}

func openAIModelUsesFixedWebSearchContentTokens(model string) bool {
	normalized := strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(normalized, "gpt-4o-mini") && !strings.Contains(normalized, "search-preview") ||
		strings.HasPrefix(normalized, "gpt-4.1-mini")
}
