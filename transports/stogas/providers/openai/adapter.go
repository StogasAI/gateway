package openai

import (
	"encoding/json"
	"math/big"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/transports/stogas/providers"
)

const (
	webSearchFixedContentInputTokens = 8000
	searchCallQuantity               = 1

	MeterOpenAIChatCompletionSearchModelCalls        = "openai_chat_completion_search_model_calls"
	MeterOpenAIChatCompletionSearchPreviewModelCalls = "openai_chat_completion_search_preview_model_calls"
	MeterOpenAIResponsesWebSearchCalls               = "openai_responses_web_search_calls"
	MeterOpenAIResponsesWebSearchPreviewCalls        = "openai_responses_web_search_preview_calls"

	RatePerThousandSearchContextHighCalls   = "per_1k_search_context_high_calls"
	RatePerThousandSearchContextLowCalls    = "per_1k_search_context_low_calls"
	RatePerThousandSearchContextMediumCalls = "per_1k_search_context_medium_calls"
)

type Adapter struct{}

func (Adapter) ValidateRequest(ctx providers.RequestContext) error {
	if ctx.OutputTokenLimit > 0 && ctx.OutputTokenLimit < 16 {
		return providers.ErrOutputTokenLimitTooLow
	}
	if err := validateRequestInput(ctx); err != nil {
		return err
	}
	if ctx.Route == providers.RouteResponses && ctx.HasWebSearchOptions {
		return providers.ErrUnsupportedParameter
	}
	if ctx.Route == providers.RouteChat && ctx.HasWebSearchOptions {
		if meterKey, _ := chatSearchMeter(ctx); meterKey == "" {
			return providers.ErrUnsupportedParameter
		}
	}
	if ctx.ToolsParseFailed {
		return providers.ErrInvalidProviderToolSpec
	}
	for _, tool := range ctx.RawTools {
		if err := validateTool(ctx.Route, tool); err != nil {
			return err
		}
	}
	return nil
}

func (Adapter) ExtraHoldMeters(ctx providers.RequestContext, outputTokenLimit int, inputTokenLimit int) []providers.MeterEstimate {
	meters := []providers.MeterEstimate{}
	if fixedContentTokens := webSearchFixedContentTokens(ctx.Deployment.Model, ctx.ToolTypes); fixedContentTokens > 0 {
		meters = providers.AppendTokenMeterCost(meters, ctx.Deployment.Pricing, providers.MeterInputTokens, fixedContentTokens, true, true)
	}
	if webSearchContentTokensBilledAtModelRates(ctx) && ctx.Deployment.ContextWindowTokens > 0 {
		remainingInputTokens := ctx.Deployment.ContextWindowTokens - outputTokenLimit - inputTokenLimit
		meters = providers.AppendTokenMeterCost(meters, ctx.Deployment.Pricing, providers.MeterInputTokens, remainingInputTokens, true, true)
	}
	if meterKey, rateKey := chatSearchMeter(ctx); meterKey != "" {
		meters = providers.AppendCallMeterCostWithRate(meters, ctx.Deployment.Pricing, meterKey, rateKey, searchCallQuantity, true)
	}
	if meterKey := responsesSearchMeter(ctx); meterKey != "" {
		meters = providers.AppendCallMeterCost(meters, ctx.Deployment.Pricing, meterKey, searchCallQuantity, true)
	}
	return meters
}

func (Adapter) ExtraSettlementMeters(ctx providers.RequestContext) []providers.MeterEstimate {
	meters := []providers.MeterEstimate{}
	if fixedContentTokens := webSearchFixedContentTokens(ctx.Deployment.Model, ctx.ToolTypes); fixedContentTokens > 0 {
		meters = providers.AppendTokenMeterCost(meters, ctx.Deployment.Pricing, providers.MeterInputTokens, fixedContentTokens, false, true)
	}
	if meterKey, rateKey := chatSearchMeter(ctx); meterKey != "" {
		meters = providers.AppendCallMeterCostWithRate(meters, ctx.Deployment.Pricing, meterKey, rateKey, searchCallQuantity, false)
	}
	if meterKey := responsesSearchMeter(ctx); meterKey != "" {
		meters = providers.AppendCallMeterCost(meters, ctx.Deployment.Pricing, meterKey, searchCallQuantity, false)
	}
	return meters
}

func (Adapter) AllowUpstreamRequestHeader(providers.HeaderContext) bool {
	return false
}

func (Adapter) FilterProviderResponseHeaders(providers.HeaderContext, map[string]string) map[string]string {
	return nil
}

func validateRequestInput(ctx providers.RequestContext) error {
	switch ctx.Route {
	case providers.RouteChat:
		return validateChatInput(ctx.RawBody["messages"])
	case providers.RouteResponses:
		return validateResponsesInput(ctx.RawBody["input"])
	default:
		return nil
	}
}

func validateChatInput(raw json.RawMessage) error {
	return walkRawJSON(raw, func(object map[string]json.RawMessage) error {
		switch rawStringField(object, "type") {
		case "file", "image_url", "input_audio":
			return providers.ErrUnsupportedInput
		default:
			return nil
		}
	})
}

func validateResponsesInput(raw json.RawMessage) error {
	return walkRawJSON(raw, func(object map[string]json.RawMessage) error {
		switch rawStringField(object, "type") {
		case "input_image", "input_audio":
			return providers.ErrUnsupportedInput
		case "input_file":
			if _, ok := object["file_id"]; ok {
				return providers.ErrUnsupportedInput
			}
		}
		return nil
	})
}

func walkRawJSON(raw json.RawMessage, visit func(map[string]json.RawMessage) error) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	switch trimmed[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := sonic.Unmarshal(raw, &object); err != nil {
			return providers.ErrUnsupportedInput
		}
		if err := visit(object); err != nil {
			return err
		}
		for _, child := range object {
			if err := walkRawJSON(child, visit); err != nil {
				return err
			}
		}
	case '[':
		var array []json.RawMessage
		if err := sonic.Unmarshal(raw, &array); err != nil {
			return providers.ErrUnsupportedInput
		}
		for _, child := range array {
			if err := walkRawJSON(child, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTool(route providers.Route, tool map[string]json.RawMessage) error {
	toolType := rawStringField(tool, "type")
	switch {
	case toolType == "":
		return providers.ErrInvalidProviderToolSpec
	case toolType == "function", toolType == "local_shell", toolType == "apply_patch":
		return nil
	case toolType == "shell":
		return validateShellTool(tool)
	case route == providers.RouteResponses && webSearchToolKind(toolType) != "":
		return nil
	default:
		return providers.ErrUnsupportedTool
	}
}

func validateShellTool(tool map[string]json.RawMessage) error {
	rawEnvironment, ok := tool["environment"]
	if !ok {
		return providers.ErrProviderContainers
	}
	var environment map[string]json.RawMessage
	if err := sonic.Unmarshal(rawEnvironment, &environment); err != nil {
		return providers.ErrInvalidProviderToolSpec
	}
	if rawStringField(environment, "type") != "local" {
		return providers.ErrProviderContainers
	}
	if !onlyKeys(tool, "type", "environment") || !onlyKeys(environment, "type") {
		return providers.ErrUnsupportedTool
	}
	return nil
}

func chatSearchMeter(ctx providers.RequestContext) (string, string) {
	normalized := strings.ToLower(strings.TrimSpace(ctx.Deployment.Model))
	meterKey := ""
	switch {
	case normalized == "gpt-5-search-api" || strings.HasPrefix(normalized, "gpt-5-search-api-") && hasDateSuffix(normalized):
		meterKey = MeterOpenAIChatCompletionSearchModelCalls
	case normalized == "gpt-4o-search-preview" || strings.HasPrefix(normalized, "gpt-4o-search-preview-") && hasDateSuffix(normalized):
		meterKey = MeterOpenAIChatCompletionSearchPreviewModelCalls
	case normalized == "gpt-4o-mini-search-preview" || strings.HasPrefix(normalized, "gpt-4o-mini-search-preview-") && hasDateSuffix(normalized):
		meterKey = MeterOpenAIChatCompletionSearchPreviewModelCalls
	}
	if meterKey == "" {
		return "", ""
	}
	return meterKey, searchContextRateKey(ctx.Deployment.Pricing, meterKey, ctx.SearchContextSize)
}

func responsesSearchMeter(ctx providers.RequestContext) string {
	if ctx.Route != providers.RouteResponses {
		return ""
	}
	usesWebSearch := usesWebSearchKind(ctx.ToolTypes, "web_search")
	usesPreview := usesWebSearchKind(ctx.ToolTypes, "web_search_preview")
	switch {
	case usesWebSearch && usesPreview:
		return higherCallRateMeter(ctx.Deployment.Pricing, MeterOpenAIResponsesWebSearchCalls, MeterOpenAIResponsesWebSearchPreviewCalls)
	case usesPreview:
		return MeterOpenAIResponsesWebSearchPreviewCalls
	case usesWebSearch:
		return MeterOpenAIResponsesWebSearchCalls
	default:
		return ""
	}
}

func webSearchContentTokensBilledAtModelRates(ctx providers.RequestContext) bool {
	if ctx.Route != providers.RouteResponses {
		return false
	}
	if usesWebSearchKind(ctx.ToolTypes, "web_search") && webSearchFixedContentTokens(ctx.Deployment.Model, ctx.ToolTypes) == 0 {
		return true
	}
	return usesWebSearchKind(ctx.ToolTypes, "web_search_preview") && ctx.Deployment.ReasoningSupported
}

func webSearchFixedContentTokens(model string, toolTypes []string) int {
	if !usesWebSearchKind(toolTypes, "web_search") {
		return 0
	}
	normalized := strings.ToLower(strings.TrimSpace(model))
	if strings.HasPrefix(normalized, "gpt-4.1-mini") || strings.HasPrefix(normalized, "gpt-4o-mini") && !strings.Contains(normalized, "search-preview") {
		return webSearchFixedContentInputTokens
	}
	return 0
}

func usesWebSearchKind(toolTypes []string, kind string) bool {
	for _, toolType := range toolTypes {
		if webSearchToolKind(toolType) == kind {
			return true
		}
	}
	return false
}

func webSearchToolKind(toolType string) string {
	normalized := strings.ToLower(strings.TrimSpace(toolType))
	switch {
	case normalized == "web_search" || strings.HasPrefix(normalized, "web_search_") && !strings.HasPrefix(normalized, "web_search_preview"):
		return "web_search"
	case normalized == "web_search_preview" || strings.HasPrefix(normalized, "web_search_preview_"):
		return "web_search_preview"
	default:
		return ""
	}
}

func searchContextRateKey(pricing providers.Pricing, meterKey string, searchContextSize string) string {
	meter, ok := pricing[meterKey]
	if !ok {
		return providers.RatePerThousandCalls
	}
	switch strings.ToLower(strings.TrimSpace(searchContextSize)) {
	case "low":
		if _, ok := meter[RatePerThousandSearchContextLowCalls]; ok {
			return RatePerThousandSearchContextLowCalls
		}
	case "high":
		if _, ok := meter[RatePerThousandSearchContextHighCalls]; ok {
			return RatePerThousandSearchContextHighCalls
		}
	case "medium", "":
		if _, ok := meter[RatePerThousandSearchContextMediumCalls]; ok {
			return RatePerThousandSearchContextMediumCalls
		}
	}
	if _, ok := meter[providers.RatePerThousandCalls]; ok {
		return providers.RatePerThousandCalls
	}
	if _, ok := meter[RatePerThousandSearchContextHighCalls]; ok {
		return RatePerThousandSearchContextHighCalls
	}
	if _, ok := meter[RatePerThousandSearchContextMediumCalls]; ok {
		return RatePerThousandSearchContextMediumCalls
	}
	return RatePerThousandSearchContextLowCalls
}

func higherCallRateMeter(pricing providers.Pricing, first string, second string) string {
	firstRate := callRate(pricing, first)
	secondRate := callRate(pricing, second)
	if secondRate != nil && (firstRate == nil || secondRate.Cmp(firstRate) >= 0) {
		return second
	}
	if firstRate != nil {
		return first
	}
	return ""
}

func callRate(pricing providers.Pricing, meterKey string) *big.Int {
	meter, ok := pricing[meterKey]
	if !ok {
		return nil
	}
	rate, ok := providers.ParseRate(meter[providers.RatePerThousandCalls])
	if !ok {
		return nil
	}
	return rate
}

func rawStringField(object map[string]json.RawMessage, key string) string {
	raw, ok := object[key]
	if !ok {
		return ""
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func onlyKeys(object map[string]json.RawMessage, allowed ...string) bool {
	allowedSet := map[string]bool{}
	for _, key := range allowed {
		allowedSet[strings.ToLower(strings.TrimSpace(key))] = true
	}
	for key := range object {
		if !allowedSet[strings.ToLower(strings.TrimSpace(key))] {
			return false
		}
	}
	return true
}

func hasDateSuffix(value string) bool {
	if len(value) < len("2006-01-02") {
		return false
	}
	suffix := value[len(value)-len("2006-01-02"):]
	for i, char := range suffix {
		switch i {
		case 4, 7:
			if char != '-' {
				return false
			}
		default:
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func WebSearchFixedContentInputTokensForRequest(model string, toolTypes []string) int {
	return webSearchFixedContentTokens(model, toolTypes)
}

func WebSearchContentTokensBilledAtModelRates(ctx providers.RequestContext) bool {
	return webSearchContentTokensBilledAtModelRates(ctx)
}

func ResponsesWebSearchCallMeter(ctx providers.RequestContext) string {
	return responsesSearchMeter(ctx)
}
