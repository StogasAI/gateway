package openai

import (
	"encoding/json"
	"math/big"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/providers"
)

const (
	RouteChat      Route = "chat-completions"
	RouteResponses Route = "responses"

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

type Route string

type Deployment struct {
	Model               string
	ContextWindowTokens int
	Pricing             providers.Pricing
	ReasoningSupported  bool
}

type PolicyRequest struct {
	Route               Route
	Deployment          Deployment
	OutputTokenLimit    int
	HasWebSearchOptions bool
	SearchContextSize   string
	ToolsParseFailed    bool
	RawBody             map[string]json.RawMessage
	ToolTypes           []string
	RawTools            []map[string]json.RawMessage
	ActualWebSearchCalls int
}

func ValidateRequest(req PolicyRequest) error {
	if err := validateOutputTokensMin16(req); err != nil {
		return err
	}
	if err := validateReasoningSupport(req); err != nil {
		return err
	}
	switch req.Route {
	case RouteChat:
		if err := validateChatTextOnlyMVP(req); err != nil {
			return err
		}
		if err := validateChatNoHostedTools(req); err != nil {
			return err
		}
		if err := validateChatSearchModelWebSearchOptions(req); err != nil {
			return err
		}
	case RouteResponses:
		if err := validateResponsesTextOnlyMVP(req); err != nil {
			return err
		}
		if err := validateResponsesNoUnbilledHostedTools(req); err != nil {
			return err
		}
	}
	return nil
}

func validateReasoningSupport(req PolicyRequest) error {
	if req.Deployment.ReasoningSupported {
		return nil
	}
	for _, name := range []string{"reasoning", "reasoning_effort", "reasoning_max_tokens", "reasoning_display", "reasoning.effort"} {
		if _, ok := req.RawBody[name]; ok {
			return providers.ErrUnsupportedParameter
		}
	}
	return nil
}

func ExtraHoldMeters(req PolicyRequest, outputTokenLimit int, inputTokenLimit int) []providers.MeterEstimate {
	meters := []providers.MeterEstimate{}
	if req.Route == RouteResponses {
		meters = append(meters, extraResponsesHostedToolHoldMeters(req, outputTokenLimit, inputTokenLimit)...)
	}
	if req.Route == RouteChat {
		meters = append(meters, extraChatSearchModelHoldMeters(req, outputTokenLimit, inputTokenLimit)...)
	}
	return meters
}

func ExtraSettlementMeters(req PolicyRequest) []providers.MeterEstimate {
	meters := []providers.MeterEstimate{}
	if req.Route == RouteResponses {
		meters = append(meters, extraResponsesHostedToolSettlementMeters(req)...)
	}
	if req.Route == RouteChat {
		meters = append(meters, extraChatSearchModelSettlementMeters(req)...)
	}
	return meters
}

func validateOutputTokensMin16(req PolicyRequest) error {
	if req.OutputTokenLimit > 0 && req.OutputTokenLimit < 16 {
		return providers.ErrOutputTokenLimitTooLow
	}
	return nil
}

func validateChatTextOnlyMVP(req PolicyRequest) error {
	if req.Route != RouteChat {
		return nil
	}
	return validateChatInput(req.RawBody["messages"])
}

func validateResponsesTextOnlyMVP(req PolicyRequest) error {
	if req.Route != RouteResponses {
		return nil
	}
	return validateResponsesInput(req.RawBody["input"])
}

func validateChatNoHostedTools(req PolicyRequest) error {
	if req.Route != RouteChat {
		return nil
	}
	return validateHostedTools(req)
}

func validateResponsesNoUnbilledHostedTools(req PolicyRequest) error {
	if req.Route != RouteResponses {
		return nil
	}
	return validateHostedTools(req)
}

func validateHostedTools(req PolicyRequest) error {
	if req.ToolsParseFailed {
		return providers.ErrInvalidProviderToolSpec
	}
	for _, tool := range req.RawTools {
		if err := validateTool(req.Route, tool); err != nil {
			return err
		}
	}
	return nil
}

func validateChatSearchModelWebSearchOptions(req PolicyRequest) error {
	if req.Route != RouteChat || !req.HasWebSearchOptions {
		return nil
	}
	if meterKey, _ := chatSearchMeter(req); meterKey == "" {
		return providers.ErrUnsupportedParameter
	}
	return nil
}

func extraResponsesHostedToolHoldMeters(req PolicyRequest, outputTokenLimit int, inputTokenLimit int) []providers.MeterEstimate {
	meters := []providers.MeterEstimate{}
	quantity := responsesHostedToolHoldQuantity(req)
	searchKind := responsesSearchKind(req)
	if fixedContentTokens := webSearchFixedContentTokensForKind(req.Deployment.Model, searchKind); fixedContentTokens > 0 {
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, billing.MeterInputTokens, fixedContentTokens*quantity, true, true)
	}
	if webSearchContentTokensBilledAtModelRatesForKind(req, searchKind) && req.Deployment.ContextWindowTokens > 0 {
		remainingInputTokens := req.Deployment.ContextWindowTokens - outputTokenLimit - inputTokenLimit
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, billing.MeterInputTokens, remainingInputTokens, true, true)
	}
	if meterKey := responsesSearchMeterForKind(searchKind); meterKey != "" {
		meters = billing.AppendCallMeterCost(meters, req.Deployment.Pricing, meterKey, quantity, true)
	}
	return meters
}

func extraResponsesHostedToolSettlementMeters(req PolicyRequest) []providers.MeterEstimate {
	meters := []providers.MeterEstimate{}
	quantity := req.ActualWebSearchCalls
	if quantity <= 0 {
		return meters
	}
	searchKind := responsesSearchKind(req)
	if fixedContentTokens := webSearchFixedContentTokensForKind(req.Deployment.Model, searchKind); fixedContentTokens > 0 {
		meters = billing.AppendTokenMeterCost(meters, req.Deployment.Pricing, billing.MeterInputTokens, fixedContentTokens*quantity, false, true)
	}
	if meterKey := responsesSearchMeterForKind(searchKind); meterKey != "" {
		meters = billing.AppendCallMeterCost(meters, req.Deployment.Pricing, meterKey, quantity, false)
	}
	return meters
}

func extraChatSearchModelHoldMeters(req PolicyRequest, _ int, _ int) []providers.MeterEstimate {
	if meterKey, rateKey := chatSearchMeter(req); meterKey != "" {
		return billing.AppendCallMeterCostWithRate(nil, req.Deployment.Pricing, meterKey, rateKey, searchCallQuantity, true)
	}
	return nil
}

func extraChatSearchModelSettlementMeters(req PolicyRequest) []providers.MeterEstimate {
	if meterKey, rateKey := chatSearchMeter(req); meterKey != "" {
		return billing.AppendCallMeterCostWithRate(nil, req.Deployment.Pricing, meterKey, rateKey, searchCallQuantity, false)
	}
	return nil
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
			return providers.ErrUnsupportedInput
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

func validateTool(route Route, tool map[string]json.RawMessage) error {
	toolType := rawStringField(tool, "type")
	if route == RouteResponses {
		raw, err := sonic.Marshal(tool)
		if err != nil {
			return providers.ErrInvalidProviderToolSpec
		}
		var responsesTool schemas.ResponsesTool
		if err := sonic.Unmarshal(raw, &responsesTool); err != nil {
			return providers.ErrInvalidProviderToolSpec
		}
		switch responsesTool.Type {
		case schemas.ResponsesToolTypeFunction,
			schemas.ResponsesToolTypeCustom,
			schemas.ResponsesToolTypeLocalShell,
			schemas.ResponsesToolTypeApplyPatch,
			schemas.ResponsesToolTypeWebSearch,
			schemas.ResponsesToolTypeWebSearchPreview:
			return nil
		case schemas.ResponsesToolTypeShell:
			return validateShellTool(tool)
		default:
			return providers.ErrUnsupportedTool
		}
	}
	if route == RouteChat {
		switch toolType {
		case "":
			return providers.ErrInvalidProviderToolSpec
		case "function", "custom":
			return nil
		default:
			return providers.ErrUnsupportedTool
		}
	}
	switch {
	case toolType == "":
		return providers.ErrInvalidProviderToolSpec
	case toolType == "function", toolType == "local_shell", toolType == "apply_patch":
		return nil
	case toolType == "shell":
		return validateShellTool(tool)
	default:
		return providers.ErrUnsupportedTool
	}
}

func responsesHostedToolHoldQuantity(req PolicyRequest) int {
	if req.Route != RouteResponses {
		return searchCallQuantity
	}
	raw, ok := req.RawBody["max_tool_calls"]
	if !ok {
		return searchCallQuantity
	}
	var quantity int
	if err := sonic.Unmarshal(raw, &quantity); err != nil || quantity < searchCallQuantity {
		return searchCallQuantity
	}
	return quantity
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

func chatSearchMeter(ctx PolicyRequest) (string, string) {
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

func responsesSearchMeter(ctx PolicyRequest) string {
	return responsesSearchMeterForKind(responsesSearchKind(ctx))
}

func responsesSearchMeterForKind(kind string) string {
	switch kind {
	case "web_search_preview":
		return MeterOpenAIResponsesWebSearchPreviewCalls
	case "web_search":
		return MeterOpenAIResponsesWebSearchCalls
	default:
		return ""
	}
}

func responsesSearchKind(ctx PolicyRequest) string {
	if ctx.Route != RouteResponses {
		return ""
	}
	usesWebSearch := usesWebSearchKind(ctx.ToolTypes, "web_search")
	usesPreview := usesWebSearchKind(ctx.ToolTypes, "web_search_preview")
	switch {
	case usesWebSearch && usesPreview:
		return higherCostSearchKind(ctx)
	case usesPreview:
		return "web_search_preview"
	case usesWebSearch:
		return "web_search"
	default:
		return ""
	}
}

func webSearchContentTokensBilledAtModelRates(ctx PolicyRequest) bool {
	return webSearchContentTokensBilledAtModelRatesForKind(ctx, responsesSearchKind(ctx))
}

func webSearchContentTokensBilledAtModelRatesForKind(ctx PolicyRequest, kind string) bool {
	if ctx.Route != RouteResponses {
		return false
	}
	if kind == "web_search" && webSearchFixedContentTokensForKind(ctx.Deployment.Model, kind) == 0 {
		return true
	}
	return kind == "web_search_preview" && ctx.Deployment.ReasoningSupported
}

func webSearchFixedContentTokens(model string, toolTypes []string) int {
	if !usesWebSearchKind(toolTypes, "web_search") {
		return 0
	}
	return webSearchFixedContentTokensForKind(model, "web_search")
}

func webSearchFixedContentTokensForKind(model string, kind string) int {
	if kind != "web_search" {
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
		if strings.EqualFold(strings.TrimSpace(toolType), kind) {
			return true
		}
	}
	return false
}

func higherCostSearchKind(ctx PolicyRequest) string {
	webSearchCost := searchKindEstimatedExtraCost(ctx, "web_search")
	previewCost := searchKindEstimatedExtraCost(ctx, "web_search_preview")
	if previewCost != nil && (webSearchCost == nil || previewCost.Cmp(webSearchCost) >= 0) {
		return "web_search_preview"
	}
	if webSearchCost != nil {
		return "web_search"
	}
	return ""
}

func searchKindEstimatedExtraCost(ctx PolicyRequest, kind string) *big.Int {
	meterKey := responsesSearchMeterForKind(kind)
	if meterKey == "" {
		return nil
	}
	call := callRate(ctx.Deployment.Pricing, meterKey)
	if call == nil {
		return nil
	}
	total := billing.CostPerThousand(searchCallQuantity, call)
	if fixedContentTokens := webSearchFixedContentTokensForKind(ctx.Deployment.Model, kind); fixedContentTokens > 0 {
		if _, inputRate, ok := billing.PricingRate(ctx.Deployment.Pricing, billing.MeterInputTokens, true); ok {
			total = new(big.Int).Add(total, billing.CostPerMillion(fixedContentTokens, inputRate))
		}
	}
	return total
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

func callRate(pricing providers.Pricing, meterKey string) *big.Int {
	meter, ok := pricing[meterKey]
	if !ok {
		return nil
	}
	rate, ok := billing.ParseRate(meter[billing.RatePerThousandCalls])
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

func WebSearchContentTokensBilledAtModelRates(ctx PolicyRequest) bool {
	return webSearchContentTokensBilledAtModelRates(ctx)
}

func ResponsesWebSearchCallMeter(ctx PolicyRequest) string {
	return responsesSearchMeter(ctx)
}
