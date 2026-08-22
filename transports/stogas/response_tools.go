package stogas

import (
	"bytes"
	"encoding/json"
	"math"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func validProviderHTTPURL(value string) bool {
	if value == "" || len(value) > 16*1024 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.User == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != ""
}

func validProviderLogProb(token string, probability float64, bytes []int) bool {
	if !utf8.ValidString(token) || math.IsNaN(probability) || math.IsInf(probability, 0) || probability > 0 ||
		strings.ContainsRune(token, '\x00') || len(bytes) > 64 {
		return false
	}
	for _, value := range bytes {
		if value < 0 || value > 255 {
			return false
		}
	}
	return true
}

func validateProviderResponsesOutput(state *State, response *schemas.BifrostResponsesResponse, terminal bool) error {
	if response == nil || len(response.Output) > maxProviderResponseItems {
		return ErrProviderResponseMalformed
	}
	if !terminal && (len(response.Output) != 0 || response.CompletedAt != nil || response.Container != nil ||
		response.StopReason != nil || response.StopDetails != nil) {
		return ErrProviderResponseMalformed
	}
	if !validProviderResponsesStatusDetails(state, response) {
		return ErrProviderResponseMalformed
	}
	if terminal && state != nil && state.responsesStreamSeen && len(response.Output) != len(state.responsesItems) {
		return ErrProviderResponseMalformed
	}
	if response.Background != nil && *response.Background || response.Store != nil && *response.Store ||
		response.Conversation != nil || response.PreviousResponseID != nil || response.Prompt != nil ||
		response.Error != nil {
		return ErrProviderResponseMalformed
	}
	if response.Container != nil {
		if !providerResponsesImplicitCodeExecutionAllowed(state) || !validProviderResponseID(response.Container.ID) ||
			response.Container.ExpiresAt == nil || !validProviderRFC3339(*response.Container.ExpiresAt) {
			return ErrProviderResponseMalformed
		}
	}
	if response.MaxToolCalls != nil {
		if *response.MaxToolCalls < 1 || *response.MaxToolCalls > responsesTopLevelMaxToolCallsOrDefault(state) {
			return ErrProviderResponseMalformed
		}
	}
	seenIDs := make(map[string]struct{}, len(response.Output))
	codeExecutionItems := 0
	for index := range response.Output {
		item := &response.Output[index]
		observed, err := validateProviderResponsesItem(state, item)
		if err != nil {
			return err
		}
		if terminal && validateProviderResponsesTerminalItem(state, item, false) != nil {
			return ErrProviderResponseMalformed
		}
		if item.Type != nil && *item.Type == schemas.ResponsesMessageTypeCodeInterpreterCall {
			codeExecutionItems++
			if terminal && !providerResponsesCodeExecutionContainerMatches(response.Container, item) {
				return ErrProviderResponseMalformed
			}
		}
		if _, duplicate := seenIDs[observed.id]; duplicate {
			return ErrProviderResponseMalformed
		}
		seenIDs[observed.id] = struct{}{}
		if terminal && state != nil && state.responsesStreamSeen {
			streamItem, ok := state.responsesItems[index]
			if !ok || !streamItem.done || !sameProviderResponsesItem(streamItem, observed) ||
				validateProviderResponsesCompletedStreamItem(streamItem, item) != nil {
				return ErrProviderResponseMalformed
			}
		}
	}
	if terminal && state != nil && state.responsesStreamSeen {
		for _, item := range state.responsesItems {
			if !item.done {
				return ErrProviderResponseMalformed
			}
		}
	}
	if terminal && state != nil {
		if providerResponsesToolCallRequired(state) && state.responsesDeclaredCalls == 0 {
			return ErrProviderResponseMalformed
		}
		if state.Resolution != nil {
			if raw, ok := state.Resolution.RawBody()["parallel_tool_calls"]; ok && !rawBool(raw) && state.responsesClientCalls > 1 {
				return ErrProviderResponseMalformed
			}
		}
		if validateProviderResponsesCallerReferences(response.Output) != nil {
			return ErrProviderResponseMalformed
		}
	}
	if terminal && (response.Container != nil) != (codeExecutionItems > 0) {
		return ErrProviderResponseMalformed
	}
	return sanitizeProviderResponsesEcho(state, response)
}

func providerResponsesToolCallRequired(state *State) bool {
	if state == nil || state.Resolution == nil {
		return false
	}
	choice := state.Resolution.RawBody()["tool_choice"]
	if selected, ok := rawStringValue(choice); ok {
		return selected == "required"
	}
	object, ok := rawObject(choice)
	if !ok {
		return false
	}
	if rawString(object["type"]) == "allowed_tools" {
		return rawString(object["mode"]) == "required"
	}
	return true
}

func validProviderResponsesStatusDetails(state *State, response *schemas.BifrostResponsesResponse) bool {
	if response == nil {
		return false
	}
	status := schemas.ResponsesResponseStatusCompleted
	if response.Status != nil {
		status = *response.Status
	}
	if response.IncompleteDetails != nil {
		if status != schemas.ResponsesResponseStatusIncomplete ||
			!validProviderText(response.IncompleteDetails.Reason, 128, false) {
			return false
		}
	} else if status == schemas.ResponsesResponseStatusIncomplete {
		return false
	}

	if response.StopReason == nil {
		return response.StopDetails == nil
	}
	if state == nil || state.Resolution == nil || !responsesUsesAnthropicWire(state) ||
		!validProviderText(*response.StopReason, 128, false) {
		return false
	}
	switch *response.StopReason {
	case string(schemas.BifrostFinishReasonStop),
		string(schemas.BifrostFinishReasonLength),
		string(schemas.BifrostFinishReasonToolCalls),
		"pause_turn", "model_context_window_exceeded":
		return response.StopDetails == nil
	case "compaction":
		return response.StopDetails == nil &&
			anthropicContextManagementUsesCompaction(state.Resolution.RawBody()["context_management"])
	case "refusal":
		return validProviderResponsesStopDetails(response.StopDetails)
	default:
		// Stop reasons are descriptive terminal metadata. Providers can add
		// values without changing request execution, pricing, or data handling.
		return response.StopDetails == nil
	}
}

func validProviderResponsesStopDetails(details *schemas.ResponsesStopDetails) bool {
	if details == nil {
		return true
	}
	if details.Type != "refusal" ||
		!validOptionalProviderText(details.Category, 1024, false) ||
		!validOptionalProviderText(details.Explanation, 64*1024, false) ||
		details.RecommendedModel != nil && !validProviderResponseID(*details.RecommendedModel) ||
		!validOptionalProviderASCII(details.FallbackCreditToken, 16*1024) ||
		details.FallbackHasPrefillClaim != nil && details.FallbackCreditToken == nil {
		return false
	}
	return true
}

func validOptionalProviderASCII(value *string, maxBytes int) bool {
	if value == nil {
		return true
	}
	if len(*value) == 0 || len(*value) > maxBytes {
		return false
	}
	for index := range len(*value) {
		if (*value)[index] < 0x21 || (*value)[index] > 0x7e {
			return false
		}
	}
	return true
}

type trustedResponsesEcho struct {
	Background           *bool                                 `json:"background"`
	Include              []string                              `json:"include"`
	Instructions         *string                               `json:"instructions"`
	MaxOutputTokens      *int                                  `json:"max_output_tokens"`
	MaxToolCalls         *int                                  `json:"max_tool_calls"`
	Metadata             *map[string]any                       `json:"metadata"`
	ParallelToolCalls    *bool                                 `json:"parallel_tool_calls"`
	PromptCacheKey       *string                               `json:"prompt_cache_key"`
	PromptCacheRetention *string                               `json:"prompt_cache_retention"`
	PromptCacheOptions   *schemas.PromptCacheOptions           `json:"prompt_cache_options"`
	PresencePenalty      *float64                              `json:"presence_penalty"`
	FrequencyPenalty     *float64                              `json:"frequency_penalty"`
	Reasoning            *schemas.ResponsesParametersReasoning `json:"reasoning"`
	SafetyIdentifier     *string                               `json:"safety_identifier"`
	StreamOptions        *schemas.ResponsesStreamOptions       `json:"stream_options"`
	Store                *bool                                 `json:"store"`
	Temperature          *float64                              `json:"temperature"`
	Text                 *schemas.ResponsesTextConfig          `json:"text"`
	TopLogProbs          *int                                  `json:"top_logprobs"`
	TopP                 *float64                              `json:"top_p"`
	ToolChoice           *schemas.ResponsesToolChoice          `json:"tool_choice"`
	Tools                []schemas.ResponsesTool               `json:"tools"`
	Truncation           *string                               `json:"truncation"`
}

func sanitizeProviderResponsesEcho(state *State, response *schemas.BifrostResponsesResponse) error {
	if response == nil {
		return ErrProviderResponseMalformed
	}
	trusted := trustedResponsesEcho{}
	if state != nil && state.Resolution != nil {
		encoded, err := json.Marshal(state.Resolution.RawBody())
		if err != nil || json.Unmarshal(encoded, &trusted) != nil {
			return ErrProviderResponseMalformed
		}
		if trusted.Reasoning == nil {
			if rawEffort := state.Resolution.RawBody()["reasoning.effort"]; len(rawEffort) != 0 {
				var effort string
				if json.Unmarshal(rawEffort, &effort) != nil {
					return ErrProviderResponseMalformed
				}
				trusted.Reasoning = &schemas.ResponsesParametersReasoning{Effort: &effort}
			}
		}
	}
	response.Background = schemas.Ptr(false)
	response.Store = schemas.Ptr(false)
	response.Include = trusted.Include
	response.Instructions = nil
	if trusted.Instructions != nil {
		response.Instructions = &schemas.ResponsesResponseInstructions{ResponsesResponseInstructionsStr: trusted.Instructions}
	}
	response.MaxOutputTokens = trusted.MaxOutputTokens
	response.MaxToolCalls = trusted.MaxToolCalls
	response.Metadata = trusted.Metadata
	response.ParallelToolCalls = trusted.ParallelToolCalls
	response.PromptCacheKey = trusted.PromptCacheKey
	response.PromptCacheRetention = trusted.PromptCacheRetention
	response.PromptCacheOptions = trusted.PromptCacheOptions
	response.PresencePenalty = trusted.PresencePenalty
	response.FrequencyPenalty = trusted.FrequencyPenalty
	response.Reasoning = trusted.Reasoning
	response.SafetyIdentifier = trusted.SafetyIdentifier
	response.StreamOptions = trusted.StreamOptions
	response.Temperature = trusted.Temperature
	response.Text = trusted.Text
	response.TopLogProbs = trusted.TopLogProbs
	response.TopP = trusted.TopP
	response.ToolChoice = trusted.ToolChoice
	response.Tools = trusted.Tools
	response.Truncation = trusted.Truncation
	return nil
}

func validateProviderResponsesStreamPayload(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if response == nil {
		return ErrProviderResponseMalformed
	}

	switch response.Type {
	case schemas.ResponsesStreamResponseTypeCreated,
		schemas.ResponsesStreamResponseTypeInProgress,
		schemas.ResponsesStreamResponseTypeCompleted,
		schemas.ResponsesStreamResponseTypeIncomplete:
		terminal := response.Type == schemas.ResponsesStreamResponseTypeCompleted || response.Type == schemas.ResponsesStreamResponseTypeIncomplete
		if responsesStreamNonResponsePayloadSet(response) || validateProviderResponsesOutput(state, response.Response, terminal) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeOutputItemAdded, schemas.ResponsesStreamResponseTypeOutputItemDone:
		return validateProviderResponsesOutputItemEvent(state, response)
	case schemas.ResponsesStreamResponseTypeContentPartAdded, schemas.ResponsesStreamResponseTypeContentPartDone:
		if response.Part == nil || !responsesStreamHasItemReference(state, response) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadPart) ||
			validateProviderResponsesStreamPartEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeOutputTextDelta:
		if response.Delta == nil || !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeMessage) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadDelta|responsePayloadObfuscation|responsePayloadLogProbs) ||
			validateProviderResponsesLogProbs(response.LogProbs) != nil ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeText) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeOutputTextDone:
		if response.Text == nil || !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeMessage) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadText|responsePayloadLogProbs) ||
			validateProviderResponsesLogProbs(response.LogProbs) != nil ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeText) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeRefusalDelta:
		if response.Delta == nil || !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeMessage) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeRefusal) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeRefusalDone:
		if response.Refusal == nil || !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeMessage) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadRefusal) ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeRefusal) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta:
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeFunction) || response.Delta == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeFunctionCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesToolValueEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone:
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeFunction) || response.Arguments == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeFunctionCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadArguments) ||
			validateProviderResponsesToolValueEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeCustomToolCallInputDelta:
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeCustom) || response.Delta == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeCustomToolCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesToolValueEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeCustomToolCallInputDone:
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeCustom) || response.Input == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeCustomToolCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadInput) ||
			validateProviderResponsesToolValueEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeWebSearchCallInProgress,
		schemas.ResponsesStreamResponseTypeWebSearchCallSearching,
		schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
		schemas.ResponsesStreamResponseTypeWebSearchCallResultsAdded,
		schemas.ResponsesStreamResponseTypeWebSearchCallResultsCompleted:
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeWebSearch) ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeWebSearchCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference) ||
			validateProviderResponsesHostedToolEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeWebFetchCallInProgress,
		schemas.ResponsesStreamResponseTypeWebFetchCallFetching,
		schemas.ResponsesStreamResponseTypeWebFetchCallCompleted:
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeWebFetch) ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeWebFetchCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference) ||
			validateProviderResponsesHostedToolEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartDone:
		if response.Part == nil || response.SummaryIndex == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeReasoning) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadSummaryIndex|responsePayloadPart) ||
			validateProviderResponsesContentBlock(state, response.Part) != nil ||
			response.Part.Type != schemas.ResponsesOutputMessageContentTypeReasoning ||
			validateProviderResponsesReasoningPartEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta:
		if (response.Delta == nil) == (response.Signature == nil) || (response.SummaryIndex == nil) == (response.ContentIndex == nil) ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeReasoning) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadSummaryIndex|responsePayloadContentIndex|responsePayloadDelta|responsePayloadSignature|responsePayloadObfuscation) ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeReasoning) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone:
		if response.Text == nil || (response.SummaryIndex == nil) == (response.ContentIndex == nil) ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeReasoning) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadSummaryIndex|responsePayloadContentIndex|responsePayloadText) ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeReasoning) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallInProgress,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallInterpreting,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallCompleted:
		if !providerResponsesImplicitCodeExecutionAllowed(state) ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeCodeInterpreterCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference) ||
			validateProviderResponsesHostedToolEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDelta:
		if !providerResponsesImplicitCodeExecutionAllowed(state) || response.Delta == nil ||
			!validProviderText(*response.Delta, maxProviderResponseBodySize, true) ||
			!validOptionalProviderText(response.Obfuscation, maxProviderResponseBodySize, false) ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeCodeInterpreterCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesHostedToolEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDone:
		if !providerResponsesImplicitCodeExecutionAllowed(state) || response.Code == nil ||
			!validProviderText(*response.Code, maxProviderResponseBodySize, true) ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeCodeInterpreterCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadCode) ||
			validateProviderResponsesHostedToolEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeOutputTextAnnotationAdded,
		schemas.ResponsesStreamResponseTypeOutputTextAnnotationDone:
		if response.Annotation == nil || response.AnnotationIndex == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeMessage) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadAnnotation|responsePayloadAnnotationIndex) ||
			validateProviderResponsesAnnotation(state, response.Annotation) != nil ||
			validateProviderResponsesAnnotationEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	default:
		return ErrProviderResponseMalformed
	}
}

func validateProviderResponsesOutputItemEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if state == nil || response == nil || response.OutputIndex == nil || response.Item == nil ||
		*response.OutputIndex >= maxProviderResponseItems ||
		responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadContentIndex|responsePayloadItemID|responsePayloadItem) {
		return ErrProviderResponseMalformed
	}
	item, err := validateProviderResponsesItem(state, response.Item)
	if err != nil {
		return err
	}
	if !providerResponsesStreamCallerReferencesCode(state, response.Item) {
		return ErrProviderResponseMalformed
	}
	if response.ItemID != nil && *response.ItemID != item.id {
		return ErrProviderResponseMalformed
	}
	if state.responsesItems == nil {
		state.responsesItems = make(map[int]providerResponsesItem)
	}
	index := *response.OutputIndex
	prior, exists := state.responsesItems[index]
	if response.Type == schemas.ResponsesStreamResponseTypeOutputItemAdded {
		if exists || index != len(state.responsesItems) || providerResponsesInitialToolValue(response.Item) != "" ||
			response.Item.Status == nil || *response.Item.Status != "in_progress" ||
			!providerResponsesInitialPayloadAllowed(response.Item, item.atomicPayload) {
			return ErrProviderResponseMalformed
		}
		state.responsesItems[index] = item
		return nil
	}
	if !exists || prior.done || response.Item.Status != nil &&
		(*response.Item.Status == "in_progress" || *response.Item.Status == "interpreting") ||
		!sameProviderResponsesItem(prior, item) ||
		validateProviderResponsesTerminalItem(state, response.Item, true) != nil ||
		validateProviderResponsesCompletedStreamItem(prior, response.Item) != nil {
		return ErrProviderResponseMalformed
	}
	fingerprint, err := providerResponsesCompletedItemFingerprint(response.Item)
	if err != nil {
		return ErrProviderResponseMalformed
	}
	prior.done = true
	if prior.toolActionPayload == "" {
		prior.toolActionPayload = item.toolActionPayload
	}
	prior.completedPayload = fingerprint
	state.responsesItems[index] = prior
	return nil
}

func providerResponsesInitialPayloadAllowed(item *schemas.ResponsesMessage, atomicPayload string) bool {
	if item == nil || item.Type == nil {
		return false
	}
	switch *item.Type {
	case schemas.ResponsesMessageTypeMessage:
		return item.Content != nil && (len(item.Content.ContentBlocks) == 0 || atomicPayload != "")
	case schemas.ResponsesMessageTypeReasoning:
		contentEmpty := item.Content == nil || len(item.Content.ContentBlocks) == 0
		reasoningEmpty := item.ResponsesReasoning == nil ||
			(len(item.ResponsesReasoning.Summary) == 0 && item.ResponsesReasoning.EncryptedContent == nil)
		return contentEmpty && reasoningEmpty || atomicPayload != ""
	default:
		return true
	}
}

func providerResponsesInitialToolValue(item *schemas.ResponsesMessage) string {
	value, _ := providerResponsesToolItemValue(item)
	return value
}

func providerResponsesToolItemValue(item *schemas.ResponsesMessage) (string, bool) {
	if item == nil || item.Type == nil || item.ResponsesToolMessage == nil {
		return "", false
	}
	switch *item.Type {
	case schemas.ResponsesMessageTypeFunctionCall:
		if item.ResponsesToolMessage.Arguments == nil {
			return "", false
		}
		return *item.ResponsesToolMessage.Arguments, true
	case schemas.ResponsesMessageTypeCustomToolCall:
		if item.ResponsesToolMessage.ResponsesCustomToolCall == nil {
			return "", false
		}
		return item.ResponsesToolMessage.ResponsesCustomToolCall.Input, true
	default:
		return "", false
	}
}

func validateProviderResponsesTerminalItem(state *State, item *schemas.ResponsesMessage, allowPendingContainer bool) error {
	if item == nil || item.Type == nil || item.Status == nil {
		return ErrProviderResponseMalformed
	}
	switch *item.Type {
	case schemas.ResponsesMessageTypeMessage:
		if !stringInSet(*item.Status, "completed", "incomplete") || item.Content == nil || len(item.Content.ContentBlocks) == 0 {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeReasoning:
		if !stringInSet(*item.Status, "completed", "incomplete") {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeFunctionCall:
		if *item.Status != "completed" || item.ResponsesToolMessage == nil || item.ResponsesToolMessage.Arguments == nil ||
			!catalog.ValidateJSONObjectText(*item.ResponsesToolMessage.Arguments) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeCustomToolCall:
		if *item.Status != "completed" || item.ResponsesToolMessage == nil || item.ResponsesToolMessage.ResponsesCustomToolCall == nil ||
			!validProviderText(item.ResponsesToolMessage.ResponsesCustomToolCall.Input, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeWebSearchCall:
		if !stringInSet(*item.Status, "completed", "failed") || item.ResponsesToolMessage == nil || item.ResponsesToolMessage.Action == nil ||
			item.ResponsesToolMessage.Action.ResponsesWebSearchToolCallAction == nil {
			return ErrProviderResponseMalformed
		}
		search := item.ResponsesToolMessage.Action.ResponsesWebSearchToolCallAction
		if search.Type == "search" && search.Query == nil && len(search.Queries) == 0 {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeWebFetchCall:
		if !stringInSet(*item.Status, "completed", "failed") || item.ResponsesToolMessage == nil || item.ResponsesToolMessage.Action == nil ||
			item.ResponsesToolMessage.Action.ResponsesWebFetchToolCallAction == nil ||
			item.ResponsesToolMessage.ResponsesWebFetchCall == nil {
			return ErrProviderResponseMalformed
		}
		actionURL := item.ResponsesToolMessage.Action.ResponsesWebFetchToolCallAction.URL
		result := item.ResponsesToolMessage.ResponsesWebFetchCall
		if result.ResultType == "web_fetch_result" && (result.URL == nil || *result.URL != actionURL) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeCodeInterpreterCall:
		if item.ResponsesToolMessage == nil || item.ResponsesToolMessage.ResponsesCodeInterpreterToolCall == nil ||
			item.ResponsesToolMessage.ResponsesCodeExecutionCall == nil {
			return ErrProviderResponseMalformed
		}
		carry := item.ResponsesToolMessage.ResponsesCodeExecutionCall
		failed := strings.HasSuffix(carry.ResultType, "_tool_result_error")
		if carry.Input == nil || carry.ResultType == "" || item.Status == nil ||
			failed && *item.Status != "failed" || !failed && *item.Status != "completed" ||
			!validProviderCodeExecutionNeutralMatch(item.ResponsesToolMessage.ResponsesCodeInterpreterToolCall, carry, allowPendingContainer) {
			return ErrProviderResponseMalformed
		}
	}
	return nil
}

func providerResponsesCodeExecutionContainerMatches(container *schemas.ResponsesResponseContainer, item *schemas.ResponsesMessage) bool {
	if container == nil || container.ExpiresAt == nil || item == nil || item.ResponsesToolMessage == nil ||
		item.ResponsesToolMessage.ResponsesCodeInterpreterToolCall == nil ||
		item.ResponsesToolMessage.ResponsesCodeExecutionCall == nil {
		return false
	}
	interpreter := item.ResponsesToolMessage.ResponsesCodeInterpreterToolCall
	carry := item.ResponsesToolMessage.ResponsesCodeExecutionCall
	return interpreter.ContainerID == container.ID && carry.ContainerExpiresAt != nil &&
		*carry.ContainerExpiresAt == *container.ExpiresAt
}

func validateProviderResponsesCompletedStreamItem(streamItem providerResponsesItem, finalItem *schemas.ResponsesMessage) error {
	for _, part := range streamItem.parts {
		if part == nil || !part.done {
			return ErrProviderResponseMalformed
		}
	}
	for _, part := range streamItem.reasoningParts {
		if part == nil || !part.done {
			return ErrProviderResponseMalformed
		}
	}
	if streamItem.value != nil {
		value, ok := providerResponsesToolItemValue(finalItem)
		if !ok || !streamItem.valueDone || value != streamItem.value.String() {
			return ErrProviderResponseMalformed
		}
	}
	if streamItem.done {
		fingerprint, err := providerResponsesCompletedItemFingerprint(finalItem)
		if err != nil || streamItem.completedPayload == "" || fingerprint != streamItem.completedPayload {
			return ErrProviderResponseMalformed
		}
	}
	switch streamItem.itemType {
	case schemas.ResponsesMessageTypeMessage:
		if len(streamItem.parts) == 0 && !providerResponsesAtomicPayloadMatches(streamItem.atomicPayload, finalItem) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeReasoning:
		if len(streamItem.parts) == 0 && len(streamItem.reasoningParts) == 0 &&
			!providerResponsesAtomicPayloadMatches(streamItem.atomicPayload, finalItem) {
			return ErrProviderResponseMalformed
		}
	}
	switch streamItem.itemType {
	case schemas.ResponsesMessageTypeWebSearchCall:
		if streamItem.stage != 5 {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeWebFetchCall:
		if streamItem.stage != 3 {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeCodeInterpreterCall:
		if streamItem.stage != 4 || !streamItem.codeDone {
			return ErrProviderResponseMalformed
		}
		tool := finalItem.ResponsesToolMessage
		call := tool.ResponsesCodeInterpreterToolCall
		carry := tool.ResponsesCodeExecutionCall
		if streamItem.code == nil || carry == nil ||
			carry.ToolName == "text_editor_code_execution" && (call.Code != nil || streamItem.code.Len() != 0) ||
			carry.ToolName != "text_editor_code_execution" && (call.Code == nil || *call.Code != streamItem.code.String()) {
			return ErrProviderResponseMalformed
		}
	}
	if len(streamItem.parts) != 0 && !providerResponsesFinalContentMatches(streamItem.parts, finalItem) {
		return ErrProviderResponseMalformed
	}
	if len(streamItem.reasoningParts) != 0 && !providerResponsesFinalReasoningMatches(streamItem.reasoningParts, finalItem) {
		return ErrProviderResponseMalformed
	}
	return nil
}

func providerResponsesCompletedItemFingerprint(item *schemas.ResponsesMessage) (string, error) {
	if item == nil {
		return "", ErrProviderResponseMalformed
	}
	copyItem := *item
	if item.ResponsesToolMessage != nil {
		tool := *item.ResponsesToolMessage
		copyItem.ResponsesToolMessage = &tool
		if tool.ResponsesCodeInterpreterToolCall != nil {
			interpreter := *tool.ResponsesCodeInterpreterToolCall
			interpreter.ContainerID = ""
			tool.ResponsesCodeInterpreterToolCall = &interpreter
		}
		if tool.ResponsesCodeExecutionCall != nil {
			carry := *tool.ResponsesCodeExecutionCall
			carry.ContainerExpiresAt = nil
			tool.ResponsesCodeExecutionCall = &carry
		}
	}
	encoded, err := json.Marshal(&copyItem)
	if err != nil || len(encoded) == 0 || len(encoded) > maxProviderResponseBodySize {
		return "", ErrProviderResponseMalformed
	}
	return string(encoded), nil
}

func providerResponsesFinalContentMatches(parts map[int]*providerResponsesPart, item *schemas.ResponsesMessage) bool {
	if item == nil || item.Content == nil || item.Content.ContentBlocks == nil ||
		len(item.Content.ContentBlocks) != len(parts) {
		return false
	}
	for index, part := range parts {
		if part == nil || index >= len(item.Content.ContentBlocks) {
			return false
		}
		block := &item.Content.ContentBlocks[index]
		value, ok := providerResponsesBlockValue(block)
		if !ok || block.Type != part.blockType || value != part.value.String() ||
			!sameProviderOptionalString(part.signature, block.Signature) ||
			!providerResponsesFinalAnnotationsMatch(part, block) {
			return false
		}
	}
	return true
}

func providerResponsesFinalReasoningMatches(parts map[int]*providerResponsesPart, item *schemas.ResponsesMessage) bool {
	if item == nil || item.ResponsesReasoning == nil || len(item.ResponsesReasoning.Summary) != len(parts) {
		return false
	}
	for index, part := range parts {
		if part == nil || index >= len(item.ResponsesReasoning.Summary) {
			return false
		}
		if part.signature != nil || item.ResponsesReasoning.Summary[index].Text != part.value.String() {
			return false
		}
	}
	return true
}

func providerResponsesFinalAnnotationsMatch(part *providerResponsesPart, block *schemas.ResponsesMessageContentBlock) bool {
	if part == nil || block == nil {
		return false
	}
	var annotations []schemas.ResponsesOutputMessageContentTextAnnotation
	if block.ResponsesOutputMessageContentText != nil {
		annotations = block.ResponsesOutputMessageContentText.Annotations
	}
	if len(annotations) != len(part.annotations) {
		return false
	}
	for index := range annotations {
		observed, ok := part.annotations[index]
		if !ok {
			return false
		}
		encoded, err := json.Marshal(&annotations[index])
		if err != nil || observed.value != string(encoded) {
			return false
		}
	}
	return true
}

func responsesStreamHasItemReference(state *State, response *schemas.BifrostResponsesStreamResponse) bool {
	if state == nil || response == nil || response.OutputIndex == nil || response.ItemID == nil ||
		!validProviderResponseID(*response.ItemID) {
		return false
	}
	item, ok := state.responsesItems[*response.OutputIndex]
	return ok && !item.done && item.id == *response.ItemID
}

func responsesStreamHasItemType(state *State, response *schemas.BifrostResponsesStreamResponse, itemType schemas.ResponsesMessageType) bool {
	if !responsesStreamHasItemReference(state, response) {
		return false
	}
	return state.responsesItems[*response.OutputIndex].itemType == itemType
}

func responsesStreamNonResponsePayloadSet(response *schemas.BifrostResponsesStreamResponse) bool {
	return response.OutputIndex != nil || response.Item != nil || response.SummaryIndex != nil || response.ContentIndex != nil ||
		response.ItemID != nil || response.Part != nil || response.Delta != nil || response.Signature != nil ||
		response.Obfuscation != nil || len(response.LogProbs) != 0 || response.Text != nil || response.Refusal != nil ||
		response.Arguments != nil || response.Input != nil || response.PartialImageB64 != nil || response.PartialImageIndex != nil ||
		response.Annotation != nil || response.AnnotationIndex != nil || response.Error != nil || response.Code != nil ||
		response.Message != nil || response.Param != nil
}

type responsesStreamPayload uint32

const (
	responsePayloadResponse responsesStreamPayload = 1 << iota
	responsePayloadOutputIndex
	responsePayloadSummaryIndex
	responsePayloadContentIndex
	responsePayloadItemID
	responsePayloadItem
	responsePayloadPart
	responsePayloadDelta
	responsePayloadSignature
	responsePayloadObfuscation
	responsePayloadLogProbs
	responsePayloadText
	responsePayloadRefusal
	responsePayloadArguments
	responsePayloadInput
	responsePayloadPartialImageB64
	responsePayloadPartialImageIndex
	responsePayloadAnnotation
	responsePayloadAnnotationIndex
	responsePayloadError
	responsePayloadCode
	responsePayloadMessage
	responsePayloadParam
)

const responsePayloadItemReference = responsePayloadOutputIndex | responsePayloadContentIndex | responsePayloadItemID

func responsesStreamUnexpectedPayload(response *schemas.BifrostResponsesStreamResponse, allowed responsesStreamPayload) bool {
	if response == nil {
		return true
	}
	present := responsesStreamPayload(0)
	if response.Response != nil {
		present |= responsePayloadResponse
	}
	if response.OutputIndex != nil {
		present |= responsePayloadOutputIndex
	}
	if response.SummaryIndex != nil {
		present |= responsePayloadSummaryIndex
	}
	if response.ContentIndex != nil {
		present |= responsePayloadContentIndex
	}
	if response.ItemID != nil {
		present |= responsePayloadItemID
	}
	if response.Item != nil {
		present |= responsePayloadItem
	}
	if response.Part != nil {
		present |= responsePayloadPart
	}
	if response.Delta != nil {
		present |= responsePayloadDelta
	}
	if response.Signature != nil {
		present |= responsePayloadSignature
	}
	if response.Obfuscation != nil {
		present |= responsePayloadObfuscation
	}
	if len(response.LogProbs) != 0 {
		present |= responsePayloadLogProbs
	}
	if response.Text != nil {
		present |= responsePayloadText
	}
	if response.Refusal != nil {
		present |= responsePayloadRefusal
	}
	if response.Arguments != nil {
		present |= responsePayloadArguments
	}
	if response.Input != nil {
		present |= responsePayloadInput
	}
	if response.PartialImageB64 != nil {
		present |= responsePayloadPartialImageB64
	}
	if response.PartialImageIndex != nil {
		present |= responsePayloadPartialImageIndex
	}
	if response.Annotation != nil {
		present |= responsePayloadAnnotation
	}
	if response.AnnotationIndex != nil {
		present |= responsePayloadAnnotationIndex
	}
	if response.Error != nil {
		present |= responsePayloadError
	}
	if response.Code != nil {
		present |= responsePayloadCode
	}
	if response.Message != nil {
		present |= responsePayloadMessage
	}
	if response.Param != nil {
		present |= responsePayloadParam
	}
	return present&^allowed != 0
}

const maxProviderResponseItems = 4_096

func validateProviderResponsesItem(state *State, item *schemas.ResponsesMessage) (providerResponsesItem, error) {
	if item == nil || item.ID == nil || !validProviderResponseID(*item.ID) || item.Type == nil {
		return providerResponsesItem{}, ErrProviderResponseMalformed
	}
	observed := providerResponsesItem{
		id:             *item.ID,
		itemType:       *item.Type,
		parts:          make(map[int]*providerResponsesPart),
		reasoningParts: make(map[int]*providerResponsesPart),
	}
	if item.Status != nil && !stringInSet(*item.Status, "in_progress", "completed", "incomplete", "failed", "interpreting") {
		return providerResponsesItem{}, ErrProviderResponseMalformed
	}
	if item.Role != nil && *item.Role != schemas.ResponsesInputMessageRoleAssistant ||
		rawProviderExtensionSet(item.Author) || rawProviderExtensionSet(item.Recipient) ||
		rawProviderExtensionSet(item.ToolSearchOutputTools) || rawProviderExtensionSet(item.AdditionalTools) ||
		!validProviderCacheControl(item.CacheControl) ||
		item.Phase != nil && !stringInSet(*item.Phase, "commentary", "final_answer") {
		return providerResponsesItem{}, ErrProviderResponseMalformed
	}

	switch *item.Type {
	case schemas.ResponsesMessageTypeMessage:
		if item.Role == nil || item.Content == nil || item.ResponsesToolMessage != nil || item.ResponsesReasoning != nil ||
			validateProviderResponsesContent(state, item.Content) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeReasoning:
		if item.Phase != nil || item.ResponsesToolMessage != nil || (item.Content == nil) == (item.ResponsesReasoning == nil) {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		if item.Content != nil && validateProviderResponsesContent(state, item.Content) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		if item.ResponsesReasoning != nil && validateProviderResponsesReasoning(item.ResponsesReasoning) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeFunctionCall, schemas.ResponsesMessageTypeCustomToolCall:
		kind := schemas.ResponsesToolTypeFunction
		if *item.Type == schemas.ResponsesMessageTypeCustomToolCall {
			kind = schemas.ResponsesToolTypeCustom
		}
		if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil ||
			item.ResponsesToolMessage == nil || item.ResponsesToolMessage.Name == nil ||
			validateProviderResponsesToolMessage(state, item.ResponsesToolMessage, *item.Type) != nil ||
			!providerResponsesToolNameAllowed(state, kind, *item.ResponsesToolMessage.Name) {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		observed.name = *item.ResponsesToolMessage.Name
		observed.value = &bytes.Buffer{}
		if err := validateAndRecordProviderResponsesToolCall(state, item, &observed, true); err != nil {
			return providerResponsesItem{}, err
		}
	case schemas.ResponsesMessageTypeWebSearchCall:
		if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil ||
			!providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeWebSearch) || item.ResponsesToolMessage == nil ||
			validateProviderResponsesToolMessage(state, item.ResponsesToolMessage, *item.Type) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		if err := validateAndRecordProviderResponsesToolCall(state, item, &observed, false); err != nil {
			return providerResponsesItem{}, err
		}
	case schemas.ResponsesMessageTypeWebFetchCall:
		if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil ||
			!providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeWebFetch) || item.ResponsesToolMessage == nil ||
			validateProviderResponsesToolMessage(state, item.ResponsesToolMessage, *item.Type) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		if err := validateAndRecordProviderResponsesToolCall(state, item, &observed, false); err != nil {
			return providerResponsesItem{}, err
		}
	case schemas.ResponsesMessageTypeCodeInterpreterCall:
		if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil ||
			!providerResponsesImplicitCodeExecutionAllowed(state) || item.ResponsesToolMessage == nil ||
			validateProviderResponsesToolMessage(state, item.ResponsesToolMessage, *item.Type) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		if err := validateAndRecordProviderResponsesToolCall(state, item, &observed, false); err != nil {
			return providerResponsesItem{}, err
		}
		observed.code = &bytes.Buffer{}
	default:
		return providerResponsesItem{}, ErrProviderResponseMalformed
	}
	if item.ResponsesToolMessage != nil {
		callerPayload, actionPayload, toolKind, err := providerResponsesToolIdentity(item)
		if err != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		observed.toolCallerPayload = callerPayload
		observed.toolActionPayload = actionPayload
		observed.toolKind = toolKind
	}
	observed.atomicPayload = providerResponsesAtomicPayload(item)
	return observed, nil
}

func providerResponsesToolIdentity(item *schemas.ResponsesMessage) (string, string, string, error) {
	if item == nil || item.Type == nil || item.ResponsesToolMessage == nil {
		return "", "", "", nil
	}
	tool := item.ResponsesToolMessage
	callerIdentity := struct {
		Caller     *schemas.ResponsesToolCaller `json:"caller"`
		CodeCaller *schemas.ResponsesToolCaller `json:"code_caller"`
	}{Caller: tool.Caller}
	if tool.ResponsesCodeExecutionCall != nil {
		callerIdentity.CodeCaller = tool.ResponsesCodeExecutionCall.Caller
	}
	callerPayload, err := json.Marshal(callerIdentity)
	if err != nil {
		return "", "", "", err
	}

	actionPayload := ""
	switch *item.Type {
	case schemas.ResponsesMessageTypeWebSearchCall:
		if tool.Action != nil && tool.Action.ResponsesWebSearchToolCallAction != nil {
			action := tool.Action.ResponsesWebSearchToolCallAction
			identity := struct {
				Type    string   `json:"type"`
				Query   *string  `json:"query"`
				Queries []string `json:"queries"`
				URL     *string  `json:"url"`
				Pattern *string  `json:"pattern"`
			}{action.Type, action.Query, action.Queries, action.URL, action.Pattern}
			encoded, marshalErr := json.Marshal(identity)
			if marshalErr != nil {
				return "", "", "", marshalErr
			}
			actionPayload = string(encoded)
		}
	case schemas.ResponsesMessageTypeWebFetchCall:
		if tool.Action != nil && tool.Action.ResponsesWebFetchToolCallAction != nil {
			encoded, marshalErr := json.Marshal(tool.Action.ResponsesWebFetchToolCallAction)
			if marshalErr != nil {
				return "", "", "", marshalErr
			}
			actionPayload = string(encoded)
		}
	}
	toolKind := ""
	if tool.ResponsesCodeExecutionCall != nil {
		toolKind = tool.ResponsesCodeExecutionCall.ToolName
	}
	return string(callerPayload), actionPayload, toolKind, nil
}

func providerResponsesAtomicPayload(item *schemas.ResponsesMessage) string {
	if item == nil || item.Type == nil {
		return ""
	}
	var value any
	switch *item.Type {
	case schemas.ResponsesMessageTypeMessage:
		if item.Content == nil || len(item.Content.ContentBlocks) != 1 ||
			item.Content.ContentBlocks[0].Type != schemas.ResponsesOutputMessageContentTypeCompaction {
			return ""
		}
		value = item.Content
	case schemas.ResponsesMessageTypeReasoning:
		if item.ResponsesReasoning == nil || item.ResponsesReasoning.EncryptedContent == nil ||
			len(item.ResponsesReasoning.Summary) != 0 || item.Content != nil {
			return ""
		}
		value = item.ResponsesReasoning
	default:
		return ""
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func providerResponsesAtomicPayloadMatches(expected string, item *schemas.ResponsesMessage) bool {
	return expected != "" && providerResponsesAtomicPayload(item) == expected
}

func validateProviderResponsesReasoning(reasoning *schemas.ResponsesReasoning) error {
	if reasoning == nil || len(reasoning.Summary) > maxProviderResponseItems ||
		!validOptionalProviderText(reasoning.EncryptedContent, maxProviderResponseBodySize, false) {
		return ErrProviderResponseMalformed
	}
	for _, summary := range reasoning.Summary {
		if summary.Type != schemas.ResponsesReasoningContentBlockTypeSummaryText ||
			!validProviderText(summary.Text, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
	}
	return nil
}

func validateProviderResponsesToolMessage(state *State, tool *schemas.ResponsesToolMessage, itemType schemas.ResponsesMessageType) error {
	if tool == nil {
		return ErrProviderResponseMalformed
	}
	if tool.Namespace != nil || tool.Execution != nil || tool.Output != nil || tool.Error != nil ||
		tool.ResponsesFileSearchToolCall != nil || tool.ResponsesComputerToolCall != nil ||
		tool.ResponsesComputerToolCallOutput != nil || tool.ResponsesMCPToolCall != nil ||
		tool.ResponsesImageGenerationCall != nil || tool.ResponsesMCPListTools != nil ||
		tool.ResponsesMCPApprovalResponse != nil || tool.ResponsesAdvisorCall != nil ||
		tool.ResponsesToolSearchCall != nil {
		return ErrProviderResponseMalformed
	}

	switch itemType {
	case schemas.ResponsesMessageTypeFunctionCall:
		if tool.CallID == nil || tool.Name == nil || tool.Arguments == nil || tool.Action != nil || tool.Caller != nil ||
			tool.ResponsesCustomToolCall != nil || tool.ResponsesCodeInterpreterToolCall != nil ||
			tool.ResponsesWebFetchCall != nil || tool.ResponsesCodeExecutionCall != nil {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeCustomToolCall:
		if tool.CallID == nil || tool.Name == nil || tool.Arguments != nil || tool.Action != nil || tool.Caller != nil ||
			tool.ResponsesCustomToolCall == nil || tool.ResponsesCodeInterpreterToolCall != nil ||
			tool.ResponsesWebFetchCall != nil || tool.ResponsesCodeExecutionCall != nil {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeWebSearchCall:
		if tool.Name != nil || tool.Arguments != nil || tool.ResponsesCustomToolCall != nil ||
			tool.ResponsesCodeInterpreterToolCall != nil || tool.ResponsesWebFetchCall != nil ||
			tool.ResponsesCodeExecutionCall != nil || !validProviderWebSearchAction(state, tool.Action) ||
			!validProviderToolCaller(tool.Caller) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeWebFetchCall:
		if tool.Name != nil || tool.Arguments != nil || tool.ResponsesCustomToolCall != nil ||
			tool.ResponsesCodeInterpreterToolCall != nil || tool.ResponsesCodeExecutionCall != nil ||
			!validProviderWebFetchAction(state, tool.Action) || !validProviderToolCaller(tool.Caller) ||
			!validProviderWebFetchResult(state, tool.ResponsesWebFetchCall) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeCodeInterpreterCall:
		if tool.CallID == nil || tool.Name != nil || tool.Arguments != nil || tool.Action != nil || tool.Caller != nil ||
			tool.ResponsesCustomToolCall != nil || tool.ResponsesCodeInterpreterToolCall == nil ||
			tool.ResponsesWebFetchCall != nil || !validProviderCodeInterpreterCall(tool.ResponsesCodeInterpreterToolCall) ||
			!validProviderCodeExecutionCall(tool.ResponsesCodeExecutionCall) {
			return ErrProviderResponseMalformed
		}
	default:
		return ErrProviderResponseMalformed
	}
	return nil
}

func validProviderWebSearchAction(state *State, action *schemas.ResponsesToolMessageActionStruct) bool {
	if action == nil {
		return true
	}
	search := action.ResponsesWebSearchToolCallAction
	if search == nil || action.ResponsesComputerToolCallAction != nil || action.ResponsesWebFetchToolCallAction != nil ||
		action.ResponsesLocalShellToolCallAction != nil || action.ResponsesMCPApprovalRequestAction != nil ||
		len(search.ImageQueries) != 0 || len(search.Queries) > maxProviderResponseItems ||
		len(search.Sources) > maxProviderResponseItems || !validOptionalProviderText(search.Query, 64*1024, false) ||
		!validOptionalProviderText(search.Pattern, 64*1024, false) {
		return false
	}
	for _, query := range search.Queries {
		if !validProviderText(query, 64*1024, false) {
			return false
		}
	}
	if search.Query != nil && len(search.Queries) != 0 {
		matched := false
		for _, query := range search.Queries {
			matched = matched || query == *search.Query
		}
		if !matched {
			return false
		}
	}
	for _, source := range search.Sources {
		if source.Type != "url" || !validProviderHTTPURL(source.URL) ||
			!providerResponsesURLAllowed(state, schemas.ResponsesToolTypeWebSearch, source.URL) ||
			source.ImageURL != nil || source.Domain != nil ||
			!validOptionalProviderText(source.Title, 64*1024, true) ||
			!validOptionalProviderText(source.EncryptedContent, 16*1024*1024, false) ||
			!validOptionalProviderText(source.PageAge, 1024, false) {
			return false
		}
	}
	switch search.Type {
	case "search":
		return search.URL == nil && search.Pattern == nil
	case "open_page":
		return search.URL != nil && validProviderHTTPURL(*search.URL) &&
			providerResponsesURLAllowed(state, schemas.ResponsesToolTypeWebSearch, *search.URL) && search.Query == nil &&
			len(search.Queries) == 0 && len(search.Sources) == 0 && search.Pattern == nil
	case "find_in_page":
		return search.URL != nil && validProviderHTTPURL(*search.URL) &&
			providerResponsesURLAllowed(state, schemas.ResponsesToolTypeWebSearch, *search.URL) && search.Pattern != nil &&
			search.Query == nil && len(search.Queries) == 0 && len(search.Sources) == 0
	default:
		return false
	}
}

func validProviderWebFetchAction(state *State, action *schemas.ResponsesToolMessageActionStruct) bool {
	if action == nil {
		return true
	}
	fetch := action.ResponsesWebFetchToolCallAction
	return fetch != nil && fetch.Type == "fetch" && validProviderHTTPURL(fetch.URL) &&
		providerResponsesURLAllowed(state, schemas.ResponsesToolTypeWebFetch, fetch.URL) &&
		action.ResponsesComputerToolCallAction == nil && action.ResponsesWebSearchToolCallAction == nil &&
		action.ResponsesLocalShellToolCallAction == nil && action.ResponsesMCPApprovalRequestAction == nil
}

func validProviderWebFetchResult(state *State, result *schemas.ResponsesWebFetchCall) bool {
	if result == nil {
		return true
	}
	if !validOptionalProviderText(result.RetrievedAt, 1024, false) ||
		result.RetrievedAt != nil && !validProviderRFC3339(*result.RetrievedAt) {
		return false
	}
	switch result.ResultType {
	case "web_fetch_result":
		if result.URL == nil || !validProviderHTTPURL(*result.URL) ||
			!providerResponsesURLAllowed(state, schemas.ResponsesToolTypeWebFetch, *result.URL) ||
			result.Document == nil || result.ErrorCode != nil {
			return false
		}
	case "web_fetch_tool_result_error":
		return result.URL == nil && result.RetrievedAt == nil && result.Document == nil && result.ErrorCode != nil &&
			stringInSet(*result.ErrorCode, "invalid_tool_input", "url_too_long", "url_not_allowed",
				"url_not_in_prior_context", "url_not_accessible", "unsupported_content_type",
				"too_many_requests", "max_uses_exceeded", "unavailable")
	default:
		return false
	}
	document := result.Document
	if document.Type != "document" || document.Citations != nil || document.Text != nil || document.Context != nil ||
		!validOptionalProviderText(document.Title, 64*1024, true) ||
		document.Source == nil {
		return false
	}
	source := document.Source
	if source.Data == nil || source.MediaType == nil || source.URL != nil || source.FileID != nil {
		return false
	}
	return source.Type == "text" && *source.MediaType == "text/plain" &&
		validProviderText(*source.Data, maxProviderResponseBodySize, false)
}

func providerResponsesURLAllowed(state *State, wanted schemas.ResponsesToolType, value string) bool {
	if state == nil || state.Resolution == nil {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	hostname := strings.ToLower(parsed.Hostname())
	enabled := make(map[schemas.ResponsesToolType]bool)
	for _, rawType := range effectiveResponsesToolTypes(state.Resolution.RawBody(), state.Resolution.ToolTypes()) {
		enabled[canonicalResponsesToolType(rawType)] = true
	}
	for _, tool := range state.Resolution.RawTools() {
		toolType := canonicalResponsesToolType(rawString(tool["type"]))
		matches := toolType == wanted || wanted == schemas.ResponsesToolTypeWebSearch && toolType == schemas.ResponsesToolTypeWebSearchPreview
		if !matches || !enabled[toolType] {
			continue
		}
		filters, hasFilters := rawObject(tool["filters"])
		if !hasFilters {
			return true
		}
		allowed, allowedOK := providerResponseDomains(filters["allowed_domains"])
		blocked, blockedOK := providerResponseDomains(filters["blocked_domains"])
		if !allowedOK || !blockedOK {
			return false
		}
		if providerDomainMatches(hostname, blocked) {
			continue
		}
		if len(allowed) == 0 || providerDomainMatches(hostname, allowed) {
			return true
		}
	}
	return false
}

func providerResponseDomains(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	var domains []string
	if json.Unmarshal(raw, &domains) != nil {
		return nil, false
	}
	for index := range domains {
		domains[index] = strings.ToLower(strings.TrimSpace(domains[index]))
	}
	return domains, true
}

func providerDomainMatches(hostname string, domains []string) bool {
	for _, domain := range domains {
		if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
			return true
		}
	}
	return false
}

func validProviderRFC3339(value string) bool {
	if !validProviderText(value, 1024, false) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func validProviderCodeInterpreterCall(call *schemas.ResponsesCodeInterpreterToolCall) bool {
	if call == nil || !validOptionalProviderText(call.Code, maxProviderResponseBodySize, true) ||
		call.ContainerID != "" && !validProviderResponseID(call.ContainerID) ||
		len(call.Outputs) > maxProviderResponseItems {
		return false
	}
	for _, output := range call.Outputs {
		if output.ResponsesCodeInterpreterOutputLogs == nil || output.ResponsesCodeInterpreterOutputImage != nil {
			return false
		}
		logs := output.ResponsesCodeInterpreterOutputLogs
		if logs.Type != "logs" || !validProviderText(logs.Logs, maxProviderResponseBodySize, true) {
			return false
		}
	}
	return true
}

func validProviderCodeExecutionCall(call *schemas.ResponsesCodeExecutionCall) bool {
	if call == nil || !stringInSet(call.ToolName, "code_execution", "bash_code_execution", "text_editor_code_execution") ||
		!validOptionalProviderText(call.Stdout, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(call.Stderr, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(call.EncryptedStdout, maxProviderResponseBodySize, false) ||
		!validOptionalProviderText(call.FileType, 1024, false) ||
		!validOptionalProviderText(call.FileContent, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(call.ErrorCode, 1024, false) ||
		!validOptionalProviderText(call.ErrorMessage, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(call.ContainerExpiresAt, 1024, false) ||
		call.ContainerExpiresAt != nil && !validProviderRFC3339(*call.ContainerExpiresAt) ||
		!validProviderToolCaller(call.Caller) || len(call.Lines) > maxProviderResponseItems || len(call.Files) != 0 {
		return false
	}
	if call.Input != nil && !validProviderCodeExecutionInput(call.ToolName, *call.Input) {
		return false
	}
	for _, line := range call.Lines {
		if !validProviderText(line, maxProviderResponseBodySize, true) {
			return false
		}
	}
	for _, value := range []*int{call.NumLines, call.TotalLines, call.OldLines, call.NewLines} {
		if value != nil && *value < 0 {
			return false
		}
	}
	for _, value := range []*int{call.StartLine, call.OldStart, call.NewStart} {
		if value != nil && *value < 1 {
			return false
		}
	}
	return validProviderCodeExecutionResult(call)
}

func validProviderCodeExecutionInput(toolName, value string) bool {
	if len(value) > maxProviderResponseBodySize || !catalog.ValidateJSONObjectText(value) {
		return false
	}
	var input map[string]json.RawMessage
	if json.Unmarshal([]byte(value), &input) != nil {
		return false
	}
	validString := func(key string, allowEmpty bool) bool {
		field, ok := rawStringValue(input[key])
		return ok && validProviderText(field, maxProviderResponseBodySize, allowEmpty)
	}
	only := func(keys ...string) bool {
		if len(input) != len(keys) {
			return false
		}
		allowed := make(map[string]struct{}, len(keys))
		for _, key := range keys {
			allowed[key] = struct{}{}
		}
		for key := range input {
			if _, ok := allowed[key]; !ok {
				return false
			}
		}
		return true
	}

	switch toolName {
	case "code_execution":
		return only("code") && validString("code", false)
	case "bash_code_execution":
		return only("command") && validString("command", false)
	case "text_editor_code_execution":
		command, ok := rawStringValue(input["command"])
		if !ok || !validString("path", false) {
			return false
		}
		switch command {
		case "view":
			if only("command", "path") {
				return true
			}
			if !only("command", "path", "view_range") {
				return false
			}
			var viewRange []int
			return json.Unmarshal(input["view_range"], &viewRange) == nil && len(viewRange) == 2 &&
				viewRange[0] >= 1 && (viewRange[1] == -1 || viewRange[1] >= viewRange[0])
		case "create":
			return only("command", "path", "file_text") && validString("file_text", true)
		case "str_replace":
			return only("command", "path", "old_str", "new_str") &&
				validString("old_str", false) && validString("new_str", true)
		default:
			return false
		}
	default:
		return false
	}
}

func validProviderCodeExecutionResult(call *schemas.ResponsesCodeExecutionCall) bool {
	if call == nil {
		return false
	}
	if call.ResultType == "" {
		return !providerCodeExecutionResultPayloadSet(call)
	}

	noExecution := call.Stdout == nil && call.Stderr == nil && call.ReturnCode == nil && call.EncryptedStdout == nil
	noEditor := call.FileType == nil && call.FileContent == nil && call.StartLine == nil && call.NumLines == nil &&
		call.TotalLines == nil && call.IsFileUpdate == nil && call.OldStart == nil && call.OldLines == nil &&
		call.NewStart == nil && call.NewLines == nil && len(call.Lines) == 0
	noError := call.ErrorCode == nil && call.ErrorMessage == nil

	switch call.ResultType {
	case "code_execution_result":
		return call.ToolName == "code_execution" && call.Stdout != nil && call.Stderr != nil && call.ReturnCode != nil &&
			call.EncryptedStdout == nil && noEditor && noError
	case "encrypted_code_execution_result":
		return call.ToolName == "code_execution" && call.Stdout == nil && call.Stderr != nil && call.ReturnCode != nil &&
			call.EncryptedStdout != nil && noEditor && noError
	case "bash_code_execution_result":
		return call.ToolName == "bash_code_execution" && call.Stdout != nil && call.Stderr != nil && call.ReturnCode != nil &&
			call.EncryptedStdout == nil && noEditor && noError
	case "text_editor_code_execution_view_result":
		return call.ToolName == "text_editor_code_execution" && noExecution && noError && len(call.Files) == 0 &&
			call.FileType != nil && *call.FileType == "text" && call.FileContent != nil &&
			call.IsFileUpdate == nil && call.OldStart == nil && call.OldLines == nil && call.NewStart == nil &&
			call.NewLines == nil && len(call.Lines) == 0
	case "text_editor_code_execution_create_result":
		return call.ToolName == "text_editor_code_execution" && noExecution && noError && len(call.Files) == 0 &&
			call.IsFileUpdate != nil && call.FileType == nil && call.FileContent == nil && call.StartLine == nil &&
			call.NumLines == nil && call.TotalLines == nil && call.OldStart == nil && call.OldLines == nil &&
			call.NewStart == nil && call.NewLines == nil && len(call.Lines) == 0
	case "text_editor_code_execution_str_replace_result":
		return call.ToolName == "text_editor_code_execution" && noExecution && noError && len(call.Files) == 0 &&
			call.FileType == nil && call.FileContent == nil && call.StartLine == nil && call.NumLines == nil &&
			call.TotalLines == nil && call.IsFileUpdate == nil
	case "code_execution_tool_result_error":
		return call.ToolName == "code_execution" && noExecution && noEditor && len(call.Files) == 0 &&
			call.ErrorCode != nil && call.ErrorMessage == nil &&
			stringInSet(*call.ErrorCode, "invalid_tool_input", "unavailable", "too_many_requests", "execution_time_exceeded")
	case "bash_code_execution_tool_result_error":
		return call.ToolName == "bash_code_execution" && noExecution && noEditor && len(call.Files) == 0 &&
			call.ErrorCode != nil && call.ErrorMessage == nil &&
			stringInSet(*call.ErrorCode, "invalid_tool_input", "unavailable", "too_many_requests", "execution_time_exceeded", "output_file_too_large")
	case "text_editor_code_execution_tool_result_error":
		return call.ToolName == "text_editor_code_execution" && noExecution && noEditor && len(call.Files) == 0 &&
			call.ErrorCode != nil &&
			stringInSet(*call.ErrorCode, "invalid_tool_input", "unavailable", "too_many_requests", "execution_time_exceeded", "file_not_found")
	default:
		return false
	}
}

func providerCodeExecutionResultPayloadSet(call *schemas.ResponsesCodeExecutionCall) bool {
	return call.Stdout != nil || call.Stderr != nil || call.ReturnCode != nil || call.EncryptedStdout != nil ||
		call.FileType != nil || call.FileContent != nil || call.StartLine != nil || call.NumLines != nil ||
		call.TotalLines != nil || call.IsFileUpdate != nil || call.OldStart != nil || call.OldLines != nil ||
		call.NewStart != nil || call.NewLines != nil || len(call.Lines) != 0 || call.ErrorCode != nil ||
		call.ErrorMessage != nil || len(call.Files) != 0
}

func validProviderCodeExecutionNeutralMatch(
	interpreter *schemas.ResponsesCodeInterpreterToolCall,
	call *schemas.ResponsesCodeExecutionCall,
	allowPendingContainer bool,
) bool {
	if interpreter == nil || call == nil || call.Input == nil {
		return false
	}
	var input map[string]json.RawMessage
	if json.Unmarshal([]byte(*call.Input), &input) != nil {
		return false
	}
	if call.ToolName == "text_editor_code_execution" {
		if interpreter.Code != nil || len(interpreter.Outputs) != 0 {
			return false
		}
	} else {
		key := "code"
		if call.ToolName == "bash_code_execution" {
			key = "command"
		}
		code, ok := rawStringValue(input[key])
		if !ok || interpreter.Code == nil || *interpreter.Code != code {
			return false
		}
		wantLogs := call.Stdout != nil && *call.Stdout != ""
		if wantLogs {
			if len(interpreter.Outputs) != 1 || interpreter.Outputs[0].ResponsesCodeInterpreterOutputLogs == nil ||
				interpreter.Outputs[0].ResponsesCodeInterpreterOutputLogs.Logs != *call.Stdout {
				return false
			}
		} else if len(interpreter.Outputs) != 0 {
			return false
		}
	}
	return allowPendingContainer || interpreter.ContainerID != ""
}

func validProviderToolCaller(caller *schemas.ResponsesToolCaller) bool {
	if caller == nil {
		return true
	}
	switch caller.Type {
	case "direct":
		return caller.ToolID == nil
	case "code_execution_20250825", "code_execution_20260120", "code_execution_20260521":
		return caller.ToolID != nil && validProviderResponseID(*caller.ToolID)
	default:
		return false
	}
}

func validateProviderResponsesCallerReferences(output []schemas.ResponsesMessage) error {
	codeCalls := make(map[string]struct{})
	for index := range output {
		item := &output[index]
		if item.Type == nil || *item.Type != schemas.ResponsesMessageTypeCodeInterpreterCall || item.ID == nil {
			continue
		}
		codeCalls[*item.ID] = struct{}{}
		if item.ResponsesToolMessage != nil && item.ResponsesToolMessage.CallID != nil {
			codeCalls[*item.ResponsesToolMessage.CallID] = struct{}{}
		}
	}
	for index := range output {
		item := &output[index]
		if item.ResponsesToolMessage == nil {
			continue
		}
		callers := []*schemas.ResponsesToolCaller{item.ResponsesToolMessage.Caller}
		if item.ResponsesToolMessage.ResponsesCodeExecutionCall != nil {
			callers = append(callers, item.ResponsesToolMessage.ResponsesCodeExecutionCall.Caller)
		}
		for _, caller := range callers {
			if caller == nil || caller.Type == "direct" {
				continue
			}
			if caller.ToolID == nil {
				return ErrProviderResponseMalformed
			}
			if _, ok := codeCalls[*caller.ToolID]; !ok {
				return ErrProviderResponseMalformed
			}
		}
	}
	return nil
}

func providerResponsesStreamCallerReferencesCode(state *State, item *schemas.ResponsesMessage) bool {
	if state == nil || item == nil || item.ResponsesToolMessage == nil {
		return true
	}
	callers := []*schemas.ResponsesToolCaller{item.ResponsesToolMessage.Caller}
	if item.ResponsesToolMessage.ResponsesCodeExecutionCall != nil {
		callers = append(callers, item.ResponsesToolMessage.ResponsesCodeExecutionCall.Caller)
	}
	for _, caller := range callers {
		if caller == nil || caller.Type == "direct" {
			continue
		}
		if caller.ToolID == nil {
			return false
		}
		found := false
		for _, observed := range state.responsesItems {
			if observed.itemType == schemas.ResponsesMessageTypeCodeInterpreterCall &&
				(observed.id == *caller.ToolID || observed.callID == *caller.ToolID) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validateAndRecordProviderResponsesToolCall(state *State, item *schemas.ResponsesMessage, observed *providerResponsesItem, requireCallID bool) error {
	if item == nil || observed == nil || item.ResponsesToolMessage == nil {
		return ErrProviderResponseMalformed
	}
	observed.callID = observed.id
	if item.ResponsesToolMessage.CallID != nil {
		if !validProviderResponseID(*item.ResponsesToolMessage.CallID) {
			return ErrProviderResponseMalformed
		}
		observed.callID = *item.ResponsesToolMessage.CallID
	} else if requireCallID {
		return ErrProviderResponseMalformed
	}
	if state == nil {
		return nil
	}
	if state.responsesToolCallIDs == nil {
		state.responsesToolCallIDs = make(map[string]string)
	}
	identity := observed.id
	newCall := state.responsesToolCallIDs[observed.id] == ""
	for _, value := range []string{observed.id, observed.callID} {
		if prior, duplicate := state.responsesToolCallIDs[value]; duplicate && prior != identity {
			return ErrProviderResponseMalformed
		}
		state.responsesToolCallIDs[value] = identity
	}
	if newCall {
		state.responsesToolCalls++
		if state.responsesToolCalls > maxResponsesToolCalls {
			return ErrProviderResponseMalformed
		}
		switch *item.Type {
		case schemas.ResponsesMessageTypeFunctionCall, schemas.ResponsesMessageTypeCustomToolCall:
			state.responsesDeclaredCalls++
			state.responsesClientCalls++
		case schemas.ResponsesMessageTypeWebSearchCall, schemas.ResponsesMessageTypeWebFetchCall:
			state.responsesDeclaredCalls++
			state.responsesHostedCalls++
			if state.responsesHostedCalls > responsesTopLevelMaxToolCallsOrDefault(state) {
				return ErrProviderResponseMalformed
			}
		}
	}
	return nil
}

func validateProviderResponsesContent(state *State, content *schemas.ResponsesMessageContent) error {
	if content == nil || content.ContentStr != nil || content.ContentBlocks == nil ||
		len(content.ContentBlocks) > maxProviderResponseItems {
		return ErrProviderResponseMalformed
	}
	for index := range content.ContentBlocks {
		if err := validateProviderResponsesContentBlock(state, &content.ContentBlocks[index]); err != nil {
			return ErrProviderResponseMalformed
		}
	}
	return nil
}

func validateProviderResponsesStreamPartEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if state == nil || response == nil || response.Part == nil || response.OutputIndex == nil ||
		response.ContentIndex == nil || *response.ContentIndex >= maxProviderResponseItems {
		return ErrProviderResponseMalformed
	}
	item, ok := state.responsesItems[*response.OutputIndex]
	if !ok || item.done || validateProviderResponsesContentBlock(state, response.Part) != nil {
		return ErrProviderResponseMalformed
	}
	switch item.itemType {
	case schemas.ResponsesMessageTypeMessage:
		if response.Part.Type != schemas.ResponsesOutputMessageContentTypeText &&
			response.Part.Type != schemas.ResponsesOutputMessageContentTypeRefusal {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeReasoning:
		if response.Part.Type != schemas.ResponsesOutputMessageContentTypeReasoning {
			return ErrProviderResponseMalformed
		}
	default:
		return ErrProviderResponseMalformed
	}

	value, ok := providerResponsesBlockValue(response.Part)
	if !ok {
		return ErrProviderResponseMalformed
	}
	index := *response.ContentIndex
	part, exists := item.parts[index]
	if response.Type == schemas.ResponsesStreamResponseTypeContentPartAdded {
		if exists || index != len(item.parts) || value != "" {
			return ErrProviderResponseMalformed
		}
		var signature *string
		if response.Part.Signature != nil {
			copy := *response.Part.Signature
			signature = &copy
		}
		item.parts[index] = &providerResponsesPart{
			blockType:   response.Part.Type,
			signature:   signature,
			annotations: make(map[int]providerResponsesAnnotation),
		}
		return nil
	}
	if !exists || part.done || !part.valueDone || part.blockType != response.Part.Type || part.value.String() != value ||
		!sameProviderOptionalString(part.signature, response.Part.Signature) {
		return ErrProviderResponseMalformed
	}
	part.done = true
	return nil
}

func validateProviderResponsesReasoningPartEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if state == nil || response == nil || response.Part == nil || response.OutputIndex == nil ||
		response.SummaryIndex == nil || *response.SummaryIndex >= maxProviderResponseItems {
		return ErrProviderResponseMalformed
	}
	item, ok := state.responsesItems[*response.OutputIndex]
	if !ok || item.done || item.itemType != schemas.ResponsesMessageTypeReasoning {
		return ErrProviderResponseMalformed
	}
	value, ok := providerResponsesBlockValue(response.Part)
	if !ok {
		return ErrProviderResponseMalformed
	}
	index := *response.SummaryIndex
	part, exists := item.reasoningParts[index]
	if response.Type == schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded {
		if exists || index != len(item.reasoningParts) || value != "" {
			return ErrProviderResponseMalformed
		}
		item.reasoningParts[index] = &providerResponsesPart{blockType: response.Part.Type}
		return nil
	}
	if !exists || part.done || !part.valueDone || part.blockType != response.Part.Type || part.value.String() != value {
		return ErrProviderResponseMalformed
	}
	part.done = true
	return nil
}

func validateProviderResponsesTextEvent(state *State, response *schemas.BifrostResponsesStreamResponse, blockType schemas.ResponsesMessageContentBlockType) error {
	part := providerResponsesPartForEvent(state, response)
	if part == nil || part.done || part.blockType != blockType {
		return ErrProviderResponseMalformed
	}
	if !validOptionalProviderText(response.Delta, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(response.Signature, maxProviderResponseBodySize, false) ||
		!validOptionalProviderText(response.Text, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(response.Refusal, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(response.Obfuscation, maxProviderResponseBodySize, false) {
		return ErrProviderResponseMalformed
	}
	switch response.Type {
	case schemas.ResponsesStreamResponseTypeOutputTextDelta,
		schemas.ResponsesStreamResponseTypeRefusalDelta,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta:
		if part.valueDone {
			return ErrProviderResponseMalformed
		}
		if response.Signature != nil {
			if part.signature != nil {
				return ErrProviderResponseMalformed
			}
			copy := *response.Signature
			part.signature = &copy
		}
		if response.Delta != nil {
			if !appendProviderBuffer(&part.value, *response.Delta) {
				return ErrProviderResponseMalformed
			}
		}
		return nil
	case schemas.ResponsesStreamResponseTypeOutputTextDone,
		schemas.ResponsesStreamResponseTypeRefusalDone,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone:
		if part.valueDone {
			return ErrProviderResponseMalformed
		}
		value := response.Text
		if response.Type == schemas.ResponsesStreamResponseTypeRefusalDone {
			value = response.Refusal
		}
		if value == nil || part.value.String() != *value {
			return ErrProviderResponseMalformed
		}
		part.valueDone = true
		return nil
	default:
		return ErrProviderResponseMalformed
	}
}

func sameProviderOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func validateProviderResponsesToolValueEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if state == nil || response == nil || response.OutputIndex == nil {
		return ErrProviderResponseMalformed
	}
	item, ok := state.responsesItems[*response.OutputIndex]
	if !ok || item.done || item.value == nil || item.valueDone {
		return ErrProviderResponseMalformed
	}
	switch response.Type {
	case schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta,
		schemas.ResponsesStreamResponseTypeCustomToolCallInputDelta:
		if response.Delta == nil {
			return ErrProviderResponseMalformed
		}
		if !validProviderText(*response.Delta, maxProviderResponseBodySize, true) ||
			!validOptionalProviderText(response.Obfuscation, maxProviderResponseBodySize, false) {
			return ErrProviderResponseMalformed
		}
		if !appendProviderBuffer(item.value, *response.Delta) {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone:
		if response.Arguments == nil || item.value.String() != *response.Arguments ||
			!catalog.ValidateJSONObjectText(*response.Arguments) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesStreamResponseTypeCustomToolCallInputDone:
		if response.Input == nil || item.value.String() != *response.Input ||
			!validProviderText(*response.Input, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
	default:
		return ErrProviderResponseMalformed
	}
	item.valueDone = true
	state.responsesItems[*response.OutputIndex] = item
	return nil
}

func validateProviderResponsesHostedToolEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if state == nil || response == nil || response.OutputIndex == nil {
		return ErrProviderResponseMalformed
	}
	item, ok := state.responsesItems[*response.OutputIndex]
	if !ok || item.done {
		return ErrProviderResponseMalformed
	}
	next := item.stage
	switch response.Type {
	case schemas.ResponsesStreamResponseTypeWebSearchCallInProgress,
		schemas.ResponsesStreamResponseTypeWebFetchCallInProgress,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallInProgress:
		if item.stage != 0 {
			return ErrProviderResponseMalformed
		}
		next = 1
	case schemas.ResponsesStreamResponseTypeWebSearchCallSearching,
		schemas.ResponsesStreamResponseTypeWebFetchCallFetching:
		if item.stage != 1 {
			return ErrProviderResponseMalformed
		}
		next = 2
	case schemas.ResponsesStreamResponseTypeWebSearchCallResultsAdded:
		if item.stage != 2 {
			return ErrProviderResponseMalformed
		}
		next = 3
	case schemas.ResponsesStreamResponseTypeWebSearchCallResultsCompleted:
		if item.stage != 3 {
			return ErrProviderResponseMalformed
		}
		next = 4
	case schemas.ResponsesStreamResponseTypeWebSearchCallCompleted:
		if item.stage != 2 && item.stage != 4 {
			return ErrProviderResponseMalformed
		}
		next = 5
	case schemas.ResponsesStreamResponseTypeWebFetchCallCompleted:
		if item.stage != 2 {
			return ErrProviderResponseMalformed
		}
		next = 3
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDelta:
		if item.stage != 1 || item.code == nil || item.codeDone || response.Delta == nil ||
			!appendProviderBuffer(item.code, *response.Delta) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDone:
		if item.stage != 1 || item.code == nil || item.codeDone || response.Code == nil ||
			item.code.String() != *response.Code {
			return ErrProviderResponseMalformed
		}
		item.codeDone = true
		next = 2
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallInterpreting:
		if item.stage != 2 {
			return ErrProviderResponseMalformed
		}
		next = 3
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallCompleted:
		if item.stage != 3 {
			return ErrProviderResponseMalformed
		}
		next = 4
	default:
		return ErrProviderResponseMalformed
	}
	item.stage = next
	state.responsesItems[*response.OutputIndex] = item
	return nil
}

func appendProviderBuffer(buffer *bytes.Buffer, value string) bool {
	if buffer == nil || len(value) > maxProviderResponseBodySize-buffer.Len() {
		return false
	}
	_, _ = buffer.WriteString(value)
	return true
}

func validateProviderResponsesAnnotationEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	part := providerResponsesPartForEvent(state, response)
	if part == nil || part.done || part.blockType != schemas.ResponsesOutputMessageContentTypeText ||
		response.AnnotationIndex == nil || *response.AnnotationIndex >= maxProviderResponseItems {
		return ErrProviderResponseMalformed
	}
	index := *response.AnnotationIndex
	encoded, err := json.Marshal(response.Annotation)
	if err != nil {
		return ErrProviderResponseMalformed
	}
	observed, exists := part.annotations[index]
	if response.Type == schemas.ResponsesStreamResponseTypeOutputTextAnnotationAdded {
		if exists || index != len(part.annotations) {
			return ErrProviderResponseMalformed
		}
		part.annotations[index] = providerResponsesAnnotation{value: string(encoded)}
		return nil
	}
	if !exists || observed.done || observed.value != string(encoded) {
		return ErrProviderResponseMalformed
	}
	observed.done = true
	part.annotations[index] = observed
	return nil
}

func providerResponsesPartForEvent(state *State, response *schemas.BifrostResponsesStreamResponse) *providerResponsesPart {
	if state == nil || response == nil || response.OutputIndex == nil {
		return nil
	}
	item, ok := state.responsesItems[*response.OutputIndex]
	if !ok || item.done {
		return nil
	}
	if response.SummaryIndex != nil {
		return item.reasoningParts[*response.SummaryIndex]
	}
	if response.ContentIndex != nil {
		return item.parts[*response.ContentIndex]
	}
	return nil
}

func providerResponsesBlockValue(block *schemas.ResponsesMessageContentBlock) (string, bool) {
	if block == nil {
		return "", false
	}
	switch block.Type {
	case schemas.ResponsesOutputMessageContentTypeText, schemas.ResponsesOutputMessageContentTypeReasoning:
		if block.Text == nil {
			return "", false
		}
		return *block.Text, true
	case schemas.ResponsesOutputMessageContentTypeRefusal:
		if block.ResponsesOutputMessageContentRefusal == nil {
			return "", false
		}
		return block.ResponsesOutputMessageContentRefusal.Refusal, true
	default:
		return "", false
	}
}

func validateProviderResponsesContentBlock(state *State, block *schemas.ResponsesMessageContentBlock) error {
	if block == nil || block.FileID != nil || block.ResponsesInputMessageContentBlockImage != nil ||
		block.ResponsesInputMessageContentBlockFile != nil || block.Audio != nil ||
		block.ResponsesOutputMessageContentRenderedContent != nil ||
		block.ResponsesOutputMessageContentFallback != nil || block.PromptCacheBreakpoint != nil ||
		block.Citations != nil || !validProviderCacheControl(block.CacheControl) {
		return ErrProviderResponseMalformed
	}

	switch block.Type {
	case schemas.ResponsesOutputMessageContentTypeText:
		if block.Text == nil || !validProviderText(*block.Text, maxProviderResponseBodySize, true) ||
			block.Signature != nil || block.EncryptedContent != nil ||
			block.ResponsesOutputMessageContentRefusal != nil || block.ResponsesOutputMessageContentCompaction != nil ||
			validateProviderResponsesOutputText(state, block.ResponsesOutputMessageContentText) != nil {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesOutputMessageContentTypeRefusal:
		if block.Text != nil || block.Signature != nil || block.EncryptedContent != nil ||
			block.ResponsesOutputMessageContentText != nil || block.ResponsesOutputMessageContentRefusal == nil ||
			!validProviderText(block.ResponsesOutputMessageContentRefusal.Refusal, maxProviderResponseBodySize, true) ||
			block.ResponsesOutputMessageContentCompaction != nil {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesOutputMessageContentTypeReasoning:
		if block.Text == nil && block.EncryptedContent == nil ||
			!validOptionalProviderText(block.Text, maxProviderResponseBodySize, true) ||
			!validOptionalProviderText(block.Signature, maxProviderResponseBodySize, false) ||
			!validOptionalProviderText(block.EncryptedContent, maxProviderResponseBodySize, false) ||
			block.ResponsesOutputMessageContentText != nil || block.ResponsesOutputMessageContentRefusal != nil ||
			block.ResponsesOutputMessageContentCompaction != nil {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesOutputMessageContentTypeCompaction:
		if state == nil || state.Resolution == nil ||
			!anthropicContextManagementUsesCompaction(state.Resolution.RawBody()["context_management"]) ||
			block.Text != nil || block.Signature != nil || block.EncryptedContent != nil ||
			block.ResponsesOutputMessageContentText != nil || block.ResponsesOutputMessageContentRefusal != nil ||
			block.ResponsesOutputMessageContentCompaction == nil ||
			!validProviderText(block.ResponsesOutputMessageContentCompaction.Summary, maxProviderResponseBodySize, false) {
			return ErrProviderResponseMalformed
		}
	default:
		return ErrProviderResponseMalformed
	}
	return nil
}

func validProviderText(value string, maxBytes int, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= maxBytes && utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}

func validOptionalProviderText(value *string, maxBytes int, allowEmpty bool) bool {
	return value == nil || validProviderText(*value, maxBytes, allowEmpty)
}

func validateProviderResponsesOutputText(state *State, output *schemas.ResponsesOutputMessageContentText) error {
	if output == nil {
		return nil
	}
	if len(output.Annotations) > maxProviderResponseItems || validateProviderResponsesLogProbs(output.LogProbs) != nil {
		return ErrProviderResponseMalformed
	}
	for index := range output.Annotations {
		if validateProviderResponsesAnnotation(state, &output.Annotations[index]) != nil {
			return ErrProviderResponseMalformed
		}
	}
	return nil
}

func validateProviderResponsesLogProbs(values []schemas.ResponsesOutputMessageContentTextLogProb) error {
	if len(values) > maxProviderResponseItems {
		return ErrProviderResponseMalformed
	}
	for _, value := range values {
		if !validProviderLogProb(value.Token, value.LogProb, value.Bytes) || len(value.TopLogProbs) > 20 {
			return ErrProviderResponseMalformed
		}
		for _, top := range value.TopLogProbs {
			if !validProviderLogProb(top.Token, top.LogProb, top.Bytes) {
				return ErrProviderResponseMalformed
			}
		}
	}
	return nil
}

func validateProviderResponsesAnnotation(state *State, annotation *schemas.ResponsesOutputMessageContentTextAnnotation) error {
	if annotation == nil || negativeOptionalInt(annotation.Index) || negativeOptionalInt(annotation.StartIndex) ||
		negativeOptionalInt(annotation.EndIndex) || negativeOptionalInt(annotation.StartCharIndex) ||
		negativeOptionalInt(annotation.EndCharIndex) || negativeOptionalInt(annotation.StartPageNumber) ||
		negativeOptionalInt(annotation.EndPageNumber) || negativeOptionalInt(annotation.StartBlockIndex) ||
		negativeOptionalInt(annotation.EndBlockIndex) || !orderedOptionalRange(annotation.StartIndex, annotation.EndIndex) ||
		!orderedOptionalRange(annotation.StartCharIndex, annotation.EndCharIndex) ||
		!orderedOptionalRange(annotation.StartPageNumber, annotation.EndPageNumber) ||
		!orderedOptionalRange(annotation.StartBlockIndex, annotation.EndBlockIndex) ||
		annotation.FileID != nil && !validProviderResponseID(*annotation.FileID) ||
		annotation.ContainerID != nil && !validProviderResponseID(*annotation.ContainerID) ||
		(annotation.StartIndex == nil) != (annotation.EndIndex == nil) ||
		annotation.URL != nil && !validProviderHTTPURL(*annotation.URL) {
		return ErrProviderResponseMalformed
	}
	if annotation.Type != "url_citation" || annotation.URL == nil ||
		!providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeWebSearch) ||
		!providerResponsesURLAllowed(state, schemas.ResponsesToolTypeWebSearch, *annotation.URL) ||
		annotation.FileID != nil || annotation.Filename != nil || annotation.ContainerID != nil ||
		annotation.StartCharIndex != nil || annotation.EndCharIndex != nil ||
		annotation.StartPageNumber != nil || annotation.EndPageNumber != nil ||
		annotation.StartBlockIndex != nil || annotation.EndBlockIndex != nil || annotation.Source != nil ||
		!validOptionalProviderText(annotation.Title, 64*1024, true) ||
		!validOptionalProviderText(annotation.Text, 1024*1024, true) ||
		!validOptionalProviderText(annotation.EncryptedIndex, 16*1024*1024, true) {
		return ErrProviderResponseMalformed
	}
	return nil
}

func orderedOptionalRange(start, end *int) bool {
	return start == nil || end == nil || *start <= *end
}

func validProviderCacheControl(value *schemas.CacheControl) bool {
	if value == nil {
		return true
	}
	if value.Type != schemas.CacheControlTypeEphemeral || value.Scope != nil {
		return false
	}
	return value.TTL == nil || *value.TTL == "5m" || *value.TTL == "1h"
}

func providerResponsesToolTypeAllowed(state *State, wanted schemas.ResponsesToolType) bool {
	if state == nil || state.Resolution == nil || state.Resolution.Route != catalog.RouteResponses {
		return false
	}
	for _, rawType := range effectiveResponsesToolTypes(state.Resolution.RawBody(), state.Resolution.ToolTypes()) {
		if canonicalResponsesToolType(rawType) == wanted ||
			wanted == schemas.ResponsesToolTypeWebSearch && canonicalResponsesToolType(rawType) == schemas.ResponsesToolTypeWebSearchPreview {
			return true
		}
	}
	return false
}

func providerResponsesImplicitCodeExecutionAllowed(state *State) bool {
	return state != nil && state.Resolution != nil &&
		(state.Resolution.Provider == schemas.Anthropic ||
			state.Resolution.Provider == schemas.Azure && azureDeploymentUsesAnthropicWire(state)) &&
		(providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeWebSearch) ||
			providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeWebFetch))
}

func providerResponsesToolNameAllowed(state *State, kind schemas.ResponsesToolType, name string) bool {
	if !validClientToolName(name) || !providerResponsesToolTypeAllowed(state, kind) {
		return false
	}
	declared := false
	for _, tool := range state.Resolution.RawTools() {
		if canonicalResponsesToolType(rawString(tool["type"])) == kind && rawString(tool["name"]) == name {
			declared = true
			break
		}
	}
	if !declared {
		return false
	}
	choice := state.Resolution.RawBody()["tool_choice"]
	if selected, ok := rawStringValue(choice); ok {
		return selected != "none"
	}
	object, ok := rawObject(choice)
	if !ok {
		return true
	}
	if rawString(object["type"]) == "allowed_tools" {
		var allowed []map[string]json.RawMessage
		if err := json.Unmarshal(object["tools"], &allowed); err != nil {
			return false
		}
		for _, tool := range allowed {
			if canonicalResponsesToolType(rawString(tool["type"])) == kind && rawString(tool["name"]) == name {
				return true
			}
		}
		return false
	}
	selectedType := canonicalResponsesToolType(rawString(object["type"]))
	if selectedType != schemas.ResponsesToolTypeFunction && selectedType != schemas.ResponsesToolTypeCustom {
		return true
	}
	return selectedType == kind && rawString(object["name"]) == name
}

func sameProviderResponsesItem(left, right providerResponsesItem) bool {
	return left.id == right.id && left.callID == right.callID && left.itemType == right.itemType && left.name == right.name &&
		left.toolCallerPayload == right.toolCallerPayload && left.toolKind == right.toolKind &&
		(left.toolActionPayload == "" || left.toolActionPayload == right.toolActionPayload)
}

func rawProviderExtensionSet(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null"))
}
