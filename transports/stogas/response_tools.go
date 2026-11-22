package stogas

import (
	"bytes"
	"encoding/json"
	"math"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	providerutils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"golang.org/x/net/idna"
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
		strings.ContainsRune(token, '\x00') {
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
	if !terminal && (len(response.Output) != 0 || response.CompletedAt != nil ||
		response.StopReason != nil || response.StopDetails != nil) {
		return ErrProviderResponseMalformed
	}
	if !validProviderResponsesStatusDetails(state, response) {
		return ErrProviderResponseMalformed
	}
	if terminal && state != nil && state.responsesStreamSeen && len(response.Output) != len(state.responsesItems) {
		return ErrProviderResponseMalformed
	}
	if response.Background != nil && *response.Background || response.Prompt != nil || response.Container != nil ||
		response.Error != nil || !providerResponsesStateEchoed(state, response) {
		return ErrProviderResponseMalformed
	}
	if response.MaxToolCalls != nil {
		if cap, supplied := responsesExplicitMaxToolCalls(state); *response.MaxToolCalls < 1 || supplied && *response.MaxToolCalls > cap {
			return ErrProviderResponseMalformed
		}
	}
	// Only a reply that the provider cut holds an unfinished call, or no call that the request required.
	cut := response.Status != nil && *response.Status == schemas.ResponsesResponseStatusIncomplete
	seenIDs := make(map[string]struct{}, len(response.Output))
	for index := range response.Output {
		item := &response.Output[index]
		observed, err := validateProviderResponsesItem(state, item)
		if err != nil {
			return err
		}
		if terminal && (validateProviderResponsesTerminalItem(item, false) != nil || !cut && providerResponsesItemIncompleteCall(item)) {
			return ErrProviderResponseMalformed
		}
		if _, duplicate := seenIDs[observed.id]; duplicate {
			return ErrProviderResponseMalformed
		}
		seenIDs[observed.id] = struct{}{}
		if state != nil && !state.responsesStreamSeen {
			state.observeResponsesToolCall(observed, time.Time{})
		}
		if terminal && state != nil && state.responsesStreamSeen {
			streamItem, ok := state.responsesItems[index]
			if !ok || !streamItem.done || !sameProviderResponsesItem(streamItem, observed) ||
				validateProviderResponsesCompletedStreamItem(streamItem, providerResponsesStreamedItem(state, response, index)) != nil {
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
	if terminal && state != nil && !cut {
		if providerResponsesToolCallRequired(state) && state.responsesDeclaredCalls == 0 {
			return ErrProviderResponseMalformed
		}
	}
	return sanitizeProviderResponsesEcho(state, response)
}

// providerResponsesStateEchoed reports a reply that keeps only the provider state that the request
// asked for: a stored reply only when the provider got store: true, and a conversation or a
// previous reply only when the request named one.
func providerResponsesStateEchoed(state *State, response *schemas.BifrostResponsesResponse) bool {
	var asked catalog.ProviderState
	if state != nil {
		asked = state.Resolution.ProviderState()
	}
	return (response.Store == nil || !*response.Store || asked.Store) &&
		(response.Conversation == nil || slices.Contains(asked.Fields, "conversation")) &&
		(response.PreviousResponseID == nil || slices.Contains(asked.Fields, "previous_response_id"))
}

func providerResponsesToolCallRequired(state *State) bool {
	if state == nil || state.Resolution == nil {
		return false
	}
	choice := state.Resolution.WireView().RawBody()["tool_choice"]
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
			anthropicContextManagementUsesCompaction(state.Resolution.WireView().RawBody()["context_management"])
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
	Background           *bool                                  `json:"background"`
	Conversation         *schemas.ResponsesResponseConversation `json:"conversation"`
	PreviousResponseID   *string                                `json:"previous_response_id"`
	Include              []string                               `json:"include"`
	Instructions         *string                                `json:"instructions"`
	MaxOutputTokens      *int                                   `json:"max_output_tokens"`
	MaxToolCalls         *int                                   `json:"max_tool_calls"`
	Metadata             *map[string]any                        `json:"metadata"`
	ParallelToolCalls    *bool                                  `json:"parallel_tool_calls"`
	PromptCacheKey       *string                                `json:"prompt_cache_key"`
	PromptCacheRetention *string                                `json:"prompt_cache_retention"`
	PromptCacheOptions   *schemas.PromptCacheOptions            `json:"prompt_cache_options"`
	PresencePenalty      *float64                               `json:"presence_penalty"`
	FrequencyPenalty     *float64                               `json:"frequency_penalty"`
	Reasoning            *schemas.ResponsesParametersReasoning  `json:"reasoning"`
	SafetyIdentifier     *string                                `json:"safety_identifier"`
	StreamOptions        *schemas.ResponsesStreamOptions        `json:"stream_options"`
	Temperature          *float64                               `json:"temperature"`
	Text                 *schemas.ResponsesTextConfig           `json:"text"`
	TopLogProbs          *int                                   `json:"top_logprobs"`
	TopP                 *float64                               `json:"top_p"`
	ToolChoice           *schemas.ResponsesToolChoice           `json:"tool_choice"`
	Tools                []schemas.ResponsesTool                `json:"tools"`
	Truncation           *string                                `json:"truncation"`
}

func sanitizeProviderResponsesEcho(state *State, response *schemas.BifrostResponsesResponse) error {
	if response == nil {
		return ErrProviderResponseMalformed
	}
	trusted := trustedResponsesEcho{}
	if state != nil && state.Resolution != nil {
		body := state.Resolution.WireView().RawBody()
		encoded, err := json.Marshal(body)
		if err != nil || json.Unmarshal(encoded, &trusted) != nil {
			return ErrProviderResponseMalformed
		}
		if trusted.Reasoning == nil {
			if rawEffort := body["reasoning.effort"]; len(rawEffort) != 0 {
				var effort string
				if json.Unmarshal(rawEffort, &effort) != nil {
					return ErrProviderResponseMalformed
				}
				trusted.Reasoning = &schemas.ResponsesParametersReasoning{Effort: &effort}
			}
		}
	}
	response.Background = schemas.Ptr(false)
	response.Store = schemas.Ptr(state != nil && state.Resolution.ProviderState().Store)
	response.PreviousResponseID = trusted.PreviousResponseID
	response.Conversation = nil
	if trusted.Conversation != nil {
		// OpenAI gives the conversation as an object, whichever form the request named it in.
		id := trusted.Conversation.ResponsesResponseConversationStr
		if trusted.Conversation.ResponsesResponseConversationStruct != nil {
			id = &trusted.Conversation.ResponsesResponseConversationStruct.ID
		}
		response.Conversation = &schemas.ResponsesResponseConversation{
			ResponsesResponseConversationStruct: &schemas.ResponsesResponseConversationStruct{ID: *id},
		}
	}
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
	response.Tools = redactResponsesToolCredentials(trusted.Tools)
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
	case schemas.ResponsesStreamResponseTypeApplyPatchCallOperationDiffDelta:
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeApplyPatch) || response.Delta == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeApplyPatchCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesToolValueEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeApplyPatchCallOperationDiffDone:
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeApplyPatch) || response.Diff == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeApplyPatchCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID) ||
			validateProviderResponsesToolValueEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeShellCallCommandAdded,
		schemas.ResponsesStreamResponseTypeShellCallCommandDelta,
		schemas.ResponsesStreamResponseTypeShellCallCommandDone:
		// OpenAI names the call of a command event by its output index alone.
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeShell) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesShellCommandEvent(state, response) != nil {
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
	case schemas.ResponsesStreamResponseTypeFileSearchCallInProgress,
		schemas.ResponsesStreamResponseTypeFileSearchCallSearching,
		schemas.ResponsesStreamResponseTypeFileSearchCallCompleted:
		if !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeFileSearch) ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeFileSearchCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference) ||
			validateProviderResponsesHostedToolEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallInProgress,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallInterpreting,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallCompleted:
		if !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeCodeInterpreterCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference) ||
			validateProviderResponsesHostedToolEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDelta:
		if response.Delta == nil || !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeCodeInterpreterCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesToolValueEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDone:
		if response.Code == nil || !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeCodeInterpreterCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadCode) ||
			validateProviderResponsesToolValueEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeShellCallOutputContentDelta,
		schemas.ResponsesStreamResponseTypeShellCallOutputContentDone:
		if !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeShellCallOutput) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference) ||
			validateProviderResponsesShellOutputEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeMCPListToolsInProgress,
		schemas.ResponsesStreamResponseTypeMCPListToolsCompleted,
		schemas.ResponsesStreamResponseTypeMCPListToolsFailed:
		if !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeMCPListTools) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference) ||
			validateProviderResponsesMCPEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeMCPCallInProgress,
		schemas.ResponsesStreamResponseTypeMCPCallCompleted,
		schemas.ResponsesStreamResponseTypeMCPCallFailed:
		if !responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeMCPCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference) ||
			validateProviderResponsesMCPEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeMCPCallArgumentsDelta:
		if response.Delta == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeMCPCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesMCPArgumentsEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeMCPCallArgumentsDone:
		if response.Arguments == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeMCPCall) ||
			responsesStreamUnexpectedPayload(response, responsePayloadItemReference|responsePayloadArguments) ||
			validateProviderResponsesMCPArgumentsEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartDone:
		if response.Part == nil || response.SummaryIndex == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeReasoning) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadSummaryIndex|responsePayloadPart) ||
			validateProviderResponsesSummaryPart(state, response.Part) != nil ||
			validateProviderResponsesReasoningPartEvent(state, response) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta:
		if response.Delta == nil || response.SummaryIndex == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeReasoning) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadSummaryIndex|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeSummaryText) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone:
		if response.Text == nil || response.SummaryIndex == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeReasoning) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadSummaryIndex|responsePayloadText) ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeSummaryText) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeReasoningTextDelta:
		if response.Delta == nil || response.ContentIndex == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeReasoning) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadContentIndex|responsePayloadDelta|responsePayloadObfuscation) ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeReasoning) != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeReasoningTextDone:
		if response.Text == nil || response.ContentIndex == nil ||
			!responsesStreamHasItemType(state, response, schemas.ResponsesMessageTypeReasoning) ||
			responsesStreamUnexpectedPayload(response, responsePayloadOutputIndex|responsePayloadItemID|responsePayloadContentIndex|responsePayloadText) ||
			validateProviderResponsesTextEvent(state, response, schemas.ResponsesOutputMessageContentTypeReasoning) != nil {
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
			len(providerShellCommands(response.Item)) != 0 ||
			!providerResponsesInitialPayloadAllowed(response.Item, item.compactionPayload) {
			return ErrProviderResponseMalformed
		}
		state.responsesItems[index] = item
		state.observeResponsesToolCall(item, time.Now())
		return nil
	}
	if !exists || prior.done || response.Item.Status != nil && *response.Item.Status == "in_progress" ||
		!sameProviderResponsesItem(prior, item) ||
		validateProviderResponsesTerminalItem(response.Item, responsesUsesAnthropicWire(state)) != nil ||
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
	state.finishResponsesToolCall(prior, time.Now())
	return nil
}

func providerResponsesInitialPayloadAllowed(item *schemas.ResponsesMessage, compactionPayload string) bool {
	if item == nil || item.Type == nil {
		return false
	}
	switch *item.Type {
	case schemas.ResponsesMessageTypeMessage:
		return item.Content != nil && (len(item.Content.ContentBlocks) == 0 || compactionPayload != "")
	case schemas.ResponsesMessageTypeReasoning:
		// OpenAI's initial encrypted content may be provisional. Visible content
		// still belongs to its own part events; output_item.done owns the final blob.
		return (item.Content == nil || len(item.Content.ContentBlocks) == 0) &&
			(item.ResponsesReasoning == nil || len(item.ResponsesReasoning.Summary) == 0)
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
	case schemas.ResponsesMessageTypeApplyPatchCall:
		// A patch that deletes a file has no diff.
		if patch := item.ResponsesToolMessage.ResponsesApplyPatchCall; patch != nil && patch.Operation != nil && patch.Operation.Diff != nil {
			return *patch.Operation.Diff, true
		}
		return "", true
	case schemas.ResponsesMessageTypeCodeInterpreterCall:
		if call := item.ResponsesToolMessage.ResponsesCodeInterpreterToolCall; call != nil && call.Code != nil {
			return *call.Code, true
		}
		return "", true
	default:
		return "", false
	}
}

// providerComputerActions returns the actions of a computer call: its list, or the one action of a
// call of the retired preview.
func providerComputerActions(tool *schemas.ResponsesToolMessage) []schemas.ResponsesComputerToolCallAction {
	if tool == nil {
		return nil
	}
	if tool.ResponsesComputerToolCall != nil && len(tool.ResponsesComputerToolCall.Actions) > 0 {
		return tool.ResponsesComputerToolCall.Actions
	}
	if tool.Action != nil && tool.Action.ResponsesComputerToolCallAction != nil {
		return []schemas.ResponsesComputerToolCallAction{*tool.Action.ResponsesComputerToolCallAction}
	}
	return nil
}

// providerShellCommands returns the commands of a shell call.
func providerShellCommands(item *schemas.ResponsesMessage) []string {
	if item == nil || item.ResponsesToolMessage == nil || item.ResponsesToolMessage.Action == nil ||
		item.ResponsesToolMessage.Action.ResponsesShellToolCallAction == nil {
		return nil
	}
	return item.ResponsesToolMessage.Action.ResponsesShellToolCallAction.Commands
}

// validateProviderResponsesTerminalItem checks an item that the provider has ended. A function
// call that it finished holds a JSON object. A reply that the provider cut keeps the call that it
// was writing as an incomplete item with its unfinished arguments, as OpenAI sends it (capture
// openai/tool-call-cut-at-output-limit). beforeStopReason says that the item ends in a stream
// before the reply's stop reason arrives, as on Anthropic's wire, where core completes each item
// and marks the last one incomplete in the terminal response.
func validateProviderResponsesTerminalItem(item *schemas.ResponsesMessage, beforeStopReason bool) error {
	if item == nil || item.Type == nil {
		return ErrProviderResponseMalformed
	}
	switch *item.Type {
	case schemas.ResponsesMessageTypeMCPListTools, schemas.ResponsesMessageTypeMCPApprovalRequest:
		// OpenAI's listings and approval requests have no status of their own.
		if item.Status != nil && !stringInSet(*item.Status, "completed", "incomplete", "failed") {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesMessageTypeMCPCall:
		// A call's status is optional, and a failed call carries its error.
		if item.Status != nil && !stringInSet(*item.Status, "completed", "incomplete", "failed") {
			return ErrProviderResponseMalformed
		}
		return nil
	}
	// Reasoning status is optional in OpenAI's Responses wire contract.
	if *item.Type == schemas.ResponsesMessageTypeReasoning {
		if item.Status != nil && !stringInSet(*item.Status, "completed", "incomplete") {
			return ErrProviderResponseMalformed
		}
		return nil
	}
	if item.Status == nil {
		return ErrProviderResponseMalformed
	}
	switch *item.Type {
	case schemas.ResponsesMessageTypeMessage:
		if !stringInSet(*item.Status, "completed", "incomplete") || item.Content == nil || len(item.Content.ContentBlocks) == 0 {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeFunctionCall:
		if !stringInSet(*item.Status, "completed", "incomplete") || item.ResponsesToolMessage == nil || item.ResponsesToolMessage.Arguments == nil ||
			!validProviderText(*item.ResponsesToolMessage.Arguments, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
		if *item.Status == "completed" && !beforeStopReason && !catalog.ValidateJSONObjectText(*item.ResponsesToolMessage.Arguments) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeCustomToolCall:
		if *item.Status != "completed" || item.ResponsesToolMessage == nil || item.ResponsesToolMessage.ResponsesCustomToolCall == nil ||
			!validProviderText(item.ResponsesToolMessage.ResponsesCustomToolCall.Input, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeShellCall, schemas.ResponsesMessageTypeShellCallOutput, schemas.ResponsesMessageTypeComputerCall:
		if !stringInSet(*item.Status, "completed", "incomplete") {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeCodeInterpreterCall:
		// max_tool_calls leaves a call that it stops with the status interpreting (capture
		// openai/container-tool-calls).
		if !stringInSet(*item.Status, "completed", "incomplete", "interpreting", "failed") {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeApplyPatchCall:
		if !stringInSet(*item.Status, "completed", "incomplete") || item.ResponsesToolMessage == nil ||
			item.ResponsesToolMessage.ResponsesApplyPatchCall == nil || item.ResponsesToolMessage.ResponsesApplyPatchCall.Operation == nil {
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
	case schemas.ResponsesMessageTypeFileSearchCall:
		if !stringInSet(*item.Status, "completed", "incomplete", "failed") || item.ResponsesToolMessage == nil ||
			item.ResponsesToolMessage.ResponsesFileSearchToolCall == nil {
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
	case schemas.ResponsesMessageTypeToolSearchCall:
		if !stringInSet(*item.Status, "completed", "incomplete") || item.ResponsesToolMessage == nil || item.ResponsesToolMessage.Arguments == nil {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeToolSearchOutput:
		if !stringInSet(*item.Status, "completed", "incomplete") || len(item.ToolSearchOutputTools) == 0 {
			return ErrProviderResponseMalformed
		}
	}
	return nil
}

// numberAnthropicResponsesContentPart replaces the Anthropic block index that
// core's conversion sends as content_index. Each block becomes its own output
// item, so its content part is the item's first.
func numberAnthropicResponsesContentPart(state *State, response *schemas.BifrostResponsesStreamResponse) {
	if response.ContentIndex != nil && responsesUsesAnthropicWire(state) {
		response.ContentIndex = schemas.Ptr(0)
	}
}

// providerResponsesStreamedItem returns a terminal output item as the stream
// completed it. Core's Anthropic conversion completes each item before the stop
// reason arrives, then marks the last one incomplete in a truncated or refused
// terminal response.
func providerResponsesStreamedItem(state *State, response *schemas.BifrostResponsesResponse, index int) *schemas.ResponsesMessage {
	item := &response.Output[index]
	if !responsesUsesAnthropicWire(state) || index != len(response.Output)-1 ||
		response.Status == nil || *response.Status != schemas.ResponsesResponseStatusIncomplete ||
		item.Status == nil || *item.Status != schemas.ResponsesResponseStatusIncomplete {
		return item
	}
	streamed := *item
	streamed.Status = schemas.Ptr("completed")
	return &streamed
}

// providerResponsesItemIncompleteCall reports a function call that the provider did not finish.
func providerResponsesItemIncompleteCall(item *schemas.ResponsesMessage) bool {
	return item.Type != nil && *item.Type == schemas.ResponsesMessageTypeFunctionCall &&
		item.Status != nil && *item.Status == "incomplete"
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
	if streamItem.itemType == schemas.ResponsesMessageTypeMCPCall {
		if err := validateProviderResponsesCompletedMCPItem(streamItem, finalItem); err != nil {
			return err
		}
	} else if streamItem.value != nil {
		value, ok := providerResponsesToolItemValue(finalItem)
		// A patch without a diff, which deletes a file, streams none, and neither does a code
		// interpreter call without code.
		withoutValue := (streamItem.itemType == schemas.ResponsesMessageTypeApplyPatchCall ||
			streamItem.itemType == schemas.ResponsesMessageTypeCodeInterpreterCall) && !streamItem.valueDone && streamItem.value.Len() == 0
		if !ok || !streamItem.valueDone && !withoutValue || value != streamItem.value.String() {
			return ErrProviderResponseMalformed
		}
	}
	if streamItem.itemType == schemas.ResponsesMessageTypeShellCall && len(streamItem.commands) != 0 {
		commands := providerShellCommands(finalItem)
		if len(commands) != len(streamItem.commands) {
			return ErrProviderResponseMalformed
		}
		for index, command := range streamItem.commands {
			if command == nil || !command.done || command.value.String() != commands[index] {
				return ErrProviderResponseMalformed
			}
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
		if len(streamItem.parts) == 0 && !providerResponsesCompactionPayloadMatches(streamItem.compactionPayload, finalItem) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeReasoning:
		// The encrypted blob can first arrive or change at item completion.
		// Visible parts cannot appear without their corresponding stream events.
		if len(streamItem.parts) == 0 && finalItem.Content != nil && len(finalItem.Content.ContentBlocks) != 0 ||
			len(streamItem.reasoningParts) == 0 && finalItem.ResponsesReasoning != nil && len(finalItem.ResponsesReasoning.Summary) != 0 {
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
	if item.ResponsesReasoning != nil && item.ResponsesReasoning.EncryptedContent != nil {
		// OpenAI can re-encode the opaque reasoning blob in response.completed.
		// Bind its presence, identity and visible content, not ciphertext equality.
		reasoning := *item.ResponsesReasoning
		reasoning.EncryptedContent = schemas.Ptr("present")
		copyItem.ResponsesReasoning = &reasoning
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
		if item.ResponsesReasoning.Summary[index].Text != part.value.String() {
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
	if item.Status != nil && !stringInSet(*item.Status, "in_progress", "completed", "incomplete", "failed") &&
		!(*item.Type == schemas.ResponsesMessageTypeMCPCall && *item.Status == "calling") &&
		!(*item.Type == schemas.ResponsesMessageTypeCodeInterpreterCall && *item.Status == "interpreting") {
		return providerResponsesItem{}, ErrProviderResponseMalformed
	}
	if item.Role != nil && *item.Role != schemas.ResponsesInputMessageRoleAssistant ||
		rawProviderExtensionSet(item.Author) || rawProviderExtensionSet(item.Recipient) ||
		rawProviderExtensionSet(item.ToolSearchOutputTools) && *item.Type != schemas.ResponsesMessageTypeToolSearchOutput ||
		rawProviderExtensionSet(item.AdditionalTools) ||
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
		if item.Phase != nil || item.ResponsesToolMessage != nil || (item.Content == nil && item.ResponsesReasoning == nil) {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		if item.Content != nil && validateProviderResponsesContent(state, item.Content) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		if item.Content != nil {
			for _, block := range item.Content.ContentBlocks {
				if block.Type != schemas.ResponsesOutputMessageContentTypeReasoning {
					return providerResponsesItem{}, ErrProviderResponseMalformed
				}
			}
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
			!providerResponsesToolNameAllowed(state, kind, providerCallNamespace(item.ResponsesToolMessage), *item.ResponsesToolMessage.Name) {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		observed.name = *item.ResponsesToolMessage.Name
		observed.namespace = providerCallNamespace(item.ResponsesToolMessage)
		observed.value = &bytes.Buffer{}
		if err := validateAndRecordProviderResponsesToolCall(state, item, &observed, true); err != nil {
			return providerResponsesItem{}, err
		}
	case schemas.ResponsesMessageTypeShellCall, schemas.ResponsesMessageTypeApplyPatchCall, schemas.ResponsesMessageTypeComputerCall:
		kind := schemas.ResponsesToolTypeShell
		switch *item.Type {
		case schemas.ResponsesMessageTypeApplyPatchCall:
			kind = schemas.ResponsesToolTypeApplyPatch
			observed.value = &bytes.Buffer{}
		case schemas.ResponsesMessageTypeComputerCall:
			kind = schemas.ResponsesToolTypeComputer
		}
		if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil ||
			!providerResponsesToolTypeAllowed(state, kind) || item.ResponsesToolMessage == nil ||
			validateProviderResponsesToolMessage(state, item.ResponsesToolMessage, *item.Type) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		if err := validateAndRecordProviderResponsesToolCall(state, item, &observed, true); err != nil {
			return providerResponsesItem{}, err
		}
	case schemas.ResponsesMessageTypeWebSearchCall, schemas.ResponsesMessageTypeWebFetchCall, schemas.ResponsesMessageTypeFileSearchCall:
		kind := schemas.ResponsesToolTypeWebSearch
		switch *item.Type {
		case schemas.ResponsesMessageTypeWebFetchCall:
			kind = schemas.ResponsesToolTypeWebFetch
		case schemas.ResponsesMessageTypeFileSearchCall:
			kind = schemas.ResponsesToolTypeFileSearch
		}
		if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil ||
			!providerResponsesToolTypeAllowed(state, kind) || item.ResponsesToolMessage == nil ||
			validateProviderResponsesToolMessage(state, item.ResponsesToolMessage, *item.Type) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		if err := validateAndRecordProviderResponsesToolCall(state, item, &observed, false); err != nil {
			return providerResponsesItem{}, err
		}
	case schemas.ResponsesMessageTypeCodeInterpreterCall:
		if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil ||
			!providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeCodeInterpreter) || item.ResponsesToolMessage == nil ||
			validateProviderResponsesToolMessage(state, item.ResponsesToolMessage, *item.Type) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		observed.value = &bytes.Buffer{}
		if err := validateAndRecordProviderResponsesToolCall(state, item, &observed, false); err != nil {
			return providerResponsesItem{}, err
		}
	case schemas.ResponsesMessageTypeShellCallOutput:
		// OpenAI writes the output of each call that a hosted shell runs, after the call.
		if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil ||
			item.ResponsesToolMessage == nil || item.ResponsesToolMessage.CallID == nil || state == nil ||
			!state.responsesHostedShellCalls[*item.ResponsesToolMessage.CallID] ||
			validateProviderResponsesToolMessage(state, item.ResponsesToolMessage, *item.Type) != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		observed.callID = *item.ResponsesToolMessage.CallID
	case schemas.ResponsesMessageTypeMCPListTools, schemas.ResponsesMessageTypeMCPCall, schemas.ResponsesMessageTypeMCPApprovalRequest:
		if err := validateProviderResponsesMCPItem(state, item, &observed); err != nil {
			return providerResponsesItem{}, err
		}
	case schemas.ResponsesMessageTypeToolSearchCall, schemas.ResponsesMessageTypeToolSearchOutput:
		if err := validateProviderToolSearchItem(state, item, &observed); err != nil {
			return providerResponsesItem{}, err
		}
	default:
		return providerResponsesItem{}, ErrProviderResponseMalformed
	}
	if item.ResponsesToolMessage != nil {
		callerPayload, actionPayload, err := providerResponsesToolIdentity(item)
		if err != nil {
			return providerResponsesItem{}, ErrProviderResponseMalformed
		}
		observed.toolCallerPayload = callerPayload
		observed.toolActionPayload = actionPayload
	}
	observed.compactionPayload = providerResponsesCompactionPayload(item)
	return observed, nil
}

// validateProviderToolSearchItem checks a step of the tool search that the request declares. The
// search that the client runs is one call, which the client answers by its call ID. OpenAI's own
// search is a call without one and an output that loads some of the request's deferred tools, which
// the client sends back with the reply and which must pass the checks of its next request.
func validateProviderToolSearchItem(state *State, item *schemas.ResponsesMessage, observed *providerResponsesItem) error {
	tool := item.ResponsesToolMessage
	if item.Role != nil || item.Phase != nil || item.Content != nil || item.ResponsesReasoning != nil || tool == nil ||
		tool.Name != nil || tool.ResponsesToolSearchCall != nil || tool.Execution == nil ||
		!providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeToolSearch) ||
		*tool.Execution != state.providerTools().toolSearch {
		return ErrProviderResponseMalformed
	}
	observed.execution = *tool.Execution
	client := *tool.Execution == schemas.ToolSearchExecutionClient
	if *item.Type == schemas.ResponsesMessageTypeToolSearchOutput {
		if client || tool.CallID != nil || tool.Arguments != nil ||
			validateResponsesLoadedTools(item.ToolSearchOutputTools, "tools") != nil {
			return ErrProviderResponseMalformed
		}
		return nil
	}
	if !client && tool.CallID != nil || tool.Arguments != nil && !catalog.ValidateJSONObjectText(*tool.Arguments) {
		return ErrProviderResponseMalformed
	}
	return validateAndRecordProviderResponsesToolCall(state, item, observed, client)
}

func providerResponsesToolIdentity(item *schemas.ResponsesMessage) (string, string, error) {
	if item == nil || item.Type == nil || item.ResponsesToolMessage == nil {
		return "", "", nil
	}
	tool := item.ResponsesToolMessage
	callerPayload, err := json.Marshal(tool.Caller)
	if err != nil {
		return "", "", err
	}

	actionPayload := ""
	switch *item.Type {
	case schemas.ResponsesMessageTypeWebSearchCall:
		if tool.Action != nil && tool.Action.ResponsesWebSearchToolCallAction != nil {
			action := tool.Action.ResponsesWebSearchToolCallAction
			// Claude can stream a search's query after the search starts, so an action that names
			// only its type does not announce the search yet.
			if action.Query == nil && len(action.Queries) == 0 && action.URL == nil && action.Pattern == nil {
				break
			}
			identity := struct {
				Type    string   `json:"type"`
				Query   *string  `json:"query"`
				Queries []string `json:"queries"`
				URL     *string  `json:"url"`
				Pattern *string  `json:"pattern"`
			}{action.Type, action.Query, action.Queries, action.URL, action.Pattern}
			encoded, marshalErr := json.Marshal(identity)
			if marshalErr != nil {
				return "", "", marshalErr
			}
			actionPayload = string(encoded)
		}
	case schemas.ResponsesMessageTypeWebFetchCall:
		if tool.Action != nil && tool.Action.ResponsesWebFetchToolCallAction != nil {
			encoded, marshalErr := json.Marshal(tool.Action.ResponsesWebFetchToolCallAction)
			if marshalErr != nil {
				return "", "", marshalErr
			}
			actionPayload = string(encoded)
		}
	case schemas.ResponsesMessageTypeMCPListTools, schemas.ResponsesMessageTypeMCPCall, schemas.ResponsesMessageTypeMCPApprovalRequest:
		// An MCP item keeps the server that it names from start to end.
		if tool.ServerLabel != nil {
			actionPayload = "mcp:" + *tool.ServerLabel
		}
	}
	return string(callerPayload), actionPayload, nil
}

func providerResponsesCompactionPayload(item *schemas.ResponsesMessage) string {
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
	default:
		return ""
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func providerResponsesCompactionPayloadMatches(expected string, item *schemas.ResponsesMessage) bool {
	return expected != "" && providerResponsesCompactionPayload(item) == expected
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
	shellOutput := itemType == schemas.ResponsesMessageTypeShellCallOutput
	if tool.Execution != nil || tool.Output != nil && !shellOutput || tool.Error != nil ||
		tool.ResponsesComputerToolCallOutput != nil || tool.ServerLabel != nil ||
		tool.ResponsesImageGenerationCall != nil || tool.ResponsesMCPListTools != nil ||
		tool.ResponsesMCPApprovalResponse != nil || tool.ResponsesAdvisorCall != nil ||
		tool.ResponsesToolSearchCall != nil || tool.ResponsesCodeExecutionCall != nil ||
		tool.ResponsesCodeInterpreterToolCall != nil && itemType != schemas.ResponsesMessageTypeCodeInterpreterCall {
		return ErrProviderResponseMalformed
	}
	shell, patch := itemType == schemas.ResponsesMessageTypeShellCall, itemType == schemas.ResponsesMessageTypeApplyPatchCall
	if tool.ResponsesShellCall != nil && !shell && !shellOutput || tool.ResponsesApplyPatchCall != nil && !patch ||
		(tool.ItemCaller != nil || tool.CreatedBy != nil) && !shell && !shellOutput && !patch ||
		tool.ResponsesComputerToolCall != nil && itemType != schemas.ResponsesMessageTypeComputerCall ||
		tool.ResponsesFileSearchToolCall != nil && itemType != schemas.ResponsesMessageTypeFileSearchCall {
		return ErrProviderResponseMalformed
	}

	switch itemType {
	case schemas.ResponsesMessageTypeShellCall, schemas.ResponsesMessageTypeApplyPatchCall:
		if tool.CallID == nil || tool.Name != nil || tool.Namespace != nil || tool.Arguments != nil || tool.Caller != nil ||
			tool.ResponsesCustomToolCall != nil || tool.ResponsesWebFetchCall != nil ||
			!validOptionalProviderText(tool.CreatedBy, maxProviderResponseIDBytes, false) ||
			tool.ItemCaller != nil && tool.ItemCaller.Type != "direct" {
			return ErrProviderResponseMalformed
		}
		if patch {
			if tool.Action != nil || tool.ResponsesApplyPatchCall == nil || !validProviderPatchOperation(tool.ResponsesApplyPatchCall.Operation) {
				return ErrProviderResponseMalformed
			}
			break
		}
		// The client runs the commands of a shell in a local environment, and OpenAI those of a
		// hosted shell, in a container that the call names. Only a shell that the request lets the
		// model call runs a call.
		hosted := providerHostedShellCall(tool)
		if tool.Action == nil || tool.Action.ResponsesShellToolCallAction == nil || state == nil ||
			tool.ResponsesShellCall != nil && (tool.ResponsesShellCall.MaxOutputLength != nil || tool.ResponsesShellCall.Environment != nil && !hosted &&
				(tool.ResponsesShellCall.Environment.Type != "local" || tool.ResponsesShellCall.Environment.ContainerID != nil)) ||
			hosted && (!state.providerTools().hostedShell || !validProviderResponseID(*tool.ResponsesShellCall.Environment.ContainerID)) ||
			!hosted && !state.providerTools().localShell {
			return ErrProviderResponseMalformed
		}
		action := tool.Action.ResponsesShellToolCallAction
		if len(action.Commands) > maxProviderResponseItems || action.TimeoutMS != nil && *action.TimeoutMS < 0 ||
			action.MaxOutputLength != nil && *action.MaxOutputLength < 0 {
			return ErrProviderResponseMalformed
		}
		for _, command := range action.Commands {
			if !validProviderText(command, maxProviderResponseBodySize, true) {
				return ErrProviderResponseMalformed
			}
		}
	case schemas.ResponsesMessageTypeShellCallOutput:
		if tool.Name != nil || tool.Namespace != nil || tool.Arguments != nil || tool.Action != nil || tool.Caller != nil ||
			tool.ResponsesCustomToolCall != nil || tool.ResponsesWebFetchCall != nil ||
			!validOptionalProviderText(tool.CreatedBy, maxProviderResponseIDBytes, false) ||
			tool.ItemCaller != nil && tool.ItemCaller.Type != "direct" ||
			tool.ResponsesShellCall != nil && (tool.ResponsesShellCall.Environment != nil ||
				tool.ResponsesShellCall.MaxOutputLength != nil && *tool.ResponsesShellCall.MaxOutputLength < 0) ||
			!validProviderShellOutput(tool.Output) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeCodeInterpreterCall:
		if tool.CallID != nil || tool.Name != nil || tool.Namespace != nil || tool.Arguments != nil || tool.Action != nil ||
			tool.Caller != nil || tool.ResponsesCustomToolCall != nil || tool.ResponsesWebFetchCall != nil ||
			!validProviderCodeInterpreterCall(tool.ResponsesCodeInterpreterToolCall) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeComputerCall:
		// The client runs every action, and OpenAI decides which exist. A call of the retired
		// preview holds one action.
		if tool.CallID == nil || tool.Name != nil || tool.Namespace != nil || tool.Arguments != nil || tool.Caller != nil ||
			tool.ResponsesCustomToolCall != nil || tool.ResponsesWebFetchCall != nil ||
			tool.Action != nil && tool.Action.ResponsesComputerToolCallAction == nil {
			return ErrProviderResponseMalformed
		}
		actions := providerComputerActions(tool)
		var checks []schemas.ResponsesComputerToolCallPendingSafetyCheck
		if tool.ResponsesComputerToolCall != nil {
			checks = tool.ResponsesComputerToolCall.PendingSafetyChecks
		}
		if len(actions) > maxProviderResponseItems || len(checks) > maxProviderResponseItems {
			return ErrProviderResponseMalformed
		}
		for _, action := range actions {
			if !validProviderText(action.Type, maxProviderResponseIDBytes, false) ||
				!validOptionalProviderText(action.Button, maxProviderResponseIDBytes, false) ||
				!validOptionalProviderText(action.Text, maxProviderResponseBodySize, true) || len(action.Keys) > maxProviderResponseItems {
				return ErrProviderResponseMalformed
			}
			for _, key := range action.Keys {
				if !validProviderText(key, maxProviderResponseIDBytes, false) {
					return ErrProviderResponseMalformed
				}
			}
		}
		for _, check := range checks {
			if !validProviderText(check.ID, maxProviderResponseIDBytes, false) || !validOptionalProviderText(check.Code, maxProviderResponseIDBytes, true) ||
				!validOptionalProviderText(check.Message, maxProviderResponseBodySize, true) {
				return ErrProviderResponseMalformed
			}
		}
	case schemas.ResponsesMessageTypeFunctionCall:
		if tool.CallID == nil || tool.Name == nil || tool.Arguments == nil || tool.Action != nil || tool.Caller != nil ||
			tool.ResponsesCustomToolCall != nil || tool.ResponsesWebFetchCall != nil {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeCustomToolCall:
		if tool.CallID == nil || tool.Name == nil || tool.Arguments != nil || tool.Action != nil || tool.Caller != nil ||
			tool.ResponsesCustomToolCall == nil || tool.ResponsesWebFetchCall != nil {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeWebSearchCall:
		if tool.Name != nil || tool.Namespace != nil || tool.Arguments != nil || tool.ResponsesCustomToolCall != nil ||
			tool.ResponsesWebFetchCall != nil || !validProviderWebSearchAction(state, tool.Action) ||
			!validProviderToolCaller(tool.Caller) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeWebFetchCall:
		if tool.Name != nil || tool.Namespace != nil || tool.Arguments != nil || tool.ResponsesCustomToolCall != nil ||
			!validProviderWebFetchAction(state, tool.Action) || !validProviderToolCaller(tool.Caller) ||
			!validProviderWebFetchResult(state, tool.ResponsesWebFetchCall) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesMessageTypeFileSearchCall:
		if tool.CallID != nil || tool.Name != nil || tool.Namespace != nil || tool.Arguments != nil || tool.Action != nil ||
			tool.Caller != nil || tool.ResponsesCustomToolCall != nil || tool.ResponsesWebFetchCall != nil ||
			!validProviderFileSearch(tool.ResponsesFileSearchToolCall) {
			return ErrProviderResponseMalformed
		}
	default:
		return ErrProviderResponseMalformed
	}
	return nil
}

// providerHostedShellCall reports whether a shell call ran in a container, which OpenAI names by
// reference.
func providerHostedShellCall(tool *schemas.ResponsesToolMessage) bool {
	return tool != nil && tool.ResponsesShellCall != nil && tool.ResponsesShellCall.Environment != nil &&
		tool.ResponsesShellCall.Environment.Type == "container_reference" && tool.ResponsesShellCall.Environment.ContainerID != nil
}

// validProviderShellOutput checks what the commands of a hosted shell's call wrote: each command's
// output and how it ended, which a stream starts without.
func validProviderShellOutput(output *schemas.ResponsesToolMessageOutputStruct) bool {
	return output == nil || output.ResponsesToolCallOutputStr == nil && output.ResponsesComputerToolCallOutput == nil &&
		len(output.ResponsesFunctionToolCallOutputBlocks) == 0 && validProviderShellOutputContent(output.ResponsesShellCallOutput)
}

func validProviderShellOutputContent(output []schemas.ResponsesShellCallOutputContent) bool {
	if len(output) > maxProviderResponseItems {
		return false
	}
	for _, content := range output {
		if !validProviderText(content.Stdout, maxProviderResponseBodySize, true) || !validProviderText(content.Stderr, maxProviderResponseBodySize, true) ||
			!validProviderText(content.Outcome.Type, maxProviderResponseIDBytes, false) ||
			!validOptionalProviderText(content.CreatedBy, maxProviderResponseIDBytes, false) {
			return false
		}
	}
	return true
}

// validProviderCodeInterpreterCall checks a call of code interpreter: the code that the model wrote,
// the container that ran it and, where include asks for them, the logs and images that it output.
func validProviderCodeInterpreterCall(call *schemas.ResponsesCodeInterpreterToolCall) bool {
	if call == nil || !validOptionalProviderText(call.Code, maxProviderResponseBodySize, true) ||
		!validProviderResponseID(call.ContainerID) || len(call.Outputs) > maxProviderResponseItems {
		return false
	}
	for _, output := range call.Outputs {
		switch {
		case output.ResponsesCodeInterpreterOutputLogs != nil:
			if !validProviderText(output.Logs, maxProviderResponseBodySize, true) {
				return false
			}
		case output.ResponsesCodeInterpreterOutputImage != nil:
			if !validProviderText(output.URL, maxProviderResponseBodySize, false) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// validProviderFileSearch checks the queries of a file search and the results that include
// file_search_call.results returns: text from the files of the customer's vector stores, with
// each file's ID, name, score and attributes.
func validProviderFileSearch(search *schemas.ResponsesFileSearchToolCall) bool {
	if search == nil || len(search.Queries) > maxProviderResponseItems || len(search.Results) > maxProviderResponseItems {
		return false
	}
	for _, query := range search.Queries {
		if !validProviderText(query, 64*1024, false) {
			return false
		}
	}
	for _, result := range search.Results {
		if result.FileID != nil && !validProviderResponseID(*result.FileID) ||
			!validOptionalProviderText(result.Filename, 64*1024, true) ||
			!validOptionalProviderText(result.Text, maxProviderResponseBodySize, true) ||
			result.Attributes != nil && len(*result.Attributes) > maxProviderResponseItems {
			return false
		}
	}
	return true
}

// validProviderPatchOperation checks the file instruction of a patch call. OpenAI decides which
// operations exist.
func validProviderPatchOperation(operation *schemas.ResponsesApplyPatchOperation) bool {
	return operation != nil && validProviderText(operation.Type, maxProviderResponseIDBytes, false) &&
		validProviderText(operation.Path, maxProviderResponseBodySize, true) &&
		validOptionalProviderText(operation.Diff, maxProviderResponseBodySize, true)
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

// Calls of hosted tools come back in the shape that replies return them: a web search with its
// action and, from Claude, its results, Claude's web fetch with the page that it got, or OpenAI's
// file search with its queries and, when include asked for them, its results.
var (
	webSearchCallShape = inputShape{"type": inputText, "id": inputText, "status": inputText, "call_id": inputText,
		"tool_caller": inputShape{"type": inputText}, "action": inputShape{"type": inputText, "query": inputText,
			"queries": inputTexts, "url": inputText, "pattern": inputText, "sources": inputObjects{"type": inputText,
				"url": inputText, "title": inputText, "encrypted_content": inputText, "page_age": inputText}}}
	webFetchCallShape = inputShape{"type": inputText, "id": inputText, "status": inputText, "call_id": inputText,
		"tool_caller": inputShape{"type": inputText}, "action": inputShape{"type": inputText, "url": inputText},
		"web_fetch_result_type": inputText, "web_fetch_result_url": inputText, "web_fetch_retrieved_at": inputText,
		"web_fetch_error_code": inputText, "web_fetch_document": inputShape{"type": inputText, "title": inputText,
			"source": inputShape{"type": inputText, "media_type": inputText, "data": inputText}}}
	fileSearchCallShape = inputShape{"type": inputText, "id": inputText, "status": inputText, "queries": inputTexts,
		"results": inputObjects{"file_id": inputText, "filename": inputText, "text": inputText, "score": inputNumber,
			"attributes": inputScalars}}
)

// validateResponsesHostedCallInput checks a call of a hosted tool that a reply returned. The checks
// are the same on every deployment, and each deployment gets only the calls that it reads
// (catalog.ResolvedRequest.KeepReadableHistory).
func validateResponsesHostedCallInput(item map[string]json.RawMessage, path, itemType string) error {
	if itemType == "file_search_call" {
		// Core sends null queries for an item that leaves them out, so an item holds them, as
		// replies return them.
		if err := checkInputShape(item, path, fileSearchCallShape); err != nil {
			return err
		}
		if !rawJSONValueSet(item["queries"]) {
			return invalidRequest(path + ".queries must be an array of strings")
		}
		return nil
	}
	shape := webSearchCallShape
	if itemType == "web_fetch_call" {
		shape = webFetchCallShape
	}
	if err := checkInputShape(item, path, shape); err != nil {
		return err
	}
	if err := requiredInputStrings(item, path, "id", "status"); err != nil {
		return err
	}
	// OpenAI's statuses of a web search call. A reply returns completed or failed.
	if !stringInSet(rawString(item["status"]), "in_progress", "searching", "completed", "failed", "incomplete") {
		return invalidRequest(path + ".status is not supported")
	}
	if action, ok := rawObject(item["action"]); ok {
		if _, err := requiredInputString(action, "type", path+".action", false); err != nil {
			return err
		}
	}
	// A reply returns only the calls that the model made itself.
	if caller, ok := rawObject(item["tool_caller"]); ok && rawString(caller["type"]) != "direct" {
		return invalidRequest(path + ".tool_caller.type must be direct")
	}
	return nil
}

func providerResponsesURLAllowed(state *State, wanted schemas.ResponsesToolType, value string) bool {
	if state == nil || state.Resolution == nil {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	hostname, domain := providerResultDomain(parsed.Hostname())
	for _, tool := range state.providerTools().web {
		if tool.kind != wanted && (wanted != schemas.ResponsesToolTypeWebSearch || tool.kind != schemas.ResponsesToolTypeWebSearchPreview) {
			continue
		}
		if !tool.filtered {
			return true
		}
		// An address or a host that cannot be read is in no listed domain, so
		// only a tool with a block list alone allows it.
		if !tool.valid || hostname == "" {
			return false
		}
		if !domain {
			if len(tool.allowed) == 0 {
				return true
			}
			continue
		}
		if providerDomainMatches(hostname, tool.blocked) {
			continue
		}
		if len(tool.allowed) == 0 || providerDomainMatches(hostname, tool.allowed) {
			return true
		}
	}
	return false
}

func readProviderWebTool(kind schemas.ResponsesToolType, raw json.RawMessage) providerWebTool {
	filters, filtered := rawObject(raw)
	if !filtered {
		return providerWebTool{kind: kind}
	}
	allowed, allowedOK := providerResponseDomains(filters["allowed_domains"])
	blocked, blockedOK := providerResponseDomains(filters["blocked_domains"])
	return providerWebTool{kind: kind, filtered: true, valid: allowedOK && blockedOK, allowed: allowed, blocked: blocked}
}

func providerResponseDomains(raw json.RawMessage) (map[string]bool, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	var domains []string
	if json.Unmarshal(raw, &domains) != nil {
		return nil, false
	}
	set := make(map[string]bool, len(domains))
	for _, domain := range domains {
		set[strings.ToLower(strings.TrimSpace(domain))] = true
	}
	return set, true
}

// Browsers map a host before they visit it (UTS #46, as the URL standard
// applies it), so different spellings of one domain open the same site.
var providerResultHostProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.BidiRule())

// providerResultDomain returns a result URL's host as the browser visits it and
// whether that is a domain name rather than an IP address. The host is ASCII in
// lower case without a trailing dot, which is how filters list domains, and
// empty when a browser would not open it.
func providerResultDomain(hostname string) (string, bool) {
	host, err := providerResultHostProfile.ToASCII(hostname)
	host = strings.TrimSuffix(host, ".")
	if err != nil || host == "" {
		return "", false
	}
	if strings.Contains(host, ":") {
		if net.ParseIP(host) == nil {
			return "", false
		}
		return host, false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return "", false
		}
	}
	return host, !hostEndsInNumber(host)
}

// hostEndsInNumber reports whether the URL standard reads a host as an IPv4
// address, written in any of the forms it accepts, such as 2130706433 or
// 0x7f.1, rather than as a domain.
func hostEndsInNumber(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	hex, ok := strings.CutPrefix(strings.ToLower(last), "0x")
	return ok && strings.Trim(hex, "0123456789abcdef") == ""
}

// providerDomainMatches reports whether hostname is a listed domain or one of its subdomains.
func providerDomainMatches(hostname string, domains map[string]bool) bool {
	for {
		if domains[hostname] {
			return true
		}
		_, parent, found := strings.Cut(hostname, ".")
		if !found {
			return false
		}
		hostname = parent
	}
}

func validProviderRFC3339(value string) bool {
	if !validProviderText(value, 1024, false) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

// Anthropic reports tools that the model called itself as "direct". Requests
// cannot enable code execution, so no other caller is valid.
func validProviderToolCaller(caller *schemas.ResponsesToolCaller) bool {
	return caller == nil || caller.Type == "direct" && caller.ToolID == nil
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
		switch *item.Type {
		case schemas.ResponsesMessageTypeShellCall:
			state.responsesDeclaredCalls++
			if !providerHostedShellCall(item.ResponsesToolMessage) {
				state.responsesClientCalls++
				break
			}
			// OpenAI runs the calls of a hosted shell, and max_tool_calls caps none of them.
			if state.responsesHostedShellCalls == nil {
				state.responsesHostedShellCalls = make(map[string]bool)
			}
			state.responsesHostedShellCalls[observed.callID] = true
		case schemas.ResponsesMessageTypeCodeInterpreterCall:
			// max_tool_calls stops code interpreter's calls past it, which end interpreting (capture
			// openai/container-tool-calls), and they cost nothing of their own, so no cap on hosted
			// calls counts them.
			state.responsesDeclaredCalls++
		case schemas.ResponsesMessageTypeFunctionCall, schemas.ResponsesMessageTypeCustomToolCall,
			schemas.ResponsesMessageTypeApplyPatchCall, schemas.ResponsesMessageTypeComputerCall:
			state.responsesDeclaredCalls++
			state.responsesClientCalls++
		case schemas.ResponsesMessageTypeToolSearchCall:
			// OpenAI's own search has no fee, so no cap on hosted calls counts it.
			state.responsesDeclaredCalls++
			if observed.execution == schemas.ToolSearchExecutionClient {
				state.responsesClientCalls++
			}
		case schemas.ResponsesMessageTypeWebSearchCall, schemas.ResponsesMessageTypeWebFetchCall, schemas.ResponsesMessageTypeMCPCall,
			schemas.ResponsesMessageTypeFileSearchCall:
			state.responsesDeclaredCalls++
			state.responsesHostedCalls++
			if cap, supplied := responsesExplicitMaxToolCalls(state); supplied && !responsesUsesAnthropicWire(state) && state.responsesHostedCalls > cap {
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
		item.parts[index] = &providerResponsesPart{
			blockType:   response.Part.Type,
			annotations: make(map[int]providerResponsesAnnotation),
		}
		return nil
	}
	if !exists || part.done || !part.valueDone || part.blockType != response.Part.Type || part.value.String() != value {
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

// validateProviderResponsesSummaryPart checks a reasoning summary part, which holds only its text.
func validateProviderResponsesSummaryPart(state *State, part *schemas.ResponsesMessageContentBlock) error {
	if part.Type != schemas.ResponsesOutputMessageContentTypeSummaryText {
		return ErrProviderResponseMalformed
	}
	text := *part
	text.Type = schemas.ResponsesOutputMessageContentTypeReasoning
	return validateProviderResponsesContentBlock(state, &text)
}

func validateProviderResponsesTextEvent(state *State, response *schemas.BifrostResponsesStreamResponse, blockTypes ...schemas.ResponsesMessageContentBlockType) error {
	part := providerResponsesPartForEvent(state, response)
	if part == nil || part.done || !slices.Contains(blockTypes, part.blockType) {
		return ErrProviderResponseMalformed
	}
	if !validOptionalProviderText(response.Delta, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(response.Text, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(response.Refusal, maxProviderResponseBodySize, true) ||
		!validOptionalProviderText(response.Obfuscation, maxProviderResponseBodySize, true) {
		return ErrProviderResponseMalformed
	}
	switch response.Type {
	case schemas.ResponsesStreamResponseTypeOutputTextDelta,
		schemas.ResponsesStreamResponseTypeRefusalDelta,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		schemas.ResponsesStreamResponseTypeReasoningTextDelta:
		if part.valueDone || response.Delta == nil || !appendProviderBuffer(&part.value, *response.Delta) {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeOutputTextDone,
		schemas.ResponsesStreamResponseTypeRefusalDone,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone,
		schemas.ResponsesStreamResponseTypeReasoningTextDone:
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
		schemas.ResponsesStreamResponseTypeCustomToolCallInputDelta,
		schemas.ResponsesStreamResponseTypeApplyPatchCallOperationDiffDelta,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDelta:
		if response.Delta == nil {
			return ErrProviderResponseMalformed
		}
		if !validProviderText(*response.Delta, maxProviderResponseBodySize, true) ||
			!validOptionalProviderText(response.Obfuscation, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
		if !appendProviderBuffer(item.value, *response.Delta) {
			return ErrProviderResponseMalformed
		}
		return nil
	case schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone:
		// The item's end says whether the provider finished the call, and so whether these must be a JSON object.
		if response.Arguments == nil || item.value.String() != *response.Arguments {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesStreamResponseTypeCustomToolCallInputDone:
		if response.Input == nil || item.value.String() != *response.Input ||
			!validProviderText(*response.Input, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesStreamResponseTypeApplyPatchCallOperationDiffDone:
		if response.Diff == nil || item.value.String() != *response.Diff ||
			!validProviderText(*response.Diff, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDone:
		if response.Code == nil || item.value.String() != *response.Code {
			return ErrProviderResponseMalformed
		}
	default:
		return ErrProviderResponseMalformed
	}
	item.valueDone = true
	state.responsesItems[*response.OutputIndex] = item
	return nil
}

// validateProviderResponsesShellCommandEvent follows the commands of a streamed shell call. Each
// command opens in order, takes its text in deltas and closes with the whole text.
func validateProviderResponsesShellCommandEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if state == nil || response == nil || response.OutputIndex == nil || response.CommandIndex == nil {
		return ErrProviderResponseMalformed
	}
	item, ok := state.responsesItems[*response.OutputIndex]
	index := *response.CommandIndex
	if !ok || item.done || item.itemType != schemas.ResponsesMessageTypeShellCall ||
		response.ItemID != nil && *response.ItemID != item.id || index < 0 || index > len(item.commands) {
		return ErrProviderResponseMalformed
	}
	if response.Type == schemas.ResponsesStreamResponseTypeShellCallCommandAdded {
		if index != len(item.commands) || index >= maxProviderResponseItems || response.Delta != nil ||
			response.Command != nil && *response.Command != "" {
			return ErrProviderResponseMalformed
		}
		item.commands = append(item.commands, &providerResponsesCommand{})
		state.responsesItems[*response.OutputIndex] = item
		return nil
	}
	if index == len(item.commands) || item.commands[index].done {
		return ErrProviderResponseMalformed
	}
	command := item.commands[index]
	if response.Type == schemas.ResponsesStreamResponseTypeShellCallCommandDelta {
		if response.Delta == nil || response.Command != nil ||
			!validProviderText(*response.Delta, maxProviderResponseBodySize, true) ||
			!validOptionalProviderText(response.Obfuscation, maxProviderResponseBodySize, true) ||
			!appendProviderBuffer(&command.value, *response.Delta) {
			return ErrProviderResponseMalformed
		}
		return nil
	}
	if response.Delta != nil || response.Command == nil || command.value.String() != *response.Command {
		return ErrProviderResponseMalformed
	}
	command.done = true
	return nil
}

// validateProviderResponsesShellOutputEvent checks what a command of a hosted shell's call wrote,
// which OpenAI streams by command.
func validateProviderResponsesShellOutputEvent(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if response.CommandIndex == nil || *response.CommandIndex < 0 || *response.CommandIndex >= maxProviderResponseItems ||
		response.Command != nil {
		return ErrProviderResponseMalformed
	}
	if response.Type == schemas.ResponsesStreamResponseTypeShellCallOutputContentDelta {
		delta := response.ShellOutputDelta
		if delta == nil || response.Output != nil ||
			delta.Stdout != nil && !validProviderText(*delta.Stdout, maxProviderResponseBodySize, true) ||
			delta.Stderr != nil && !validProviderText(*delta.Stderr, maxProviderResponseBodySize, true) {
			return ErrProviderResponseMalformed
		}
		return nil
	}
	if response.ShellOutputDelta != nil || !validProviderShellOutputContent(response.Output) {
		return ErrProviderResponseMalformed
	}
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
		schemas.ResponsesStreamResponseTypeFileSearchCallInProgress:
		if item.stage != 0 {
			return ErrProviderResponseMalformed
		}
		next = 1
	case schemas.ResponsesStreamResponseTypeWebSearchCallSearching,
		schemas.ResponsesStreamResponseTypeWebFetchCallFetching,
		schemas.ResponsesStreamResponseTypeFileSearchCallSearching:
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
	case schemas.ResponsesStreamResponseTypeWebFetchCallCompleted,
		schemas.ResponsesStreamResponseTypeFileSearchCallCompleted:
		if item.stage != 2 {
			return ErrProviderResponseMalformed
		}
		next = 3
	// Code interpreter's events come in order, but none is required: a call that max_tool_calls
	// stops ends while it is interpreting.
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallInProgress:
		if item.stage != 0 {
			return ErrProviderResponseMalformed
		}
		next = 1
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallInterpreting:
		if item.stage > 1 {
			return ErrProviderResponseMalformed
		}
		next = 2
	case schemas.ResponsesStreamResponseTypeCodeInterpreterCallCompleted:
		if item.stage > 2 {
			return ErrProviderResponseMalformed
		}
		next = 3
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
	if response.ContentIndex != nil {
		return item.parts[*response.ContentIndex]
	}
	if response.SummaryIndex != nil {
		return item.reasoningParts[*response.SummaryIndex]
	}
	return nil
}

func providerResponsesBlockValue(block *schemas.ResponsesMessageContentBlock) (string, bool) {
	if block == nil {
		return "", false
	}
	switch block.Type {
	case schemas.ResponsesOutputMessageContentTypeText, schemas.ResponsesOutputMessageContentTypeReasoning,
		schemas.ResponsesOutputMessageContentTypeSummaryText:
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
		if block.Text == nil || !validProviderText(*block.Text, maxProviderResponseBodySize, true) ||
			block.Signature != nil || block.EncryptedContent != nil ||
			block.ResponsesOutputMessageContentText != nil || block.ResponsesOutputMessageContentRefusal != nil ||
			block.ResponsesOutputMessageContentCompaction != nil {
			return ErrProviderResponseMalformed
		}
	case schemas.ResponsesOutputMessageContentTypeCompaction:
		if state == nil || state.Resolution == nil ||
			!anthropicContextManagementUsesCompaction(state.Resolution.WireView().RawBody()["context_management"]) ||
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
	for _, value := range values {
		if !validProviderLogProb(value.Token, value.LogProb, value.Bytes) {
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
	if annotation.StartCharIndex != nil || annotation.EndCharIndex != nil ||
		annotation.StartPageNumber != nil || annotation.EndPageNumber != nil ||
		annotation.StartBlockIndex != nil || annotation.EndBlockIndex != nil || annotation.Source != nil {
		return ErrProviderResponseMalformed
	}
	switch annotation.Type {
	case "url_citation":
		if annotation.URL == nil || !providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeWebSearch) ||
			!providerResponsesURLAllowed(state, schemas.ResponsesToolTypeWebSearch, *annotation.URL) ||
			annotation.FileID != nil || annotation.Filename != nil || annotation.ContainerID != nil ||
			!validOptionalProviderText(annotation.Title, 64*1024, true) ||
			!validOptionalProviderText(annotation.Text, 1024*1024, true) ||
			!validOptionalProviderText(annotation.EncryptedIndex, 16*1024*1024, true) {
			return ErrProviderResponseMalformed
		}
	case "file_citation":
		// A file search cites one of the files that it read at a place in the text.
		if annotation.FileID == nil || annotation.Filename == nil || annotation.Index == nil ||
			!providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeFileSearch) ||
			!validProviderText(*annotation.Filename, 64*1024, true) || annotation.URL != nil || annotation.ContainerID != nil ||
			annotation.Title != nil || annotation.Text != nil || annotation.StartIndex != nil || annotation.EncryptedIndex != nil {
			return ErrProviderResponseMalformed
		}
	case "container_file_citation":
		// Code that ran in a container cites a file there, at a place in the text or at its start.
		if annotation.ContainerID == nil || annotation.FileID == nil || annotation.Filename == nil || annotation.StartIndex == nil ||
			!providerContainerToolAllowed(state) ||
			!validProviderText(*annotation.Filename, 64*1024, true) || annotation.URL != nil || annotation.Index != nil ||
			annotation.Title != nil || annotation.Text != nil || annotation.EncryptedIndex != nil {
			return ErrProviderResponseMalformed
		}
	default:
		return ErrProviderResponseMalformed
	}
	return nil
}

// providerContainerToolAllowed reports whether the request lets the model run code in a container
// that OpenAI hosts.
func providerContainerToolAllowed(state *State) bool {
	return providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeCodeInterpreter) ||
		providerResponsesToolTypeAllowed(state, schemas.ResponsesToolTypeShell) && state.providerTools().hostedShell
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

// providerToolSet records what a request lets the provider call. It is read once per
// request, so checking an output event costs the same however many tools the request declares.
type providerToolSet struct {
	// types holds the canonical Responses tool types that tool_choice leaves enabled.
	types map[schemas.ResponsesToolType]bool
	// names holds the declared tools that tool_choice lets the provider call by name.
	names map[providerToolName]bool
	// web holds the enabled hosted web tools in request order.
	web []providerWebTool
	// mcpDeclared holds the labels of the MCP servers that the request declares, and mcp those
	// that tool_choice leaves callable.
	mcpDeclared, mcp map[string]bool
	// toolSearch is where the request's tool search runs, server or client, when tool_choice leaves
	// it callable.
	toolSearch string
	// hostedShell and localShell report whether tool_choice leaves a shell callable that runs in
	// a container OpenAI hosts, or in the client's own environment.
	hostedShell, localShell bool
}

// providerToolName names a declared tool. A tool in a namespace other than functions goes by its
// namespace too, since tools in different namespaces can share a name.
type providerToolName struct {
	kind      schemas.ResponsesToolType
	namespace string
	name      string
}

type providerWebTool struct {
	kind schemas.ResponsesToolType
	// filtered marks a tool with domain filters; valid is false when they cannot be read.
	filtered, valid  bool
	allowed, blocked map[string]bool
}

func (s *State) providerTools() *providerToolSet {
	if s.providerToolSet == nil {
		s.providerToolSet = readProviderTools(s.Resolution.WireView())
	}
	return s.providerToolSet
}

func readProviderTools(resolution *catalog.ResolvedRequest) *providerToolSet {
	tools := &providerToolSet{types: map[schemas.ResponsesToolType]bool{}, names: map[providerToolName]bool{},
		mcpDeclared: map[string]bool{}, mcp: map[string]bool{}}
	if resolution == nil {
		return tools
	}
	for _, tool := range resolution.RawTools() {
		if catalog.CanonicalResponsesToolType(rawString(tool["type"])) == schemas.ResponsesToolTypeMCP {
			tools.mcpDeclared[rawString(tool["server_label"])] = true
		}
	}
	chat := resolution.Route == catalog.RouteChat
	// An object tool_choice can limit named calls to selected tools; nil leaves all of them.
	var selected map[providerToolName]bool
	choice := resolution.RawBody()["tool_choice"]
	if mode, ok := rawStringValue(choice); ok {
		if mode == "none" {
			return tools
		}
	} else if object, ok := rawObject(choice); ok {
		selected = selectedProviderTools(chat, object)
	}
	if !chat {
		for _, rawType := range catalog.EffectiveResponsesToolTypes(resolution.RawBody(), resolution.ToolTypes()) {
			tools.types[catalog.CanonicalResponsesToolType(rawType)] = true
		}
	}
	for _, entry := range resolution.CallableTools() {
		tool := entry.Tool
		var name providerToolName
		if chat {
			function, ok := rawObject(tool["function"])
			if !ok || rawString(tool["type"]) != "function" {
				continue
			}
			name = providerToolName{kind: schemas.ResponsesToolTypeFunction, name: rawString(function["name"])}
		} else {
			name = providerToolName{kind: catalog.CanonicalResponsesToolType(rawString(tool["type"])), namespace: entry.Namespace, name: rawString(tool["name"])}
			switch name.kind {
			case schemas.ResponsesToolTypeWebSearch, schemas.ResponsesToolTypeWebSearchPreview, schemas.ResponsesToolTypeWebFetch:
				if tools.types[name.kind] {
					tools.web = append(tools.web, readProviderWebTool(name.kind, tool["filters"]))
				}
				continue
			case schemas.ResponsesToolTypeMCP:
				label := providerToolName{kind: schemas.ResponsesToolTypeMCP, name: rawString(tool["server_label"])}
				if tools.types[label.kind] && (selected == nil || selected[label]) {
					tools.mcp[label.name] = true
				}
				continue
			case schemas.ResponsesToolTypeToolSearch:
				if tools.types[name.kind] {
					tools.toolSearch = rawString(tool["execution"])
					if tools.toolSearch == "" {
						tools.toolSearch = "server"
					}
				}
				continue
			case schemas.ResponsesToolTypeShell:
				if tools.types[name.kind] {
					hosted, _ := catalog.HostedToolOf(tool)
					tools.hostedShell = tools.hostedShell || hosted == catalog.HostedToolShell
					tools.localShell = tools.localShell || hosted != catalog.HostedToolShell
				}
				continue
			}
		}
		if selected == nil || selected[name] {
			tools.names[name] = true
		}
	}
	return tools
}

func selectedProviderTools(chat bool, object map[string]json.RawMessage) map[providerToolName]bool {
	if chat {
		function, ok := rawObject(object["function"])
		if !ok {
			return nil
		}
		return map[providerToolName]bool{{kind: schemas.ResponsesToolTypeFunction, name: rawString(function["name"])}: true}
	}
	if rawString(object["type"]) == "allowed_tools" {
		selected := map[providerToolName]bool{}
		var allowed []map[string]json.RawMessage
		if json.Unmarshal(object["tools"], &allowed) == nil {
			for _, tool := range allowed {
				selected[selectedProviderToolName(tool)] = true
			}
		}
		return selected
	}
	kind := catalog.CanonicalResponsesToolType(rawString(object["type"]))
	if kind == schemas.ResponsesToolTypeMCP {
		return map[providerToolName]bool{selectedProviderToolName(object): true}
	}
	if kind != schemas.ResponsesToolTypeFunction && kind != schemas.ResponsesToolTypeCustom {
		return nil
	}
	return map[providerToolName]bool{{kind: kind, name: rawString(object["name"])}: true}
}

// selectedProviderToolName names a tool that tool_choice selects, which is never in a namespace
// other than functions. An MCP server goes by its label.
func selectedProviderToolName(selector map[string]json.RawMessage) providerToolName {
	kind := catalog.CanonicalResponsesToolType(rawString(selector["type"]))
	if kind == schemas.ResponsesToolTypeMCP {
		return providerToolName{kind: kind, name: rawString(selector["server_label"])}
	}
	return providerToolName{kind: kind, name: rawString(selector["name"])}
}

func providerResponsesToolTypeAllowed(state *State, wanted schemas.ResponsesToolType) bool {
	if state == nil || state.Resolution == nil || state.Resolution.WireView().Route != catalog.RouteResponses {
		return false
	}
	types := state.providerTools().types
	return types[wanted] || wanted == schemas.ResponsesToolTypeWebSearch && types[schemas.ResponsesToolTypeWebSearchPreview]
}

func providerResponsesToolNameAllowed(state *State, kind schemas.ResponsesToolType, namespace, name string) bool {
	maxName := maxClientToolName
	if namespace != "" {
		maxName = maxNamespacedToolName
	}
	return validToolName(name, maxName) && providerResponsesToolTypeAllowed(state, kind) &&
		state.providerTools().names[providerToolName{kind, namespace, name}]
}

// providerCallNamespace returns the namespace of a provider's call to a client tool. The namespace
// functions holds top-level tools, so it reads as none, as an empty one does.
func providerCallNamespace(tool *schemas.ResponsesToolMessage) string {
	if tool == nil || tool.Namespace == nil || *tool.Namespace == providerutils.DefaultToolNamespace {
		return ""
	}
	return *tool.Namespace
}

func sameProviderResponsesItem(left, right providerResponsesItem) bool {
	return left.id == right.id && left.callID == right.callID && left.itemType == right.itemType && left.name == right.name &&
		left.namespace == right.namespace &&
		left.toolCallerPayload == right.toolCallerPayload &&
		(left.toolActionPayload == "" || left.toolActionPayload == right.toolActionPayload)
}

func rawProviderExtensionSet(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null"))
}
