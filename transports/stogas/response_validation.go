package stogas

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const maxProviderResponseIDBytes = 512

func validateProviderChatResponse(state *State, response *schemas.BifrostChatResponse, streaming bool) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route == "" || response == nil {
		return nil
	}
	discardUnexposedChatFields(response)
	if response.SystemFingerprint != "" && !validProviderResponseID(response.SystemFingerprint) {
		return ErrProviderResponseMalformed
	}
	if state.Resolution.Route != catalog.RouteChat || !validProviderResponseID(response.ID) {
		return ErrProviderResponseMalformed
	}
	if streaming && !observeProviderStreamPayload(state, response) {
		return ErrProviderResponseMalformed
	}
	if !observeProviderTemporalMetadata(state, response.Created, nil, response.SystemFingerprint) {
		return ErrProviderResponseMalformed
	}
	wantObject := "chat.completion"
	if streaming {
		wantObject = "chat.completion.chunk"
	}
	if response.Object != wantObject {
		return ErrProviderResponseMalformed
	}
	if streaming {
		state.chatStreamObserved = true
		// Bifrost can forward a provider chunk that contains both content and a
		// finish reason, then emit its accumulated usage in one synthetic empty
		// choice. Normalize only that exact carrier to OpenAI's zero-choice usage
		// shape. Any post-finish content or control data remains malformed.
		if state.chatStreamFinished && !state.chatStreamUsageEnded && response.Usage != nil &&
			len(response.Choices) == 1 && emptyProviderChatUsageChoice(response.Choices[0]) {
			response.Choices = []schemas.BifrostResponseChoice{}
		}
		if len(response.Choices) == 0 {
			if response.Usage == nil || !state.chatStreamFinished || state.chatStreamUsageEnded {
				return ErrProviderResponseMalformed
			}
			state.chatStreamUsageEnded = true
			return nil
		}
		if len(response.Choices) != 1 || state.chatStreamFinished || state.chatStreamUsageEnded {
			return ErrProviderResponseMalformed
		}
		choice := response.Choices[0]
		if choice.Index != 0 || choice.TextCompletionResponseChoice != nil ||
			choice.ChatNonStreamResponseChoice != nil || choice.ChatStreamResponseChoice == nil ||
			choice.ChatStreamResponseChoice.Delta == nil ||
			response.Usage != nil && choice.FinishReason == nil ||
			validateProviderChatLogProbs(choice.LogProbs) != nil {
			return ErrProviderResponseMalformed
		}
		delta := choice.ChatStreamResponseChoice.Delta
		if delta.Role != nil {
			if state.chatStreamRoleSeen || *delta.Role != string(schemas.ChatMessageRoleAssistant) {
				return ErrProviderResponseMalformed
			}
			state.chatStreamRoleSeen = true
		}
		if err := validateProviderChatDelta(state, delta); err != nil {
			return err
		}
		if choice.FinishReason != nil {
			if strings.TrimSpace(*choice.FinishReason) == "" {
				return ErrProviderResponseMalformed
			}
			if err := validateProviderChatToolCompletion(state, *choice.FinishReason); err != nil {
				return err
			}
			state.chatStreamFinished = true
			state.chatStreamUsageEnded = response.Usage != nil
		}
		return nil
	}
	if len(response.Choices) != 1 {
		return ErrProviderResponseMalformed
	}
	choice := response.Choices[0]
	if choice.Index != 0 || choice.TextCompletionResponseChoice != nil ||
		choice.ChatStreamResponseChoice != nil || choice.ChatNonStreamResponseChoice == nil ||
		choice.ChatNonStreamResponseChoice.Message == nil ||
		choice.ChatNonStreamResponseChoice.Message.Role != schemas.ChatMessageRoleAssistant ||
		choice.FinishReason == nil || strings.TrimSpace(*choice.FinishReason) == "" ||
		validateProviderChatLogProbs(choice.LogProbs) != nil {
		return ErrProviderResponseMalformed
	}
	if err := validateProviderChatMessage(state, choice.ChatNonStreamResponseChoice.Message); err != nil {
		return err
	}
	return validateProviderChatToolCompletion(state, *choice.FinishReason)
}

func emptyProviderChatUsageChoice(choice schemas.BifrostResponseChoice) bool {
	if choice.Index != 0 || choice.FinishReason != nil || choice.LogProbs != nil ||
		choice.TextCompletionResponseChoice != nil || choice.ChatNonStreamResponseChoice != nil ||
		choice.ChatStreamResponseChoice == nil || choice.ChatStreamResponseChoice.Delta == nil {
		return false
	}
	delta := choice.ChatStreamResponseChoice.Delta
	return delta.Role == nil && delta.Content == nil && delta.Refusal == nil && delta.Audio == nil &&
		delta.Reasoning == nil && len(delta.ReasoningDetails) == 0 && len(delta.Annotations) == 0 &&
		len(delta.ToolCalls) == 0 && len(delta.ExtraContent) == 0
}

func validateProviderResponsesResponse(state *State, response *schemas.BifrostResponsesResponse) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route == "" || response == nil {
		return nil
	}
	discardUnexposedResponsesFields(response)
	status := schemas.ResponsesResponseStatusCompleted
	if response.Status != nil {
		status = *response.Status
	}
	if state.Resolution.Route != catalog.RouteResponses || response.ID == nil ||
		!validProviderResponseID(*response.ID) ||
		response.Object != "response" || response.Status == nil ||
		(status != schemas.ResponsesResponseStatusCompleted && status != schemas.ResponsesResponseStatusIncomplete) {
		return ErrProviderResponseMalformed
	}
	if !observeProviderTemporalMetadata(state, response.CreatedAt, response.CompletedAt, "") {
		return ErrProviderResponseMalformed
	}
	return validateProviderResponsesOutput(state, response, true)
}

func validateProviderResponsesStream(state *State, response *schemas.BifrostResponsesStreamResponse) error {
	if state == nil || state.Resolution == nil || state.Resolution.Route == "" || response == nil {
		return nil
	}
	if state.Resolution.Route != catalog.RouteResponses {
		return ErrProviderResponseMalformed
	}
	discardUnexposedResponsesStreamFields(response)
	if !validResponsesStreamType(response.Type) || response.SequenceNumber != state.responsesNextSequence || state.responsesStreamEnded {
		return ErrProviderResponseMalformed
	}
	if !observeProviderStreamPayload(state, response) {
		return ErrProviderResponseMalformed
	}
	if !state.responsesStreamSeen {
		if response.Type != schemas.ResponsesStreamResponseTypeCreated {
			return ErrProviderResponseMalformed
		}
		state.responsesStreamSeen = true
	} else if response.Type == schemas.ResponsesStreamResponseTypeCreated {
		return ErrProviderResponseMalformed
	}
	if response.Type == schemas.ResponsesStreamResponseTypeInProgress &&
		(state.responsesInProgressSeen || state.responsesOutputStarted) {
		return ErrProviderResponseMalformed
	}
	if err := validateResponsesStreamEventShape(response); err != nil {
		return err
	}
	if response.Response != nil {
		if response.Response.ID == nil || !validProviderResponseID(*response.Response.ID) ||
			response.Response.Object != "response" {
			return ErrProviderResponseMalformed
		}
		if !observeProviderTemporalMetadata(state, response.Response.CreatedAt, response.Response.CompletedAt, "") {
			return ErrProviderResponseMalformed
		}
		if expected := expectedResponsesEventStatus(response.Type); expected != "" {
			if response.Response.Status == nil || *response.Response.Status != expected {
				return ErrProviderResponseMalformed
			}
		}
	}
	if response.Type == schemas.ResponsesStreamResponseTypeCreated {
		if response.Response == nil || response.Response.ID == nil {
			return ErrProviderResponseMalformed
		}
	}
	if err := validateProviderResponsesStreamPayload(state, response); err != nil {
		return err
	}
	if response.Type == schemas.ResponsesStreamResponseTypeInProgress {
		state.responsesInProgressSeen = true
	} else if response.Type != schemas.ResponsesStreamResponseTypeCreated {
		state.responsesOutputStarted = true
	}
	if response.Type == schemas.ResponsesStreamResponseTypeCompleted ||
		response.Type == schemas.ResponsesStreamResponseTypeIncomplete {
		if response.Response == nil || response.Response.ID == nil {
			return ErrProviderResponseMalformed
		}
		status := schemas.ResponsesResponseStatusCompleted
		if response.Type == schemas.ResponsesStreamResponseTypeIncomplete {
			status = schemas.ResponsesResponseStatusIncomplete
		}
		if response.Response.Status != nil && *response.Response.Status != status {
			return ErrProviderResponseMalformed
		}
		state.responsesStreamEnded = true
	}
	state.responsesNextSequence++
	return nil
}

func discardUnexposedChatFields(response *schemas.BifrostChatResponse) {
	if response == nil {
		return
	}
	response.Diagnostics = nil
	response.ExtraParams = nil
	response.SearchResults = nil
	response.Videos = nil
	response.Citations = nil
}

func discardUnexposedResponsesFields(response *schemas.BifrostResponsesResponse) {
	if response == nil {
		return
	}
	response.Diagnostics = nil
	response.ProviderExtraFields = nil
	response.SearchResults = nil
	response.Videos = nil
	response.Citations = nil
}

func discardUnexposedResponsesStreamFields(response *schemas.BifrostResponsesStreamResponse) {
	if response == nil {
		return
	}
	response.SearchResults = nil
	response.Videos = nil
	response.Citations = nil
	discardUnexposedResponsesFields(response.Response)
}

func expectedResponsesEventStatus(eventType schemas.ResponsesStreamResponseType) string {
	switch eventType {
	case schemas.ResponsesStreamResponseTypeCreated, schemas.ResponsesStreamResponseTypeInProgress:
		return schemas.ResponsesResponseStatusInProgress
	case schemas.ResponsesStreamResponseTypeQueued:
		return schemas.ResponsesResponseStatusQueued
	case schemas.ResponsesStreamResponseTypeCompleted:
		return schemas.ResponsesResponseStatusCompleted
	case schemas.ResponsesStreamResponseTypeIncomplete:
		return schemas.ResponsesResponseStatusIncomplete
	case schemas.ResponsesStreamResponseTypeFailed:
		return schemas.ResponsesResponseStatusFailed
	default:
		return ""
	}
}

func validateResponsesStreamEventShape(response *schemas.BifrostResponsesStreamResponse) error {
	if response == nil || negativeOptionalInt(response.OutputIndex) || negativeOptionalInt(response.ContentIndex) ||
		negativeOptionalInt(response.SummaryIndex) || negativeOptionalInt(response.PartialImageIndex) ||
		negativeOptionalInt(response.AnnotationIndex) ||
		(response.ItemID != nil && !validProviderResponseID(*response.ItemID)) ||
		(response.Item != nil && response.Item.ID != nil && !validProviderResponseID(*response.Item.ID)) {
		return ErrProviderResponseMalformed
	}

	responseEvent := response.Type == schemas.ResponsesStreamResponseTypeCreated ||
		response.Type == schemas.ResponsesStreamResponseTypeInProgress ||
		response.Type == schemas.ResponsesStreamResponseTypeQueued ||
		response.Type == schemas.ResponsesStreamResponseTypeCompleted ||
		response.Type == schemas.ResponsesStreamResponseTypeIncomplete ||
		response.Type == schemas.ResponsesStreamResponseTypeFailed
	if responseEvent != (response.Response != nil) {
		return ErrProviderResponseMalformed
	}
	return nil
}

func negativeOptionalInt(value *int) bool {
	return value != nil && *value < 0
}

func validResponsesStreamType(value schemas.ResponsesStreamResponseType) bool {
	switch value {
	case schemas.ResponsesStreamResponseTypeCreated,
		schemas.ResponsesStreamResponseTypeInProgress,
		schemas.ResponsesStreamResponseTypeCompleted,
		schemas.ResponsesStreamResponseTypeIncomplete,
		schemas.ResponsesStreamResponseTypeOutputItemAdded,
		schemas.ResponsesStreamResponseTypeOutputItemDone,
		schemas.ResponsesStreamResponseTypeContentPartAdded,
		schemas.ResponsesStreamResponseTypeContentPartDone,
		schemas.ResponsesStreamResponseTypeOutputTextDelta,
		schemas.ResponsesStreamResponseTypeOutputTextDone,
		schemas.ResponsesStreamResponseTypeRefusalDelta,
		schemas.ResponsesStreamResponseTypeRefusalDone,
		schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta,
		schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone,
		schemas.ResponsesStreamResponseTypeWebSearchCallInProgress,
		schemas.ResponsesStreamResponseTypeWebSearchCallSearching,
		schemas.ResponsesStreamResponseTypeWebSearchCallCompleted,
		schemas.ResponsesStreamResponseTypeWebSearchCallResultsAdded,
		schemas.ResponsesStreamResponseTypeWebSearchCallResultsCompleted,
		schemas.ResponsesStreamResponseTypeWebFetchCallInProgress,
		schemas.ResponsesStreamResponseTypeWebFetchCallFetching,
		schemas.ResponsesStreamResponseTypeWebFetchCallCompleted,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartAdded,
		schemas.ResponsesStreamResponseTypeReasoningSummaryPartDone,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallInProgress,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallInterpreting,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallCompleted,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDelta,
		schemas.ResponsesStreamResponseTypeCodeInterpreterCallCodeDone,
		schemas.ResponsesStreamResponseTypeOutputTextAnnotationAdded,
		schemas.ResponsesStreamResponseTypeOutputTextAnnotationDone,
		schemas.ResponsesStreamResponseTypeCustomToolCallInputDelta,
		schemas.ResponsesStreamResponseTypeCustomToolCallInputDone:
		return true
	default:
		return false
	}
}

func observeProviderStreamPayload(state *State, response any) bool {
	if state == nil || response == nil {
		return false
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > maxProviderResponseBodySize-state.providerStreamBytes {
		return false
	}
	state.providerStreamBytes += len(encoded)
	return true
}

func validateProviderStreamCompleted(state *State) error {
	if state == nil {
		return nil
	}
	if state.chatStreamObserved && !state.chatStreamFinished {
		return ErrProviderResponseMalformed
	}
	if state.responsesStreamSeen && !state.responsesStreamEnded {
		return ErrProviderResponseMalformed
	}
	return nil
}

// ProviderStreamTerminal reports the first validated, billable terminal
// boundary. The HTTP transport can stop reading at this point; later provider
// noise cannot retroactively invalidate output or settlement.
func ProviderStreamTerminal(state *State) bool {
	if state == nil || !HasMeasuredUsage(state) {
		return false
	}
	return (state.chatStreamFinished && state.chatStreamUsageEnded) || state.responsesStreamEnded
}

func validProviderResponseID(value string) bool {
	if value == "" || len(value) > maxProviderResponseIDBytes || !utf8.ValidString(value) {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func observeProviderTemporalMetadata(state *State, created int, completed *int, fingerprint string) bool {
	if state == nil || created < 0 || completed != nil && *completed <= 0 ||
		completed != nil && created > 0 && *completed < created ||
		fingerprint != "" && !validProviderResponseID(fingerprint) {
		return false
	}
	return true
}
