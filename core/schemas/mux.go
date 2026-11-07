package schemas

import (
	"slices"
	"strings"
)

// =============================================================================
// BIDIRECTIONAL CONVERSION METHODS
// =============================================================================
//
// This section contains methods for converting between Chat Completions API
// and Responses API formats. These methods are attached to the structs themselves
// for easy conversion in both directions.
//
// Key Features:
// 1. Bidirectional: Convert to and from both formats
// 2. Data preservation: All relevant data is preserved during conversion
// 3. Aggregation/Spreading: Handle tool messages properly for each format
// 4. Validation: Ensure data integrity during conversion
//
// =============================================================================

// =============================================================================
// TOOL CONVERSION METHODS
// =============================================================================

// ToResponsesTool converts a ChatTool to ResponsesTool format
func (ct *ChatTool) ToResponsesTool() *ResponsesTool {
	if ct == nil {
		return &ResponsesTool{}
	}

	rt := &ResponsesTool{
		Type:                ResponsesToolType(ct.Type),
		CacheControl:        ct.CacheControl,
		DeferLoading:        ct.DeferLoading,
		AllowedCallers:      ct.AllowedCallers,
		InputExamples:       ct.InputExamples,
		EagerInputStreaming: ct.EagerInputStreaming,
	}

	// Convert function tools
	if ct.Type == ChatToolTypeFunction && ct.Function != nil {
		rt.Name = &ct.Function.Name
		rt.Description = ct.Function.Description

		// Create ResponsesToolFunction if needed
		if ct.Function.Parameters != nil || ct.Function.Strict != nil {
			rt.ResponsesToolFunction = &ResponsesToolFunction{
				Parameters: ct.Function.Parameters,
				Strict:     ct.Function.Strict,
			}
		}
	}

	// Convert custom tools, which Bifrost's chat schema names at the top level
	if ct.Type == ChatToolTypeCustom && ct.Name != "" {
		rt.Name = Ptr(ct.Name)
	}
	if ct.Type == ChatToolTypeCustom && ct.Custom != nil {
		if ct.Custom.Format != nil {
			rt.ResponsesToolCustom = &ResponsesToolCustom{
				Format: &ResponsesToolCustomFormat{
					Type: ct.Custom.Format.Type,
				},
			}
			if ct.Custom.Format.Grammar != nil {
				rt.ResponsesToolCustom.Format.Definition = &ct.Custom.Format.Grammar.Definition
				rt.ResponsesToolCustom.Format.Syntax = &ct.Custom.Format.Grammar.Syntax
			}
		}
	}

	return rt
}

// ToChatTool converts a ResponsesTool to ChatTool format
func (rt *ResponsesTool) ToChatTool() *ChatTool {
	if rt == nil {
		return &ChatTool{}
	}

	ct := &ChatTool{
		Type:                ChatToolType(rt.Type),
		CacheControl:        rt.CacheControl,
		DeferLoading:        rt.DeferLoading,
		AllowedCallers:      rt.AllowedCallers,
		InputExamples:       rt.InputExamples,
		EagerInputStreaming: rt.EagerInputStreaming,
	}

	// Convert function tools
	if rt.Type == "function" {
		ct.Function = &ChatToolFunction{}

		if rt.Name != nil {
			ct.Function.Name = *rt.Name
		}
		if rt.Description != nil {
			ct.Function.Description = rt.Description
		}
		if rt.ResponsesToolFunction != nil {
			ct.Function.Parameters = rt.ResponsesToolFunction.Parameters
			ct.Function.Strict = rt.ResponsesToolFunction.Strict
		}
	}

	// Convert custom tools, which Bifrost's chat schema names at the top level
	if rt.Type == "custom" && rt.Name != nil {
		ct.Name = *rt.Name
	}
	if rt.Type == "custom" && rt.ResponsesToolCustom != nil {
		ct.Custom = &ChatToolCustom{}
		if rt.ResponsesToolCustom.Format != nil {
			ct.Custom.Format = &ChatToolCustomFormat{
				Type: rt.ResponsesToolCustom.Format.Type,
			}
			if rt.ResponsesToolCustom.Format.Definition != nil && rt.ResponsesToolCustom.Format.Syntax != nil {
				ct.Custom.Format.Grammar = &ChatToolCustomGrammarFormat{
					Definition: *rt.ResponsesToolCustom.Format.Definition,
					Syntax:     *rt.ResponsesToolCustom.Format.Syntax,
				}
			}
		}
	}

	return ct
}

// ToChatAssistantMessageToolCall converts a ResponsesToolMessage to ChatAssistantMessageToolCall format.
// This is useful for executing Responses API tool calls using the Chat API tool executor.
//
// Returns:
//   - *ChatAssistantMessageToolCall: The converted tool call in Chat API format
//
// Example:
//
//	responsesToolMsg := &ResponsesToolMessage{
//	    CallID:    Ptr("call-123"),
//	    Name:      Ptr("calculate"),
//	    Arguments: Ptr("{\"x\": 10, \"y\": 20}"),
//	}
//	chatToolCall := responsesToolMsg.ToChatAssistantMessageToolCall()
func (rtm *ResponsesToolMessage) ToChatAssistantMessageToolCall() *ChatAssistantMessageToolCall {
	if rtm == nil {
		return nil
	}

	toolCall := &ChatAssistantMessageToolCall{
		ID:   rtm.CallID,
		Type: Ptr("function"),
		Function: ChatAssistantMessageToolCallFunction{
			Name:      rtm.Name,
			Arguments: "{}", // Default to empty JSON object for valid JSON unmarshaling
		},
	}

	// Extract arguments string
	if rtm.Arguments != nil {
		toolCall.Function.Arguments = *rtm.Arguments
	}

	return toolCall
}

// responsesInputBlockType maps a chat content block type onto its Responses input
func responsesInputBlockType(t ChatContentBlockType) ResponsesMessageContentBlockType {
	switch t {
	case ChatContentBlockTypeText:
		return ResponsesInputMessageContentBlockTypeText
	case ChatContentBlockTypeImage:
		return ResponsesInputMessageContentBlockTypeImage
	case ChatContentBlockTypeFile:
		return ResponsesInputMessageContentBlockTypeFile
	case ChatContentBlockTypeInputAudio:
		return ResponsesInputMessageContentBlockTypeAudio
	}
	return ResponsesMessageContentBlockType(t)
}

// ToResponsesToolMessage converts a ChatToolMessage (tool execution result) to ResponsesToolMessage format.
// This creates a function_call_output message suitable for the Responses API.
//
// Returns:
//   - *ResponsesMessage: A ResponsesMessage with type=function_call_output containing the tool result
//
// Example:
//
//	chatToolMsg := &ChatMessage{
//	    Role: ChatMessageRoleTool,
//	    ChatToolMessage: &ChatToolMessage{
//	        ToolCallID: Ptr("call-123"),
//	    },
//	    Content: &ChatMessageContent{
//	        ContentStr: Ptr("Result: 30"),
//	    },
//	}
//	responsesMsg := chatToolMsg.ToResponsesToolMessage()
func (cm *ChatMessage) ToResponsesToolMessage() *ResponsesMessage {
	if cm == nil || cm.ChatToolMessage == nil {
		return nil
	}

	msgType := ResponsesMessageTypeFunctionCallOutput

	respMsg := &ResponsesMessage{
		Type: &msgType,
		ResponsesToolMessage: &ResponsesToolMessage{
			CallID: cm.ChatToolMessage.ToolCallID,
		},
	}

	// Extract output from content
	if cm.Content != nil {
		if cm.Content.ContentStr != nil {
			output := *cm.Content.ContentStr
			respMsg.ResponsesToolMessage.Output = &ResponsesToolMessageOutputStruct{
				ResponsesToolCallOutputStr: &output,
			}
		} else if len(cm.Content.ContentBlocks) > 0 {
			// For structured content blocks, convert to ResponsesMessageContentBlock
			respBlocks := make([]ResponsesMessageContentBlock, len(cm.Content.ContentBlocks))
			for i, block := range cm.Content.ContentBlocks {
				respBlocks[i] = ResponsesMessageContentBlock{
					Type:         responsesInputBlockType(block.Type),
					Text:         block.Text,
					CacheControl: block.CacheControl,
					GuardContent: block.GuardContent,
				}

				// Map image
				if block.ImageURLStruct != nil {
					respBlocks[i].ResponsesInputMessageContentBlockImage = &ResponsesInputMessageContentBlockImage{
						ImageURL: &block.ImageURLStruct.URL,
						Detail:   block.ImageURLStruct.Detail,
					}
				}

				// Map file
				if block.File != nil {
					respBlocks[i].FileID = block.File.FileID
					respBlocks[i].ResponsesInputMessageContentBlockFile = &ResponsesInputMessageContentBlockFile{
						FileData: block.File.FileData,
						FileURL:  block.File.FileURL,
						Filename: block.File.Filename,
						FileType: block.File.FileType,
					}
				}

				// Map audio
				if block.InputAudio != nil {
					format := ""
					if block.InputAudio.Format != nil {
						format = *block.InputAudio.Format
					}
					respBlocks[i].Audio = &ResponsesInputMessageContentBlockAudio{
						Data:   block.InputAudio.Data,
						Format: format,
					}
				}
			}
			respMsg.ResponsesToolMessage.Output = &ResponsesToolMessageOutputStruct{
				ResponsesFunctionToolCallOutputBlocks: respBlocks,
			}
		}
	}

	return respMsg
}

// =============================================================================
// TOOL CHOICE CONVERSION METHODS
// =============================================================================

// ToChatToolChoice converts a ResponsesToolChoice to ChatToolChoice format
func (tc *ResponsesToolChoice) ToChatToolChoice() *ChatToolChoice {
	if tc == nil {
		return &ChatToolChoice{}
	}

	ctc := &ChatToolChoice{}

	// Handle string choice
	if tc.ResponsesToolChoiceStr != nil {
		ctc.ChatToolChoiceStr = tc.ResponsesToolChoiceStr
		return ctc
	}

	// Handle structured choice
	if tc.ResponsesToolChoiceStruct != nil {
		ctc.ChatToolChoiceStruct = &ChatToolChoiceStruct{
			Type: ChatToolChoiceType(tc.ResponsesToolChoiceStruct.Type),
		}

		// Handle mode-based choices (none, auto, required)
		if tc.ResponsesToolChoiceStruct.Mode != nil {
			switch *tc.ResponsesToolChoiceStruct.Mode {
			case "none":
				ctc.ChatToolChoiceStruct.Type = ChatToolChoiceTypeNone
			case "auto":
				ctc.ChatToolChoiceStruct.Type = ChatToolChoiceTypeAny
			case "required":
				ctc.ChatToolChoiceStruct.Type = ChatToolChoiceTypeRequired
			}
		}

		// Handle function choice
		if tc.ResponsesToolChoiceStruct.Type == ResponsesToolChoiceTypeFunction && tc.ResponsesToolChoiceStruct.Name != nil {
			ctc.ChatToolChoiceStruct.Function = &ChatToolChoiceFunction{
				Name: *tc.ResponsesToolChoiceStruct.Name,
			}
		}

		// Handle custom choice
		if tc.ResponsesToolChoiceStruct.Type == ResponsesToolChoiceTypeCustom && tc.ResponsesToolChoiceStruct.Name != nil {
			ctc.ChatToolChoiceStruct.Custom = &ChatToolChoiceCustom{
				Name: *tc.ResponsesToolChoiceStruct.Name,
			}
		}

		// Handle allowed tools
		if len(tc.ResponsesToolChoiceStruct.Tools) > 0 {
			ctc.ChatToolChoiceStruct.Type = ChatToolChoiceTypeAllowedTools
			tools := make([]ChatToolChoiceAllowedToolsTool, len(tc.ResponsesToolChoiceStruct.Tools))
			for i, tool := range tc.ResponsesToolChoiceStruct.Tools {
				tools[i] = ChatToolChoiceAllowedToolsTool{
					Type: tool.Type,
				}
				if tool.Name != nil {
					tools[i].Function = ChatToolChoiceFunction{Name: *tool.Name}
				}
			}
			// Copy the mode if present, otherwise default to "auto"
			mode := "auto"
			if tc.ResponsesToolChoiceStruct.Mode != nil && *tc.ResponsesToolChoiceStruct.Mode != "" {
				mode = *tc.ResponsesToolChoiceStruct.Mode
			}
			ctc.ChatToolChoiceStruct.AllowedTools = &ChatToolChoiceAllowedTools{
				Mode:  mode,
				Tools: tools,
			}
		}

		return ctc
	}

	return nil
}

// =============================================================================
// MESSAGE CONVERSION METHODS
// =============================================================================

func (cu *BifrostLLMUsage) ToResponsesResponseUsage() *ResponsesResponseUsage {
	if cu == nil {
		return nil
	}

	usage := &ResponsesResponseUsage{
		InputTokens:    cu.PromptTokens,
		OutputTokens:   cu.CompletionTokens,
		TotalTokens:    cu.TotalTokens,
		Cost:           cu.Cost,
		CostInUsdTicks: cu.CostInUsdTicks,
	}

	if cu.PromptTokensDetails != nil {
		usage.InputTokensDetails = &ResponsesResponseInputTokens{
			TextTokens:              cu.PromptTokensDetails.TextTokens,
			AudioTokens:             cu.PromptTokensDetails.AudioTokens,
			ImageTokens:             cu.PromptTokensDetails.ImageTokens,
			CachedReadTokens:        cu.PromptTokensDetails.CachedReadTokens,
			CachedWriteTokens:       cu.PromptTokensDetails.CachedWriteTokens,
			CachedWriteTokenDetails: cu.PromptTokensDetails.CachedWriteTokenDetails,

			StandardSpeechAudioTokens: cu.PromptTokensDetails.StandardSpeechAudioTokens,
			CustomSpeechAudioTokens:   cu.PromptTokensDetails.CustomSpeechAudioTokens,
		}
	}
	if cu.CompletionTokensDetails != nil {
		usage.OutputTokensDetails = &ResponsesResponseOutputTokens{
			TextTokens:               cu.CompletionTokensDetails.TextTokens,
			AcceptedPredictionTokens: cu.CompletionTokensDetails.AcceptedPredictionTokens,
			AudioTokens:              cu.CompletionTokensDetails.AudioTokens,
			ReasoningTokens:          cu.CompletionTokensDetails.ReasoningTokens,
			RejectedPredictionTokens: cu.CompletionTokensDetails.RejectedPredictionTokens,
			CitationTokens:           cu.CompletionTokensDetails.CitationTokens,
			NumSearchQueries:         cu.CompletionTokensDetails.NumSearchQueries,

			StandardSpeechAudioTokens: cu.CompletionTokensDetails.StandardSpeechAudioTokens,
			CustomSpeechAudioTokens:   cu.CompletionTokensDetails.CustomSpeechAudioTokens,

			ReasoningTokensReported: cu.CompletionTokensDetails.ReasoningTokensReported,
		}
	}
	usage.ToolUsage = cu.ToolUsage.DeepCopy()
	usage.Iterations = slices.Clone(cu.Iterations)

	return usage
}

func (ru *ResponsesResponseUsage) ToBifrostLLMUsage() *BifrostLLMUsage {
	if ru == nil {
		return nil
	}

	usage := &BifrostLLMUsage{
		PromptTokens:     ru.InputTokens,
		CompletionTokens: ru.OutputTokens,
		TotalTokens:      ru.TotalTokens,
		Cost:             ru.Cost,
		CostInUsdTicks:   ru.CostInUsdTicks,
	}

	if ru.InputTokensDetails != nil {
		usage.PromptTokensDetails = &ChatPromptTokensDetails{
			TextTokens:              ru.InputTokensDetails.TextTokens,
			AudioTokens:             ru.InputTokensDetails.AudioTokens,
			ImageTokens:             ru.InputTokensDetails.ImageTokens,
			CachedReadTokens:        ru.InputTokensDetails.CachedReadTokens,
			CachedWriteTokens:       ru.InputTokensDetails.CachedWriteTokens,
			CachedWriteTokenDetails: ru.InputTokensDetails.CachedWriteTokenDetails,

			StandardSpeechAudioTokens: ru.InputTokensDetails.StandardSpeechAudioTokens,
			CustomSpeechAudioTokens:   ru.InputTokensDetails.CustomSpeechAudioTokens,
		}
	}
	if ru.OutputTokensDetails != nil {
		usage.CompletionTokensDetails = &ChatCompletionTokensDetails{
			TextTokens:               ru.OutputTokensDetails.TextTokens,
			AcceptedPredictionTokens: ru.OutputTokensDetails.AcceptedPredictionTokens,
			AudioTokens:              ru.OutputTokensDetails.AudioTokens,
			ImageTokens:              ru.OutputTokensDetails.ImageTokens,
			ReasoningTokens:          ru.OutputTokensDetails.ReasoningTokens,
			RejectedPredictionTokens: ru.OutputTokensDetails.RejectedPredictionTokens,
			CitationTokens:           ru.OutputTokensDetails.CitationTokens,
			NumSearchQueries:         ru.OutputTokensDetails.NumSearchQueries,

			StandardSpeechAudioTokens: ru.OutputTokensDetails.StandardSpeechAudioTokens,
			CustomSpeechAudioTokens:   ru.OutputTokensDetails.CustomSpeechAudioTokens,

			ReasoningTokensReported: ru.OutputTokensDetails.ReasoningTokensReported,
		}
	}
	usage.ToolUsage = ru.ToolUsage.DeepCopy()
	usage.Iterations = slices.Clone(ru.Iterations) // advisor passes are priced from these, so they survive the round trip

	return usage
}

// NormalizedUsage folds whichever family's usage a settled response carries into
// the canonical BifrostLLMUsage shape, so the logging plugin and the tracer read
// token counts from one place and cannot disagree.
//
// Streaming requests do not reach here: they settle through the accumulator and
// carry usage on the accumulated result instead.
//
// The returned value may alias the response's own usage; callers that retain it
// past the request should DeepCopy.
func (r *BifrostResponse) NormalizedUsage() *BifrostLLMUsage {
	if r == nil {
		return nil
	}
	switch {
	case r.TextCompletionResponse != nil && r.TextCompletionResponse.Usage != nil:
		return r.TextCompletionResponse.Usage
	case r.ChatResponse != nil && r.ChatResponse.Usage != nil:
		return r.ChatResponse.Usage
	case r.ResponsesResponse != nil && r.ResponsesResponse.Usage != nil:
		return r.ResponsesResponse.Usage.ToBifrostLLMUsage()
	case r.CompactionResponse != nil && r.CompactionResponse.Usage != nil:
		return r.CompactionResponse.Usage.ToBifrostLLMUsage()
	case r.EmbeddingResponse != nil && r.EmbeddingResponse.Usage != nil:
		return r.EmbeddingResponse.Usage
	case r.RerankResponse != nil && r.RerankResponse.Usage != nil:
		return r.RerankResponse.Usage
	case r.DecisionResponse != nil && r.DecisionResponse.Usage != nil:
		return r.DecisionResponse.Usage
	case r.TranscriptionResponse != nil && r.TranscriptionResponse.Usage != nil:
		u := r.TranscriptionResponse.Usage
		out := &BifrostLLMUsage{}
		if u.InputTokens != nil {
			out.PromptTokens = *u.InputTokens
		}
		if u.OutputTokens != nil {
			out.CompletionTokens = *u.OutputTokens
		}
		if u.TotalTokens != nil {
			out.TotalTokens = *u.TotalTokens
		}
		// Derive on zero as well as nil: some providers report total_tokens: 0
		// alongside real counts. Matches the speech branch below.
		if out.TotalTokens == 0 {
			out.TotalTokens = out.PromptTokens + out.CompletionTokens
		}
		if d := u.InputTokenDetails; d != nil {
			out.PromptTokensDetails = &ChatPromptTokensDetails{
				TextTokens:  d.TextTokens,
				AudioTokens: d.AudioTokens,
			}
		}
		return out
	case r.SpeechResponse != nil && r.SpeechResponse.Usage != nil:
		u := r.SpeechResponse.Usage
		out := &BifrostLLMUsage{
			PromptTokens:     u.InputTokens,
			CompletionTokens: u.OutputTokens,
			TotalTokens:      u.TotalTokens,
		}
		if out.TotalTokens == 0 {
			out.TotalTokens = out.PromptTokens + out.CompletionTokens
		}
		return out
	case r.ImageGenerationResponse != nil && r.ImageGenerationResponse.Usage != nil:
		u := r.ImageGenerationResponse.Usage
		out := &BifrostLLMUsage{
			PromptTokens:     u.InputTokens,
			CompletionTokens: u.OutputTokens,
		}
		if u.TotalTokens > 0 {
			out.TotalTokens = u.TotalTokens
		} else {
			out.TotalTokens = out.PromptTokens + out.CompletionTokens
		}
		return out
	case r.PassthroughResponse != nil && r.PassthroughResponse.PassthroughUsage != nil:
		return r.PassthroughResponse.PassthroughUsage.LLMUsage
	}
	return nil
}

// =============================================================================
// RESPONSE CONVERSION METHODS
// =============================================================================

func responsesStatusFromChatFinishReason(finishReason string) (status string, incompleteDetails *ResponsesResponseIncompleteDetails, mapped bool) {
	switch finishReason {
	// Anthropic's reasons pass through Chat Completions: a full context window cuts the reply short,
	// and a refusal is a classifier stopping it.
	case string(BifrostFinishReasonLength), "model_context_window_exceeded":
		return "incomplete", &ResponsesResponseIncompleteDetails{Reason: ResponsesResponseIncompleteReasonMaxOutputTokens}, true
	case "content_filter", "guardrail_intervened", "refusal":
		return "incomplete", &ResponsesResponseIncompleteDetails{Reason: ResponsesResponseIncompleteReasonContentFilter}, true
	case string(BifrostFinishReasonStop), string(BifrostFinishReasonToolCalls):
		return "completed", nil, true
	default:
		return "", nil, false
	}
}

// ResponsesStatusFromFinishReason maps a Bifrost finish reason to the Responses-API
// status and incomplete_details. mapped is false for reasons with no Responses
// equivalent, which should leave Status unset.
func ResponsesStatusFromFinishReason(finishReason string) (status string, incompleteDetails *ResponsesResponseIncompleteDetails, mapped bool) {
	return responsesStatusFromChatFinishReason(finishReason)
}

// MarkTruncatedOutputItem sets status "incomplete" on the last output item -- the one
// being generated when the turn was cut short -- matching OpenAI's truncated-turn shape.
func MarkTruncatedOutputItem(output []ResponsesMessage) {
	if len(output) == 0 {
		return
	}
	output[len(output)-1].Status = Ptr(ResponsesResponseStatusIncomplete)
}

// chatFinishReasonFromResponses derives a Chat finish_reason from a Responses terminal state.
// Returns nil for non-terminal or unrecognized states so finish_reason stays unset.
func chatFinishReasonFromResponses(status *string, incompleteDetails *ResponsesResponseIncompleteDetails, stopReason *string, output []ResponsesMessage) *string {
	if status != nil && (*status == ResponsesResponseStatusInProgress || *status == ResponsesResponseStatusQueued) {
		return nil
	}

	if stopReason != nil && *stopReason != "" {
		if _, _, mapped := responsesStatusFromChatFinishReason(*stopReason); mapped {
			return Ptr(*stopReason)
		}
	}

	if incompleteDetails != nil {
		switch incompleteDetails.Reason {
		case ResponsesResponseIncompleteReasonMaxOutputTokens:
			return Ptr(string(BifrostFinishReasonLength))
		case ResponsesResponseIncompleteReasonContentFilter:
			return Ptr("content_filter")
		}
	}

	if status != nil && *status == ResponsesResponseStatusCompleted {
		for _, item := range output {
			if item.Type != nil && *item.Type == ResponsesMessageTypeFunctionCall {
				return Ptr(string(BifrostFinishReasonToolCalls))
			}
		}
		return Ptr(string(BifrostFinishReasonStop))
	}

	return nil
}

// =============================================================================
// RESPONSE CONVERSION METHODS
// =============================================================================

// ToBifrostTextCompletionResponse converts a BifrostChatResponse to a BifrostTextCompletionResponse
func (cr *BifrostChatResponse) ToBifrostTextCompletionResponse() *BifrostTextCompletionResponse {
	if cr == nil {
		return nil
	}

	if len(cr.Choices) == 0 {
		return &BifrostTextCompletionResponse{
			ID:                cr.ID,
			Model:             cr.Model,
			Created:           cr.Created,
			Object:            "text_completion",
			SystemFingerprint: cr.SystemFingerprint,
			Usage:             cr.Usage,
			ExtraFields: BifrostResponseExtraFields{
				RequestType:             TextCompletionRequest,
				ChunkIndex:              cr.ExtraFields.ChunkIndex,
				Provider:                cr.ExtraFields.Provider,
				OriginalModelRequested:  cr.ExtraFields.OriginalModelRequested,
				Latency:                 cr.ExtraFields.Latency,
				RawResponse:             cr.ExtraFields.RawResponse,
				CacheDebug:              cr.ExtraFields.CacheDebug,
				GuardrailDebug:          cr.ExtraFields.GuardrailDebug,
				ProviderResponseHeaders: cr.ExtraFields.ProviderResponseHeaders,
			},
		}
	}

	choice := cr.Choices[0]

	// Handle streaming response choice
	if choice.ChatStreamResponseChoice != nil && choice.ChatStreamResponseChoice.Delta != nil {
		return &BifrostTextCompletionResponse{
			ID:                cr.ID,
			Model:             cr.Model,
			Created:           cr.Created,
			Object:            "text_completion",
			SystemFingerprint: cr.SystemFingerprint,
			Choices: []BifrostResponseChoice{
				{
					Index: 0,
					TextCompletionResponseChoice: &TextCompletionResponseChoice{
						Text: choice.ChatStreamResponseChoice.Delta.Content,
					},
					FinishReason: choice.FinishReason,
					LogProbs:     choice.LogProbs,
				},
			},
			Usage: cr.Usage,
			ExtraFields: BifrostResponseExtraFields{
				RequestType:             TextCompletionRequest,
				ChunkIndex:              cr.ExtraFields.ChunkIndex,
				Provider:                cr.ExtraFields.Provider,
				OriginalModelRequested:  cr.ExtraFields.OriginalModelRequested,
				Latency:                 cr.ExtraFields.Latency,
				RawResponse:             cr.ExtraFields.RawResponse,
				CacheDebug:              cr.ExtraFields.CacheDebug,
				GuardrailDebug:          cr.ExtraFields.GuardrailDebug,
				ProviderResponseHeaders: cr.ExtraFields.ProviderResponseHeaders,
			},
		}
	}

	// Handle non-streaming response choice
	if choice.ChatNonStreamResponseChoice != nil {
		msg := choice.ChatNonStreamResponseChoice.Message
		var textContent *string
		if msg != nil && msg.Content != nil {
			if msg.Content.ContentStr != nil {
				textContent = msg.Content.ContentStr
			} else if len(msg.Content.ContentBlocks) > 0 {
				var sb strings.Builder
				for _, block := range msg.Content.ContentBlocks {
					if block.Text != nil {
						sb.WriteString(*block.Text)
					}
				}
				if sb.Len() > 0 {
					s := sb.String()
					textContent = &s
				}
			}
		}
		return &BifrostTextCompletionResponse{
			ID:                cr.ID,
			Model:             cr.Model,
			Created:           cr.Created,
			Object:            "text_completion",
			SystemFingerprint: cr.SystemFingerprint,
			Choices: []BifrostResponseChoice{
				{
					Index: 0,
					TextCompletionResponseChoice: &TextCompletionResponseChoice{
						Text: textContent,
					},
					FinishReason: choice.FinishReason,
					LogProbs:     choice.LogProbs,
				},
			},
			Usage: cr.Usage,
			ExtraFields: BifrostResponseExtraFields{
				RequestType:             TextCompletionRequest,
				ChunkIndex:              cr.ExtraFields.ChunkIndex,
				Provider:                cr.ExtraFields.Provider,
				OriginalModelRequested:  cr.ExtraFields.OriginalModelRequested,
				Latency:                 cr.ExtraFields.Latency,
				RawResponse:             cr.ExtraFields.RawResponse,
				CacheDebug:              cr.ExtraFields.CacheDebug,
				GuardrailDebug:          cr.ExtraFields.GuardrailDebug,
				ProviderResponseHeaders: cr.ExtraFields.ProviderResponseHeaders,
			},
		}
	}

	// Fallback case - return basic response structure
	return &BifrostTextCompletionResponse{
		ID:                cr.ID,
		Model:             cr.Model,
		Created:           cr.Created,
		Object:            "text_completion",
		SystemFingerprint: cr.SystemFingerprint,
		Usage:             cr.Usage,
		ExtraFields: BifrostResponseExtraFields{
			RequestType:             TextCompletionRequest,
			ChunkIndex:              cr.ExtraFields.ChunkIndex,
			Provider:                cr.ExtraFields.Provider,
			OriginalModelRequested:  cr.ExtraFields.OriginalModelRequested,
			Latency:                 cr.ExtraFields.Latency,
			RawResponse:             cr.ExtraFields.RawResponse,
			CacheDebug:              cr.ExtraFields.CacheDebug,
			GuardrailDebug:          cr.ExtraFields.GuardrailDebug,
			ProviderResponseHeaders: cr.ExtraFields.ProviderResponseHeaders,
		},
	}
}
