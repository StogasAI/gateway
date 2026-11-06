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

// ToResponsesToolChoice converts a ChatToolChoice to ResponsesToolChoice format
func (ctc *ChatToolChoice) ToResponsesToolChoice() *ResponsesToolChoice {
	if ctc == nil {
		return &ResponsesToolChoice{}
	}

	rtc := &ResponsesToolChoice{}

	// Handle string choice (e.g., "none", "auto", "required")
	if ctc.ChatToolChoiceStr != nil {
		rtc.ResponsesToolChoiceStr = ctc.ChatToolChoiceStr
		return rtc
	}

	// Handle structured choice
	if ctc.ChatToolChoiceStruct != nil {
		rtc.ResponsesToolChoiceStruct = &ResponsesToolChoiceStruct{
			Type: ResponsesToolChoiceType(ctc.ChatToolChoiceStruct.Type),
		}

		switch ctc.ChatToolChoiceStruct.Type {
		case ChatToolChoiceTypeNone, ChatToolChoiceTypeAny, ChatToolChoiceTypeRequired:
			// These map to mode field
			modeStr := string(ctc.ChatToolChoiceStruct.Type)
			rtc.ResponsesToolChoiceStruct.Mode = &modeStr

		case ChatToolChoiceTypeFunction:
			// Map function choice
			if ctc.ChatToolChoiceStruct.Function != nil && ctc.ChatToolChoiceStruct.Function.Name != "" {
				rtc.ResponsesToolChoiceStruct.Name = &ctc.ChatToolChoiceStruct.Function.Name
			}

		case ChatToolChoiceTypeAllowedTools:
			// Map allowed tools
			if ctc.ChatToolChoiceStruct.AllowedTools != nil && len(ctc.ChatToolChoiceStruct.AllowedTools.Tools) > 0 {
				tools := make([]ResponsesToolChoiceAllowedToolDef, len(ctc.ChatToolChoiceStruct.AllowedTools.Tools))
				for i, tool := range ctc.ChatToolChoiceStruct.AllowedTools.Tools {
					tools[i] = ResponsesToolChoiceAllowedToolDef{
						Type: tool.Type,
					}
					if tool.Function.Name != "" {
						name := tool.Function.Name
						tools[i].Name = &name
					}
				}
				rtc.ResponsesToolChoiceStruct.Tools = tools
			}
			// Copy the mode (e.g., "auto", "required")
			if ctc.ChatToolChoiceStruct.AllowedTools != nil && ctc.ChatToolChoiceStruct.AllowedTools.Mode != "" {
				mode := ctc.ChatToolChoiceStruct.AllowedTools.Mode
				rtc.ResponsesToolChoiceStruct.Mode = &mode
			}

		case ChatToolChoiceTypeCustom:
			// Map custom choice
			if ctc.ChatToolChoiceStruct.Custom != nil && ctc.ChatToolChoiceStruct.Custom.Name != "" {
				rtc.ResponsesToolChoiceStruct.Name = &ctc.ChatToolChoiceStruct.Custom.Name
			}
		}
	}

	return rtc
}

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

// ToResponsesMessages converts a ChatMessage to one or more ResponsesMessages
// This handles the expansion of assistant messages with tool calls into separate function_call messages
func (cm *ChatMessage) ToResponsesMessages() []ResponsesMessage {
	if cm == nil {
		return []ResponsesMessage{}
	}

	var messages []ResponsesMessage

	// Emit reasoning first so chat->responses->anthropic preserves reasoning content
	// (Anthropic signatures, OpenAI encrypted/summary entries) for clients to echo back; see symmetric ToChatMessages buffering.
	if cm.Role == ChatMessageRoleAssistant && cm.ChatAssistantMessage != nil {
		am := cm.ChatAssistantMessage
		if len(am.ReasoningDetails) > 0 {
			var contentBlocks []ResponsesMessageContentBlock
			var encryptedContent *string
			// Non-nil: the Responses schema requires summary to be an array, and a nil
			// slice marshals to null, which upstreams reject for the whole input item.
			summaries := []ResponsesReasoningSummary{}
			// OpenAI pairs an item id with its encrypted token, so the id must come from the encrypted detail whose
			// token is emitted below (the last one carrying data). If that detail has no id, mint a fresh one rather
			// than borrow a neighbour's: an id the token was never issued with is rejected upstream. With no token
			// to pair, the first recorded id is kept.
			var emittedToken *ChatReasoningDetails
			for i := range am.ReasoningDetails {
				if d := &am.ReasoningDetails[i]; d.Type == BifrostReasoningDetailsTypeEncrypted && d.Data != nil {
					emittedToken = d
				}
			}
			reasoningID := ""
			if emittedToken != nil {
				if emittedToken.ID != nil {
					reasoningID = *emittedToken.ID
				}
			} else {
				for _, d := range am.ReasoningDetails {
					if d.ID != nil && *d.ID != "" {
						reasoningID = *d.ID
						break
					}
				}
			}
			if reasoningID == "" {
				reasoningID = "rs_" + GetRandomString(50)
			}
			for _, d := range am.ReasoningDetails {
				switch d.Type {
				case BifrostReasoningDetailsTypeText:
					if d.Text != nil && *d.Text != "" {
						contentBlocks = append(contentBlocks, ResponsesMessageContentBlock{
							Type:      ResponsesOutputMessageContentTypeReasoning,
							Text:      d.Text,
							Signature: d.Signature,
						})
					}
				case BifrostReasoningDetailsTypeSummary:
					if d.Summary != nil {
						summaries = append(summaries, ResponsesReasoningSummary{
							Type: ResponsesReasoningContentBlockTypeSummaryText,
							Text: *d.Summary,
						})
					}
				case BifrostReasoningDetailsTypeEncrypted:
					if d.Data != nil {
						encryptedContent = d.Data
					}
				}
			}
			if len(contentBlocks) > 0 || len(summaries) > 0 || encryptedContent != nil {
				reasoningType := ResponsesMessageTypeReasoning
				reasoningRole := ResponsesInputMessageRoleAssistant
				rm := ResponsesMessage{
					ID:   new(reasoningID),
					Type: &reasoningType,
					Role: &reasoningRole,
				}
				if len(contentBlocks) > 0 {
					rm.Content = &ResponsesMessageContent{ContentBlocks: contentBlocks}
				}
				if len(summaries) > 0 || encryptedContent != nil {
					rm.ResponsesReasoning = &ResponsesReasoning{
						Summary:          summaries,
						EncryptedContent: encryptedContent,
					}
				}
				messages = append(messages, rm)
			}
		} else if am.Reasoning != nil && *am.Reasoning != "" {
			// Fallback for providers that surface plain reasoning text only (e.g. DeepSeek).
			reasoningType := ResponsesMessageTypeReasoning
			reasoningRole := ResponsesInputMessageRoleAssistant
			reasoningText := *am.Reasoning
			messages = append(messages, ResponsesMessage{
				ID:   new("rs_" + GetRandomString(50)),
				Type: &reasoningType,
				Role: &reasoningRole,
				Content: &ResponsesMessageContent{
					ContentBlocks: []ResponsesMessageContentBlock{
						{
							Type: ResponsesOutputMessageContentTypeReasoning,
							Text: &reasoningText,
						},
					},
				},
			})
		}
	}

	// Check if this is an assistant message with multiple tool calls that need expansion
	if cm.ChatAssistantMessage != nil && cm.ChatAssistantMessage.ToolCalls != nil && len(cm.ChatAssistantMessage.ToolCalls) > 0 {
		// Expand multiple tool calls into separate function_call items
		for _, tc := range cm.ChatAssistantMessage.ToolCalls {
			messageType := ResponsesMessageTypeFunctionCall

			var callID *string
			if tc.ID != nil && *tc.ID != "" {
				callID = tc.ID
			}

			var namePtr *string
			if tc.Function.Name != nil && *tc.Function.Name != "" {
				namePtr = tc.Function.Name
			}

			// Create a copy of the arguments string to avoid range loop variable capture
			var argumentsPtr *string
			if tc.Function.Arguments != "" {
				argumentsPtr = Ptr(tc.Function.Arguments)
			}

			rm := ResponsesMessage{
				ID:     Ptr("fc_" + GetRandomString(50)),
				Type:   &messageType,
				Role:   Ptr(ResponsesInputMessageRoleAssistant),
				Status: Ptr("completed"),
				ResponsesToolMessage: &ResponsesToolMessage{
					CallID:    callID,
					Name:      namePtr,
					Arguments: argumentsPtr,
				},
			}

			messages = append(messages, rm)
		}
		return messages
	}

	// Regular message conversion
	messageType := ResponsesMessageTypeMessage
	role := ResponsesInputMessageRoleUser

	// Determine message type and role
	switch cm.Role {
	case ChatMessageRoleAssistant:
		role = ResponsesInputMessageRoleAssistant
		// Check for refusal
		if cm.ChatAssistantMessage != nil && cm.ChatAssistantMessage.Refusal != nil {
			messageType = ResponsesMessageTypeRefusal
		}
	case ChatMessageRoleUser:
		role = ResponsesInputMessageRoleUser
	case ChatMessageRoleSystem:
		role = ResponsesInputMessageRoleSystem
	case ChatMessageRoleTool:
		messageType = ResponsesMessageTypeFunctionCallOutput
		role = "" // tool call output messages don't include a role field
	case ChatMessageRoleDeveloper:
		role = ResponsesInputMessageRoleDeveloper
	}

	rm := ResponsesMessage{
		Type: &messageType,
	}

	if role != "" {
		rm.Role = &role
	}

	if role == ResponsesInputMessageRoleAssistant && messageType != ResponsesMessageTypeFunctionCallOutput {
		rm.ID = Ptr("msg_" + GetRandomString(50))
	}

	// Handle refusal content specifically - use content blocks with ResponsesOutputMessageContentRefusal
	if messageType == ResponsesMessageTypeRefusal && cm.ChatAssistantMessage != nil && cm.ChatAssistantMessage.Refusal != nil {
		refusalBlock := ResponsesMessageContentBlock{
			Type: ResponsesOutputMessageContentTypeRefusal,
			ResponsesOutputMessageContentRefusal: &ResponsesOutputMessageContentRefusal{
				Refusal: *cm.ChatAssistantMessage.Refusal,
			},
		}
		rm.Content = &ResponsesMessageContent{
			ContentBlocks: []ResponsesMessageContentBlock{refusalBlock},
		}
	} else if cm.Content != nil && cm.Content.ContentStr != nil {
		// Convert regular string content (if input message then ContentStr, else ContentBlocks)
		// Skip setting content for function_call_output - content should only be in output field
		if messageType == ResponsesMessageTypeFunctionCallOutput {
			// Don't set content for function_call_output - it will be set in ResponsesToolMessage.Output
		} else if cm.Role == ChatMessageRoleAssistant {
			rm.Content = &ResponsesMessageContent{
				ContentBlocks: []ResponsesMessageContentBlock{
					{
						Type: ResponsesOutputMessageContentTypeText,
						Text: cm.Content.ContentStr,
						ResponsesOutputMessageContentText: &ResponsesOutputMessageContentText{
							LogProbs:    []ResponsesOutputMessageContentTextLogProb{},
							Annotations: []ResponsesOutputMessageContentTextAnnotation{},
						},
					},
				},
			}

			rm.Status = Ptr("completed")
		} else {
			rm.Content = &ResponsesMessageContent{
				ContentStr: cm.Content.ContentStr,
			}
		}
	} else if cm.Content != nil && cm.Content.ContentBlocks != nil {
		// Convert content blocks
		// Skip setting content blocks for function_call_output
		if messageType == ResponsesMessageTypeFunctionCallOutput {
			// Don't set content for function_call_output - it will be set in ResponsesToolMessage.Output
		} else {
			responseBlocks := make([]ResponsesMessageContentBlock, 0, len(cm.Content.ContentBlocks))
			for _, block := range cm.Content.ContentBlocks {
				// Responses blocks have no cachePoint equivalent; a standalone marker would serialize as an empty-type block.
				if block.Type == "" && block.CachePoint != nil {
					continue
				}
				blockType := ResponsesMessageContentBlockType(block.Type)

				switch block.Type {
				case ChatContentBlockTypeText:
					if cm.Role == ChatMessageRoleAssistant {
						blockType = ResponsesOutputMessageContentTypeText
					} else {
						blockType = ResponsesInputMessageContentBlockTypeText
					}
				case ChatContentBlockTypeImage:
					blockType = ResponsesInputMessageContentBlockTypeImage
				case ChatContentBlockTypeFile:
					blockType = ResponsesInputMessageContentBlockTypeFile
				case ChatContentBlockTypeInputAudio:
					blockType = ResponsesInputMessageContentBlockTypeAudio
				}

				responseBlocks = append(responseBlocks, ResponsesMessageContentBlock{
					Type:         blockType,
					Text:         block.Text,
					GuardContent: block.GuardContent,
				})
				rb := &responseBlocks[len(responseBlocks)-1]

				// Convert specific block types
				if block.ImageURLStruct != nil {
					rb.ResponsesInputMessageContentBlockImage = &ResponsesInputMessageContentBlockImage{
						ImageURL: &block.ImageURLStruct.URL,
						Detail:   block.ImageURLStruct.Detail,
					}
				}
				if block.File != nil {
					rb.ResponsesInputMessageContentBlockFile = &ResponsesInputMessageContentBlockFile{
						FileData: block.File.FileData,
						FileURL:  block.File.FileURL,
						Filename: block.File.Filename,
						FileType: block.File.FileType,
					}
					rb.FileID = block.File.FileID
				}
				if block.InputAudio != nil {
					format := ""
					if block.InputAudio.Format != nil {
						format = *block.InputAudio.Format
					}
					rb.Audio = &ResponsesInputMessageContentBlockAudio{
						Data:   block.InputAudio.Data,
						Format: format,
					}
				}
			}
			rm.Content = &ResponsesMessageContent{
				ContentBlocks: responseBlocks,
			}
		}
	}

	// Handle tool messages
	if cm.ChatToolMessage != nil {
		rm.ResponsesToolMessage = &ResponsesToolMessage{}
		if cm.ChatToolMessage.ToolCallID != nil {
			rm.ResponsesToolMessage.CallID = cm.ChatToolMessage.ToolCallID
		}

		// The chat surface marks a failed tool result with a bool and carries no
		// error text, so there is nothing to put in ResponsesToolMessage.Error.
		// Status "incomplete" is the equivalent signal on this surface, and is
		// what the Anthropic Responses converter already reads back as is_error
		// (providers/anthropic/responses.go).
		if cm.ChatToolMessage.IsError != nil && *cm.ChatToolMessage.IsError {
			rm.Status = Ptr("incomplete")
		}

		// If tool output content exists, add it to function_call_output
		// For function_call_output, get content from cm.Content since rm.Content is not set
		if messageType == ResponsesMessageTypeFunctionCallOutput && cm.Content != nil {
			// Prefer ContentStr if present
			if cm.Content.ContentStr != nil {
				rm.ResponsesToolMessage.Output = &ResponsesToolMessageOutputStruct{
					ResponsesToolCallOutputStr: cm.Content.ContentStr,
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
				rm.ResponsesToolMessage.Output = &ResponsesToolMessageOutputStruct{
					ResponsesFunctionToolCallOutputBlocks: respBlocks,
				}
			}
		}
	}

	messages = append(messages, rm)
	return messages
}

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
// REQUEST CONVERSION METHODS
// =============================================================================

// ToResponsesRequest converts a BifrostChatRequest to BifrostResponsesRequest format
func (cr *BifrostChatRequest) ToResponsesRequest() *BifrostResponsesRequest {
	if cr == nil {
		return &BifrostResponsesRequest{}
	}

	brr := &BifrostResponsesRequest{
		Provider:  cr.Provider,
		Model:     cr.Model,
		Fallbacks: cr.Fallbacks, // Copy fallbacks as-is
	}

	// Convert Input messages using existing ChatMessage.ToResponsesMessages()
	var allResponsesMessages []ResponsesMessage
	for _, chatMsg := range cr.Input {
		msg := &chatMsg
		if chatMsg.Role == ChatMessageRoleTool {
			// A function_call_output carries only the media every Responses provider reads.
			msg = ToolResultForResponses(msg)
		}
		responsesMessages := msg.ToResponsesMessages()
		allResponsesMessages = append(allResponsesMessages, responsesMessages...)
	}
	brr.Input = allResponsesMessages

	// Convert Parameters
	if cr.Params != nil {
		brr.Params = &ResponsesParameters{
			// Map common fields
			ParallelToolCalls:    cr.Params.ParallelToolCalls,
			PromptCacheKey:       cr.Params.PromptCacheKey,
			PromptCacheRetention: cr.Params.PromptCacheRetention,
			PromptCacheOptions:   cr.Params.PromptCacheOptions,
			SafetyIdentifier:     cr.Params.SafetyIdentifier,
			ServiceTier:          cr.Params.ServiceTier,
			Store:                cr.Params.Store,
			Temperature:          cr.Params.Temperature,
			TopLogProbs:          cr.Params.TopLogProbs,
			TopP:                 cr.Params.TopP,
			ExtraParams:          cr.Params.ExtraParams,

			// Map specific fields
			MaxOutputTokens: cr.Params.MaxCompletionTokens, // max_completion_tokens -> max_output_tokens
			Metadata:        cr.Params.Metadata,
		}

		// Convert StreamOptions
		if cr.Params.StreamOptions != nil {
			brr.Params.StreamOptions = &ResponsesStreamOptions{
				IncludeObfuscation: cr.Params.StreamOptions.IncludeObfuscation,
			}
		}

		// Convert Tools using existing ChatTool.ToResponsesTool()
		if len(cr.Params.Tools) > 0 {
			responsesTools := make([]ResponsesTool, 0, len(cr.Params.Tools))
			for _, chatTool := range cr.Params.Tools {
				responsesTool := chatTool.ToResponsesTool()
				responsesTools = append(responsesTools, *responsesTool)
			}
			brr.Params.Tools = responsesTools
		}

		// Convert ToolChoice using existing ChatToolChoice.ToResponsesToolChoice()
		if cr.Params.ToolChoice != nil {
			responsesToolChoice := cr.Params.ToolChoice.ToResponsesToolChoice()
			brr.Params.ToolChoice = responsesToolChoice
		}

		// Handle Reasoning from reasoning_effort
		if cr.Params.Reasoning != nil && (cr.Params.Reasoning.Enabled != nil || cr.Params.Reasoning.Effort != nil || cr.Params.Reasoning.MaxTokens != nil || cr.Params.Reasoning.Type != nil || cr.Params.Reasoning.Mode != nil || cr.Params.Reasoning.Summary != nil) {
			brr.Params.Reasoning = &ResponsesParametersReasoning{
				Effort:    cr.Params.Reasoning.Effort,
				MaxTokens: cr.Params.Reasoning.MaxTokens,
				Type:      cr.Params.Reasoning.Type,
				Mode:      cr.Params.Reasoning.Mode,
				Summary:   cr.Params.Reasoning.Summary,
			}
		}

		if format := ResponsesTextConfigFormatFromChatResponseFormat(cr.Params.ResponseFormat); format != nil {
			if brr.Params.Text == nil {
				brr.Params.Text = &ResponsesTextConfig{}
			}
			brr.Params.Text.Format = format
		}

		// Handle Verbosity
		if cr.Params.Verbosity != nil {
			if brr.Params.Text == nil {
				brr.Params.Text = &ResponsesTextConfig{}
			}
			brr.Params.Text.Verbosity = cr.Params.Verbosity
		}
	}

	brr.RawRequestBody = cr.RawRequestBody

	return brr
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

// ToBifrostChatResponse converts a BifrostResponsesResponse to BifrostChatResponse format
// This converts Responses API format to Chat-style fields (Choices)
func (responsesResp *BifrostResponsesResponse) ToBifrostChatResponse() *BifrostChatResponse {
	if responsesResp == nil {
		return nil
	}

	// Create new BifrostChatResponse from Responses fields
	chatResp := &BifrostChatResponse{
		Created:       responsesResp.CreatedAt,
		Object:        "chat.completion",
		Model:         responsesResp.Model,
		ServiceTier:   responsesResp.ServiceTier,
		Speed:         responsesResp.Speed,
		InferenceGeo:  responsesResp.InferenceGeo,
		Citations:     responsesResp.Citations,
		SearchResults: responsesResp.SearchResults,
		Videos:        responsesResp.Videos,
	}

	if responsesResp.ID != nil {
		chatResp.ID = *responsesResp.ID
	}

	// Create Choices from ResponsesResponse
	if len(responsesResp.Output) > 0 {
		// Convert ResponsesMessages back to ChatMessages
		chatMessages := ToChatMessages(responsesResp.Output)

		finishReason := chatFinishReasonFromResponses(responsesResp.Status, responsesResp.IncompleteDetails, responsesResp.StopReason, responsesResp.Output)

		// Create choices from chat messages
		choices := make([]BifrostResponseChoice, 0, len(chatMessages))
		for i, chatMsg := range chatMessages {
			choice := BifrostResponseChoice{
				Index:        i,
				FinishReason: finishReason,
				ChatNonStreamResponseChoice: &ChatNonStreamResponseChoice{
					Message: &chatMsg,
				},
			}
			choices = append(choices, choice)
		}

		chatResp.Choices = choices
	}

	// Convert Usage if needed
	if responsesResp.Usage != nil {
		// Map Responses usage to Chat usage
		chatResp.Usage = responsesResp.Usage.ToBifrostLLMUsage()
	}

	// Copy other relevant fields
	chatResp.ExtraFields = responsesResp.ExtraFields
	chatResp.ExtraFields.RequestType = ChatCompletionRequest
	chatResp.ExtraFields.Provider = responsesResp.ExtraFields.Provider

	return chatResp
}

// ToBifrostChatResponse converts a BifrostResponsesStreamResponse chunk to a BifrostChatResponse (chat.completion.chunk).
func (rsr *BifrostResponsesStreamResponse) ToBifrostChatResponse() *BifrostChatResponse {
	if rsr == nil {
		return nil
	}

	extraFields := rsr.ExtraFields
	extraFields.RequestType = ChatCompletionStreamRequest

	resp := &BifrostChatResponse{
		Object:        "chat.completion.chunk",
		ExtraFields:   extraFields,
		SearchResults: rsr.SearchResults,
		Videos:        rsr.Videos,
		Citations:     rsr.Citations,
	}

	if rsr.Response != nil {
		if rsr.Response.ID != nil {
			resp.ID = *rsr.Response.ID
		}
		resp.Created = rsr.Response.CreatedAt
		resp.Model = rsr.Response.Model
		resp.ServiceTier = rsr.Response.ServiceTier
		resp.Speed = rsr.Response.Speed
		resp.InferenceGeo = rsr.Response.InferenceGeo
	}

	switch rsr.Type {
	case ResponsesStreamResponseTypeOutputTextDelta:
		resp.Choices = []BifrostResponseChoice{
			{
				Index: 0,
				ChatStreamResponseChoice: &ChatStreamResponseChoice{
					Delta: &ChatStreamResponseChoiceDelta{
						Content: rsr.Delta,
					},
				},
			},
		}
		return resp

	case ResponsesStreamResponseTypeReasoningSummaryTextDelta, ResponsesStreamResponseTypeReasoningTextDelta:
		resp.Choices = []BifrostResponseChoice{
			{
				Index: 0,
				ChatStreamResponseChoice: &ChatStreamResponseChoice{
					Delta: &ChatStreamResponseChoiceDelta{
						Reasoning: rsr.Delta,
					},
				},
			},
		}
		return resp

	case ResponsesStreamResponseTypeRefusalDelta:
		resp.Choices = []BifrostResponseChoice{
			{
				Index: 0,
				ChatStreamResponseChoice: &ChatStreamResponseChoice{
					Delta: &ChatStreamResponseChoiceDelta{
						Refusal: rsr.Delta,
					},
				},
			},
		}
		return resp

	case ResponsesStreamResponseTypeOutputItemAdded:
		if rsr.Item == nil || rsr.Item.Type == nil {
			resp.Choices = []BifrostResponseChoice{
				{
					Index: 0,
					ChatStreamResponseChoice: &ChatStreamResponseChoice{
						Delta: &ChatStreamResponseChoiceDelta{},
					},
				},
			}
			return resp
		}

		switch *rsr.Item.Type {
		case ResponsesMessageTypeFunctionCall:
			if rsr.Item.ResponsesToolMessage == nil {
				resp.Choices = []BifrostResponseChoice{
					{
						Index: 0,
						ChatStreamResponseChoice: &ChatStreamResponseChoice{
							Delta: &ChatStreamResponseChoiceDelta{},
						},
					},
				}
				return resp
			}
			funcType := "function"
			var idx uint16
			if rsr.OutputIndex != nil && *rsr.OutputIndex > 0 {
				idx = uint16(*rsr.OutputIndex - 1)
			}
			resp.Choices = []BifrostResponseChoice{
				{
					Index: 0,
					ChatStreamResponseChoice: &ChatStreamResponseChoice{
						Delta: &ChatStreamResponseChoiceDelta{
							ToolCalls: []ChatAssistantMessageToolCall{
								{
									Index: idx,
									Type:  &funcType,
									ID:    rsr.Item.ResponsesToolMessage.CallID,
									Function: ChatAssistantMessageToolCallFunction{
										Name: rsr.Item.ResponsesToolMessage.Name,
									},
								},
							},
						},
					},
				},
			}
			return resp

		case ResponsesMessageTypeMessage:
			role := "assistant"
			resp.Choices = []BifrostResponseChoice{
				{
					Index: 0,
					ChatStreamResponseChoice: &ChatStreamResponseChoice{
						Delta: &ChatStreamResponseChoiceDelta{
							Role: &role,
						},
					},
				},
			}
			return resp

		default:
			// reasoning, file_search_call, web_search_call, etc. — no chat equivalent,
			// actual content arrives via separate delta events.
			resp.Choices = []BifrostResponseChoice{
				{
					Index: 0,
					ChatStreamResponseChoice: &ChatStreamResponseChoice{
						Delta: &ChatStreamResponseChoiceDelta{},
					},
				},
			}
			return resp
		}

	case ResponsesStreamResponseTypeFunctionCallArgumentsDelta:
		if rsr.Delta == nil {
			resp.Choices = []BifrostResponseChoice{
				{
					Index: 0,
					ChatStreamResponseChoice: &ChatStreamResponseChoice{
						Delta: &ChatStreamResponseChoiceDelta{},
					},
				},
			}
			return resp
		}
		var idx uint16
		if rsr.OutputIndex != nil && *rsr.OutputIndex > 0 {
			idx = uint16(*rsr.OutputIndex - 1)
		}

		resp.Choices = []BifrostResponseChoice{
			{
				Index: 0,
				ChatStreamResponseChoice: &ChatStreamResponseChoice{
					Delta: &ChatStreamResponseChoiceDelta{
						ToolCalls: []ChatAssistantMessageToolCall{
							{
								Index: idx,
								Function: ChatAssistantMessageToolCallFunction{
									Arguments: *rsr.Delta,
								},
							},
						},
					},
				},
			},
		}
		return resp

	case ResponsesStreamResponseTypeCompleted, ResponsesStreamResponseTypeIncomplete:
		status := ResponsesResponseStatusCompleted
		fallback := string(BifrostFinishReasonStop)
		if rsr.Type == ResponsesStreamResponseTypeIncomplete {
			status = ResponsesResponseStatusIncomplete
			fallback = string(BifrostFinishReasonLength)
		}

		var (
			incompleteDetails *ResponsesResponseIncompleteDetails
			stopReason        *string
			output            []ResponsesMessage
		)
		if rsr.Response != nil {
			incompleteDetails = rsr.Response.IncompleteDetails
			stopReason = rsr.Response.StopReason
			output = rsr.Response.Output
			if rsr.Response.Usage != nil {
				resp.Usage = rsr.Response.Usage.ToBifrostLLMUsage()
			}
		}

		finishReason := chatFinishReasonFromResponses(&status, incompleteDetails, stopReason, output)
		if finishReason == nil {
			finishReason = &fallback
		}

		resp.Choices = []BifrostResponseChoice{
			{
				Index:        0,
				FinishReason: finishReason,
				ChatStreamResponseChoice: &ChatStreamResponseChoice{
					Delta: &ChatStreamResponseChoiceDelta{},
				},
			},
		}
		return resp

	default:
		// Lifecycle events (created, in_progress, content_part.added/done, output_text.done,
		// output_item.done, function_call_arguments.done, etc.) → empty chat chunk with no content.
		resp.Choices = []BifrostResponseChoice{
			{
				Index: 0,
				ChatStreamResponseChoice: &ChatStreamResponseChoice{
					Delta: &ChatStreamResponseChoiceDelta{},
				},
			},
		}
		return resp
	}
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
