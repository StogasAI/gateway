package schemas

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file converts between the Chat Completions and Responses interfaces for the providers that
// serve Chat Completions requests through Responses, such as OpenAI for its models that take only
// Responses. A conversion carries every part of a request or reply that the other interface can
// represent. ResponsesGap names the first part of a Chat Completions request that Responses cannot
// represent, so that a caller can refuse the request instead of losing that part.

// ResponsesGap returns the first part of the request that ToResponsesRequest cannot carry, checking
// the request's parameters and then its messages, or nil when it carries the whole request.
func (cr *BifrostChatRequest) ResponsesGap() *ConversionGap {
	if cr == nil {
		return nil
	}
	if gap := chatParamsResponsesGap(cr.Params); gap != nil {
		return gap
	}
	for i := range cr.Input {
		if gap := chatMessageResponsesGap(&cr.Input[i], "messages["+strconv.Itoa(i)+"]"); gap != nil {
			return gap
		}
	}
	return nil
}

func chatParamsResponsesGap(p *ChatParameters) *ConversionGap {
	if p == nil {
		return nil
	}
	switch {
	case p.Audio != nil:
		return &ConversionGap{"audio", "audio output"}
	case p.LogitBias != nil && len(*p.LogitBias) > 0:
		return &ConversionGap{"logit_bias", "logit biases"}
	case p.N != nil && *p.N > 1:
		return &ConversionGap{"n", "several choices"}
	case p.Prediction != nil:
		return &ConversionGap{"prediction", "predicted outputs"}
	case p.Seed != nil:
		return &ConversionGap{"seed", "seeds"}
	case len(p.Stop) > 0:
		return &ConversionGap{"stop", "stop sequences"}
	case p.WebSearchOptions != nil:
		return &ConversionGap{"web_search_options", "web search options"}
	case p.TopK != nil:
		return &ConversionGap{"top_k", "top_k sampling"}
	case p.Speed != nil:
		return &ConversionGap{"speed", "the speed setting"}
	case p.InferenceGeo != nil:
		return &ConversionGap{"inference_geo", "the inference_geo setting"}
	case len(p.MCPServers) > 0:
		return &ConversionGap{"mcp_servers", "MCP servers"}
	case p.Container != nil:
		return &ConversionGap{"container", "containers"}
	case p.CacheControl != nil:
		return &ConversionGap{"cache_control", "request cache control"}
	case p.TaskBudget != nil:
		return &ConversionGap{"task_budget", "task budgets"}
	}
	for i, modality := range p.Modalities {
		if modality != "text" {
			return &ConversionGap{"modalities[" + strconv.Itoa(i) + "]", modality + " output"}
		}
	}
	if r := p.Reasoning; r != nil {
		// Responses has no switch for reasoning: an effort turns it on or off.
		if r.Enabled != nil {
			return &ConversionGap{"reasoning.enabled", "a reasoning on/off switch"}
		}
		if r.Display != nil {
			return &ConversionGap{"reasoning.display", "the reasoning display setting"}
		}
	}
	if p.ResponseFormat != nil && *p.ResponseFormat != nil {
		format, ok := ParseChatResponseFormat(p.ResponseFormat)
		switch {
		case !ok:
			return &ConversionGap{"response_format", "a response format without a type"}
		case format.Type != "text" && format.Type != "json_object" && format.Type != "json_schema":
			return &ConversionGap{"response_format.type", "the " + format.Type + " response format"}
		case ResponsesTextConfigFormatFromChatResponseFormat(p.ResponseFormat) == nil:
			return &ConversionGap{"response_format.json_schema", "a JSON schema format without its json_schema object"}
		}
	}
	// Chat Completions tool calls name only functions.
	for i := range p.Tools {
		if tool := &p.Tools[i]; tool.Type != ChatToolTypeFunction {
			return &ConversionGap{"tools[" + strconv.Itoa(i) + "].type", string(tool.Type) + " tools"}
		}
	}
	if choice := p.ToolChoice; choice != nil && choice.ChatToolChoiceStruct != nil {
		switch c := choice.ChatToolChoiceStruct; c.Type {
		case ChatToolChoiceTypeNone, ChatToolChoiceTypeAuto, ChatToolChoiceTypeAny, ChatToolChoiceTypeRequired,
			ChatToolChoiceTypeFunction:
		case ChatToolChoiceTypeAllowedTools:
			if c.AllowedTools != nil {
				for i, tool := range c.AllowedTools.Tools {
					if tool.Type != string(ChatToolTypeFunction) {
						return &ConversionGap{"tool_choice.allowed_tools.tools[" + strconv.Itoa(i) + "].type", tool.Type + " tools"}
					}
				}
			}
		default:
			return &ConversionGap{"tool_choice.type", string(c.Type) + " tools"}
		}
	}
	return nil
}

func chatMessageResponsesGap(message *ChatMessage, path string) *ConversionGap {
	if message.Name != nil {
		return &ConversionGap{path + ".name", "message names"}
	}
	switch message.Role {
	case ChatMessageRoleSystem, ChatMessageRoleDeveloper, ChatMessageRoleUser:
		return chatContentResponsesGap(message.Content, path+".content", inputParts)
	case ChatMessageRoleTool:
		return chatContentResponsesGap(message.Content, path+".content", toolParts)
	case ChatMessageRoleAssistant:
		if gap := chatContentResponsesGap(message.Content, path+".content", assistantParts); gap != nil {
			return gap
		}
		return chatAssistantResponsesGap(message, path)
	}
	return &ConversionGap{path + ".role", string(message.Role) + " messages"}
}

func chatAssistantResponsesGap(message *ChatMessage, path string) *ConversionGap {
	assistant := message.ChatAssistantMessage
	if assistant == nil {
		return nil
	}
	switch {
	case assistant.Audio != nil:
		return &ConversionGap{path + ".audio", "audio replies"}
	case len(assistant.Images) > 0:
		return &ConversionGap{path + ".images", "image replies"}
	}
	for k, detail := range assistant.ReasoningDetails {
		switch detail.Type {
		case BifrostReasoningDetailsTypeText, BifrostReasoningDetailsTypeSummary, BifrostReasoningDetailsTypeEncrypted:
		default:
			return &ConversionGap{path + ".reasoning_details[" + strconv.Itoa(k) + "].type", string(detail.Type) + " reasoning details"}
		}
	}
	if len(assistant.Annotations) > 0 {
		if _, misplaced := placeCitations(assistantTexts(message.Content), assistant.Annotations); misplaced >= 0 {
			return &ConversionGap{path + ".annotations[" + strconv.Itoa(misplaced) + "]", "citations that no single text part holds"}
		}
	}
	for k, call := range assistant.ToolCalls {
		callPath := path + ".tool_calls[" + strconv.Itoa(k) + "]"
		switch {
		case call.Type != nil && *call.Type != string(ChatToolTypeFunction):
			return &ConversionGap{callPath + ".type", *call.Type + " tool calls"}
		case len(call.ExtraContent) > 0:
			return &ConversionGap{callPath + ".extra_content", "extra content on tool calls"}
		}
	}
	return nil
}

func chatContentResponsesGap(content *ChatMessageContent, path string, place partPlace) *ConversionGap {
	if content == nil {
		return nil
	}
	for j := range content.ContentBlocks {
		block := &content.ContentBlocks[j]
		blockPath := path + "[" + strconv.Itoa(j) + "]"
		if block.CachePoint != nil {
			return &ConversionGap{blockPath + ".cachePoint", "cache points"}
		}
		switch block.Type {
		case ChatContentBlockTypeText:
			continue
		case ChatContentBlockTypeRefusal:
			if place == assistantParts {
				continue
			}
		case ChatContentBlockTypeImage, ChatContentBlockTypeFile, ChatContentBlockTypeInputAudio:
			if place != assistantParts {
				continue
			}
		}
		return &ConversionGap{blockPath + ".type", string(block.Type) + " parts in " + string(place)}
	}
	return nil
}

// ToResponsesRequest converts the request to Responses. It carries every part that ResponsesGap
// accepts, and leaves out the parts that it reports.
func (cr *BifrostChatRequest) ToResponsesRequest() *BifrostResponsesRequest {
	if cr == nil {
		return &BifrostResponsesRequest{}
	}
	brr := &BifrostResponsesRequest{
		Provider:  cr.Provider,
		Model:     cr.Model,
		Fallbacks: cr.Fallbacks,
		Params:    cr.Params.toResponsesParameters(),
	}
	for i := range cr.Input {
		brr.Input = append(brr.Input, cr.Input[i].ToResponsesMessages()...)
	}
	return brr
}

func (p *ChatParameters) toResponsesParameters() *ResponsesParameters {
	// Responses stores a response unless the request says otherwise, and Chat Completions stores a
	// completion only on request.
	params := &ResponsesParameters{Store: Ptr(false)}
	if p == nil {
		return params
	}
	params.ContextManagement = p.ContextManagement
	params.ExtraParams = p.ExtraParams
	params.FrequencyPenalty = p.FrequencyPenalty
	params.IncludeServerSideToolInvocations = p.IncludeServerSideToolInvocations
	params.MaxOutputTokens = p.MaxCompletionTokens
	params.Metadata = p.Metadata
	params.ParallelToolCalls = p.ParallelToolCalls
	params.PresencePenalty = p.PresencePenalty
	params.PromptCacheKey = p.PromptCacheKey
	params.PromptCacheOptions = p.PromptCacheOptions
	params.PromptCacheRetention = p.PromptCacheRetention
	params.SafetyIdentifier = p.SafetyIdentifier
	params.ServiceTier = p.ServiceTier
	params.Temperature = p.Temperature
	params.TopLogProbs = p.TopLogProbs
	params.TopP = p.TopP
	params.User = p.User
	if p.Store != nil {
		params.Store = p.Store
	}
	// Responses returns log probabilities only when include asks for them.
	if p.LogProbs != nil && *p.LogProbs {
		params.Include = []string{responsesIncludeLogProbs}
	}
	// A Responses stream always ends with the usage, which a Chat Completions stream gives only on
	// request, so only obfuscation remains to ask for.
	if p.StreamOptions != nil && p.StreamOptions.IncludeObfuscation != nil {
		params.StreamOptions = &ResponsesStreamOptions{IncludeObfuscation: p.StreamOptions.IncludeObfuscation}
	}
	if r := p.Reasoning; r != nil && (r.Effort != nil || r.MaxTokens != nil || r.Summary != nil || r.Mode != nil || r.Type != nil) {
		params.Reasoning = &ResponsesParametersReasoning{Effort: r.Effort, MaxTokens: r.MaxTokens, Summary: r.Summary, Mode: r.Mode, Type: r.Type}
	}
	if format := ResponsesTextConfigFormatFromChatResponseFormat(p.ResponseFormat); format != nil || p.Verbosity != nil {
		params.Text = &ResponsesTextConfig{Format: format, Verbosity: p.Verbosity}
	}
	for i := range p.Tools {
		params.Tools = append(params.Tools, *p.Tools[i].ToResponsesTool())
	}
	params.ToolChoice = responsesToolChoice(p.ToolChoice)
	return params
}

// responsesToolChoice converts a tool choice. A mode in the form of a struct is the mode itself, and
// Responses calls Anthropic's any mode required.
func responsesToolChoice(choice *ChatToolChoice) *ResponsesToolChoice {
	if choice == nil {
		return nil
	}
	if choice.ChatToolChoiceStr != nil {
		return &ResponsesToolChoice{ResponsesToolChoiceStr: choice.ChatToolChoiceStr}
	}
	c := choice.ChatToolChoiceStruct
	if c == nil {
		return nil
	}
	switch c.Type {
	case ChatToolChoiceTypeNone, ChatToolChoiceTypeAuto, ChatToolChoiceTypeRequired:
		return &ResponsesToolChoice{ResponsesToolChoiceStr: Ptr(string(c.Type))}
	case ChatToolChoiceTypeAny:
		return &ResponsesToolChoice{ResponsesToolChoiceStr: Ptr(string(ChatToolChoiceTypeRequired))}
	case ChatToolChoiceTypeFunction:
		if c.Function == nil {
			return nil
		}
		return &ResponsesToolChoice{ResponsesToolChoiceStruct: &ResponsesToolChoiceStruct{
			Type: ResponsesToolChoiceTypeFunction, Name: Ptr(c.Function.Name),
		}}
	case ChatToolChoiceTypeAllowedTools:
		allowed := &ResponsesToolChoiceStruct{Type: ResponsesToolChoiceTypeAllowedTools, Tools: []ResponsesToolChoiceAllowedToolDef{}}
		if c.AllowedTools != nil {
			if c.AllowedTools.Mode != "" {
				allowed.Mode = Ptr(c.AllowedTools.Mode)
			}
			for _, tool := range c.AllowedTools.Tools {
				allowed.Tools = append(allowed.Tools, ResponsesToolChoiceAllowedToolDef{Type: tool.Type, Name: Ptr(tool.Function.Name)})
			}
		}
		return &ResponsesToolChoice{ResponsesToolChoiceStruct: allowed}
	}
	return nil
}

// ToResponsesMessages converts a Chat Completions message to the Responses items that carry it: a
// user, system or developer message to a message, a tool message to a function call's output, and
// an assistant message to its reasoning, then a message with its text and refusal, then a function
// call for each tool call, the order in which a Responses reply gives them. The items take no IDs
// or statuses, which describe a reply, except the IDs of reasoning, which OpenAI pairs with its
// encrypted content, and the incomplete status that marks the output of a tool that failed, as
// Bifrost's Responses conversions read it. Each part that ResponsesGap reports stays out.
func (cm *ChatMessage) ToResponsesMessages() []ResponsesMessage {
	if cm == nil {
		return nil
	}
	switch cm.Role {
	case ChatMessageRoleAssistant:
		return responsesAssistantItems(cm)
	case ChatMessageRoleTool:
		return []ResponsesMessage{responsesToolOutput(cm)}
	}
	return []ResponsesMessage{responsesInputMessage(cm)}
}

func responsesInputMessage(cm *ChatMessage) ResponsesMessage {
	role := ResponsesInputMessageRoleUser
	switch cm.Role {
	case ChatMessageRoleSystem:
		role = ResponsesInputMessageRoleSystem
	case ChatMessageRoleDeveloper:
		role = ResponsesInputMessageRoleDeveloper
	}
	item := ResponsesMessage{Type: Ptr(ResponsesMessageTypeMessage), Role: Ptr(role)}
	switch content := cm.Content; {
	case content == nil:
	case content.ContentStr != nil:
		item.Content = &ResponsesMessageContent{ContentStr: content.ContentStr}
	default:
		item.Content = &ResponsesMessageContent{ContentBlocks: responsesInputBlocks(content.ContentBlocks)}
	}
	return item
}

// responsesInputBlocks converts the parts of an input message or of a tool's output.
func responsesInputBlocks(blocks []ChatContentBlock) []ResponsesMessageContentBlock {
	converted := make([]ResponsesMessageContentBlock, 0, len(blocks))
	for _, block := range blocks {
		part := ResponsesMessageContentBlock{
			Text:                  block.Text,
			CacheControl:          block.CacheControl,
			Citations:             block.Citations,
			PromptCacheBreakpoint: block.PromptCacheBreakpoint,
			GuardContent:          block.GuardContent,
		}
		switch block.Type {
		case ChatContentBlockTypeText:
			part.Type = ResponsesInputMessageContentBlockTypeText
		case ChatContentBlockTypeImage:
			part.Type = ResponsesInputMessageContentBlockTypeImage
			if image := block.ImageURLStruct; image != nil {
				part.FileID = image.FileID
				part.ResponsesInputMessageContentBlockImage = &ResponsesInputMessageContentBlockImage{Detail: image.Detail}
				if image.URL != "" {
					part.ResponsesInputMessageContentBlockImage.ImageURL = Ptr(image.URL)
				}
			}
		case ChatContentBlockTypeFile:
			part.Type = ResponsesInputMessageContentBlockTypeFile
			if file := block.File; file != nil {
				part.FileID = file.FileID
				part.ResponsesInputMessageContentBlockFile = &ResponsesInputMessageContentBlockFile{
					FileData: file.FileData, FileURL: file.FileURL, Filename: file.Filename, FileType: file.FileType,
				}
			}
		case ChatContentBlockTypeInputAudio:
			part.Type = ResponsesInputMessageContentBlockTypeAudio
			if audio := block.InputAudio; audio != nil {
				part.Audio = &ResponsesInputMessageContentBlockAudio{Data: audio.Data}
				if audio.Format != nil {
					part.Audio.Format = *audio.Format
				}
			}
		default:
			continue
		}
		converted = append(converted, part)
	}
	return converted
}

// responsesToolOutput converts a tool's output. Responses requires the output, so a message without
// content outputs empty text.
func responsesToolOutput(cm *ChatMessage) ResponsesMessage {
	tool := &ResponsesToolMessage{Output: &ResponsesToolMessageOutputStruct{}}
	item := ResponsesMessage{Type: Ptr(ResponsesMessageTypeFunctionCallOutput), ResponsesToolMessage: tool}
	switch content := cm.Content; {
	case content != nil && content.ContentStr != nil:
		tool.Output.ResponsesToolCallOutputStr = content.ContentStr
	case content != nil && len(content.ContentBlocks) > 0:
		tool.Output.ResponsesFunctionToolCallOutputBlocks = responsesInputBlocks(content.ContentBlocks)
	default:
		tool.Output.ResponsesToolCallOutputStr = Ptr("")
	}
	if message := cm.ChatToolMessage; message != nil {
		tool.CallID = message.ToolCallID
		if message.IsError != nil && *message.IsError {
			item.Status = Ptr(ResponsesResponseStatusIncomplete)
		}
	}
	return item
}

// responsesAssistantItems converts an assistant message. An assistant message without content
// still takes its turn, as a message with empty text.
func responsesAssistantItems(cm *ChatMessage) []ResponsesMessage {
	assistant := cm.ChatAssistantMessage
	if assistant == nil {
		assistant = &ChatAssistantMessage{}
	}
	items := responsesReasoningItems(assistant)
	if parts := responsesAssistantParts(cm.Content, assistant); len(parts) > 0 {
		items = append(items, ResponsesMessage{
			Type:    Ptr(ResponsesMessageTypeMessage),
			Role:    Ptr(ResponsesInputMessageRoleAssistant),
			Content: &ResponsesMessageContent{ContentBlocks: parts},
		})
	}
	for _, call := range assistant.ToolCalls {
		items = append(items, ResponsesMessage{
			Type:         Ptr(ResponsesMessageTypeFunctionCall),
			CacheControl: call.CacheControl,
			ResponsesToolMessage: &ResponsesToolMessage{
				CallID: call.ID, Name: call.Function.Name, Arguments: Ptr(call.Function.Arguments),
			},
		})
	}
	if len(items) == 0 {
		items = append(items, ResponsesMessage{
			Type:    Ptr(ResponsesMessageTypeMessage),
			Role:    Ptr(ResponsesInputMessageRoleAssistant),
			Content: &ResponsesMessageContent{ContentStr: Ptr("")},
		})
	}
	return items
}

// responsesReasoningItems converts an assistant message's reasoning. Its details give one item for
// each run of details that one item holds, as OpenAI pairs encrypted reasoning with the ID of its
// item: a detail with another ID than its item's starts the next item, as does any detail after
// encrypted content, which ends its item, and an item without an ID takes the first that its details
// name. The reasoning field repeats the visible text of the details, and without details it is
// plain reasoning text.
func responsesReasoningItems(assistant *ChatAssistantMessage) []ResponsesMessage {
	newItem := func() ResponsesMessage {
		return ResponsesMessage{
			Type:               Ptr(ResponsesMessageTypeReasoning),
			ResponsesReasoning: &ResponsesReasoning{Summary: []ResponsesReasoningSummary{}},
		}
	}
	if len(assistant.ReasoningDetails) == 0 {
		if assistant.Reasoning == nil || *assistant.Reasoning == "" {
			return nil
		}
		item := newItem()
		item.Content = &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{{
			Type: ResponsesOutputMessageContentTypeReasoning, Text: assistant.Reasoning,
		}}}
		return []ResponsesMessage{item}
	}
	var items []ResponsesMessage
	for _, detail := range assistant.ReasoningDetails {
		named := detail.ID != nil && *detail.ID != ""
		last := len(items) - 1
		if last < 0 || items[last].ResponsesReasoning.EncryptedContent != nil ||
			(named && items[last].ID != nil && *items[last].ID != *detail.ID) {
			items = append(items, newItem())
			last++
		}
		item := &items[last]
		if named && item.ID == nil {
			item.ID = detail.ID
		}
		switch detail.Type {
		case BifrostReasoningDetailsTypeText:
			if item.Content == nil {
				item.Content = &ResponsesMessageContent{}
			}
			item.Content.ContentBlocks = append(item.Content.ContentBlocks, ResponsesMessageContentBlock{
				Type: ResponsesOutputMessageContentTypeReasoning, Text: detail.Text, Signature: detail.Signature,
			})
		case BifrostReasoningDetailsTypeSummary:
			if detail.Summary != nil {
				item.ResponsesReasoning.Summary = append(item.ResponsesReasoning.Summary, ResponsesReasoningSummary{
					Type: ResponsesReasoningContentBlockTypeSummaryText, Text: *detail.Summary,
				})
			}
		case BifrostReasoningDetailsTypeEncrypted:
			item.ResponsesReasoning.EncryptedContent = detail.Data
		}
	}
	return items
}

// responsesAssistantParts converts an assistant message's text and refusal to the parts of a
// message, leaving out text that is an empty string, which clients send with tool calls.
func responsesAssistantParts(content *ChatMessageContent, assistant *ChatAssistantMessage) []ResponsesMessageContentBlock {
	var parts []ResponsesMessageContentBlock
	if content != nil {
		if content.ContentStr != nil && *content.ContentStr != "" {
			parts = append(parts, outputTextPart(ChatContentBlock{Text: content.ContentStr}))
		}
		for _, block := range content.ContentBlocks {
			switch block.Type {
			case ChatContentBlockTypeText:
				parts = append(parts, outputTextPart(block))
			case ChatContentBlockTypeRefusal:
				if block.Refusal != nil {
					parts = append(parts, refusalPart(*block.Refusal))
				}
			}
		}
	}
	if assistant.Refusal != nil {
		parts = append(parts, refusalPart(*assistant.Refusal))
	}
	if len(assistant.Annotations) == 0 {
		return parts
	}
	placed, _ := placeCitations(assistantTexts(content), assistant.Annotations)
	text := 0
	for i := range parts {
		if parts[i].Type == ResponsesOutputMessageContentTypeText {
			parts[i].ResponsesOutputMessageContentText.Annotations = placed[text]
			text++
		}
	}
	return parts
}

func outputTextPart(block ChatContentBlock) ResponsesMessageContentBlock {
	return ResponsesMessageContentBlock{
		Type:                  ResponsesOutputMessageContentTypeText,
		Text:                  block.Text,
		CacheControl:          block.CacheControl,
		Citations:             block.Citations,
		PromptCacheBreakpoint: block.PromptCacheBreakpoint,
		GuardContent:          block.GuardContent,
		ResponsesOutputMessageContentText: &ResponsesOutputMessageContentText{
			Annotations: []ResponsesOutputMessageContentTextAnnotation{},
			LogProbs:    []ResponsesOutputMessageContentTextLogProb{},
		},
	}
}

func refusalPart(refusal string) ResponsesMessageContentBlock {
	return ResponsesMessageContentBlock{
		Type:                                 ResponsesOutputMessageContentTypeRefusal,
		ResponsesOutputMessageContentRefusal: &ResponsesOutputMessageContentRefusal{Refusal: refusal},
	}
}

// assistantTexts are the texts of an assistant message's text parts, as responsesAssistantParts
// makes them.
func assistantTexts(content *ChatMessageContent) []string {
	var texts []string
	if content == nil {
		return nil
	}
	if content.ContentStr != nil && *content.ContentStr != "" {
		texts = append(texts, *content.ContentStr)
	}
	for _, block := range content.ContentBlocks {
		if block.Type == ChatContentBlockTypeText {
			text := ""
			if block.Text != nil {
				text = *block.Text
			}
			texts = append(texts, text)
		}
	}
	return texts
}

// placeCitations places a message's citations on its text parts, whose texts are texts. A citation
// indexes the message's whole text in runes. With one part, every citation goes to it. With several,
// each goes to the part that holds it, with its indexes counted from that part's start. misplaced is
// the first citation that no single part holds, or -1.
func placeCitations(texts []string, annotations []ChatAssistantMessageAnnotation) (placed [][]ResponsesOutputMessageContentTextAnnotation, misplaced int) {
	placed = make([][]ResponsesOutputMessageContentTextAnnotation, len(texts))
	if len(texts) == 1 {
		placed[0] = responsesAnnotations(annotations)
		return placed, -1
	}
	starts := make([]int, len(texts)+1)
	for i, text := range texts {
		starts[i+1] = starts[i] + utf8.RuneCountInString(text)
	}
	for k, annotation := range annotations {
		citation := annotation.URLCitation
		part := -1
		for i := range texts {
			if citation.StartIndex >= starts[i] && citation.EndIndex <= starts[i+1] {
				part = i
				break
			}
		}
		if part < 0 {
			return nil, k
		}
		annotation.URLCitation.StartIndex -= starts[part]
		annotation.URLCitation.EndIndex -= starts[part]
		placed[part] = append(placed[part], responsesAnnotations([]ChatAssistantMessageAnnotation{annotation})...)
	}
	for i := range placed {
		if placed[i] == nil {
			placed[i] = []ResponsesOutputMessageContentTextAnnotation{}
		}
	}
	return placed, -1
}

// ToBifrostChatResponse converts a Responses reply to Chat Completions. Its one choice holds the
// reply's reasoning, the text and the refusal of its messages, each joined in order, and a tool call
// for each function call. The text takes the citations of its parts, with their indexes counted from
// the start of the whole text, and the log probabilities of its tokens. The IDs, statuses and phases
// of items stay out, as do items of other kinds, which a converted request never asks for.
func (r *BifrostResponsesResponse) ToBifrostChatResponse() *BifrostChatResponse {
	if r == nil {
		return nil
	}
	chat := &BifrostChatResponse{
		Created:       r.CreatedAt,
		Object:        "chat.completion",
		Model:         r.Model,
		ServiceTier:   r.ServiceTier,
		Speed:         r.Speed,
		InferenceGeo:  r.InferenceGeo,
		Diagnostics:   r.Diagnostics,
		StopDetails:   r.StopDetails,
		Citations:     r.Citations,
		SearchResults: r.SearchResults,
		Videos:        r.Videos,
		ExtraFields:   r.ExtraFields,
	}
	if r.ID != nil {
		chat.ID = *r.ID
	}
	chat.ExtraFields.RequestType = ChatCompletionRequest
	if r.Usage != nil {
		chat.Usage = r.Usage.ToBifrostLLMUsage()
	}
	var reply chatReplyParts
	for i := range r.Output {
		reply.add(&r.Output[i])
	}
	choice := BifrostResponseChoice{
		FinishReason:                chatFinishReason(r.Status, r.IncompleteDetails, r.StopReason, r.Output, len(reply.calls) > 0),
		ChatNonStreamResponseChoice: &ChatNonStreamResponseChoice{Message: reply.message()},
	}
	if len(reply.tokens) > 0 {
		choice.LogProbs = &BifrostLogProbs{Content: reply.tokens}
	}
	chat.Choices = []BifrostResponseChoice{choice}
	return chat
}

// chatReplyParts collects the items of a Responses reply into a Chat Completions message.
type chatReplyParts struct {
	text        strings.Builder
	textRunes   int
	texted      bool
	refusal     strings.Builder
	refused     bool
	annotations []ChatAssistantMessageAnnotation
	tokens      []ContentLogProb
	reasoning   strings.Builder
	details     []ChatReasoningDetails
	calls       []ChatAssistantMessageToolCall
}

func (c *chatReplyParts) add(item *ResponsesMessage) {
	switch responsesItemType(item) {
	case ResponsesMessageTypeMessage, ResponsesMessageTypeRefusal:
		if item.Content == nil {
			return
		}
		refusal := responsesItemType(item) == ResponsesMessageTypeRefusal
		if text := item.Content.ContentStr; text != nil {
			if refusal {
				c.refusal.WriteString(*text)
				c.refused = true
			} else {
				c.addText(*text, nil, nil)
			}
		}
		for _, block := range item.Content.ContentBlocks {
			switch block.Type {
			case ResponsesOutputMessageContentTypeText:
				text := ""
				if block.Text != nil {
					text = *block.Text
				}
				var annotations []ResponsesOutputMessageContentTextAnnotation
				var logProbs []ResponsesOutputMessageContentTextLogProb
				if output := block.ResponsesOutputMessageContentText; output != nil {
					annotations, logProbs = output.Annotations, output.LogProbs
				}
				c.addText(text, annotations, logProbs)
			case ResponsesOutputMessageContentTypeRefusal:
				if block.ResponsesOutputMessageContentRefusal != nil {
					c.refusal.WriteString(block.ResponsesOutputMessageContentRefusal.Refusal)
					c.refused = true
				}
			}
		}
	case ResponsesMessageTypeReasoning:
		c.details, _ = appendChatReasoning(&c.reasoning, c.details, item)
	case ResponsesMessageTypeFunctionCall:
		if call := item.ResponsesToolMessage; call != nil {
			arguments := ""
			if call.Arguments != nil {
				arguments = *call.Arguments
			}
			c.calls = append(c.calls, ChatAssistantMessageToolCall{
				Type:     Ptr(string(ChatToolTypeFunction)),
				ID:       call.CallID,
				Function: ChatAssistantMessageToolCallFunction{Name: call.Name, Arguments: arguments},
			})
		}
	}
}

// addText adds a text part with its citations, which only URL citations are in Chat Completions,
// and the log probabilities of its tokens.
func (c *chatReplyParts) addText(text string, annotations []ResponsesOutputMessageContentTextAnnotation, logProbs []ResponsesOutputMessageContentTextLogProb) {
	c.texted = true
	for _, annotation := range annotations {
		if annotation.Type == "url_citation" {
			c.annotations = append(c.annotations, chatAnnotation(annotation, c.textRunes))
		}
	}
	c.tokens = append(c.tokens, chatLogProbs(logProbs)...)
	c.text.WriteString(text)
	c.textRunes += utf8.RuneCountInString(text)
}

// message is the reply's assistant message. Chat Completions gives no content with only a refusal or
// tool calls, and empty text for a reply without output.
func (c *chatReplyParts) message() *ChatMessage {
	assistant := &ChatAssistantMessage{Annotations: c.annotations, ReasoningDetails: c.details, ToolCalls: c.calls}
	if c.reasoning.Len() > 0 {
		assistant.Reasoning = Ptr(c.reasoning.String())
	}
	if c.refused {
		assistant.Refusal = Ptr(c.refusal.String())
	}
	message := &ChatMessage{Role: ChatMessageRoleAssistant, ChatAssistantMessage: assistant}
	if c.texted || (!c.refused && len(c.calls) == 0) {
		message.Content = &ChatMessageContent{ContentStr: Ptr(c.text.String())}
	}
	return message
}

// chatAnnotation converts a URL citation of a text that starts offset runes into the message's text.
func chatAnnotation(annotation ResponsesOutputMessageContentTextAnnotation, offset int) ChatAssistantMessageAnnotation {
	citation := ChatAssistantMessageAnnotationCitation{URL: annotation.URL, Text: annotation.Text}
	if annotation.StartIndex != nil {
		citation.StartIndex = *annotation.StartIndex + offset
	}
	if annotation.EndIndex != nil {
		citation.EndIndex = *annotation.EndIndex + offset
	}
	if annotation.Title != nil {
		citation.Title = *annotation.Title
	}
	return ChatAssistantMessageAnnotation{Type: annotation.Type, URLCitation: citation}
}

func chatLogProbs(logProbs []ResponsesOutputMessageContentTextLogProb) []ContentLogProb {
	converted := make([]ContentLogProb, 0, len(logProbs))
	for _, token := range logProbs {
		converted = append(converted, ContentLogProb{Bytes: token.Bytes, LogProb: token.LogProb, Token: token.Token, TopLogProbs: token.TopLogProbs})
	}
	return converted
}

// chatFinishReason is the finish reason of a reply: tool_calls for a completed reply that calls
// tools, as Chat Completions name it, and the reason that ends any other. A reply cut short for a
// reason that Chat Completions has no name for ends for length. It is nil for a reply that did not
// end, or that failed.
func chatFinishReason(status *string, incomplete *ResponsesResponseIncompleteDetails, stopReason *string, output []ResponsesMessage, calls bool) *string {
	reason := chatFinishReasonFromResponses(status, incomplete, stopReason, output)
	switch {
	case reason == nil && status != nil && *status == ResponsesResponseStatusIncomplete:
		return Ptr(string(BifrostFinishReasonLength))
	case reason != nil && *reason == string(BifrostFinishReasonStop) && calls:
		return Ptr(string(BifrostFinishReasonToolCalls))
	}
	return reason
}

// ResponsesToChatStreamState converts the events of a Responses stream into Chat Completions chunks,
// one for each event, as Bifrost's stream hooks take one chunk for each that the provider gives. An
// event that adds nothing that a chunk carries, such as one that opens a part, gives a chunk with an
// empty delta. The chunks carry the reply that ToBifrostChatResponse gives: the role in the first,
// then reasoning, text and refusals as they come, a tool call for each function call, numbered in
// order, and the finish reason and the usage in the chunk of the event that ends the response. A
// done event sends what the deltas before it left out, for providers that send a value whole. The
// zero value is ready for a new stream.
type ResponsesToChatStreamState struct {
	id           string
	model        string
	created      int
	serviceTier  *BifrostServiceTier
	speed        *string
	inferenceGeo *string
	started      bool
	// parts holds what each part of the output has sent.
	parts map[streamPartKey]*streamPart
	// calls are the tool call indexes of the function calls, by output index.
	calls map[int]uint16
	// details counts the reasoning details that the stream has numbered, and encrypted marks the
	// reasoning items whose encrypted content it sent.
	details   int
	encrypted map[int]bool
	// textRunes counts the runes of the text sent, from which citations count their indexes.
	textRunes int
}

// streamPartKind is the kind of a part of a stream's output.
type streamPartKind uint8

const (
	streamText streamPartKind = iota
	streamRefusal
	streamReasoning
	streamSummary
	streamArguments
)

// streamPartKey names a part by its item's output index, its kind and its index among the item's
// content or summary parts.
type streamPartKey struct {
	output int
	kind   streamPartKind
	index  int
}

// streamPart is what a part has sent: its value, the citations and log probabilities of a text and
// where the text starts in the message's text, and the reasoning detail of a reasoning text or a
// summary, with whether a reasoning text sent its signature.
type streamPart struct {
	value       strings.Builder
	annotations int
	logProbs    int
	start       int
	detail      int
	signed      bool
}

// ToBifrostChatResponse returns the Chat Completions chunk of a Responses stream event.
func (rsr *BifrostResponsesStreamResponse) ToBifrostChatResponse(state *ResponsesToChatStreamState) *BifrostChatResponse {
	if rsr == nil || state == nil {
		return nil
	}
	if state.parts == nil {
		state.parts = make(map[streamPartKey]*streamPart)
		state.calls = make(map[int]uint16)
		state.encrypted = make(map[int]bool)
	}
	if rsr.Response != nil {
		state.identify(rsr.Response)
	}
	delta := &ChatStreamResponseChoiceDelta{}
	choice := BifrostResponseChoice{ChatStreamResponseChoice: &ChatStreamResponseChoice{Delta: delta}}
	if !state.started {
		state.started = true
		delta.Role = Ptr(string(ChatMessageRoleAssistant))
	}
	output := 0
	if rsr.OutputIndex != nil {
		output = *rsr.OutputIndex
	}
	content := 0
	if rsr.ContentIndex != nil {
		content = *rsr.ContentIndex
	}
	summary := 0
	if rsr.SummaryIndex != nil {
		summary = *rsr.SummaryIndex
	}
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	switch rsr.Type {
	case ResponsesStreamResponseTypeOutputItemAdded, ResponsesStreamResponseTypeOutputItemDone:
		if rsr.Item != nil {
			state.item(output, rsr.Item, rsr.Type == ResponsesStreamResponseTypeOutputItemDone, delta, &choice)
		}
	case ResponsesStreamResponseTypeContentPartAdded, ResponsesStreamResponseTypeContentPartDone:
		if rsr.Part != nil {
			state.part(output, content, rsr.Part, rsr.ItemID, delta, &choice)
		}
	case ResponsesStreamResponseTypeOutputTextDelta:
		state.send(streamPartKey{output, streamText, content}, text(rsr.Delta), nil, delta)
		state.sendLogProbs(streamPartKey{output, streamText, content}, rsr.LogProbs, false, &choice)
	case ResponsesStreamResponseTypeOutputTextDone:
		state.sendRest(streamPartKey{output, streamText, content}, text(rsr.Text), nil, delta)
		state.sendLogProbs(streamPartKey{output, streamText, content}, rsr.LogProbs, true, &choice)
	case ResponsesStreamResponseTypeOutputTextAnnotationAdded:
		if rsr.Annotation != nil {
			index := -1
			if rsr.AnnotationIndex != nil {
				index = *rsr.AnnotationIndex
			}
			state.sendAnnotation(streamPartKey{output, streamText, content}, index, *rsr.Annotation, delta)
		}
	case ResponsesStreamResponseTypeRefusalDelta:
		state.send(streamPartKey{output, streamRefusal, content}, text(rsr.Delta), nil, delta)
	case ResponsesStreamResponseTypeRefusalDone:
		state.sendRest(streamPartKey{output, streamRefusal, content}, text(rsr.Refusal), nil, delta)
	case ResponsesStreamResponseTypeReasoningTextDelta:
		state.send(streamPartKey{output, streamReasoning, content}, text(rsr.Delta), rsr.ItemID, delta)
		if rsr.Signature != nil {
			state.sendSignature(streamPartKey{output, streamReasoning, content}, *rsr.Signature, rsr.ItemID, delta)
		}
	case ResponsesStreamResponseTypeReasoningTextDone:
		state.sendRest(streamPartKey{output, streamReasoning, content}, text(rsr.Text), rsr.ItemID, delta)
	case ResponsesStreamResponseTypeReasoningSummaryTextDelta:
		state.send(streamPartKey{output, streamSummary, summary}, text(rsr.Delta), rsr.ItemID, delta)
	case ResponsesStreamResponseTypeReasoningSummaryTextDone:
		state.sendRest(streamPartKey{output, streamSummary, summary}, text(rsr.Text), rsr.ItemID, delta)
	case ResponsesStreamResponseTypeReasoningSummaryPartAdded, ResponsesStreamResponseTypeReasoningSummaryPartDone:
		if rsr.Part != nil {
			state.sendRest(streamPartKey{output, streamSummary, summary}, text(rsr.Part.Text), rsr.ItemID, delta)
		}
	case ResponsesStreamResponseTypeFunctionCallArgumentsDelta:
		state.sendArguments(output, text(rsr.Delta), false, delta)
	case ResponsesStreamResponseTypeFunctionCallArgumentsDone:
		state.sendArguments(output, text(rsr.Arguments), true, delta)
	case ResponsesStreamResponseTypeCompleted, ResponsesStreamResponseTypeIncomplete:
		status := ResponsesResponseStatusCompleted
		if rsr.Type == ResponsesStreamResponseTypeIncomplete {
			status = ResponsesResponseStatusIncomplete
		}
		var incomplete *ResponsesResponseIncompleteDetails
		var stopReason *string
		var finalOutput []ResponsesMessage
		if response := rsr.Response; response != nil {
			incomplete, stopReason, finalOutput = response.IncompleteDetails, response.StopReason, response.Output
		}
		choice.FinishReason = chatFinishReason(&status, incomplete, stopReason, finalOutput, len(state.calls) > 0)
	}
	chunk := &BifrostChatResponse{
		ID:            state.id,
		Created:       state.created,
		Model:         state.model,
		Object:        "chat.completion.chunk",
		ServiceTier:   state.serviceTier,
		Speed:         state.speed,
		InferenceGeo:  state.inferenceGeo,
		Choices:       []BifrostResponseChoice{choice},
		ExtraFields:   rsr.ExtraFields,
		SearchResults: rsr.SearchResults,
		Videos:        rsr.Videos,
		Citations:     rsr.Citations,
	}
	chunk.ExtraFields.RequestType = ChatCompletionStreamRequest
	if choice.FinishReason != nil && rsr.Response != nil && rsr.Response.Usage != nil {
		chunk.Usage = rsr.Response.Usage.ToBifrostLLMUsage()
	}
	return chunk
}

// identify takes the stream's identity from a response that an event describes, which the events
// of its output lack.
func (s *ResponsesToChatStreamState) identify(response *BifrostResponsesResponse) {
	if response.ID != nil && *response.ID != "" {
		s.id = *response.ID
	}
	if response.Model != "" {
		s.model = response.Model
	}
	if response.CreatedAt != 0 {
		s.created = response.CreatedAt
	}
	if response.ServiceTier != nil {
		s.serviceTier = response.ServiceTier
	}
	if response.Speed != nil {
		s.speed = response.Speed
	}
	if response.InferenceGeo != nil {
		s.inferenceGeo = response.InferenceGeo
	}
}

// record returns what a part has sent, starting its record at its first event.
func (s *ResponsesToChatStreamState) record(key streamPartKey) *streamPart {
	part, ok := s.parts[key]
	if !ok {
		part = &streamPart{start: s.textRunes}
		if key.kind == streamReasoning || key.kind == streamSummary {
			part.detail = s.details
			s.details++
		}
		s.parts[key] = part
	}
	return part
}

// send adds text to a part and to the delta: a text to the content, a refusal to the refusal, a
// reasoning text to the reasoning and to its reasoning detail, and a summary to its reasoning
// detail. id names the reasoning item.
func (s *ResponsesToChatStreamState) send(key streamPartKey, text string, id *string, delta *ChatStreamResponseChoiceDelta) {
	if text == "" {
		return
	}
	part := s.record(key)
	part.value.WriteString(text)
	join := func(field **string) {
		if *field == nil {
			*field = Ptr(text)
			return
		}
		*field = Ptr(**field + text)
	}
	switch key.kind {
	case streamText:
		join(&delta.Content)
		s.textRunes += utf8.RuneCountInString(text)
	case streamRefusal:
		join(&delta.Refusal)
	case streamReasoning:
		join(&delta.Reasoning)
		delta.ReasoningDetails = append(delta.ReasoningDetails, ChatReasoningDetails{
			ID: id, Index: part.detail, Type: BifrostReasoningDetailsTypeText, Text: Ptr(text),
		})
	case streamSummary:
		delta.ReasoningDetails = append(delta.ReasoningDetails, ChatReasoningDetails{
			ID: id, Index: part.detail, Type: BifrostReasoningDetailsTypeSummary, Summary: Ptr(text),
		})
	}
}

// sendSignature sends the signature of a reasoning text on its reasoning detail, unless the stream
// sent it.
func (s *ResponsesToChatStreamState) sendSignature(key streamPartKey, signature string, id *string, delta *ChatStreamResponseChoiceDelta) {
	part := s.record(key)
	if part.signed {
		return
	}
	part.signed = true
	for i := range delta.ReasoningDetails {
		if detail := &delta.ReasoningDetails[i]; detail.Index == part.detail {
			detail.Signature = Ptr(signature)
			return
		}
	}
	delta.ReasoningDetails = append(delta.ReasoningDetails, ChatReasoningDetails{
		ID: id, Index: part.detail, Type: BifrostReasoningDetailsTypeText, Signature: Ptr(signature),
	})
}

// sendRest sends what a part's whole value adds to what the part has sent.
func (s *ResponsesToChatStreamState) sendRest(key streamPartKey, value string, id *string, delta *ChatStreamResponseChoiceDelta) {
	if rest, ok := strings.CutPrefix(value, s.record(key).value.String()); ok {
		s.send(key, rest, id, delta)
	}
}

// sendLogProbs sends the log probabilities of a text's tokens: those of a delta, or those of the
// whole text that its deltas left out.
func (s *ResponsesToChatStreamState) sendLogProbs(key streamPartKey, logProbs []ResponsesOutputMessageContentTextLogProb, whole bool, choice *BifrostResponseChoice) {
	part := s.record(key)
	if whole {
		if len(logProbs) <= part.logProbs {
			return
		}
		logProbs = logProbs[part.logProbs:]
	}
	if len(logProbs) == 0 {
		return
	}
	part.logProbs += len(logProbs)
	if choice.LogProbs == nil {
		choice.LogProbs = &BifrostLogProbs{}
	}
	choice.LogProbs.Content = append(choice.LogProbs.Content, chatLogProbs(logProbs)...)
}

// sendAnnotation sends a text's citation at index among the text's citations, or the next one for
// a negative index, unless the stream sent it. Only URL citations are in Chat Completions.
func (s *ResponsesToChatStreamState) sendAnnotation(key streamPartKey, index int, annotation ResponsesOutputMessageContentTextAnnotation, delta *ChatStreamResponseChoiceDelta) {
	part := s.record(key)
	if index < 0 {
		index = part.annotations
	}
	if index < part.annotations {
		return
	}
	part.annotations = index + 1
	if annotation.Type == "url_citation" {
		delta.Annotations = append(delta.Annotations, chatAnnotation(annotation, part.start))
	}
}

// sendArguments sends a function call's arguments: a delta, or what the whole arguments add to
// what the call has sent.
func (s *ResponsesToChatStreamState) sendArguments(output int, arguments string, whole bool, delta *ChatStreamResponseChoiceDelta) {
	key := streamPartKey{output, streamArguments, 0}
	part := s.record(key)
	if whole {
		rest, ok := strings.CutPrefix(arguments, part.value.String())
		if !ok {
			return
		}
		arguments = rest
	}
	if arguments == "" {
		return
	}
	part.value.WriteString(arguments)
	index, started := s.calls[output]
	if !started {
		index = uint16(len(s.calls))
		s.calls[output] = index
	}
	for i := range delta.ToolCalls {
		if delta.ToolCalls[i].Index == index {
			delta.ToolCalls[i].Function.Arguments += arguments
			return
		}
	}
	delta.ToolCalls = append(delta.ToolCalls, ChatAssistantMessageToolCall{Index: index, Function: ChatAssistantMessageToolCallFunction{Arguments: arguments}})
}

// item handles an item's added or done event: a function call's first event starts its tool call,
// and each event sends what the item holds that its deltas left out, with the encrypted content of
// reasoning when the item is done.
func (s *ResponsesToChatStreamState) item(output int, item *ResponsesMessage, done bool, delta *ChatStreamResponseChoiceDelta, choice *BifrostResponseChoice) {
	switch responsesItemType(item) {
	case ResponsesMessageTypeFunctionCall:
		call := item.ResponsesToolMessage
		if call == nil {
			return
		}
		if _, started := s.calls[output]; !started {
			index := uint16(len(s.calls))
			s.calls[output] = index
			delta.ToolCalls = append(delta.ToolCalls, ChatAssistantMessageToolCall{
				Index: index, Type: Ptr(string(ChatToolTypeFunction)), ID: call.CallID,
				Function: ChatAssistantMessageToolCallFunction{Name: call.Name},
			})
		}
		if call.Arguments != nil {
			s.sendArguments(output, *call.Arguments, true, delta)
		}
	case ResponsesMessageTypeMessage:
		if item.Content == nil {
			return
		}
		for j := range item.Content.ContentBlocks {
			s.part(output, j, &item.Content.ContentBlocks[j], item.ID, delta, choice)
		}
	case ResponsesMessageTypeReasoning:
		if item.Content != nil {
			for j := range item.Content.ContentBlocks {
				s.part(output, j, &item.Content.ContentBlocks[j], item.ID, delta, choice)
			}
		}
		reasoning := item.ResponsesReasoning
		if reasoning == nil {
			return
		}
		for j, summary := range reasoning.Summary {
			s.sendRest(streamPartKey{output, streamSummary, j}, summary.Text, item.ID, delta)
		}
		if done && reasoning.EncryptedContent != nil && !s.encrypted[output] {
			s.encrypted[output] = true
			delta.ReasoningDetails = append(delta.ReasoningDetails, ChatReasoningDetails{
				ID: item.ID, Index: s.details, Type: BifrostReasoningDetailsTypeEncrypted, Data: reasoning.EncryptedContent,
			})
			s.details++
		}
	}
}

// part sends what a content part holds that its deltas left out: its text with its citations and
// the log probabilities of its tokens, its refusal, or its reasoning text and signature.
func (s *ResponsesToChatStreamState) part(output, index int, block *ResponsesMessageContentBlock, id *string, delta *ChatStreamResponseChoiceDelta, choice *BifrostResponseChoice) {
	value := ""
	if block.Text != nil {
		value = *block.Text
	}
	switch block.Type {
	case ResponsesOutputMessageContentTypeText:
		key := streamPartKey{output, streamText, index}
		s.sendRest(key, value, nil, delta)
		if text := block.ResponsesOutputMessageContentText; text != nil {
			for i, annotation := range text.Annotations {
				s.sendAnnotation(key, i, annotation, delta)
			}
			s.sendLogProbs(key, text.LogProbs, true, choice)
		}
	case ResponsesOutputMessageContentTypeRefusal:
		if block.ResponsesOutputMessageContentRefusal != nil {
			s.sendRest(streamPartKey{output, streamRefusal, index}, block.ResponsesOutputMessageContentRefusal.Refusal, nil, delta)
		}
	case ResponsesOutputMessageContentTypeReasoning:
		s.sendRest(streamPartKey{output, streamReasoning, index}, value, id, delta)
		if block.Signature != nil {
			s.sendSignature(streamPartKey{output, streamReasoning, index}, *block.Signature, id, delta)
		}
	}
}
