package schemas

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file converts between the Responses and Chat Completions interfaces for the providers that
// serve one interface through the other. A conversion carries every part of a request or reply
// that the other interface can represent. ChatCompletionsGap names the first part of a Responses
// request that Chat Completions cannot represent, so that a caller can refuse the request instead
// of losing that part.

// responsesIncludeLogProbs is the include value that asks for the log probabilities of output
// text, which Chat Completions returns as logprobs.
const responsesIncludeLogProbs = "message.output_text.logprobs"

// responsesIncludeEncryptedReasoning is the include value that asks for reasoning in a form that
// the client can send back. Chat Completions gives reasoning as text, which the reply carries
// whole, or encrypted, which the reply carries as encrypted content, so a client that asks for
// it, as Codex always does, gets reasoning that it can send back either way.
const responsesIncludeEncryptedReasoning = "reasoning.encrypted_content"

// ConversionGap names a part of a request that the other interface cannot carry.
type ConversionGap struct {
	// Param is the part's path in the request body, such as "tools[2].type".
	Param string
	// Feature names what the part asks for, such as "web_search tools".
	Feature string
}

func (g *ConversionGap) Error() string {
	return g.Param + ": the conversion cannot carry " + g.Feature
}

// defaultToolNamespace is the namespace that holds top-level tools, as DefaultToolNamespace in
// providers/utils, which this package cannot import.
const defaultToolNamespace = "functions"

// ChatCompletionsGap returns the first part of the request that ToChatRequest cannot carry, in the
// order of the request's fields and then of its input, or nil when it carries the whole request.
// Chat Completions has no namespaces, so the caller flattens namespace tools into function tools
// before the conversion (UnwrapDefaultNamespaceTools and FlattenResponsesNamespaceTools in
// providers/utils), which renames each input call to a declared namespace tool. A namespace tool
// therefore counts by its tools, and a call in input by the tool that it names.
func (brr *BifrostResponsesRequest) ChatCompletionsGap() *ConversionGap {
	if brr == nil {
		return nil
	}
	if gap := responsesParamsChatGap(brr.Params); gap != nil {
		return gap
	}
	var tools []ResponsesTool
	if brr.Params != nil {
		tools = brr.Params.Tools
	}
	for i := range brr.Input {
		if gap := responsesItemChatGap(&brr.Input[i], "input["+strconv.Itoa(i)+"]", tools); gap != nil {
			return gap
		}
	}
	return nil
}

func responsesParamsChatGap(p *ResponsesParameters) *ConversionGap {
	if p == nil {
		return nil
	}
	switch {
	case p.Background != nil && *p.Background:
		return &ConversionGap{"background", "background mode"}
	case p.Conversation != nil:
		return &ConversionGap{"conversation", "stored conversations"}
	case p.PreviousResponseID != nil:
		return &ConversionGap{"previous_response_id", "stored responses"}
	case p.MaxToolCalls != nil:
		return &ConversionGap{"max_tool_calls", "a limit on tool calls"}
	case p.Truncation != nil && *p.Truncation != "disabled":
		return &ConversionGap{"truncation", "automatic truncation"}
	}
	for i, value := range p.Include {
		if value != responsesIncludeLogProbs && value != responsesIncludeEncryptedReasoning {
			return &ConversionGap{"include[" + strconv.Itoa(i) + "]", "the " + value + " output"}
		}
	}
	// Chat Completions returns the model's reasoning text, never a summary of it, so the reply
	// carries that text whatever summary the request asks for.
	if r := p.Reasoning; r != nil {
		if r.Context != nil && *r.Context != "auto" {
			return &ConversionGap{"reasoning.context", "the reasoning context setting"}
		}
	}
	for i := range p.Tools {
		path := "tools[" + strconv.Itoa(i) + "]"
		tool := &p.Tools[i]
		if tool.Type == ResponsesToolTypeNamespace && tool.ResponsesToolNamespace != nil {
			for j := range tool.ResponsesToolNamespace.Tools {
				if gap := responsesToolChatGap(&tool.ResponsesToolNamespace.Tools[j], path+".tools["+strconv.Itoa(j)+"]"); gap != nil {
					return gap
				}
			}
			continue
		}
		if gap := responsesToolChatGap(tool, path); gap != nil {
			return gap
		}
	}
	if choice := p.ToolChoice; choice != nil && choice.ResponsesToolChoiceStruct != nil {
		switch c := choice.ResponsesToolChoiceStruct; c.Type {
		case ResponsesToolChoiceTypeNone, ResponsesToolChoiceTypeAuto, ResponsesToolChoiceTypeAny,
			ResponsesToolChoiceTypeRequired, ResponsesToolChoiceTypeFunction:
		case ResponsesToolChoiceTypeAllowedTools:
			for i, tool := range c.Tools {
				if tool.Type != string(ResponsesToolTypeFunction) {
					return &ConversionGap{"tool_choice.tools[" + strconv.Itoa(i) + "].type", tool.Type + " tools"}
				}
			}
		default:
			return &ConversionGap{"tool_choice.type", string(c.Type) + " tools"}
		}
	}
	if format := p.Text.GetFormat(); format != nil {
		switch format.Type {
		case "text", "json_object", "json_schema":
		default:
			return &ConversionGap{"text.format.type", "the " + format.Type + " text format"}
		}
	}
	return nil
}

// responsesToolChatGap returns the part of a tool that a Chat Completions function cannot carry.
func responsesToolChatGap(tool *ResponsesTool, path string) *ConversionGap {
	switch {
	case tool.Type != ResponsesToolTypeFunction:
		return &ConversionGap{path + ".type", string(tool.Type) + " tools"}
	case tool.Async != nil && *tool.Async:
		return &ConversionGap{path + ".async", "async tools"}
	case tool.ResponsesToolFunction != nil && tool.ResponsesToolFunction.OutputSchema != nil:
		return &ConversionGap{path + ".output_schema", "function output schemas"}
	}
	return nil
}

// namespacedCallDeclared reports whether a call's namespace holds top-level tools or is a namespace
// in tools with a function of the call's name, which the flattening renames the call to.
func namespacedCallDeclared(tools []ResponsesTool, namespace string, name *string) bool {
	if namespace == "" || namespace == defaultToolNamespace {
		return true
	}
	for _, tool := range tools {
		if tool.Type != ResponsesToolTypeNamespace || tool.Name == nil || *tool.Name != namespace || tool.ResponsesToolNamespace == nil {
			continue
		}
		for _, member := range tool.ResponsesToolNamespace.Tools {
			if member.Type == ResponsesToolTypeFunction && member.Name != nil && name != nil && *member.Name == *name {
				return true
			}
		}
	}
	return false
}

func responsesItemChatGap(item *ResponsesMessage, path string, tools []ResponsesTool) *ConversionGap {
	switch kind := responsesItemType(item); kind {
	case ResponsesMessageTypeMessage, ResponsesMessageTypeRefusal:
		place := inputParts
		if kind == ResponsesMessageTypeRefusal || (item.Role != nil && *item.Role == ResponsesInputMessageRoleAssistant) {
			place = assistantParts
		}
		return responsesContentChatGap(item.Content, path+".content", place)
	case ResponsesMessageTypeReasoning:
		if item.Content == nil {
			return nil
		}
		for j, block := range item.Content.ContentBlocks {
			if block.Type != ResponsesOutputMessageContentTypeReasoning {
				return &ConversionGap{path + ".content[" + strconv.Itoa(j) + "].type", string(block.Type) + " parts in reasoning"}
			}
		}
	case ResponsesMessageTypeFunctionCall:
		if call := item.ResponsesToolMessage; call != nil {
			if call.Namespace != nil && !namespacedCallDeclared(tools, *call.Namespace, call.Name) {
				return &ConversionGap{path + ".namespace", "calls to namespace tools that tools does not list"}
			}
			if call.Async != nil && *call.Async {
				return &ConversionGap{path + ".async", "async tools"}
			}
		}
	case ResponsesMessageTypeFunctionCallOutput:
		if gap := responsesContentChatGap(item.Content, path+".content", toolParts); gap != nil {
			return gap
		}
		if call := item.ResponsesToolMessage; call != nil && call.Output != nil {
			for j := range call.Output.ResponsesFunctionToolCallOutputBlocks {
				if gap := responsesBlockChatGap(&call.Output.ResponsesFunctionToolCallOutputBlocks[j], path+".output["+strconv.Itoa(j)+"]", toolParts); gap != nil {
					return gap
				}
			}
		}
	default:
		return &ConversionGap{path + ".type", string(kind) + " items"}
	}
	return nil
}

// partPlace is where a content part sits, which decides the parts that the other interface takes.
type partPlace string

const (
	inputParts     partPlace = "input messages"
	assistantParts partPlace = "assistant messages"
	toolParts      partPlace = "tool outputs"
)

func responsesContentChatGap(content *ResponsesMessageContent, path string, place partPlace) *ConversionGap {
	if content == nil {
		return nil
	}
	for j := range content.ContentBlocks {
		if gap := responsesBlockChatGap(&content.ContentBlocks[j], path+"["+strconv.Itoa(j)+"]", place); gap != nil {
			return gap
		}
	}
	return nil
}

func responsesBlockChatGap(block *ResponsesMessageContentBlock, path string, place partPlace) *ConversionGap {
	if block.MediaResolution != nil {
		return &ConversionGap{path + ".media_resolution", "media resolution settings"}
	}
	switch block.Type {
	case ResponsesInputMessageContentBlockTypeText:
		return nil
	case ResponsesOutputMessageContentTypeText, ResponsesOutputMessageContentTypeRefusal:
		if place == assistantParts {
			return nil
		}
	case ResponsesInputMessageContentBlockTypeImage, ResponsesInputMessageContentBlockTypeFile,
		ResponsesInputMessageContentBlockTypeAudio:
		if place != assistantParts {
			return nil
		}
	}
	return &ConversionGap{path + ".type", string(block.Type) + " parts in " + string(place)}
}

func responsesItemType(item *ResponsesMessage) ResponsesMessageType {
	if item.Type == nil {
		return ResponsesMessageTypeMessage
	}
	return *item.Type
}

// ToChatRequest converts the request to Chat Completions. It carries every part that
// ChatCompletionsGap accepts once namespace tools are flattened, and leaves out the parts that it
// reports.
func (brr *BifrostResponsesRequest) ToChatRequest() *BifrostChatRequest {
	if brr == nil {
		return &BifrostChatRequest{}
	}
	bcr := &BifrostChatRequest{
		Provider:  brr.Provider,
		Model:     brr.Model,
		Fallbacks: brr.Fallbacks,
		Input:     ToChatMessages(brr.Input),
		Params:    brr.Params.toChatParameters(),
	}
	// Only OpenAI's Chat Completions know developer messages, and they treat system messages alike.
	for i := range bcr.Input {
		if bcr.Input[i].Role == ChatMessageRoleDeveloper {
			bcr.Input[i].Role = ChatMessageRoleSystem
		}
	}
	// OpenAI inserts instructions before the input, even when the input opens with a system turn.
	if brr.Params != nil && brr.Params.Instructions != nil && *brr.Params.Instructions != "" {
		bcr.Input = append([]ChatMessage{{
			Role:    ChatMessageRoleSystem,
			Content: &ChatMessageContent{ContentStr: brr.Params.Instructions},
		}}, bcr.Input...)
	}
	return bcr
}

func (p *ResponsesParameters) toChatParameters() *ChatParameters {
	if p == nil {
		return nil
	}
	params := &ChatParameters{
		ContextManagement:                p.ContextManagement,
		ExtraParams:                      p.ExtraParams,
		FrequencyPenalty:                 p.FrequencyPenalty,
		IncludeServerSideToolInvocations: p.IncludeServerSideToolInvocations,
		MaxCompletionTokens:              p.MaxOutputTokens,
		Metadata:                         p.Metadata,
		ParallelToolCalls:                p.ParallelToolCalls,
		PresencePenalty:                  p.PresencePenalty,
		PromptCacheKey:                   p.PromptCacheKey,
		PromptCacheOptions:               p.PromptCacheOptions,
		PromptCacheRetention:             p.PromptCacheRetention,
		SafetyIdentifier:                 p.SafetyIdentifier,
		ServiceTier:                      p.ServiceTier,
		Store:                            p.Store,
		Temperature:                      p.Temperature,
		TopP:                             p.TopP,
		User:                             p.User,
	}
	// Responses returns log probabilities only when include asks for them, and top_logprobs then
	// says how many alternatives each token lists.
	if slices.Contains(p.Include, responsesIncludeLogProbs) {
		params.LogProbs = Ptr(true)
		params.TopLogProbs = p.TopLogProbs
	}
	if p.StreamOptions != nil {
		// A Responses stream always ends with the usage, which a Chat Completions stream gives only
		// on request.
		params.StreamOptions = &ChatStreamOptions{IncludeObfuscation: p.StreamOptions.IncludeObfuscation, IncludeUsage: Ptr(true)}
	}
	if r := p.Reasoning; r != nil {
		summary := r.Summary
		if summary == nil {
			summary = r.GenerateSummary
		}
		if r.Effort != nil || r.MaxTokens != nil || r.Type != nil || r.Mode != nil || summary != nil {
			params.Reasoning = &ChatReasoning{Effort: r.Effort, MaxTokens: r.MaxTokens, Type: r.Type, Mode: r.Mode, Summary: summary}
		}
	}
	if p.Text != nil {
		// Plain text is the default of both interfaces.
		if format := p.Text.Format; format != nil && format.Type != "text" {
			params.ResponseFormat = ChatResponseFormatFromResponsesFormat(format)
		}
		params.Verbosity = p.Text.Verbosity
	}
	for i := range p.Tools {
		if tool := &p.Tools[i]; tool.Type == ResponsesToolTypeFunction && tool.Name != nil && strings.TrimSpace(*tool.Name) != "" {
			params.Tools = append(params.Tools, *tool.ToChatTool())
		}
	}
	params.ToolChoice = chatToolChoice(p.ToolChoice, params)
	return params
}

// chatToolChoice converts a tool choice for the tools in params. Few Chat Completions providers
// take allowed_tools, so params then keep only the allowed tools, and the choice becomes the
// choice's mode, which the model meets alike. A choice of a tool that params lack is left out.
func chatToolChoice(choice *ResponsesToolChoice, params *ChatParameters) *ChatToolChoice {
	if choice == nil || len(params.Tools) == 0 {
		return nil
	}
	if choice.ResponsesToolChoiceStr != nil {
		return &ChatToolChoice{ChatToolChoiceStr: choice.ResponsesToolChoiceStr}
	}
	c := choice.ResponsesToolChoiceStruct
	if c == nil {
		return nil
	}
	carried := func(name *string) bool {
		return name != nil && slices.ContainsFunc(params.Tools, func(tool ChatTool) bool { return tool.Function.Name == *name })
	}
	switch c.Type {
	case ResponsesToolChoiceTypeNone, ResponsesToolChoiceTypeAuto, ResponsesToolChoiceTypeRequired:
		return &ChatToolChoice{ChatToolChoiceStr: Ptr(string(c.Type))}
	case ResponsesToolChoiceTypeAny:
		return &ChatToolChoice{ChatToolChoiceStr: Ptr(string(ResponsesToolChoiceTypeRequired))}
	case ResponsesToolChoiceTypeFunction:
		if !carried(c.Name) {
			return nil
		}
		return &ChatToolChoice{ChatToolChoiceStruct: &ChatToolChoiceStruct{
			Type: ChatToolChoiceTypeFunction, Function: &ChatToolChoiceFunction{Name: *c.Name},
		}}
	case ResponsesToolChoiceTypeAllowedTools:
		var allowed []ChatTool
		for _, tool := range params.Tools {
			if slices.ContainsFunc(c.Tools, func(def ResponsesToolChoiceAllowedToolDef) bool {
				return def.Type == string(ResponsesToolTypeFunction) && def.Name != nil && *def.Name == tool.Function.Name
			}) {
				allowed = append(allowed, tool)
			}
		}
		params.Tools = allowed
		if len(allowed) == 0 {
			return nil
		}
		mode := string(ResponsesToolChoiceTypeAuto)
		if c.Mode != nil && *c.Mode != "" {
			mode = *c.Mode
		}
		return &ChatToolChoice{ChatToolChoiceStr: Ptr(mode)}
	}
	return nil
}

// ToChatMessages converts Responses input items to Chat Completions messages. The items of an
// assistant turn, which runs until the next item of another role, form one assistant message, as
// a Chat Completions reply holds its reasoning, text, refusal and tool calls in one message: the
// reasoning, the text and the refusal of the turn's items each join in order, and the calls keep
// their order. Item IDs, statuses, phases, annotations and log probabilities describe an earlier reply
// and stay out, as does each part that ChatCompletionsGap reports.
func ToChatMessages(rms []ResponsesMessage) []ChatMessage {
	messages := make([]ChatMessage, 0, len(rms))
	var turn *chatTurn
	end := func() {
		if turn != nil {
			messages = append(messages, turn.message())
			turn = nil
		}
	}
	join := func() *chatTurn {
		if turn == nil {
			turn = &chatTurn{}
		}
		return turn
	}
	for i := range rms {
		item := &rms[i]
		switch responsesItemType(item) {
		case ResponsesMessageTypeMessage:
			if item.Role != nil && *item.Role == ResponsesInputMessageRoleAssistant {
				join().addContent(item.Content, false)
				continue
			}
			end()
			if message, ok := chatInputMessage(item); ok {
				messages = append(messages, message)
			}
		case ResponsesMessageTypeRefusal:
			join().addContent(item.Content, true)
		case ResponsesMessageTypeReasoning:
			join().addReasoning(item)
		case ResponsesMessageTypeFunctionCall:
			if item.ResponsesToolMessage != nil {
				join().addCall(item)
			}
		case ResponsesMessageTypeFunctionCallOutput:
			end()
			messages = append(messages, chatToolMessage(item))
		}
	}
	end()
	return messages
}

// chatTurn collects the items of an assistant turn.
type chatTurn struct {
	texts     []ChatContentBlock
	refusal   strings.Builder
	refused   bool
	reasoning strings.Builder
	details   []ChatReasoningDetails
	// signed marks reasoning that only reasoning details carry: a signature, a summary or
	// encrypted content.
	signed bool
	calls  []ChatAssistantMessageToolCall
}

// addContent adds a message's content. The text of a refusal item is its refusal.
func (t *chatTurn) addContent(content *ResponsesMessageContent, refusal bool) {
	if content == nil {
		return
	}
	switch {
	case content.ContentStr != nil && refusal:
		t.refusal.WriteString(*content.ContentStr)
		t.refused = true
	case content.ContentStr != nil:
		t.texts = append(t.texts, ChatContentBlock{Type: ChatContentBlockTypeText, Text: content.ContentStr})
	}
	for _, block := range content.ContentBlocks {
		switch block.Type {
		case ResponsesOutputMessageContentTypeText, ResponsesInputMessageContentBlockTypeText:
			text := ""
			if block.Text != nil {
				text = *block.Text
			}
			t.texts = append(t.texts, ChatContentBlock{
				Type: ChatContentBlockTypeText, Text: &text,
				CacheControl: block.CacheControl, PromptCacheBreakpoint: block.PromptCacheBreakpoint,
			})
		case ResponsesOutputMessageContentTypeRefusal:
			if block.ResponsesOutputMessageContentRefusal != nil {
				t.refusal.WriteString(block.ResponsesOutputMessageContentRefusal.Refusal)
				t.refused = true
			}
		}
	}
}

func (t *chatTurn) addReasoning(item *ResponsesMessage) {
	var signed bool
	t.details, signed = appendChatReasoning(&t.reasoning, t.details, item)
	t.signed = t.signed || signed
}

// appendChatReasoning converts a reasoning item: its text parts to reasoning text, which it writes
// to text, and to text details with the signature that Claude models give them, its summaries to
// summary details, and its encrypted content to an encrypted detail, which it appends to details.
// signed reports whether the item holds what only details carry: a signature, a summary or
// encrypted content.
func appendChatReasoning(text *strings.Builder, details []ChatReasoningDetails, item *ResponsesMessage) ([]ChatReasoningDetails, bool) {
	signed := false
	if item.Content != nil {
		for _, block := range item.Content.ContentBlocks {
			if block.Type != ResponsesOutputMessageContentTypeReasoning || block.Text == nil {
				continue
			}
			text.WriteString(*block.Text)
			signed = signed || block.Signature != nil
			details = append(details, ChatReasoningDetails{
				ID: item.ID, Index: len(details), Type: BifrostReasoningDetailsTypeText,
				Text: block.Text, Signature: block.Signature,
			})
		}
	}
	if item.ResponsesReasoning == nil {
		return details, signed
	}
	for _, summary := range item.ResponsesReasoning.Summary {
		signed = true
		details = append(details, ChatReasoningDetails{
			ID: item.ID, Index: len(details), Type: BifrostReasoningDetailsTypeSummary, Summary: Ptr(summary.Text),
		})
	}
	if item.ResponsesReasoning.EncryptedContent != nil {
		signed = true
		details = append(details, ChatReasoningDetails{
			ID: item.ID, Index: len(details), Type: BifrostReasoningDetailsTypeEncrypted, Data: item.ResponsesReasoning.EncryptedContent,
		})
	}
	return details, signed
}

func (t *chatTurn) addCall(item *ResponsesMessage) {
	call := item.ResponsesToolMessage
	arguments := ""
	if call.Arguments != nil {
		arguments = *call.Arguments
	}
	t.calls = append(t.calls, ChatAssistantMessageToolCall{
		Index:        uint16(len(t.calls)),
		Type:         Ptr(string(ChatToolTypeFunction)),
		ID:           call.CallID,
		Function:     ChatAssistantMessageToolCallFunction{Name: call.Name, Arguments: arguments},
		CacheControl: item.CacheControl,
	})
}

// message is the turn's assistant message. A text without a prompt cache mark, which only content
// parts hold, is a string, and several texts are parts, which each provider joins as it joins the
// parts of its own messages.
func (t *chatTurn) message() ChatMessage {
	assistant := &ChatAssistantMessage{ToolCalls: t.calls}
	message := ChatMessage{Role: ChatMessageRoleAssistant, ChatAssistantMessage: assistant}
	switch {
	case len(t.texts) == 1 && t.texts[0].CacheControl == nil && t.texts[0].PromptCacheBreakpoint == nil:
		message.Content = &ChatMessageContent{ContentStr: t.texts[0].Text}
	case len(t.texts) > 0:
		message.Content = &ChatMessageContent{ContentBlocks: t.texts}
	}
	if t.refused {
		assistant.Refusal = Ptr(t.refusal.String())
	}
	// Chat Completions takes an assistant message without content only when it calls tools.
	if message.Content == nil && len(t.calls) == 0 && !t.refused {
		message.Content = &ChatMessageContent{ContentStr: Ptr("")}
	}
	if t.reasoning.Len() > 0 {
		assistant.Reasoning = Ptr(t.reasoning.String())
	}
	if t.signed {
		assistant.ReasoningDetails = t.details
	}
	return message
}

// chatInputMessage converts a user, system or developer message. A message whose parts Chat
// Completions all lack is left out.
func chatInputMessage(item *ResponsesMessage) (ChatMessage, bool) {
	message := ChatMessage{Role: ChatMessageRoleUser}
	if item.Role != nil {
		switch *item.Role {
		case ResponsesInputMessageRoleSystem:
			message.Role = ChatMessageRoleSystem
		case ResponsesInputMessageRoleDeveloper:
			message.Role = ChatMessageRoleDeveloper
		}
	}
	if item.Content == nil {
		return message, true
	}
	if item.Content.ContentStr != nil {
		message.Content = &ChatMessageContent{ContentStr: item.Content.ContentStr}
		return message, true
	}
	blocks := chatContentBlocks(item.Content.ContentBlocks)
	if len(blocks) == 0 && len(item.Content.ContentBlocks) > 0 {
		return message, false
	}
	message.Content = &ChatMessageContent{ContentBlocks: blocks}
	return message, true
}

// chatContentBlocks converts input parts.
func chatContentBlocks(blocks []ResponsesMessageContentBlock) []ChatContentBlock {
	converted := make([]ChatContentBlock, 0, len(blocks))
	for _, block := range blocks {
		part := ChatContentBlock{
			Text:                  block.Text,
			CacheControl:          block.CacheControl,
			Citations:             block.Citations,
			PromptCacheBreakpoint: block.PromptCacheBreakpoint,
			GuardContent:          block.GuardContent,
		}
		switch block.Type {
		case ResponsesInputMessageContentBlockTypeText:
			part.Type = ChatContentBlockTypeText
		case ResponsesInputMessageContentBlockTypeImage:
			part.Type = ChatContentBlockTypeImage
			part.ImageURLStruct = &ChatInputImage{FileID: block.FileID}
			if image := block.ResponsesInputMessageContentBlockImage; image != nil {
				part.ImageURLStruct.Detail = image.Detail
				if image.ImageURL != nil {
					part.ImageURLStruct.URL = *image.ImageURL
				}
			}
		case ResponsesInputMessageContentBlockTypeFile:
			part.Type = ChatContentBlockTypeFile
			part.File = &ChatInputFile{FileID: block.FileID}
			if file := block.ResponsesInputMessageContentBlockFile; file != nil {
				part.File.FileData, part.File.FileURL = file.FileData, file.FileURL
				part.File.Filename, part.File.FileType = file.Filename, file.FileType
			}
		case ResponsesInputMessageContentBlockTypeAudio:
			part.Type = ChatContentBlockTypeInputAudio
			if block.Audio != nil {
				part.InputAudio = &ChatInputAudio{Data: block.Audio.Data}
				if block.Audio.Format != "" {
					part.InputAudio.Format = Ptr(block.Audio.Format)
				}
			}
		default:
			continue
		}
		converted = append(converted, part)
	}
	return converted
}

// chatToolMessage converts a function call's output, which Bifrost's provider converters may put
// in the item's content instead. Chat Completions requires the content of a tool message, so an
// output without a body becomes empty text. A cache mark on the item marks the output, which then
// takes the form of a part.
func chatToolMessage(item *ResponsesMessage) ChatMessage {
	tool := &ChatToolMessage{}
	message := ChatMessage{Role: ChatMessageRoleTool, ChatToolMessage: tool}
	call := item.ResponsesToolMessage
	switch content := item.Content; {
	case content != nil && content.ContentStr != nil:
		message.Content = &ChatMessageContent{ContentStr: content.ContentStr}
	case content != nil && len(content.ContentBlocks) > 0:
		message.Content = &ChatMessageContent{ContentBlocks: chatContentBlocks(content.ContentBlocks)}
	case call != nil && call.Output != nil && call.Output.ResponsesToolCallOutputStr != nil:
		message.Content = &ChatMessageContent{ContentStr: call.Output.ResponsesToolCallOutputStr}
	case call != nil && call.Output != nil:
		message.Content = &ChatMessageContent{ContentBlocks: chatContentBlocks(call.Output.ResponsesFunctionToolCallOutputBlocks)}
	}
	if call != nil {
		tool.ToolCallID = call.CallID
		// The Responses interface marks a failed call with an error or an incomplete status.
		if call.Error.IsError() || (item.Status != nil && *item.Status == ResponsesResponseStatusIncomplete) {
			tool.IsError = Ptr(true)
		}
	}
	if message.Content == nil || (message.Content.ContentStr == nil && len(message.Content.ContentBlocks) == 0) {
		message.Content = &ChatMessageContent{ContentStr: Ptr("")}
	}
	if item.CacheControl != nil {
		if message.Content.ContentStr != nil {
			message.Content = &ChatMessageContent{ContentBlocks: []ChatContentBlock{{Type: ChatContentBlockTypeText, Text: message.Content.ContentStr}}}
		}
		last := &message.Content.ContentBlocks[len(message.Content.ContentBlocks)-1]
		last.CacheControl = item.CacheControl
	}
	return message
}

// maxReplyIDBase bounds the part of a reply's ID that the IDs of its items repeat.
const maxReplyIDBase = 64

// chatReplyIDs names a converted reply after the provider's ID for it, and the reply's items
// after that ID, with OpenAI's prefix for each kind of item, so that a reply and its stream name
// the same item alike.
type chatReplyIDs struct{ reply, base string }

func newChatReplyIDs(id string) chatReplyIDs {
	if id == "" {
		id = "resp_" + GetRandomString(32)
	}
	base := id
	if len(base) > maxReplyIDBase {
		sum := sha256.Sum256([]byte(base))
		base = hex.EncodeToString(sum[:16])
	}
	return chatReplyIDs{reply: id, base: base}
}

func (ids chatReplyIDs) item(kind ResponsesMessageType, index int) string {
	prefix := "msg_"
	switch kind {
	case ResponsesMessageTypeReasoning:
		prefix = "rs_"
	case ResponsesMessageTypeFunctionCall:
		prefix = "fc_"
	}
	return prefix + ids.base + "_" + strconv.Itoa(index)
}

// chatReplyStatus is the status of a reply that ended for reason, and why it is incomplete.
// mapped is false for a missing reason, or one that Responses has no status for.
func chatReplyStatus(reason *string) (status string, incomplete *ResponsesResponseIncompleteDetails, mapped bool) {
	if reason == nil {
		return "", nil, false
	}
	return responsesStatusFromChatFinishReason(*reason)
}

// completedAt is when a reply that its provider created at created completed: now, unless the
// provider's clock is ahead of ours.
func completedAt(created int) *int {
	return Ptr(max(int(time.Now().Unix()), created))
}

// replyText is a text or a refusal part of a converted message, with what describes it.
type replyText struct {
	refusal     bool
	text        string
	annotations []ResponsesOutputMessageContentTextAnnotation
	logProbs    []ResponsesOutputMessageContentTextLogProb
}

func (t replyText) block() ResponsesMessageContentBlock {
	if t.refusal {
		return ResponsesMessageContentBlock{
			Type:                                 ResponsesOutputMessageContentTypeRefusal,
			ResponsesOutputMessageContentRefusal: &ResponsesOutputMessageContentRefusal{Refusal: t.text},
		}
	}
	annotations, logProbs := t.annotations, t.logProbs
	if annotations == nil {
		annotations = []ResponsesOutputMessageContentTextAnnotation{}
	}
	if logProbs == nil {
		logProbs = []ResponsesOutputMessageContentTextLogProb{}
	}
	return ResponsesMessageContentBlock{
		Type:                              ResponsesOutputMessageContentTypeText,
		Text:                              Ptr(t.text),
		ResponsesOutputMessageContentText: &ResponsesOutputMessageContentText{Annotations: annotations, LogProbs: logProbs},
	}
}

// replyReasoning is the reasoning of a converted reply: its text, with the signature that Claude
// models give it, the summaries and the encrypted content.
type replyReasoning struct {
	id        *string
	text      strings.Builder
	signature *string
	summaries []ResponsesReasoningSummary
	encrypted *string
}

// add takes reasoning details, or the reasoning text when there are none.
func (r *replyReasoning) add(text *string, details []ChatReasoningDetails) {
	if len(details) == 0 {
		if text != nil {
			r.text.WriteString(*text)
		}
		return
	}
	for _, detail := range details {
		if r.id == nil && detail.ID != nil && *detail.ID != "" {
			r.id = detail.ID
		}
		switch detail.Type {
		case BifrostReasoningDetailsTypeText:
			if detail.Text != nil {
				r.text.WriteString(*detail.Text)
			}
			if detail.Signature != nil {
				r.signature = detail.Signature
			}
		case BifrostReasoningDetailsTypeSummary:
			if detail.Summary != nil {
				r.summaries = append(r.summaries, ResponsesReasoningSummary{Type: ResponsesReasoningContentBlockTypeSummaryText, Text: *detail.Summary})
			}
		case BifrostReasoningDetailsTypeEncrypted:
			if detail.Data != nil {
				r.encrypted = detail.Data
			}
		}
	}
}

// reasoningRuns splits reasoning details into the runs that make one reasoning item each, as OpenAI
// pairs encrypted reasoning with the ID of its item: a detail with an ID other than that of its
// run's first detail starts the next run. A stream opens its reasoning item with the ID of the
// first detail, so a run without an ID at its start also ends at the next ID.
func reasoningRuns(details []ChatReasoningDetails) [][]ChatReasoningDetails {
	var runs [][]ChatReasoningDetails
	start := 0
	for i := 1; i < len(details); i++ {
		if id := details[i].ID; id != nil && *id != "" && (details[start].ID == nil || *details[start].ID != *id) {
			runs = append(runs, details[start:i])
			start = i
		}
	}
	if len(details) > 0 {
		runs = append(runs, details[start:])
	}
	return runs
}

func (r *replyReasoning) empty() bool {
	return r.text.Len() == 0 && r.signature == nil && len(r.summaries) == 0 && r.encrypted == nil
}

func (r *replyReasoning) item(ids chatReplyIDs, index int, status string) ResponsesMessage {
	id := ids.item(ResponsesMessageTypeReasoning, index)
	if r.id != nil {
		// OpenAI pairs encrypted reasoning with the ID of the item that it came with.
		id = *r.id
	}
	summaries := r.summaries
	if summaries == nil {
		summaries = []ResponsesReasoningSummary{}
	}
	item := ResponsesMessage{
		ID:                 Ptr(id),
		Type:               Ptr(ResponsesMessageTypeReasoning),
		Status:             Ptr(status),
		ResponsesReasoning: &ResponsesReasoning{Summary: summaries, EncryptedContent: r.encrypted},
	}
	if r.text.Len() > 0 || r.signature != nil {
		item.Content = &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{{
			Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr(r.text.String()), Signature: r.signature,
		}}}
	}
	return item
}

func replyMessageItem(ids chatReplyIDs, index int, status string, texts []replyText) ResponsesMessage {
	blocks := make([]ResponsesMessageContentBlock, 0, len(texts))
	for _, text := range texts {
		blocks = append(blocks, text.block())
	}
	return ResponsesMessage{
		ID:      Ptr(ids.item(ResponsesMessageTypeMessage, index)),
		Type:    Ptr(ResponsesMessageTypeMessage),
		Role:    Ptr(ResponsesInputMessageRoleAssistant),
		Status:  Ptr(status),
		Content: &ResponsesMessageContent{ContentBlocks: blocks},
	}
}

func replyCallItem(ids chatReplyIDs, index int, status string, callID, name, arguments string) ResponsesMessage {
	return ResponsesMessage{
		ID:     Ptr(ids.item(ResponsesMessageTypeFunctionCall, index)),
		Type:   Ptr(ResponsesMessageTypeFunctionCall),
		Status: Ptr(status),
		ResponsesToolMessage: &ResponsesToolMessage{
			CallID: Ptr(callID), Name: Ptr(name), Arguments: Ptr(arguments),
		},
	}
}

// responsesAnnotations converts the URL citations of a Chat Completions message.
func responsesAnnotations(annotations []ChatAssistantMessageAnnotation) []ResponsesOutputMessageContentTextAnnotation {
	converted := make([]ResponsesOutputMessageContentTextAnnotation, 0, len(annotations))
	for _, annotation := range annotations {
		citation := annotation.URLCitation
		converted = append(converted, ResponsesOutputMessageContentTextAnnotation{
			Type:       annotation.Type,
			StartIndex: Ptr(citation.StartIndex),
			EndIndex:   Ptr(citation.EndIndex),
			Title:      Ptr(citation.Title),
			URL:        citation.URL,
			Text:       citation.Text,
		})
	}
	return converted
}

// responsesLogProbs converts the log probabilities of output text.
func responsesLogProbs(logProbs *BifrostLogProbs) []ResponsesOutputMessageContentTextLogProb {
	if logProbs == nil || len(logProbs.Content) == 0 {
		return nil
	}
	converted := make([]ResponsesOutputMessageContentTextLogProb, 0, len(logProbs.Content))
	for _, token := range logProbs.Content {
		top := token.TopLogProbs
		if top == nil {
			top = []LogProb{}
		}
		converted = append(converted, ResponsesOutputMessageContentTextLogProb{
			Bytes: token.Bytes, LogProb: token.LogProb, Token: token.Token, TopLogProbs: top,
		})
	}
	return converted
}

// ToBifrostResponsesResponse converts a Chat Completions reply to Responses. Its output is the
// reasoning, then a message with the text and refusal, then a function call for each tool call,
// since a Chat Completions message keeps no order among them. A reply has one choice, as a
// converted request never asks for more. A reply cut short leaves its last item incomplete.
func (cr *BifrostChatResponse) ToBifrostResponsesResponse() *BifrostResponsesResponse {
	if cr == nil {
		return nil
	}
	ids := newChatReplyIDs(cr.ID)
	response := &BifrostResponsesResponse{
		ID:            Ptr(ids.reply),
		Object:        "response",
		CreatedAt:     cr.Created,
		Model:         cr.Model,
		ServiceTier:   cr.ServiceTier,
		Speed:         cr.Speed,
		InferenceGeo:  cr.InferenceGeo,
		Citations:     cr.Citations,
		SearchResults: cr.SearchResults,
		Videos:        cr.Videos,
		ExtraFields:   cr.ExtraFields,
	}
	response.ExtraFields.RequestType = ResponsesRequest
	if cr.Usage != nil {
		response.Usage = cr.Usage.ToResponsesResponseUsage()
	}
	if len(cr.Choices) == 0 {
		return response
	}
	// A reason that Responses has no status for leaves the status unset, for the caller to judge.
	choice := cr.Choices[0]
	status, incomplete, mapped := chatReplyStatus(choice.FinishReason)
	if mapped {
		response.Status, response.IncompleteDetails = Ptr(status), incomplete
		response.StopReason = Ptr(*choice.FinishReason)
	}
	if status == ResponsesResponseStatusCompleted {
		response.CompletedAt = completedAt(cr.Created)
	}
	itemStatus := ResponsesResponseStatusCompleted
	if choice.ChatNonStreamResponseChoice == nil || choice.ChatNonStreamResponseChoice.Message == nil {
		return response
	}
	message := choice.ChatNonStreamResponseChoice.Message
	assistant := message.ChatAssistantMessage
	if assistant == nil {
		assistant = &ChatAssistantMessage{}
	}
	output := make([]ResponsesMessage, 0, 2+len(assistant.ToolCalls))
	runs := reasoningRuns(assistant.ReasoningDetails)
	if len(runs) == 0 {
		runs = [][]ChatReasoningDetails{nil}
	}
	for _, run := range runs {
		var reasoning replyReasoning
		reasoning.add(assistant.Reasoning, run)
		if !reasoning.empty() {
			output = append(output, reasoning.item(ids, len(output), itemStatus))
		}
	}
	if texts := chatReplyTexts(message.Content, assistant, choice.LogProbs); len(texts) > 0 {
		output = append(output, replyMessageItem(ids, len(output), itemStatus, texts))
	}
	for _, call := range assistant.ToolCalls {
		callID, name := "call_"+GetRandomString(24), ""
		if call.ID != nil && *call.ID != "" {
			callID = *call.ID
		}
		if call.Function.Name != nil {
			name = *call.Function.Name
		}
		output = append(output, replyCallItem(ids, len(output), itemStatus, callID, name, call.Function.Arguments))
	}
	if status == ResponsesResponseStatusIncomplete {
		MarkTruncatedOutputItem(output)
	}
	response.Output = output
	return response
}

// chatReplyTexts are the parts of a reply's message: its text and refusal, with adjacent text of
// one kind joined and empty text left out. The text takes the message's citations and the log
// probabilities of its tokens.
func chatReplyTexts(content *ChatMessageContent, assistant *ChatAssistantMessage, logProbs *BifrostLogProbs) []replyText {
	var texts []replyText
	add := func(refusal bool, text string) {
		if text == "" {
			return
		}
		if last := len(texts) - 1; last >= 0 && texts[last].refusal == refusal {
			texts[last].text += text
			return
		}
		texts = append(texts, replyText{refusal: refusal, text: text})
	}
	if content != nil {
		if content.ContentStr != nil {
			add(false, *content.ContentStr)
		}
		for _, block := range content.ContentBlocks {
			switch {
			case block.Type == ChatContentBlockTypeText && block.Text != nil:
				add(false, *block.Text)
			case block.Type == ChatContentBlockTypeRefusal && block.Refusal != nil:
				add(true, *block.Refusal)
			}
		}
	}
	if assistant.Refusal != nil {
		add(true, *assistant.Refusal)
	}
	for i := range texts {
		if !texts[i].refusal {
			texts[i].annotations = responsesAnnotations(assistant.Annotations)
			texts[i].logProbs = textLogProbs(responsesLogProbs(logProbs), texts[i].text, assistant.Reasoning, assistant.ReasoningDetails, len(assistant.ToolCalls) > 0)
			break
		}
	}
	return texts
}

// textLogProbs returns the log probabilities of a text's tokens. Some providers, such as those
// that run vLLM, list them among the tokens of the reasoning before the text and of the tool
// calls after it. With reasoning or tool calls, the text thus takes a run of tokens that spells
// it, after the reasoning text when the tokens spell that too: the last run, as the text follows
// the reasoning, or the first when tool calls may follow the text. When tool calls follow
// reasoning that the tokens do not spell, a run may lie in the reasoning, so only a sole run
// counts. When no run spells the text, which happens when a provider splits a character across
// tokens, the text takes none, as its tokens cannot be told apart.
func textLogProbs(logProbs []ResponsesOutputMessageContentTextLogProb, text string, reasoning *string, details []ChatReasoningDetails, calls bool) []ResponsesOutputMessageContentTextLogProb {
	reasoned := (reasoning != nil && *reasoning != "") || len(details) > 0
	if (!reasoned && !calls) || len(logProbs) == 0 {
		return logProbs
	}
	// offsets[i] is where token i starts in the joined tokens, and offsets[len] is their length.
	offsets := make([]int, len(logProbs)+1)
	var joined strings.Builder
	for i, token := range logProbs {
		offsets[i] = joined.Len()
		joined.WriteString(token.Token)
	}
	offsets[len(logProbs)] = joined.Len()
	tokens := joined.String()
	from, placed := 0, !reasoned
	if reasoning != nil && *reasoning != "" {
		if at := strings.Index(tokens, *reasoning); at >= 0 {
			from, placed = at+len(*reasoning), true
		}
	}
	var runs [][2]int
	for from+len(text) <= len(tokens) {
		at := strings.Index(tokens[from:], text)
		if at < 0 {
			break
		}
		start, end := from+at, from+at+len(text)
		from = start + 1
		// The run leaves out the empty tokens at its edges.
		first, _ := slices.BinarySearch(offsets[:len(logProbs)], start+1)
		last, found := slices.BinarySearch(offsets, end)
		if first--; first >= 0 && offsets[first] == start && found && last > first {
			runs = append(runs, [2]int{first, last})
		}
	}
	var run [2]int
	switch {
	case len(runs) == 0:
		return nil
	case !calls:
		run = runs[len(runs)-1]
	case placed || len(runs) == 1:
		run = runs[0]
	default:
		return nil
	}
	return logProbs[run[0]:run[1]]
}

// ChatToResponsesStreamState converts the stream of a Chat Completions reply into Responses
// events. Reasoning and text stream as they come, and a change between them completes the open
// item and opens the next, so that each item's events are contiguous for a consumer that maps
// items to blocks, as Anthropic's interface does. A stream whose reasoning and text alternate
// thus has more items than its reply, whose message holds all its reasoning in one field and all
// its text in another, and a stream whose text and refusal alternate has more parts. A Chat
// Completions message keeps no order between its text and its tool calls, which some providers
// interleave, so the calls follow, whole, as a reply's do, when the provider gives the finish
// reason, as text may still come before then. The chunk that gives the finish reason also yields
// response.completed or response.incomplete, to which the caller adds the usage that later chunks
// bring. A chunk that the conversion cannot represent yields an error event.
type ChatToResponsesStreamState struct {
	ids          chatReplyIDs
	started      bool
	finished     bool
	sequence     int
	createdAt    int
	model        string
	serviceTier  *BifrostServiceTier
	speed        *string
	inferenceGeo *string
	// items are the output items in order, and open is the reasoning or message item that takes
	// the next delta of its kind.
	items []*streamItem
	open  *streamItem
	// calls are the tool calls in the order of their first deltas, and callAt holds the latest
	// call at each index.
	calls  []*streamItem
	callAt map[uint16]*streamItem
}

// streamItem is an output item of a stream.
type streamItem struct {
	id     string
	index  int
	kind   ResponsesMessageType
	status string
	done   bool
	// texts are a message's parts; every part but the last is done.
	texts []replyText
	// reasoning is a reasoning item's content. textPart and summaryPart mark the parts that the
	// item opened for its text and its summary.
	reasoning   replyReasoning
	textPart    bool
	summaryPart bool
	callID      string
	name        string
	arguments   strings.Builder
}

var chatToResponsesStreamStatePool = sync.Pool{
	New: func() any { return &ChatToResponsesStreamState{} },
}

// AcquireChatToResponsesStreamState returns a state for a new stream.
func AcquireChatToResponsesStreamState() *ChatToResponsesStreamState {
	state := chatToResponsesStreamStatePool.Get().(*ChatToResponsesStreamState)
	*state = ChatToResponsesStreamState{callAt: make(map[uint16]*streamItem)}
	return state
}

// ReleaseChatToResponsesStreamState returns a state that its stream no longer uses.
func ReleaseChatToResponsesStreamState(state *ChatToResponsesStreamState) {
	if state != nil {
		*state = ChatToResponsesStreamState{}
		chatToResponsesStreamStatePool.Put(state)
	}
}

// ToBifrostResponsesStreamResponse returns the Responses events of a Chat Completions stream chunk.
func (cr *BifrostChatResponse) ToBifrostResponsesStreamResponse(state *ChatToResponsesStreamState) []*BifrostResponsesStreamResponse {
	if cr == nil || state == nil {
		return nil
	}
	if state.callAt == nil {
		state.callAt = make(map[uint16]*streamItem)
	}
	// OpenAI gives the served tier on every chunk and other providers on some, the last chunk
	// among them, which may hold no choice.
	if cr.ServiceTier != nil {
		state.serviceTier = cr.ServiceTier
	}
	if cr.Speed != nil {
		state.speed = cr.Speed
	}
	if cr.InferenceGeo != nil {
		state.inferenceGeo = cr.InferenceGeo
	}
	if state.model == "" {
		state.model = cr.Model
	}
	// Azure opens a stream with a chunk that holds only its content filter results and no ID.
	if len(cr.Choices) == 0 {
		return nil
	}
	var events []*BifrostResponsesStreamResponse
	emit := func(event *BifrostResponsesStreamResponse) {
		event.SequenceNumber = state.sequence
		state.sequence++
		event.ExtraFields = cr.ExtraFields
		event.ExtraFields.RequestType = ResponsesStreamRequest
		event.SearchResults, event.Videos, event.Citations = cr.SearchResults, cr.Videos, cr.Citations
		events = append(events, event)
	}
	fail := func(message string) []*BifrostResponsesStreamResponse {
		emit(&BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeError, Message: Ptr(message)})
		return events
	}
	if !state.started {
		state.started = true
		state.ids = newChatReplyIDs(cr.ID)
		state.createdAt = cr.Created
		if state.createdAt == 0 {
			state.createdAt = int(time.Now().Unix())
		}
		emit(&BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeCreated, Response: state.response(ResponsesResponseStatusInProgress)})
		emit(&BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeInProgress, Response: state.response(ResponsesResponseStatusInProgress)})
	}
	for _, choice := range cr.Choices {
		if choice.Index != 0 {
			return fail("the stream has more than one choice")
		}
		var delta *ChatStreamResponseChoiceDelta
		if choice.ChatStreamResponseChoice != nil {
			delta = choice.ChatStreamResponseChoice.Delta
		}
		if delta != nil {
			if state.finished && streamDeltaWrites(delta) {
				return fail("the stream continues after its finish reason")
			}
			if (delta.Reasoning != nil && *delta.Reasoning != "") || len(delta.ReasoningDetails) > 0 {
				state.writeReasoning(delta.Reasoning, delta.ReasoningDetails, emit)
			}
			if delta.Content != nil && *delta.Content != "" {
				logProbs := textLogProbs(responsesLogProbs(choice.LogProbs), *delta.Content, delta.Reasoning, delta.ReasoningDetails, len(delta.ToolCalls) > 0)
				state.writeText(false, *delta.Content, logProbs, emit)
			}
			if delta.Refusal != nil && *delta.Refusal != "" {
				state.writeText(true, *delta.Refusal, nil, emit)
			}
			if len(delta.Annotations) > 0 {
				state.writeAnnotations(responsesAnnotations(delta.Annotations), emit)
			}
			for _, call := range delta.ToolCalls {
				state.addCall(call)
			}
		}
		if choice.FinishReason != nil && *choice.FinishReason != "" && !state.finished {
			if message := state.finish(choice.FinishReason, cr.Usage, emit); message != "" {
				return fail(message)
			}
		}
	}
	return events
}

// streamDeltaWrites reports whether a delta adds to the reply.
func streamDeltaWrites(delta *ChatStreamResponseChoiceDelta) bool {
	return (delta.Content != nil && *delta.Content != "") || (delta.Refusal != nil && *delta.Refusal != "") ||
		(delta.Reasoning != nil && *delta.Reasoning != "") || len(delta.ReasoningDetails) > 0 ||
		len(delta.ToolCalls) > 0 || len(delta.Annotations) > 0
}

// response is the response that the stream describes, without output.
func (s *ChatToResponsesStreamState) response(status string) *BifrostResponsesResponse {
	return &BifrostResponsesResponse{
		ID:           Ptr(s.ids.reply),
		Object:       "response",
		CreatedAt:    s.createdAt,
		Model:        s.model,
		Status:       Ptr(status),
		Output:       []ResponsesMessage{},
		ServiceTier:  s.serviceTier,
		Speed:        s.speed,
		InferenceGeo: s.inferenceGeo,
	}
}

// begin completes the open item and opens a reasoning or message item. An empty id names the
// item after the reply.
func (s *ChatToResponsesStreamState) begin(kind ResponsesMessageType, id string, emit func(*BifrostResponsesStreamResponse)) *streamItem {
	s.end(s.open, ResponsesResponseStatusCompleted, emit)
	item := &streamItem{kind: kind}
	s.place(item, id)
	s.open = item
	added := s.final(item)
	added.Status = Ptr(ResponsesResponseStatusInProgress)
	emit(&BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: Ptr(item.index), Item: &added})
	return item
}

// place puts an item at the end of the output. An empty id names the item after the reply.
func (s *ChatToResponsesStreamState) place(item *streamItem, id string) {
	item.index, item.id = len(s.items), id
	if item.id == "" {
		item.id = s.ids.item(item.kind, item.index)
	}
	if item.kind == ResponsesMessageTypeReasoning {
		item.reasoning.id = Ptr(item.id)
	}
	s.items = append(s.items, item)
}

// event is an event about the item.
func (item *streamItem) event(kind ResponsesStreamResponseType) *BifrostResponsesStreamResponse {
	return &BifrostResponsesStreamResponse{Type: kind, OutputIndex: Ptr(item.index), ItemID: Ptr(item.id)}
}

// writeReasoning adds reasoning: its text to the item's reasoning text, with the signature that
// Claude models give it, its summaries to the item's summary, and its encrypted content to the
// item. A signature comes as a reasoning text delta whose signature field holds it, as the
// Anthropic stream converters expect.
func (s *ChatToResponsesStreamState) writeReasoning(text *string, details []ChatReasoningDetails, emit func(*BifrostResponsesStreamResponse)) {
	if len(details) == 0 {
		s.writeReasoningRun(text, nil, emit)
		return
	}
	for _, run := range reasoningRuns(details) {
		s.writeReasoningRun(nil, run, emit)
	}
}

// writeReasoningRun adds reasoning that belongs to one item: the open reasoning item, unless the
// reasoning names another, as a run of details with another ID does.
func (s *ChatToResponsesStreamState) writeReasoningRun(text *string, details []ChatReasoningDetails, emit func(*BifrostResponsesStreamResponse)) {
	var added replyReasoning
	added.add(text, details)
	item := s.open
	if item == nil || item.kind != ResponsesMessageTypeReasoning || (added.id != nil && *added.id != item.id) {
		id := ""
		if added.id != nil {
			id = *added.id
		}
		item = s.begin(ResponsesMessageTypeReasoning, id, emit)
	}
	delta := added.text.String()
	if (delta != "" || added.signature != nil) && !item.textPart {
		item.textPart = true
		event := item.event(ResponsesStreamResponseTypeContentPartAdded)
		event.ContentIndex = Ptr(0)
		event.Part = &ResponsesMessageContentBlock{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr("")}
		emit(event)
	}
	if delta != "" {
		item.reasoning.text.WriteString(delta)
		event := item.event(ResponsesStreamResponseTypeReasoningTextDelta)
		event.ContentIndex, event.Delta = Ptr(0), Ptr(delta)
		emit(event)
	}
	if added.signature != nil {
		item.reasoning.signature = added.signature
		event := item.event(ResponsesStreamResponseTypeReasoningTextDelta)
		event.ContentIndex, event.Signature = Ptr(0), added.signature
		emit(event)
	}
	for _, summary := range added.summaries {
		if !item.summaryPart {
			item.summaryPart = true
			item.reasoning.summaries = append(item.reasoning.summaries, ResponsesReasoningSummary{Type: ResponsesReasoningContentBlockTypeSummaryText})
			event := item.event(ResponsesStreamResponseTypeReasoningSummaryPartAdded)
			event.SummaryIndex = Ptr(0)
			event.Part = &ResponsesMessageContentBlock{Type: ResponsesOutputMessageContentTypeSummaryText, Text: Ptr("")}
			emit(event)
		}
		item.reasoning.summaries[0].Text += summary.Text
		event := item.event(ResponsesStreamResponseTypeReasoningSummaryTextDelta)
		event.SummaryIndex, event.Delta = Ptr(0), Ptr(summary.Text)
		emit(event)
	}
	if added.encrypted != nil {
		item.reasoning.encrypted = added.encrypted
	}
}

// textPart returns the message part that takes text, or a refusal, and its index. It opens the
// message when the open item is another, and the part when the open part is of the other kind.
func (s *ChatToResponsesStreamState) textPart(refusal bool, emit func(*BifrostResponsesStreamResponse)) (*streamItem, int) {
	item := s.open
	if item == nil || item.kind != ResponsesMessageTypeMessage {
		item = s.begin(ResponsesMessageTypeMessage, "", emit)
	}
	last := len(item.texts) - 1
	if last >= 0 && item.texts[last].refusal == refusal {
		return item, last
	}
	if last >= 0 {
		s.closePart(item, last, emit)
	}
	item.texts = append(item.texts, replyText{refusal: refusal})
	event := item.event(ResponsesStreamResponseTypeContentPartAdded)
	event.ContentIndex, event.Part = Ptr(last+1), Ptr(replyText{refusal: refusal}.block())
	emit(event)
	return item, last + 1
}

// writeText adds text or a refusal to the message.
func (s *ChatToResponsesStreamState) writeText(refusal bool, text string, logProbs []ResponsesOutputMessageContentTextLogProb, emit func(*BifrostResponsesStreamResponse)) {
	item, index := s.textPart(refusal, emit)
	item.texts[index].text += text
	event := item.event(ResponsesStreamResponseTypeOutputTextDelta)
	event.ContentIndex, event.Delta = Ptr(index), Ptr(text)
	if refusal {
		event.Type = ResponsesStreamResponseTypeRefusalDelta
	} else {
		item.texts[index].logProbs = append(item.texts[index].logProbs, logProbs...)
		event.LogProbs = logProbs
		if event.LogProbs == nil {
			event.LogProbs = []ResponsesOutputMessageContentTextLogProb{}
		}
	}
	emit(event)
}

// writeAnnotations adds citations to the message's text.
func (s *ChatToResponsesStreamState) writeAnnotations(annotations []ResponsesOutputMessageContentTextAnnotation, emit func(*BifrostResponsesStreamResponse)) {
	item, index := s.textPart(false, emit)
	for i := range annotations {
		item.texts[index].annotations = append(item.texts[index].annotations, annotations[i])
		event := item.event(ResponsesStreamResponseTypeOutputTextAnnotationAdded)
		event.ContentIndex, event.AnnotationIndex = Ptr(index), Ptr(len(item.texts[index].annotations)-1)
		event.Annotation = &annotations[i]
		emit(event)
	}
}

// addCall adds a tool call's delta. A delta with another ID than the call at its index starts a
// call, as some providers give every call index 0.
func (s *ChatToResponsesStreamState) addCall(call ChatAssistantMessageToolCall) {
	item, exists := s.callAt[call.Index]
	if !exists || (call.ID != nil && *call.ID != "" && item.callID != "" && *call.ID != item.callID) {
		item = &streamItem{kind: ResponsesMessageTypeFunctionCall}
		s.calls = append(s.calls, item)
		s.callAt[call.Index] = item
	}
	if item.callID == "" && call.ID != nil {
		item.callID = *call.ID
	}
	if item.name == "" && call.Function.Name != nil {
		item.name = *call.Function.Name
	}
	item.arguments.WriteString(call.Function.Arguments)
}

// closePart sends a message part's text, then the part.
func (s *ChatToResponsesStreamState) closePart(item *streamItem, index int, emit func(*BifrostResponsesStreamResponse)) {
	text := item.texts[index]
	part := text.block()
	var done *BifrostResponsesStreamResponse
	if text.refusal {
		done = item.event(ResponsesStreamResponseTypeRefusalDone)
		done.ContentIndex, done.Refusal = Ptr(index), Ptr(text.text)
	} else {
		done = item.event(ResponsesStreamResponseTypeOutputTextDone)
		done.ContentIndex, done.Text, done.LogProbs = Ptr(index), Ptr(text.text), part.LogProbs
	}
	emit(done)
	partDone := item.event(ResponsesStreamResponseTypeContentPartDone)
	partDone.ContentIndex, partDone.Part = Ptr(index), &part
	emit(partDone)
}

// end completes an open item with status: the text and the part that it has open, or the
// call's arguments, then the item.
func (s *ChatToResponsesStreamState) end(item *streamItem, status string, emit func(*BifrostResponsesStreamResponse)) {
	if item == nil || item.done {
		return
	}
	switch item.kind {
	case ResponsesMessageTypeReasoning:
		if item.textPart {
			text := item.reasoning.text.String()
			done := item.event(ResponsesStreamResponseTypeReasoningTextDone)
			done.ContentIndex, done.Text = Ptr(0), Ptr(text)
			emit(done)
			partDone := item.event(ResponsesStreamResponseTypeContentPartDone)
			partDone.ContentIndex = Ptr(0)
			partDone.Part = &ResponsesMessageContentBlock{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr(text), Signature: item.reasoning.signature}
			emit(partDone)
		}
		if item.summaryPart {
			text := item.reasoning.summaries[0].Text
			done := item.event(ResponsesStreamResponseTypeReasoningSummaryTextDone)
			done.SummaryIndex, done.Text = Ptr(0), Ptr(text)
			emit(done)
			partDone := item.event(ResponsesStreamResponseTypeReasoningSummaryPartDone)
			partDone.SummaryIndex = Ptr(0)
			partDone.Part = &ResponsesMessageContentBlock{Type: ResponsesOutputMessageContentTypeSummaryText, Text: Ptr(text)}
			emit(partDone)
		}
	case ResponsesMessageTypeMessage:
		s.closePart(item, len(item.texts)-1, emit)
	case ResponsesMessageTypeFunctionCall:
		done := item.event(ResponsesStreamResponseTypeFunctionCallArgumentsDone)
		done.Arguments = Ptr(item.arguments.String())
		emit(done)
	}
	if s.open == item {
		s.open = nil
	}
	item.done, item.status = true, status
	final := s.final(item)
	emit(&BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemDone, OutputIndex: Ptr(item.index), Item: &final})
}

// final is the item as the reply returns it.
func (s *ChatToResponsesStreamState) final(item *streamItem) ResponsesMessage {
	switch item.kind {
	case ResponsesMessageTypeReasoning:
		return item.reasoning.item(s.ids, item.index, item.status)
	case ResponsesMessageTypeFunctionCall:
		return replyCallItem(s.ids, item.index, item.status, item.callID, item.name, item.arguments.String())
	default:
		return replyMessageItem(s.ids, item.index, item.status, item.texts)
	}
}

// finish completes the reply when the provider gives the reason why it ended: the open item,
// then the tool calls, then the response. A reply cut short leaves its last item incomplete. It
// returns why the calls are malformed, if they are.
func (s *ChatToResponsesStreamState) finish(reason *string, usage *BifrostLLMUsage, emit func(*BifrostResponsesStreamResponse)) string {
	s.finished = true
	for _, call := range s.calls {
		if call.name == "" {
			return "a tool call has no function name"
		}
	}
	status, incomplete, mapped := chatReplyStatus(reason)
	if !mapped {
		// A reply with such a reason has no status either, for the caller to judge.
		return "the finish reason " + *reason + " has no Responses status"
	}
	openStatus := status
	if len(s.calls) > 0 {
		openStatus = ResponsesResponseStatusCompleted
	}
	s.end(s.open, openStatus, emit)
	for i, call := range s.calls {
		s.place(call, "")
		if call.callID == "" {
			call.callID = "call_" + GetRandomString(24)
		}
		added := replyCallItem(s.ids, call.index, ResponsesResponseStatusInProgress, call.callID, call.name, "")
		emit(&BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: Ptr(call.index), Item: &added})
		if arguments := call.arguments.String(); arguments != "" {
			event := call.event(ResponsesStreamResponseTypeFunctionCallArgumentsDelta)
			event.Delta = Ptr(arguments)
			emit(event)
		}
		callStatus := ResponsesResponseStatusCompleted
		if i == len(s.calls)-1 {
			callStatus = status
		}
		s.end(call, callStatus, emit)
	}
	response := s.response(status)
	response.IncompleteDetails, response.StopReason = incomplete, Ptr(*reason)
	if status == ResponsesResponseStatusCompleted {
		response.CompletedAt = completedAt(s.createdAt)
	}
	for _, item := range s.items {
		response.Output = append(response.Output, s.final(item))
	}
	if usage != nil {
		response.Usage = usage.ToResponsesResponseUsage()
	}
	eventType := ResponsesStreamResponseTypeCompleted
	if status == ResponsesResponseStatusIncomplete {
		eventType = ResponsesStreamResponseTypeIncomplete
	}
	emit(&BifrostResponsesStreamResponse{Type: eventType, Response: response})
	return ""
}
