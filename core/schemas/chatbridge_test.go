package schemas

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestChatCompletionsGapNamesWhatChatCompletionsCannotCarry(t *testing.T) {
	text := func(kind ResponsesMessageContentBlockType) ResponsesMessageContentBlock {
		return ResponsesMessageContentBlock{Type: kind, Text: Ptr("x")}
	}
	message := func(role ResponsesMessageRoleType, blocks ...ResponsesMessageContentBlock) ResponsesMessage {
		return ResponsesMessage{Type: Ptr(ResponsesMessageTypeMessage), Role: Ptr(role), Content: &ResponsesMessageContent{ContentBlocks: blocks}}
	}
	function := ResponsesTool{Type: ResponsesToolTypeFunction, Name: Ptr("lookup")}
	tests := []struct {
		name    string
		request BifrostResponsesRequest
		param   string
		feature string
	}{
		{"background", BifrostResponsesRequest{Params: &ResponsesParameters{Background: Ptr(true)}}, "background", "background mode"},
		{"stored conversation", BifrostResponsesRequest{Params: &ResponsesParameters{Conversation: &ResponsesResponseConversation{}}}, "conversation", "stored conversations"},
		{"stored response", BifrostResponsesRequest{Params: &ResponsesParameters{PreviousResponseID: Ptr("resp_1")}}, "previous_response_id", "stored responses"},
		{"tool call limit", BifrostResponsesRequest{Params: &ResponsesParameters{MaxToolCalls: Ptr(2)}}, "max_tool_calls", "a limit on tool calls"},
		{"automatic truncation", BifrostResponsesRequest{Params: &ResponsesParameters{Truncation: Ptr("auto")}}, "truncation", "automatic truncation"},
		{"include", BifrostResponsesRequest{Params: &ResponsesParameters{Include: []string{responsesIncludeLogProbs, responsesIncludeEncryptedReasoning, "web_search_call.results"}}},
			"include[2]", "the web_search_call.results output"},
		{"reasoning summary", BifrostResponsesRequest{Params: &ResponsesParameters{Reasoning: &ResponsesParametersReasoning{Summary: Ptr("detailed")}}},
			"reasoning.summary", "reasoning summaries"},
		{"reasoning context", BifrostResponsesRequest{Params: &ResponsesParameters{Reasoning: &ResponsesParametersReasoning{Context: Ptr("all")}}},
			"reasoning.context", "the reasoning context setting"},
		{"hosted tool", BifrostResponsesRequest{Params: &ResponsesParameters{Tools: []ResponsesTool{function, {Type: ResponsesToolTypeWebSearch}}}},
			"tools[1].type", "web_search tools"},
		{"async tool", BifrostResponsesRequest{Params: &ResponsesParameters{Tools: []ResponsesTool{{Type: ResponsesToolTypeFunction, Name: Ptr("f"), Async: Ptr(true)}}}},
			"tools[0].async", "async tools"},
		{"output schema", BifrostResponsesRequest{Params: &ResponsesParameters{Tools: []ResponsesTool{{
			Type: ResponsesToolTypeFunction, Name: Ptr("f"), ResponsesToolFunction: &ResponsesToolFunction{OutputSchema: &OrderedMap{}},
		}}}}, "tools[0].output_schema", "function output schemas"},
		{"hosted tool choice", BifrostResponsesRequest{Params: &ResponsesParameters{Tools: []ResponsesTool{function},
			ToolChoice: &ResponsesToolChoice{ResponsesToolChoiceStruct: &ResponsesToolChoiceStruct{Type: ResponsesToolChoiceTypeFileSearch}}}},
			"tool_choice.type", "file_search tools"},
		{"allowed hosted tool", BifrostResponsesRequest{Params: &ResponsesParameters{Tools: []ResponsesTool{function},
			ToolChoice: &ResponsesToolChoice{ResponsesToolChoiceStruct: &ResponsesToolChoiceStruct{
				Type: ResponsesToolChoiceTypeAllowedTools, Tools: []ResponsesToolChoiceAllowedToolDef{{Type: "function", Name: Ptr("lookup")}, {Type: "mcp"}},
			}}}}, "tool_choice.tools[1].type", "mcp tools"},
		{"text format", BifrostResponsesRequest{Params: &ResponsesParameters{Text: &ResponsesTextConfig{Format: &ResponsesTextConfigFormat{Type: "grammar"}}}},
			"text.format.type", "the grammar text format"},
		{"hosted item", BifrostResponsesRequest{Input: []ResponsesMessage{message(ResponsesInputMessageRoleUser, text(ResponsesInputMessageContentBlockTypeText)),
			{Type: Ptr(ResponsesMessageTypeItemReference)}}}, "input[1].type", "item_reference items"},
		{"custom tool call", BifrostResponsesRequest{Input: []ResponsesMessage{{Type: Ptr(ResponsesMessageTypeCustomToolCall)}}},
			"input[0].type", "custom_tool_call items"},
		{"custom tool in a namespace", BifrostResponsesRequest{Params: &ResponsesParameters{Tools: []ResponsesTool{function, {
			Type: ResponsesToolTypeNamespace, Name: Ptr("crm"), ResponsesToolNamespace: &ResponsesToolNamespace{Tools: []ResponsesTool{
				{Type: ResponsesToolTypeFunction, Name: Ptr("find")}, {Type: ResponsesToolTypeCustom, Name: Ptr("query")},
			}},
		}}}}, "tools[1].tools[1].type", "custom tools"},
		{"call to an undeclared namespace", BifrostResponsesRequest{
			Params: &ResponsesParameters{Tools: []ResponsesTool{{Type: ResponsesToolTypeNamespace, Name: Ptr("crm"),
				ResponsesToolNamespace: &ResponsesToolNamespace{Tools: []ResponsesTool{{Type: ResponsesToolTypeFunction, Name: Ptr("find")}}}}}},
			Input: []ResponsesMessage{{Type: Ptr(ResponsesMessageTypeFunctionCall), ResponsesToolMessage: &ResponsesToolMessage{Name: Ptr("f"), Namespace: Ptr("crm")}}},
		}, "input[0].namespace", "calls to namespace tools that tools does not list"},
		{"output text in a user message", BifrostResponsesRequest{Input: []ResponsesMessage{message(ResponsesInputMessageRoleUser, text(ResponsesOutputMessageContentTypeText))}},
			"input[0].content[0].type", "output_text parts in input messages"},
		{"image in an assistant message", BifrostResponsesRequest{Input: []ResponsesMessage{message(ResponsesInputMessageRoleAssistant,
			ResponsesMessageContentBlock{Type: ResponsesInputMessageContentBlockTypeImage})}}, "input[0].content[0].type", "input_image parts in assistant messages"},
		{"media resolution", BifrostResponsesRequest{Input: []ResponsesMessage{message(ResponsesInputMessageRoleUser,
			ResponsesMessageContentBlock{Type: ResponsesInputMessageContentBlockTypeImage, MediaResolution: &MediaResolution{Level: "high"}})}},
			"input[0].content[0].media_resolution", "media resolution settings"},
		{"tool output part", BifrostResponsesRequest{Input: []ResponsesMessage{{Type: Ptr(ResponsesMessageTypeFunctionCallOutput),
			ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c"), Output: &ResponsesToolMessageOutputStruct{
				ResponsesFunctionToolCallOutputBlocks: []ResponsesMessageContentBlock{text(ResponsesOutputMessageContentTypeRefusal)},
			}}}}}, "input[0].output[0].type", "refusal parts in tool outputs"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gap := test.request.ChatCompletionsGap()
			if gap == nil || gap.Param != test.param || gap.Feature != test.feature {
				t.Fatalf("gap = %+v, want %s: %s", gap, test.param, test.feature)
			}
		})
	}
}

func TestChatCompletionsGapAcceptsWhatChatCompletionsCarry(t *testing.T) {
	request := BifrostResponsesRequest{
		Params: &ResponsesParameters{
			Include:    []string{responsesIncludeLogProbs, responsesIncludeEncryptedReasoning},
			Truncation: Ptr("disabled"),
			Reasoning:  &ResponsesParametersReasoning{Effort: Ptr("high"), Summary: Ptr("auto"), Context: Ptr("auto")},
			Tools: []ResponsesTool{{Type: ResponsesToolTypeFunction, Name: Ptr("lookup")}, {Type: ResponsesToolTypeNamespace, Name: Ptr("crm"),
				ResponsesToolNamespace: &ResponsesToolNamespace{Tools: []ResponsesTool{{Type: ResponsesToolTypeFunction, Name: Ptr("find")}}}}},
			ToolChoice: &ResponsesToolChoice{ResponsesToolChoiceStruct: &ResponsesToolChoiceStruct{
				Type: ResponsesToolChoiceTypeAllowedTools, Tools: []ResponsesToolChoiceAllowedToolDef{{Type: "function", Name: Ptr("lookup")}},
			}},
			Text: &ResponsesTextConfig{Format: &ResponsesTextConfigFormat{Type: "json_object"}},
		},
		Input: []ResponsesMessage{
			{Role: Ptr(ResponsesInputMessageRoleDeveloper), Content: &ResponsesMessageContent{ContentStr: Ptr("Be brief.")}},
			{Role: Ptr(ResponsesInputMessageRoleUser), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
				{Type: ResponsesInputMessageContentBlockTypeText, Text: Ptr("Look")},
				{Type: ResponsesInputMessageContentBlockTypeImage, ResponsesInputMessageContentBlockImage: &ResponsesInputMessageContentBlockImage{ImageURL: Ptr("https://example.com/a.png")}},
				{Type: ResponsesInputMessageContentBlockTypeFile, ResponsesInputMessageContentBlockFile: &ResponsesInputMessageContentBlockFile{FileData: Ptr("data:application/pdf;base64,AA==")}},
			}}},
			{Type: Ptr(ResponsesMessageTypeReasoning), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
				{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr("think")},
			}}},
			{Role: Ptr(ResponsesInputMessageRoleAssistant), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
				{Type: ResponsesOutputMessageContentTypeText, Text: Ptr("Calling.")},
				{Type: ResponsesOutputMessageContentTypeRefusal, ResponsesOutputMessageContentRefusal: &ResponsesOutputMessageContentRefusal{Refusal: "no"}},
			}}},
			{Type: Ptr(ResponsesMessageTypeFunctionCall), ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c1"), Name: Ptr("lookup"), Arguments: Ptr("{}")}},
			{Type: Ptr(ResponsesMessageTypeFunctionCallOutput), ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c1"),
				Output: &ResponsesToolMessageOutputStruct{ResponsesToolCallOutputStr: Ptr("42")}}},
			// The flattening renames a call to a declared namespace tool, and functions holds top-level tools.
			{Type: Ptr(ResponsesMessageTypeFunctionCall), ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c2"), Name: Ptr("find"), Namespace: Ptr("crm"), Arguments: Ptr("{}")}},
			{Type: Ptr(ResponsesMessageTypeFunctionCall), ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c3"), Name: Ptr("lookup"), Namespace: Ptr("functions"), Arguments: Ptr("{}")}},
		},
	}
	if gap := request.ChatCompletionsGap(); gap != nil {
		t.Fatalf("gap = %+v, want none", gap)
	}
	var none *BifrostResponsesRequest
	if gap := none.ChatCompletionsGap(); gap != nil {
		t.Fatalf("nil request gap = %+v", gap)
	}
}

func TestToChatRequestCarriesParameters(t *testing.T) {
	tools := []ResponsesTool{
		{Type: ResponsesToolTypeFunction, Name: Ptr("a"), CacheControl: &CacheControl{Type: CacheControlTypeEphemeral}, DeferLoading: Ptr(true)},
		{Type: ResponsesToolTypeFunction, Name: Ptr("b"), Description: Ptr("B"), ResponsesToolFunction: &ResponsesToolFunction{Strict: Ptr(true)}},
		{Type: ResponsesToolTypeFunction, Name: Ptr(" ")},
		{Type: ResponsesToolTypeWebSearch},
	}
	request := &BifrostResponsesRequest{
		Model: "m",
		Params: &ResponsesParameters{
			FrequencyPenalty: Ptr(0.1), PresencePenalty: Ptr(0.2), Temperature: Ptr(0.3), TopP: Ptr(0.4),
			MaxOutputTokens: Ptr(100), User: Ptr("u"), SafetyIdentifier: Ptr("s"), Store: Ptr(false),
			ParallelToolCalls: Ptr(false), PromptCacheKey: Ptr("k"), Metadata: &map[string]any{"a": "b"},
			Include: []string{responsesIncludeLogProbs}, TopLogProbs: Ptr(3),
			StreamOptions: &ResponsesStreamOptions{IncludeObfuscation: Ptr(false)},
			Reasoning:     &ResponsesParametersReasoning{Effort: Ptr("low"), GenerateSummary: Ptr("auto")},
			Text:          &ResponsesTextConfig{Format: &ResponsesTextConfigFormat{Type: "json_object"}, Verbosity: Ptr("low")},
			Instructions:  Ptr("Answer in French."),
			Tools:         tools,
			ToolChoice: &ResponsesToolChoice{ResponsesToolChoiceStruct: &ResponsesToolChoiceStruct{
				Type: ResponsesToolChoiceTypeAllowedTools, Mode: Ptr("required"),
				Tools: []ResponsesToolChoiceAllowedToolDef{{Type: "function", Name: Ptr("b")}},
			}},
			ExtraParams: map[string]any{"top_k": 5},
		},
		Input: []ResponsesMessage{{Role: Ptr(ResponsesInputMessageRoleDeveloper), Content: &ResponsesMessageContent{ContentStr: Ptr("Be brief.")}}},
	}
	chat := request.ToChatRequest()
	p := chat.Params
	if *p.FrequencyPenalty != 0.1 || *p.PresencePenalty != 0.2 || *p.Temperature != 0.3 || *p.TopP != 0.4 ||
		*p.MaxCompletionTokens != 100 || *p.User != "u" || *p.SafetyIdentifier != "s" || *p.Store ||
		*p.ParallelToolCalls || *p.PromptCacheKey != "k" || (*p.Metadata)["a"] != "b" || p.ExtraParams["top_k"] != 5 {
		t.Fatalf("parameters were not carried: %+v", p)
	}
	if p.LogProbs == nil || !*p.LogProbs || p.TopLogProbs == nil || *p.TopLogProbs != 3 {
		t.Fatalf("logprobs = %v, top_logprobs = %v", p.LogProbs, p.TopLogProbs)
	}
	if p.StreamOptions == nil || p.StreamOptions.IncludeUsage == nil || !*p.StreamOptions.IncludeUsage || *p.StreamOptions.IncludeObfuscation {
		t.Fatalf("stream_options = %+v", p.StreamOptions)
	}
	if p.Reasoning == nil || *p.Reasoning.Effort != "low" || *p.Reasoning.Summary != "auto" {
		t.Fatalf("reasoning = %+v", p.Reasoning)
	}
	if p.Verbosity == nil || *p.Verbosity != "low" || responseFormatAsMap(t, p.ResponseFormat)["type"] != "json_object" {
		t.Fatalf("text = %v, %v", p.Verbosity, p.ResponseFormat)
	}
	// allowed_tools keeps only the allowed tool, and the choice's mode chooses among them.
	if len(p.Tools) != 1 || p.Tools[0].Function.Name != "b" || *p.Tools[0].Function.Description != "B" || !*p.Tools[0].Function.Strict {
		t.Fatalf("tools = %+v", p.Tools)
	}
	if p.ToolChoice == nil || p.ToolChoice.ChatToolChoiceStr == nil || *p.ToolChoice.ChatToolChoiceStr != "required" {
		t.Fatalf("tool_choice = %+v", p.ToolChoice)
	}
	if len(chat.Input) != 2 || chat.Input[0].Role != ChatMessageRoleSystem || *chat.Input[0].Content.ContentStr != "Answer in French." ||
		chat.Input[1].Role != ChatMessageRoleSystem {
		t.Fatalf("input = %+v", chat.Input)
	}

	// Without allowed_tools, every function tool keeps its cache mark and Anthropic flags.
	request.Params.ToolChoice = &ResponsesToolChoice{ResponsesToolChoiceStruct: &ResponsesToolChoiceStruct{Type: ResponsesToolChoiceTypeAny}}
	request.Params.Include = nil
	p = request.ToChatRequest().Params
	if len(p.Tools) != 2 || p.Tools[0].CacheControl == nil || p.Tools[0].DeferLoading == nil || !*p.Tools[0].DeferLoading {
		t.Fatalf("tools = %+v", p.Tools)
	}
	if p.ToolChoice == nil || *p.ToolChoice.ChatToolChoiceStr != "required" {
		t.Fatalf("any tool choice = %+v, want required", p.ToolChoice)
	}
	if p.LogProbs != nil || p.TopLogProbs != nil {
		t.Fatalf("top_logprobs without include must stay out: %v, %v", p.LogProbs, p.TopLogProbs)
	}
}

func TestToChatMessagesJoinsAnAssistantTurn(t *testing.T) {
	cache := &CacheControl{Type: CacheControlTypeEphemeral}
	items := []ResponsesMessage{
		{Role: Ptr(ResponsesInputMessageRoleUser), Content: &ResponsesMessageContent{ContentStr: Ptr("Weather?")}},
		{Type: Ptr(ResponsesMessageTypeReasoning), ID: Ptr("rs_1"), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
			{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr("Need ")},
			{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr("a tool.")},
		}}},
		{Role: Ptr(ResponsesInputMessageRoleAssistant), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
			{Type: ResponsesOutputMessageContentTypeText, Text: Ptr("Checking.")},
		}}},
		{Type: Ptr(ResponsesMessageTypeFunctionCall), CacheControl: cache, ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c1"), Name: Ptr("weather"), Arguments: Ptr(`{"city":"Paris"}`)}},
		{Type: Ptr(ResponsesMessageTypeFunctionCall), ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c2"), Name: Ptr("time")}},
		{Type: Ptr(ResponsesMessageTypeFunctionCallOutput), Status: Ptr(ResponsesResponseStatusIncomplete),
			ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c1"), Output: &ResponsesToolMessageOutputStruct{ResponsesToolCallOutputStr: Ptr("rain")}}},
		{Type: Ptr(ResponsesMessageTypeFunctionCallOutput), CacheControl: cache, ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c2")}},
		{Type: Ptr(ResponsesMessageTypeRefusal), Content: &ResponsesMessageContent{ContentStr: Ptr("I can't share that.")}},
		{Role: Ptr(ResponsesInputMessageRoleUser), Content: &ResponsesMessageContent{ContentStr: Ptr("Thanks")}},
	}
	messages := ToChatMessages(items)
	if len(messages) != 6 {
		t.Fatalf("messages = %d, want user, assistant, tool, tool, assistant, user: %+v", len(messages), messages)
	}
	turn := messages[1]
	if turn.Role != ChatMessageRoleAssistant || *turn.Content.ContentStr != "Checking." || *turn.Reasoning != "Need a tool." ||
		turn.ReasoningDetails != nil {
		t.Fatalf("assistant turn = %+v", turn)
	}
	calls := turn.ToolCalls
	if len(calls) != 2 || *calls[0].ID != "c1" || *calls[0].Function.Name != "weather" || calls[0].Function.Arguments != `{"city":"Paris"}` ||
		calls[0].CacheControl != cache || calls[1].Index != 1 || calls[1].Function.Arguments != "" || *calls[1].Type != "function" {
		t.Fatalf("calls = %+v", calls)
	}
	if out := messages[2]; out.Role != ChatMessageRoleTool || *out.ToolCallID != "c1" || *out.Content.ContentStr != "rain" || out.IsError == nil || !*out.IsError {
		t.Fatalf("first tool message = %+v", out)
	}
	if out := messages[3]; *out.ToolCallID != "c2" || len(out.Content.ContentBlocks) != 1 || *out.Content.ContentBlocks[0].Text != "" ||
		out.Content.ContentBlocks[0].CacheControl != cache || out.IsError != nil {
		t.Fatalf("second tool message = %+v", out)
	}
	if refusal := messages[4]; refusal.Role != ChatMessageRoleAssistant || *refusal.Refusal != "I can't share that." || refusal.Content != nil {
		t.Fatalf("refusal = %+v", refusal)
	}
}

func TestToChatMessagesKeepsSignedReasoningAndMarkedText(t *testing.T) {
	cache := &CacheControl{Type: CacheControlTypeEphemeral}
	messages := ToChatMessages([]ResponsesMessage{
		{Type: Ptr(ResponsesMessageTypeReasoning), ID: Ptr("rs_1"),
			Content:            &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr("think"), Signature: Ptr("sig")}}},
			ResponsesReasoning: &ResponsesReasoning{Summary: []ResponsesReasoningSummary{{Type: ResponsesReasoningContentBlockTypeSummaryText, Text: "sum"}}, EncryptedContent: Ptr("enc")}},
		{Role: Ptr(ResponsesInputMessageRoleAssistant), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
			{Type: ResponsesOutputMessageContentTypeText, Text: Ptr("a")},
			{Type: ResponsesOutputMessageContentTypeText, Text: Ptr("b"), CacheControl: cache},
		}}},
	})
	if len(messages) != 1 {
		t.Fatalf("messages = %+v", messages)
	}
	turn := messages[0]
	want := []ChatReasoningDetails{
		{ID: Ptr("rs_1"), Index: 0, Type: BifrostReasoningDetailsTypeText, Text: Ptr("think"), Signature: Ptr("sig")},
		{ID: Ptr("rs_1"), Index: 1, Type: BifrostReasoningDetailsTypeSummary, Summary: Ptr("sum")},
		{ID: Ptr("rs_1"), Index: 2, Type: BifrostReasoningDetailsTypeEncrypted, Data: Ptr("enc")},
	}
	if !reflect.DeepEqual(turn.ReasoningDetails, want) || *turn.Reasoning != "think" {
		t.Fatalf("reasoning = %v, details = %+v", turn.Reasoning, turn.ReasoningDetails)
	}
	blocks := turn.Content.ContentBlocks
	if len(blocks) != 2 || *blocks[0].Text != "a" || blocks[1].CacheControl != cache || blocks[0].Type != ChatContentBlockTypeText {
		t.Fatalf("content = %+v", turn.Content)
	}
	// A turn with only reasoning still has content, which Chat Completions requires without calls.
	reasoningOnly := ToChatMessages([]ResponsesMessage{{Type: Ptr(ResponsesMessageTypeReasoning), Content: &ResponsesMessageContent{
		ContentBlocks: []ResponsesMessageContentBlock{{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr("t")}},
	}}})
	if len(reasoningOnly) != 1 || reasoningOnly[0].Content == nil || *reasoningOnly[0].Content.ContentStr != "" {
		t.Fatalf("reasoning-only turn = %+v", reasoningOnly)
	}
}

// chatReply is a Chat Completions reply with reasoning, text, a refusal and two tool calls.
func chatReply(finish string) *BifrostChatResponse {
	return &BifrostChatResponse{
		ID: "chatcmpl-1", Created: 100, Model: "m",
		Usage: &BifrostLLMUsage{PromptTokens: 3, CompletionTokens: 5, TotalTokens: 8},
		Choices: []BifrostResponseChoice{{
			FinishReason: Ptr(finish),
			ChatNonStreamResponseChoice: &ChatNonStreamResponseChoice{Message: &ChatMessage{
				Role:    ChatMessageRoleAssistant,
				Content: &ChatMessageContent{ContentStr: Ptr("Checking.")},
				ChatAssistantMessage: &ChatAssistantMessage{
					Reasoning: Ptr("Need tools."),
					ToolCalls: []ChatAssistantMessageToolCall{
						{ID: Ptr("c1"), Type: Ptr("function"), Function: ChatAssistantMessageToolCallFunction{Name: Ptr("weather"), Arguments: `{"city":"Paris"}`}},
						{Index: 1, ID: Ptr("c2"), Type: Ptr("function"), Function: ChatAssistantMessageToolCallFunction{Name: Ptr("time"), Arguments: "{}"}},
					},
				},
			}},
		}},
	}
}

func TestToBifrostResponsesResponseOrdersOutput(t *testing.T) {
	response := chatReply("tool_calls").ToBifrostResponsesResponse()
	if *response.ID != "chatcmpl-1" || *response.Status != ResponsesResponseStatusCompleted || *response.StopReason != "tool_calls" ||
		response.CompletedAt == nil || response.Usage.TotalTokens != 8 || response.ExtraFields.RequestType != ResponsesRequest {
		t.Fatalf("response = %+v", response)
	}
	var kinds, ids []string
	for _, item := range response.Output {
		kinds = append(kinds, string(*item.Type))
		ids = append(ids, *item.ID)
	}
	if !reflect.DeepEqual(kinds, []string{"reasoning", "message", "function_call", "function_call"}) ||
		!reflect.DeepEqual(ids, []string{"rs_chatcmpl-1_0", "msg_chatcmpl-1_1", "fc_chatcmpl-1_2", "fc_chatcmpl-1_3"}) {
		t.Fatalf("output = %v %v", kinds, ids)
	}
	if text := *response.Output[0].Content.ContentBlocks[0].Text; text != "Need tools." {
		t.Fatalf("reasoning = %q", text)
	}

	cut := chatReply("length").ToBifrostResponsesResponse()
	if *cut.Status != ResponsesResponseStatusIncomplete || cut.IncompleteDetails.Reason != ResponsesResponseIncompleteReasonMaxOutputTokens ||
		cut.CompletedAt != nil || *cut.Output[3].Status != ResponsesResponseStatusIncomplete || *cut.Output[2].Status != ResponsesResponseStatusCompleted {
		t.Fatalf("cut reply = %+v", cut)
	}

	long := chatReply("stop")
	long.ID = strings.Repeat("x", 100)
	if converted := long.ToBifrostResponsesResponse(); *converted.ID != long.ID || len(*converted.Output[0].ID) > 40 {
		t.Fatalf("long ID = %q, item ID = %q", *converted.ID, *converted.Output[0].ID)
	}
}

func TestToBifrostResponsesResponseCarriesLogProbsAndCitations(t *testing.T) {
	reply := &BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{
		FinishReason: Ptr("stop"),
		LogProbs:     &BifrostLogProbs{Content: []ContentLogProb{{Token: "Hi", LogProb: -0.1, TopLogProbs: []LogProb{{Token: "Hi", LogProb: -0.1}}}}},
		ChatNonStreamResponseChoice: &ChatNonStreamResponseChoice{Message: &ChatMessage{
			Role:    ChatMessageRoleAssistant,
			Content: &ChatMessageContent{ContentBlocks: []ChatContentBlock{{Type: ChatContentBlockTypeText, Text: Ptr("Hi")}, {Type: ChatContentBlockTypeRefusal, Refusal: Ptr("no")}}},
			ChatAssistantMessage: &ChatAssistantMessage{Annotations: []ChatAssistantMessageAnnotation{{
				Type: "url_citation", URLCitation: ChatAssistantMessageAnnotationCitation{StartIndex: 0, EndIndex: 2, Title: "T", URL: Ptr("https://example.com")},
			}}},
		}},
	}}}
	blocks := reply.ToBifrostResponsesResponse().Output[0].Content.ContentBlocks
	if len(blocks) != 2 || blocks[1].Type != ResponsesOutputMessageContentTypeRefusal || blocks[1].ResponsesOutputMessageContentRefusal.Refusal != "no" {
		t.Fatalf("blocks = %+v", blocks)
	}
	text := blocks[0].ResponsesOutputMessageContentText
	if len(text.LogProbs) != 1 || text.LogProbs[0].Token != "Hi" || len(text.LogProbs[0].TopLogProbs) != 1 ||
		len(text.Annotations) != 1 || *text.Annotations[0].URL != "https://example.com" || *text.Annotations[0].EndIndex != 2 {
		t.Fatalf("text part = %+v", text)
	}
}

// A provider that lists the tokens of the reasoning and the tool calls with the text's, as vLLM
// does, gives the text only the run of tokens that spells it.
func TestReplyTextTakesOnlyItsOwnLogProbs(t *testing.T) {
	tokens := func(texts ...string) []ContentLogProb {
		out := make([]ContentLogProb, len(texts))
		for i, text := range texts {
			out[i] = ContentLogProb{Token: text, LogProb: -float64(i)}
		}
		return out
	}
	calls := []ChatAssistantMessageToolCall{{ID: Ptr("c1"), Function: ChatAssistantMessageToolCallFunction{Name: Ptr("f"), Arguments: "{}"}}}
	tests := []struct {
		name      string
		text      string
		reasoning *string
		calls     []ChatAssistantMessageToolCall
		tokens    []ContentLogProb
		want      []string
	}{
		{"only text", "Hi \u00e9", nil, nil, tokens("Hi", " \ufffd", "\ufffd"), []string{"Hi", " \ufffd", "\ufffd"}},
		{"reasoning first", "4", Ptr("So: 4"), nil, tokens("So", ":", " ", "4", "</think>", "\n\n", "", "4", "", "<|im_end|>"), []string{"4"}},
		{"calls after", "Checking.", nil, calls, tokens("Checking", ".", "<tool_call>", `{"q":"x"}`, "</tool_call>"), []string{"Checking", "."}},
		{"calls that repeat the text", "x", nil, calls, tokens("x", "<tool_call>", `{"q":"`, "x", `"}`), []string{"x"}},
		{"reasoning that repeats the text before calls", "I'll check.", Ptr("I'll check."), calls,
			tokens("I'll", " check", ".", "</think>", "I'll", " check", ".", "<tool_call>", `{"q":1}`, "</tool_call>"), []string{"I'll", " check", "."}},
		{"calls after reasoning that the tokens do not spell", "x", Ptr("r"), calls, tokens("x", "<tool_call>", `{"q":"`, "x", `"}`), nil},
		{"split character", "\u00e9", Ptr("r"), nil, tokens("r", "</think>", "\ufffd", "\ufffd"), nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reply := &BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{
				FinishReason: Ptr("stop"),
				LogProbs:     &BifrostLogProbs{Content: test.tokens},
				ChatNonStreamResponseChoice: &ChatNonStreamResponseChoice{Message: &ChatMessage{
					Role:                 ChatMessageRoleAssistant,
					Content:              &ChatMessageContent{ContentStr: Ptr(test.text)},
					ChatAssistantMessage: &ChatAssistantMessage{Reasoning: test.reasoning, ToolCalls: test.calls},
				}},
			}}}
			var got []string
			for _, item := range reply.ToBifrostResponsesResponse().Output {
				if *item.Type == ResponsesMessageTypeMessage {
					for _, token := range item.Content.ContentBlocks[0].LogProbs {
						got = append(got, token.Token)
					}
				}
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("text tokens = %q, want %q", got, test.want)
			}
		})
	}

	// A stream chunk that holds the end of the reasoning and the start of the text gives the text
	// the text's tokens.
	state := AcquireChatToResponsesStreamState()
	defer ReleaseChatToResponsesStreamState(state)
	chunk := &BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{
		LogProbs:                 &BifrostLogProbs{Content: tokens("done", "</think>", "Hi")},
		ChatStreamResponseChoice: &ChatStreamResponseChoice{Delta: &ChatStreamResponseChoiceDelta{Reasoning: Ptr("done"), Content: Ptr("Hi")}},
	}}}
	var deltas int
	for _, event := range chunk.ToBifrostResponsesStreamResponse(state) {
		if event.Type == ResponsesStreamResponseTypeOutputTextDelta {
			deltas++
			if len(event.LogProbs) != 1 || event.LogProbs[0].Token != "Hi" {
				t.Fatalf("text delta tokens = %+v", event.LogProbs)
			}
		}
	}
	if deltas != 1 {
		t.Fatalf("%d text deltas", deltas)
	}
}

// streamOf streams a reply as a provider would: reasoning, text and the tool calls, each in
// pieces, with the second tool call's arguments split around more text, then the finish reason
// and a chunk with only the usage.
func streamOf(reply *BifrostChatResponse) []*BifrostChatResponse {
	message := reply.Choices[0].ChatNonStreamResponseChoice.Message
	chunk := func(delta ChatStreamResponseChoiceDelta, finish *string) *BifrostChatResponse {
		return &BifrostChatResponse{ID: reply.ID, Created: reply.Created, Model: reply.Model, Choices: []BifrostResponseChoice{{
			FinishReason: finish, ChatStreamResponseChoice: &ChatStreamResponseChoice{Delta: &delta},
		}}}
	}
	reasoning := *message.Reasoning
	text := *message.Content.ContentStr
	calls := message.ToolCalls
	return []*BifrostChatResponse{
		{Choices: []BifrostResponseChoice{}},
		chunk(ChatStreamResponseChoiceDelta{Role: Ptr("assistant"), Reasoning: Ptr(reasoning[:4])}, nil),
		chunk(ChatStreamResponseChoiceDelta{Reasoning: Ptr(reasoning[4:])}, nil),
		chunk(ChatStreamResponseChoiceDelta{Content: Ptr(text[:3])}, nil),
		chunk(ChatStreamResponseChoiceDelta{ToolCalls: []ChatAssistantMessageToolCall{{ID: calls[0].ID, Function: ChatAssistantMessageToolCallFunction{Name: calls[0].Function.Name, Arguments: calls[0].Function.Arguments}}}}, nil),
		chunk(ChatStreamResponseChoiceDelta{ToolCalls: []ChatAssistantMessageToolCall{{Index: 1, ID: calls[1].ID, Function: ChatAssistantMessageToolCallFunction{Name: calls[1].Function.Name, Arguments: "{"}}}}, nil),
		chunk(ChatStreamResponseChoiceDelta{Content: Ptr(text[3:]), ToolCalls: []ChatAssistantMessageToolCall{{Index: 1, Function: ChatAssistantMessageToolCallFunction{Arguments: "}"}}}}, nil),
		chunk(ChatStreamResponseChoiceDelta{}, reply.Choices[0].FinishReason),
		{ID: reply.ID, Choices: []BifrostResponseChoice{}, Usage: reply.Usage},
	}
}

// contiguous checks that each item's events come between its output_item.added and
// output_item.done, and that no two items are open at once.
func contiguous(t *testing.T, events []*BifrostResponsesStreamResponse) {
	t.Helper()
	open := -1
	for i, event := range events {
		switch {
		case event.Type == ResponsesStreamResponseTypeOutputItemAdded:
			if open != -1 {
				t.Fatalf("event %d opens item %d while item %d is open", i, *event.OutputIndex, open)
			}
			open = *event.OutputIndex
		case event.Type == ResponsesStreamResponseTypeOutputItemDone:
			if *event.OutputIndex != open {
				t.Fatalf("event %d completes item %d while item %d is open", i, *event.OutputIndex, open)
			}
			open = -1
		case event.OutputIndex != nil && *event.OutputIndex != open:
			t.Fatalf("event %d (%s) is about item %d while item %d is open", i, event.Type, *event.OutputIndex, open)
		}
		if event.SequenceNumber != i {
			t.Fatalf("event %d has sequence number %d", i, event.SequenceNumber)
		}
	}
}

func TestStreamEndsAsTheUnaryReply(t *testing.T) {
	for _, finish := range []string{"tool_calls", "length"} {
		t.Run(finish, func(t *testing.T) {
			reply := chatReply(finish)
			state := AcquireChatToResponsesStreamState()
			defer ReleaseChatToResponsesStreamState(state)
			var events []*BifrostResponsesStreamResponse
			for _, chunk := range streamOf(reply) {
				events = append(events, chunk.ToBifrostResponsesStreamResponse(state)...)
			}
			contiguous(t, events)
			terminal := events[len(events)-1]
			unary := reply.ToBifrostResponsesResponse()
			wantType := ResponsesStreamResponseTypeCompleted
			if finish == "length" {
				wantType = ResponsesStreamResponseTypeIncomplete
			}
			if terminal.Type != wantType || *terminal.Response.Status != *unary.Status || *terminal.Response.ID != *unary.ID {
				t.Fatalf("terminal = %s %+v", terminal.Type, terminal.Response)
			}
			got, _ := json.Marshal(terminal.Response.Output)
			want, _ := json.Marshal(unary.Output)
			if string(got) != string(want) {
				t.Fatalf("stream output\n%s\nunary output\n%s", got, want)
			}
			var reasoning, text strings.Builder
			for _, event := range events {
				switch event.Type {
				case ResponsesStreamResponseTypeReasoningTextDelta:
					reasoning.WriteString(*event.Delta)
				case ResponsesStreamResponseTypeOutputTextDelta:
					text.WriteString(*event.Delta)
				case ResponsesStreamResponseTypeOutputItemDone:
					if *event.Item.ID != *terminal.Response.Output[*event.OutputIndex].ID {
						t.Fatalf("item %d done with ID %s", *event.OutputIndex, *event.Item.ID)
					}
				}
			}
			if reasoning.String() != "Need tools." || text.String() != "Checking." {
				t.Fatalf("deltas: reasoning %q, text %q", reasoning.String(), text.String())
			}
		})
	}
}

// A refusal that follows text closes the text part and opens a refusal part, as the unary reply
// holds both.
func TestStreamTextThenRefusal(t *testing.T) {
	chunk := func(delta ChatStreamResponseChoiceDelta, finish *string) *BifrostChatResponse {
		return &BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{FinishReason: finish, ChatStreamResponseChoice: &ChatStreamResponseChoice{Delta: &delta}}}}
	}
	state := AcquireChatToResponsesStreamState()
	defer ReleaseChatToResponsesStreamState(state)
	var events []*BifrostResponsesStreamResponse
	for _, c := range []*BifrostChatResponse{
		chunk(ChatStreamResponseChoiceDelta{Content: Ptr("Well. ")}, nil),
		chunk(ChatStreamResponseChoiceDelta{Refusal: Ptr("No.")}, nil),
		chunk(ChatStreamResponseChoiceDelta{}, Ptr("stop")),
	} {
		events = append(events, c.ToBifrostResponsesStreamResponse(state)...)
	}
	contiguous(t, events)
	unary := (&BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{
		FinishReason: Ptr("stop"),
		ChatNonStreamResponseChoice: &ChatNonStreamResponseChoice{Message: &ChatMessage{
			Role: ChatMessageRoleAssistant, Content: &ChatMessageContent{ContentStr: Ptr("Well. ")},
			ChatAssistantMessage: &ChatAssistantMessage{Refusal: Ptr("No.")},
		}},
	}}}).ToBifrostResponsesResponse()
	got, _ := json.Marshal(events[len(events)-1].Response.Output)
	want, _ := json.Marshal(unary.Output)
	if string(got) != string(want) {
		t.Fatalf("stream output\n%s\nunary output\n%s", got, want)
	}
}

func TestStreamToolCallQuirks(t *testing.T) {
	chunk := func(delta ChatStreamResponseChoiceDelta, finish *string) *BifrostChatResponse {
		return &BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{FinishReason: finish, ChatStreamResponseChoice: &ChatStreamResponseChoice{Delta: &delta}}}}
	}
	call := func(id, name *string, arguments string) ChatStreamResponseChoiceDelta {
		return ChatStreamResponseChoiceDelta{ToolCalls: []ChatAssistantMessageToolCall{{ID: id, Function: ChatAssistantMessageToolCallFunction{Name: name, Arguments: arguments}}}}
	}
	run := func(chunks ...*BifrostChatResponse) []*BifrostResponsesStreamResponse {
		state := AcquireChatToResponsesStreamState()
		defer ReleaseChatToResponsesStreamState(state)
		var events []*BifrostResponsesStreamResponse
		for _, c := range chunks {
			events = append(events, c.ToBifrostResponsesStreamResponse(state)...)
		}
		return events
	}

	// Every call at index 0, each with its own ID, and a call without an ID.
	events := run(
		chunk(call(Ptr("a"), Ptr("one"), `{"x":1}`), nil),
		chunk(call(Ptr("b"), Ptr("two"), "{}"), nil),
		chunk(ChatStreamResponseChoiceDelta{}, Ptr("tool_calls")),
	)
	output := events[len(events)-1].Response.Output
	if len(output) != 2 || *output[0].CallID != "a" || *output[0].Arguments != `{"x":1}` || *output[1].CallID != "b" || *output[1].Name != "two" {
		t.Fatalf("calls = %+v", output)
	}
	events = run(chunk(call(nil, Ptr("one"), "{}"), nil), chunk(ChatStreamResponseChoiceDelta{}, Ptr("tool_calls")))
	if output := events[len(events)-1].Response.Output; len(output) != 1 || !strings.HasPrefix(*output[0].CallID, "call_") {
		t.Fatalf("call without an ID = %+v", output)
	}

	// What the conversion cannot represent ends the stream with an error event.
	for name, chunks := range map[string][]*BifrostChatResponse{
		"call without a name": {chunk(call(Ptr("a"), nil, "{}"), nil), chunk(ChatStreamResponseChoiceDelta{}, Ptr("tool_calls"))},
		"second choice":       {{ID: "c", Choices: []BifrostResponseChoice{{Index: 1, ChatStreamResponseChoice: &ChatStreamResponseChoice{Delta: &ChatStreamResponseChoiceDelta{Content: Ptr("x")}}}}}},
		"text after finish":   {chunk(ChatStreamResponseChoiceDelta{Content: Ptr("x")}, Ptr("stop")), chunk(ChatStreamResponseChoiceDelta{Content: Ptr("y")}, nil)},
		// vLLM ends an aborted request with abort, which a reply leaves without a status.
		"unknown finish reason": {chunk(ChatStreamResponseChoiceDelta{Content: Ptr("x")}, Ptr("abort"))},
	} {
		events := run(chunks...)
		if last := events[len(events)-1]; last.Type != ResponsesStreamResponseTypeError || last.Message == nil {
			t.Fatalf("%s: last event = %+v", name, last)
		}
	}
}

// A reply and its stream give each reasoning ID its own item, as OpenAI pairs encrypted reasoning
// with the ID of its item, and leave a finish reason that Responses has no status for to the
// caller.
func TestReplyAndStreamAgree(t *testing.T) {
	details := []ChatReasoningDetails{
		{ID: Ptr("rs_a"), Type: BifrostReasoningDetailsTypeText, Text: Ptr("one")},
		{ID: Ptr("rs_b"), Type: BifrostReasoningDetailsTypeEncrypted, Data: Ptr("ENC_B")},
	}
	want := []string{"rs_a one ", "rs_b  ENC_B"}
	reasoning := func(output []ResponsesMessage) []string {
		var items []string
		for _, item := range output {
			text, encrypted := "", ""
			if item.Content != nil {
				text = *item.Content.ContentBlocks[0].Text
			}
			if item.EncryptedContent != nil {
				encrypted = *item.EncryptedContent
			}
			items = append(items, *item.ID+" "+text+" "+encrypted)
		}
		return items
	}
	reply := &BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{
		FinishReason: Ptr("stop"),
		ChatNonStreamResponseChoice: &ChatNonStreamResponseChoice{Message: &ChatMessage{
			Role: ChatMessageRoleAssistant, ChatAssistantMessage: &ChatAssistantMessage{ReasoningDetails: details},
		}},
	}}}
	if got := reasoning(reply.ToBifrostResponsesResponse().Output); !reflect.DeepEqual(got, want) {
		t.Fatalf("reply reasoning items = %q", got)
	}
	for _, chunks := range [][][]ChatReasoningDetails{{details[:1], details[1:]}, {details}} {
		state := AcquireChatToResponsesStreamState()
		var events []*BifrostResponsesStreamResponse
		for _, chunk := range chunks {
			events = append(events, (&BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{ChatStreamResponseChoice: &ChatStreamResponseChoice{
				Delta: &ChatStreamResponseChoiceDelta{ReasoningDetails: chunk},
			}}}}).ToBifrostResponsesStreamResponse(state)...)
		}
		events = append(events, (&BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{FinishReason: Ptr("stop"),
			ChatStreamResponseChoice: &ChatStreamResponseChoice{Delta: &ChatStreamResponseChoiceDelta{}}}}}).ToBifrostResponsesStreamResponse(state)...)
		ReleaseChatToResponsesStreamState(state)
		contiguous(t, events)
		if got := reasoning(events[len(events)-1].Response.Output); !reflect.DeepEqual(got, want) {
			t.Fatalf("stream of %d chunks: reasoning items = %q", len(chunks), got)
		}
	}

	reply.Choices[0].FinishReason = Ptr("abort")
	if status := reply.ToBifrostResponsesResponse().Status; status != nil {
		t.Fatalf("reply with an unknown finish reason has status %s", *status)
	}
}

func TestStreamReasoningDetails(t *testing.T) {
	state := AcquireChatToResponsesStreamState()
	defer ReleaseChatToResponsesStreamState(state)
	delta := func(details ...ChatReasoningDetails) *BifrostChatResponse {
		return &BifrostChatResponse{ID: "c", Choices: []BifrostResponseChoice{{ChatStreamResponseChoice: &ChatStreamResponseChoice{
			Delta: &ChatStreamResponseChoiceDelta{ReasoningDetails: details},
		}}}}
	}
	var events []*BifrostResponsesStreamResponse
	for _, chunk := range []*BifrostChatResponse{
		delta(ChatReasoningDetails{ID: Ptr("rs_x"), Type: BifrostReasoningDetailsTypeText, Text: Ptr("think")}),
		delta(ChatReasoningDetails{Type: BifrostReasoningDetailsTypeText, Signature: Ptr("sig")}),
		delta(ChatReasoningDetails{Type: BifrostReasoningDetailsTypeSummary, Summary: Ptr("sum")}),
		delta(ChatReasoningDetails{Type: BifrostReasoningDetailsTypeEncrypted, Data: Ptr("enc")}),
		{ID: "c", Choices: []BifrostResponseChoice{{FinishReason: Ptr("stop"), ChatStreamResponseChoice: &ChatStreamResponseChoice{Delta: &ChatStreamResponseChoiceDelta{}}}}},
	} {
		events = append(events, chunk.ToBifrostResponsesStreamResponse(state)...)
	}
	contiguous(t, events)
	var signed, summarized bool
	for _, event := range events {
		if event.ItemID != nil && *event.ItemID != "rs_x" {
			t.Fatalf("event %s names item %s", event.Type, *event.ItemID)
		}
		signed = signed || event.Type == ResponsesStreamResponseTypeReasoningTextDelta && event.Signature != nil && *event.Signature == "sig"
		summarized = summarized || event.Type == ResponsesStreamResponseTypeReasoningSummaryTextDelta && *event.Delta == "sum"
	}
	item := events[len(events)-1].Response.Output[0]
	if !signed || !summarized || *item.ID != "rs_x" || *item.Content.ContentBlocks[0].Signature != "sig" ||
		item.Summary[0].Text != "sum" || *item.EncryptedContent != "enc" {
		t.Fatalf("signed %v, summarized %v, item %+v", signed, summarized, item)
	}
}

// A Chat Completions reply, converted to Responses and sent back as input, is the assistant
// message that the provider gave.
func TestReplyRoundTrip(t *testing.T) {
	reply := chatReply("tool_calls")
	messages := ToChatMessages(reply.ToBifrostResponsesResponse().Output)
	original := reply.Choices[0].ChatNonStreamResponseChoice.Message
	if len(messages) != 1 {
		t.Fatalf("messages = %+v", messages)
	}
	got := messages[0]
	if *got.Content.ContentStr != *original.Content.ContentStr || *got.Reasoning != *original.Reasoning || got.ReasoningDetails != nil {
		t.Fatalf("message = %+v", got)
	}
	for i, call := range got.ToolCalls {
		want := original.ToolCalls[i]
		if *call.ID != *want.ID || *call.Function.Name != *want.Function.Name || call.Function.Arguments != want.Function.Arguments {
			t.Fatalf("call %d = %+v, want %+v", i, call, want)
		}
	}
}
