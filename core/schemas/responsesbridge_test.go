package schemas

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestResponsesGapNamesWhatResponsesCannotCarry(t *testing.T) {
	user := ChatMessage{Role: ChatMessageRoleUser, Content: &ChatMessageContent{ContentStr: Ptr("hi")}}
	params := func(p ChatParameters) BifrostChatRequest {
		return BifrostChatRequest{Params: &p, Input: []ChatMessage{user}}
	}
	messages := func(m ...ChatMessage) BifrostChatRequest { return BifrostChatRequest{Input: m} }
	assistant := func(content *ChatMessageContent, a ChatAssistantMessage) ChatMessage {
		return ChatMessage{Role: ChatMessageRoleAssistant, Content: content, ChatAssistantMessage: &a}
	}
	blocks := func(b ...ChatContentBlock) *ChatMessageContent { return &ChatMessageContent{ContentBlocks: b} }
	text := func(s string) ChatContentBlock { return ChatContentBlock{Type: ChatContentBlockTypeText, Text: Ptr(s)} }
	refusal := ChatContentBlock{Type: ChatContentBlockTypeRefusal, Refusal: Ptr("no")}
	format := func(v any) *any { return &v }
	function := ChatTool{Type: ChatToolTypeFunction, Function: &ChatToolFunction{Name: "lookup"}}
	call := func(c ChatAssistantMessageToolCall) ChatMessage {
		c.ID, c.Function.Name, c.Function.Arguments = Ptr("c1"), Ptr("lookup"), "{}"
		return assistant(nil, ChatAssistantMessage{ToolCalls: []ChatAssistantMessageToolCall{c}})
	}
	tests := []struct {
		name    string
		request BifrostChatRequest
		param   string
		feature string
	}{
		{"audio output", params(ChatParameters{Audio: &ChatAudioParameters{}}), "audio", "audio output"},
		{"logit bias", params(ChatParameters{LogitBias: &map[string]float64{"50256": -100}}), "logit_bias", "logit biases"},
		{"several choices", params(ChatParameters{N: Ptr(2)}), "n", "several choices"},
		{"predicted output", params(ChatParameters{Prediction: &ChatPrediction{Type: "content", Content: "x"}}), "prediction", "predicted outputs"},
		{"seed", params(ChatParameters{Seed: Ptr(7)}), "seed", "seeds"},
		{"stop sequence", params(ChatParameters{Stop: []string{"END"}}), "stop", "stop sequences"},
		{"web search options", params(ChatParameters{WebSearchOptions: &ChatWebSearchOptions{}}), "web_search_options", "web search options"},
		{"top_k", params(ChatParameters{TopK: Ptr(5)}), "top_k", "top_k sampling"},
		{"request cache control", params(ChatParameters{CacheControl: &CacheControl{Type: CacheControlTypeEphemeral}}), "cache_control", "request cache control"},
		{"audio modality", params(ChatParameters{Modalities: []string{"text", "audio"}}), "modalities[1]", "audio output"},
		{"reasoning switch", params(ChatParameters{Reasoning: &ChatReasoning{Enabled: Ptr(true)}}), "reasoning.enabled", "a reasoning on/off switch"},
		{"reasoning display", params(ChatParameters{Reasoning: &ChatReasoning{Display: Ptr("brief")}}), "reasoning.display", "the brief reasoning display"},
		{"untyped response format", params(ChatParameters{ResponseFormat: format(map[string]any{"json_schema": map[string]any{}})}),
			"response_format", "a response format without a type"},
		{"unknown response format", params(ChatParameters{ResponseFormat: format(map[string]any{"type": "grammar"})}),
			"response_format.type", "the grammar response format"},
		{"schema format without its schema", params(ChatParameters{ResponseFormat: format(map[string]any{"type": "json_schema"})}),
			"response_format.json_schema", "a JSON schema format without its json_schema object"},
		{"custom tool", params(ChatParameters{Tools: []ChatTool{function, {Type: ChatToolTypeCustom, Name: "patch"}}}), "tools[1].type", "custom tools"},
		{"Anthropic server tool", params(ChatParameters{Tools: []ChatTool{{Type: "web_search_20250305", Name: "web_search"}}}),
			"tools[0].type", "web_search_20250305 tools"},
		{"custom tool choice", params(ChatParameters{Tools: []ChatTool{function},
			ToolChoice: &ChatToolChoice{ChatToolChoiceStruct: &ChatToolChoiceStruct{Type: ChatToolChoiceTypeCustom}}}), "tool_choice.type", "custom tools"},
		{"allowed custom tool", params(ChatParameters{Tools: []ChatTool{function}, ToolChoice: &ChatToolChoice{ChatToolChoiceStruct: &ChatToolChoiceStruct{
			Type: ChatToolChoiceTypeAllowedTools, AllowedTools: &ChatToolChoiceAllowedTools{Mode: "auto", Tools: []ChatToolChoiceAllowedToolsTool{
				{Type: "function", Function: ChatToolChoiceFunction{Name: "lookup"}}, {Type: "custom"},
			}},
		}}}), "tool_choice.allowed_tools.tools[1].type", "custom tools"},
		{"message name", messages(ChatMessage{Role: ChatMessageRoleUser, Name: Ptr("ann"), Content: user.Content}), "messages[0].name", "message names"},
		{"unknown role", messages(user, ChatMessage{Role: "critic", Content: user.Content}), "messages[1].role", "critic messages"},
		{"refusal in a user message", messages(ChatMessage{Role: ChatMessageRoleUser, Content: blocks(text("x"), refusal)}),
			"messages[0].content[1].type", "refusal parts in input messages"},
		{"image in an assistant message", messages(user, assistant(blocks(ChatContentBlock{Type: ChatContentBlockTypeImage,
			ImageURLStruct: &ChatInputImage{URL: "https://example.com/a.png"}}), ChatAssistantMessage{})),
			"messages[1].content[0].type", "image_url parts in assistant messages"},
		{"refusal in a tool output", messages(ChatMessage{Role: ChatMessageRoleTool, Content: blocks(refusal), ChatToolMessage: &ChatToolMessage{ToolCallID: Ptr("c1")}}),
			"messages[0].content[0].type", "refusal parts in tool outputs"},
		{"cache point", messages(ChatMessage{Role: ChatMessageRoleUser, Content: blocks(text("x"), ChatContentBlock{CachePoint: &CachePoint{Type: "default"}})}),
			"messages[0].content[1].cachePoint", "cache points"},
		{"audio reply", messages(assistant(nil, ChatAssistantMessage{Audio: &ChatAudioMessageAudio{}})), "messages[0].audio", "audio replies"},
		{"image reply", messages(assistant(nil, ChatAssistantMessage{Images: []ChatAssistantMessageImage{{}}})), "messages[0].images", "image replies"},
		{"unknown reasoning detail", messages(assistant(nil, ChatAssistantMessage{ReasoningDetails: []ChatReasoningDetails{
			{Type: BifrostReasoningDetailsTypeText, Text: Ptr("t")}, {Index: 1, Type: "reasoning.redacted"},
		}})), "messages[0].reasoning_details[1].type", "reasoning.redacted reasoning details"},
		{"citation across text parts", messages(assistant(blocks(text("Hello "), text("world")), ChatAssistantMessage{Annotations: []ChatAssistantMessageAnnotation{
			{Type: "url_citation", URLCitation: ChatAssistantMessageAnnotationCitation{StartIndex: 0, EndIndex: 5, URL: Ptr("https://example.com/1")}},
			{Type: "url_citation", URLCitation: ChatAssistantMessageAnnotationCitation{StartIndex: 4, EndIndex: 8, URL: Ptr("https://example.com/2")}},
		}})), "messages[0].annotations[1]", "citations that no single text part holds"},
		{"custom tool call", messages(call(ChatAssistantMessageToolCall{Type: Ptr("custom")})), "messages[0].tool_calls[0].type", "custom tool calls"},
		{"tool call extra content", messages(call(ChatAssistantMessageToolCall{ExtraContent: json.RawMessage(`{"google":{"thought_signature":"x"}}`)})),
			"messages[0].tool_calls[0].extra_content", "extra content on tool calls"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gap := test.request.ResponsesGap()
			if gap == nil || gap.Param != test.param || gap.Feature != test.feature {
				t.Fatalf("gap = %+v, want %s: %s", gap, test.param, test.feature)
			}
		})
	}
}

func TestResponsesGapAcceptsWhatResponsesCarries(t *testing.T) {
	schema := any(map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "answer", "schema": map[string]any{"type": "object"}}})
	request := BifrostChatRequest{
		Params: &ChatParameters{
			N: Ptr(1), LogitBias: &map[string]float64{}, Modalities: []string{"text"}, Stop: []string{},
			LogProbs: Ptr(true), TopLogProbs: Ptr(2), PresencePenalty: Ptr(0.1), FrequencyPenalty: Ptr(0.2),
			Reasoning:      &ChatReasoning{Effort: Ptr("high"), Display: Ptr("summarized"), Mode: Ptr("pro")},
			ResponseFormat: &schema,
			Tools:          []ChatTool{{Type: ChatToolTypeFunction, Function: &ChatToolFunction{Name: "lookup"}}},
			ToolChoice: &ChatToolChoice{ChatToolChoiceStruct: &ChatToolChoiceStruct{Type: ChatToolChoiceTypeAllowedTools,
				AllowedTools: &ChatToolChoiceAllowedTools{Mode: "required", Tools: []ChatToolChoiceAllowedToolsTool{{Type: "function", Function: ChatToolChoiceFunction{Name: "lookup"}}}}}},
		},
		Input: responsesBridgeConversation(),
	}
	if gap := request.ResponsesGap(); gap != nil {
		t.Fatalf("gap = %+v, want none", gap)
	}
	var none *BifrostChatRequest
	if gap := none.ResponsesGap(); gap != nil {
		t.Fatalf("nil request gap = %+v", gap)
	}
}

// responsesBridgeConversation is a conversation with every message and part that Responses
// carries.
func responsesBridgeConversation() []ChatMessage {
	cache := &CacheControl{Type: CacheControlTypeEphemeral}
	return []ChatMessage{
		{Role: ChatMessageRoleSystem, Content: &ChatMessageContent{ContentStr: Ptr("Be brief.")}},
		{Role: ChatMessageRoleDeveloper, Content: &ChatMessageContent{ContentBlocks: []ChatContentBlock{{Type: ChatContentBlockTypeText, Text: Ptr("Cite sources."), CacheControl: cache}}}},
		{Role: ChatMessageRoleUser, Content: &ChatMessageContent{ContentBlocks: []ChatContentBlock{
			{Type: ChatContentBlockTypeText, Text: Ptr("Look")},
			{Type: ChatContentBlockTypeImage, ImageURLStruct: &ChatInputImage{URL: "https://example.com/a.png", Detail: Ptr("low")}},
			{Type: ChatContentBlockTypeImage, ImageURLStruct: &ChatInputImage{FileID: Ptr("file-img")}},
			{Type: ChatContentBlockTypeFile, File: &ChatInputFile{FileData: Ptr("data:application/pdf;base64,AA=="), Filename: Ptr("a.pdf")}},
			{Type: ChatContentBlockTypeFile, File: &ChatInputFile{FileID: Ptr("file-1")}},
			{Type: ChatContentBlockTypeInputAudio, InputAudio: &ChatInputAudio{Data: "UklG", Format: Ptr("wav")}},
		}}},
		{Role: ChatMessageRoleAssistant, Content: &ChatMessageContent{ContentStr: Ptr("Héllo world")}, ChatAssistantMessage: &ChatAssistantMessage{
			ReasoningDetails: []ChatReasoningDetails{
				{ID: Ptr("rs_1"), Index: 0, Type: BifrostReasoningDetailsTypeSummary, Summary: Ptr("Plan.")},
				{ID: Ptr("rs_1"), Index: 1, Type: BifrostReasoningDetailsTypeEncrypted, Data: Ptr("ENC")},
			},
			Annotations: []ChatAssistantMessageAnnotation{{Type: "url_citation", URLCitation: ChatAssistantMessageAnnotationCitation{
				StartIndex: 6, EndIndex: 11, Title: "W", URL: Ptr("https://example.com/w"),
			}}},
			ToolCalls: []ChatAssistantMessageToolCall{
				{ID: Ptr("call_1"), Type: Ptr("function"), Function: ChatAssistantMessageToolCallFunction{Name: Ptr("weather"), Arguments: `{"city":"Paris"}`}},
				{Index: 1, ID: Ptr("call_2"), Type: Ptr("function"), Function: ChatAssistantMessageToolCallFunction{Name: Ptr("time"), Arguments: "{}"}, CacheControl: cache},
			},
		}},
		{Role: ChatMessageRoleTool, Content: &ChatMessageContent{ContentStr: Ptr("rain")}, ChatToolMessage: &ChatToolMessage{ToolCallID: Ptr("call_1")}},
		{Role: ChatMessageRoleTool, Content: &ChatMessageContent{ContentBlocks: []ChatContentBlock{
			{Type: ChatContentBlockTypeText, Text: Ptr("timeout")},
			{Type: ChatContentBlockTypeImage, ImageURLStruct: &ChatInputImage{URL: "https://example.com/c.png"}},
		}}, ChatToolMessage: &ChatToolMessage{ToolCallID: Ptr("call_2"), IsError: Ptr(true)}},
		{Role: ChatMessageRoleTool, ChatToolMessage: &ChatToolMessage{ToolCallID: Ptr("call_3")}},
		{Role: ChatMessageRoleAssistant, Content: &ChatMessageContent{ContentBlocks: []ChatContentBlock{{Type: ChatContentBlockTypeRefusal, Refusal: Ptr("I can't.")}}}},
		{Role: ChatMessageRoleAssistant, Content: &ChatMessageContent{ContentStr: Ptr("")}, ChatAssistantMessage: &ChatAssistantMessage{Reasoning: Ptr("plain")}},
		{Role: ChatMessageRoleAssistant},
	}
}

func jsonEqual(t *testing.T, got any, want string) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var gotValue, wantValue any
	if err := json.Unmarshal(gotJSON, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("want: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("got\n%s\nwant\n%s", gotJSON, want)
	}
}

// Each message becomes the items that a Responses reply gives for it, without the IDs and statuses
// that describe a reply.
func TestToResponsesMessagesConvertsTheConversation(t *testing.T) {
	jsonEqual(t, (&BifrostChatRequest{Input: responsesBridgeConversation()}).ToResponsesRequest().Input, `[
		{"type": "message", "role": "system", "content": "Be brief."},
		{"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "Cite sources.", "cache_control": {"type": "ephemeral"}}]},
		{"type": "message", "role": "user", "content": [
			{"type": "input_text", "text": "Look"},
			{"type": "input_image", "image_url": "https://example.com/a.png", "detail": "low"},
			{"type": "input_image", "file_id": "file-img"},
			{"type": "input_file", "file_data": "data:application/pdf;base64,AA==", "filename": "a.pdf"},
			{"type": "input_file", "file_id": "file-1"},
			{"type": "input_audio", "input_audio": {"format": "wav", "data": "UklG"}}
		]},
		{"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "Plan."}], "encrypted_content": "ENC"},
		{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Héllo world", "logprobs": [],
			"annotations": [{"type": "url_citation", "start_index": 6, "end_index": 11, "title": "W", "url": "https://example.com/w"}]}]},
		{"type": "function_call", "call_id": "call_1", "name": "weather", "arguments": "{\"city\":\"Paris\"}"},
		{"type": "function_call", "call_id": "call_2", "name": "time", "arguments": "{}", "cache_control": {"type": "ephemeral"}},
		{"type": "function_call_output", "call_id": "call_1", "output": "rain"},
		{"type": "function_call_output", "call_id": "call_2", "status": "incomplete", "output": [
			{"type": "input_text", "text": "timeout"},
			{"type": "input_image", "image_url": "https://example.com/c.png"}
		]},
		{"type": "function_call_output", "call_id": "call_3", "output": ""},
		{"type": "message", "role": "assistant", "content": [{"type": "refusal", "refusal": "I can't."}]},
		{"type": "reasoning", "summary": [], "content": [{"type": "reasoning_text", "text": "plain"}]},
		{"type": "message", "role": "assistant", "content": ""}
	]`)
}

// Reasoning details give one item for each run that one item holds, as OpenAI pairs encrypted
// reasoning with the ID of its item.
func TestToResponsesMessagesGroupsReasoningDetails(t *testing.T) {
	text := func(id *string, s string) ChatReasoningDetails {
		return ChatReasoningDetails{ID: id, Type: BifrostReasoningDetailsTypeText, Text: Ptr(s)}
	}
	summary := func(id *string, s string) ChatReasoningDetails {
		return ChatReasoningDetails{ID: id, Type: BifrostReasoningDetailsTypeSummary, Summary: Ptr(s)}
	}
	encrypted := func(id *string, s string) ChatReasoningDetails {
		return ChatReasoningDetails{ID: id, Type: BifrostReasoningDetailsTypeEncrypted, Data: Ptr(s)}
	}
	tests := []struct {
		name    string
		details []ChatReasoningDetails
		want    string
	}{
		{"an ID for each item", []ChatReasoningDetails{summary(Ptr("rs_a"), "a1"), summary(Ptr("rs_a"), "a2"), encrypted(Ptr("rs_a"), "A"), summary(Ptr("rs_b"), "b"), encrypted(Ptr("rs_b"), "B")}, `[
			{"type": "reasoning", "id": "rs_a", "summary": [{"type": "summary_text", "text": "a1"}, {"type": "summary_text", "text": "a2"}], "encrypted_content": "A"},
			{"type": "reasoning", "id": "rs_b", "summary": [{"type": "summary_text", "text": "b"}], "encrypted_content": "B"}
		]`},
		{"encrypted content ends its item", []ChatReasoningDetails{text(nil, "one"), encrypted(nil, "E1"), text(nil, "two"), encrypted(nil, "E2")}, `[
			{"type": "reasoning", "summary": [], "content": [{"type": "reasoning_text", "text": "one"}], "encrypted_content": "E1"},
			{"type": "reasoning", "summary": [], "content": [{"type": "reasoning_text", "text": "two"}], "encrypted_content": "E2"}
		]`},
		{"an item takes the first ID that its details name", []ChatReasoningDetails{text(nil, "t"), text(Ptr("rs_x"), "u"), encrypted(nil, "X")}, `[
			{"type": "reasoning", "id": "rs_x", "summary": [], "content": [{"type": "reasoning_text", "text": "t"}, {"type": "reasoning_text", "text": "u"}], "encrypted_content": "X"}
		]`},
		{"a signature stays with its text", []ChatReasoningDetails{{Type: BifrostReasoningDetailsTypeText, Text: Ptr("t"), Signature: Ptr("sig")}}, `[
			{"type": "reasoning", "summary": [], "content": [{"type": "reasoning_text", "text": "t", "signature": "sig"}]}
		]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := ChatMessage{Role: ChatMessageRoleAssistant, ChatAssistantMessage: &ChatAssistantMessage{ReasoningDetails: test.details, Reasoning: Ptr("not used")}}
			jsonEqual(t, message.ToResponsesMessages(), test.want)
		})
	}
}

// A citation indexes the message's whole text, in runes, and goes to the part that holds it.
func TestToResponsesMessagesPlacesCitations(t *testing.T) {
	citation := func(start, end int, url string) ChatAssistantMessageAnnotation {
		return ChatAssistantMessageAnnotation{Type: "url_citation", URLCitation: ChatAssistantMessageAnnotationCitation{StartIndex: start, EndIndex: end, URL: Ptr(url)}}
	}
	message := ChatMessage{
		Role: ChatMessageRoleAssistant,
		Content: &ChatMessageContent{ContentBlocks: []ChatContentBlock{
			{Type: ChatContentBlockTypeText, Text: Ptr("Ünïcode ")},
			{Type: ChatContentBlockTypeRefusal, Refusal: Ptr("no")},
			{Type: ChatContentBlockTypeText, Text: Ptr("text")},
		}},
		ChatAssistantMessage: &ChatAssistantMessage{Annotations: []ChatAssistantMessageAnnotation{citation(10, 12, "https://b.example"), citation(0, 7, "https://a.example")}},
	}
	jsonEqual(t, message.ToResponsesMessages(), `[{"type": "message", "role": "assistant", "content": [
		{"type": "output_text", "text": "Ünïcode ", "logprobs": [], "annotations": [{"type": "url_citation", "start_index": 0, "end_index": 7, "title": "", "url": "https://a.example"}]},
		{"type": "refusal", "refusal": "no"},
		{"type": "output_text", "text": "text", "logprobs": [], "annotations": [{"type": "url_citation", "start_index": 2, "end_index": 4, "title": "", "url": "https://b.example"}]}
	]}]`)
}

func TestToResponsesRequestCarriesParameters(t *testing.T) {
	schema := any(map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "answer", "strict": true, "schema": map[string]any{"type": "object"}}})
	request := &BifrostChatRequest{
		Provider:  OpenAI,
		Model:     "gpt-5-pro",
		Fallbacks: []Fallback{{Provider: Azure, Model: "gpt-5-pro"}},
		Params: &ChatParameters{
			FrequencyPenalty: Ptr(0.1), PresencePenalty: Ptr(0.2), Temperature: Ptr(0.3), TopP: Ptr(0.4),
			MaxCompletionTokens: Ptr(100), User: Ptr("u"), SafetyIdentifier: Ptr("s"), ParallelToolCalls: Ptr(false),
			PromptCacheKey: Ptr("k"), PromptCacheRetention: Ptr("24h"), Metadata: &map[string]any{"a": "b"},
			ServiceTier: Ptr(BifrostServiceTier("flex")), LogProbs: Ptr(true), TopLogProbs: Ptr(3),
			StreamOptions:  &ChatStreamOptions{IncludeUsage: Ptr(true), IncludeObfuscation: Ptr(false)},
			Reasoning:      &ChatReasoning{Effort: Ptr("high"), Summary: Ptr("detailed"), Mode: Ptr("pro")},
			ResponseFormat: &schema,
			Verbosity:      Ptr("low"),
			Tools: []ChatTool{{Type: ChatToolTypeFunction, CacheControl: &CacheControl{Type: CacheControlTypeEphemeral},
				Function: &ChatToolFunction{Name: "lookup", Description: Ptr("Look up."), Strict: Ptr(true), Parameters: &ToolFunctionParameters{Type: "object"}}}},
			ToolChoice:  &ChatToolChoice{ChatToolChoiceStruct: &ChatToolChoiceStruct{Type: ChatToolChoiceTypeFunction, Function: &ChatToolChoiceFunction{Name: "lookup"}}},
			ExtraParams: map[string]any{"x": 1},
		},
	}
	converted := request.ToResponsesRequest()
	if converted.Provider != OpenAI || converted.Model != "gpt-5-pro" || !reflect.DeepEqual(converted.Fallbacks, request.Fallbacks) || converted.RawRequestBody != nil {
		t.Fatalf("request = %+v", converted)
	}
	if converted.Params.ExtraParams["x"] != 1 {
		t.Fatalf("extra params = %v", converted.Params.ExtraParams)
	}
	converted.Params.ExtraParams = nil
	jsonEqual(t, converted.Params, `{
		"frequency_penalty": 0.1, "presence_penalty": 0.2, "temperature": 0.3, "top_p": 0.4,
		"max_output_tokens": 100, "user": "u", "safety_identifier": "s", "parallel_tool_calls": false,
		"prompt_cache_key": "k", "prompt_cache_retention": "24h", "metadata": {"a": "b"}, "service_tier": "flex",
		"store": false,
		"include": ["message.output_text.logprobs"], "top_logprobs": 3,
		"stream_options": {"include_obfuscation": false},
		"reasoning": {"effort": "high", "summary": "detailed", "mode": "pro"},
		"text": {"format": {"type": "json_schema", "name": "answer", "strict": true, "schema": {"type": "object"}}, "verbosity": "low"},
		"tools": [{"type": "function", "name": "lookup", "description": "Look up.", "strict": true, "parameters": {"type": "object", "properties": {}}, "cache_control": {"type": "ephemeral"}}],
		"tool_choice": {"type": "function", "name": "lookup"}
	}`)

	// Responses show reasoning only as summaries: summarized asks for them, and omitted leaves them
	// out as Responses do by default.
	for _, test := range []struct {
		effort, display, summary *string
	}{
		{Ptr("low"), Ptr("summarized"), Ptr("auto")},
		{nil, Ptr("summarized"), Ptr("auto")},
		{Ptr("low"), Ptr("omitted"), nil},
	} {
		request.Params = &ChatParameters{Reasoning: &ChatReasoning{Effort: test.effort, Display: test.display}}
		reasoning := request.ToResponsesRequest().Params.Reasoning
		if reasoning == nil || !reflect.DeepEqual(reasoning.Effort, test.effort) || !reflect.DeepEqual(reasoning.Summary, test.summary) {
			t.Fatalf("display %s: reasoning = %+v", *test.display, reasoning)
		}
	}

	// The client's store wins, and a request without parameters asks only not to store.
	request.Params = &ChatParameters{Store: Ptr(true)}
	if store := request.ToResponsesRequest().Params.Store; store == nil || !*store {
		t.Fatalf("store = %v, want true", store)
	}
	request.Params = nil
	jsonEqual(t, request.ToResponsesRequest().Params, `{"store": false}`)
}

func TestToResponsesRequestConvertsToolChoices(t *testing.T) {
	choice := func(c ChatToolChoice) string {
		out, _ := json.Marshal((&BifrostChatRequest{Params: &ChatParameters{ToolChoice: &c}}).ToResponsesRequest().Params.ToolChoice)
		return string(out)
	}
	mode := func(m ChatToolChoiceType) ChatToolChoice {
		return ChatToolChoice{ChatToolChoiceStruct: &ChatToolChoiceStruct{Type: m}}
	}
	tests := []struct {
		name   string
		choice ChatToolChoice
		want   string
	}{
		{"string", ChatToolChoice{ChatToolChoiceStr: Ptr("none")}, `"none"`},
		{"auto mode", mode(ChatToolChoiceTypeAuto), `"auto"`},
		{"required mode", mode(ChatToolChoiceTypeRequired), `"required"`},
		{"Anthropic's any mode", mode(ChatToolChoiceTypeAny), `"required"`},
		{"allowed tools", ChatToolChoice{ChatToolChoiceStruct: &ChatToolChoiceStruct{Type: ChatToolChoiceTypeAllowedTools, AllowedTools: &ChatToolChoiceAllowedTools{
			Mode: "required", Tools: []ChatToolChoiceAllowedToolsTool{{Type: "function", Function: ChatToolChoiceFunction{Name: "a"}}, {Type: "function", Function: ChatToolChoiceFunction{Name: "b"}}},
		}}}, `{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"a"},{"type":"function","name":"b"}]}`},
	}
	for _, test := range tests {
		if got := choice(test.choice); got != test.want {
			t.Errorf("%s: tool_choice = %s, want %s", test.name, got, test.want)
		}
	}
}

// openAIReply is a Responses reply as OpenAI gives it: reasoning with a summary of two parts and
// encrypted content, a message whose two text parts each cite a source, and two function calls.
func openAIReply() *BifrostResponsesResponse {
	citation := func(url string) ResponsesOutputMessageContentTextAnnotation {
		return ResponsesOutputMessageContentTextAnnotation{Type: "url_citation", StartIndex: Ptr(0), EndIndex: Ptr(5), Title: Ptr("T"), URL: Ptr(url)}
	}
	token := func(s string) ResponsesOutputMessageContentTextLogProb {
		return ResponsesOutputMessageContentTextLogProb{Token: s, LogProb: -0.5, TopLogProbs: []LogProb{{Token: s, LogProb: -0.5}}}
	}
	textPart := func(text string, url string, tokens ...ResponsesOutputMessageContentTextLogProb) ResponsesMessageContentBlock {
		return ResponsesMessageContentBlock{Type: ResponsesOutputMessageContentTypeText, Text: Ptr(text), ResponsesOutputMessageContentText: &ResponsesOutputMessageContentText{
			Annotations: []ResponsesOutputMessageContentTextAnnotation{citation(url)}, LogProbs: tokens,
		}}
	}
	return &BifrostResponsesResponse{
		ID: Ptr("resp_1"), CreatedAt: 100, Model: "gpt-5-pro", Status: Ptr(ResponsesResponseStatusCompleted),
		ServiceTier: Ptr(BifrostServiceTier("default")),
		Usage: &ResponsesResponseUsage{InputTokens: 10, OutputTokens: 20, TotalTokens: 30,
			OutputTokensDetails: &ResponsesResponseOutputTokens{ReasoningTokens: 5}},
		Output: []ResponsesMessage{
			{Type: Ptr(ResponsesMessageTypeReasoning), ID: Ptr("rs_1"), ResponsesReasoning: &ResponsesReasoning{
				Summary: []ResponsesReasoningSummary{
					{Type: ResponsesReasoningContentBlockTypeSummaryText, Text: "Plan the call."},
					{Type: ResponsesReasoningContentBlockTypeSummaryText, Text: "Check the city."},
				}, EncryptedContent: Ptr("ENC"),
			}},
			{Type: Ptr(ResponsesMessageTypeMessage), ID: Ptr("msg_1"), Role: Ptr(ResponsesInputMessageRoleAssistant), Status: Ptr(ResponsesResponseStatusCompleted),
				Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
					textPart("Héllo ", "https://a.example", token("Hé"), token("llo"), token(" ")),
					textPart("world", "https://b.example", token("world")),
				}}},
			{Type: Ptr(ResponsesMessageTypeFunctionCall), ID: Ptr("fc_1"), Status: Ptr(ResponsesResponseStatusCompleted),
				ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("call_1"), Name: Ptr("weather"), Arguments: Ptr(`{"city":"Paris"}`)}},
			{Type: Ptr(ResponsesMessageTypeFunctionCall), ID: Ptr("fc_2"), Status: Ptr(ResponsesResponseStatusCompleted),
				ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("call_2"), Name: Ptr("time"), Arguments: Ptr("{}")}},
		},
	}
}

func TestToBifrostChatResponseJoinsTheReply(t *testing.T) {
	chat := openAIReply().ToBifrostChatResponse()
	if chat.ID != "resp_1" || chat.Created != 100 || chat.Model != "gpt-5-pro" || chat.Object != "chat.completion" ||
		*chat.ServiceTier != "default" || chat.ExtraFields.RequestType != ChatCompletionRequest {
		t.Fatalf("reply = %+v", chat)
	}
	if chat.Usage == nil || chat.Usage.PromptTokens != 10 || chat.Usage.CompletionTokens != 20 || chat.Usage.TotalTokens != 30 ||
		chat.Usage.CompletionTokensDetails == nil || chat.Usage.CompletionTokensDetails.ReasoningTokens != 5 {
		t.Fatalf("usage = %+v", chat.Usage)
	}
	if len(chat.Choices) != 1 {
		t.Fatalf("choices = %+v", chat.Choices)
	}
	choice := chat.Choices[0]
	if *choice.FinishReason != "tool_calls" || len(choice.LogProbs.Content) != 4 || choice.LogProbs.Content[3].Token != "world" ||
		len(choice.LogProbs.Content[0].TopLogProbs) != 1 {
		t.Fatalf("finish reason %s, log probabilities %+v", *choice.FinishReason, choice.LogProbs)
	}
	// The second part's citation counts from the start of the whole text: "Héllo " is six runes.
	// The reasoning text shows each summary part, a blank line between two.
	jsonEqual(t, choice.Message, `{
		"role": "assistant",
		"content": "Héllo world",
		"refusal": null,
		"reasoning": "Plan the call.\n\nCheck the city.",
		"reasoning_content": "Plan the call.\n\nCheck the city.",
		"reasoning_details": [
			{"id": "rs_1", "index": 0, "type": "reasoning.summary", "summary": "Plan the call."},
			{"id": "rs_1", "index": 1, "type": "reasoning.summary", "summary": "Check the city."},
			{"id": "rs_1", "index": 2, "type": "reasoning.encrypted", "data": "ENC"}
		],
		"annotations": [
			{"type": "url_citation", "url_citation": {"start_index": 0, "end_index": 5, "title": "T", "url": "https://a.example"}},
			{"type": "url_citation", "url_citation": {"start_index": 6, "end_index": 11, "title": "T", "url": "https://b.example"}}
		],
		"tool_calls": [
			{"index": 0, "type": "function", "id": "call_1", "function": {"name": "weather", "arguments": "{\"city\":\"Paris\"}"}},
			{"index": 0, "type": "function", "id": "call_2", "function": {"name": "time", "arguments": "{}"}}
		]
	}`)
}

func TestToBifrostChatResponseGivesContentAsChatCompletionsDoes(t *testing.T) {
	message := func(output ...ResponsesMessage) *ChatMessage {
		reply := &BifrostResponsesResponse{ID: Ptr("r"), Status: Ptr(ResponsesResponseStatusCompleted), Output: output}
		return reply.ToBifrostChatResponse().Choices[0].ChatNonStreamResponseChoice.Message
	}
	refusal := ResponsesMessage{Type: Ptr(ResponsesMessageTypeMessage), Role: Ptr(ResponsesInputMessageRoleAssistant), Content: &ResponsesMessageContent{
		ContentBlocks: []ResponsesMessageContentBlock{{Type: ResponsesOutputMessageContentTypeRefusal, ResponsesOutputMessageContentRefusal: &ResponsesOutputMessageContentRefusal{Refusal: "I can't."}}},
	}}
	call := ResponsesMessage{Type: Ptr(ResponsesMessageTypeFunctionCall), ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr("c"), Name: Ptr("f"), Arguments: Ptr("{}")}}
	reasoning := ResponsesMessage{Type: Ptr(ResponsesMessageTypeReasoning), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
		{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr("Think "), Signature: Ptr("sig")},
		{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr("more.")},
	}}, ResponsesReasoning: &ResponsesReasoning{}}

	if got := message(refusal); got.Content != nil || *got.Refusal != "I can't." {
		t.Errorf("refusal = %+v", got)
	}
	if got := message(call); got.Content != nil || len(got.ToolCalls) != 1 {
		t.Errorf("calls = %+v", got)
	}
	if got := message(); got.Content == nil || *got.Content.ContentStr != "" {
		t.Errorf("empty reply = %+v", got)
	}
	got := message(reasoning)
	want := []ChatReasoningDetails{
		{Index: 0, Type: BifrostReasoningDetailsTypeText, Text: Ptr("Think "), Signature: Ptr("sig")},
		{Index: 1, Type: BifrostReasoningDetailsTypeText, Text: Ptr("more.")},
	}
	if *got.Reasoning != "Think more." || !reflect.DeepEqual(got.ReasoningDetails, want) || *got.Content.ContentStr != "" {
		t.Errorf("reasoning = %v, details = %+v, content = %+v", got.Reasoning, got.ReasoningDetails, got.Content)
	}
}

func TestChatFinishReasonOfAResponsesReply(t *testing.T) {
	call := []ResponsesMessage{{Type: Ptr(ResponsesMessageTypeFunctionCall)}}
	incomplete := func(reason string) *ResponsesResponseIncompleteDetails {
		return &ResponsesResponseIncompleteDetails{Reason: reason}
	}
	tests := []struct {
		name       string
		status     string
		incomplete *ResponsesResponseIncompleteDetails
		stopReason *string
		output     []ResponsesMessage
		calls      bool
		want       *string
	}{
		{"completed", ResponsesResponseStatusCompleted, nil, nil, nil, false, Ptr("stop")},
		{"completed with calls", ResponsesResponseStatusCompleted, nil, nil, call, true, Ptr("tool_calls")},
		{"completed with streamed calls", ResponsesResponseStatusCompleted, nil, nil, nil, true, Ptr("tool_calls")},
		{"stop reason stop with calls", ResponsesResponseStatusCompleted, nil, Ptr("stop"), call, true, Ptr("tool_calls")},
		{"output limit", ResponsesResponseStatusIncomplete, incomplete(ResponsesResponseIncompleteReasonMaxOutputTokens), nil, nil, false, Ptr("length")},
		{"content filter", ResponsesResponseStatusIncomplete, incomplete(ResponsesResponseIncompleteReasonContentFilter), nil, nil, false, Ptr("content_filter")},
		{"cut short for another reason", ResponsesResponseStatusIncomplete, incomplete("max_tool_calls"), nil, nil, false, Ptr("length")},
		{"failed", ResponsesResponseStatusFailed, nil, nil, nil, false, nil},
		{"in progress", ResponsesResponseStatusInProgress, nil, nil, nil, false, nil},
	}
	for _, test := range tests {
		got := chatFinishReason(Ptr(test.status), test.incomplete, test.stopReason, test.output, test.calls)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: finish reason = %v, want %v", test.name, got, test.want)
		}
	}
}

// openAIStream streams openAIReply as OpenAI does.
func openAIStream() []*BifrostResponsesStreamResponse {
	reply := openAIReply()
	var events []*BifrostResponsesStreamResponse
	add := func(event BifrostResponsesStreamResponse) {
		event.SequenceNumber = len(events)
		events = append(events, &event)
	}
	at := func(output int) *int { return Ptr(output) }
	created := *reply
	created.Status, created.Output, created.Usage = Ptr(ResponsesResponseStatusInProgress), nil, nil
	add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeCreated, Response: &created})
	add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeInProgress, Response: &created})

	reasoning := reply.Output[0]
	add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: at(0), Item: &ResponsesMessage{
		Type: reasoning.Type, ID: reasoning.ID, ResponsesReasoning: &ResponsesReasoning{Summary: []ResponsesReasoningSummary{}},
	}})
	for index, summary := range reasoning.ResponsesReasoning.Summary {
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeReasoningSummaryPartAdded, OutputIndex: at(0), ItemID: reasoning.ID, SummaryIndex: at(index),
			Part: &ResponsesMessageContentBlock{Type: ResponsesOutputMessageContentTypeSummaryText, Text: Ptr("")}})
		cut := len(summary.Text) / 2
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeReasoningSummaryTextDelta, OutputIndex: at(0), ItemID: reasoning.ID, SummaryIndex: at(index), Delta: Ptr(summary.Text[:cut])})
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeReasoningSummaryTextDelta, OutputIndex: at(0), ItemID: reasoning.ID, SummaryIndex: at(index), Delta: Ptr(summary.Text[cut:])})
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeReasoningSummaryTextDone, OutputIndex: at(0), ItemID: reasoning.ID, SummaryIndex: at(index), Text: Ptr(summary.Text)})
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeReasoningSummaryPartDone, OutputIndex: at(0), ItemID: reasoning.ID, SummaryIndex: at(index),
			Part: &ResponsesMessageContentBlock{Type: ResponsesOutputMessageContentTypeSummaryText, Text: Ptr(summary.Text)}})
	}
	add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemDone, OutputIndex: at(0), Item: &reasoning})

	message := reply.Output[1]
	add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: at(1), Item: &ResponsesMessage{
		Type: message.Type, ID: message.ID, Role: message.Role, Status: Ptr(ResponsesResponseStatusInProgress), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{}},
	}})
	for content, part := range message.Content.ContentBlocks {
		empty := ResponsesMessageContentBlock{Type: part.Type, Text: Ptr(""), ResponsesOutputMessageContentText: &ResponsesOutputMessageContentText{
			Annotations: []ResponsesOutputMessageContentTextAnnotation{}, LogProbs: []ResponsesOutputMessageContentTextLogProb{},
		}}
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeContentPartAdded, OutputIndex: at(1), ItemID: message.ID, ContentIndex: at(content), Part: &empty})
		for _, token := range part.LogProbs {
			add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputTextDelta, OutputIndex: at(1), ItemID: message.ID, ContentIndex: at(content),
				Delta: Ptr(token.Token), LogProbs: []ResponsesOutputMessageContentTextLogProb{token}})
		}
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputTextAnnotationAdded, OutputIndex: at(1), ItemID: message.ID, ContentIndex: at(content),
			AnnotationIndex: at(0), Annotation: &part.Annotations[0]})
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputTextDone, OutputIndex: at(1), ItemID: message.ID, ContentIndex: at(content),
			Text: part.Text, LogProbs: part.LogProbs})
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeContentPartDone, OutputIndex: at(1), ItemID: message.ID, ContentIndex: at(content), Part: &part})
	}
	add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemDone, OutputIndex: at(1), Item: &message})

	for output := 2; output < 4; output++ {
		call := reply.Output[output]
		started := call
		started.Status = Ptr(ResponsesResponseStatusInProgress)
		started.ResponsesToolMessage = &ResponsesToolMessage{CallID: call.CallID, Name: call.Name, Arguments: Ptr("")}
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: at(output), Item: &started})
		arguments := *call.Arguments
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeFunctionCallArgumentsDelta, OutputIndex: at(output), ItemID: call.ID, Delta: Ptr(arguments[:1])})
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeFunctionCallArgumentsDelta, OutputIndex: at(output), ItemID: call.ID, Delta: Ptr(arguments[1:])})
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeFunctionCallArgumentsDone, OutputIndex: at(output), ItemID: call.ID, Arguments: call.Arguments})
		add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemDone, OutputIndex: at(output), Item: &call})
	}
	add(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeCompleted, Response: reply})
	return events
}

// streamed is a Chat Completions stream accumulated as OpenAI's SDKs accumulate one.
type streamed struct {
	message *ChatMessage
	finish  *string
	tokens  []ContentLogProb
	usage   *BifrostLLMUsage
}

func accumulate(t *testing.T, events []*BifrostResponsesStreamResponse) streamed {
	t.Helper()
	var state ResponsesToChatStreamState
	assistant := &ChatAssistantMessage{}
	out := streamed{message: &ChatMessage{ChatAssistantMessage: assistant}}
	var content, refusal, reasoning *string
	join := func(field **string, value *string) {
		if value == nil {
			return
		}
		if *field == nil {
			*field = Ptr("")
		}
		*field = Ptr(**field + *value)
	}
	for i, event := range events {
		chunk := event.ToBifrostChatResponse(&state)
		if chunk.ID != "resp_1" || chunk.Model != "gpt-5-pro" || chunk.Created != 100 || chunk.Object != "chat.completion.chunk" ||
			chunk.ExtraFields.RequestType != ChatCompletionStreamRequest || len(chunk.Choices) != 1 {
			t.Fatalf("chunk %d = %+v", i, chunk)
		}
		choice := chunk.Choices[0]
		delta := choice.Delta
		if (delta.Role != nil) != (i == 0) {
			t.Fatalf("chunk %d role = %v", i, delta.Role)
		}
		if delta.Role != nil {
			out.message.Role = ChatMessageRole(*delta.Role)
		}
		if delta.Content != nil && delta.Refusal != nil {
			t.Fatalf("chunk %d holds content and a refusal", i)
		}
		join(&content, delta.Content)
		join(&refusal, delta.Refusal)
		join(&reasoning, delta.Reasoning)
		for _, detail := range delta.ReasoningDetails {
			if detail.Index == len(assistant.ReasoningDetails) {
				assistant.ReasoningDetails = append(assistant.ReasoningDetails, detail)
				continue
			}
			merged := &assistant.ReasoningDetails[detail.Index]
			join(&merged.Text, detail.Text)
			join(&merged.Summary, detail.Summary)
			if detail.Signature != nil {
				merged.Signature = detail.Signature
			}
		}
		assistant.Annotations = append(assistant.Annotations, delta.Annotations...)
		for _, call := range delta.ToolCalls {
			if int(call.Index) == len(assistant.ToolCalls) {
				call.Index = 0
				assistant.ToolCalls = append(assistant.ToolCalls, call)
				continue
			}
			assistant.ToolCalls[call.Index].Function.Arguments += call.Function.Arguments
		}
		if choice.LogProbs != nil {
			out.tokens = append(out.tokens, choice.LogProbs.Content...)
		}
		if choice.FinishReason != nil {
			out.finish = choice.FinishReason
		}
		if chunk.Usage != nil && choice.FinishReason == nil {
			t.Fatalf("chunk %d has usage before the finish reason", i)
		}
		if chunk.Usage != nil {
			out.usage = chunk.Usage
		}
	}
	assistant.Reasoning, assistant.Refusal = reasoning, refusal
	if content != nil || (refusal == nil && len(assistant.ToolCalls) == 0) {
		out.message.Content = &ChatMessageContent{ContentStr: content}
		if content == nil {
			out.message.Content.ContentStr = Ptr("")
		}
	}
	return out
}

// agrees checks that a stream accumulates to the reply that ToBifrostChatResponse gives.
func agrees(t *testing.T, got streamed, reply *BifrostResponsesResponse) {
	t.Helper()
	want := reply.ToBifrostChatResponse()
	choice := want.Choices[0]
	gotJSON, _ := json.Marshal(got.message)
	wantJSON, _ := json.Marshal(choice.Message)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("stream message\n%s\nreply message\n%s", gotJSON, wantJSON)
	}
	var wantTokens []ContentLogProb
	if choice.LogProbs != nil {
		wantTokens = choice.LogProbs.Content
	}
	if !reflect.DeepEqual(got.finish, choice.FinishReason) || !reflect.DeepEqual(got.tokens, wantTokens) || !reflect.DeepEqual(got.usage, want.Usage) {
		t.Fatalf("stream finish %v, tokens %+v, usage %+v; reply finish %v, tokens %+v, usage %+v",
			got.finish, got.tokens, got.usage, choice.FinishReason, wantTokens, want.Usage)
	}
}

func TestResponsesStreamAccumulatesToTheReply(t *testing.T) {
	agrees(t, accumulate(t, openAIStream()), openAIReply())
}

// A provider that sends values whole, in done events or in items, gives each value once.
func TestResponsesStreamSendsWhatDeltasLeftOut(t *testing.T) {
	var whole []*BifrostResponsesStreamResponse
	for _, event := range openAIStream() {
		switch event.Type {
		case ResponsesStreamResponseTypeOutputTextDelta, ResponsesStreamResponseTypeReasoningSummaryTextDelta,
			ResponsesStreamResponseTypeFunctionCallArgumentsDelta, ResponsesStreamResponseTypeOutputTextAnnotationAdded:
			continue
		}
		whole = append(whole, event)
	}
	agrees(t, accumulate(t, whole), openAIReply())

	var itemsOnly []*BifrostResponsesStreamResponse
	for _, event := range openAIStream() {
		switch event.Type {
		case ResponsesStreamResponseTypeCreated, ResponsesStreamResponseTypeOutputItemDone, ResponsesStreamResponseTypeCompleted:
			itemsOnly = append(itemsOnly, event)
		}
	}
	agrees(t, accumulate(t, itemsOnly), openAIReply())
}

func TestResponsesStreamCatchesUpOnlyAnExtension(t *testing.T) {
	var state ResponsesToChatStreamState
	text := func(kind ResponsesStreamResponseType, delta, whole *string) *ChatStreamResponseChoiceDelta {
		event := &BifrostResponsesStreamResponse{Type: kind, OutputIndex: Ptr(0), ContentIndex: Ptr(0), Delta: delta, Text: whole}
		return event.ToBifrostChatResponse(&state).Choices[0].Delta
	}
	text(ResponsesStreamResponseTypeOutputTextDelta, Ptr("Hel"), nil)
	if rest := text(ResponsesStreamResponseTypeOutputTextDone, nil, Ptr("Hello")); rest.Content == nil || *rest.Content != "lo" {
		t.Fatalf("rest = %+v, want lo", rest.Content)
	}
	// A whole value that does not extend what the stream sent cannot be reconciled, and adds
	// nothing.
	if rest := text(ResponsesStreamResponseTypeOutputTextDone, nil, Ptr("Help")); rest.Content != nil {
		t.Fatalf("rest = %q, want none", *rest.Content)
	}
}

func TestResponsesStreamNumbersCallsAndEndsIncomplete(t *testing.T) {
	var state ResponsesToChatStreamState
	convert := func(event BifrostResponsesStreamResponse) BifrostResponseChoice {
		return event.ToBifrostChatResponse(&state).Choices[0]
	}
	added := func(output int, id string) BifrostResponsesStreamResponse {
		return BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: Ptr(output), Item: &ResponsesMessage{
			Type: Ptr(ResponsesMessageTypeFunctionCall), ResponsesToolMessage: &ResponsesToolMessage{CallID: Ptr(id), Name: Ptr("f"), Arguments: Ptr("")},
		}}
	}
	arguments := func(output int, delta string) BifrostResponsesStreamResponse {
		return BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeFunctionCallArgumentsDelta, OutputIndex: Ptr(output), Delta: Ptr(delta)}
	}
	first := convert(added(3, "call_a")).Delta.ToolCalls
	second := convert(added(5, "call_b")).Delta.ToolCalls
	more := convert(arguments(3, "{}")).Delta.ToolCalls
	if len(first) != 1 || first[0].Index != 0 || *first[0].ID != "call_a" || *first[0].Type != "function" ||
		len(second) != 1 || second[0].Index != 1 || len(more) != 1 || more[0].Index != 0 || more[0].Function.Arguments != "{}" || more[0].ID != nil {
		t.Fatalf("calls: %+v, %+v, %+v", first, second, more)
	}
	end := convert(BifrostResponsesStreamResponse{Type: ResponsesStreamResponseTypeIncomplete, Response: &BifrostResponsesResponse{
		Status: Ptr(ResponsesResponseStatusIncomplete), IncompleteDetails: &ResponsesResponseIncompleteDetails{Reason: ResponsesResponseIncompleteReasonMaxOutputTokens},
	}})
	if end.FinishReason == nil || *end.FinishReason != "length" {
		t.Fatalf("finish reason = %v, want length", end.FinishReason)
	}
}

func TestResponsesStreamCarriesRefusalsAndSignedReasoning(t *testing.T) {
	reply := &BifrostResponsesResponse{ID: Ptr("resp_1"), CreatedAt: 100, Model: "gpt-5-pro", Status: Ptr(ResponsesResponseStatusCompleted),
		Usage: &ResponsesResponseUsage{InputTokens: 3, OutputTokens: 4, TotalTokens: 7}, Output: []ResponsesMessage{
			{Type: Ptr(ResponsesMessageTypeReasoning), ID: Ptr("rs_1"), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
				{Type: ResponsesOutputMessageContentTypeReasoning, Text: Ptr("Think."), Signature: Ptr("sig")},
			}}, ResponsesReasoning: &ResponsesReasoning{Summary: []ResponsesReasoningSummary{}}},
			{Type: Ptr(ResponsesMessageTypeMessage), Role: Ptr(ResponsesInputMessageRoleAssistant), Content: &ResponsesMessageContent{ContentBlocks: []ResponsesMessageContentBlock{
				{Type: ResponsesOutputMessageContentTypeRefusal, ResponsesOutputMessageContentRefusal: &ResponsesOutputMessageContentRefusal{Refusal: "I can't."}},
			}}},
		}}
	events := []*BifrostResponsesStreamResponse{
		{Type: ResponsesStreamResponseTypeCreated, Response: &BifrostResponsesResponse{ID: reply.ID, CreatedAt: 100, Model: reply.Model}},
		{Type: ResponsesStreamResponseTypeReasoningTextDelta, OutputIndex: Ptr(0), ContentIndex: Ptr(0), ItemID: Ptr("rs_1"), Delta: Ptr("Think.")},
		{Type: ResponsesStreamResponseTypeReasoningTextDelta, OutputIndex: Ptr(0), ContentIndex: Ptr(0), ItemID: Ptr("rs_1"), Delta: Ptr(""), Signature: Ptr("sig")},
		{Type: ResponsesStreamResponseTypeOutputItemDone, OutputIndex: Ptr(0), Item: &reply.Output[0]},
		{Type: ResponsesStreamResponseTypeRefusalDelta, OutputIndex: Ptr(1), ContentIndex: Ptr(0), Delta: Ptr("I can")},
		{Type: ResponsesStreamResponseTypeRefusalDone, OutputIndex: Ptr(1), ContentIndex: Ptr(0), Refusal: Ptr("I can't.")},
		{Type: ResponsesStreamResponseTypeCompleted, Response: reply},
	}
	agrees(t, accumulate(t, events), reply)
}

// A Responses reply that a Chat Completions client sends back as history reaches Responses as
// the items the reply gave, so OpenAI finds its encrypted reasoning under the ID it gave it.
func TestResponsesReplyRoundTripsThroughChatHistory(t *testing.T) {
	reply := openAIReply()
	reply.Output[1].Content.ContentBlocks = reply.Output[1].Content.ContentBlocks[1:]
	message := reply.ToBifrostChatResponse().Choices[0].ChatNonStreamResponseChoice.Message
	want := make([]ResponsesMessage, len(reply.Output))
	for i, item := range reply.Output {
		item.Status = nil
		if *item.Type != ResponsesMessageTypeReasoning {
			item.ID = nil
		}
		if item.Content != nil {
			blocks := append([]ResponsesMessageContentBlock(nil), item.Content.ContentBlocks...)
			for j := range blocks {
				text := *blocks[j].ResponsesOutputMessageContentText
				text.LogProbs = []ResponsesOutputMessageContentTextLogProb{}
				blocks[j].ResponsesOutputMessageContentText = &text
			}
			item.Content = &ResponsesMessageContent{ContentBlocks: blocks}
		}
		want[i] = item
	}
	wantJSON, _ := json.Marshal(want)
	jsonEqual(t, message.ToResponsesMessages(), string(wantJSON))

	// The Responses to Chat Completions conversion, which serves Chat Completions providers that
	// take no citations in history, reads back the rest of the message.
	back := ToChatMessages(message.ToResponsesMessages())
	if len(back) != 1 || *back[0].Content.ContentStr != *message.Content.ContentStr ||
		!reflect.DeepEqual(back[0].ReasoningDetails, message.ReasoningDetails) || len(back[0].ToolCalls) != len(message.ToolCalls) {
		t.Fatalf("history = %+v", back)
	}
	for i, call := range back[0].ToolCalls {
		if want := message.ToolCalls[i]; *call.ID != *want.ID || *call.Function.Name != *want.Function.Name || call.Function.Arguments != want.Function.Arguments {
			t.Fatalf("call %d = %+v, want %+v", i, call, want)
		}
	}
}
