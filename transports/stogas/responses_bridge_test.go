package stogas

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

const bridgedTestTools = `"tools":[{"type":"function","name":"lookup","description":"Look up a value","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}]`

// bridgedState resolves a Responses request that reaches a Chat Completions deployment and
// prepares it as a pair does.
func bridgedState(t *testing.T, body string) *State {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	if !resolution.Bridged() {
		t.Fatalf("deployment %s takes Responses itself", resolution.Deployment.ID)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatal(err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatal(err)
	}
	return state
}

func bridgedValidationError(t *testing.T, body string) error {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/responses", Body: []byte(body)})
	if err != nil {
		return err
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	return state.Adapter.ValidateRequest(state)
}

// wireMessages are the Chat Completions messages of a bridged request.
func wireMessages(t *testing.T, state *State) []map[string]json.RawMessage {
	t.Helper()
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(state.Resolution.WireView().RawBody()["messages"], &messages); err != nil {
		t.Fatal(err)
	}
	return messages
}

func TestResponsesReachChatOnlyDeploymentsThroughChatCompletions(t *testing.T) {
	for _, model := range []string{"chutes-glm-5.2", "azure-minimax-m3"} {
		t.Run(model, func(t *testing.T) {
			state := bridgedState(t, `{"model":"`+model+`","instructions":"Be brief.","input":[{"role":"developer","content":"Use tools."},{"role":"user","content":[{"type":"input_text","text":"Find a1."}]}],"max_output_tokens":300,"stream":true,`+bridgedTestTools+`}`)
			resolution := state.Resolution
			if resolution.RequestType != schemas.ResponsesStreamRequest || resolution.WireRoute() != catalog.RouteChat ||
				resolution.WireRequestType() != schemas.ChatCompletionStreamRequest {
				t.Fatalf("request type %s, wire %s %s", resolution.RequestType, resolution.WireRoute(), resolution.WireRequestType())
			}
			clientType := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			clientType.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.RequestType)
			request, err := resolution.ToBifrost(clientType)
			if err != nil {
				t.Fatal(err)
			}
			if request.ChatRequest == nil || request.ResponsesRequest != nil || request.RequestType != schemas.ChatCompletionStreamRequest {
				t.Fatalf("provider request = %#v", request)
			}
			if err := PrepareProviderRequest(clientType, state, request); !errors.Is(err, catalog.ErrUnsupportedRequest) {
				t.Fatalf("a call typed as the client's Responses prepared: %v", err)
			}
			wireType := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			wireType.SetValue(schemas.BifrostContextKeyHTTPRequestType, resolution.WireRequestType())
			if err := PrepareProviderRequest(wireType, state, request); err != nil {
				t.Fatal(err)
			}
			var body struct {
				Model    string `json:"model"`
				Messages []struct {
					Role    string          `json:"role"`
					Content json.RawMessage `json:"content"`
				} `json:"messages"`
				Tools []struct {
					Type     string `json:"type"`
					Function struct {
						Name string `json:"name"`
					} `json:"function"`
				} `json:"tools"`
				Stream        bool `json:"stream"`
				StreamOptions struct {
					IncludeUsage bool `json:"include_usage"`
				} `json:"stream_options"`
				Input json.RawMessage `json:"input"`
			}
			if err := json.Unmarshal(preparedProviderBody(t, wireType, request.ChatRequest), &body); err != nil {
				t.Fatal(err)
			}
			if body.Model != resolution.Model || len(body.Messages) != 3 || body.Input != nil ||
				body.Messages[0].Role != "system" || string(body.Messages[0].Content) != `"Be brief."` ||
				body.Messages[1].Role != "system" || string(body.Messages[1].Content) != `"Use tools."` ||
				body.Messages[2].Role != "user" || !strings.Contains(string(body.Messages[2].Content), `"Find a1."`) ||
				len(body.Tools) != 1 || body.Tools[0].Type != "function" || body.Tools[0].Function.Name != "lookup" ||
				!body.Stream || !body.StreamOptions.IncludeUsage {
				t.Fatalf("provider body = %+v", body)
			}
		})
	}
}

func TestDeploymentsWithResponsesKeepResponses(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST", Path: "/v1/responses", Body: []byte(`{"model":"azure-gpt-5.6-sol","input":"hi"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Bridged() || resolution.WireRoute() != catalog.RouteResponses || resolution.WireRequestType() != schemas.ResponsesRequest {
		t.Fatalf("deployment %s with Responses was bridged", resolution.Deployment.ID)
	}
	// A model field that names the deployment's Chat Completions route chooses the translation.
	resolution, err = catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST", Path: "/v1/responses", Body: []byte(`{"model":"route:azure-chat-completions azure-gpt-5.6-sol","input":"hi"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resolution.Bridged() || resolution.Deployment.RouteID != "azure-chat-completions" || resolution.WireRequestType() != schemas.ChatCompletionRequest {
		t.Fatalf("named Chat Completions route resolved to %s on %s", resolution.Deployment.ID, resolution.Deployment.RouteID)
	}
	// OpenAI's search model prices its searches only through Chat Completions' web_search_options.
	if _, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST", Path: "/v1/responses", Body: []byte(`{"model":"openai-gpt-5-search-api-2025-10-14","input":"hi"}`),
	}); err == nil {
		t.Fatal("OpenAI's search model took a Responses request")
	}
}

func TestBridgedRequestsRefuseWhatChatCompletionsLacks(t *testing.T) {
	for _, test := range []struct{ name, body, want string }{
		{"include", `"include":["message.output_text.logprobs"]`, "include is not supported for Chat Completions deployments"},
		{"verbosity", `"text":{"verbosity":"low"}`, "verbosity"},
		{"hosted tool", `"tools":[{"type":"web_search"}]`, "web_search"},
		{"reasoning summary", `"reasoning":{"summary":"detailed"}`, "reasoning.summary must be auto or none"},
		{"file URL", `"input":[{"role":"user","content":[{"type":"input_file","file_url":"https://example.com/a.pdf"}]}]`, "file URLs are not supported"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := `{"model":"chutes-glm-5.2","input":"hi",` + test.body + `}`
			if strings.Contains(test.body, `"input"`) {
				body = `{"model":"chutes-glm-5.2",` + test.body + `}`
			}
			err := bridgedValidationError(t, body)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func bridgedChatReply(state *State, finish string, message *schemas.ChatMessage) *schemas.BifrostResponse {
	return &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{
		ID: "chatcmpl-bridge", Object: "chat.completion", Created: 1_700_000_000, Model: state.Resolution.Model,
		Choices: []schemas.BifrostResponseChoice{{
			FinishReason:                schemas.Ptr(finish),
			ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{Message: message},
		}},
		Usage: &schemas.BifrostLLMUsage{
			PromptTokens: 20, CompletionTokens: 15, TotalTokens: 35,
			CompletionTokensDetails: &schemas.ChatCompletionTokensDetails{ReasoningTokens: 4},
		},
	}}
}

func ingestBridgedReply(t *testing.T, state *State, response *schemas.BifrostResponse) *schemas.BifrostResponsesResponse {
	t.Helper()
	if err := state.Adapter.IngestResponse(state, response, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompletedExecution(state); err != nil {
		t.Fatal(err)
	}
	converted, err := BridgedResponse(state, response)
	if err != nil {
		t.Fatal(err)
	}
	if state.Response != response || converted.ChatResponse != nil || converted.ResponsesResponse == nil {
		t.Fatalf("the state lost the provider's reply, or the client got %#v", converted)
	}
	return converted.ResponsesResponse
}

func TestBridgedReplyBecomesResponses(t *testing.T) {
	state := bridgedState(t, `{"model":"chutes-glm-5.2","instructions":"Be brief.","input":"Find a1.","max_output_tokens":300,`+bridgedTestTools+`}`)
	reasoning := "Need the tool."
	reply := ingestBridgedReply(t, state, bridgedChatReply(state, "tool_calls", &schemas.ChatMessage{
		Role:    schemas.ChatMessageRoleAssistant,
		Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Looking it up.")},
		ChatAssistantMessage: &schemas.ChatAssistantMessage{
			Reasoning: &reasoning,
			ReasoningDetails: []schemas.ChatReasoningDetails{{
				Type: schemas.BifrostReasoningDetailsTypeText, Text: &reasoning,
			}},
			ToolCalls: []schemas.ChatAssistantMessageToolCall{{
				Type: schemas.Ptr("function"), ID: schemas.Ptr("call_1"),
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: schemas.Ptr("lookup"), Arguments: `{"id":"a1"}`},
			}},
		},
	}))
	if *reply.ID != "chatcmpl-bridge" || *reply.Status != schemas.ResponsesResponseStatusCompleted ||
		reply.CompletedAt == nil || *reply.CompletedAt < reply.CreatedAt || reply.StopReason != nil || reply.IncompleteDetails != nil {
		t.Fatalf("response = %+v", reply)
	}
	if reply.Usage == nil || reply.Usage.InputTokens != 20 || reply.Usage.OutputTokens != 15 ||
		reply.Usage.OutputTokensDetails == nil || reply.Usage.OutputTokensDetails.ReasoningTokens != 4 {
		t.Fatalf("usage = %+v", reply.Usage)
	}
	if reply.Instructions == nil || reply.Instructions.ResponsesResponseInstructionsStr == nil ||
		*reply.Instructions.ResponsesResponseInstructionsStr != "Be brief." || reply.MaxOutputTokens == nil ||
		*reply.MaxOutputTokens != 300 || len(reply.Tools) != 1 || reply.Store == nil || *reply.Store {
		t.Fatalf("the reply does not echo the request: %+v", reply)
	}
	output, err := json.Marshal(reply.Output)
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"id":"rs_chatcmpl-bridge_0","type":"reasoning","status":"completed","content":[{"type":"reasoning_text","text":"Need the tool."}],"summary":[]},` +
		`{"id":"msg_chatcmpl-bridge_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Looking it up.","annotations":[],"logprobs":[]}]},` +
		`{"arguments":"{\"id\":\"a1\"}","id":"fc_chatcmpl-bridge_2","type":"function_call","status":"completed","call_id":"call_1","name":"lookup"}]`
	if string(output) != want {
		t.Fatalf("output =\n%s\nwant\n%s", output, want)
	}
}

func TestBridgedReplyCutShortIsIncomplete(t *testing.T) {
	state := bridgedState(t, `{"model":"chutes-glm-5.2","input":"Count.","max_output_tokens":16}`)
	reply := ingestBridgedReply(t, state, bridgedChatReply(state, "length", &schemas.ChatMessage{
		Role:    schemas.ChatMessageRoleAssistant,
		Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("One, two")},
	}))
	if *reply.Status != schemas.ResponsesResponseStatusIncomplete || reply.IncompleteDetails == nil ||
		reply.IncompleteDetails.Reason != schemas.ResponsesResponseIncompleteReasonMaxOutputTokens ||
		reply.CompletedAt != nil || len(reply.Output) != 1 || *reply.Output[0].Status != schemas.ResponsesResponseStatusIncomplete {
		t.Fatalf("response = %+v", reply)
	}
}

func TestBridgedReplyRefusal(t *testing.T) {
	state := bridgedState(t, `{"model":"chutes-glm-5.2","input":"Do harm."}`)
	reply := ingestBridgedReply(t, state, bridgedChatReply(state, "stop", &schemas.ChatMessage{
		Role:                 schemas.ChatMessageRoleAssistant,
		ChatAssistantMessage: &schemas.ChatAssistantMessage{Refusal: schemas.Ptr("I can't help with that.")},
	}))
	blocks := reply.Output[0].Content.ContentBlocks
	if *reply.Status != schemas.ResponsesResponseStatusCompleted || len(reply.Output) != 1 || len(blocks) != 1 ||
		blocks[0].Type != schemas.ResponsesOutputMessageContentTypeRefusal ||
		blocks[0].ResponsesOutputMessageContentRefusal.Refusal != "I can't help with that." {
		t.Fatalf("response = %+v", reply)
	}
}

func TestBridgedReplyRefusesReasoningThatCannotGoBack(t *testing.T) {
	text, signature, data := "Thinking.", "sig_1", "ciphertext"
	for name, detail := range map[string]schemas.ChatReasoningDetails{
		"signed":    {Type: schemas.BifrostReasoningDetailsTypeText, Text: &text, Signature: &signature},
		"encrypted": {Type: schemas.BifrostReasoningDetailsTypeEncrypted, Data: &data},
		"summary":   {Type: schemas.BifrostReasoningDetailsTypeSummary, Summary: &text},
	} {
		t.Run(name, func(t *testing.T) {
			state := bridgedState(t, `{"model":"chutes-glm-5.2","input":"Think."}`)
			response := bridgedChatReply(state, "stop", &schemas.ChatMessage{
				Role:                 schemas.ChatMessageRoleAssistant,
				Content:              &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Done.")},
				ChatAssistantMessage: &schemas.ChatAssistantMessage{ReasoningDetails: []schemas.ChatReasoningDetails{detail}},
			})
			if err := state.Adapter.IngestResponse(state, response, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := BridgedResponse(state, response); !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v, want a malformed reply", err)
			}
		})
	}
}

func TestBridgedRequestRefusesResponsesReplies(t *testing.T) {
	state := bridgedState(t, `{"model":"chutes-glm-5.2","input":"hi"}`)
	if err := state.Adapter.IngestResponse(state, &schemas.BifrostResponse{
		ResponsesResponse: validUnaryResponsesProviderResponse("resp_1"),
	}, nil); !errors.Is(err, ErrProviderResponseMalformed) {
		t.Fatalf("unary Responses reply error = %v", err)
	}
	stream := bridgedState(t, `{"model":"chutes-glm-5.2","input":"hi","stream":true}`)
	if err := stream.Adapter.IngestChunk(stream, &schemas.BifrostStreamChunk{
		BifrostResponsesStreamResponse: validResponsesProviderEvent(schemas.ResponsesStreamResponseTypeCreated, 0, "resp_1"),
	}); !errors.Is(err, ErrProviderResponseMalformed) {
		t.Fatalf("streamed Responses reply error = %v", err)
	}
}

// bridgedStream feeds chunks to the state and its converter, as the HTTP stream does.
type bridgedStream struct {
	t      *testing.T
	state  *State
	stream *BridgedStream
	events []*schemas.BifrostResponsesStreamResponse
	first  bool
}

func newBridgedStream(t *testing.T, body string) *bridgedStream {
	state := bridgedState(t, body)
	stream := NewBridgedStream(state)
	if stream == nil {
		t.Fatal("no converter for a bridged stream")
	}
	return &bridgedStream{t: t, state: state, stream: stream, first: true}
}

func (s *bridgedStream) chunk(delta schemas.ChatStreamResponseChoiceDelta, finish string, usage bool) error {
	s.t.Helper()
	if s.first {
		delta.Role = schemas.Ptr(string(schemas.ChatMessageRoleAssistant))
		s.first = false
	}
	if delta.Reasoning != nil {
		delta.ReasoningDetails = []schemas.ChatReasoningDetails{{Type: schemas.BifrostReasoningDetailsTypeText, Text: delta.Reasoning}}
	}
	chunk := &schemas.BifrostChatResponse{
		ID: "chatcmpl-stream", Object: "chat.completion.chunk", Created: 1_700_000_000, Model: s.state.Resolution.Model,
		Choices: []schemas.BifrostResponseChoice{{
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &delta},
		}},
	}
	if finish != "" {
		chunk.Choices[0].FinishReason = &finish
	}
	if usage {
		chunk.Usage = &schemas.BifrostLLMUsage{PromptTokens: 9, CompletionTokens: 12, TotalTokens: 21}
		if finish == "" {
			chunk.Choices = []schemas.BifrostResponseChoice{}
		}
	}
	if err := s.state.Adapter.IngestChunk(s.state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
		s.t.Fatal(err)
	}
	events, err := s.stream.Convert(chunk)
	s.events = append(s.events, events...)
	return err
}

func (s *bridgedStream) send(delta schemas.ChatStreamResponseChoiceDelta, finish string, usage bool) {
	s.t.Helper()
	if err := s.chunk(delta, finish, usage); err != nil {
		s.t.Fatal(err)
	}
}

func (s *bridgedStream) types() string {
	names := make([]string, 0, len(s.events))
	for index, event := range s.events {
		if event.SequenceNumber != index {
			s.t.Fatalf("event %d has sequence number %d", index, event.SequenceNumber)
		}
		names = append(names, strings.TrimPrefix(string(event.Type), "response."))
	}
	return strings.Join(names, " ")
}

func callDelta(index uint16, id, name, arguments string) schemas.ChatStreamResponseChoiceDelta {
	call := schemas.ChatAssistantMessageToolCall{Index: index, Function: schemas.ChatAssistantMessageToolCallFunction{Arguments: arguments}}
	if id != "" {
		call.ID, call.Type, call.Function.Name = &id, schemas.Ptr("function"), &name
	}
	return schemas.ChatStreamResponseChoiceDelta{ToolCalls: []schemas.ChatAssistantMessageToolCall{call}}
}

func TestBridgedStreamBecomesResponsesEvents(t *testing.T) {
	s := newBridgedStream(t, `{"model":"chutes-glm-5.2","input":"Find a1 and b2.","stream":true,`+bridgedTestTools+`}`)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{Reasoning: schemas.Ptr("Need ")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{Reasoning: schemas.Ptr("the tool.")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("Looking")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr(" it up.")}, "", false)
	s.send(callDelta(0, "call_1", "lookup", ""), "", false)
	s.send(callDelta(0, "", "", `{"id":`), "", false)
	s.send(callDelta(0, "", "", `"a1"}`), "", false)
	s.send(callDelta(1, "call_2", "lookup", `{"id":"b2"}`), "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{}, "tool_calls", false)
	if ProviderStreamTerminal(s.state) {
		t.Fatal("the stream ended before its usage")
	}
	s.send(schemas.ChatStreamResponseChoiceDelta{}, "", true)
	if !ProviderStreamTerminal(s.state) {
		t.Fatal("the stream did not end with its usage")
	}
	want := "created in_progress " +
		"output_item.added content_part.added reasoning_summary_text.delta reasoning_summary_text.delta " +
		"reasoning_summary_text.done content_part.done output_item.done " +
		"output_item.added content_part.added output_text.delta output_text.delta " +
		"output_item.added function_call_arguments.delta function_call_arguments.delta " +
		"output_item.added function_call_arguments.delta " +
		"output_text.done content_part.done output_item.done " +
		"function_call_arguments.done output_item.done function_call_arguments.done output_item.done completed"
	if got := s.types(); got != want {
		t.Fatalf("events =\n%s\nwant\n%s", got, want)
	}
	completed := s.events[len(s.events)-1].Response
	output, err := json.Marshal(completed.Output)
	if err != nil {
		t.Fatal(err)
	}
	wantOutput := `[{"id":"rs_chatcmpl-stream_0","type":"reasoning","status":"completed","content":[{"type":"reasoning_text","text":"Need the tool."}],"summary":[]},` +
		`{"id":"msg_chatcmpl-stream_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Looking it up.","annotations":[],"logprobs":[]}]},` +
		`{"arguments":"{\"id\":\"a1\"}","id":"fc_chatcmpl-stream_2","type":"function_call","status":"completed","call_id":"call_1","name":"lookup"},` +
		`{"arguments":"{\"id\":\"b2\"}","id":"fc_chatcmpl-stream_3","type":"function_call","status":"completed","call_id":"call_2","name":"lookup"}]`
	if string(output) != wantOutput {
		t.Fatalf("output =\n%s\nwant\n%s", output, wantOutput)
	}
	if *completed.Status != schemas.ResponsesResponseStatusCompleted || completed.CompletedAt == nil ||
		completed.Usage == nil || completed.Usage.InputTokens != 9 || completed.Usage.OutputTokens != 12 ||
		len(completed.Tools) != 1 || completed.Store == nil || *completed.Store {
		t.Fatalf("completed response = %+v", completed)
	}
	if created := s.events[0].Response; created.ID == nil || *created.ID != "chatcmpl-stream" || len(created.Output) != 0 ||
		*created.Status != schemas.ResponsesResponseStatusInProgress || len(created.Tools) != 1 {
		t.Fatalf("created response = %+v", created)
	}
}

func TestBridgedStreamCutShortIsIncomplete(t *testing.T) {
	s := newBridgedStream(t, `{"model":"chutes-glm-5.2","input":"Count.","max_output_tokens":16,"stream":true}`)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("One, two")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{}, "length", true)
	want := "created in_progress output_item.added content_part.added output_text.delta " +
		"output_text.done content_part.done output_item.done incomplete"
	if got := s.types(); got != want {
		t.Fatalf("events =\n%s\nwant\n%s", got, want)
	}
	incomplete := s.events[len(s.events)-1].Response
	if *incomplete.Status != schemas.ResponsesResponseStatusIncomplete || incomplete.CompletedAt != nil ||
		incomplete.IncompleteDetails == nil || incomplete.IncompleteDetails.Reason != schemas.ResponsesResponseIncompleteReasonMaxOutputTokens ||
		*incomplete.Output[0].Status != schemas.ResponsesResponseStatusIncomplete {
		t.Fatalf("incomplete response = %+v", incomplete)
	}
}

func TestBridgedStreamTextThenRefusal(t *testing.T) {
	s := newBridgedStream(t, `{"model":"chutes-glm-5.2","input":"Do harm.","stream":true}`)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("Well. ")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{Refusal: schemas.Ptr("I can't help.")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{}, "stop", true)
	want := "created in_progress output_item.added content_part.added output_text.delta " +
		"output_text.done content_part.done content_part.added refusal.delta " +
		"refusal.done content_part.done output_item.done completed"
	if got := s.types(); got != want {
		t.Fatalf("events =\n%s\nwant\n%s", got, want)
	}
	blocks := s.events[len(s.events)-1].Response.Output[0].Content.ContentBlocks
	if len(blocks) != 2 || *blocks[0].Text != "Well. " || blocks[1].ResponsesOutputMessageContentRefusal.Refusal != "I can't help." {
		t.Fatalf("message = %+v", blocks)
	}
}

func TestBridgedStreamTextAcrossCallsJoinsTheMessage(t *testing.T) {
	s := newBridgedStream(t, `{"model":"chutes-glm-5.2","input":"Find a1.","stream":true,`+bridgedTestTools+`}`)
	s.send(schemas.ChatStreamResponseChoiceDelta{Reasoning: schemas.Ptr("Need ")}, "", false)
	s.send(callDelta(0, "call_1", "lookup", `{"id":"a1"}`), "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{Reasoning: schemas.Ptr("the tool.")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("Asked.")}, "", false)
	s.send(callDelta(1, "call_2", "lookup", `{"id":"b2"}`), "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr(" Twice.")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{}, "tool_calls", true)
	want := "created in_progress output_item.added content_part.added reasoning_summary_text.delta " +
		"output_item.added function_call_arguments.delta reasoning_summary_text.delta " +
		"reasoning_summary_text.done content_part.done output_item.done " +
		"output_item.added content_part.added output_text.delta " +
		"output_item.added function_call_arguments.delta output_text.delta " +
		"function_call_arguments.done output_item.done output_text.done content_part.done output_item.done " +
		"function_call_arguments.done output_item.done completed"
	if got := s.types(); got != want {
		t.Fatalf("events =\n%s\nwant\n%s", got, want)
	}
	output := s.events[len(s.events)-1].Response.Output
	if len(output) != 4 || *output[0].Content.ContentBlocks[0].Text != "Need the tool." ||
		*output[1].Type != schemas.ResponsesMessageTypeFunctionCall ||
		*output[2].Content.ContentBlocks[0].Text != "Asked. Twice." || *output[3].ResponsesToolMessage.CallID != "call_2" {
		t.Fatalf("output = %s", replayed(t, output))
	}
}

func TestBridgedStreamEndsWithoutOutput(t *testing.T) {
	s := newBridgedStream(t, `{"model":"chutes-glm-5.2","input":"Say nothing.","stream":true}`)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{}, "stop", true)
	if got := s.types(); got != "created in_progress completed" {
		t.Fatalf("events = %s", got)
	}
}

// replayed is a reply's output as its client sends it back in the next request's input.
func replayed(t *testing.T, output []schemas.ResponsesMessage) string {
	t.Helper()
	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(strings.TrimPrefix(string(encoded), "["), "]")
}

func TestBridgedReplyGoesBackAsHistory(t *testing.T) {
	first := bridgedState(t, `{"model":"chutes-glm-5.2","input":"Find a1.",`+bridgedTestTools+`}`)
	reasoning := "\n\n"
	reply := ingestBridgedReply(t, first, bridgedChatReply(first, "tool_calls", &schemas.ChatMessage{
		Role:    schemas.ChatMessageRoleAssistant,
		Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Looking it up.")},
		ChatAssistantMessage: &schemas.ChatAssistantMessage{
			Reasoning:        &reasoning,
			ReasoningDetails: []schemas.ChatReasoningDetails{{Type: schemas.BifrostReasoningDetailsTypeText, Text: &reasoning}},
			ToolCalls: []schemas.ChatAssistantMessageToolCall{{
				Type: schemas.Ptr("function"), ID: schemas.Ptr("call_1"),
				Function: schemas.ChatAssistantMessageToolCallFunction{Name: schemas.Ptr("lookup"), Arguments: `{"id":"a1"}`},
			}},
		},
	}))
	next := bridgedState(t, `{"model":"chutes-glm-5.2","input":[{"role":"user","content":"Find a1."},`+replayed(t, reply.Output)+
		`,{"type":"function_call_output","call_id":"call_1","output":"a1 is 42"}],`+bridgedTestTools+`}`)
	messages := wireMessages(t, next)
	if len(messages) != 3 || string(messages[1]["role"]) != `"assistant"` || string(messages[1]["reasoning"]) != `"\n\n"` ||
		string(messages[1]["content"]) != `"Looking it up."` || !strings.Contains(string(messages[1]["tool_calls"]), `"call_1"`) ||
		string(messages[2]["role"]) != `"tool"` || string(messages[2]["tool_call_id"]) != `"call_1"` {
		t.Fatalf("messages = %s", messagesText(messages))
	}

	// Text that a model streams after its calls joins the message that precedes them, so that the
	// calls' results can follow the calls.
	s := newBridgedStream(t, `{"model":"chutes-glm-5.2","input":"Find a1.","stream":true,`+bridgedTestTools+`}`)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("Asked")}, "", false)
	s.send(callDelta(0, "call_1", "lookup", `{"id":"a1"}`), "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr(".")}, "", false)
	s.send(schemas.ChatStreamResponseChoiceDelta{}, "tool_calls", true)
	streamed := s.events[len(s.events)-1].Response.Output
	next = bridgedState(t, `{"model":"chutes-glm-5.2","input":[{"role":"user","content":"Find a1."},`+replayed(t, streamed)+
		`,{"type":"function_call_output","call_id":"call_1","output":"a1 is 42"}],`+bridgedTestTools+`}`)
	messages = wireMessages(t, next)
	if len(messages) != 3 || string(messages[1]["content"]) != `"Asked."` || !strings.Contains(string(messages[1]["tool_calls"]), `"call_1"`) ||
		string(messages[2]["role"]) != `"tool"` {
		t.Fatalf("messages = %s", messagesText(messages))
	}
}

func messagesText(messages []map[string]json.RawMessage) string {
	encoded, _ := json.Marshal(messages)
	return string(encoded)
}

func TestAzureBridgedRequestsRefuseReasoningHistory(t *testing.T) {
	err := bridgedValidationError(t, `{"model":"azure-minimax-m3","input":[{"role":"user","content":"hi"},`+
		`{"type":"reasoning","id":"rs_1","summary":[],"content":[{"type":"reasoning_text","text":"Thinking."}]},`+
		`{"role":"assistant","content":[{"type":"output_text","text":"Hello."}]},{"role":"user","content":"again"}]}`)
	if err == nil || !strings.Contains(err.Error(), "reasoning input items") {
		t.Fatalf("error = %v", err)
	}
}
