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

// These tests cover Chat Completions clients of deployments that take only Responses, such as Pro.

const chatBridgeTools = `"tools":[{"type":"function","function":{"name":"lookup","description":"Look up a value","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}}]`

// chatBridgeValidation resolves a Chat Completions request and checks it as a pair does.
func chatBridgeValidation(t *testing.T, body string) (*State, error) {
	t.Helper()
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)})
	if err != nil {
		return nil, err
	}
	if !resolution.Bridged() {
		t.Fatalf("deployment %s takes Chat Completions itself", resolution.Deployment.ID)
	}
	state := NewState(resolution, "sk-test", nil, AdapterFor(resolution.Provider))
	return state, state.Adapter.ValidateRequest(state)
}

// chatBridgeState prepares a Chat Completions request that reaches a deployment that takes only
// Responses, as a pair does.
func chatBridgeState(t *testing.T, body string) *State {
	t.Helper()
	state, err := chatBridgeValidation(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatal(err)
	}
	return state
}

// chatBridgeProviderBody is the Responses body that the provider gets.
func chatBridgeProviderBody(t *testing.T, state *State) map[string]json.RawMessage {
	t.Helper()
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, state.Resolution.WireRequestType())
	request, err := state.Resolution.ToBifrost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if request.ResponsesRequest == nil || request.ChatRequest != nil || request.RequestType != state.Resolution.WireRequestType() {
		t.Fatalf("provider request = %#v", request)
	}
	if err := PrepareProviderRequest(ctx, state, request); err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(preparedProviderBody(t, ctx, request.ResponsesRequest), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestChatReachesResponsesOnlyDeploymentsThroughResponses(t *testing.T) {
	for _, test := range []struct{ model, include string }{
		// OpenAI takes back the encrypted reasoning of its replies, which Azure refuses.
		{"openai-gpt-5.6-sol-pro", `["reasoning.encrypted_content"]`},
		{"azure-gpt-6-astra-pro", ""},
	} {
		t.Run(test.model, func(t *testing.T) {
			state := chatBridgeState(t, `{"model":"`+test.model+`","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"Find a1."},`+
				`{"role":"assistant","content":"Looking.","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]},`+
				`{"role":"tool","tool_call_id":"call_1","content":"42"},{"role":"user","content":"Answer."}],`+chatBridgeTools+
				`,"tool_choice":"auto","max_completion_tokens":300,"reasoning_effort":"high","stream":true,"stream_options":{"include_usage":true},`+
				`"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false},"strict":true}}}`)
			resolution := state.Resolution
			if resolution.RequestType != schemas.ChatCompletionStreamRequest || resolution.WireRoute() != catalog.RouteResponses ||
				resolution.WireRequestType() != schemas.ResponsesStreamRequest {
				t.Fatalf("request type %s, wire %s %s", resolution.RequestType, resolution.WireRoute(), resolution.WireRequestType())
			}
			body := chatBridgeProviderBody(t, state)
			want := map[string]string{
				"model":             `"` + resolution.Model + `"`,
				"input":             `[{"type":"message","role":"system","content":"Be brief."},{"type":"message","role":"user","content":"Find a1."},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Looking.","annotations":[],"logprobs":[]}]},{"arguments":"{\"id\":\"a1\"}","type":"function_call","call_id":"call_1","name":"lookup"},{"type":"function_call_output","call_id":"call_1","output":"42"},{"type":"message","role":"user","content":"Answer."}]`,
				"tools":             `[{"type":"function","name":"lookup","description":"Look up a value","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]},"strict":false}]`,
				"tool_choice":       `"auto"`,
				"max_output_tokens": `300`,
				"reasoning":         `{"effort":"high","mode":"pro","summary":null}`,
				"text":              `{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false},"strict":true}}`,
				"store":             `false`,
				"stream":            `true`,
				"service_tier":      `"default"`,
				"include":           test.include,
			}
			for name, value := range want {
				if string(body[name]) != value {
					t.Errorf("%s = %s, want %s", name, body[name], value)
				}
			}
			for name := range body {
				if _, ok := want[name]; !ok {
					t.Errorf("unexpected field %s = %s", name, body[name])
				}
			}
		})
	}
}

func TestChatKeepsDeploymentsThatTakeChatCompletions(t *testing.T) {
	resolution, err := catalog.ResolveRequest(catalog.RequestInput{
		Method: "POST", Path: "/v1/chat/completions", Body: []byte(`{"model":"provider:openai gpt-5.6-sol","messages":[{"role":"user","content":"hi"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Bridged() || resolution.WireRoute() != catalog.RouteChat || resolution.WireRequestType() != schemas.ChatCompletionRequest {
		t.Fatalf("deployment %s with Chat Completions was bridged", resolution.Deployment.ID)
	}
}

func TestChatBridgeRefusesWhatResponsesLackOrTheFormatRefuses(t *testing.T) {
	for _, test := range []struct{ name, fields, want string }{
		{"several choices", `"n":2`, "n: Responses deployments do not support several choices"},
		{"seed", `"seed":7`, "seed: Responses deployments do not support seeds"},
		{"stop sequences", `"stop":["END"]`, "stop: Responses deployments do not support stop sequences"},
		{"logit bias", `"logit_bias":{"50256":-100}`, "logit_bias: Responses deployments do not support logit biases"},
		{"predicted output", `"prediction":{"type":"content","content":"x"}`, "prediction: Responses deployments do not support predicted outputs"},
		{"message name", `"messages":[{"role":"user","name":"ann","content":"hi"}]`, "messages[0].name: Responses deployments do not support message names"},
		// OpenAI's format refuses these on Chat Completions, so the translation must not drop them.
		{"repetition penalty", `"repetition_penalty":1.1`, "repetition_penalty is not supported for OpenAI-format deployments"},
		{"reasoning display", `"reasoning":{"display":"summarized"}`, "reasoning.display"},
		{"top_k", `"top_k":5`, "top_k"},
		{"prompt cache breakpoint member", `"messages":[{"role":"user","content":[{"type":"text","text":"hi","prompt_cache_breakpoint":{"mode":"explicit","ttl":"1h"}}]}]`, "prompt_cache_breakpoint must contain only mode"},
		{"prompt cache option", `"prompt_cache_options":{"mode":"implicit","scope":"org"}`, "prompt_cache_options supports only mode and ttl"},
		{"breakpoint in a tool output", `"messages":[{"role":"user","content":"Find a1."},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]},` +
			`{"role":"tool","tool_call_id":"call_1","content":[{"type":"text","text":"42","prompt_cache_breakpoint":{"mode":"explicit"}}]}],` + chatBridgeTools,
			"messages[2].content[0].prompt_cache_breakpoint: Responses deployments do not support prompt cache breakpoints in tool outputs"},
		{"cache control in a tool output", `"messages":[{"role":"user","content":"Find a1."},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]},` +
			`{"role":"tool","tool_call_id":"call_1","content":[{"type":"text","text":"42","cache_control":{"type":"ephemeral"}}]}],` + chatBridgeTools, "cache_control"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"hi"}],` + test.fields + `}`
			if strings.Contains(test.fields, `"messages"`) {
				body = `{"model":"openai-gpt-5.6-sol-pro",` + test.fields + `}`
			}
			_, err := chatBridgeValidation(t, body)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// A Chat Completions client gets an OpenAI deployment's reasoning as encrypted reasoning_details,
// which it sends back so that the model keeps its reasoning across turns. Azure refuses reasoning
// that comes back.
func TestChatBridgeTakesBackEncryptedReasoning(t *testing.T) {
	history := `"messages":[{"role":"user","content":"Find a1."},{"role":"assistant","reasoning_details":[{"index":0,"type":"reasoning.encrypted","id":"rs_1","data":"opaque"}],` +
		`"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"42"}],` + chatBridgeTools
	state := chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro",`+history+`}`)
	input := string(chatBridgeProviderBody(t, state)["input"])
	if !strings.Contains(input, `{"id":"rs_1","type":"reasoning","summary":[],"encrypted_content":"opaque"}`) {
		t.Fatalf("input = %s", input)
	}
	for _, test := range []struct{ name, body, want string }{
		{"Azure", `{"model":"azure-gpt-6-astra-pro",` + history + `}`, "reasoning_details history is not supported for the selected deployment"},
		{"reasoning text", `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hello.","reasoning_details":[{"index":0,"type":"reasoning.text","text":"Thinking.","signature":"sig"}]},{"role":"user","content":"again"}]}`, "reasoning_details[0].type is not supported for the selected deployment"},
		{"plain reasoning", `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"Hello.","reasoning":"Thinking."},{"role":"user","content":"again"}]}`, "requires signed reasoning_details"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := chatBridgeValidation(t, test.body); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func chatBridgeReply(output ...schemas.ResponsesMessage) *schemas.BifrostResponse {
	return &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{
		ID: schemas.Ptr("resp_bridge"), Object: "response", CreatedAt: 1_700_000_000,
		Status: schemas.Ptr(schemas.ResponsesResponseStatusCompleted), Output: output,
		Usage: &schemas.ResponsesResponseUsage{
			InputTokens: 20, OutputTokens: 15, TotalTokens: 35,
			OutputTokensDetails: &schemas.ResponsesResponseOutputTokens{ReasoningTokens: 4},
		},
	}}
}

func encryptedReasoningItem(id, data string) schemas.ResponsesMessage {
	return schemas.ResponsesMessage{
		ID: schemas.Ptr(id), Type: schemas.Ptr(schemas.ResponsesMessageTypeReasoning),
		ResponsesReasoning: &schemas.ResponsesReasoning{Summary: []schemas.ResponsesReasoningSummary{}, EncryptedContent: schemas.Ptr(data)},
	}
}

func textItem(id, text string) schemas.ResponsesMessage {
	return schemas.ResponsesMessage{
		ID: schemas.Ptr(id), Type: schemas.Ptr(schemas.ResponsesMessageTypeMessage),
		Role: schemas.Ptr(schemas.ResponsesInputMessageRoleAssistant), Status: schemas.Ptr("completed"),
		Content: &schemas.ResponsesMessageContent{ContentBlocks: []schemas.ResponsesMessageContentBlock{{
			Type: schemas.ResponsesOutputMessageContentTypeText, Text: schemas.Ptr(text),
			ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{}},
		}}},
	}
}

func functionCallItem(id, callID, name, arguments string) schemas.ResponsesMessage {
	return schemas.ResponsesMessage{
		ID: schemas.Ptr(id), Type: schemas.Ptr(schemas.ResponsesMessageTypeFunctionCall), Status: schemas.Ptr("completed"),
		ResponsesToolMessage: &schemas.ResponsesToolMessage{CallID: schemas.Ptr(callID), Name: schemas.Ptr(name), Arguments: schemas.Ptr(arguments)},
	}
}

func TestChatBridgeReplyBecomesChatCompletions(t *testing.T) {
	state := chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Find a1."}],`+chatBridgeTools+`}`)
	response := chatBridgeReply(
		encryptedReasoningItem("rs_1", "opaque"),
		textItem("msg_1", "Looking it up."),
		functionCallItem("fc_1", "call_1", "lookup", `{"id":"a1"}`),
	)
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
	if state.Response != response || converted.ResponsesResponse != nil || converted.ChatResponse == nil {
		t.Fatalf("the state lost the provider's reply, or the client got %#v", converted)
	}
	reply := converted.ChatResponse
	if reply.ID != "resp_bridge" || reply.Object != "chat.completion" || reply.Usage == nil || reply.Usage.PromptTokens != 20 ||
		reply.Usage.CompletionTokens != 15 || reply.Usage.CompletionTokensDetails == nil || reply.Usage.CompletionTokensDetails.ReasoningTokens != 4 {
		t.Fatalf("reply = %+v", reply)
	}
	choice := reply.Choices[0]
	message, err := json.Marshal(choice.ChatNonStreamResponseChoice.Message)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"role":"assistant","content":"Looking it up.","refusal":null,"reasoning_details":[{"id":"rs_1","index":0,"type":"reasoning.encrypted","data":"opaque"}],` +
		`"tool_calls":[{"index":0,"type":"function","id":"call_1","function":{"name":"lookup","arguments":"{\"id\":\"a1\"}"}}]}`
	if *choice.FinishReason != "tool_calls" || string(message) != want {
		t.Fatalf("finish reason %s, message =\n%s\nwant\n%s", *choice.FinishReason, message, want)
	}

	// The client sends the reply back unchanged as history, with the tool's output in text parts, and
	// the provider gets its items again.
	next := chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Find a1."},`+string(message)+`,`+
		`{"role":"tool","tool_call_id":"call_1","content":[{"type":"text","text":"a1 is "},{"type":"text","text":"42"}]}],`+chatBridgeTools+`}`)
	input := string(chatBridgeProviderBody(t, next)["input"])
	if !strings.Contains(input, `{"id":"rs_1","type":"reasoning","summary":[],"encrypted_content":"opaque"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Looking it up.","annotations":[],"logprobs":[]}]},{"arguments":"{\"id\":\"a1\"}","type":"function_call","call_id":"call_1","name":"lookup"},{"type":"function_call_output","call_id":"call_1","output":"a1 is 42"}`) {
		t.Fatalf("input = %s", input)
	}
}

// OpenAI takes a prompt cache breakpoint on the assistant's text too.
func TestChatBridgeKeepsAssistantCacheBreakpoints(t *testing.T) {
	state := chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Say hi."},`+
		`{"role":"assistant","content":[{"type":"text","text":"Hi.","prompt_cache_breakpoint":{"mode":"explicit"}}]},{"role":"user","content":"Again."}]}`)
	input := string(chatBridgeProviderBody(t, state)["input"])
	if !strings.Contains(input, `{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi.","annotations":[],"logprobs":[],"prompt_cache_breakpoint":{"mode":"explicit"}}]}`) {
		t.Fatalf("input = %s", input)
	}
}

func TestChatBridgeRefusesBadReplies(t *testing.T) {
	body := `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Find a1."}],` + chatBridgeTools + `}`
	for _, test := range []struct {
		name     string
		response *schemas.BifrostResponse
	}{
		{"a Chat Completions reply", &schemas.BifrostResponse{ChatResponse: validUnaryChatProviderResponse()}},
		{"a call to an undeclared tool", chatBridgeReply(functionCallItem("fc_1", "call_1", "missing", `{}`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := chatBridgeState(t, body)
			if err := state.Adapter.IngestResponse(state, test.response, nil); !errors.Is(err, ErrProviderResponseMalformed) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// chatBridgeStream feeds a Responses stream, as OpenAI sends it, to a Chat Completions request's
// state and converter, as the HTTP stream does.
type chatBridgeStream struct {
	t        *testing.T
	state    *State
	stream   *BridgedStream
	sequence int
	output   []schemas.ResponsesMessage
	chunks   []*schemas.BifrostChatResponse
}

func newChatBridgeStream(t *testing.T, body string) *chatBridgeStream {
	t.Helper()
	state := chatBridgeState(t, body)
	stream := NewBridgedStream(state)
	if stream == nil {
		t.Fatal("no converter for a bridged stream")
	}
	s := &chatBridgeStream{t: t, state: state, stream: stream}
	for _, eventType := range []schemas.ResponsesStreamResponseType{schemas.ResponsesStreamResponseTypeCreated, schemas.ResponsesStreamResponseTypeInProgress} {
		event := validResponsesProviderEvent(eventType, 0, "resp_stream")
		event.Response.CreatedAt = 1_700_000_000
		s.send(event)
	}
	return s
}

func (s *chatBridgeStream) send(event *schemas.BifrostResponsesStreamResponse) {
	s.t.Helper()
	event.SequenceNumber = s.sequence
	s.sequence++
	chunk := &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}
	if err := s.state.Adapter.IngestChunk(s.state, chunk); err != nil {
		s.t.Fatalf("%s: %v", event.Type, err)
	}
	converted, err := s.stream.Convert(chunk)
	if err != nil {
		s.t.Fatalf("%s: %v", event.Type, err)
	}
	for _, chunk := range converted {
		s.chunks = append(s.chunks, chunk.BifrostChatResponse)
	}
}

func (s *chatBridgeStream) item(added, done schemas.ResponsesMessage, events func(output int, id *string)) {
	output := len(s.output)
	s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: &output, Item: &added})
	if events != nil {
		events(output, added.ID)
	}
	s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &output, Item: &done})
	s.output = append(s.output, done)
}

func (s *chatBridgeStream) reasoning(id, data string) {
	added := encryptedReasoningItem(id, data)
	added.ResponsesReasoning.EncryptedContent = nil
	s.item(added, encryptedReasoningItem(id, data), nil)
}

func (s *chatBridgeStream) text(id string, deltas ...string) {
	added := textItem(id, "")
	added.Status = schemas.Ptr("in_progress")
	added.Content.ContentBlocks = []schemas.ResponsesMessageContentBlock{}
	text := strings.Join(deltas, "")
	s.item(added, textItem(id, text), func(output int, id *string) {
		content := 0
		part := func(text string) *schemas.ResponsesMessageContentBlock {
			return &schemas.ResponsesMessageContentBlock{
				Type: schemas.ResponsesOutputMessageContentTypeText, Text: schemas.Ptr(text),
				ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{}},
			}
		}
		s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeContentPartAdded, OutputIndex: &output, ContentIndex: &content, ItemID: id, Part: part("")})
		for _, delta := range deltas {
			s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDelta, OutputIndex: &output, ContentIndex: &content, ItemID: id, Delta: schemas.Ptr(delta)})
		}
		s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDone, OutputIndex: &output, ContentIndex: &content, ItemID: id, Text: schemas.Ptr(text)})
		s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeContentPartDone, OutputIndex: &output, ContentIndex: &content, ItemID: id, Part: part(text)})
	})
}

func (s *chatBridgeStream) call(id, callID, name string, fragments ...string) {
	added := functionCallItem(id, callID, name, "")
	added.Status = schemas.Ptr("in_progress")
	arguments := strings.Join(fragments, "")
	s.item(added, functionCallItem(id, callID, name, arguments), func(output int, id *string) {
		for _, fragment := range fragments {
			s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta, OutputIndex: &output, ItemID: id, Delta: schemas.Ptr(fragment)})
		}
		s.send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone, OutputIndex: &output, ItemID: id, Arguments: schemas.Ptr(arguments)})
	})
}

func (s *chatBridgeStream) end(eventType schemas.ResponsesStreamResponseType) {
	terminal := validResponsesProviderEvent(eventType, 0, "resp_stream")
	terminal.Response.CreatedAt = 1_700_000_000
	terminal.Response.Output = s.output
	terminal.Response.Usage = chatBridgeReply().ResponsesResponse.Usage
	s.send(terminal)
}

// deltas describes the chunks that the client got, one line each.
func (s *chatBridgeStream) deltas() string {
	lines := make([]string, len(s.chunks))
	for i, chunk := range s.chunks {
		if len(chunk.Choices) == 0 {
			lines[i] = "usage"
			continue
		}
		choice := chunk.Choices[0]
		encoded, err := json.Marshal(choice.ChatStreamResponseChoice.Delta)
		if err != nil {
			s.t.Fatal(err)
		}
		lines[i] = string(encoded)
		if choice.FinishReason != nil {
			lines[i] += " " + *choice.FinishReason
		}
	}
	return strings.Join(lines, "\n")
}

func TestChatBridgeStreamBecomesChatChunks(t *testing.T) {
	s := newChatBridgeStream(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Find a1."}],"stream":true,`+chatBridgeTools+`}`)
	s.reasoning("rs_1", "opaque")
	s.text("msg_1", "Looking", " it up.")
	s.call("fc_1", "call_1", "lookup", `{"id":`, `"a1"}`)
	if ProviderStreamTerminal(s.state) {
		t.Fatal("the stream ended before its terminal event")
	}
	s.end(schemas.ResponsesStreamResponseTypeCompleted)
	if !ProviderStreamTerminal(s.state) {
		t.Fatal("the stream did not end with its terminal event")
	}
	// Chunks that carry nothing stay out, and the usage follows the finish reason in its own chunk.
	want := strings.Join([]string{
		`{"role":"assistant"}`,
		`{"reasoning_details":[{"id":"rs_1","index":0,"type":"reasoning.encrypted","data":"opaque"}]}`,
		`{"content":"Looking"}`,
		`{"content":" it up."}`,
		`{"tool_calls":[{"index":0,"type":"function","id":"call_1","function":{"name":"lookup","arguments":""}}]}`,
		`{"tool_calls":[{"index":0,"function":{"arguments":"{\"id\":"}}]}`,
		`{"tool_calls":[{"index":0,"function":{"arguments":"\"a1\"}"}}]}`,
		`{} tool_calls`,
		`usage`,
	}, "\n")
	if got := s.deltas(); got != want {
		t.Fatalf("chunks =\n%s\nwant\n%s", got, want)
	}
	for _, chunk := range s.chunks {
		if chunk.ID != "resp_stream" || chunk.Object != "chat.completion.chunk" || chunk.Created != 1_700_000_000 {
			t.Fatalf("chunk = %+v", chunk)
		}
	}
	if usage := s.chunks[len(s.chunks)-1].Usage; usage == nil || usage.PromptTokens != 20 || usage.CompletionTokens != 15 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestChatBridgeStreamCutShortEndsForLength(t *testing.T) {
	s := newChatBridgeStream(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"Count."}],"max_completion_tokens":16,"stream":true}`)
	s.text("msg_1", "One, two")
	s.end(schemas.ResponsesStreamResponseTypeIncomplete)
	want := `{"role":"assistant"}` + "\n" + `{"content":"One, two"}` + "\n" + `{} length` + "\nusage"
	if got := s.deltas(); got != want {
		t.Fatalf("chunks =\n%s\nwant\n%s", got, want)
	}
}

func TestChatBridgeRefusesChatStreams(t *testing.T) {
	state := chatBridgeState(t, `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{
		BifrostChatResponse: validChatProviderChunk("chatcmpl_1", false),
	}); !errors.Is(err, ErrProviderResponseMalformed) {
		t.Fatalf("streamed Chat Completions reply error = %v", err)
	}
}
