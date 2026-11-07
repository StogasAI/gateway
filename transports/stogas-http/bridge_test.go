package stogashttp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof/prooftest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
)

const bridgedStreamBody = `{"model":"chutes-glm-5.2","input":"hi","stream":true}`

// bridgedTestState prepares a request that reaches a deployment on the other interface, as a pair
// does before it calls the provider.
func bridgedTestState(t *testing.T, path, body string) *stogas.State {
	t.Helper()
	resolution := mustResolvedRequest(t, path, body)
	if !resolution.Bridged() {
		t.Fatalf("deployment %s takes the client's interface itself", resolution.Deployment.ID)
	}
	state := &stogas.State{
		Pair:      stogas.Pair{Resolution: resolution, Adapter: stogas.AdapterFor(resolution.Provider)},
		StartedAt: time.Now().Add(-5 * time.Millisecond),
	}
	if err := state.Adapter.ValidateRequest(state); err != nil {
		t.Fatal(err)
	}
	if err := state.Adapter.SanitizeRequest(state); err != nil {
		t.Fatal(err)
	}
	return state
}

// sendBridgedChunks streams a reply with reasoning and text, then its usage, in its own chunk or
// with the finish reason.
func sendBridgedChunks(stream chan<- *schemas.BifrostStreamChunk, state *stogas.State, usageWithFinish bool) {
	chunk := func(delta schemas.ChatStreamResponseChoiceDelta, finish *string, usage *schemas.BifrostLLMUsage) *schemas.BifrostStreamChunk {
		choices := []schemas.BifrostResponseChoice{{
			FinishReason:             finish,
			ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{Delta: &delta},
		}}
		if usage != nil && finish == nil {
			choices = []schemas.BifrostResponseChoice{}
		}
		return &schemas.BifrostStreamChunk{BifrostChatResponse: &schemas.BifrostChatResponse{
			ID: "chatcmpl-bridged", Object: "chat.completion.chunk", Created: 1_700_000_000,
			Model: state.Resolution.Model, Choices: choices, Usage: usage,
		}}
	}
	reasoning := "Short."
	stream <- chunk(schemas.ChatStreamResponseChoiceDelta{
		Role: schemas.Ptr(string(schemas.ChatMessageRoleAssistant)), Reasoning: &reasoning,
		ReasoningDetails: []schemas.ChatReasoningDetails{{Type: schemas.BifrostReasoningDetailsTypeText, Text: &reasoning}},
	}, nil, nil)
	stream <- chunk(schemas.ChatStreamResponseChoiceDelta{Content: schemas.Ptr("Hello")}, nil, nil)
	usage := &schemas.BifrostLLMUsage{PromptTokens: 3, CompletionTokens: 4, TotalTokens: 7}
	if usageWithFinish {
		stream <- chunk(schemas.ChatStreamResponseChoiceDelta{}, schemas.Ptr("stop"), usage)
	} else {
		stream <- chunk(schemas.ChatStreamResponseChoiceDelta{}, schemas.Ptr("stop"), nil)
		stream <- chunk(schemas.ChatStreamResponseChoiceDelta{}, nil, usage)
	}
	close(stream)
}

type sseEvent struct {
	name string
	data map[string]json.RawMessage
}

func parseSSEEvents(t *testing.T, body string) []sseEvent {
	t.Helper()
	var events []sseEvent
	for frame := range strings.SplitSeq(body, "\n\n") {
		var event sseEvent
		for line := range strings.SplitSeq(frame, "\n") {
			if name, ok := strings.CutPrefix(line, "event: "); ok {
				event.name = name
			} else if data, ok := strings.CutPrefix(line, "data: "); ok {
				if err := json.Unmarshal([]byte(data), &event.data); err != nil {
					t.Fatalf("event data %q: %v", data, err)
				}
			}
		}
		if event.name != "" || event.data != nil {
			events = append(events, event)
		}
	}
	return events
}

func TestWriteSSEStreamSendsBridgedChatAsResponsesEvents(t *testing.T) {
	ctx := newTestRequest(t)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)
	state := bridgedTestState(t, "/v1/responses", bridgedStreamBody)
	reader := startTestStream(&Server{}, ctx, bifrostCtx, state, stream, cancel, nil)
	defer reader.Close()
	go sendBridgedChunks(stream, state, false)

	body := readResponseBodyStream(t, reader)
	if strings.Contains(body, "[DONE]") || strings.Contains(body, "chat.completion") {
		t.Fatalf("a Responses client got Chat Completions framing: %q", body)
	}
	events := parseSSEEvents(t, body)
	names := make([]string, 0, len(events))
	for index, event := range events {
		var eventType string
		var sequence int
		if json.Unmarshal(event.data["type"], &eventType) != nil || eventType != event.name ||
			json.Unmarshal(event.data["sequence_number"], &sequence) != nil || sequence != index {
			t.Fatalf("event %d %q = %v", index, event.name, event.data)
		}
		names = append(names, strings.TrimPrefix(event.name, "response."))
	}
	want := "created in_progress output_item.added content_part.added reasoning_text.delta " +
		"reasoning_text.done content_part.done output_item.done " +
		"output_item.added content_part.added output_text.delta output_text.done content_part.done output_item.done completed"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("events =\n%s\nwant\n%s", got, want)
	}
	var completed struct {
		ID     string `json:"id"`
		Model  string `json:"model"`
		Status string `json:"status"`
		Store  bool   `json:"store"`
		Output []struct {
			Type string `json:"type"`
		} `json:"output"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(events[len(events)-1].data["response"], &completed); err != nil {
		t.Fatal(err)
	}
	if completed.ID != "chatcmpl-bridged" || completed.Model != state.Resolution.Deployment.ModelID ||
		completed.Status != "completed" || completed.Store || len(completed.Output) != 2 ||
		completed.Output[0].Type != "reasoning" || completed.Output[1].Type != "message" ||
		completed.Usage.InputTokens != 3 || completed.Usage.OutputTokens != 4 {
		t.Fatalf("completed response = %+v", completed)
	}
	if !state.ProviderOutputObserved || state.TTFTMS == nil {
		t.Fatal("delivered output was not observed")
	}
	if state.Response == nil || state.Response.ChatResponse == nil {
		t.Fatal("the state lost the provider's Chat Completions reply")
	}
}

func TestWriteSSEStreamSignsBridgedResponsesTerminalEvent(t *testing.T) {
	for _, usageWithFinish := range []bool{false, true} {
		t.Run(map[bool]string{false: "usage alone", true: "usage with the finish reason"}[usageWithFinish], func(t *testing.T) {
			testBridgedResponsesReceipt(t, usageWithFinish)
		})
	}
}

func testBridgedResponsesReceipt(t *testing.T, usageWithFinish bool) {
	service, publicKey, boot := testProofService(t)
	ctx := newTestRequest(t)
	testRequestBody(ctx, bridgedStreamBody)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	bifrostCtx.SetValue(stogasMetadataKey, true)
	stream := make(chan *schemas.BifrostStreamChunk)
	state := bridgedTestState(t, "/v1/responses", bridgedStreamBody)
	state.RequestID = "018f4f70-7c88-7b9a-baf8-31a93d2cf615"
	state.NodeID = strings.Repeat("5", 64)
	state.FinalEvent = &billing.RequestEvent{
		CreatedAt: "2026-08-24T12:34:56.789Z", Usage: billing.RequestUsage{BilledCostUSD: "0", UpstreamCostUSD: "0", Meters: billing.EventMeters{}},
	}
	reader := startTestStream(&Server{proofs: service}, ctx, bifrostCtx, state, stream, cancel, nil)
	defer reader.Close()
	go sendBridgedChunks(stream, state, usageWithFinish)

	body := readResponseBodyStream(t, reader)
	proofPrefix := ": " + proofhttp.SSECommentPrefix
	proofIndex := strings.Index(body, proofPrefix)
	terminalIndex := strings.Index(body, "event: response.completed\n")
	if proofIndex < 0 || terminalIndex < 0 || proofIndex > terminalIndex ||
		strings.LastIndex(body, "event: response.output_item.done\n") > proofIndex {
		t.Fatalf("expected the receipt after the items and before response.completed, got %q", body)
	}
	proofEnd := strings.Index(body[proofIndex:], "\n\n")
	var proofObject proof.Object
	if err := json.Unmarshal([]byte(strings.TrimSpace(body[proofIndex+len(proofPrefix):proofIndex+proofEnd])), &proofObject); err != nil {
		t.Fatal(err)
	}
	var terminal struct {
		Response json.RawMessage `json:"response"`
	}
	data, _, _ := strings.Cut(strings.TrimPrefix(body[terminalIndex:], "event: response.completed\ndata: "), "\n")
	if err := json.Unmarshal([]byte(data), &terminal); err != nil {
		t.Fatal(err)
	}
	request := prooftest.Digest(ctx.body, "encryption_keys")
	if !prooftest.VerifyDigests(publicKey, proofObject, boot, request, prooftest.Digest(terminal.Response)) ||
		!prooftest.VerifyDigests(publicKey, proofObject, boot, request, streamDigest(t, body)) {
		t.Fatal("the receipt did not cover the bridged response and its events")
	}
}

func TestUnaryBridgedReplyReachesTheClientAsResponses(t *testing.T) {
	state := bridgedTestState(t, "/v1/responses", `{"model":"chutes-glm-5.2","input":"hi"}`)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	response := &schemas.BifrostResponse{ChatResponse: &schemas.BifrostChatResponse{
		ID: "chatcmpl-unary", Object: "chat.completion", Created: 1_700_000_000, Model: state.Resolution.Model,
		Choices: []schemas.BifrostResponseChoice{{
			FinishReason: schemas.Ptr("stop"),
			ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{Message: &schemas.ChatMessage{
				Role: schemas.ChatMessageRoleAssistant, Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("Hello")},
			}},
		}},
		Usage: &schemas.BifrostLLMUsage{PromptTokens: 3, CompletionTokens: 1, TotalTokens: 4},
	}}
	reply, outcome, failure := ingestProviderResult(nil, bifrostCtx, state, response, nil)
	if outcome != nil || failure != nil || reply == nil || reply.ResponsesResponse == nil || state.Response != response {
		t.Fatalf("reply = %#v, outcome = %v, failure = %v", reply, outcome, failure)
	}
	encoded, err := marshalPayload(unaryResponsePayload(reply, servedModel(state)))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		ID     string `json:"id"`
		Object string `json:"object"`
		Model  string `json:"model"`
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ID != "chatcmpl-unary" || payload.Object != "response" || payload.Model != state.Resolution.Deployment.ModelID ||
		len(payload.Output) != 1 || payload.Output[0].Type != "message" || payload.Output[0].Content[0].Text != "Hello" {
		t.Fatalf("payload = %s", encoded)
	}
}

const chatBridgeBody = `{"model":"openai-gpt-5.6-sol-pro","messages":[{"role":"user","content":"hi"}]`

// responsesReply is a Responses reply without output, as OpenAI gives it.
func responsesReply(status string) *schemas.BifrostResponsesResponse {
	return &schemas.BifrostResponsesResponse{ID: schemas.Ptr("resp_bridged"), Object: "response", CreatedAt: 1_700_000_000, Status: &status}
}

func responsesTextItem(status, text string) *schemas.ResponsesMessage {
	item := &schemas.ResponsesMessage{
		ID: schemas.Ptr("msg_1"), Type: schemas.Ptr(schemas.ResponsesMessageTypeMessage),
		Role: schemas.Ptr(schemas.ResponsesInputMessageRoleAssistant), Status: &status,
		Content: &schemas.ResponsesMessageContent{ContentBlocks: []schemas.ResponsesMessageContentBlock{}},
	}
	if status == "completed" {
		item.Content.ContentBlocks = []schemas.ResponsesMessageContentBlock{*responsesTextPart(text)}
	}
	return item
}

func responsesTextPart(text string) *schemas.ResponsesMessageContentBlock {
	return &schemas.ResponsesMessageContentBlock{
		Type: schemas.ResponsesOutputMessageContentTypeText, Text: &text,
		ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{}},
	}
}

// sendResponsesEvents streams a Responses reply with one message, as OpenAI sends it.
func sendResponsesEvents(stream chan<- *schemas.BifrostStreamChunk, text string) {
	sequence, output, content, id := 0, 0, 0, "msg_1"
	send := func(event *schemas.BifrostResponsesStreamResponse) {
		event.SequenceNumber = sequence
		sequence++
		stream <- &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}
	}
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeCreated, Response: responsesReply("in_progress")})
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeInProgress, Response: responsesReply("in_progress")})
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemAdded, OutputIndex: &output, Item: responsesTextItem("in_progress", "")})
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeContentPartAdded, OutputIndex: &output, ContentIndex: &content, ItemID: &id, Part: responsesTextPart("")})
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDelta, OutputIndex: &output, ContentIndex: &content, ItemID: &id, Delta: &text})
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDone, OutputIndex: &output, ContentIndex: &content, ItemID: &id, Text: &text})
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeContentPartDone, OutputIndex: &output, ContentIndex: &content, ItemID: &id, Part: responsesTextPart(text)})
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &output, Item: responsesTextItem("completed", text)})
	completed := responsesReply("completed")
	completed.Output = []schemas.ResponsesMessage{*responsesTextItem("completed", text)}
	completed.Usage = &schemas.ResponsesResponseUsage{InputTokens: 3, OutputTokens: 4, TotalTokens: 7}
	send(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeCompleted, Response: completed})
	close(stream)
}

func TestWriteSSEStreamSendsBridgedResponsesAsChatChunks(t *testing.T) {
	for _, tc := range []struct {
		name, options string
		want          string
	}{
		{"usage omitted", "", `{"role":"assistant"}` + "\n" + `{"content":"Hello"}` + "\n" + `{} stop`},
		{"usage requested", `,"stream_options":{"include_usage":true}`, `{"role":"assistant"}` + "\n" + `{"content":"Hello"}` + "\n" + `{} stop` + "\nusage 3 4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newTestRequest(t)
			bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
			stream := make(chan *schemas.BifrostStreamChunk)
			state := bridgedTestState(t, "/v1/chat/completions", chatBridgeBody+`,"stream":true`+tc.options+`}`)
			reader := startTestStream(&Server{}, ctx, bifrostCtx, state, stream, cancel, nil)
			defer reader.Close()
			go sendResponsesEvents(stream, "Hello")

			body := readResponseBodyStream(t, reader)
			chunks, done := strings.CutSuffix(body, "data: [DONE]\n\n")
			if !done || strings.Contains(chunks, "event: ") || strings.Contains(chunks, "response.") {
				t.Fatalf("a Chat Completions client got Responses framing: %q", body)
			}
			lines := []string{}
			for _, event := range parseSSEEvents(t, chunks) {
				var chunk struct {
					ID      string `json:"id"`
					Object  string `json:"object"`
					Model   string `json:"model"`
					Choices []struct {
						Delta        json.RawMessage `json:"delta"`
						FinishReason *string         `json:"finish_reason"`
					} `json:"choices"`
					Usage *struct {
						PromptTokens     int `json:"prompt_tokens"`
						CompletionTokens int `json:"completion_tokens"`
					} `json:"usage"`
				}
				encoded, _ := json.Marshal(event.data)
				if err := json.Unmarshal(encoded, &chunk); err != nil {
					t.Fatal(err)
				}
				if chunk.ID != "resp_bridged" || chunk.Object != "chat.completion.chunk" || chunk.Model != state.Resolution.Deployment.ModelID {
					t.Fatalf("chunk = %s", encoded)
				}
				switch {
				case len(chunk.Choices) == 0 && chunk.Usage != nil:
					lines = append(lines, fmt.Sprintf("usage %d %d", chunk.Usage.PromptTokens, chunk.Usage.CompletionTokens))
				case len(chunk.Choices) == 1 && chunk.Usage == nil:
					line := string(chunk.Choices[0].Delta)
					if reason := chunk.Choices[0].FinishReason; reason != nil {
						line += " " + *reason
					}
					lines = append(lines, line)
				default:
					t.Fatalf("chunk = %s", encoded)
				}
			}
			if got := strings.Join(lines, "\n"); got != tc.want {
				t.Fatalf("chunks =\n%s\nwant\n%s", got, tc.want)
			}
			if state.Response == nil || state.Response.ResponsesStreamResponse == nil {
				t.Fatal("the state lost the provider's Responses reply")
			}
		})
	}
}

func TestUnaryBridgedReplyReachesTheClientAsChatCompletions(t *testing.T) {
	state := bridgedTestState(t, "/v1/chat/completions", chatBridgeBody+`}`)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	defer cancel()
	completed := responsesReply("completed")
	completed.Output = []schemas.ResponsesMessage{*responsesTextItem("completed", "Hello")}
	completed.Usage = &schemas.ResponsesResponseUsage{InputTokens: 3, OutputTokens: 1, TotalTokens: 4}
	response := &schemas.BifrostResponse{ResponsesResponse: completed}
	reply, outcome, failure := ingestProviderResult(nil, bifrostCtx, state, response, nil)
	if outcome != nil || failure != nil || reply == nil || reply.ChatResponse == nil || state.Response != response {
		t.Fatalf("reply = %#v, outcome = %v, failure = %v", reply, outcome, failure)
	}
	encoded, err := marshalPayload(unaryResponsePayload(reply, servedModel(state)))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ID != "resp_bridged" || payload.Object != "chat.completion" || payload.Model != state.Resolution.Deployment.ModelID ||
		len(payload.Choices) != 1 || payload.Choices[0].FinishReason != "stop" || payload.Choices[0].Message.Role != "assistant" ||
		payload.Choices[0].Message.Content != "Hello" || payload.Usage.PromptTokens != 3 || payload.Usage.CompletionTokens != 1 {
		t.Fatalf("payload = %s", encoded)
	}
}
