package stogashttp

import (
	"encoding/json"
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

func bridgedTestState(t *testing.T, body string) *stogas.State {
	t.Helper()
	resolution := mustResolvedRequest(t, "/v1/responses", body)
	if !resolution.Bridged() {
		t.Fatalf("deployment %s takes Responses itself", resolution.Deployment.ID)
	}
	return &stogas.State{
		Pair:      stogas.Pair{Resolution: resolution, Adapter: stogas.AdapterFor(resolution.Provider)},
		StartedAt: time.Now().Add(-5 * time.Millisecond),
	}
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
	state := bridgedTestState(t, bridgedStreamBody)
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
	want := "created in_progress output_item.added content_part.added reasoning_summary_text.delta " +
		"reasoning_summary_text.done content_part.done output_item.done " +
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
	state := bridgedTestState(t, bridgedStreamBody)
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
	state := bridgedTestState(t, `{"model":"chutes-glm-5.2","input":"hi"}`)
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
