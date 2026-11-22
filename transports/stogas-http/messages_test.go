package stogashttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof/prooftest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
)

const (
	messagesRequestID = "018f4f70-7c88-7b9a-baf8-31a93d2cf615"
	// recordedClaudeModel is the model that Claude names in the recorded exchanges, which the
	// client gets as the served model, messagesModel.
	recordedClaudeModel = "anthropic.claude-haiku-4-5-20251001-v1:0"
	messagesModel       = "claude-haiku-4-5"
)

// messagesState is the state of a Messages request that Claude serves as messagesModel.
func messagesState(requestType schemas.RequestType) *stogas.State {
	resolution := &catalog.ResolvedRequest{Route: catalog.RouteResponses, RequestType: requestType, Provider: schemas.Anthropic, Messages: true}
	resolution.Deployment.ModelID = messagesModel
	return &stogas.State{Pair: stogas.Pair{Resolution: resolution}, RequestID: messagesRequestID}
}

// recordedClaudeExchange reads an exchange that Claude answered through Amazon Bedrock: the whole
// reply, or the data of each event of a stream as the capture holds it, over several lines.
func recordedClaudeExchange(t *testing.T, name string) (json.RawMessage, []json.RawMessage) {
	t.Helper()
	data, err := os.ReadFile("../stogas/testdata/provider/aws/eager-input-streaming.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Exchanges []struct {
			Name     string `json:"name"`
			Response struct {
				Body   json.RawMessage   `json:"body"`
				Events []json.RawMessage `json:"events"`
			} `json:"response"`
		} `json:"exchanges"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	for _, exchange := range capture.Exchanges {
		if exchange.Name == name {
			return exchange.Response.Body, exchange.Response.Events
		}
	}
	t.Fatalf("the capture has no exchange %q", name)
	return nil, nil
}

// claudeEventChunk is a chunk of core's Responses stream that carries one of Claude's events. Core
// puts each event on one chunk, or on a chunk of its own when the event yields no other.
func claudeEventChunk(kind schemas.ResponsesStreamResponseType, raw json.RawMessage) *schemas.BifrostStreamChunk {
	chunk := &schemas.BifrostResponsesStreamResponse{Type: kind}
	if raw != nil {
		chunk.ExtraFields.RawResponse = string(raw)
	}
	return &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: chunk}
}

// streamMessages delivers the chunks to a Messages client and returns what it reads.
func streamMessages(t *testing.T, chunks ...*schemas.BifrostStreamChunk) string {
	t.Helper()
	ctx := newTestRequest(t)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	stream := make(chan *schemas.BifrostStreamChunk)
	reader := startTestStream(&Server{}, ctx, bifrostCtx, messagesState(schemas.ResponsesStreamRequest), stream, cancel, nil)
	defer reader.Close()
	go func() {
		for _, chunk := range chunks {
			stream <- chunk
		}
		close(stream)
	}()
	return readResponseBodyStream(t, reader)
}

func compactJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	return compact.String()
}

// A Messages client reads Claude's own events, each on one line under its type, with the served
// model in place of Claude's name for it, and nothing that core adds: no event for a chunk that
// carries none of Claude's, and no end marker.
func TestMessagesStreamSendsClaudesOwnEvents(t *testing.T) {
	_, events := recordedClaudeExchange(t, "stream cut inside the call")
	chunks := []*schemas.BifrostStreamChunk{
		claudeEventChunk(schemas.ResponsesStreamResponseTypeCreated, events[0]),
		// Core's second chunk for message_start carries no event.
		claudeEventChunk(schemas.ResponsesStreamResponseTypeInProgress, nil),
		claudeEventChunk(schemas.ResponsesStreamResponseTypeProviderRawEvent, json.RawMessage(`{"type": "ping"}`)),
	}
	for _, event := range events[1:] {
		chunks = append(chunks, claudeEventChunk(schemas.ResponsesStreamResponseTypeProviderRawEvent, event))
	}
	// The capture holds each event over several lines, which the client gets on one. An event on
	// one line passes byte for byte.
	want := "event: message_start\ndata: " +
		strings.Replace(compactJSON(t, events[0]), `"`+recordedClaudeModel+`"`, `"`+messagesModel+`"`, 1) + "\n\n" +
		"event: ping\ndata: {\"type\": \"ping\"}\n\n"
	for _, event := range events[1:] {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(event, &head); err != nil {
			t.Fatal(err)
		}
		want += "event: " + head.Type + "\ndata: " + compactJSON(t, event) + "\n\n"
	}
	if got := streamMessages(t, chunks...); got != want {
		t.Fatalf("stream =\n%s\nwant\n%s", got, want)
	}
}

// A Messages stream that asks for a receipt gets it right before message_stop, and the receipt
// signs the message that the stream's events assemble to.
func TestMessagesStreamReceiptSignsTheAssembledMessage(t *testing.T) {
	service, publicKey, boot := testProofService(t)
	ctx := newTestRequest(t)
	testRequestBody(ctx, `{"model":"provider:anthropic claude-haiku-4-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}],"stream":true}`)
	bifrostCtx, cancel := schemas.NewBifrostContextWithCancel(t.Context())
	bifrostCtx.SetValue(stogasMetadataKey, true)
	// A receipt names the catalog that the request resolved in.
	state := &stogas.State{
		Pair:      stogas.Pair{Resolution: mustResolvedRequest(t, "/v1/messages", string(ctx.body)), Adapter: stogas.DefaultAdapter{}},
		RequestID: messagesRequestID, NodeID: strings.Repeat("6", 64),
	}
	// The record of the call that Claude served, which the receipt signs.
	state.FinalEvent = &billing.RequestEvent{
		RequestID: messagesRequestID, CreatedAt: "2026-08-24T12:34:56.789Z", CatalogVersion: new(uint64(7)),
		ProviderAttempts: []billing.ProviderAttempt{{CatalogChainHash: "sha256:" + strings.Repeat("a", 64), Provider: "anthropic", Status: "success"}},
		Usage:            billing.RequestUsage{BilledCostUSD: "0", UpstreamCostUSD: "0", Meters: billing.EventMeters{}},
	}
	stream := make(chan *schemas.BifrostStreamChunk)
	reader := startTestStream(&Server{proofs: service}, ctx, bifrostCtx, state, stream, cancel, nil)
	defer reader.Close()
	go func() {
		inProgress, completed := schemas.ResponsesResponseStatusInProgress, schemas.ResponsesResponseStatusCompleted
		created := claudeEventChunk(schemas.ResponsesStreamResponseTypeCreated, json.RawMessage(
			`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"`+recordedClaudeModel+
				`","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":3,"output_tokens":1}}}`))
		created.BifrostResponsesStreamResponse.Response = &schemas.BifrostResponsesResponse{ID: schemas.Ptr("msg_1"), Object: "response", Status: &inProgress}
		stream <- created
		events := []string{
			`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"lo"}}`,
			`{"type":"content_block_stop","index":0}`,
			`{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}`,
		}
		for index, event := range events {
			chunk := claudeEventChunk(schemas.ResponsesStreamResponseTypeProviderRawEvent, json.RawMessage(event))
			chunk.BifrostResponsesStreamResponse.SequenceNumber = index + 1
			stream <- chunk
		}
		stop := claudeEventChunk(schemas.ResponsesStreamResponseTypeCompleted, json.RawMessage(`{"type":"message_stop"}`))
		stop.BifrostResponsesStreamResponse.SequenceNumber = len(events) + 1
		stop.BifrostResponsesStreamResponse.Response = &schemas.BifrostResponsesResponse{
			ID: schemas.Ptr("msg_1"), Object: "response", Status: &completed,
			Usage: &schemas.ResponsesResponseUsage{InputTokens: 3, OutputTokens: 2, TotalTokens: 5},
		}
		stream <- stop
		close(stream)
	}()

	body := readResponseBodyStream(t, reader)
	prefix := ": " + proofhttp.SSECommentPrefix
	receiptAt, terminalAt := strings.Index(body, prefix), strings.Index(body, "event: message_stop\n")
	if receiptAt < 0 || terminalAt < 0 || !strings.HasSuffix(body[:terminalAt], "\n\n") ||
		strings.Contains(body[receiptAt:terminalAt-2], "\n\n") {
		t.Fatalf("want the receipt right before message_stop, got %q", body)
	}
	var receipt proof.Object
	if err := json.Unmarshal([]byte(strings.TrimSpace(body[receiptAt+len(prefix):terminalAt])), &receipt); err != nil {
		t.Fatal(err)
	}
	message := []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"` + messagesModel + `",` +
		`"content":[{"type":"text","text":"Hello"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":3,"output_tokens":2}}`)
	request := prooftest.Digest(ctx.body, "encryption_keys")
	if !prooftest.VerifyDigests(publicKey, receipt, boot, request, prooftest.Digest(message)) ||
		!prooftest.VerifyDigests(publicKey, receipt, boot, request, streamDigest(t, body)) {
		t.Fatalf("the receipt does not sign the assembled message: %q", body)
	}
}

// A failure after the stream starts ends it with Anthropic's error event, whose type names the
// failure as Anthropic does, so that Claude Code treats Claude's overload as an overload.
func TestMessagesStreamEndsWithAnthropicErrorEvent(t *testing.T) {
	_, events := recordedClaudeExchange(t, "stream cut inside the call")
	overloaded := testBifrostError(529, "Overloaded", "overloaded_error", "")
	body := streamMessages(t,
		claudeEventChunk(schemas.ResponsesStreamResponseTypeCreated, events[0]),
		&schemas.BifrostStreamChunk{BifrostError: overloaded},
	)
	_, last, found := strings.Cut(body, "\n\nevent: error\ndata: ")
	if !found || strings.Count(body, "event: ") != 2 {
		t.Fatalf("stream = %q", body)
	}
	var payload struct {
		Type      string         `json:"type"`
		Error     map[string]any `json:"error"`
		RequestID string         `json:"request_id"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSuffix(last, "\n\n")), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Type != "error" || payload.Error["type"] != "overloaded_error" || payload.Error["message"] == "" ||
		payload.Error["provider"] != "anthropic" || payload.RequestID != messagesRequestID {
		t.Fatalf("error event = %+v", payload)
	}
	for _, name := range []string{"code", "param"} {
		if _, present := payload.Error[name]; present {
			t.Fatalf("error event carries %s without a value: %+v", name, payload)
		}
	}
}

// A Messages client that asks for no stream reads Claude's own JSON, every field that Claude sent
// included, with the served model.
func TestMessagesReplyIsClaudesJSON(t *testing.T) {
	recorded, _ := recordedClaudeExchange(t, "whole")
	reply := &schemas.BifrostResponse{ResponsesResponse: &schemas.BifrostResponsesResponse{}}
	reply.ResponsesResponse.ExtraFields.RawResponse = recorded
	state := messagesState(schemas.ResponsesRequest)
	payload, failure := unaryReplyPayload(state, nil, reply)
	if failure != nil {
		t.Fatal(failure.Error.Message)
	}
	want := strings.Replace(string(recorded), `"`+recordedClaudeModel+`"`, `"`+messagesModel+`"`, 1)
	if got, ok := payload.([]byte); !ok || string(got) != want {
		t.Fatalf("reply = %s\nwant %s", payload, want)
	}

	// Core keeps Claude's JSON for every Messages call, so a reply without it is the gateway's
	// failure, not an empty answer.
	reply.ResponsesResponse.ExtraFields.RawResponse = nil
	if _, failure := unaryReplyPayload(messagesState(schemas.ResponsesRequest), nil, reply); failure == nil {
		t.Fatal("a reply without Claude's JSON passed")
	}
}

// The gateway's own refusals of a Messages request take Anthropic's shape and headers, which
// Anthropic's SDKs read; the other routes keep theirs.
func TestMessagesRefusalsTakeAnthropicsShape(t *testing.T) {
	for _, test := range []struct {
		path      string
		anthropic bool
	}{
		{"/v1/messages", true},
		{"/v1/chat/completions", false},
	} {
		ctx := newTestRequest(t)
		ctx.request.Method = http.MethodPost
		testRequestURI(ctx, test.path)
		if _, ok := (&Server{}).requireAPIKey(ctx); ok {
			t.Fatalf("%s: a request without an API key passed", test.path)
		}
		response := testResponse(ctx)
		requestID := response.Header().Get("X-Request-ID")
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		detail, _ := body["error"].(map[string]any)
		if response.Code != http.StatusUnauthorized || requestID == "" || detail["message"] != "Missing API key" {
			t.Fatalf("%s: status %d, body %s", test.path, response.Code, response.Body)
		}
		if !test.anthropic {
			if _, present := body["type"]; present || response.Header().Get("Request-Id") != "" {
				t.Fatalf("%s: body %s", test.path, response.Body)
			}
			continue
		}
		if body["type"] != "error" || detail["type"] != "authentication_error" || body["request_id"] != requestID ||
			response.Header().Get("Request-Id") != requestID {
			t.Fatalf("%s: body %s, headers %v", test.path, response.Body, response.Header())
		}
		if _, present := detail["param"]; present {
			t.Fatalf("%s: body %s", test.path, response.Body)
		}
	}
}

// Anthropic's SDKs add beta=true to the URL of a beta call and send anthropic-beta, which the
// Messages route reads. Every other route refuses both.
func TestMessagesRouteTakesBetaQueryAndHeader(t *testing.T) {
	for _, test := range []struct {
		uri    string
		header string
		query  bool
		refuse string
	}{
		{uri: "/v1/messages?beta=true", header: "anthropic-beta", query: true},
		{uri: "/v1/messages", header: "x-stogas-trace", query: true, refuse: "x-stogas-trace"},
		{uri: "/v1/messages?beta=false", header: "anthropic-beta"},
		{uri: "/v1/messages?beta=true&limit=1", header: "anthropic-beta"},
		{uri: "/v1/chat/completions?beta=true", header: "anthropic-beta", refuse: "anthropic-beta"},
		{uri: "/v1/responses", header: "anthropic-beta", query: true, refuse: "anthropic-beta"},
	} {
		ctx := newTestRequest(t)
		testRequestURI(ctx, test.uri)
		ctx.request.Header.Set(test.header, "claude-code-20250219")
		if got := acceptedInferenceQuery(ctx.request); got != test.query {
			t.Errorf("%s: query accepted = %v", test.uri, got)
		}
		if got := unsupportedInferenceHeader(ctx); got != test.refuse {
			t.Errorf("%s with %s: refused header = %q, want %q", test.uri, test.header, got, test.refuse)
		}
	}
}
