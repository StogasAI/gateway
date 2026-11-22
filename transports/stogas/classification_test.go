package stogas

import (
	"encoding/json"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

const germanReply = "Ich arbeite an einem kleinen Webdienst, der Bestellungen in einer Datenbank speichert. Wenn zwei Kunden gleichzeitig bestellen, verschwindet manchmal eine der Bestellungen."

func classifiedState(t *testing.T, path, classifiers, body string) *State {
	t.Helper()
	source, err := policy.CompileSource([]byte(`{"plugins":{"classification":` + classifiers + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	config, err := policy.ComposeSources([]policy.ScopedSource{{Scope: policy.OrganizationScope, Value: source}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := catalog.ResolveRequest(catalog.RequestInput{
		AvailableCredentials: map[string][]int{"openai": {0}},
		Body:                 []byte(body),
		Method:               "POST",
		Path:                 path,
		Policy:               config,
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewState(resolved, "sk-test", nil, AdapterFor(resolved.Provider))
}

func classificationJSON(t *testing.T, state *State) string {
	t.Helper()
	encoded, err := json.Marshal(state.pluginMetrics().Classification)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// A streamed reply is classified as it arrives, with a run of hidden characters that spans two
// deltas, and the request record holds the input's and the output's results.
func TestClassificationOfAChatStream(t *testing.T) {
	state := classifiedState(t, "/v1/chat/completions", `["hidden_characters","language"]`,
		`{"model":"openai-gpt-5.6-sol","stream":true,"messages":[{"role":"user","content":"Please translate this email into a more formal tone and keep it short. Thank you for the help.​​"}]}`)
	adapter := DefaultAdapter{}
	for i, text := range []string{germanReply[:40], germanReply[40:] + "​", "​"} {
		chunk := validChatProviderChunk("chat_stream", false)
		if i > 0 {
			chunk.Choices[0].Delta.Role = nil
		}
		chunk.Choices[0].Delta.Content = &text
		if err := adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostChatResponse: chunk}); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := classificationJSON(t, state), `{"language":{"input":"en","output":"de"},"hidden_characters":{"input":2,"output":2}}`; got != want {
		t.Fatalf("classification %s, want %s", got, want)
	}
}

// Tool arguments count hidden characters and say nothing of the reply's language, and each text
// starts a run of its own.
func TestClassificationReadsEachOutputText(t *testing.T) {
	state := classifiedState(t, "/v1/chat/completions", `["hidden_characters","language"]`,
		`{"model":"openai-gpt-5.6-sol","messages":[{"role":"user","content":"Hallo"}]}`)
	var response schemas.BifrostChatResponse
	if err := json.Unmarshal([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"`+germanReply+`​","tool_calls":[{"type":"function","function":{"name":"lookup","arguments":"​{\"q\":\"Please translate this email into a more formal tone and keep it short.`+"\U000E0041"+`\"}"}}]}}]}`), &response); err != nil {
		t.Fatal(err)
	}
	state.classifyChatOutput(&response)
	if got, want := classificationJSON(t, state), `{"language":{"input":"und","output":"de"},"hidden_characters":{"input":0,"output":1}}`; got != want {
		t.Fatalf("classification %s, want %s", got, want)
	}
}

func TestClassificationOfResponses(t *testing.T) {
	body := `{"model":"openai-gpt-5.6-sol","input":"` + germanReply + `"}`
	index, part := 0, 0
	delta := func(eventType schemas.ResponsesStreamResponseType, text string) *schemas.BifrostResponsesStreamResponse {
		return &schemas.BifrostResponsesStreamResponse{Type: eventType, OutputIndex: &index, ContentIndex: &part, Delta: &text}
	}
	stream := classifiedState(t, "/v1/responses", `["hidden_characters","language"]`, body)
	for _, event := range []*schemas.BifrostResponsesStreamResponse{
		delta(schemas.ResponsesStreamResponseTypeOutputTextDelta, germanReply[:60]),
		delta(schemas.ResponsesStreamResponseTypeOutputTextDelta, germanReply[60:]+"\U000E0041"),
		// The done item repeats what the deltas held.
		{Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &index, Item: &schemas.ResponsesMessage{
			Type: schemas.Ptr(schemas.ResponsesMessageTypeMessage),
			Content: &schemas.ResponsesMessageContent{ContentBlocks: []schemas.ResponsesMessageContentBlock{{
				Type: schemas.ResponsesOutputMessageContentTypeText, Text: schemas.Ptr(germanReply + "\U000E0041"),
			}}},
		}},
	} {
		stream.classifyResponsesStream(event)
	}
	if got, want := classificationJSON(t, stream), `{"language":{"input":"de","output":"de"},"hidden_characters":{"input":0,"output":1}}`; got != want {
		t.Fatalf("stream classification %s, want %s", got, want)
	}

	unary := classifiedState(t, "/v1/responses", `["language"]`, body)
	unary.classifyResponsesOutput(&schemas.BifrostResponsesResponse{Output: []schemas.ResponsesMessage{{
		Type:                 schemas.Ptr(schemas.ResponsesMessageTypeFunctionCall),
		ResponsesToolMessage: &schemas.ResponsesToolMessage{Arguments: schemas.Ptr(`{"text":"` + germanReply + `"}`)},
	}}})
	// A reply without text has no language.
	if got, want := classificationJSON(t, unary), `{"language":{"input":"de"}}`; got != want {
		t.Fatalf("unary classification %s, want %s", got, want)
	}

	// The prompt that the model wrote for an image counts hidden characters as tool arguments do,
	// and arrives in a stream when the call ends.
	image := func() *schemas.ResponsesMessage {
		return &schemas.ResponsesMessage{
			Type: schemas.Ptr(schemas.ResponsesMessageTypeImageGenerationCall),
			ResponsesToolMessage: &schemas.ResponsesToolMessage{ResponsesImageGenerationCall: &schemas.ResponsesImageGenerationCall{
				Result: "UklGRg==", RevisedPrompt: schemas.Ptr(germanReply + "\U000E0041"),
			}},
		}
	}
	unary = classifiedState(t, "/v1/responses", `["hidden_characters","language"]`, body)
	unary.classifyResponsesOutput(&schemas.BifrostResponsesResponse{Output: []schemas.ResponsesMessage{*image()}})
	stream = classifiedState(t, "/v1/responses", `["hidden_characters","language"]`, body)
	stream.classifyResponsesStream(&schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputItemDone, OutputIndex: &index, Item: image()})
	for _, state := range []*State{unary, stream} {
		if got, want := classificationJSON(t, state), `{"language":{"input":"de"},"hidden_characters":{"input":0,"output":1}}`; got != want {
			t.Fatalf("image classification %s, want %s", got, want)
		}
	}
}

func TestNoClassifiersLeaveNoSection(t *testing.T) {
	state := classifiedState(t, "/v1/responses", `[]`, `{"model":"openai-gpt-5.6-sol","input":"`+germanReply+`"}`)
	state.classifyResponsesOutput(&schemas.BifrostResponsesResponse{Output: []schemas.ResponsesMessage{{
		Type: schemas.Ptr(schemas.ResponsesMessageTypeMessage),
		Content: &schemas.ResponsesMessageContent{ContentBlocks: []schemas.ResponsesMessageContentBlock{{
			Type: schemas.ResponsesOutputMessageContentTypeText, Text: schemas.Ptr("​​"),
		}}},
	}}})
	if metrics := state.pluginMetrics(); metrics != (plugins.Metrics{}) {
		t.Fatalf("plugin section %+v", metrics)
	}
}
