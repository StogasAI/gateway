package stogas

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

// Each recorded reply passes. OpenAI makes each image, so the log keeps no call for the client to
// answer, and no call bills anything of its own: OpenAI bills the image model's tokens, which the
// reply reports apart from its usage, to the customer's account.
func TestOpenAIImageGenerationRepliesPass(t *testing.T) {
	for _, test := range []struct {
		capture, name string
		images        int
	}{
		{"image-generation", "an image", 1},
		{"image-generation", "an image edited", 1},
		{"image-generation", "SVG output", 1},
		{"image-generation", "two images", 2},
		// max_tool_calls caps image generation, and the call that it stops ends generating, without
		// an image.
		{"image-generation", "two images under max_tool_calls 1", 2},
		{"image-generation", "an image sent back as an input image", 0},
		{"image-generation-replay", "a stored image", 1},
		{"image-generation-replay", "the image sent back by its ID", 0},
		{"image-generation-replay", "the image sent back with another result", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorded, request := hostedToolExchange(t, test.capture, test.name)
			state := customerFileSearchState(t, request)
			if err := ingestHostedToolReply(state, recorded.responsesReply(t)); err != nil {
				t.Fatalf("recorded reply refused: %v", err)
			}
			calls := state.loggedToolCalls()
			if len(calls) != test.images {
				t.Fatalf("logged calls %+v, want %d images", calls, test.images)
			}
			for _, call := range calls {
				if call.Type != "image_generation_call" || call.CallID != "" {
					t.Fatalf("logged %+v, want an image that OpenAI made", call)
				}
			}
			if err := state.Adapter.CalculateUpstreamCost(state); err != nil {
				t.Fatal(err)
			}
			for _, meter := range state.FinalMeters {
				if strings.HasPrefix(meter.MeterKey, "openai_responses_") {
					t.Fatalf("an image billed %+v", meter)
				}
			}
		})
	}
}

// A stream passes with the events that OpenAI sent, and without image generation's lifecycle
// events, which a call that max_tool_calls stops never finishes, but not out of order, with a
// partial image after the image, with another event's payload, or on a request whose model cannot
// make images.
func TestOpenAIImageGenerationStreamsAsRecorded(t *testing.T) {
	recorded, request := hostedToolExchange(t, "image-generation", "a streamed image")
	state := customerFileSearchState(t, request)
	state.Signals = &StandardSignals{Prompt: 10, Completion: 10}
	for sequence, event := range recorded.responsesStream(t) {
		event.SequenceNumber = sequence
		if event.Response != nil {
			event.Response.Model = state.Resolution.Deployment.Upstream.Model
		}
		if err := state.Adapter.IngestChunk(state, &schemas.BifrostStreamChunk{BifrostResponsesStreamResponse: event}); err != nil {
			t.Fatalf("recorded event %s refused: %v", event.Type, err)
		}
	}
	calls := state.loggedToolCalls()
	if len(calls) != 1 || calls[0].Type != "image_generation_call" || calls[0].CallID != "" || calls[0].DoneAt.Before(calls[0].StartedAt) {
		t.Fatalf("logged calls = %+v, want one timed image", calls)
	}

	type stream = []*schemas.BifrostResponsesStreamResponse
	at := func(events stream, eventType schemas.ResponsesStreamResponseType) int {
		return slices.IndexFunc(events, func(event *schemas.BifrostResponsesStreamResponse) bool { return event.Type == eventType })
	}
	withoutLifecycle := func(events stream) stream {
		return slices.DeleteFunc(events, func(event *schemas.BifrostResponsesStreamResponse) bool {
			switch event.Type {
			case schemas.ResponsesStreamResponseTypeImageGenerationCallInProgress, schemas.ResponsesStreamResponseTypeImageGenerationCallGenerating,
				schemas.ResponsesStreamResponseTypeImageGenerationCallCompleted:
				return true
			}
			return false
		})
	}
	if err := replayLocalToolStream(customerFileSearchState(t, request), withoutLifecycle(recorded.responsesStream(t))); err != nil {
		t.Fatalf("a stream without the lifecycle events got %v", err)
	}
	none := changedRequest(t, request, func(body map[string]any) { body["tool_choice"] = "none" })
	for _, test := range []struct {
		name, request string
		change        func(stream) stream
	}{
		{"generating before in progress", request, func(events stream) stream {
			progress, generating := at(events, schemas.ResponsesStreamResponseTypeImageGenerationCallInProgress), at(events, schemas.ResponsesStreamResponseTypeImageGenerationCallGenerating)
			events[progress], events[generating] = events[generating], events[progress]
			return events
		}},
		{"a partial image after the image", request, func(events stream) stream {
			partial, completed := at(events, schemas.ResponsesStreamResponseTypeImageGenerationCallPartialImage), at(events, schemas.ResponsesStreamResponseTypeImageGenerationCallCompleted)
			events[partial], events[completed] = events[completed], events[partial]
			return events
		}},
		{"a partial image without its index", request, func(events stream) stream {
			events[at(events, schemas.ResponsesStreamResponseTypeImageGenerationCallPartialImage)].PartialImageIndex = nil
			return events
		}},
		{"a partial image with code", request, func(events stream) stream {
			events[at(events, schemas.ResponsesStreamResponseTypeImageGenerationCallPartialImage)].Code = schemas.Ptr("print(1)")
			return events
		}},
		{"a lifecycle event with an image", request, func(events stream) stream {
			events[at(events, schemas.ResponsesStreamResponseTypeImageGenerationCallCompleted)].PartialImageB64 = schemas.Ptr("iVBORw0KGgo=")
			return events
		}},
		{"a lifecycle event of no image", request, func(events stream) stream {
			events[at(events, schemas.ResponsesStreamResponseTypeImageGenerationCallGenerating)].OutputIndex = schemas.Ptr(1)
			return events
		}},
		{"an image on a request whose model cannot make one", none, func(events stream) stream { return events }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := replayLocalToolStream(customerFileSearchState(t, test.request), test.change(recorded.responsesStream(t))); err == nil {
				t.Fatal("the stream passed")
			}
		})
	}
}

// A reply's image calls must be OpenAI's own: without a call ID or another tool's action, and only
// where the request lets the model make images. A failed call holds its error, and only an image
// call may still be generating.
func TestOpenAIImageGenerationReplyChecks(t *testing.T) {
	recorded, request := hostedToolExchange(t, "image-generation", "an image")
	none := changedRequest(t, request, func(body map[string]any) { body["tool_choice"] = "none" })
	for _, test := range []struct {
		name, request string
		change        func(reply *schemas.BifrostResponsesResponse)
	}{
		{"a call ID", request, func(reply *schemas.BifrostResponsesResponse) {
			reply.Output[0].ResponsesToolMessage.CallID = schemas.Ptr("call_1")
		}},
		{"another tool's action", request, func(reply *schemas.BifrostResponsesResponse) {
			reply.Output[0].ResponsesToolMessage.Action = &schemas.ResponsesToolMessageActionStruct{
				ResponsesComputerToolCallAction: &schemas.ResponsesComputerToolCallAction{Type: "wait"},
			}
		}},
		{"a code run's result", request, func(reply *schemas.BifrostResponsesResponse) {
			reply.Output[0].ResponsesToolMessage.ResponsesCodeInterpreterToolCall = &schemas.ResponsesCodeInterpreterToolCall{}
		}},
		{"a message that is generating", request, func(reply *schemas.BifrostResponsesResponse) {
			reply.Output[1].Status = schemas.Ptr("generating")
		}},
		{"an image on a request whose model cannot make one", none, func(*schemas.BifrostResponsesResponse) {}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reply := recorded.responsesReply(t)
			test.change(reply)
			if err := ingestHostedToolReply(customerFileSearchState(t, test.request), reply); err == nil {
				t.Fatal("the reply passed")
			}
		})
	}

	reply := recorded.responsesReply(t)
	reply.Output[0].Status = schemas.Ptr("failed")
	reply.Output[0].ResponsesToolMessage.ResponsesImageGenerationCall = &schemas.ResponsesImageGenerationCall{}
	reply.Output[0].ResponsesToolMessage.Error = &schemas.ResponsesToolMessageError{ResponsesToolMessageErrorStruct: &schemas.ResponsesToolMessageErrorStruct{
		Type: "image_generation_user_error", Code: json.RawMessage(`"moderation_blocked"`), Message: schemas.Ptr("Your request was rejected by the safety system."),
		ModerationDetails: json.RawMessage(`{"categories":["violence"]}`),
	}}
	if err := ingestHostedToolReply(customerFileSearchState(t, request), reply); err != nil {
		t.Fatalf("a failed call got %v", err)
	}
}

// A call sent back reaches OpenAI as its type and ID alone. OpenAI reads the image by its ID from
// the stored reply, whatever else the item holds, and refuses a call without one (capture
// openai/image-generation-replay), as the gateway does. No other deployment can read the stored
// reply.
func TestOpenAIImageGenerationCallsSentBack(t *testing.T) {
	for _, test := range []struct{ capture, name string }{
		{"image-generation-replay", "the image sent back by its ID"},
		{"image-generation-replay", "the image sent back with another result"},
		{"image-generation", "an image sent back"},
		{"image-generation", "an image sent back without the tool"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, request := hostedToolExchange(t, test.capture, test.name)
			var sent, wire struct {
				Input []json.RawMessage `json:"input"`
			}
			if err := json.Unmarshal([]byte(request), &sent); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(fileSearchProviderBody(t, customerFileSearchState(t, request)), &wire); err != nil {
				t.Fatal(err)
			}
			if len(wire.Input) != len(sent.Input) {
				t.Fatalf("OpenAI got %d items of %d", len(wire.Input), len(sent.Input))
			}
			for index := range sent.Input {
				want := withoutStatus(t, sent.Input[index])
				var item struct{ Type, ID string }
				if err := json.Unmarshal(sent.Input[index], &item); err != nil {
					t.Fatal(err)
				}
				if item.Type == "image_generation_call" {
					want = []byte(`{"type":"image_generation_call","id":"` + item.ID + `"}`)
				}
				if !sameJSON(t, withoutStatus(t, wire.Input[index]), want) {
					t.Fatalf("input[%d] sent as %s, want %s", index, wire.Input[index], want)
				}
			}
		})
	}

	_, request := hostedToolExchange(t, "image-generation-replay", "the image sent back without its ID")
	if err := customerRequestError(t, []byte(request)); err == nil || !strings.Contains(err.Error(), "input[1].id is required") {
		t.Fatalf("a call without its ID got %v", err)
	}
	_, request = hostedToolExchange(t, "image-generation-replay", "the image sent back by its ID")
	claude := changedRequest(t, request, func(body map[string]any) { body["model"] = "anthropic-claude-sonnet-4-6" })
	if err := customerRequestError(t, []byte(claude)); err == nil || !strings.Contains(err.Error(), "input[1] needs one of OpenAI's models") {
		t.Fatalf("Claude with a call sent back got %v", err)
	}
}

// An image that the request makes reaches the client in the reply, but one that the input sends
// back by its ID lives in a stored reply in one account, so only the account's owner can send it,
// and no input check reads it.
func TestOpenAIImageGenerationProviderState(t *testing.T) {
	_, made := hostedToolExchange(t, "image-generation", "an image")
	if provider := customerFileSearchState(t, made).Resolution.ProviderState(); len(provider.Fields) != 0 {
		t.Fatalf("an image that the request makes reads as provider state %+v", provider)
	}
	_, sentBack := hostedToolExchange(t, "image-generation-replay", "the image sent back by its ID")
	provider := customerFileSearchState(t, sentBack).Resolution.ProviderState()
	if !slices.Equal(provider.Fields, []string{"image_generation_call"}) || provider.Reads != "input[1]" || provider.Keeps {
		t.Fatalf("provider state %+v", provider)
	}
	if err := provider.ManagedRefusal(); err == nil || !strings.Contains(err.Error(), "input[1] needs your own provider credential") {
		t.Fatalf("Stogas's own credential got %v", err)
	}
}

// OpenAI adds its instructions for the tool to the input, under tool_choice none too, and the
// model reads each image that it makes, as the input tokens of each recorded reply show. The hold
// takes both, and each image that the input sends back, which OpenAI reads from the stored reply.
func TestOpenAIImageGenerationHold(t *testing.T) {
	inputTokens := func(recorded providerExchange) int64 {
		var usage struct {
			Usage struct {
				InputTokens int64 `json:"input_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(recorded.Response.Body, &usage); err != nil {
			t.Fatal(err)
		}
		return usage.Usage.InputTokens
	}
	recorded, declared := hostedToolExchange(t, "image-generation", "the tool under tool_choice none")
	_, bare := hostedToolExchange(t, "image-generation", "without the tool")
	held := heldInputTokensOf(t, customerFileSearchState(t, declared))
	if without := heldInputTokensOf(t, customerFileSearchState(t, bare)); held < inputTokens(recorded) || held-without < 342 {
		t.Fatalf("held %d with the tool and %d without it; OpenAI counted %d", held, without, inputTokens(recorded))
	}
	for _, name := range []string{"an image", "an image edited", "SVG output", "two images", "two images under max_tool_calls 1"} {
		recorded, request := hostedToolExchange(t, "image-generation", name)
		if held := heldInputTokensOf(t, customerFileSearchState(t, request)); held < inputTokens(recorded) {
			t.Fatalf("%s: held %d; OpenAI counted %d", name, held, inputTokens(recorded))
		}
	}

	recorded, sentBack := hostedToolExchange(t, "image-generation-replay", "the image sent back by its ID")
	withoutCall := changedRequest(t, sentBack, func(body map[string]any) {
		body["input"] = slices.Delete(body["input"].([]any), 1, 2)
	})
	held = heldInputTokensOf(t, customerFileSearchState(t, sentBack))
	if without := heldInputTokensOf(t, customerFileSearchState(t, withoutCall)); held < inputTokens(recorded) || held-without < hostedCallContentTokens {
		t.Fatalf("held %d with the call and %d without it; OpenAI counted %d", held, without, inputTokens(recorded))
	}
}

// Each setting reaches OpenAI as the client sent it, and OpenAI checks its value. A key that the
// gateway does not know is refused, since core would drop it, and so is a second tool. Only
// OpenAI's own Responses API makes images, and policy can refuse the tool by name.
func TestOpenAIImageGenerationToolShapes(t *testing.T) {
	for _, tools := range []string{
		`[{"type":"image_generation","action":"edit","background":"transparent","input_fidelity":"high","input_image_mask":{"file_id":"file-1"},` +
			`"model":"gpt-image-1","moderation":"low","output_compression":50,"output_format":"png","partial_images":2,"quality":"high","size":"1024x1536"}]`,
		`[{"type":"image_generation","output_format":"svg","svg":{"model":"gpt-6-luna","reasoning":{"effort":"low"}}}]`,
		`[{"type":"image_generation","output_format":"gif","complexity":"high","frame_count":4,"frame_duration_ms":250}]`,
	} {
		state := customerFileSearchState(t, `{"model":"provider:openai gpt-5.5","input":"hi","tools":`+tools+`}`)
		if got := state.Resolution.HostedTools(); !slices.Equal(got, []catalog.HostedTool{catalog.HostedToolImageGeneration}) {
			t.Fatalf("hosted tools of %s = %v", tools, got)
		}
		var wire struct {
			Tools json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(fileSearchProviderBody(t, state), &wire); err != nil {
			t.Fatal(err)
		}
		if !sameJSON(t, wire.Tools, []byte(tools)) {
			t.Fatalf("OpenAI got tools %s", wire.Tools)
		}
	}
	for _, test := range []struct{ name, tools, want string }{
		{"a key that the gateway does not know", `[{"type":"image_generation","n":2}]`, "tools[0].n is not supported"},
		// Core reads each setting as its type, and the body does not parse.
		{"partial images as text", `[{"type":"image_generation","partial_images":"2"}]`, "Invalid JSON body"},
		{"a mask of another shape", `[{"type":"image_generation","input_image_mask":{"file_id":"file-1","detail":"high"}}]`, "tools[0].input_image_mask.detail is not supported"},
		{"an SVG option that the gateway does not know", `[{"type":"image_generation","svg":{"reasoning":{"summary":"auto"}}}]`, "tools[0].svg.reasoning.summary is not supported"},
		{"a second tool", `[{"type":"image_generation"},{"type":"image_generation","quality":"low"}]`, "tools[1].type duplicates another image_generation tool"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := customerRequestError(t, []byte(`{"model":"provider:openai gpt-5.5","input":"hi","tools":`+test.tools+`}`))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want %q", err, test.want)
			}
		})
	}
	err := customerRequestError(t, []byte(`{"model":"anthropic-claude-sonnet-4-6","input":"hi","tools":[{"type":"image_generation"}]}`))
	if err == nil || !strings.Contains(err.Error(), "No deployment for this request runs") {
		t.Fatalf("Claude with image generation got %v", err)
	}
}
