package stogashttp

import (
	"bytes"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestPublicResponsesStreamPreservesWireShapeWithoutCoreMetadata(t *testing.T) {
	for _, logprobs := range [][]schemas.ResponsesOutputMessageContentTextLogProb{nil, {}} {
		response := &schemas.BifrostResponsesStreamResponse{
			Type:           schemas.ResponsesStreamResponseTypeCompleted,
			SequenceNumber: 7,
			OutputIndex:    schemas.Ptr(0),
			LogProbs:       logprobs,
			ExtraFields:    schemas.BifrostResponseExtraFields{RawRequest: "private-stream-request"},
			Response: &schemas.BifrostResponsesResponse{
				ID:          schemas.Ptr("resp_1"),
				ExtraFields: schemas.BifrostResponseExtraFields{RawResponse: "private-response"},
				Usage:       &schemas.ResponsesResponseUsage{InputTokens: 3, OutputTokens: 5, TotalTokens: 8},
			},
		}
		wire, err := marshalPayload(publicResponsePayload(response, ""))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(wire, []byte("extra_fields")) || bytes.Contains(wire, []byte("private-")) {
			t.Fatalf("core metadata reached the public stream: %s", wire)
		}
		object := publicPayloadObject(t, publicResponsePayload(response, ""))
		if object["sequence_number"] != float64(7) || object["output_index"] != float64(0) {
			t.Fatalf("event indices changed: %s", wire)
		}
		if _, present := object["logprobs"]; present != (logprobs != nil) {
			t.Fatalf("event logprobs omission changed: %s", wire)
		}
		nested := object["response"].(map[string]any)
		if nested["id"] != "resp_1" || nested["usage"].(map[string]any)["total_tokens"] != float64(8) {
			t.Fatalf("response identity or usage changed: %s", wire)
		}
		if response.ExtraFields.RawRequest != "private-stream-request" || response.Response.ExtraFields.RawResponse != "private-response" {
			t.Fatal("public serialization mutated internal metadata")
		}
	}
}

func TestPublicResponsesResponseKeepsCoreWireShapeWithoutCoreMetadata(t *testing.T) {
	toolUsage := &schemas.ToolUsage{WebSearch: &schemas.WebSearchToolUsage{NumRequests: 2}}
	response := &schemas.BifrostResponsesResponse{
		ID:          schemas.Ptr("resp_1"),
		Object:      "response",
		ExtraFields: schemas.BifrostResponseExtraFields{RawResponse: "private-response"},
		Usage:       &schemas.ResponsesResponseUsage{InputTokens: 3, OutputTokens: 5, TotalTokens: 8, ToolUsage: toolUsage},
	}
	wire, err := marshalPayload(publicResponsePayload(response, ""))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte("extra_fields")) || bytes.Contains(wire, []byte("private-")) {
		t.Fatalf("core metadata reached the public response: %s", wire)
	}
	object := publicPayloadObject(t, publicResponsePayload(response, ""))
	usage := object["usage"].(map[string]any)
	if object["id"] != "resp_1" || usage["total_tokens"] != float64(8) {
		t.Fatalf("response identity or usage changed: %s", wire)
	}
	// Core's marshaler, as OpenAI does, sends tool usage once at the top level and output as [].
	if _, nested := usage["tool_usage"]; nested || object["tool_usage"] == nil {
		t.Fatalf("tool usage is not top-level: %s", wire)
	}
	if output, ok := object["output"].([]any); !ok || len(output) != 0 {
		t.Fatalf("absent output is not an empty array: %s", wire)
	}
	if response.ExtraFields.RawResponse != "private-response" || response.Usage.ToolUsage != toolUsage {
		t.Fatal("public serialization mutated the response")
	}
	var absent *schemas.BifrostResponsesResponse
	if wire, err := marshalPayload(publicResponsePayload(absent, "")); err != nil || string(wire) != "null" {
		t.Fatalf("absent response = %s, %v", wire, err)
	}
}

func TestPublicResponsesDeltaPreservesUserContentAndOmittedFields(t *testing.T) {
	// The same key is valid inside model output; only core metadata is private.
	delta := `{"extra_fields":{"response":{"extra_fields":"customer content"}}}`
	response := &schemas.BifrostResponsesStreamResponse{
		Type:        schemas.ResponsesStreamResponseTypeOutputTextDelta,
		OutputIndex: schemas.Ptr(0), ContentIndex: schemas.Ptr(0),
		ItemID: schemas.Ptr("msg_1"), Delta: &delta,
		ExtraFields: schemas.BifrostResponseExtraFields{RawRequest: "private request"},
	}
	object := publicPayloadObject(t, publicResponsePayload(response, ""))
	if object["delta"] != delta || object["item_id"] != "msg_1" || object["content_index"] != float64(0) || object["output_index"] != float64(0) {
		t.Fatalf("delta content or zero indices changed: %#v", object)
	}
	for _, field := range []string{"extra_fields", "response", "item", "part", "logprobs"} {
		if _, exists := object[field]; exists {
			t.Errorf("delta contains inapplicable field %q", field)
		}
	}
	var absent *schemas.BifrostResponsesStreamResponse
	wire, err := marshalPayload(publicResponsePayload(absent, ""))
	if err != nil || string(wire) != "null" {
		t.Fatalf("absent response = %s, %v", wire, err)
	}
}

func TestPublicResponsesNameTheCatalogModelThatServed(t *testing.T) {
	chat := &schemas.BifrostChatResponse{ID: "chatcmpl_1", Object: "chat.completion", Model: "gpt-5.6-sol-2026-07-09"}
	responses := &schemas.BifrostResponsesResponse{ID: schemas.Ptr("resp_1"), Object: "response", Model: "probe-sol"}
	event := &schemas.BifrostResponsesStreamResponse{
		Type:     schemas.ResponsesStreamResponseTypeCreated,
		Response: &schemas.BifrostResponsesResponse{ID: schemas.Ptr("resp_1"), Model: "probe-sol"},
	}
	for name, payload := range map[string]any{"chat": chat, "responses": responses} {
		if model := publicPayloadObject(t, publicResponsePayload(payload, "gpt-5.6-sol"))["model"]; model != "gpt-5.6-sol" {
			t.Errorf("%s model = %v, want gpt-5.6-sol", name, model)
		}
		if model := publicPayloadObject(t, publicResponsePayload(payload, ""))["model"]; model == "gpt-5.6-sol" {
			t.Errorf("%s without a catalog model lost the provider's name", name)
		}
	}
	nested := publicPayloadObject(t, publicResponsePayload(event, "gpt-5.6-sol"))["response"].(map[string]any)
	if nested["model"] != "gpt-5.6-sol" || nested["id"] != "resp_1" {
		t.Fatalf("event response = %#v", nested)
	}
	if chat.Model != "gpt-5.6-sol-2026-07-09" || responses.Model != "probe-sol" || event.Response.Model != "probe-sol" {
		t.Fatal("naming the served model mutated the provider's response, which validation compares across chunks")
	}

	// An event without a response object gains none.
	delta := "hi"
	text := &schemas.BifrostResponsesStreamResponse{Type: schemas.ResponsesStreamResponseTypeOutputTextDelta, Delta: &delta}
	if _, present := publicPayloadObject(t, publicResponsePayload(text, "gpt-5.6-sol"))["response"]; present {
		t.Fatal("delta event gained a response object")
	}
	var absent *schemas.BifrostResponsesResponse
	if wire, err := marshalPayload(publicResponsePayload(absent, "gpt-5.6-sol")); err != nil || string(wire) != "null" {
		t.Fatalf("absent response = %s, %v", wire, err)
	}
}
