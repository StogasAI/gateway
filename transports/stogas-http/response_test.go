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
		wire, err := marshalPayload(publicPayload(response))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(wire, []byte("extra_fields")) || bytes.Contains(wire, []byte("private-")) {
			t.Fatalf("core metadata reached the public stream: %s", wire)
		}
		object := publicPayloadObject(t, publicPayload(response))
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
	wire, err := marshalPayload(publicPayload(response))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte("extra_fields")) || bytes.Contains(wire, []byte("private-")) {
		t.Fatalf("core metadata reached the public response: %s", wire)
	}
	object := publicPayloadObject(t, publicPayload(response))
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
	if wire, err := marshalPayload(publicPayload(absent)); err != nil || string(wire) != "null" {
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
	object := publicPayloadObject(t, publicPayload(response))
	if object["delta"] != delta || object["item_id"] != "msg_1" || object["content_index"] != float64(0) || object["output_index"] != float64(0) {
		t.Fatalf("delta content or zero indices changed: %#v", object)
	}
	for _, field := range []string{"extra_fields", "response", "item", "part", "logprobs"} {
		if _, exists := object[field]; exists {
			t.Errorf("delta contains inapplicable field %q", field)
		}
	}
	var absent *schemas.BifrostResponsesStreamResponse
	wire, err := marshalPayload(publicPayload(absent))
	if err != nil || string(wire) != "null" {
		t.Fatalf("absent response = %s, %v", wire, err)
	}
}
